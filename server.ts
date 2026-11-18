import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import {
  initialRestaurants,
  initialMenus,
  initialCoupons,
  GENERATED_IMAGES,
} from './server/seedData.ts';
import type {
  FoodItemData,
  RestaurantData,
  RestaurantMenu,
  CouponData,
} from './server/seedData.ts';
import {
  generateDishRecommendations,
  analyzeRestaurantReviews,
} from './server/aiService.ts';
import { connectMongoDB, getDatabaseStatus } from './server/db.ts';
import { Restaurant } from './server/models/Restaurant.ts';
import { Menu } from './server/models/Menu.ts';
import { Order } from './server/models/Order.ts';
import { User } from './server/models/User.ts';
import { Coupon } from './server/models/Coupon.ts';
import { securitySanitizerMiddleware } from './server/security.ts';
import { createStripePaymentIntent, verifyStripePaymentIntent, verifyStripeWebhook } from './server/stripeService.ts';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import { createHmac, randomUUID, timingSafeEqual, randomBytes } from 'node:crypto';
dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const allowedOrigins = (process.env.CORS_ORIGIN || '')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);
app.use(cors({
  credentials: true,
  origin(origin, callback) {
    // Same-origin/browserless requests have no Origin header. Cross-origin access must be explicit.
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('Origin is not allowed by CORS.'));
  },
}));
// Stripe requires the exact raw request body to verify webhook signatures.
app.post('/api/v1/payment/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    const signature = req.get('stripe-signature');
    if (!signature) return res.status(400).send('Missing Stripe signature.');
    const event = verifyStripeWebhook(req.body, signature);
    if (event.type === 'payment_intent.payment_failed' || event.type === 'charge.refunded') {
      const paymentIntentId = event.type === 'payment_intent.payment_failed'
        ? event.data.object.id : String((event.data.object as any).payment_intent || '');
      if (paymentIntentId && mongoose.connection.readyState === 1) {
        await Order.updateMany({ 'paymentInfo.id': paymentIntentId }, { $set: { 'paymentInfo.status': event.type === 'charge.refunded' ? 'Refunded' : 'Payment Failed' } });
      }
    }
    res.json({ received: true });
  } catch (error: any) {
    console.error('[Stripe webhook] signature verification failed:', error?.message);
    res.status(400).send('Invalid webhook.');
  }
});
app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());
app.use(csrfProtection);
app.use(securitySanitizerMiddleware);

const AUTH_SESSION_COOKIE = 'orderit_session';
const CSRF_COOKIE = 'orderit_csrf';
const AUTH_SESSION_SECONDS = 7 * 24 * 60 * 60;

function makeSessionToken(userId: string): string {
  const secret = process.env.SESSION_SECRET;
  if (!secret) throw new Error('SESSION_SECRET is not configured.');
  const payload = Buffer.from(JSON.stringify({
    sub: userId,
    exp: Math.floor(Date.now() / 1000) + AUTH_SESSION_SECONDS,
  })).toString('base64url');
  const signature = createHmac('sha256', secret).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}

function readSessionUserId(token: unknown): string | null {
  const secret = process.env.SESSION_SECRET;
  if (!secret || typeof token !== 'string') return null;
  try {
    const [payload, signature, extra] = token.split('.');
    if (!payload || !signature || extra) return null;
    const expected = createHmac('sha256', secret).update(payload).digest();
    const actual = Buffer.from(signature, 'base64url');
    if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) return null;
    const session = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (typeof session.sub !== 'string' || session.exp <= Math.floor(Date.now() / 1000)) return null;
    return session.sub;
  } catch {
    return null;
  }
}

function setSessionCookie(res: express.Response, userId: string) {
  res.cookie(AUTH_SESSION_COOKIE, makeSessionToken(userId), {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production' || process.env.VERCEL === '1',
    sameSite: 'lax',
    maxAge: AUTH_SESSION_SECONDS * 1000,
    path: '/',
  });
  res.cookie(CSRF_COOKIE, randomBytes(32).toString('base64url'), {
    httpOnly: false,
    secure: process.env.NODE_ENV === 'production' || process.env.VERCEL === '1',
    sameSite: 'lax',
    maxAge: AUTH_SESSION_SECONDS * 1000,
    path: '/',
  });
}

function requireAuth(req: express.Request, res: express.Response, next: express.NextFunction) {
  const userId = readSessionUserId(req.cookies?.[AUTH_SESSION_COOKIE]);
  if (!userId) return res.status(401).json({ status: 'fail', message: 'Please sign in to continue.' });
  res.locals.userId = userId;
  next();
}

function csrfProtection(req: express.Request, res: express.Response, next: express.NextFunction) {
  if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) || !req.cookies?.[AUTH_SESSION_COOKIE]) return next();
  const token = req.get('x-csrf-token');
  const cookieToken = req.cookies?.[CSRF_COOKIE];
  if (!token || typeof cookieToken !== 'string' || token.length !== cookieToken.length ||
      !timingSafeEqual(Buffer.from(token), Buffer.from(cookieToken))) {
    return res.status(403).json({ status: 'fail', message: 'Invalid CSRF token.' });
  }
  next();
}

const requestBuckets = new Map<string, { count: number; resetAt: number }>();
function rateLimit(limit: number, windowMs: number) {
  return (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const key = `${req.ip}:${req.path}`;
    const now = Date.now();
    const bucket = requestBuckets.get(key);
    if (!bucket || bucket.resetAt <= now) {
      requestBuckets.set(key, { count: 1, resetAt: now + windowMs });
      return next();
    }
    bucket.count += 1;
    if (bucket.count > limit) return res.status(429).json({ status: 'fail', message: 'Too many requests. Please try again later.' });
    next();
  };
}

function publicUser(user: any): UserAccount {
  const record = typeof user?.toObject === 'function' ? user.toObject() : user;
  const { passwordHash: _passwordHash, ...safeUser } = record;
  return safeUser as UserAccount;
}

// In-memory state initialized from rich seed data
const restaurants: RestaurantData[] = structuredClone(initialRestaurants);
const menus: RestaurantMenu[] = structuredClone(initialMenus);
const coupons: CouponData[] = structuredClone(initialCoupons);

interface UserAccount {
  _id: string;
  name: string;
  email: string;
  phoneNumber: string;
  avatar: { public_id: string; url: string };
  role: string;
  createdAt: string;
  defaultAddress: {
    address: string;
    city: string;
    postalCode: string;
    phoneNo: string;
    country: string;
  };
}

const users: UserAccount[] = [];

interface CartEntry {
  fooditem: FoodItemData;
  quantity: number;
}

interface CartState {
  user: string;
  restaurant: RestaurantData | null;
  items: CartEntry[];
}

const cartsByUser = new Map<string, CartState>();
function getCart(userId: string): CartState {
  let cart = cartsByUser.get(userId);
  if (!cart) {
    cart = { user: userId, restaurant: null, items: [] };
    cartsByUser.set(userId, cart);
  }
  return cart;
}

export interface OrderRecord {
  _id: string;
  user: UserAccount;
  restaurant: {
    _id: string;
    name: string;
    address: string;
    image: string;
  };
  orderItems: {
    fooditem: string;
    name: string;
    price: number;
    quantity: number;
    image: string;
    isVeg: boolean;
  }[];
  deliveryInfo: {
    address: string;
    city: string;
    postalCode: string;
    phoneNo: string;
    country: string;
  };
  itemsPrice: number;
  taxPrice: number;
  deliveryCharge: number;
  discountAmount: number;
  couponApplied?: string;
  finalTotal: number;
  paymentInfo: {
    id: string;
    status: string;
    method: string;
  };
  orderStatus: 'Order Confirmed' | 'Preparing in Kitchen' | 'Out for Delivery' | 'Delivered';
  createdAt: string;
}

const orders: OrderRecord[] = [];
const processedPaymentIntents = new Set<string>();
const paymentDrafts = new Map<string, { userId: string; cart: CartState; couponCode?: string; expiresAt: number }>();

function getAllFoodItemsFlat(): FoodItemData[] {
  const list: FoodItemData[] = [];
  for (const m of menus) {
    for (const cat of m.menu) {
      for (const item of cat.items) {
        list.push(item);
      }
    }
  }
  return list;
}

// ==========================================
// 1. RESTAURANT ROUTES (/api/v1/eats/stores)
// ==========================================
app.get('/api/v1/eats/stores/count', async (_req, res) => {
  await connectMongoDB();
  const source: any[] = mongoose.connection.readyState === 1 ? await Restaurant.find().lean() : restaurants;
  const count = source.length;
  const pureVegCount = source.filter((r) => r.isVeg).length;
  res.json({
    status: 'success',
    count,
    pureVegCount,
  });
});

app.get('/api/v1/eats/stores', async (req, res) => {
  await connectMongoDB();
  const source: any[] = mongoose.connection.readyState === 1 ? await Restaurant.find().lean() : restaurants;
  const menuSource: any[] = mongoose.connection.readyState === 1 ? await Menu.find().lean() : menus;
  const { keyword, isVeg, sortByRatings, sortByReviews, cuisine } = req.query;
  let result = [...source];

  if (keyword && typeof keyword === 'string' && keyword.trim() !== '') {
    const q = keyword.toLowerCase().trim();
    const matchingRestIdsFromDishes = new Set(
      menuSource.flatMap((m: any) => m.menu.flatMap((c: any) => c.items))
        .filter(
          (item) =>
            item.name.toLowerCase().includes(q) ||
            item.description.toLowerCase().includes(q) ||
            item.category.toLowerCase().includes(q)
        )
        .map((item) => item.restaurant)
    );

    result = result.filter(
      (r) =>
        r.name.toLowerCase().includes(q) ||
        r.address.toLowerCase().includes(q) ||
        r.cuisine.some((c: string) => c.toLowerCase().includes(q)) ||
        matchingRestIdsFromDishes.has(r._id)
    );
  }

  if (isVeg === 'true') {
    result = result.filter((r) => r.isVeg);
  }

  if (cuisine && typeof cuisine === 'string' && cuisine !== 'All') {
    result = result.filter((r) =>
      r.cuisine.some((c: string) => c.toLowerCase().includes(cuisine.toLowerCase()))
    );
  }

  if (sortByRatings === 'true') {
    result.sort((a, b) => b.ratings - a.ratings);
  } else if (sortByReviews === 'true') {
    result.sort((a, b) => b.numOfReviews - a.numOfReviews);
  }

  res.json({
    status: 'success',
    count: result.length,
    restaurants: result,
  });
});

app.get('/api/v1/eats/stores/:storeId', async (req, res) => {
  await connectMongoDB();
  const restaurant = mongoose.connection.readyState === 1 ? await Restaurant.findById(req.params.storeId).lean() : restaurants.find((r) => r._id === req.params.storeId);
  if (!restaurant) {
    return res.status(404).json({ status: 'fail', message: 'Restaurant not found' });
  }
  res.json({ status: 'success', data: { restaurant } });
});

app.get('/api/v1/eats/stores/:storeId/menus', async (req, res) => {
  await connectMongoDB();
  const { storeId } = req.params;
  const [restaurant, storeMenu] = mongoose.connection.readyState === 1
    ? await Promise.all([Restaurant.findById(storeId).lean(), Menu.findOne({ restaurant: storeId }).lean()])
    : [restaurants.find((r) => r._id === storeId), menus.find((m) => m.restaurant === storeId)];

  if (!restaurant || !storeMenu) {
    return res.status(404).json({ status: 'fail', message: 'Menu not found for this store' });
  }

  res.json({
    status: 'success',
    count: storeMenu.menu.length,
    data: {
      restaurant,
      menus: [storeMenu],
    },
  });
});

app.post('/api/v1/eats/stores/:storeId/reviews', requireAuth, async (req, res) => {
  const { storeId } = req.params;
  const { rating, comment, dishMentioned } = req.body;
  const numericRating = Number(rating);
  if (!Number.isInteger(numericRating) || numericRating < 1 || numericRating > 5 || !String(comment || '').trim()) {
    return res.status(400).json({ status: 'fail', message: 'Provide a review and a rating from 1 to 5.' });
  }
  const restaurant = restaurants.find((r) => r._id === storeId);
  if (!restaurant) {
    return res.status(404).json({ status: 'fail', message: 'Restaurant not found' });
  }

  const newReview = {
    _id: `rev-${Date.now()}`,
    userName: (await User.findById(res.locals.userId).lean())?.name || 'Verified Diner',
    rating: numericRating,
    comment: String(comment).trim(),
    createdAt: new Date().toISOString().split('T')[0],
    dishMentioned: dishMentioned || undefined,
  };

  restaurant.reviews.unshift(newReview);
  restaurant.numOfReviews += 1;
  const avg =
    restaurant.reviews.reduce((acc, r) => acc + r.rating, 0) / restaurant.reviews.length;
  restaurant.ratings = Number(avg.toFixed(1));

  res.status(201).json({
    status: 'success',
    review: newReview,
    restaurant,
  });
});

// ==========================================
// 2. FOOD ITEMS ROUTES (/api/v1/eats/item)
// ==========================================
app.get('/api/v1/eats/item', async (_req, res) => {
  await connectMongoDB();
  const source: any[] = mongoose.connection.readyState === 1 ? await Menu.find().lean() : menus;
  const items = source.flatMap((m) => m.menu.flatMap((c: any) => c.items));
  res.json({ status: 'success', count: items.length, items });
});

// ==========================================
// 3. CART ROUTES (/api/v1/eats/cart)
// ==========================================
app.get('/api/v1/eats/cart/get-cart', requireAuth, (req, res) => {
  const currentCart = getCart(res.locals.userId);
  res.json({
    status: 'success',
    data: currentCart,
  });
});

app.post('/api/v1/eats/cart/add-to-cart', requireAuth, (req, res) => {
  const currentCart = getCart(res.locals.userId);
  const { foodItemId, restaurant: restaurantId, quantity = 1 } = req.body;
  const allItems = getAllFoodItemsFlat();
  const targetItem = allItems.find((i) => i._id === foodItemId);
  if (!targetItem) {
    return res.status(404).json({ status: 'fail', message: 'Food item not found' });
  }

  const requestedQuantity = Number(quantity);
  if (!Number.isInteger(requestedQuantity) || requestedQuantity < 1 || requestedQuantity > 99) {
    return res.status(400).json({ status: 'fail', message: 'Quantity must be between 1 and 99.' });
  }
  const targetRestaurant =
    restaurants.find((r) => r._id === (restaurantId || targetItem.restaurant)) || null;

  // If switching restaurants, reset cart to the new restaurant
  if (
    currentCart.restaurant &&
    targetRestaurant &&
    currentCart.restaurant._id !== targetRestaurant._id
  ) {
    currentCart.restaurant = targetRestaurant;
    currentCart.items = [{ fooditem: targetItem, quantity: requestedQuantity }];
  } else {
    currentCart.restaurant = targetRestaurant;
    const existing = currentCart.items.find((entry) => entry.fooditem._id === foodItemId);
    if (existing) {
      existing.quantity = requestedQuantity;
    } else {
      currentCart.items.push({ fooditem: targetItem, quantity: requestedQuantity });
    }
  }

  res.json({
    status: 'success',
    data: currentCart,
  });
});

app.post('/api/v1/eats/cart/update-cart-item', requireAuth, (req, res) => {
  const currentCart = getCart(res.locals.userId);
  const { foodItemId, quantity } = req.body;
  const qty = Number(quantity);

  if (!Number.isInteger(qty) || qty < 0 || qty > 99) {
    return res.status(400).json({ status: 'fail', message: 'Quantity must be between 0 and 99.' });
  }
  if (qty <= 0) {
    currentCart.items = currentCart.items.filter((i) => i.fooditem._id !== foodItemId);
  } else {
    const existing = currentCart.items.find((i) => i.fooditem._id === foodItemId);
    if (existing) {
      existing.quantity = qty;
    }
  }

  if (currentCart.items.length === 0) {
    currentCart.restaurant = null;
  }

  res.json({
    status: 'success',
    data: currentCart,
  });
});

app.delete('/api/v1/eats/cart/delete-cart-item', requireAuth, (req, res) => {
  const currentCart = getCart(res.locals.userId);
  const foodItemId = req.body?.foodItemId || req.query?.foodItemId;
  currentCart.items = currentCart.items.filter((i) => i.fooditem._id !== foodItemId);
  if (currentCart.items.length === 0) {
    currentCart.restaurant = null;
  }
  res.json({
    status: 'success',
    data: currentCart,
  });
});

app.delete('/api/v1/eats/cart/clear-cart', requireAuth, (_req, res) => {
  const currentCart = getCart(res.locals.userId);
  currentCart.items = [];
  currentCart.restaurant = null;
  res.json({
    status: 'success',
    data: currentCart,
  });
});

// ==========================================
// 4. COUPONS ROUTES (/api/v1/coupons)
// ==========================================
app.get('/api/v1/coupons', async (_req, res) => {
  await connectMongoDB();
  const source = mongoose.connection.readyState === 1 ? await Coupon.find({ isActive: true }).lean() : coupons.filter((c) => c.isActive);
  res.json({
    status: 'success',
    coupons: source,
  });
});

app.post('/api/v1/coupons/validate', async (req, res) => {
  await connectMongoDB();
  const { code, orderAmount } = req.body;
  if (!code) {
    return res.status(400).json({ valid: false, message: 'Please enter a coupon code.' });
  }

  const normalized = String(code).trim().toUpperCase();
  const coupon = mongoose.connection.readyState === 1 ? await Coupon.findOne({ code: normalized, isActive: true }).lean() : coupons.find((c) => c.code === normalized && c.isActive);
  if (!coupon) {
    return res.status(404).json({
      valid: false,
      message: `Coupon "${normalized}" is not valid or has expired.`,
    });
  }

  const subtotal = Number(orderAmount) || 0;
  if (subtotal < coupon.minOrderAmount) {
    return res.status(400).json({
      valid: false,
      message: `Minimum item subtotal of $${coupon.minOrderAmount} required for ${coupon.code}.`,
    });
  }

  let discountAmount = 0;
  if (coupon.discountType === 'PERCENTAGE') {
    discountAmount = Math.min(
      Number(((subtotal * coupon.discountValue) / 100).toFixed(2)),
      coupon.maxDiscount
    );
  } else {
    discountAmount = Math.min(coupon.discountValue, subtotal);
  }

  res.json({
    valid: true,
    coupon,
    discountAmount,
    message: `${coupon.code} applied! You saved $${discountAmount.toFixed(2)}.`,
  });
});

// ==========================================
// DATABASE (MONGODB) & SYSTEM HEALTH ROUTES
// ==========================================
app.get('/api/v1/db/status', async (_req, res) => {
  await connectMongoDB();
  const status = await getDatabaseStatus({
    restaurants: restaurants.length,
    menus: menus.length,
    orders: orders.length,
    users: users.length,
    coupons: coupons.length,
  });
  res.json({
    status: 'success',
    database: status,
  });
});

// ==========================================
// 5. AUTH & USER ROUTES (/api/v1/users)
// ==========================================
app.get('/api/v1/users/me', async (req, res) => {
  const userId = readSessionUserId(req.cookies?.[AUTH_SESSION_COOKIE]);
  if (!userId) {
    return res.json({ status: 'success', authenticated: false, user: null });
  }
  await connectMongoDB();
  if (mongoose.connection.readyState !== 1) {
    return res.status(503).json({ status: 'fail', message: 'User database is unavailable.' });
  }
  const user = await User.findById(userId).lean();
  if (!user) {
    res.clearCookie(AUTH_SESSION_COOKIE, { path: '/' });
    return res.json({ status: 'success', authenticated: false, user: null });
  }
  return res.json({ status: 'success', authenticated: true, user: publicUser(user) });
});

app.post('/api/v1/users/login', rateLimit(10, 15 * 60 * 1000), async (req, res) => {
  const cleanEmail = String(req.body?.email || '').trim().toLowerCase();
  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  if (!cleanEmail || !cleanEmail.includes('@') || !password) {
    return res.status(400).json({ success: false, message: 'Enter a valid email and password.' });
  }
  if (!process.env.SESSION_SECRET) {
    return res.status(503).json({ success: false, message: 'SESSION_SECRET is not configured on the server.' });
  }
  try {
    await connectMongoDB();
    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({ success: false, message: 'User database is unavailable. Please try again later.' });
    }
    const account = await User.findOne({ email: cleanEmail }).select('+passwordHash');
    if (!account?.passwordHash || !(await bcrypt.compare(password, account.passwordHash))) {
      return res.status(401).json({ success: false, message: 'Invalid email or password. Create an account first if you are new.' });
    }
    const user = publicUser(account);
    setSessionCookie(res, user._id);
    getCart(user._id);
    return res.json({ status: 'success', user });
  } catch (error: any) {
    console.error('[Auth] Sign-in failed:', error?.message || error);
    return res.status(500).json({ success: false, message: 'Unable to sign in right now.' });
  }
});

app.post('/api/v1/users/signup', rateLimit(5, 60 * 60 * 1000), async (req, res) => {
  const name = String(req.body?.name || '').trim();
  const email = String(req.body?.email || '').trim().toLowerCase();
  const phoneNumber = String(req.body?.phoneNumber || '').trim();
  const password = typeof req.body?.password === 'string' ? req.body.password : '';
  if (!name || !email.includes('@') || password.length < 6 || password.length > 100) {
    return res.status(400).json({ success: false, message: 'Enter a name, valid email, and password with at least 6 characters.' });
  }
  if (!process.env.SESSION_SECRET) {
    return res.status(503).json({ success: false, message: 'SESSION_SECRET is not configured on the server.' });
  }
  try {
    await connectMongoDB();
    if (mongoose.connection.readyState !== 1) {
      return res.status(503).json({ success: false, message: 'User database is unavailable. Please try again later.' });
    }
    if (await User.findOne({ email }).select('_id')) {
      return res.status(409).json({ success: false, message: 'An account with this email already exists. Please sign in.' });
    }
    const userRecord = await User.create({
      _id: randomUUID(),
      name,
      email,
      phoneNumber,
      passwordHash: await bcrypt.hash(password, 12),
      avatar: { public_id: 'avatar_new', url: GENERATED_IMAGES.avatar },
      role: 'user',
    });
    const user = publicUser(userRecord);
    setSessionCookie(res, user._id);
    cartsByUser.set(user._id, { user: user._id, restaurant: null, items: [] });
    return res.status(201).json({ status: 'success', user });
  } catch (error: any) {
    if (error?.code === 11000) {
      return res.status(409).json({ success: false, message: 'An account with this email already exists. Please sign in.' });
    }
    console.error('[Auth] Sign-up failed:', error?.message || error);
    return res.status(500).json({ success: false, message: 'Unable to create the account right now.' });
  }
});

app.post('/api/v1/users/logout', requireAuth, (_req, res) => {
  res.clearCookie(AUTH_SESSION_COOKIE, { path: '/' });
  res.clearCookie(CSRF_COOKIE, { path: '/' });
  cartsByUser.delete(res.locals.userId);
  res.json({
    status: 'success',
    message: 'Logged out successfully',
  });
});

app.put('/api/v1/users/me/update', async (req, res) => {
  const userId = readSessionUserId(req.cookies?.[AUTH_SESSION_COOKIE]);
  if (!userId) return res.status(401).json({ status: 'fail', message: 'Please sign in to update your profile.' });
  await connectMongoDB();
  if (mongoose.connection.readyState !== 1) {
    return res.status(503).json({ status: 'fail', message: 'User database is unavailable.' });
  }
  const account = await User.findById(userId).select('+passwordHash');
  if (!account) return res.status(401).json({ status: 'fail', message: 'Please sign in to update your profile.' });
  const { name, email, phoneNumber, address, city, postalCode, avatar } = req.body;
  if (email && email !== account.email && await User.exists({ email })) {
    return res.status(409).json({ status: 'fail', message: 'An account with this email already exists.' });
  }
  if (name) account.name = name;
  if (email) account.email = email;
  if (phoneNumber) account.phoneNumber = phoneNumber;
  if (!account.defaultAddress) {
    account.defaultAddress = {
      address: '',
      city: '',
      postalCode: '',
      phoneNo: '',
      country: 'United States',
    };
  }
  if (address !== undefined) account.defaultAddress.address = address;
  if (city !== undefined) account.defaultAddress.city = city;
  if (postalCode !== undefined) account.defaultAddress.postalCode = postalCode;
  if (avatar) {
    const avatarUrl = typeof avatar === 'string' ? avatar : avatar.url;
    const allowedAvatar = typeof avatarUrl === 'string' &&
      (/^data:image\/(jpeg|png|webp);base64,/i.test(avatarUrl) || /^https:\/\//i.test(avatarUrl));
    if (!allowedAvatar || avatarUrl.length > 750_000) {
      return res.status(400).json({ status: 'fail', message: 'Avatar must be a JPEG, PNG, WebP upload under 750KB, or an HTTPS image URL.' });
    }
    if (typeof avatar === 'string') {
      account.avatar = { public_id: 'avatar_custom', url: avatar };
    } else if (avatar && avatar.url) {
      account.avatar = {
        public_id: avatar.public_id || 'avatar_custom',
        url: avatar.url,
      };
    }
  }

  try {
    await account.save();
  } catch (error: any) {
    if (error?.code === 11000) return res.status(409).json({ status: 'fail', message: 'An account with this email already exists.' });
    throw error;
  }

  res.json({
    status: 'success',
    user: publicUser(account),
  });
});

// ==========================================
// ==========================================
// 6. STRIPE PAYMENT & ORDERS ROUTES (/api/v1/eats/orders)
// ==========================================
app.get('/api/v1/payment/config', (_req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.json({
    publishableKey: process.env.STRIPE_PUBLISHABLE_KEY || process.env.VITE_STRIPE_PUBLISHABLE_KEY || null,
  });
});

async function calculateCheckout(cart: CartState, couponCode?: string) {
  if (!cart.restaurant || cart.items.length === 0) throw new Error('Your cart is empty.');
  const itemsPrice = Number(cart.items.reduce((sum, entry) => sum + entry.fooditem.price * entry.quantity, 0).toFixed(2));
  const taxPrice = Number((itemsPrice * 0.08).toFixed(2));
  const deliveryCharge = itemsPrice > 40 ? 0 : 3.5;
  let discountAmount = 0;
  let appliedCoupon: string | undefined;
  if (couponCode) {
    const normalized = String(couponCode).trim().toUpperCase();
    await connectMongoDB();
    const coupon: any = mongoose.connection.readyState === 1
      ? await Coupon.findOne({ code: normalized, isActive: true }).lean()
      : coupons.find((entry) => entry.code === normalized && entry.isActive);
    if (!coupon || itemsPrice < coupon.minOrderAmount) throw new Error('The selected coupon is no longer valid for this cart.');
    discountAmount = coupon.discountType === 'PERCENTAGE'
      ? Math.min(Number(((itemsPrice * coupon.discountValue) / 100).toFixed(2)), coupon.maxDiscount)
      : Math.min(coupon.discountValue, itemsPrice);
    appliedCoupon = coupon.code;
  }
  return { itemsPrice, taxPrice, deliveryCharge, discountAmount, couponApplied: appliedCoupon,
    finalTotal: Number((itemsPrice + taxPrice + deliveryCharge - discountAmount).toFixed(2)) };
}

app.post('/api/v1/payment/stripe-intent', requireAuth, rateLimit(20, 60 * 1000), async (req, res) => {
  try {
    const userId = res.locals.userId;
    const cart = getCart(userId);
    const orderId = randomUUID();
    const couponCode = req.body?.couponCode;
    const checkout = await calculateCheckout(cart, couponCode);
    const result = await createStripePaymentIntent(checkout.finalTotal, 'usd', { orderId, userId });
    paymentDrafts.set(orderId, { userId, cart: structuredClone(cart), couponCode, expiresAt: Date.now() + 30 * 60 * 1000 });
    res.json({ ...result, orderId, checkout });
  } catch (error: any) {
    console.error('Stripe Payment Intent Error:', error);
    const message = error?.message || 'Payment processing error';
    res.status(message.includes('(401)') ? 401 : message.includes('not configured') ? 503 : 502).json({ success: false, message });
  }
});

app.post('/api/v1/eats/orders/new', requireAuth, async (req, res) => {
    await connectMongoDB();
  
  const {
    deliveryInfo,
    paymentInfo,
    couponApplied,
  } = req.body;
  const userId = res.locals.userId;
  const currentCart = getCart(userId);
  if (!deliveryInfo?.address || !deliveryInfo?.city || !deliveryInfo?.phoneNo) {
    return res.status(400).json({ status: 'fail', message: 'A complete delivery address and phone number are required.' });
  }
  let checkout;
  try { checkout = await calculateCheckout(currentCart, couponApplied); }
  catch (error: any) { return res.status(400).json({ status: 'fail', message: error.message }); }
  let orderId = `ORD-${randomUUID()}`;
  if (paymentInfo?.method === 'Stripe Online Card Checkout') {
    if (!paymentInfo?.id) return res.status(400).json({ status: 'fail', message: 'A confirmed Stripe payment is required.' });
    try {
      const verified = await verifyStripePaymentIntent(String(paymentInfo.id));
      const draftId = String(paymentInfo?.orderId || '');
      const draft = paymentDrafts.get(draftId);
      if (!draft || draft.userId !== userId || draft.expiresAt < Date.now() ||
          processedPaymentIntents.has(String(paymentInfo.id)) || !verified.succeeded ||
          verified.amount !== Math.round(checkout.finalTotal * 100) || verified.currency !== 'usd' ||
          verified.metadata?.orderId !== draftId || verified.metadata?.userId !== userId) {
        return res.status(402).json({ status: 'fail', message: 'Stripe payment is not confirmed or does not match the order total.' });
      }
      processedPaymentIntents.add(String(paymentInfo.id));
      paymentDrafts.delete(draftId);
    } catch (error: any) {
      return res.status(402).json({ status: 'fail', message: error?.message || 'Unable to verify Stripe payment.' });
    }
  }

  const targetRest = currentCart.restaurant;
  if (!targetRest) return res.status(400).json({ status: 'fail', message: 'Your cart is empty.' });
  const account = await User.findById(userId).lean();
  if (!account) return res.status(401).json({ status: 'fail', message: 'Please sign in to continue.' });
  const currentUserRecord = publicUser(account);

  const newOrder: OrderRecord = {
    _id: orderId,
    user: currentUserRecord,
    restaurant: {
      _id: targetRest._id,
      name: targetRest.name,
      address: targetRest.address,
      image: targetRest.images[0]?.url || GENERATED_IMAGES.feast,
    },
    orderItems: currentCart.items.map((entry) => ({
            fooditem: entry.fooditem._id,
            name: entry.fooditem.name,
            price: entry.fooditem.price,
            quantity: entry.quantity,
            image: entry.fooditem.images[0]?.url || GENERATED_IMAGES.feast,
            isVeg: entry.fooditem.isVeg,
          })),
    deliveryInfo: deliveryInfo || currentUserRecord.defaultAddress,
    itemsPrice: checkout.itemsPrice,
    taxPrice: checkout.taxPrice,
    deliveryCharge: checkout.deliveryCharge,
    discountAmount: checkout.discountAmount,
    couponApplied: checkout.couponApplied,
    finalTotal: checkout.finalTotal,
    paymentInfo: {
      id: paymentInfo?.id || `cod_${Date.now()}`,
      status: paymentInfo?.method === 'Stripe Online Card Checkout' ? 'Paid (Stripe Verified)' : 'Pay on Arrival',
      method: paymentInfo?.method === 'Stripe Online Card Checkout' ? 'Stripe Online Card Checkout' : 'Cash on Delivery (COD)',
    },
    orderStatus: 'Order Confirmed',
    createdAt: new Date().toISOString(),
  };

  orders.unshift(newOrder);

  // Clear cart after order creation
  currentCart.items = [];
  currentCart.restaurant = null;

  // Persist to MongoDB if connected
  if (mongoose.connection.readyState === 1) {
    try {
      await Order.create(newOrder);
    } catch (e: any) {
      console.warn('[Database] MongoDB order persist warning:', e.message);
    }
  }

  res.status(201).json({
    status: 'success',
    order: newOrder,
  });
});

app.get('/api/v1/eats/orders/me/myOrders', requireAuth, async (_req, res) => {
  const userId = res.locals.userId;
  await connectMongoDB();
  const userOrders = mongoose.connection.readyState === 1
    ? await Order.find({ 'user._id': userId }).sort({ createdAt: -1 }).lean()
    : orders.filter((order) => order.user?._id === userId);

  res.json({
    status: 'success',
    count: userOrders.length,
    orders: userOrders,
  });
});

app.get('/api/v1/eats/orders/:id', requireAuth, async (req, res) => {
  let order = orders.find((o) => o._id === req.params.id);

  if (!order && mongoose.connection.readyState === 1) {
    try {
      const dbOrder = await Order.findOne({ _id: req.params.id, 'user._id': res.locals.userId }).lean();
      if (dbOrder) order = dbOrder as any;
    } catch {}
  }

  if (!order || order.user?._id !== res.locals.userId) {
    return res.status(404).json({ status: 'fail', message: 'Order not found' });
  }

  res.json({
    status: 'success',
    order,
  });
});

// ==========================================
// 7. GEMINI AI ROUTES (/api/v1/ai)
// ==========================================
app.post('/api/v1/ai/recommend', async (req, res) => {
  try {
    const { prompt, dietaryPreference = 'ALL' } = req.body;
    const allItems = getAllFoodItemsFlat();
    const result = await generateDishRecommendations(
      prompt || 'Recommend something comforting and flavorful for dinner tonight',
      dietaryPreference,
      allItems
    );

    // Enrich recommendations with full foodItem object so the user can add to cart in 1 click
    const enriched = (result.recommendations || []).map((rec: any) => {
      const matched =
        allItems.find((i) => i._id === rec.itemId) ||
        allItems.find((i) => i.name.toLowerCase() === String(rec.name || '').toLowerCase()) ||
        allItems[0];
      return {
        ...rec,
        foodItem: matched,
      };
    });

    res.json({
      status: 'success',
      conciergeNote: result.conciergeNote,
      recommendations: enriched,
    });
  } catch (error: any) {
    console.error('Gemini AI Recommendation Error:', error);
    res.status(500).json({
      status: 'error',
      message: error?.message || 'Failed to generate AI culinary recommendations.',
    });
  }
});

app.post('/api/v1/ai/analyze-reviews', async (req, res) => {
  try {
    const { restaurantId } = req.body;
    const restaurant =
      restaurants.find((r) => r._id === restaurantId) || restaurants[0];
    const analysis = await analyzeRestaurantReviews(restaurant);
    res.json({
      status: 'success',
      restaurantName: restaurant.name,
      analysis,
    });
  } catch (error: any) {
    console.error('Gemini AI Review Analyzer Error:', error);
    res.status(500).json({
      status: 'error',
      message: error?.message || 'Failed to analyze restaurant reviews with Gemini AI.',
    });
  }
});

// ==========================================
// VITE DEV MIDDLEWARE / STATIC PROD SERVING
// ==========================================
async function startServer() {
  const isProd = process.env.NODE_ENV === 'production';

  // Connect to MongoDB Atlas / cluster if MONGODB_URI is provided
  connectMongoDB().catch((err) => {
    console.log('[Database] MongoDB background initialization:', err.message);
  });

  if (!isProd) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  const PORT = 3000;
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`FoodGenie Full-Stack Server listening on http://0.0.0.0:${PORT}`);
  });
}

if (!process.env.VERCEL) {
  startServer();
} else {
  // On Vercel serverless functions, initiate connection once per cold start
  connectMongoDB().catch(() => {});
}

export default app;
