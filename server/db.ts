import mongoose from 'mongoose';
import { initialRestaurants, initialMenus, initialCoupons } from './seedData.ts';
import { Restaurant } from './models/Restaurant.ts';
import { Menu } from './models/Menu.ts';
import { Order } from './models/Order.ts';
import { User } from './models/User.ts';
import { Coupon } from './models/Coupon.ts';

let connectionError: string | null = null;
let databaseName: string | null = null;
let connectionHost: string | null = null;
let connectionPromise: Promise<{ connected: boolean; message: string }> | null = null;

export async function connectMongoDB(): Promise<{ connected: boolean; message: string }> {
  let uri = (process.env.MONGODB_URI || process.env.MONGO_URI || '').trim();
  if ((uri.startsWith('"') && uri.endsWith('"')) || (uri.startsWith("'") && uri.endsWith("'"))) uri = uri.slice(1, -1).trim();
  if (!uri || uri.includes('<username>') || uri.includes('<password>')) {
    return { connected: false, message: 'MONGODB_URI is missing or contains placeholder credentials.' };
  }
  if (mongoose.connection.readyState === 1) return { connected: true, message: `Connected to MongoDB (${databaseName || 'database'}).` };
  if (connectionPromise) return connectionPromise;
  connectionPromise = (async () => {
    try {
      const conn = await mongoose.connect(uri, { serverSelectionTimeoutMS: 10000, connectTimeoutMS: 10000, maxPoolSize: 10 });
      databaseName = conn.connection.name || 'configured database';
      connectionHost = conn.connection.host || 'MongoDB Atlas';
      connectionError = null;
      await seedMongoIfEmpty();
      return { connected: true, message: `Successfully connected to MongoDB (${databaseName}).` };
    } catch (error: any) {
      connectionError = error?.message || 'MongoDB connection failed.';
      console.error(`[Database] Connection failed: ${connectionError}`);
      return { connected: false, message: connectionError || 'MongoDB connection failed.' };
    } finally {
      connectionPromise = null;
    }
  })();
  return await connectionPromise;
}

export async function seedMongoIfEmpty() {
  if (mongoose.connection.readyState !== 1) return;
  try {
    if (await Restaurant.countDocuments() === 0) await Restaurant.insertMany(initialRestaurants);
    if (await Menu.countDocuments() === 0) await Menu.insertMany(initialMenus);
    if (await Coupon.countDocuments() === 0) await Coupon.insertMany(initialCoupons);
  } catch (error: any) {
    console.error('[Database] Seed initialization failed:', error?.message || error);
  }
}

export async function getDatabaseStatus(fallbackCounts: { restaurants: number; menus: number; orders: number; users: number; coupons: number }) {
  const connected = mongoose.connection.readyState === 1;
  const uriConfigured = !!(process.env.MONGODB_URI || process.env.MONGO_URI);
  let counts = { ...fallbackCounts };
  if (connected) {
    try {
      const [restaurants, menus, orders, users, coupons] = await Promise.all([
        Restaurant.countDocuments(), Menu.countDocuments(), Order.countDocuments(), User.countDocuments(), Coupon.countDocuments(),
      ]);
      counts = { restaurants, menus, orders, users, coupons };
    } catch (error: any) {
      connectionError = error?.message || 'Unable to read MongoDB collection counts.';
    }
  }
  return {
    engine: connected ? 'MongoDB' : 'In-Memory (Seeded Store)',
    connected,
    uriConfigured,
    databaseName: connected ? databaseName : 'in-memory-foodgenie',
    host: connected ? connectionHost : 'localhost/memory',
    connectionError,
    counts,
  };
}

export const isConnected = () => mongoose.connection.readyState === 1;
