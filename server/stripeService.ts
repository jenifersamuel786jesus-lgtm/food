import Stripe from 'stripe';
let stripeClient: Stripe | null = null;
function getStripeInstance(): Stripe {
  const secretKey = process.env.STRIPE_SECRET_KEY?.trim();
  if (!secretKey) throw new Error('Stripe is not configured. Add STRIPE_SECRET_KEY to the Vercel server environment and redeploy.');
  if (!/^sk_(test|live)_/.test(secretKey)) throw new Error('STRIPE_SECRET_KEY format is invalid. Use a Stripe secret key (sk_test_... or sk_live_...).');
  if (!stripeClient) stripeClient = new Stripe(secretKey);
  return stripeClient;
}
export async function createStripePaymentIntent(amountInDollars: number, currency = 'usd', metadata: Record<string, any> = {}) {
  if (!Number.isFinite(amountInDollars) || amountInDollars <= 0) throw new Error('Payment amount must be greater than zero.');
  const amountInCents = Math.round(amountInDollars * 100);
  try {
    const paymentIntent = await getStripeInstance().paymentIntents.create({
      amount: amountInCents,
      currency,
      metadata: { app: 'OrderIt', ...metadata },
      automatic_payment_methods: { enabled: true },
    });
    return { success: true, clientSecret: paymentIntent.client_secret, paymentIntentId: paymentIntent.id, mode: paymentIntent.livemode ? 'live' : 'test', amount: amountInDollars };
  } catch (error: any) {
    console.error('[Stripe] PaymentIntent creation failed:', error?.type || error?.code || error?.message);
    const status = error?.statusCode;
    if (status === 401 || error?.type === 'StripeAuthenticationError') throw new Error('Stripe rejected STRIPE_SECRET_KEY (401). Verify the key is a valid secret key for the intended Stripe account and deployment environment.');
    throw new Error(error?.message || 'Stripe could not create a payment session.');
  }
}
export async function verifyStripePaymentIntent(paymentIntentId: string) {
  const intent = await getStripeInstance().paymentIntents.retrieve(paymentIntentId);
  return { succeeded: intent.status === 'succeeded', amount: intent.amount, currency: intent.currency, status: intent.status, metadata: intent.metadata };
}

export function verifyStripeWebhook(payload: Buffer, signature: string) {
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET?.trim();
  if (!webhookSecret) throw new Error('STRIPE_WEBHOOK_SECRET is not configured.');
  return getStripeInstance().webhooks.constructEvent(payload, signature, webhookSecret);
}
