<div align="center">
<img width="1200" height="475" alt="GHBanner" src="https://ai.google.dev/static/site-assets/images/share-ais-513315318.png" />
</div>

# Run and deploy your AI Studio app

This contains everything you need to run your app locally.

View your app in AI Studio: https://ai.studio/apps/69dc756b-23e6-40ee-905d-2989e4843661

## Run Locally

**Prerequisites:**  Node.js


1. Install dependencies:
   `npm install`
2. Create `.env.local` (never commit it) and configure the required server secrets:

   ```env
   GEMINI_API_KEY=...
   MONGODB_URI=...
   SESSION_SECRET=a-long-random-secret
   STRIPE_PUBLISHABLE_KEY=pk_...
   STRIPE_SECRET_KEY=sk_...
   STRIPE_WEBHOOK_SECRET=whsec_...
   # Optional, comma-separated browser origins for a separate frontend deployment
   CORS_ORIGIN=https://your-app.example
   ```

   Generate `SESSION_SECRET` with a cryptographically secure password generator. Do not use
   `VITE_` for server secrets, and configure the same values in the deployment provider.
3. Run the app:
   `npm run dev`
