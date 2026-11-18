import { createRoot } from 'react-dom/client';
import { Provider } from 'react-redux';
import { Elements } from '@stripe/react-stripe-js';
import { loadStripe } from '@stripe/stripe-js';
import axios from 'axios';
import store from './redux/store.ts';
import App from './App.tsx';
import './index.css';

axios.defaults.withCredentials = true;
axios.interceptors.request.use((config) => {
  if (['post', 'put', 'patch', 'delete'].includes((config.method || '').toLowerCase())) {
    const csrfToken = document.cookie.split('; ').find((entry) => entry.startsWith('orderit_csrf='))?.split('=')[1];
    if (csrfToken) {
      config.headers = config.headers || {};
      config.headers['x-csrf-token'] = decodeURIComponent(csrfToken);
    }
  }
  return config;
});

async function bootstrap() {
  // Stripe publishable keys are public by design. The server reads STRIPE_PUBLISHABLE_KEY
  // from Vercel and returns only that public key; the secret key never reaches the browser.
  let stripePromise: ReturnType<typeof loadStripe> | null = null;
  try {
    const response = await fetch('/api/v1/payment/config');
    if (response.ok) {
      const { publishableKey } = await response.json();
      if (publishableKey) stripePromise = loadStripe(publishableKey);
    }
  } catch (error) {
    console.error('Unable to load Stripe configuration:', error);
  }

  createRoot(document.getElementById('root')!).render(
    <Provider store={store}>
      <Elements stripe={stripePromise}>
        <App />
      </Elements>
    </Provider>
  );
}

void bootstrap();
