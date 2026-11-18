import axios from 'axios';
import { AppDispatch, RootState } from '../store.ts';
import {
  authRequest,
  authSuccess,
  authFail,
  logoutSuccess,
  updateProfileSuccess,
} from '../slices/userSlice.ts';
import { clearCartLocal } from '../slices/cartSlice.ts';
import { GENERATED_IMAGES } from '../../data/seedData.ts';
import { sanitizeEmail, sanitizeInput, sanitizePhone } from '../../utils/security.ts';

export const SESSION_STORAGE_KEY = 'foodgenie_user_session';

export const defaultDemoUser = {
  _id: '',
  name: '',
  email: '',
  phoneNumber: '',
  avatar: {
    public_id: 'avatar_default',
    url: GENERATED_IMAGES.avatar,
  },
  role: 'user',
  createdAt: new Date().toISOString(),
  defaultAddress: {
    address: '',
    city: '',
    postalCode: '',
    phoneNo: '',
    country: '',
  },
};

/**
 * Loads the active user session.
 * For a first-time user (no session stored in localStorage), does NOT ask or auto-login.
 * Once a person has logged in, remembers their session until they explicitly sign out.
 */
export const loadUser = () => async (dispatch: AppDispatch) => {
  try {
    const { data } = await axios.get('/api/v1/users/me', { withCredentials: true });
    if (data?.authenticated && data?.user?._id) {
      localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(data.user));
      dispatch(authSuccess(data.user));
      return;
    }
    localStorage.removeItem(SESSION_STORAGE_KEY);
    dispatch(logoutSuccess());
  } catch {
    localStorage.removeItem(SESSION_STORAGE_KEY);
    dispatch(logoutSuccess());
  }
};

/**
 * Signs in a user and permanently remembers their session until sign out
 */
export const loginUser =
  (email: string, password: string) => async (dispatch: AppDispatch) => {
    try {
      dispatch(authRequest());
      const cleanEmail = sanitizeEmail(email);
      const cleanPassword = sanitizeInput(password, 100);

      const { data } = await axios.post('/api/v1/users/login', {
        email: cleanEmail,
        password: cleanPassword,
      }, { withCredentials: true });

      if (data?.user && data.user._id) {
        localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(data.user));
        dispatch(authSuccess(data.user));
        return true;
      }
    } catch (err: any) {
      const message = err?.response?.data?.message || 'Sign-in failed. Check your credentials and try again.';
      dispatch(authFail(message));
      return false;
    }
    dispatch(authFail('Sign-in failed. Check your credentials and try again.'));
    return false;
  };

/**
 * Registers a new diner account and saves the server-issued session.
 */
export const registerUser =
  (userData: { name: string; email: string; password: string; phoneNumber: string }) =>
  async (dispatch: AppDispatch) => {
    try {
      dispatch(authRequest());
      const cleanData = {
        name: sanitizeInput(userData.name, 60),
        email: sanitizeEmail(userData.email),
        phoneNumber: sanitizePhone(userData.phoneNumber),
        password: userData.password,
      };
      const { data } = await axios.post('/api/v1/users/signup', cleanData, { withCredentials: true });
      if (data?.user?._id) {
        localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(data.user));
        dispatch(authSuccess(data.user));
        return true;
      }
      dispatch(authFail('Account registration failed. Please try again.'));
      return false;
    } catch (err: any) {
      const message = err?.response?.data?.message || 'Account registration failed. Please try again.';
      dispatch(authFail(message));
      return false;
    }
  };

/**
 * Updates profile details including avatar image
 */
export const updateUserProfile =
  (profileData: {
    name: string;
    email: string;
    phoneNumber: string;
    address?: string;
    city?: string;
    postalCode?: string;
    avatar?: { public_id: string; url: string } | string;
  }) =>
  async (dispatch: AppDispatch, getState: () => RootState) => {
    const current = getState().user.user || defaultDemoUser;
    try {
      dispatch(authRequest());

      const cleanData: any = {
        name: sanitizeInput(profileData.name, 60),
        email: sanitizeEmail(profileData.email),
        phoneNumber: sanitizePhone(profileData.phoneNumber),
        address: profileData.address ? sanitizeInput(profileData.address, 120) : undefined,
        city: profileData.city ? sanitizeInput(profileData.city, 60) : undefined,
        postalCode: profileData.postalCode ? sanitizeInput(profileData.postalCode, 20) : undefined,
      };

      if (profileData.avatar) {
        cleanData.avatar = profileData.avatar;
      }

      const { data } = await axios.put('/api/v1/users/me/update', cleanData, {
        withCredentials: true,
      });

      if (data?.user && data.user._id) {
        try {
          localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(data.user));
        } catch (storageErr) {
          console.warn('[LocalStorage] Quota warning while caching profile:', storageErr);
        }
        dispatch(updateProfileSuccess(data.user));
        return true;
      }
    } catch {
      // Fallback local update
    }

    let newAvatar = current.avatar;
    if (profileData.avatar) {
      if (typeof profileData.avatar === 'string') {
        newAvatar = { public_id: 'avatar_custom', url: profileData.avatar };
      } else if (profileData.avatar.url) {
        newAvatar = profileData.avatar;
      }
    }

    const updated = {
      ...current,
      name: sanitizeInput(profileData.name, 60) || current.name,
      email: sanitizeEmail(profileData.email) || current.email,
      phoneNumber: sanitizePhone(profileData.phoneNumber) || current.phoneNumber,
      avatar: newAvatar,
      defaultAddress: {
        ...current.defaultAddress,
        address: profileData.address ? sanitizeInput(profileData.address, 120) : current.defaultAddress?.address || '',
        city: profileData.city ? sanitizeInput(profileData.city, 60) : current.defaultAddress?.city || '',
        postalCode: profileData.postalCode ? sanitizeInput(profileData.postalCode, 20) : current.defaultAddress?.postalCode || '',
      },
    };

    try {
      localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(updated));
    } catch (storageErr) {
      console.warn('[LocalStorage] Quota warning in fallback profile:', storageErr);
    }
    dispatch(updateProfileSuccess(updated));
    return true;
  };

/**
 * Signs out and removes stored session permanently
 */
export const logoutUser = () => async (dispatch: AppDispatch) => {
  try {
    localStorage.removeItem(SESSION_STORAGE_KEY);
    await axios.post('/api/v1/users/logout');
  } catch {
    // Ignore error
  }
  dispatch(logoutSuccess());
  dispatch(clearCartLocal());
};
