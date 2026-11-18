import axios from 'axios';
import { AppDispatch, RootState } from '../store.ts';
import {
  createOrderRequest,
  createOrderSuccess,
  myOrdersRequest,
  myOrdersSuccess,
  orderDetailsRequest,
  orderDetailsSuccess,
} from '../slices/orderSlice.ts';
import { clearCartLocal } from '../slices/cartSlice.ts';

export const createOrder =
  (orderPayload: any) => async (dispatch: AppDispatch) => {
    dispatch(createOrderRequest());
    try {
      const { data } = await axios.post('/api/v1/eats/orders/new', orderPayload);
      if (data?.order && data.order._id) {
        dispatch(createOrderSuccess(data.order));
        dispatch(clearCartLocal());
        return data.order;
      }
    } catch (error) {
      throw error;
    }
  };

export const myOrders = () => async (dispatch: AppDispatch, getState: () => RootState) => {
  dispatch(myOrdersRequest());
  try {
    const { data } = await axios.get('/api/v1/eats/orders/me/myOrders');
    if (data && Array.isArray(data.orders)) {
      dispatch(myOrdersSuccess(data.orders));
      return;
    }
  } catch {
    // Fallback to existing orders in Redux state
  }
  const existing = getState().order.orders;
  dispatch(myOrdersSuccess(Array.isArray(existing) ? existing : []));
};

export const getOrderDetails =
  (id: string) => async (dispatch: AppDispatch, getState: () => RootState) => {
    dispatch(orderDetailsRequest());
    try {
      const { data } = await axios.get(`/api/v1/eats/orders/${id}`);
      if (data?.order && data.order._id) {
        dispatch(orderDetailsSuccess(data.order));
        return;
      }
    } catch {
      // Fallback to finding order in Redux state
    }

    const found =
      (getState().order.orders || []).find((o) => o._id === id) ||
      getState().order.orders?.[0];
    if (found) {
      dispatch(orderDetailsSuccess(found));
    }
  };
