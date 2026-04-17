//AUTHENTICATION ENDPOINTS
export const USER = {
  base: '/api/v1/user',
  branches: { getUser: '/' },
};
export const AUTH = {
  base: '/api/v1/auth',
  branches: {
    signup: '/signup',
    login: '/login',
    forgetPassword: '/forget-password',
    verifyOtp: '/verify-otp',
    resetPassword: '/reset-password',
    logout: '/logout',
  },
  googleAuth: '/auth/google',
  googleAuthCallback: '/auth/google/callback',
};
export const SHOPIFY = {
  base: '/api/v1/shopify',
  branches: {
    init: '/init',
    redirect: '/redirect',
    getProduct: '/getProduct',
  },
};
