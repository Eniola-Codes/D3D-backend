//AUTHENTICATION ENDPOINTS
export const USER = {
  base: '/api/user',
  branches: { getUser: '/' },
};
export const AUTH = {
  base: '/api/auth',
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
