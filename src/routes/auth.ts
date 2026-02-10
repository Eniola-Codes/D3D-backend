import express, { Router } from 'express';
import { body } from 'express-validator';
import * as authController from '../controllers/auth';
import isAuth from '../middleware/auth';

const router: Router = express.Router();

router.post(
  '/signup',
  [
    body('name')
      .trim()
      .isLength({ min: 3 })
      .withMessage('Name must be at least 3 characters long.'),
    body('email').isEmail().withMessage('Please enter a valid email.').normalizeEmail(),
    body('password')
      .trim()
      .isLength({ min: 8 })
      .withMessage('Password must be at least 8 characters long.'),
  ],
  authController.signup
);

router.post(
  '/forget-password',
  [body('email').isEmail().withMessage('Please enter a valid email.').normalizeEmail()],
  authController.forgetPassword
);

router.post(
  '/verify-otp',
  [body('otp').trim().isLength({ min: 6 }).withMessage('OTP must be 6 numbers long.')],
  authController.verifyOtp
);

router.put(
  '/reset-password',
  [
    body('password')
      .trim()
      .isLength({ min: 8 })
      .withMessage('Password must be at least 8 characters long.'),
  ],
  authController.resetPassword
);

router.post('/login', authController.login);

router.post('/logout', isAuth, authController.logout);

export default router;