import express, { Router } from 'express';
import { body } from 'express-validator';
import * as authController from '../controllers/auth';
import isAuth from '../middleware/auth';
import { validate } from '../middleware/validation';
import {
  INVALID_EMAIL,
  NAME_CHARACTERS_LENGTH,
  OTP_CHARACTERS_LENGTH,
  PASSWORD_CHARACTERS_LENGTH,
} from '../lib/constants/messages';
import { AUTH } from '../lib/constants/endpoints';

const router: Router = express.Router();

router.post(
  AUTH.branches.signup,
  [
    body('name').trim().isLength({ min: 3 }).withMessage(NAME_CHARACTERS_LENGTH),
    body('email').isEmail().withMessage(INVALID_EMAIL).normalizeEmail(),
    body('password').trim().isLength({ min: 8 }).withMessage(PASSWORD_CHARACTERS_LENGTH),
  ],
  validate,
  authController.signup
);

router.post(
  AUTH.branches.forgetPassword,
  [body('email').isEmail().withMessage(INVALID_EMAIL).normalizeEmail()],
  validate,
  authController.forgetPassword
);

router.post(
  AUTH.branches.verifyOtp,
  [body('otp').trim().isLength({ min: 6 }).withMessage(OTP_CHARACTERS_LENGTH)],
  validate,
  authController.verifyOtp
);

router.put(
  AUTH.branches.resetPassword,
  [body('password').trim().isLength({ min: 8 }).withMessage(PASSWORD_CHARACTERS_LENGTH)],
  validate,
  authController.resetPassword
);

router.post(AUTH.branches.login, authController.login);

router.post(AUTH.branches.logout, isAuth, authController.logout);

export default router;
