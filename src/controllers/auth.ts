import { Request, Response, NextFunction } from 'express';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';
import User from '../models/user';
import { sendEmail } from '../services/email';
import { getOtpView } from '../views/emails/get-otp';
import { createAndStoreOTP, verifyOTP } from '../lib/utils/otp';
import { resetPasswordView } from '../views/emails/reset-password';
import { blackListToken, generateJwt } from '../lib/utils/auth';
import {
  CANNOT_USE_YOUR_PREVIOUS_PASSWORD,
  EMAIL_ALREADY_USED,
  EMAIL_NOT_ASSOCIATED_WITH_ACCOUNT,
  EMAIL_SENT_SUCCESSFULLY,
  INVALID_EMAIL_OR_PASSWORD,
  LOGOUT_SUCCESSFUL,
  LOGOUT_UNSUCCESSFUL,
  OTP_EXPIRED_OR_INVALID,
  OTP_VERIFIED_SUCCESSFULLY,
  PASSWORD_CHANGED_SUCCESSFULLY,
  PASSWORD_RESET_SUCCESSFUL,
  RESET_PASSWORD_TIMED_OUT,
  SOMETHING_WENT_WRONG,
  USER_AUTHENTICATED_SUCCESSFULLY,
  USER_CREATED_SUCCESSFULLY,
  YOUR_PASSWORD_RESET_CODE,
} from '../lib/constants/messages';

dotenv.config();

export const signup = async (req: Request, res: Response, next: NextFunction) => {
  const { email, password, name } = req.body;
  let newUser: any;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      res.status(409).json({
        message: EMAIL_ALREADY_USED,
      });
      return;
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    newUser = new User({
      email,
      name,
      password: hashedPassword,
    });

    await newUser.save();

    const token = generateJwt(newUser);

    res.status(201).json({
      token,
      user: { id: newUser._id, email: newUser.email, name: newUser.name },
      message: USER_CREATED_SUCCESSFULLY,
    });
  } catch (error: any) {
    if (!error.statusCode) error.statusCode = 500;
    next(error);
  }
};

export const login = async (req: Request, res: Response, next: NextFunction) => {
  const { email, password } = req.body;
  let loadedUser: any;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      res.status(401).json({
        message: INVALID_EMAIL_OR_PASSWORD,
      });
      return;
    }

    loadedUser = user;
    const isEqual = await bcrypt.compare(password, user.password);
    if (!isEqual) {
      res.status(401).json({
        message: INVALID_EMAIL_OR_PASSWORD,
      });
      return;
    }

    const token = generateJwt(loadedUser);

    res.status(200).json({
      token,
      user: { id: loadedUser._id, email: loadedUser.email, name: loadedUser.name },
      message: USER_AUTHENTICATED_SUCCESSFULLY,
    });
  } catch (error: any) {
    if (!error.statusCode) error.statusCode = 500;
    next(error);
  }
};

export const logout = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const token = (req.user as { token: string }).token;

    if (!token) {
      res.status(401).json({
        message: LOGOUT_UNSUCCESSFUL,
      });
      return;
    }

    await blackListToken(token);

    res.status(200).json({ message: LOGOUT_SUCCESSFUL });
  } catch (err: any) {
    if (!err.statusCode) err.statusCode = 500;
    next(err);
  }
};

export const forgetPassword = async (req: Request, res: Response, next: NextFunction) => {
  const { email } = req.body;
  const fromEmail = process.env.RESEND_EMAIL_USER as string;
  const subject = YOUR_PASSWORD_RESET_CODE;
  
  try {
    const user = await User.findOne({ email });
    if (!user) {
      res.status(401).json({
        message: EMAIL_NOT_ASSOCIATED_WITH_ACCOUNT,
      });
      return;
    }
    const token = await createAndStoreOTP(email);
    if (!token) {
      res.status(400).json({
        message: SOMETHING_WENT_WRONG,
      });
      return;
    }

    const mailOptions = {
      from: fromEmail,
      to: email,
      subject: subject,
      html: getOtpView(token),
    };

    const emailSuccess = await sendEmail(mailOptions);
    
    if (!emailSuccess) {
      res.status(400).json({
        message: SOMETHING_WENT_WRONG,
      });
      return;
    }

    res.status(200).json({
      email: email,
      message: EMAIL_SENT_SUCCESSFULLY,
    });
  } catch (error: any) {
    if (!error.statusCode) error.statusCode = 500;
    next(error);
  }
};

export const verifyOtp = async (req: Request, res: Response, next: NextFunction) => {
  const { email, otp } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      res.status(401).json({
        message: EMAIL_NOT_ASSOCIATED_WITH_ACCOUNT,
      });
      return;
    }
    const verifyToken = await verifyOTP(email, otp, false);
    if (!verifyToken) {
      res.status(400).json({
        message: OTP_EXPIRED_OR_INVALID,
      });
      return;
    }

    res.status(200).json({
      email: email,
      message: OTP_VERIFIED_SUCCESSFULLY,
    });
  } catch (error: any) {
    if (!error.statusCode) error.statusCode = 500;
    next(error);
  }
};

export const resetPassword = async (req: Request, res: Response, next: NextFunction) => {
  const { email, password, otp } = req.body;
  const fromEmail = process.env.RESEND_EMAIL_USER as string;
  const subject = PASSWORD_RESET_SUCCESSFUL;

  try {
    const user = await User.findOne({ email });
    if (!user) {
      res.status(401).json({
        message: EMAIL_NOT_ASSOCIATED_WITH_ACCOUNT,
      });
      return;
    }

    const hashedNewPassword = await bcrypt.hash(password, 12);
    const isPasswordEqual = await bcrypt.compare(password, user.password);
    if (isPasswordEqual) {
      res.status(400).json({
        message: CANNOT_USE_YOUR_PREVIOUS_PASSWORD,
      });
      return;
    }

    const verifyToken = await verifyOTP(email, otp, true);
    if (!verifyToken) {
      res.status(400).json({
        message: RESET_PASSWORD_TIMED_OUT,
      });
      return;
    }

    const mailOptions = {
      from: fromEmail,
      to: email,
      subject: subject,
      html: resetPasswordView(email),
    };

    const emailSuccess = await sendEmail(mailOptions);
    if (!emailSuccess) {
      res.status(400).json({
        message: SOMETHING_WENT_WRONG,
      });
      return;
    }

    user.password = hashedNewPassword;
    await user.save();

    res.status(200).json({
      email: email,
      message: PASSWORD_CHANGED_SUCCESSFULLY,
    });
  } catch (error: any) {
    if (!error.statusCode) error.statusCode = 500;
    next(error);
  }
};
