import { Request, Response, NextFunction } from 'express';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';
import User from '../models/user';
import { sendEmail } from '../services/email';
import { getOtpView } from '../views/emails/get-otp';
import { createAndStoreOTP, verifyOTP } from '../services/otp';
import { resetPasswordView } from '../views/emails/reset-password';
import { blackListToken, generateJwt } from '../lib/utils/auth';

dotenv.config();

export const verifyAuth = async (req: Request, res: Response, next: NextFunction) => {
  try {
    res.status(200).json({
      message: 'User authenticated successfully!',
    });
    return;
  } catch (err: any) {
    if (!err.statusCode) err.statusCode = 500;
    next(err);
  }
};

export const signup = async (req: Request, res: Response, next: NextFunction) => {
  const { email, password, name } = req.body;
  let newUser: any;

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      res.status(409).json({
        message: 'The email has already been used, please use another email.',
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
      message: 'User created successfully!',
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
        message: 'Invalid email or password, please try again.',
      });
      return;
    }

    loadedUser = user;
    const isEqual = await bcrypt.compare(password, user.password);
    if (!isEqual) {
      res.status(401).json({
        message: 'Invalid email or password, please try again.',
      });
      return;
    }

    const token = generateJwt(loadedUser);

    res.status(200).json({
      token,
      user: { id: loadedUser._id, email: loadedUser.email, name: loadedUser.name },
      message: 'User authenticated successfully!',
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
        message: 'Logout unsuccessful, please try again',
      });
      return;
    }

    await blackListToken(token);

    res.status(200).json({ message: 'Logout successful' });
  } catch (err: any) {
    if (!err.statusCode) err.statusCode = 500;
    next(err);
  }
};

export const forgetPassword = async (req: Request, res: Response, next: NextFunction) => {
  const { email } = req.body;
  const fromEmail = process.env.EMAIL_USER as string;
  const subject = 'Your Password Reset Code';

  try {
    const user = await User.findOne({ email });
    if (!user) {
      res.status(401).json({
        message: 'This email is not associated with an account, please try again.',
      });
      return;
    }
    const token = await createAndStoreOTP(email);
    if (!token) {
      res.status(400).json({
        message: 'Something went wrong, please try again.',
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
        message: 'Something went wrong, please try again.',
      });
      return;
    }

    res.status(200).json({
      email: email,
      message: 'Email sent successfully!',
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
        message: 'This email is not associated with an account, please try again.',
      });
      return;
    }
    const verifyToken = await verifyOTP(email, otp, false);
    if (!verifyToken) {
      res.status(400).json({
        message: 'The Otp code is expired or invalid, please resend an OTP and try again',
      });
      return;
    }

    res.status(200).json({
      email: email,
      message: 'OTP verified successfully!',
    });
  } catch (error: any) {
    if (!error.statusCode) error.statusCode = 500;
    next(error);
  }
};

export const resetPassword = async (req: Request, res: Response, next: NextFunction) => {
  const { email, password, otp } = req.body;
  const fromEmail = process.env.EMAIL_USER as string;
  const subject = 'Password Reset Successful';

  try {
    const user = await User.findOne({ email });
    if (!user) {
      res.status(401).json({
        message: 'This email is not associated with an account, please try again.',
      });
      return;
    }

    const hashedNewPassword = await bcrypt.hash(password, 12);
    const isPasswordEqual = await bcrypt.compare(password, user.password);
    if (isPasswordEqual) {
      res.status(400).json({
        message: 'You cannot use your previous password, please use a new password',
      });
      return;
    }

    const verifyToken = await verifyOTP(email, otp, true);
    if (!verifyToken) {
      res.status(400).json({
        message: 'The reset password process has timed out, please go back and try again',
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
        message: 'Something went wrong, please try again.',
      });
      return;
    }

    user.password = hashedNewPassword;
    await user.save();

    res.status(200).json({
      email: email,
      message: 'Password changed successfully!',
    });
  } catch (error: any) {
    if (!error.statusCode) error.statusCode = 500;
    next(error);
  }
};
