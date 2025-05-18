import { Request, Response, NextFunction } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import User from '../models/user';

dotenv.config();

export const createUser = async (req: Request, res: Response, next: NextFunction) => {
  const { email, password } = req.body;
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
      password: hashedPassword,
    });

    await newUser.save();

    const token = jwt.sign(
      { email: newUser.email, id: newUser._id },
      process.env.JWT_SECRET as string,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      token,
      user: { id: newUser._id, email: newUser.email },
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

    const token = jwt.sign(
      { email: loadedUser.email, id: loadedUser._id },
      process.env.JWT_SECRET as string,
      { expiresIn: '7d' }
    );

    res.status(200).json({
      token,
      user: { id: loadedUser._id, email: loadedUser.email },
      message: 'User authenticated successfully!',
    });
  } catch (error: any) {
    if (!error.statusCode) error.statusCode = 500;
    next(error);
  }
};

export const getUsers = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const users = await User.find();
    res.status(200).json({ users });
  } catch (err: any) {
    if (!err.statusCode) err.statusCode = 500;
    next(err);
  }
};

export const getUser = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = req.params.userId;
    const user = await User.findById(userId);
    if (!user) {
      const error = new Error('User not found') as any;
      error.statusCode = 404;
      throw error;
    }
    res.status(200).json({ user });
  } catch (err: any) {
    if (!err.statusCode) err.statusCode = 500;
    next(err);
  }
};
