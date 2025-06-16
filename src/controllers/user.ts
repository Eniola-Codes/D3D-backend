import { Request, Response, NextFunction } from 'express';
import User from '../models/user';

export const getUser = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const email = (req.user as { email: string }).email;

    const user = await User.findOne({ email });
    if (!user) {
      res.status(401).json({
        message: 'No user found, please try again',
      });
      return;
    }

    res.status(200).json({
      user: { email: user.email, name: user.name, id: user._id, avatar: user.avatar },
      message: 'User found successfully!',
    });
  } catch (err: any) {
    if (!err.statusCode) err.statusCode = 500;
    next(err);
  }
};
