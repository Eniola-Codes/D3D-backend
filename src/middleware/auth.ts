import { Request, Response, NextFunction } from 'express';
import jwt, { JwtPayload } from 'jsonwebtoken';
import dotenv from 'dotenv';
import redis from '../services/redis';
dotenv.config();

module.exports = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const authHeader = req.get('Authorization');

    if (!authHeader) {
      return res.status(401).json({ message: 'Unauthorized. User not found.' });
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'Unauthorized. User not found.' });
    }

    const decodedToken = jwt.verify(token, process.env.JWT_SECRET as string);

    const isBlacklisted = await redis.get(token);
    if (isBlacklisted) {
      return res.status(401).json({ message: 'Unauthorized. User not found.' });
    }

    if (decodedToken && typeof decodedToken === 'object') {
      req.user = {
        ...(decodedToken as JwtPayload),
        token: token,
      };
      next();
    } else {
      return res.status(401).json({ message: 'Unauthorized. User not found.' });
    }
  } catch (err: any) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Token expired. Please log in again.' });
    }

    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({ message: 'Invalid token.' });
    }

    return res.status(500).json({ message: 'Service unavailable. Please try again.' });
  }
};
