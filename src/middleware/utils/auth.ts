import { NextFunction, Request, Response } from 'express';
import redis from '../../services/redis';
import jwt, { JwtPayload } from 'jsonwebtoken';
import { INVALID_TOKEN, SOMETHING_WENT_WRONG, TOKEN_EXPIRED, UNAUTHORIZED_USER } from '../../lib/constants/messages';

export const istokenValid = async (req: Request, res: Response) => {
  const authHeader = req.get('Authorization');

  if (!authHeader) {
    return res.status(401).json({ message: UNAUTHORIZED_USER });
  }

  const token = authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ message: UNAUTHORIZED_USER });
  }

  const isBlacklisted = await redis.get(token);
  if (isBlacklisted) {
    return res.status(401).json({ message: UNAUTHORIZED_USER });
  }

  return token;
};

export const decodeToken = async (token: string, req: Request, res: Response, next: NextFunction) => {
  const decodedToken = jwt.verify(token, process.env.JWT_SECRET as string);

  if (decodedToken && typeof decodedToken === 'object') {
    req.user = {
      ...(decodedToken as JwtPayload),
      token: token,
    };
    next();
  } else {
    return res.status(401).json({ message: UNAUTHORIZED_USER });
  };
};

export const handleTokenError = (err: any, res: Response) => {
  if (err.name === 'TokenExpiredError') {
    return res.status(401).json({ message: TOKEN_EXPIRED });
  }

  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({ message: INVALID_TOKEN });
  }

  return res.status(500).json({ message: SOMETHING_WENT_WRONG });
};
