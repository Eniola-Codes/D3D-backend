import { Request, Response, NextFunction } from 'express';
import dotenv from 'dotenv';
import { decodeToken, handleTokenError, istokenValid } from './utils/auth';
dotenv.config();

const isAuth = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const token = await istokenValid(req, res);
    if (typeof token !== 'string') {
      return;
    }
    await decodeToken(token, req, res, next);
  } catch (err: any) {
    handleTokenError(err, res);
  }
};

export default isAuth;
