import express, { Request, Response, NextFunction } from 'express';
import bodyParser from 'body-parser';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import authRoutes from './routes/auth';
import userRoutes from './routes/user';
import passport from 'passport';
import { generateJwt } from './lib/utils/auth';
import './services/auth/google';
import { AUTH, USER } from './lib/constants/endpoints';
import { ERROR_REDIRECT_URL, SUCCESS_REDIRECT_URL } from './lib/constants';
import { DATABASE_CONNECTION_FAILED, SERVER_RUNNING_ON_PORT } from './lib/constants/messages';

dotenv.config();

const FRONTEND_URL = process.env.FRONTEND_APPLICATION_URL;
const PORT = process.env.PORT as string;
const MONGODB_CONNECTION = process.env.MONGODB_CONNECTION as string;

const app = express();

app.use(bodyParser.json());

app.use((req: Request, res: Response, next: NextFunction) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'OPTIONS, GET, POST, PUT, PATCH, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  next();
});

app.use(AUTH.base, authRoutes);
app.use(USER.base, userRoutes);
app.get(AUTH.googleAuth, passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get(AUTH.googleAuthCallback, (req: Request, res: Response, next: NextFunction) => {
  passport.authenticate('google', { session: false }, async (err: any, user: any) => {
    if (err || !user) {
      return res.redirect(`${FRONTEND_URL}${ERROR_REDIRECT_URL}`);
    }
    const token = generateJwt(user);
    return res.redirect(`${FRONTEND_URL}${SUCCESS_REDIRECT_URL}${token}`);
  })(req, res, next);
});

app.use((error: any, req: Request, res: Response, _next: NextFunction): void => {
  const status = error.statusCode || 500;
  const message = error.message;
  const data = error.data;
  res.status(status).json({ message, data });
});

export default app;

if (require.main === module) {
  mongoose
    .connect(MONGODB_CONNECTION, {
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    })
    .then(() => {
      app.listen(PORT, () => {
        console.log(`${SERVER_RUNNING_ON_PORT} ${PORT}`);
      });
    })
    .catch(err => {
      console.error(`${DATABASE_CONNECTION_FAILED}`, err);
      process.exit(1);
    });
}
