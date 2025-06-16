import express, { Request, Response, NextFunction } from 'express';
import bodyParser from 'body-parser';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import authRoutes from './routes/auth';
import userRoutes from './routes/user';
import passport from 'passport';
import { generateJwt } from './lib/utils/auth';
require('./services/auth/google');

dotenv.config();

const FRONTEND_URL = process.env.FRONTEND_APPLICATION_URL;

const app = express();

app.use(bodyParser.json());

app.use((req: Request, res: Response, next: NextFunction) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'OPTIONS, GET, POST, PUT, PATCH, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  next();
});

app.use('/api/auth', authRoutes);
app.use('/api/user', userRoutes);
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', (req, res, next) => {
  passport.authenticate('google', { session: false }, async (err, user) => {
    if (err || !user) {
      return res.redirect(`${FRONTEND_URL}/account?auth=login&error=true`);
    }
    const token = generateJwt(user);
    return res.redirect(`${FRONTEND_URL}/account?auth=login&token=${token}`);
  })(req, res, next);
});

app.use((error: any, req: Request, res: Response) => {
  const status = error.statusCode || 500;
  const message = error.message;
  const data = error.data;
  res.status(status).json({ message, data });
});

mongoose
  .connect(process.env.MONGODB_CONNECTION as string)
  .then(() => {
    app.listen(8080, () => {});
  })
  .catch(() => {});
