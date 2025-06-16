import User from '../../models/user';
import redis from '../../services/redis';
import { blacklist, expire, sevenDays, sevenDaysSeconds } from '../constants';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { IUser } from '../../types/user';
dotenv.config();

export const oauthSignupOrLogin = async (profile: any) => {
  const email = profile.emails?.[0].value;
  const providerId = profile.id;
  const providerType = profile.provider;

  const user = await User.findOne({
    email,
  });

  if (user) {
    if (user.provider?.id === providerId) {
      return user;
    } else {
      throw new Error();
    }
  }

  const newUser = await User.create({
    name: profile.displayName,
    email,
    avatar: profile.photos?.[0].value,
    provider: { id: providerId, type: providerType },
  });

  return newUser;
};

export const blackListToken = async (token: string) => {
  await redis.set(token, blacklist, expire, sevenDaysSeconds);
};

export const generateJwt = (user: IUser) => {
  const token = jwt.sign({ email: user.email, id: user._id }, process.env.JWT_SECRET as string, {
    expiresIn: sevenDays,
  });

  return token;
};
