import { oauthSignupOrLogin } from '../../lib/utils/auth';
import { Profile, VerifyCallback } from 'passport-google-oauth20';
const GoogleStrategy = require('passport-google-oauth20').Strategy;
import passport from 'passport';
import dotenv from 'dotenv';
dotenv.config();

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    async (accessToken: string, refreshToken: string, profile: Profile, done: VerifyCallback) => {
      try {
        const user = await oauthSignupOrLogin(profile);
        done(null, user);
      } catch {
        return done(null, false);
      }
    }
  )
);
