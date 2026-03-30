import mongoose, { Schema } from 'mongoose';
import { IUser } from '../types/user';
import dotenv from 'dotenv';
dotenv.config();

const userSchema: Schema<IUser> = new Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
    },
    name: { type: String },
    password: {
      type: String,
    },
    provider: {
      id: { type: String },
      type: { type: String, enum: ['google', 'github'] },
    },
    avatar: { type: String },
    store_token: {
      type: {
        shopify: {
          type: String,
          default: process.env.SHOPIFY_APP_ACCESS_TOKEN,
        },
      },
      default: {},
    },
  },
  { timestamps: true }
);

export default mongoose.model<IUser>('User', userSchema);
