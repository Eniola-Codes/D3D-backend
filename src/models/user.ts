import mongoose, { Schema } from 'mongoose';
import { IUser } from '../types/user';

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
  },
  { timestamps: true }
);

export default mongoose.model<IUser>('User', userSchema);
