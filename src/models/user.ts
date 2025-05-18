import mongoose, { Schema } from 'mongoose';
import { IUser } from '../types/user';

const userSchema: Schema<IUser> = new Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
    },
    password: {
      type: String,
      required: true,
    },
  },
  { timestamps: true }
);

export default mongoose.model<IUser>('User', userSchema);
