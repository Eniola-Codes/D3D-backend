import mongoose, { Schema } from 'mongoose';
import { IOTP } from '../types/auth';

const otpSchema: Schema<IOTP> = new Schema(
  {
    email: { type: String, required: true },
    otpHash: { type: String, required: true },
    expiresAt: { type: Date, required: true },
  },
  { timestamps: true }
);

export default mongoose.model<IOTP>('Otp', otpSchema);
