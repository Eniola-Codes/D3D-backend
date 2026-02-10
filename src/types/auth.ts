import { JwtPayload } from 'jsonwebtoken';
import { Document } from 'mongoose';

export interface IOTP extends Document {
  email: string;
  otpHash: string;
  expiresAt: Date;
  createdAt?: Date;
  updatedAt?: Date;
}

export interface isAuthPayload extends JwtPayload {
  id: string;
  email: string;
}
