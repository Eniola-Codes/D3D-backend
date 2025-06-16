export interface IOTP extends Document {
  email: string;
  otpHash: string;
  expiresAt: Date;
  createdAt?: Date;
  updatedAt?: Date;
}
