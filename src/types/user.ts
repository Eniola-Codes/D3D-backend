import { Document } from 'mongoose';

export interface IUser extends Document {
  email: string;
  password: string;
  provider: { id: string; type: string };
  avatar: string;
  name: string;
  createdAt?: Date;
  updatedAt?: Date;
}
