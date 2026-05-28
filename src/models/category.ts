import mongoose, { Schema } from 'mongoose';
import { ICategory } from '../types/products';

const categorySchema = new Schema<ICategory>(
  {
    handle: {
      type: String,
      required: true,
      trim: true,
      unique: true,
      lowercase: true,
      match: /^[a-z0-9]+(?:-[a-z0-9]+)*$/,
    },
    title: {
      type: String,
      required: true,
    },
  },
  { timestamps: true }
);

export default mongoose.model<ICategory>('Category', categorySchema);
