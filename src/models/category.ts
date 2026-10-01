import mongoose, { Schema } from 'mongoose';
import { ICategory } from '../types/products';

const categorySchema = new Schema<ICategory>(
  {
    handle: {
      type: String,
      required: true,
      trim: true,
      lowercase: true,
      match: /^[a-z0-9]+(?:-[a-z0-9]+)*$/,
    },
    title: {
      type: String,
      required: true,
    },
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
  },
  { timestamps: true }
);

categorySchema.index({ handle: 1 }, { unique: true });

export default mongoose.model<ICategory>('Category', categorySchema);
