import mongoose, { Schema } from 'mongoose';
import { IBrand } from '../types/products';

const brandSchema = new Schema<IBrand>(
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
    logo: {
      type: String,
    },
    website: {
      type: String,
      required: true,
    },
    shipping: {
      cost: { type: Number },
      deliveryTime: { type: String },
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

brandSchema.index({ handle: 1 }, { unique: true });

export default mongoose.model<IBrand>('Brand', brandSchema);
