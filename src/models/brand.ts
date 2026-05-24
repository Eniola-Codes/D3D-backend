import mongoose, { Schema } from 'mongoose';
import { IBrand } from '../types/products';

const brandSchema = new Schema<IBrand>(
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
    logo: {
      type: String,
    },

    website: {
      type: String,
      required: true,
    },
    currency: {
      type: String,
      required: true,
    },
    shipping: {
      cost: { type: Number },
      deliveryTime: { type: String },
    },
  },
  { timestamps: true }
);

export default mongoose.model<IBrand>('Brand', brandSchema);
