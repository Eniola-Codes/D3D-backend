import mongoose, { Schema } from 'mongoose';
import { IVariant } from '../types/products';

const variantSchema = new Schema<IVariant>(
  {
    handle: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      match: /^[a-z0-9]+(?:-[a-z0-9]+)*$/,
    },
    sku: {
      type: String,
      unique: true,
      required: true,
    },
    price: {
      type: Number,
      required: true,
      min: 0,
    },
    inStock: {
      type: Boolean,
      required: true,
      default: true,
    },
    images: {
      type: [String],
      default: [],
    },
    options: [
      {
        title: { type: String, required: true },
        values: [{ type: String }],
      },
    ],
    product: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Product',
      required: true,
    },
  },
  { timestamps: true }
);

export default mongoose.model<IVariant>('Variant', variantSchema);
