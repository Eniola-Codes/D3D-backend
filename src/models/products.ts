import mongoose, { Schema } from 'mongoose';
import { IProduct } from '../types/products';
import dotenv from 'dotenv';
dotenv.config();

const productSchema: Schema<IProduct> = new Schema(
  {
    handle: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      match: /^[a-z0-9]+(?:-[a-z0-9]+)*$/,
    },
    title: {
      type: String,
      required: true,
    },
    url: {
      type: String,
      required: true,
    },
    description: {
      type: String,
    },
    shortDescription: {
      type: String,
    },
    features: {
      type: [{ title: { type: String }, value: { type: String } }],
    },
    attributes: {
      type: [{ title: { type: String }, value: { type: String } }],
    },
    currency: {
      type: String,
      required: true,
    },
    priceRange: { 
      minVariantPrice: { type: Number },
      maxVariantPrice: { type: Number },
    },
    options: {
      type: [[{ title: { type: String }, value: { type: String } }]],
      default: [],
    },
    featuredImage: {
      type: String,
      required: true,
    },
    seo: {
      title: { type: String },
      description: { type: String },
    },
    shipping: {
      cost: { type: Number },
      deliveryTime: { type: String },
    },
    brand: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Brand',
      required: true,
    },
    variants: {
      type: [
        {
          type: mongoose.Schema.Types.ObjectId,
          ref: 'Variant',
        },
      ],
      default: [],
    },
    categories: {
      type: [
        {
          type: mongoose.Schema.Types.ObjectId,
          ref: 'Category',
        },
      ],
      default: [],
    },
  },
  { timestamps: true }
);

export default mongoose.model<IProduct>('Product', productSchema);
