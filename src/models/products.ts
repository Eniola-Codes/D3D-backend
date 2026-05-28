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
      required: true,
    },
    currency: {
      type: String,
      required: true,
    },
    priceRange: { 
      minVariantPrice: { type: Number },
      maxVariantPrice: { type: Number },
    },
    options: [
      {
        title: { type: String },
        values: [
          {
            type: String,
          },
        ],
      },
    ],
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
    rating: { type: Number, min: 0, max: 5 },
    reviews: [
      {
        review: { type: String },
        rating: { type: Number },
        name: { type: String },
      },
    ],
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
