import mongoose from 'mongoose';

export interface IProduct {
  handle: string;
  title: string;
  url: string;
  description: string;
  options: IVariantOption[][];
  featuredImage: string;
  rating: number;
  currency: string;
  shipping: IShipping;
  priceRange: IPriceRange;
  seo: ISEO;
  reviews: IReview[];
  variants: mongoose.Types.ObjectId[];
  brand: IBrand;
  categories: mongoose.Types.ObjectId[];
  createdAt: Date;
  updatedAt: Date;
}

export interface IVariant {
  handle: string;
  sku: string;
  url: string;
  price: number;
  inStock: boolean;
  images: string[];
  options: IVariantOption[];
  product: mongoose.Types.ObjectId;
  createdAt: Date;
  updatedAt: Date;
}

export interface IVariantOption {
  title: string;
  value: string;
}

export interface IBrand {
  handle: string;
  title: string;
  logo: string;
  website: string;
  shipping: IShipping;
  createdAt: Date;
  updatedAt: Date;
}

export interface ICategory {
  handle: string;
  title: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface IReview {
  review: string;
  rating: number;
  name: string;
}

export interface IPriceRange {
  minVariantPrice: number;
  maxVariantPrice: number;
}

export interface ISEO {
  title: string;
  description: string;
}

export interface IShipping {
  cost: number;
  deliveryTime: string;
}
