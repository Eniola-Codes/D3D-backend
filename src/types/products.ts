import mongoose from 'mongoose';

export interface IProduct {
  handle: string;
  title: string;
  url: string;
  description: string;
  options: string[];
  featuredImage: string;
  rating: number;
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

export interface IBrand {
  handle: string;
  title: string;
  logo: string;
  website: string;
  currency: string;
  shipping: IShipping;
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

export interface IVariant {
  id: string;
  title: string;
  price: number;
  compareAtPrice: number;
  available: boolean;
  sku: string;
  barcode: string;
  images: string[];
}

export interface IShipping {
  cost: number;
  deliveryTime: string;
}

