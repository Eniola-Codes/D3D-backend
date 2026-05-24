import { Request, Response, NextFunction } from 'express';
import Brand from '../models/brand';
import Product from '../models/products';
import {
  PRODUCT_UPDATED_SUCCESSFULLY,
  PRODUCTS_FETCHED_SUCCESSFULLY,
} from '../lib/constants/messages';
import { generateBrandHandle, generateProductHandle } from '../lib/utils/product';
import { DEFAULT_PAGE, PAGE_SIZE } from '../lib/constants';

export const createProduct = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const {
      title,
      url,
      description,
      options,
      featuredImage,
      shipping,
      rating,
      reviews,
      brand,
      seo,
    } = req.body;

    let brandDocument;

    const brandHandle = generateBrandHandle(brand.title);
    const existingBrand = await Brand.findOne({ handle: brandHandle });

    if (existingBrand) {
      brandDocument = existingBrand;
    } else {
      brandDocument = new Brand({
        handle: brandHandle,
        title: brand.title,
        logo: brand.logo,
        website: brand.website,
        currency: brand.currency,
        shipping: brand.shipping,
      });

      await brandDocument.save();
    }

    const productHandle = generateProductHandle(title, brandDocument.handle);
    const productDocument = await Product.findOneAndUpdate(
      { handle: productHandle },
      {
        $set: {
          handle: productHandle,
          title,
          url,
          description,
          options,
          featuredImage,
          shipping,
          rating,
          reviews,
          seo,
          brand: brandDocument._id,
        },
      },
      {
        new: true,
        upsert: true,
      }
    );

    res.status(200).json({
      product: {
        id: productDocument._id,
        title: productDocument.title,
        handle: productDocument.handle,
        url: productDocument.url,
        description: productDocument.description,
        options: productDocument.options,
        featuredImage: productDocument.featuredImage,
        shipping: productDocument.shipping,
        rating: productDocument.rating,
        reviews: productDocument.reviews,
        seo: productDocument.seo,
        brand: productDocument.brand,
      },
      message: PRODUCT_UPDATED_SUCCESSFULLY,
    });
  } catch (err: any) {
    if (!err.statusCode) err.statusCode = 500;
    next(err);
  }
};

export const getProducts = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const page = Math.max(DEFAULT_PAGE, Number(req.query.page) || DEFAULT_PAGE);

    const [products, count] = await Promise.all([
      Product.find()
        .select('title handle featuredImage rating description brand')
        .populate('brand', 'handle logo currency title')
        .sort({ createdAt: -1 })
        .skip((page - 1) * PAGE_SIZE)
        .limit(PAGE_SIZE)
        .lean(),
      Product.countDocuments(),
    ]);

    res.status(200).json({
      products,
      pagination: {
        currentPage: page,
        nextPage: page + 1,
        prevPage: page - 1,
        totalCount: count,
        totalPages: Math.ceil(count / PAGE_SIZE) || 0,
      },
      message: PRODUCTS_FETCHED_SUCCESSFULLY,
    });
  } catch (err: any) {
    if (!err.statusCode) err.statusCode = 500;
    next(err);
  }
};
