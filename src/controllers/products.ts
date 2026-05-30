import { Request, Response, NextFunction } from 'express';
import Brand from '../models/brand';
import Category from '../models/category';
import Product from '../models/products';
import {
  PRODUCT_UPDATED_SUCCESSFULLY,
  PRODUCTS_FETCHED_SUCCESSFULLY,
} from '../lib/constants/messages';
import {
  buildProductFilter,
  buildProductSort,
  generateHandle,
} from '../lib/utils/product';
import { DEFAULT_PAGE, PAGE_SIZE } from '../lib/constants';
import mongoose from 'mongoose';

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
      currency,
      categories
    } = req.body;

    let brandDocument;

    const brandHandle = generateHandle(brand.title);
    const existingBrand = await Brand.findOne({ handle: brandHandle });

    if (existingBrand) {
      brandDocument = existingBrand;
    } else {
      brandDocument = new Brand({
        handle: brandHandle,
        title: brand.title,
        logo: brand.logo,
        website: brand.website,
        shipping: brand.shipping,
      });
      await brandDocument.save();
    }

    const categoryIds: mongoose.Types.ObjectId[] = [];

    for (const category of categories) {
      const handle = generateHandle(category);
      const existingCategory = await Category.findOne({ handle });
      if (existingCategory) {
        categoryIds.push(existingCategory._id);
      } else {
        const categoryDocument = new Category({ handle, title: category });
        await categoryDocument.save();
        categoryIds.push(categoryDocument._id);
      }
    }

    const productHandle = generateHandle(title, brandDocument.handle);
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
          currency,
          brand: brandDocument._id,
          categories: categoryIds,
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
        currency: productDocument.currency,
        brand: productDocument.brand,
        categories: productDocument.categories,
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
    const page = Number(req.query.page) || DEFAULT_PAGE;
    const filter = await buildProductFilter(req.query);
    const sort = buildProductSort(req.query.sort);

    if (filter === null) {
      return res.status(200).json({
        products: [],
        pagination: {
          currentPage: page,
          nextPage: page + 1,
          prevPage: page - 1,
          totalCount: 0,
          totalPages: 0,
        },
        message: PRODUCTS_FETCHED_SUCCESSFULLY,
      });
    }

    const [products, count, brands, categories] = await Promise.all([
      Product.find(filter)
        .select('title handle featuredImage rating description brand priceRange currency')
        .populate('brand', 'handle logo title')
        .sort(sort)
        .skip((page - 1) * PAGE_SIZE)
        .limit(PAGE_SIZE)
        .lean(),
      Product.countDocuments(filter),
      Brand.find()
        .select('handle title logo')
        .sort({ title: 1 })
        .lean(),
      Category.find()
        .select('handle title')
        .sort({ title: 1 })
        .lean()
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
      filter: {
        brands,
        categories
      },
      message: PRODUCTS_FETCHED_SUCCESSFULLY,
    });
  } catch (err: any) {
    if (!err.statusCode) err.statusCode = 500;
    next(err);
  }
};