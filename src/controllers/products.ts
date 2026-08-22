import { Request, Response, NextFunction } from 'express';
import Brand from '../models/brand';
import Category from '../models/category';
import Product from '../models/products';
import {
  PRODUCT_NOT_FOUND,
  PRODUCT_UPDATED_SUCCESSFULLY,
  PRODUCTS_FETCHED_SUCCESSFULLY,
} from '../lib/constants/messages';
import {
  buildProductFilter,
  buildProductSort,
  generateHandle,
  resolveImageUrl,
} from '../lib/utils/product';
import { DEFAULT_PAGE, PAGE_SIZE } from '../lib/constants';
import mongoose from 'mongoose';

export const createProduct = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = (req.user as { id: string }).id;
    const {
      title,
      url,
      shortDescription,
      features,
      attributes,
      description,
      featuredImage,
      shipping,
      brand,
      seo,
      currency,
      categories,
    } = req.body;

    let brandDocument;

    const brandHandle = generateHandle(brand.title);
    const existingBrand = await Brand.findOne({ handle: brandHandle, user: userId });

    if (existingBrand) {
      brandDocument = existingBrand;
    } else {
      const normalizedLogo = await resolveImageUrl(brand.logo, brandHandle, 'brand');
      brandDocument = new Brand({
        handle: brandHandle,
        title: brand.title,
        logo: normalizedLogo,
        website: brand.website,
        shipping: brand.shipping,
        user: userId,
      });
      await brandDocument.save();
    }

    const categoryIds: mongoose.Types.ObjectId[] = [];

    for (const category of categories) {
      const handle = generateHandle(category);
      const existingCategory = await Category.findOne({ handle, user: userId });
      if (existingCategory) {
        categoryIds.push(existingCategory._id);
      } else {
        const categoryDocument = new Category({ handle, title: category, user: userId });
        await categoryDocument.save();
        categoryIds.push(categoryDocument._id);
      }
    }

    const normalizedFeaturedImage = await resolveImageUrl(
      featuredImage,
      brandDocument.handle,
      'product'
    );

    const productHandle = generateHandle(title, brandDocument.handle);
    const productDocument = await Product.findOneAndUpdate(
      { handle: productHandle, user: userId },
      {
        $set: {
          handle: productHandle,
          title,
          url,
          description,
          shortDescription,
          features,
          attributes,
          featuredImage: normalizedFeaturedImage,
          shipping,
          seo,
          currency,
          brand: brandDocument._id,
          categories: categoryIds,
          user: userId,
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
        shortDescription: productDocument.shortDescription,
        features: productDocument.features,
        attributes: productDocument.attributes,
        featuredImage: productDocument.featuredImage,
        shipping: productDocument.shipping,
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
    const userId = (req.user as { id: string }).id;

    const page = Number(req.query.page) || DEFAULT_PAGE;
    const filter = await buildProductFilter(req.query, userId);
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
        .select(
          'title handle featuredImage shortDescription brand priceRange options'
        )
        .populate('brand', 'handle logo title website')
        .sort(sort)
        .skip((page - 1) * PAGE_SIZE)
        .limit(PAGE_SIZE)
        .lean(),
      Product.countDocuments(filter),
      Brand.find({ user: userId }).select('handle title logo website').sort({ title: 1 }).lean(),
      Category.find({ user: userId }).select('handle title').sort({ title: 1 }).lean(),
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
        categories,
      },
      message: PRODUCTS_FETCHED_SUCCESSFULLY,
    });
  } catch (err: any) {
    if (!err.statusCode) err.statusCode = 500;
    next(err);
  }
};

export const getProduct = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = (req.user as { id: string }).id;
    const { handle } = req.params;
    const product = await Product.findOne({ handle, user: userId })
      .populate('brand', 'handle logo title website')
      .lean();

    if (!product) {
      return res.status(404).json({ message: PRODUCT_NOT_FOUND });
    }

    const categoryIds = product.categories ?? [];
    let relatedProducts: unknown[] = [];

    if (categoryIds.length > 0) {
      relatedProducts = await Product.aggregate([
        {
          $match: {
            user: new mongoose.Types.ObjectId(userId),
            _id: { $ne: product._id },
            categories: { $in: categoryIds },
          },
        },
        {
          $addFields: {
            matchingCategoriesCount: {
              $size: { $setIntersection: ['$categories', categoryIds] },
            },
          },
        },
        { $sort: { matchingCategoriesCount: -1, createdAt: -1 } },
        { $limit: 8 },
        {
          $lookup: {
            from: 'brands',
            localField: 'brand',
            foreignField: '_id',
            as: 'brand',
          },
        },
        { $unwind: { path: '$brand', preserveNullAndEmptyArrays: true } },
        {
          $project: {
            title: 1,
            handle: 1,
            featuredImage: 1,
            shortDescription: 1,
            description: 1,
            priceRange: 1,
            currency: 1,
            options: 1,
            categories: 1,
            brand: {
              handle: '$brand.handle',
              logo: '$brand.logo',
              title: '$brand.title',
              website: '$brand.website',
            },
          },
        },
      ]);
    }
    
    res.status(200).json({
      product,
      relatedProducts,
      message: PRODUCTS_FETCHED_SUCCESSFULLY,
    });
  } catch (err: any) {
    if (!err.statusCode) err.statusCode = 500;
    next(err);
  }
};
