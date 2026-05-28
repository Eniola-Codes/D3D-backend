import { Request, Response, NextFunction } from 'express';
import Product from '../models/products';
import Variant from '../models/variant';
import {
  VARIANT_CREATED_SUCCESSFULLY,
  VARIANTS_FETCHED_SUCCESSFULLY,
} from '../lib/constants/messages';
import { generateHandle, getUpdatedPriceRange } from '../lib/utils/product';

export const createVariant = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { sku, price, inStock, images, options, product } = req.body;

    if (!sku) {
      return res.status(400).json({ message: 'SKU is required.' });
    }

    const productDocument = await Product.findById(product);
    if (!productDocument) {
      res.status(404).json({ message: 'Product does not exist.' });
      return;
    }

    const priceRange = getUpdatedPriceRange(productDocument.priceRange, price);
    const handle = generateHandle(productDocument.handle, sku);

    const variantDocument = await Variant.create({
      handle,
      sku,
      price,
      inStock,
      images,
      options,
      product: productDocument._id,
    });

    await Product.findByIdAndUpdate(productDocument._id, {
      $addToSet: { variants: variantDocument._id },
      $set: { priceRange },
    });

    res.status(201).json({
      variant: variantDocument,
      message: VARIANT_CREATED_SUCCESSFULLY,
    });
  } catch (err: any) {
    if (!err.statusCode) err.statusCode = 500;
    next(err);
  }
};

export const getVariants = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { product } = req.query;

    const variants = await Variant.find({ product })
      .sort({ createdAt: -1 })
      .lean();

    res.status(200).json({
      variants,
      message: VARIANTS_FETCHED_SUCCESSFULLY,
    });
  } catch (err: any) {
    if (!err.statusCode) err.statusCode = 500;
    next(err);
  }
};
