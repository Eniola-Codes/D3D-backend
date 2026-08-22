import { Request, Response, NextFunction } from 'express';
import Product from '../models/products';
import Variant from '../models/variants';
import {
  PRODUCT_NOT_FOUND,
  VARIANT_CREATED_SUCCESSFULLY,
  VARIANT_OPTION_ALREADY_EXISTS,
  VARIANTS_FETCHED_SUCCESSFULLY,
  VARIANT_FETCHED_SUCCESSFULLY,
  VARIANT_NOT_FOUND,
} from '../lib/constants/messages';
import { generateHandle, getUpdatedPriceRange, resolveImageUrl } from '../lib/utils/product';
import {
  getUpdatedProductOptions,
  hasMatchingVariantOptions,
  findMatchingVariant,
} from '../lib/utils/variant';

export const createVariant = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = (req.user as { id: string }).id;
    const { sku, price, url, inStock, images, options, product } = req.body;

    if (!sku) {
      return res.status(400).json({ message: 'SKU is required.' });
    }

    const productDocument = await Product.findOne({ _id: product, user: userId });
    if (!productDocument) {
      res.status(404).json({ message: 'Product does not exist.' });
      return;
    }

    const existingVariants = await Variant.find({ product: productDocument._id })
      .select('options')
      .lean();

    if (hasMatchingVariantOptions(existingVariants, options)) {
      return res.status(400).json({ message: VARIANT_OPTION_ALREADY_EXISTS });
    }

    const updatedOptions = getUpdatedProductOptions(productDocument.options, options);
    const priceRange = getUpdatedPriceRange(productDocument.priceRange, price);
    const handle = generateHandle(productDocument.handle, sku);
    const uniqueImages = [...new Set((images ?? []) as string[])];
    const normalizedImages: string[] = [];
    for (const image of uniqueImages) {
      normalizedImages.push(await resolveImageUrl(image, handle, 'product'));
    }

    const variantDocument = await Variant.create({
      handle,
      sku,
      price,
      url,
      inStock,
      images: normalizedImages,
      options,
      product: productDocument._id,
    });

    await Product.findByIdAndUpdate(productDocument._id, {
      $addToSet: { variants: variantDocument._id },
      $set: { priceRange, options: updatedOptions },
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
    const userId = (req.user as { id: string }).id;
    const { product } = req.query;

    const productDocument = await Product.findOne({ _id: product, user: userId })
      .select('_id')
      .lean();
    if (!productDocument) {
      return res.status(404).json({ message: PRODUCT_NOT_FOUND });
    }

    const variants = await Variant.find({ product: productDocument._id })
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

export const getVariant = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = (req.user as { id: string }).id;
    const { handle } = req.params;

    const product = await Product.findOne({
      handle: handle.toString().toLowerCase(),
      user: userId,
    })
      .select('_id')
      .lean();
    if (!product) {
      return res.status(404).json({ message: PRODUCT_NOT_FOUND });
    }

    const parsedOptions = Object.entries(req.query).map(([title, value]) => ({
      title,
      value: String(value),
    }));

    const variants = await Variant.find({ product: product._id }).sort({ createdAt: 1 }).lean();

    const variant =
      parsedOptions.length > 0 ? findMatchingVariant(variants, parsedOptions) : variants[0];

    if (!variant) {
      return res.status(400).json({ message: VARIANT_NOT_FOUND });
    }

    res.status(200).json({
      variant,
      message: VARIANT_FETCHED_SUCCESSFULLY,
    });
  } catch (err: any) {
    if (!err.statusCode) err.statusCode = 500;
    next(err);
  }
};
