import Brand from '../../models/brand';
import Category from '../../models/category';
import { FilterQuery, SortOrder } from 'mongoose';
import { IPriceRange, IProduct } from '../../types/products';

export const generateHandle = (item: string, title?: string) => {
  const text = title ? item + '-' + title : item;

  return text
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
};

const PRICE_RANGES: Record<string, { min?: number; max?: number }> = {
  'All Prices': { min: 0, max: 999999 },
  'Under $50': { max: 49.99 },
  '$50 - $100': { min: 50, max: 99.99 },
  '$100 - $200': { min: 100, max: 199.99 },
  '$200 - $500': { min: 200, max: 499.99 },
  'Above $500': { min: 500 },
};

const buildPriceFilter = (range: { min?: number; max?: number }) => {
  const priceFilter: { $exists: boolean; $ne: null; $gte?: number; $lte?: number } = {
    $exists: true,
    $ne: null,
  };
  if (range.min != null) priceFilter.$gte = range.min;
  if (range.max != null) priceFilter.$lte = range.max;
  return priceFilter;
};

export const buildProductFilter = async (
  query: Record<string, unknown>
): Promise<FilterQuery<IProduct> | null> => {
  const filter: FilterQuery<IProduct> = {};

  const brandHandle = query.brand ? generateHandle(String(query.brand)) : undefined;
  const categoryHandle = query.category ? generateHandle(String(query.category)) : undefined;

  const [brandDoc, categoryDoc] = await Promise.all([
    brandHandle ? Brand.findOne({ handle: brandHandle }).select('_id').lean() : null,
    categoryHandle ? Category.findOne({ handle: categoryHandle }).select('_id').lean() : null,
  ]);

  if (brandHandle && !brandDoc) return null;
  if (categoryHandle && !categoryDoc) return null;

  if (brandDoc) filter.brand = brandDoc._id;
  if (categoryDoc) filter.categories = categoryDoc._id;

  const search = query.search ? String(query.search).trim() : '';
  if (search) {
    const pattern = new RegExp(search.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
    filter.$or = [{ title: pattern }, { description: pattern }];
  }

  const priceOption = query.price ? String(query.price) : undefined;
  if (priceOption) {
    const range = PRICE_RANGES[priceOption];
    if (!range) return null;

    filter['priceRange.minVariantPrice'] = buildPriceFilter(range);
  }

  return filter;
};

const buildPopularSort = (): Record<string, SortOrder> => ({ rating: -1 });

const buildTopRatedSort = (): Record<string, SortOrder> => ({ rating: -1 });

export const buildProductSort = (sort: unknown): Record<string, SortOrder> => {
  switch (sort ? String(sort).trim() : '') {
    case 'Newest':
      return { createdAt: -1 };
    case 'Popular':
      return buildPopularSort();
    case 'Top Rated':
      return buildTopRatedSort();
    case 'Price: Low to High':
      return { 'priceRange.minVariantPrice': 1 };
    case 'Price: High to Low':
      return { 'priceRange.minVariantPrice': -1 };
    default:
      return { createdAt: -1 };
  }
};

export const getUpdatedPriceRange = (
  current: IPriceRange | undefined,
  price: number
): IPriceRange => {
  const min = current?.minVariantPrice;
  const max = current?.maxVariantPrice;

  return {
    minVariantPrice: min == null ? price : Math.min(min, price),
    maxVariantPrice: max == null ? price : Math.max(max, price),
  };
};


