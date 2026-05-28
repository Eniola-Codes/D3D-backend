import Brand from '../../models/brand';
import Category from '../../models/category';
import { IPriceRange, IProductFilter } from '../../types/products';

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

export const buildProductFilter = async (
  query: Record<string, unknown>
): Promise<IProductFilter | null> => {
  const filter: IProductFilter = {};

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

  return filter;
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

