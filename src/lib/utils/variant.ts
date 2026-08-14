import { IVariantOption } from '../../types/products';

const normalizeVariantOptionsKey = (variantOptions: IVariantOption[] | undefined): string =>
  (variantOptions ?? [])
    .filter((option) => option?.title && option.value != null && option.value !== '')
    .map((option) => `${option.title.toLowerCase()}:${option.value.toLowerCase()}`)
    .sort()
    .join('|');

export const getUpdatedProductOptions = (
  current: IVariantOption[][] | undefined,
  variantOptions: IVariantOption[] | undefined
): IVariantOption[][] => {
  const options = [...(current ?? [])];
  const incomingKey = normalizeVariantOptionsKey(variantOptions);
  if (!incomingKey) return options;

  const alreadyExists = options.some(
    (combination) => normalizeVariantOptionsKey(combination) === incomingKey
  );
  if (alreadyExists) return options;

  const combination = (variantOptions ?? []).filter(
    (option) => option?.title && option.value != null && option.value !== ''
  );

  return [...options, combination];
};

export const findMatchingVariant = <T extends { options?: IVariantOption[] }>(
  existingVariants: T[],
  variantOptions: IVariantOption[] | undefined
): T | undefined => {
  const incomingKey = normalizeVariantOptionsKey(variantOptions);
  if (!incomingKey) return undefined;

  return existingVariants.find(
    (variant) => normalizeVariantOptionsKey(variant.options) === incomingKey
  );
};

export const hasMatchingVariantOptions = (
  existingVariants: { options?: IVariantOption[] }[],
  variantOptions: IVariantOption[] | undefined
): boolean => Boolean(findMatchingVariant(existingVariants, variantOptions));
