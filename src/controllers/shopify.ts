import { NextFunction, Request, Response } from 'express';
import { SHOPIFY } from '../lib/constants/endpoints';
import shopify from '../services/shopify';

export const init = async (req: Request, res: Response, next: NextFunction) => {
  try {
    await shopify.auth.begin({
      shop: shopify.utils.sanitizeShop(req.query.shop as string, true)!,
      callbackPath: `${SHOPIFY.base}${SHOPIFY.branches.redirect}`,
      isOnline: false,
      rawRequest: req,
      rawResponse: res,
    });
  } catch (error: any) {
    if (!error.statusCode) error.statusCode = 500;
    next(error);
  }
};

export const redirect = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const callback = await shopify.auth.callback({
      rawRequest: req,
      rawResponse: res,
    });

    const { shop, accessToken } = callback.session;

    res.redirect(
      302,
      `${process.env.FRONTEND_APPLICATION_URL}/dashboard?shop=${shop}&token=${accessToken}`
    );
  } catch (error: any) {
    if (!error.statusCode) error.statusCode = 500;
    next(error);
  }
};