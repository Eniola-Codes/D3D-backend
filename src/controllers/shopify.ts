import { NextFunction, Request, Response } from "express";
import { SHOPIFY } from "../lib/constants/endpoints";
import shopify from "../services/shopify";

 export const init = async (req: Request, res: Response, next: NextFunction) => {
  console.log("Hi")
  try {
  const response = await shopify.auth.begin({
      shop: shopify.utils.sanitizeShop(req.query.shop as string, true)!,
      callbackPath: `${SHOPIFY.base}${SHOPIFY.branches.redirect}`,
      isOnline: false,
      rawRequest: req,
      rawResponse: res,
    });

    console.log(response)
    console.log("Hi2")
  } catch (error) {
    next(error);
    console.log(error)
    console.log("Hi3")
  }};

export const redirect = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const callback = await shopify.auth.callback({
      rawRequest: req,
      rawResponse: res,
    });

    const { shop, accessToken } = callback.session;

    console.log('Access token for', shop, ':', accessToken);

    // TODO: save session to your database here
    // await db.saveSession(shop, accessToken);

    // Redirect user back to your frontend
    res.redirect(302, `${process.env.FRONTEND_URL}/dashboard?shop=${shop}`);
  } catch (error) {
    next(error);
  }
};