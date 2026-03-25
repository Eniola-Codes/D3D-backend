import { NextFunction, Request, Response } from "express";
import axios from 'axios';
import config from '../services/shopify';
import crypto from 'crypto';
let global_access_token = "";

 export const init = async (req: Request, res: Response, next: NextFunction) => {
  const { shop } = req.query;
  const nonce = crypto.randomBytes(16).toString('hex');
  const redirectUrl =
    `https://${shop}/admin/oauth/authorize` +
    `?client_id=${config.shopify.appProxy.clientId}` +
    `&scope=${config.shopify.appProxy.scopes.join(',')}` +
    `&redirect_uri=${config.apiUrl}/api/shopify/redirect` +
    `&state=${nonce}`;
    
  res.redirect(302, redirectUrl);
};

export const redirect = async (req: Request, res: Response, next: NextFunction) => {
  const { shop, code } = req.query;

  try {
    const response = await axios.post(
      `https://${shop}/admin/oauth/access_token`,
      {
        client_id: config.shopify.appProxy.clientId,
        client_secret: config.shopify.appProxy.clientSecret,
        code,
      }
    );

    global_access_token = response.data.access_token;

    res.redirect(302, `https://${shop}/admin/apps?shop=${shop}`);
  } catch (error: any) {
    if (!error.statusCode) error.statusCode = 500;
    next(error);
  }
};

export const getproduct = async (req: Request, res: Response, next: NextFunction) => {
  const { store, productid } = req.query;

  try {
    const productResponse = await axios.get(
      `https://${store}/admin/api/2024-01/products/${productid}.json`,
      {
        headers: {
          'X-Shopify-Access-Token': global_access_token,
        },
      }
    );

    res.json(productResponse.data);
  } catch (error: any) {
    if (!error.statusCode) error.statusCode = 500;
    next(error);
  }
};
