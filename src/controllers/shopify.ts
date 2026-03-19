import { NextFunction, Request, Response } from "express";
import axios from 'axios';
// controllers/shopifyOauth.controller.js
// const router = express.Router();

let global_access_token = "";

// GET /shopify/init
 export const init = async (req: Request, res: Response, next: NextFunction) => {
  const { shop } = req.query;

  const clientId = process.env.SHOPIFY_CLIENT_ID;
  const scopes = process.env.SHOPIFY_SCOPES; // comma-separated string
  const apiUrl = process.env.API_URL;

  const redirectUrl =
    `https://${shop}/admin/oauth/authorize` +
    `?client_id=${clientId}` +
    `&scope=${scopes}` +
    `&redirect_uri=${apiUrl}/shopify-oauth/redirect` +
    `&state={nonce}` +
    `&grant_options[]={access_mode}`;

  res.redirect(302, redirectUrl);
};

// GET /shopify/redirect
export const redirect = async (req: Request, res: Response, next: NextFunction) => {
  const { shop, code } = req.query;

  try {
    const response = await axios.post(
      `https://${shop}/admin/oauth/access_token`,
      {
        client_id: process.env.SHOPIFY_CLIENT_ID,
        client_secret: process.env.SHOPIFY_CLIENT_SECRET,
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

// GET /shopify/getproduct
export const getproducts = async (req: Request, res: Response, next: NextFunction) => {
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
