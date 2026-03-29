import '@shopify/shopify-api/adapters/node';
import { shopifyApi, ApiVersion } from '@shopify/shopify-api';
import dotenv from 'dotenv';
dotenv.config();

const shopify = shopifyApi({
  apiKey: process.env.SHOPIFY_APP_CLIENT_ID!,           // Client ID from Partner Dashboard
  apiSecretKey: process.env.SHOPIFY_APP_CLIENT_SECRET!, // Client Secret from Partner Dashboard
  scopes: [
    'read_customers',
    'write_customers',
    'read_orders',
    'write_orders',
    'read_products',
    'write_products'
  ],
  hostName: process.env.APPLICATION_URL!,  // d3d-backend.onrender.com  (no https://, no trailing slash)
  apiVersion: ApiVersion.January25,
  isEmbeddedApp: false,
});

export default shopify;