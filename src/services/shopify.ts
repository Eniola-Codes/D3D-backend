import '@shopify/shopify-api/adapters/node';
import { shopifyApi, ApiVersion } from '@shopify/shopify-api';
import dotenv from 'dotenv';
dotenv.config();

const shopify = shopifyApi({
  apiKey: process.env.SHOPIFY_APP_CLIENT_ID!,          
  apiSecretKey: process.env.SHOPIFY_APP_CLIENT_SECRET!,
  scopes: [
    'read_customers',
    'write_customers',
    'read_orders',
    'write_orders',
    'read_products',
    'write_products'
  ],
  hostName: process.env.APPLICATION_URL!, 
  apiVersion: ApiVersion.October25,
  isEmbeddedApp: false,
});

export default shopify;