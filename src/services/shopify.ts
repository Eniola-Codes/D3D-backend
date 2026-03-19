import dotenv from 'dotenv';
dotenv.config();

export default {
    port: parseInt(process.env.PORT as string, 10),
    environment: process.env.NODE_ENV,
    apiUrl: process.env.APPLICATION_URL,
    corsAllowedUrls: '*',
    shopify: {
        appProxy: {
            clientId: process.env.SHOPIFY_APP_CLIENT_ID,
            clientSecret: process.env.SHOPIFY_APP_CLIENT_SECRET,
            scopes: [
                'read_customers',
                'write_customers',
                'read_orders',
                'write_orders',
                'write_products',
                'read_products'
            ]
        },
    },
};