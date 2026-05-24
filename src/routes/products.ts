import express, { Router } from 'express';
import * as productsController from '../controllers/products';
import isAuth from '../middleware/auth';
import { PRODUCTS } from '../lib/constants/endpoints';

const router: Router = express.Router();

router.post(PRODUCTS.branches.createProduct, isAuth, productsController.createProduct);

router.get(PRODUCTS.branches.getProducts, isAuth, productsController.getProducts);

export default router;
