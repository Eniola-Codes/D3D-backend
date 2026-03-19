import express, { Router } from 'express';
import * as shopifyController from '../controllers/shopify';
import isAuth from '../middleware/auth';
import { SHOPIFY } from '../lib/constants/endpoints';

const router: Router = express.Router();

router.get(
  SHOPIFY.branches.init,
  isAuth,
  shopifyController.init
);

router.get(
    SHOPIFY.branches.redirect,
    isAuth,
    shopifyController.redirect
  );

  router.get(
    SHOPIFY.branches.getProduct,
    isAuth,
    shopifyController.getproduct
  );
  

export default router;
