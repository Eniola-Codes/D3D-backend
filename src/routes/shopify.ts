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

export default router;
