import express, { Router } from 'express';
import * as variantsController from '../controllers/variants';
import isAuth from '../middleware/auth';
import { VARIANTS } from '../lib/constants/endpoints';

const router: Router = express.Router();

router.post(VARIANTS.branches.createVariant, isAuth, variantsController.createVariant);

router.get(VARIANTS.branches.getVariants, isAuth, variantsController.getVariants);

export default router;
