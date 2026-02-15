import express, { Router } from 'express';
import * as userController from '../controllers/user';
import isAuth from '../middleware/auth';
import { USER } from '../lib/constants/endpoints';

const router: Router = express.Router();

router.get(USER.branches.getUser, isAuth, userController.getUser);

export default router;
