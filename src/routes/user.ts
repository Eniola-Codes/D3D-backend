import express, { Router } from 'express';
import * as userController from '../controllers/user';
import isAuth from '../middleware/auth';

const router: Router = express.Router();

router.get('/', isAuth, userController.getUser);

export default router;
