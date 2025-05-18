import express, { Router } from 'express';
import { body } from 'express-validator';
import * as userController from '../controllers/user';

const router: Router = express.Router();

// GET /api/users
router.get('/', userController.getUsers);

// GET /api/users/:userId
router.get('/:userId', userController.getUser);

// POST /api/users/signup
router.post(
  '/signup',
  [
    body('email').isEmail().withMessage('Please enter a valid email.').normalizeEmail(),
    body('password')
      .trim()
      .isLength({ min: 8 })
      .withMessage('Password must be at least 8 characters long.'),
  ],
  userController.createUser
);

// POST /api/users/login
router.post('/login', userController.login);

export default router;
