const express = require('express');
const router = express.Router();
const userController = require('../controllers/user');
const { body } = require("express-validator");

// GET /api/users
router.get('/', userController.getUsers);

// GET /api/users/:userId
router.get('/:userId', userController.getUser);

// POST /api/users
router.post('/signup', [body("email")
.isEmail()
.withMessage("Please enter a valid email.")
.normalizeEmail(), body("password")
.trim()
.isLength({ min: 8 })
.withMessage("Password must be at least 8 characters long.")], userController.createUser);

router.post(
    "/login", userController.login
  );

module.exports = router;
