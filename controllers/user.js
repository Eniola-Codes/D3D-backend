const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv')
dotenv.config();

exports.createUser = async (req, res, next) => {
  const { email, password } = req.body;
  let newUser;

  User.findOne({ email: email })
    .then(user => {
      if (user) {
        return res.status(409).json({
          message: 'The email as already been used, please use another email.',
        });
      }

      return bcrypt.hash(password, 12);
    })
    .then(hashedPassword => {
      newUser = new User({
        email: email,
        password: hashedPassword,
      });
      return newUser.save();
    })
    .then(() => {
      const token = jwt.sign(
        {
          email: newUser.email,
          id: newUser._id,
        },
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
      );

      return res
        .status(201)
        .json({ token: token, user : {id: newUser._id, email: newUser.email}, message: 'User created successfully!' });
    })
    .catch(error => {
      if (!error.statusCode) {
        error.statusCode = 500;
      }
      next(error);
    });
};

exports.login = async (req, res, next) => {
  const { email, password } = req.body;
  let loadedUser;

  User.findOne({ email: email })
    .then(user => {
      if (!user) {
        return res.status(401).json({
          message: 'Invalid email or password, please try again.',
        });
      }

      loadedUser = user;
      return bcrypt.compare(password, user.password);
    })
    .then((isEqual) => {
      if(!isEqual)
        {
          return res.status(401).json({
            message: 'Invalid email or password, please try again.',
          });
        }

      const token = jwt.sign(
        {
          email: loadedUser.email,
          id: loadedUser._id,
        },
        process.env.JWT_SECRET,
        { expiresIn: '7d' }
      );

      return res
        .status(200)
        .json({ token: token, user : {id: loadedUser._id, email: loadedUser.email}, message: 'User authenticated successfully!' });
    })
    .catch(error => {
      if (!error.statusCode) {
        error.statusCode = 500;
      }
      next(error);
    });
};


// Get all users
exports.getUsers = async (req, res, next) => {
  try {
    const users = await User.find();
    res.status(200).json({ users: users });
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};

// Get single user
exports.getUser = async (req, res, next) => {
  try {
    const userId = req.params.userId;
    const user = await User.findById(userId);
    if (!user) {
      const error = new Error('User not found');
      error.statusCode = 404;
      throw error;
    }
    res.status(200).json({ user: user });
  } catch (err) {
    if (!err.statusCode) {
      err.statusCode = 500;
    }
    next(err);
  }
};