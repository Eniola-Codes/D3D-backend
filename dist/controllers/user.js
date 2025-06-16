"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.getUser = void 0;
const user_1 = __importDefault(require("../models/user"));
const getUser = async (req, res, next) => {
    try {
        const email = req.user.email;
        const user = await user_1.default.findOne({ email });
        if (!user) {
            res.status(401).json({
                message: 'No user found, please try again',
            });
            return;
        }
        res.status(200).json({
            user: { email: user.email, name: user.name, id: user._id, avatar: user.avatar },
            message: 'User found successfully!',
        });
    }
    catch (err) {
        if (!err.statusCode)
            err.statusCode = 500;
        next(err);
    }
};
exports.getUser = getUser;
