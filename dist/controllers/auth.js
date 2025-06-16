"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.resetPassword = exports.verifyOtp = exports.forgetPassword = exports.logout = exports.login = exports.signup = exports.verifyAuth = void 0;
const bcryptjs_1 = __importDefault(require("bcryptjs"));
const dotenv_1 = __importDefault(require("dotenv"));
const user_1 = __importDefault(require("../models/user"));
const email_1 = require("../services/email");
const get_otp_1 = require("../views/emails/get-otp");
const otp_1 = require("../services/otp");
const reset_password_1 = require("../views/emails/reset-password");
const auth_1 = require("../lib/utils/auth");
dotenv_1.default.config();
const verifyAuth = async (req, res, next) => {
    try {
        res.status(200).json({
            message: 'User authenticated successfully!',
        });
        return;
    }
    catch (err) {
        if (!err.statusCode)
            err.statusCode = 500;
        next(err);
    }
};
exports.verifyAuth = verifyAuth;
const signup = async (req, res, next) => {
    const { email, password, name } = req.body;
    let newUser;
    try {
        const existingUser = await user_1.default.findOne({ email });
        if (existingUser) {
            res.status(409).json({
                message: 'The email has already been used, please use another email.',
            });
            return;
        }
        const hashedPassword = await bcryptjs_1.default.hash(password, 12);
        newUser = new user_1.default({
            email,
            name,
            password: hashedPassword,
        });
        await newUser.save();
        const token = (0, auth_1.generateJwt)(newUser);
        res.status(201).json({
            token,
            user: { id: newUser._id, email: newUser.email },
            message: 'User created successfully!',
        });
    }
    catch (error) {
        if (!error.statusCode)
            error.statusCode = 500;
        next(error);
    }
};
exports.signup = signup;
const login = async (req, res, next) => {
    const { email, password } = req.body;
    let loadedUser;
    try {
        const user = await user_1.default.findOne({ email });
        if (!user) {
            res.status(401).json({
                message: 'Invalid email or password, please try again.',
            });
            return;
        }
        loadedUser = user;
        const isEqual = await bcryptjs_1.default.compare(password, user.password);
        if (!isEqual) {
            res.status(401).json({
                message: 'Invalid email or password, please try again.',
            });
            return;
        }
        const token = (0, auth_1.generateJwt)(loadedUser);
        res.status(200).json({
            token,
            user: { id: loadedUser._id, email: loadedUser.email },
            message: 'User authenticated successfully!',
        });
    }
    catch (error) {
        if (!error.statusCode)
            error.statusCode = 500;
        next(error);
    }
};
exports.login = login;
const logout = async (req, res, next) => {
    try {
        const token = req.user.token;
        if (!token) {
            res.status(401).json({
                message: 'Logout unsuccessful, please try again',
            });
            return;
        }
        await (0, auth_1.blackListToken)(token);
        res.status(200).json({ message: 'Logout successful' });
    }
    catch (err) {
        if (!err.statusCode)
            err.statusCode = 500;
        next(err);
    }
};
exports.logout = logout;
const forgetPassword = async (req, res, next) => {
    const { email } = req.body;
    const fromEmail = process.env.EMAIL_USER;
    const subject = 'Your Password Reset Code';
    try {
        const user = await user_1.default.findOne({ email });
        if (!user) {
            res.status(401).json({
                message: 'This email is not associated with an account, please try again.',
            });
            return;
        }
        const token = await (0, otp_1.createAndStoreOTP)(email);
        if (!token) {
            res.status(400).json({
                message: 'Something went wrong, please try again.',
            });
            return;
        }
        const mailOptions = {
            from: fromEmail,
            to: email,
            subject: subject,
            html: (0, get_otp_1.getOtpView)(token),
        };
        const emailSuccess = await (0, email_1.sendEmail)(mailOptions);
        if (!emailSuccess) {
            res.status(400).json({
                message: 'Something went wrong, please try again.',
            });
            return;
        }
        res.status(200).json({
            email: email,
            message: 'Email sent successfully!',
        });
    }
    catch (error) {
        if (!error.statusCode)
            error.statusCode = 500;
        next(error);
    }
};
exports.forgetPassword = forgetPassword;
const verifyOtp = async (req, res, next) => {
    const { email, otp } = req.body;
    try {
        const user = await user_1.default.findOne({ email });
        if (!user) {
            res.status(401).json({
                message: 'This email is not associated with an account, please try again.',
            });
            return;
        }
        const verifyToken = await (0, otp_1.verifyOTP)(email, otp, false);
        if (!verifyToken) {
            res.status(400).json({
                message: 'The Otp code is expired or invalid, please resend an OTP and try again',
            });
            return;
        }
        res.status(200).json({
            email: email,
            message: 'OTP verified successfully!',
        });
    }
    catch (error) {
        if (!error.statusCode)
            error.statusCode = 500;
        next(error);
    }
};
exports.verifyOtp = verifyOtp;
const resetPassword = async (req, res, next) => {
    const { email, password, otp } = req.body;
    const fromEmail = process.env.EMAIL_USER;
    const subject = 'Password Reset Successful';
    try {
        const user = await user_1.default.findOne({ email });
        if (!user) {
            res.status(401).json({
                message: 'This email is not associated with an account, please try again.',
            });
            return;
        }
        const hashedNewPassword = await bcryptjs_1.default.hash(password, 12);
        const isPasswordEqual = await bcryptjs_1.default.compare(password, user.password);
        if (isPasswordEqual) {
            res.status(400).json({
                message: 'You cannot use your previous password, please use a new password',
            });
            return;
        }
        const verifyToken = await (0, otp_1.verifyOTP)(email, otp, true);
        if (!verifyToken) {
            res.status(400).json({
                message: 'The reset password process has timed out, please go back and try again',
            });
            return;
        }
        const mailOptions = {
            from: fromEmail,
            to: email,
            subject: subject,
            html: (0, reset_password_1.resetPasswordView)(email),
        };
        const emailSuccess = await (0, email_1.sendEmail)(mailOptions);
        if (!emailSuccess) {
            res.status(400).json({
                message: 'Something went wrong, please try again.',
            });
            return;
        }
        user.password = hashedNewPassword;
        await user.save();
        res.status(200).json({
            email: email,
            message: 'Password changed successfully!',
        });
    }
    catch (error) {
        if (!error.statusCode)
            error.statusCode = 500;
        next(error);
    }
};
exports.resetPassword = resetPassword;
