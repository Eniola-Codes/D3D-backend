"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const dotenv_1 = __importDefault(require("dotenv"));
const redis_1 = __importDefault(require("../services/redis"));
dotenv_1.default.config();
module.exports = async (req, res, next) => {
    try {
        const authHeader = req.get('Authorization');
        if (!authHeader) {
            return res.status(401).json({ message: 'Unauthorized. User not found.' });
        }
        const token = authHeader.split(' ')[1];
        if (!token) {
            return res.status(401).json({ message: 'Unauthorized. User not found.' });
        }
        const decodedToken = jsonwebtoken_1.default.verify(token, process.env.JWT_SECRET);
        const isBlacklisted = await redis_1.default.get(token);
        if (isBlacklisted) {
            return res.status(401).json({ message: 'Unauthorized. User not found.' });
        }
        if (decodedToken && typeof decodedToken === 'object') {
            req.user = {
                ...decodedToken,
                token: token,
            };
            next();
        }
        else {
            return res.status(401).json({ message: 'Unauthorized. User not found.' });
        }
    }
    catch (err) {
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ message: 'Token expired. Please log in again.' });
        }
        if (err.name === 'JsonWebTokenError') {
            return res.status(401).json({ message: 'Invalid token.' });
        }
        return res.status(500).json({ message: 'Service unavailable. Please try again.' });
    }
};
