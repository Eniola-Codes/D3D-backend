"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateJwt = exports.blackListToken = exports.oauthSignupOrLogin = void 0;
const user_1 = __importDefault(require("../../models/user"));
const redis_1 = __importDefault(require("../../services/redis"));
const constants_1 = require("../constants");
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const dotenv_1 = __importDefault(require("dotenv"));
dotenv_1.default.config();
const oauthSignupOrLogin = async (profile) => {
    const email = profile.emails?.[0].value;
    const providerId = profile.id;
    const providerType = profile.provider;
    const user = await user_1.default.findOne({
        email,
    });
    if (user) {
        if (user.provider?.id === providerId) {
            return user;
        }
        else {
            throw new Error();
        }
    }
    const newUser = await user_1.default.create({
        name: profile.displayName,
        email,
        avatar: profile.photos?.[0].value,
        provider: { id: providerId, type: providerType },
    });
    return newUser;
};
exports.oauthSignupOrLogin = oauthSignupOrLogin;
const blackListToken = async (token) => {
    await redis_1.default.set(token, constants_1.blacklist, constants_1.expire, constants_1.sevenDaysSeconds);
};
exports.blackListToken = blackListToken;
const generateJwt = (user) => {
    const token = jsonwebtoken_1.default.sign({ email: user.email, id: user._id }, process.env.JWT_SECRET, {
        expiresIn: constants_1.sevenDays,
    });
    return token;
};
exports.generateJwt = generateJwt;
