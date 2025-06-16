"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyOTP = exports.createAndStoreOTP = void 0;
const crypto_1 = __importDefault(require("crypto"));
const otp_1 = __importDefault(require("../models/otp"));
const OTP_LENGTH = 6;
const OTP_EXPIRE_MINUTES = 10;
const generateOTP = (length = OTP_LENGTH) => {
    const digits = '0123456789';
    let otp = '';
    for (let i = 0; i < length; i++) {
        otp += digits[crypto_1.default.randomInt(0, digits.length)];
    }
    return otp;
};
const hashOTP = (otp) => {
    return crypto_1.default.createHash('sha256').update(otp).digest('hex');
};
const createAndStoreOTP = async (email) => {
    const otp = generateOTP();
    const otpHash = hashOTP(otp);
    const expiresAt = new Date(Date.now() + OTP_EXPIRE_MINUTES * 60000);
    await otp_1.default.deleteMany({ email });
    await otp_1.default.create({ email, otpHash, expiresAt });
    return otp;
};
exports.createAndStoreOTP = createAndStoreOTP;
const verifyOTP = async (email, otp, isUseOtp) => {
    const otpHash = hashOTP(otp);
    const record = await otp_1.default.findOne({ email });
    if (!record)
        return false;
    if (record.expiresAt < new Date()) {
        await otp_1.default.deleteOne({ _id: record._id }); // expire it
        return false;
    }
    if (record.otpHash !== otpHash)
        return false;
    if (isUseOtp) {
        await otp_1.default.deleteOne({ _id: record._id }); // invalidate after use
    }
    return true;
};
exports.verifyOTP = verifyOTP;
