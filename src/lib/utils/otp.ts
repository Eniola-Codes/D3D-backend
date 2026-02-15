import crypto from 'crypto';
import Otp from '../../models/otp';

const OTP_LENGTH = 6;
const OTP_EXPIRE_MINUTES = 10;

export const generateOTP = (length = OTP_LENGTH): string => {
  const digits = '0123456789';
  let otp = '';
  for (let i = 0; i < length; i++) {
    otp += digits[crypto.randomInt(0, digits.length)];
  }
  return otp;
};

export const hashOTP = (otp: string): string => {
  return crypto.createHash('sha256').update(otp).digest('hex');
};

export const createAndStoreOTP = async (email: string): Promise<string> => {
  const otp = generateOTP();
  const otpHash = hashOTP(otp);
  const expiresAt = new Date(Date.now() + OTP_EXPIRE_MINUTES * 60000);

  await Otp.deleteMany({ email });

  await Otp.create({ email, otpHash, expiresAt });

  return otp;
};

export const verifyOTP = async (
  email: string,
  otp: string,
  isUseOtp: boolean
): Promise<boolean> => {
  const otpHash = hashOTP(otp);
  const record = await Otp.findOne({ email });

  if (!record) return false;
  if (record.expiresAt < new Date()) {
    await Otp.deleteOne({ _id: record._id });
    return false;
  }

  if (record.otpHash !== otpHash) return false;

  if (isUseOtp) {
    await Otp.deleteOne({ _id: record._id });
  }

  return true;
};
