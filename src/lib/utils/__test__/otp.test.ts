import { describe, it, expect, beforeEach, vi } from 'vitest';
import { createAndStoreOTP, verifyOTP, generateOTP, hashOTP } from '../otp';
import Otp from '../../../models/otp';
import crypto from 'crypto';

vi.mock('../../../models/otp', () => ({
  default: {
    deleteMany: vi.fn(),
    create: vi.fn(),
    findOne: vi.fn(),
    deleteOne: vi.fn(),
  },
}));

describe('createAndStoreOTP', () => {
  let realCreateAndStoreOTP: typeof createAndStoreOTP;

  beforeEach(async () => {
    vi.clearAllMocks();
    const actual = await vi.importActual<typeof import('../otp')>('../otp');
    realCreateAndStoreOTP = actual.createAndStoreOTP;
  });

  it('should generate OTP, hash it, and store in database', async () => {
    const email = 'test@example.com';

    (Otp.deleteMany as any).mockResolvedValue({ deletedCount: 1 });
    (Otp.create as any).mockResolvedValue({
      email,
      otpHash: 'hashedValue',
      expiresAt: new Date(),
    });

    const result = await realCreateAndStoreOTP(email);

    expect(Otp.deleteMany).toHaveBeenCalledWith({ email });
    expect(Otp.create).toHaveBeenCalledWith({
      email,
      otpHash: expect.any(String),
      expiresAt: expect.any(Date),
    });
    expect(result).toBeTruthy();
    expect(result.length).toBe(6);
    expect(/^\d+$/.test(result)).toBe(true);
  });

  it('should delete existing OTPs before creating new one', async () => {
    const email = 'test@example.com';

    (Otp.deleteMany as any).mockResolvedValue({ deletedCount: 2 });
    (Otp.create as any).mockResolvedValue({});

    await realCreateAndStoreOTP(email);

    expect(Otp.deleteMany).toHaveBeenCalledWith({ email });
    expect(Otp.deleteMany).toHaveBeenCalledBefore(Otp.create as any);
  });

  it('should set expiration time correctly (10 minutes from now)', async () => {
    const email = 'test@example.com';
    const beforeTime = Date.now();

    (Otp.deleteMany as any).mockResolvedValue({ deletedCount: 0 });
    (Otp.create as any).mockImplementation((data: any) => {
      const expiresAt = data.expiresAt.getTime();
      const expectedExpiresAt = beforeTime + 10 * 60 * 1000;
      expect(expiresAt).toBeCloseTo(expectedExpiresAt);
      return Promise.resolve({});
    });

    await realCreateAndStoreOTP(email);

    expect(Otp.create).toHaveBeenCalled();
  });
});

describe('verifyOTP', () => {
  let realVerifyOTP: typeof verifyOTP;

  beforeEach(async () => {
    vi.clearAllMocks();
    const actual = await vi.importActual<typeof import('../otp')>('../otp');
    realVerifyOTP = actual.verifyOTP;
  });

  it('should return false if OTP record does not exist', async () => {
    const email = 'test@example.com';
    const otp = '123456';

    (Otp.findOne as any).mockResolvedValue(null);

    const result = await realVerifyOTP(email, otp, false);

    expect(Otp.findOne).toHaveBeenCalledWith({ email });
    expect(result).toBe(false);
    expect(Otp.deleteOne).not.toHaveBeenCalled();
  });

  it('should return false and delete record if OTP is expired', async () => {
    const email = 'test@example.com';
    const otp = '123456';
    const expiredRecord = {
      _id: 'otp123',
      email,
      otpHash: crypto.createHash('sha256').update(otp).digest('hex'),
      expiresAt: new Date(Date.now() - 1000),
    };

    (Otp.findOne as any).mockResolvedValue(expiredRecord);
    (Otp.deleteOne as any).mockResolvedValue({ deletedCount: 1 });

    const result = await realVerifyOTP(email, otp, false);

    expect(Otp.findOne).toHaveBeenCalledWith({ email });
    expect(Otp.deleteOne).toHaveBeenCalledWith({ _id: expiredRecord._id });
    expect(result).toBe(false);
  });

  it('should return false if OTP hash does not match', async () => {
    const email = 'test@example.com';
    const otp = '123456';
    const wrongOtp = '654321';
    const record = {
      _id: 'otp123',
      email,
      otpHash: crypto.createHash('sha256').update(wrongOtp).digest('hex'),
      expiresAt: new Date(Date.now() + 60000),
    };

    (Otp.findOne as any).mockResolvedValue(record);

    const result = await realVerifyOTP(email, otp, false);

    expect(Otp.findOne).toHaveBeenCalledWith({ email });
    expect(result).toBe(false);
    expect(Otp.deleteOne).not.toHaveBeenCalled();
  });

  it('should return true if OTP is valid and isUseOtp is false', async () => {
    const email = 'test@example.com';
    const otp = '123456';
    const record = {
      _id: 'otp123',
      email,
      otpHash: crypto.createHash('sha256').update(otp).digest('hex'),
      expiresAt: new Date(Date.now() + 60000),
    };

    (Otp.findOne as any).mockResolvedValue(record);

    const result = await realVerifyOTP(email, otp, false);

    expect(Otp.findOne).toHaveBeenCalledWith({ email });
    expect(result).toBe(true);
    expect(Otp.deleteOne).not.toHaveBeenCalled();
  });

  it('should return true and delete record if OTP is valid and isUseOtp is true', async () => {
    const email = 'test@example.com';
    const otp = '123456';
    const record = {
      _id: 'otp123',
      email,
      otpHash: crypto.createHash('sha256').update(otp).digest('hex'),
      expiresAt: new Date(Date.now() + 60000),
    };

    (Otp.findOne as any).mockResolvedValue(record);
    (Otp.deleteOne as any).mockResolvedValue({ deletedCount: 1 });

    const result = await realVerifyOTP(email, otp, true);

    expect(Otp.findOne).toHaveBeenCalledWith({ email });
    expect(Otp.deleteOne).toHaveBeenCalledWith({ _id: record._id });
    expect(result).toBe(true);
  });
});

describe('generateOTP', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should generate a 6-digit OTP by default', () => {
    const otp = generateOTP();

    expect(otp).toBeTruthy();
    expect(otp.length).toBe(6);
    expect(/^\d+$/.test(otp)).toBe(true);
  });

  it('should generate OTP with custom length', () => {
    const length = 8;
    const otp = generateOTP(length);

    expect(otp.length).toBe(length);
    expect(/^\d+$/.test(otp)).toBe(true);
  });
});

describe('hashOTP', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should hash an OTP string', () => {
    const otp = '123456';
    const hash = hashOTP(otp);

    expect(hash).toBeTruthy();
    expect(typeof hash).toBe('string');
    expect(hash.length).toBe(64);
  });

  it('should produce consistent hash for the same OTP', () => {
    const otp = '123456';
    const hash1 = hashOTP(otp);
    const hash2 = hashOTP(otp);

    expect(hash1).toBe(hash2);
  });

  it('should produce different hashes for different OTPs', () => {
    const otp1 = '123456';
    const otp2 = '654321';
    const hash1 = hashOTP(otp1);
    const hash2 = hashOTP(otp2);

    expect(hash1).not.toBe(hash2);
  });
});
