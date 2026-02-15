import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import request from 'supertest';
import mongoose from 'mongoose';
import app from '../../app';
import User from '../../models/user';
import Otp from '../../models/otp';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';
import redis from '../../services/redis';
import {
  EMAIL_SENT_SUCCESSFULLY,
  LOGOUT_SUCCESSFUL,
  PASSWORD_CHANGED_SUCCESSFULLY,
  OTP_VERIFIED_SUCCESSFULLY,
  UNAUTHORIZED_USER,
  EMAIL_ALREADY_USED,
  INVALID_EMAIL_OR_PASSWORD,
  EMAIL_NOT_ASSOCIATED_WITH_ACCOUNT,
  OTP_EXPIRED_OR_INVALID,
  RESET_PASSWORD_TIMED_OUT,
  CANNOT_USE_YOUR_PREVIOUS_PASSWORD,
  INVALID_TOKEN,
} from '../../lib/constants/messages';
import { AUTH } from '../../lib/constants/endpoints';

dotenv.config();

const TEST_DB_URI = process.env.MONGODB_TEST_CONNECTION as string;

describe('Auth API Integration Tests', () => {
  beforeAll(async () => {
    await mongoose.connect(TEST_DB_URI, {
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    });
  }, 30000);

  afterAll(async () => {
    await User.deleteMany({});
    await Otp.deleteMany({});
    await mongoose.connection.close();
  });

  beforeEach(async () => {
    await User.deleteMany({});
    await Otp.deleteMany({});
  });

  describe('POST signup', () => {
    it('should create a new user in the database', async () => {
      const userData = {
        email: 'test@example.com',
        name: 'Test User',
        password: 'password123',
      };

      const response = await request(app)
        .post(`${AUTH.base}${AUTH.branches.signup}`)
        .send(userData)
        .expect(201);

      expect(response.body).toHaveProperty('token');
      expect(response.body).toHaveProperty('message');
      expect(response.body).toHaveProperty('user');

      const createdUser = await User.findOne({ email: userData.email });
      expect(createdUser).toBeTruthy();
      expect(createdUser?.email).toBe(userData.email);
      expect(createdUser?.name).toBe(userData.name);
      expect(await bcrypt.compare(userData.password, createdUser?.password || '')).toBe(true);
    });

    it('should return 409 when email already exists', async () => {
      const user = new User({
        email: 'test@example.com',
        name: 'Test User',
        password: await bcrypt.hash('password123', 12),
      });
      await user.save();

      const userData = {
        email: 'test@example.com',
        name: 'Another User',
        password: 'password123',
      };

      const response = await request(app)
        .post(`${AUTH.base}${AUTH.branches.signup}`)
        .send(userData)
        .expect(409);

      expect(response.body.message).toBe(EMAIL_ALREADY_USED);
    });

    it('should return validation error for invalid email format', async () => {
      const userData = {
        email: '',
        name: 'Test User',
        password: 'password123',
      };

      const response = await request(app)
        .post(`${AUTH.base}${AUTH.branches.signup}`)
        .send(userData)
        .expect(400);

      expect(response.body.message).toBeDefined();
      expect(response.body.message).toContain('valid email');
    });

    it('should return validation error for name too short', async () => {
      const userData = {
        email: 'test@example.com',
        name: 'Ab',
        password: 'password123',
      };

      const response = await request(app)
        .post(`${AUTH.base}${AUTH.branches.signup}`)
        .send(userData)
        .expect(400);

      expect(response.body.message).toBeDefined();
      expect(response.body.message).toContain('at least 3 characters');
    });

    it('should return validation error for password too short', async () => {
      const userData = {
        email: 'test@example.com',
        name: 'Test User',
        password: 'short',
      };

      const response = await request(app)
        .post(`${AUTH.base}${AUTH.branches.signup}`)
        .send(userData)
        .expect(400);

      expect(response.body.message).toBeDefined();
      expect(response.body.message).toContain('at least 8 characters');
    });
  });

  describe('POST login', () => {
    it('should login with valid credentials from database', async () => {
      const user = new User({
        email: 'test@example.com',
        name: 'Test User',
        password: await bcrypt.hash('password123', 12),
      });
      await user.save();

      const loginData = {
        email: 'test@example.com',
        password: 'password123',
      };

      const response = await request(app)
        .post(`${AUTH.base}${AUTH.branches.login}`)
        .send(loginData)
        .expect(200);

      expect(response.body).toHaveProperty('token');
      expect(response.body.token).toBeTruthy();
    });

    it('should return 401 when email does not exist', async () => {
      const loginData = {
        email: 'nonexistent@example.com',
        password: 'password123',
      };

      const response = await request(app)
        .post(`${AUTH.base}${AUTH.branches.login}`)
        .send(loginData)
        .expect(401);

      expect(response.body.message).toBe(INVALID_EMAIL_OR_PASSWORD);
    });

    it('should return 401 when password is incorrect', async () => {
      const user = new User({
        email: 'test@example.com',
        name: 'Test User',
        password: await bcrypt.hash('password123', 12),
      });
      await user.save();

      const loginData = {
        email: 'test@example.com',
        password: 'wrongpassword',
      };

      const response = await request(app)
        .post(`${AUTH.base}${AUTH.branches.login}`)
        .send(loginData)
        .expect(401);

      expect(response.body.message).toBe(INVALID_EMAIL_OR_PASSWORD);
    });
  });

  describe('POST logout', () => {
    it('should logout and blacklist token in Redis', async () => {
      const user = new User({
        email: 'test@example.com',
        name: 'Test User',
        password: await bcrypt.hash('password123', 12),
      });
      await user.save();

      const loginResponse = await request(app)
        .post(`${AUTH.base}${AUTH.branches.login}`)
        .send({
          email: 'test@example.com',
          password: 'password123',
        })
        .expect(200);

      const token = loginResponse.body.token;
      expect(token).toBeTruthy();

      const logoutResponse = await request(app)
        .post(`${AUTH.base}${AUTH.branches.logout}`)
        .set('Authorization', `Bearer ${token}`)
        .expect(200);

      expect(logoutResponse.body.message).toBe(LOGOUT_SUCCESSFUL);

      const blacklistedToken = await redis.get(token);
      expect(blacklistedToken).toBe('blacklisted');

      const failedRequest = await request(app)
        .post(`${AUTH.base}${AUTH.branches.logout}`)
        .set('Authorization', `Bearer ${token}`)
        .expect(401);

      expect(failedRequest.body.message).toBe(UNAUTHORIZED_USER);
    });

    it('should return 401 when no token is provided', async () => {
      const response = await request(app).post(`${AUTH.base}${AUTH.branches.logout}`).expect(401);

      expect(response.body.message).toBe(UNAUTHORIZED_USER);
    });

    it('should return 401 when invalid token is provided', async () => {
      const response = await request(app)
        .post(`${AUTH.base}${AUTH.branches.logout}`)
        .set('Authorization', 'Bearer invalid-token')
        .expect(401);

      expect(response.body.message).toBe(INVALID_TOKEN);
    });
  });

  describe('POST forget-password', () => {
    it('should create OTP in database and send email', async () => {
      const user = new User({
        email: 'test@gmail.com',
        name: 'Test User',
        password: await bcrypt.hash('password123', 12),
      });
      await user.save();

      const emailData = {
        email: 'test@gmail.com',
      };

      const response = await request(app)
        .post(`${AUTH.base}${AUTH.branches.forgetPassword}`)
        .send(emailData)
        .expect(200);

      expect(response.body.message).toBe(EMAIL_SENT_SUCCESSFULLY);

      const otpRecord = await Otp.findOne({ email: emailData.email });
      expect(otpRecord).toBeTruthy();
      expect(otpRecord?.email).toBe(emailData.email);
      expect(otpRecord?.otpHash).toBeTruthy();
      expect(otpRecord?.expiresAt).toBeTruthy();
    });

    it('should return 401 when email is not associated with an account', async () => {
      const emailData = {
        email: 'nonexistent@example.com',
      };

      const response = await request(app)
        .post(`${AUTH.base}${AUTH.branches.forgetPassword}`)
        .send(emailData)
        .expect(401);

      expect(response.body.message).toBe(EMAIL_NOT_ASSOCIATED_WITH_ACCOUNT);
    });

    it('should return validation error for invalid email format', async () => {
      const emailData = {
        email: 'invalid-email',
      };

      const response = await request(app)
        .post(`${AUTH.base}${AUTH.branches.forgetPassword}`)
        .send(emailData)
        .expect(400);

      expect(response.body.message).toBeDefined();
      expect(response.body.message).toContain('valid email');
    });
  });

  describe('POST verify-otp', () => {
    it('should verify OTP from database', async () => {
      const user = new User({
        email: 'test@gmail.com',
        name: 'Test User',
        password: await bcrypt.hash('password123', 12),
      });
      await user.save();

      const crypto = await import('crypto');
      const otp = '123456';
      const otpHash = crypto.createHash('sha256').update(otp).digest('hex');
      const otpRecord = new Otp({
        email: 'test@gmail.com',
        otpHash,
        expiresAt: new Date(Date.now() + 10 * 60 * 1000),
      });
      await otpRecord.save();

      const otpData = {
        email: 'test@gmail.com',
        otp: '123456',
      };

      const response = await request(app)
        .post(`${AUTH.base}${AUTH.branches.verifyOtp}`)
        .send(otpData)
        .expect(200);

      expect(response.body.message).toBe(OTP_VERIFIED_SUCCESSFULLY);
    });

    it('should return 400 when OTP is invalid', async () => {
      const user = new User({
        email: 'test@gmail.com',
        name: 'Test User',
        password: await bcrypt.hash('password123', 12),
      });
      await user.save();

      const crypto = await import('crypto');
      const otp = '123456';
      const otpHash = crypto.createHash('sha256').update(otp).digest('hex');
      const otpRecord = new Otp({
        email: 'test@gmail.com',
        otpHash,
        expiresAt: new Date(Date.now() + 10 * 60 * 1000),
      });
      await otpRecord.save();

      const otpData = {
        email: 'test@gmail.com',
        otp: '999999',
      };

      const response = await request(app)
        .post(`${AUTH.base}${AUTH.branches.verifyOtp}`)
        .send(otpData)
        .expect(400);

      expect(response.body.message).toBe(OTP_EXPIRED_OR_INVALID);
    });

    it('should return 400 when OTP is expired', async () => {
      const user = new User({
        email: 'test@gmail.com',
        name: 'Test User',
        password: await bcrypt.hash('password123', 12),
      });
      await user.save();

      const crypto = await import('crypto');
      const otp = '123456';
      const otpHash = crypto.createHash('sha256').update(otp).digest('hex');
      const otpRecord = new Otp({
        email: 'test@gmail.com',
        otpHash,
        expiresAt: new Date(Date.now() - 1000),
      });
      await otpRecord.save();

      const otpData = {
        email: 'test@gmail.com',
        otp: '123456',
      };

      const response = await request(app)
        .post(`${AUTH.base}${AUTH.branches.verifyOtp}`)
        .send(otpData)
        .expect(400);

      expect(response.body.message).toBe(OTP_EXPIRED_OR_INVALID);
    });

    it('should return 401 when email is not associated with an account', async () => {
      const otpData = {
        email: 'nonexistent@example.com',
        otp: '123456',
      };

      const response = await request(app)
        .post(`${AUTH.base}${AUTH.branches.verifyOtp}`)
        .send(otpData)
        .expect(401);

      expect(response.body.message).toBe(EMAIL_NOT_ASSOCIATED_WITH_ACCOUNT);
    });

    it('should return validation error for OTP too short', async () => {
      const otpData = {
        email: 'test@gmail.com',
        otp: '12345',
      };

      const response = await request(app)
        .post(`${AUTH.base}${AUTH.branches.verifyOtp}`)
        .send(otpData)
        .expect(400);

      expect(response.body.message).toBeDefined();
      expect(response.body.message).toContain('6 numbers');
    });
  });

  describe('PUT reset-password', () => {
    it('should reset password in database', async () => {
      const user = new User({
        email: 'test@example.com',
        name: 'Test User',
        password: await bcrypt.hash('oldpassword', 12),
      });
      await user.save();

      const crypto = await import('crypto');
      const otp = '123456';
      const otpHash = crypto.createHash('sha256').update(otp).digest('hex');
      const otpRecord = new Otp({
        email: 'test@example.com',
        otpHash,
        expiresAt: new Date(Date.now() + 10 * 60 * 1000),
      });
      await otpRecord.save();

      const resetData = {
        email: 'test@example.com',
        otp: '123456',
        password: 'newpassword123',
      };

      const response = await request(app)
        .put(`${AUTH.base}${AUTH.branches.resetPassword}`)
        .send(resetData)
        .expect(200);

      expect(response.body.message).toBe(PASSWORD_CHANGED_SUCCESSFULLY);

      const updatedUser = await User.findOne({ email: resetData.email });
      expect(updatedUser).toBeTruthy();
      const isNewPasswordValid = await bcrypt.compare(
        resetData.password,
        updatedUser?.password || ''
      );
      expect(isNewPasswordValid).toBe(true);
      const deletedOtp = await Otp.findOne({ email: resetData.email });
      expect(deletedOtp).toBeNull();
    });

    it('should return 401 when email is not associated with an account', async () => {
      const resetData = {
        email: 'nonexistent@example.com',
        otp: '123456',
        password: 'newpassword123',
      };

      const response = await request(app)
        .put(`${AUTH.base}${AUTH.branches.resetPassword}`)
        .send(resetData)
        .expect(401);

      expect(response.body.message).toBe(EMAIL_NOT_ASSOCIATED_WITH_ACCOUNT);
    });

    it('should return 400 when OTP is invalid or expired', async () => {
      const user = new User({
        email: 'test@example.com',
        name: 'Test User',
        password: await bcrypt.hash('oldpassword', 12),
      });
      await user.save();

      const resetData = {
        email: 'test@example.com',
        otp: '999999',
        password: 'newpassword123',
      };

      const response = await request(app)
        .put(`${AUTH.base}${AUTH.branches.resetPassword}`)
        .send(resetData)
        .expect(400);

      expect(response.body.message).toBe(RESET_PASSWORD_TIMED_OUT);
    });

    it('should return 400 when trying to use previous password', async () => {
      const user = new User({
        email: 'test@example.com',
        name: 'Test User',
        password: await bcrypt.hash('oldpassword', 12),
      });
      await user.save();

      const crypto = await import('crypto');
      const otp = '123456';
      const otpHash = crypto.createHash('sha256').update(otp).digest('hex');
      const otpRecord = new Otp({
        email: 'test@example.com',
        otpHash,
        expiresAt: new Date(Date.now() + 10 * 60 * 1000),
      });
      await otpRecord.save();

      const resetData = {
        email: 'test@example.com',
        otp: '123456',
        password: 'oldpassword',
      };

      const response = await request(app)
        .put(`${AUTH.base}${AUTH.branches.resetPassword}`)
        .send(resetData)
        .expect(400);

      expect(response.body.message).toBe(CANNOT_USE_YOUR_PREVIOUS_PASSWORD);
    });

    it('should return validation error for password too short', async () => {
      const resetData = {
        email: 'test@example.com',
        otp: '123456',
        password: 'short',
      };

      const response = await request(app)
        .put(`${AUTH.base}${AUTH.branches.resetPassword}`)
        .send(resetData)
        .expect(400);

      expect(response.body.message).toBeDefined();
      expect(response.body.message).toContain('at least 8 characters');
    });
  });
});
