import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
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
  });

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
  });
});