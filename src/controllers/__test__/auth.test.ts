import { describe, it, expect, beforeEach, vi } from 'vitest';
import { Request, Response, NextFunction } from 'express';
import { login, signup, logout, forgetPassword, verifyOtp, resetPassword } from '../auth';
import User from '../../models/user';
import bcrypt from 'bcryptjs';
import { generateJwt, blackListToken } from '../../lib/utils/auth';
import { createAndStoreOTP, verifyOTP } from '../../lib/utils/otp';
import { sendEmail } from '../../services/email';
import { getOtpView } from '../../views/emails/get-otp';
import { resetPasswordView } from '../../views/emails/reset-password';
import {
  CANNOT_USE_YOUR_PREVIOUS_PASSWORD,
  EMAIL_ALREADY_USED,
  EMAIL_NOT_ASSOCIATED_WITH_ACCOUNT,
  EMAIL_SENT_SUCCESSFULLY,
  INVALID_EMAIL_OR_PASSWORD,
  LOGOUT_SUCCESSFUL,
  LOGOUT_UNSUCCESSFUL,
  OTP_EXPIRED_OR_INVALID,
  OTP_VERIFIED_SUCCESSFULLY,
  PASSWORD_CHANGED_SUCCESSFULLY,
  PASSWORD_RESET_SUCCESSFUL,
  RESET_PASSWORD_TIMED_OUT,
  SOMETHING_WENT_WRONG,
  USER_AUTHENTICATED_SUCCESSFULLY,
  USER_CREATED_SUCCESSFULLY,
  YOUR_PASSWORD_RESET_CODE,
} from '../../lib/constants/messages';


vi.mock('../../models/user', () => {
  const MockUser: any = vi.fn().mockImplementation((data: any) => {
    return {
      email: data?.email,
      name: data?.name,
      password: data?.password,
      save: vi.fn().mockResolvedValue(true),
    };
  });
  MockUser.findOne = vi.fn();
  MockUser.create = vi.fn();
  
  return {
    default: MockUser,
  };
});

vi.mock('bcryptjs', () => ({
  default: {
    compare: vi.fn(),
    hash: vi.fn(),
  },
}));

vi.mock('../../services/redis', () => ({
  default: {
    set: vi.fn(),
    get: vi.fn(),
  },
}));

vi.mock('../../lib/utils/otp', async () => {
  const actual = await vi.importActual<typeof import('../../lib/utils/otp')>('../../lib/utils/otp');
  return {
    ...actual,
    createAndStoreOTP: vi.fn(),
    verifyOTP: vi.fn(),
  };
});

vi.mock('../../services/email', () => ({
  sendEmail: vi.fn(),
}));

vi.mock('../../views/emails/get-otp', () => ({
  getOtpView: vi.fn(),
}));

vi.mock('../../views/emails/reset-password', () => ({
  resetPasswordView: vi.fn(),
}));

vi.mock('../../lib/utils/auth', async () => {
  const actual = await vi.importActual('../../lib/utils/auth');
  return {
    ...actual,
    generateJwt: vi.fn(),
    blackListToken: vi.fn(),
  };
});

describe('login', () => {
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: NextFunction;

  beforeEach(() => {
    mockReq = {
      body: {},
    };
    mockRes = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
    };
    mockNext = vi.fn();
    vi.clearAllMocks();
  });

  it('should return 401 if user is not found', async () => {
    const email = 'test@example.com';
    const password = 'password123';
    mockReq.body = { email, password };

    (User.findOne as any).mockResolvedValue(null);

    await login(mockReq as Request, mockRes as Response, mockNext);

    expect(User.findOne).toHaveBeenCalledWith({ email });
    expect(mockRes.status).toHaveBeenCalledWith(401);
    expect(mockRes.json).toHaveBeenCalledWith({
      message: INVALID_EMAIL_OR_PASSWORD,
    });
    expect(mockNext).not.toHaveBeenCalled();
  });

  it('should return 401 if password is incorrect', async () => {
    const email = 'test@example.com';
    const password = 'wrongpassword';
    mockReq.body = { email, password };

    const mockUser = {
      _id: 'user123',
      email: 'test@example.com',
      name: 'Test User',
      password: 'hashedPassword123',
    };

    (User.findOne as any).mockResolvedValue(mockUser);
    (bcrypt.compare as any).mockResolvedValue(false);

    await login(mockReq as Request, mockRes as Response, mockNext);

    expect(User.findOne).toHaveBeenCalledWith({ email });
    expect(bcrypt.compare).toHaveBeenCalledWith(password, mockUser.password);
    expect(mockRes.status).toHaveBeenCalledWith(401);
    expect(mockRes.json).toHaveBeenCalledWith({
      message: INVALID_EMAIL_OR_PASSWORD,
    });
    expect(generateJwt).not.toHaveBeenCalled();
    expect(mockNext).not.toHaveBeenCalled();
  });

  it('should return 200 with token and user data on successful login', async () => {
    const email = 'test@example.com';
    const password = 'correctpassword';
    mockReq.body = { email, password };

    const mockUser = {
      _id: 'user123',
      email: 'test@example.com',
      name: 'Test User',
      password: 'hashedPassword123',
    };

    const mockToken = 'jwt-token-123';

    (User.findOne as any).mockResolvedValue(mockUser);
    (bcrypt.compare as any).mockResolvedValue(true);
    (generateJwt as any).mockReturnValue(mockToken);

    await login(mockReq as Request, mockRes as Response, mockNext);

    expect(User.findOne).toHaveBeenCalledWith({ email });
    expect(bcrypt.compare).toHaveBeenCalledWith(password, mockUser.password);
    expect(generateJwt).toHaveBeenCalledWith(mockUser);
    expect(mockRes.status).toHaveBeenCalledWith(200);
    expect(mockRes.json).toHaveBeenCalledWith({
      token: mockToken,
      user: {
        id: mockUser._id,
        email: mockUser.email,
        name: mockUser.name,
      },
      message: USER_AUTHENTICATED_SUCCESSFULLY,
    });
    expect(mockNext).not.toHaveBeenCalled();
  });
});

describe('signup', () => {
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: NextFunction;

  beforeEach(() => {
    mockReq = {
      body: {},
    };
    mockRes = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
    };
    mockNext = vi.fn();

    vi.clearAllMocks();
  });

  it('should return 409 if email already exists', async () => {
    const email = 'existing@example.com';
    const password = 'password123';
    const name = 'Test User';
    mockReq.body = { email, password, name };

    const existingUser = {
      _id: 'existing123',
      email: 'existing@example.com',
      name: 'Existing User',
    };

    (User.findOne as any).mockResolvedValue(existingUser);

    await signup(mockReq as Request, mockRes as Response, mockNext);

    expect(User.findOne).toHaveBeenCalledWith({ email });
    expect(mockRes.status).toHaveBeenCalledWith(409);
    expect(mockRes.json).toHaveBeenCalledWith({
      message: EMAIL_ALREADY_USED,
    });
    expect(bcrypt.hash).not.toHaveBeenCalled();
    expect(mockNext).not.toHaveBeenCalled();
  });

  it('should create user and return 201 with token on successful signup', async () => {
    const email = 'newuser@example.com';
    const password = 'password123';
    const name = 'New User';
    mockReq.body = { email, password, name };

    const hashedPassword = 'hashedPassword123';
    const mockToken = 'jwt-token-123';

    (User.findOne as any).mockResolvedValue(null);
    (bcrypt.hash as any).mockResolvedValue(hashedPassword);
    (generateJwt as any).mockReturnValue(mockToken);

    await signup(mockReq as Request, mockRes as Response, mockNext);

    const createdUser = vi.mocked(User).mock.results[vi.mocked(User).mock.results.length - 1]?.value;

    expect(User.findOne).toHaveBeenCalledWith({ email });
    expect(bcrypt.hash).toHaveBeenCalledWith(password, 12);
    expect(vi.mocked(User)).toHaveBeenCalledWith({
      email,
      name,
      password: hashedPassword,
    });
    expect(createdUser.save).toHaveBeenCalled();
    expect(mockRes.status).toHaveBeenCalledWith(201);
    expect(mockRes.json).toHaveBeenCalledWith({
      token: mockToken,
      user: {
        id: createdUser._id,
        email: createdUser.email,
        name: createdUser.name,
      },
      message: USER_CREATED_SUCCESSFULLY,
    });
  });
});

describe('logout', () => {
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: NextFunction;

  beforeEach(() => {
    mockReq = {
      user: {},
    };
    mockRes = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
    };
    mockNext = vi.fn();
    vi.clearAllMocks();
  });

  it('should return 401 if token is not present', async () => {
    mockReq.user = {} as any;

    await logout(mockReq as Request, mockRes as Response, mockNext);

    expect(mockRes.status).toHaveBeenCalledWith(401);
    expect(mockRes.json).toHaveBeenCalledWith({
      message: LOGOUT_UNSUCCESSFUL,
    });
    expect(blackListToken).not.toHaveBeenCalled();
  });

  it('should return 401 if token is undefined', async () => {
    mockReq.user = { token: undefined } as any;

    await logout(mockReq as Request, mockRes as Response, mockNext);

    expect(mockRes.status).toHaveBeenCalledWith(401);
    expect(mockRes.json).toHaveBeenCalledWith({
      message: LOGOUT_UNSUCCESSFUL,
    });
    expect(blackListToken).not.toHaveBeenCalled();
  });

  it('should successfully logout and blacklist token', async () => {
    const token = 'valid-token-123';
    mockReq.user = { token } as any;

    (blackListToken as any).mockResolvedValue(undefined);

    await logout(mockReq as Request, mockRes as Response, mockNext);

    expect(blackListToken).toHaveBeenCalledWith(token);
    expect(mockRes.status).toHaveBeenCalledWith(200);
    expect(mockRes.json).toHaveBeenCalledWith({
      message: LOGOUT_SUCCESSFUL,
    });
  });
});

describe('forgetPassword', () => {
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: NextFunction;

  beforeEach(() => {
    mockReq = {
      body: {},
    };
    mockRes = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
    };
    mockNext = vi.fn();
    vi.clearAllMocks();
  });

  it('should return 401 if user is not found', async () => {
    const email = 'nonexistent@example.com';
    mockReq.body = { email };

    (User.findOne as any).mockResolvedValue(null);

    await forgetPassword(mockReq as Request, mockRes as Response, mockNext);

    expect(User.findOne).toHaveBeenCalledWith({ email });
    expect(mockRes.status).toHaveBeenCalledWith(401);
    expect(mockRes.json).toHaveBeenCalledWith({
      message: EMAIL_NOT_ASSOCIATED_WITH_ACCOUNT,
    });
    expect(createAndStoreOTP).not.toHaveBeenCalled();
  });

  it('should return 400 if createAndStoreOTP returns null', async () => {
    const email = 'test@example.com';
    mockReq.body = { email };

    const mockUser = {
      _id: 'user123',
      email: 'test@example.com',
      name: 'Test User',
    };

    (User.findOne as any).mockResolvedValue(mockUser);
    (createAndStoreOTP as any).mockResolvedValue(null);

    await forgetPassword(mockReq as Request, mockRes as Response, mockNext);

    expect(User.findOne).toHaveBeenCalledWith({ email });
    expect(createAndStoreOTP).toHaveBeenCalledWith(email);
    expect(mockRes.status).toHaveBeenCalledWith(400);
    expect(mockRes.json).toHaveBeenCalledWith({
      message: SOMETHING_WENT_WRONG,
    });
    expect(sendEmail).not.toHaveBeenCalled();
  });

  it('should return 400 if sendEmail returns false', async () => {
    const email = 'test@example.com';
    mockReq.body = { email };

    const mockUser = {
      _id: 'user123',
      email: 'test@example.com',
      name: 'Test User',
    };

    const otpToken = '123456';

    (User.findOne as any).mockResolvedValue(mockUser);
    (createAndStoreOTP as any).mockResolvedValue(otpToken);
    (getOtpView as any).mockReturnValue('<html>OTP: 123456</html>');
    (sendEmail as any).mockResolvedValue(false);

    await forgetPassword(mockReq as Request, mockRes as Response, mockNext);

    expect(User.findOne).toHaveBeenCalledWith({ email });
    expect(createAndStoreOTP).toHaveBeenCalledWith(email);
    expect(getOtpView).toHaveBeenCalledWith(otpToken);
    expect(sendEmail).toHaveBeenCalledWith({
      from: process.env.RESEND_EMAIL_USER,
      to: email,
      subject: YOUR_PASSWORD_RESET_CODE,
      html: '<html>OTP: 123456</html>',
    });
    expect(mockRes.status).toHaveBeenCalledWith(400);
    expect(mockRes.json).toHaveBeenCalledWith({
      message: SOMETHING_WENT_WRONG,
    });
  });

  it('should return 200 with success message on successful email send', async () => {
    const email = 'test@example.com';
    mockReq.body = { email };

    const mockUser = {
      _id: 'user123',
      email: 'test@example.com',
      name: 'Test User',
    };

    const otpToken = '123456';

    (User.findOne as any).mockResolvedValue(mockUser);
    (createAndStoreOTP as any).mockResolvedValue(otpToken);
    (getOtpView as any).mockReturnValue('<html>OTP: 123456</html>');
    (sendEmail as any).mockResolvedValue(true);

    await forgetPassword(mockReq as Request, mockRes as Response, mockNext);

    expect(User.findOne).toHaveBeenCalledWith({ email });
    expect(createAndStoreOTP).toHaveBeenCalledWith(email);
    expect(getOtpView).toHaveBeenCalledWith(otpToken);
    expect(sendEmail).toHaveBeenCalledWith({
      from: process.env.RESEND_EMAIL_USER,
      to: email,
      subject: YOUR_PASSWORD_RESET_CODE,
      html: '<html>OTP: 123456</html>',
    });
    expect(mockRes.status).toHaveBeenCalledWith(200);
    expect(mockRes.json).toHaveBeenCalledWith({
      email: email,
      message: EMAIL_SENT_SUCCESSFULLY,
    });
  });
});

describe('verifyOtp', () => {
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: NextFunction;

  beforeEach(() => {
    mockReq = {
      body: {},
    };
    mockRes = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
    };
    mockNext = vi.fn();
    vi.clearAllMocks();
  });

  it('should return 401 if user is not found', async () => {
    const email = 'nonexistent@example.com';
    const otp = '123456';
    mockReq.body = { email, otp };

    (User.findOne as any).mockResolvedValue(null);

    await verifyOtp(mockReq as Request, mockRes as Response, mockNext);

    expect(User.findOne).toHaveBeenCalledWith({ email });
    expect(mockRes.status).toHaveBeenCalledWith(401);
    expect(mockRes.json).toHaveBeenCalledWith({
      message: EMAIL_NOT_ASSOCIATED_WITH_ACCOUNT,
    });
    expect(verifyOTP).not.toHaveBeenCalled();
  });

  it('should return 400 if OTP verification fails', async () => {
    const email = 'test@example.com';
    const otp = '123456';
    mockReq.body = { email, otp };

    const mockUser = {
      _id: 'user123',
      email: 'test@example.com',
      name: 'Test User',
    };

    (User.findOne as any).mockResolvedValue(mockUser);
    (verifyOTP as any).mockResolvedValue(null);

    await verifyOtp(mockReq as Request, mockRes as Response, mockNext);

    expect(User.findOne).toHaveBeenCalledWith({ email });
    expect(verifyOTP).toHaveBeenCalledWith(email, otp, false);
    expect(mockRes.status).toHaveBeenCalledWith(400);
    expect(mockRes.json).toHaveBeenCalledWith({
      message: OTP_EXPIRED_OR_INVALID,
    });
  });

  it('should return 200 with success message on successful OTP verification', async () => {
    const email = 'test@example.com';
    const otp = '123456';
    mockReq.body = { email, otp };

    const mockUser = {
      _id: 'user123',
      email: 'test@example.com',
      name: 'Test User',
    };

    const verifyToken = 'verification-token-123';

    (User.findOne as any).mockResolvedValue(mockUser);
    (verifyOTP as any).mockResolvedValue(verifyToken);

    await verifyOtp(mockReq as Request, mockRes as Response, mockNext);

    expect(User.findOne).toHaveBeenCalledWith({ email });
    expect(verifyOTP).toHaveBeenCalledWith(email, otp, false);
    expect(mockRes.status).toHaveBeenCalledWith(200);
    expect(mockRes.json).toHaveBeenCalledWith({
      email: email,
      message: OTP_VERIFIED_SUCCESSFULLY,
    });
  });
});

describe('resetPassword', () => {
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: NextFunction;
  let mockUserInstance: any;

  beforeEach(() => {
    mockReq = {
      body: {},
    };
    mockRes = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
    };
    mockNext = vi.fn();
    
    mockUserInstance = {
      _id: 'user123',
      email: 'test@example.com',
      name: 'Test User',
      password: 'oldHashedPassword123',
      save: vi.fn().mockResolvedValue(true),
    };
    
    vi.clearAllMocks();
  });

  it('should return 401 if user is not found', async () => {
    const email = 'nonexistent@example.com';
    const password = 'newPassword123';
    const otp = '123456';
    mockReq.body = { email, password, otp };

    (User.findOne as any).mockResolvedValue(null);

    await resetPassword(mockReq as Request, mockRes as Response, mockNext);

    expect(User.findOne).toHaveBeenCalledWith({ email });
    expect(mockRes.status).toHaveBeenCalledWith(401);
    expect(mockRes.json).toHaveBeenCalledWith({
      message: EMAIL_NOT_ASSOCIATED_WITH_ACCOUNT,
    });
    expect(bcrypt.hash).not.toHaveBeenCalled();
  });

  it('should return 400 if new password is same as old password', async () => {
    const email = 'test@example.com';
    const password = 'samePassword';
    const otp = '123456';
    mockReq.body = { email, password, otp };

    (User.findOne as any).mockResolvedValue(mockUserInstance);
    (bcrypt.compare as any).mockResolvedValue(true);

    await resetPassword(mockReq as Request, mockRes as Response, mockNext);

    expect(User.findOne).toHaveBeenCalledWith({ email });
    expect(bcrypt.hash).toHaveBeenCalledWith(password, 12);
    expect(bcrypt.compare).toHaveBeenCalledWith(password, mockUserInstance.password);
    expect(mockRes.status).toHaveBeenCalledWith(400);
    expect(mockRes.json).toHaveBeenCalledWith({
        message: CANNOT_USE_YOUR_PREVIOUS_PASSWORD,
    });
    expect(verifyOTP).not.toHaveBeenCalled();
  });

  it('should return 400 if OTP verification fails', async () => {
    const email = 'test@example.com';
    const password = 'newPassword123';
    const otp = '123456';
    mockReq.body = { email, password, otp };

    (User.findOne as any).mockResolvedValue(mockUserInstance);
    (bcrypt.hash as any).mockResolvedValue('hashedNewPassword123');
    (bcrypt.compare as any).mockResolvedValue(false);
    (verifyOTP as any).mockResolvedValue(null);

    await resetPassword(mockReq as Request, mockRes as Response, mockNext);

    expect(User.findOne).toHaveBeenCalledWith({ email });
    expect(bcrypt.hash).toHaveBeenCalledWith(password, 12);
    expect(bcrypt.compare).toHaveBeenCalledWith(password, mockUserInstance.password);
    expect(verifyOTP).toHaveBeenCalledWith(email, otp, true);
    expect(mockRes.status).toHaveBeenCalledWith(400);
    expect(mockRes.json).toHaveBeenCalledWith({
      message: RESET_PASSWORD_TIMED_OUT,
    });
    expect(sendEmail).not.toHaveBeenCalled();
  });

  it('should return 400 if email send fails', async () => {
    const email = 'test@example.com';
    const password = 'newPassword123';
    const otp = '123456';
    mockReq.body = { email, password, otp };

    const hashedPassword = 'hashedNewPassword123';
    const verifyToken = 'verification-token-123';

    (User.findOne as any).mockResolvedValue(mockUserInstance);
    (bcrypt.hash as any).mockResolvedValue(hashedPassword);
    (bcrypt.compare as any).mockResolvedValue(false);
    (verifyOTP as any).mockResolvedValue(verifyToken);
    (resetPasswordView as any).mockReturnValue('<html>Password reset successful</html>');
    (sendEmail as any).mockResolvedValue(false);

    await resetPassword(mockReq as Request, mockRes as Response, mockNext);

    expect(User.findOne).toHaveBeenCalledWith({ email });
    expect(bcrypt.hash).toHaveBeenCalledWith(password, 12);
    expect(bcrypt.compare).toHaveBeenCalledWith(password, mockUserInstance.password);
    expect(verifyOTP).toHaveBeenCalledWith(email, otp, true);
    expect(resetPasswordView).toHaveBeenCalledWith(email);
    expect(sendEmail).toHaveBeenCalledWith({
      from: process.env.RESEND_EMAIL_USER,
      to: email,
      subject: PASSWORD_RESET_SUCCESSFUL,
      html: '<html>Password reset successful</html>',
    });
    expect(mockRes.status).toHaveBeenCalledWith(400);
    expect(mockRes.json).toHaveBeenCalledWith({
      message: SOMETHING_WENT_WRONG,
    });
    expect(mockUserInstance.save).not.toHaveBeenCalled();
  });

  it('should successfully reset password and return 200', async () => {
    const email = 'test@example.com';
    const password = 'newPassword123';
    const otp = '123456';
    mockReq.body = { email, password, otp };

    const hashedPassword = 'hashedNewPassword123';
    const verifyToken = 'verification-token-123';

    (User.findOne as any).mockResolvedValue(mockUserInstance);
    (bcrypt.hash as any).mockResolvedValue(hashedPassword);
    (bcrypt.compare as any).mockResolvedValue(false);
    (verifyOTP as any).mockResolvedValue(verifyToken);
    (resetPasswordView as any).mockReturnValue('<html>Password reset successful</html>');
    (sendEmail as any).mockResolvedValue(true);

    await resetPassword(mockReq as Request, mockRes as Response, mockNext);

    expect(User.findOne).toHaveBeenCalledWith({ email });
    expect(bcrypt.hash).toHaveBeenCalledWith(password, 12);
    expect(bcrypt.compare).toHaveBeenCalledWith(password, "oldHashedPassword123");
    expect(verifyOTP).toHaveBeenCalledWith(email, otp, true);
    expect(resetPasswordView).toHaveBeenCalledWith(email);
    expect(sendEmail).toHaveBeenCalledWith({
      from: process.env.RESEND_EMAIL_USER,
      to: email,
      subject: PASSWORD_RESET_SUCCESSFUL,
      html: '<html>Password reset successful</html>',
    });
    expect(mockUserInstance.password).toBe(hashedPassword);
    expect(mockUserInstance.save).toHaveBeenCalled();
    expect(mockRes.status).toHaveBeenCalledWith(200);
    expect(mockRes.json).toHaveBeenCalledWith({
      email: email,
      message: PASSWORD_CHANGED_SUCCESSFULLY,
    });
  });
});


