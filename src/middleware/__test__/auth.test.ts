import { describe, it, expect, beforeEach, vi } from 'vitest';
import { Request, Response, NextFunction } from 'express';
import { istokenValid, decodeToken, handleTokenError } from '../utils/auth';
import jwt from 'jsonwebtoken';
import redis from '../../services/redis';
import {
  INVALID_TOKEN,
  SOMETHING_WENT_WRONG,
  TOKEN_EXPIRED,
  UNAUTHORIZED_USER,
} from '../../lib/constants/messages';

vi.mock('../../services/redis', () => ({
  default: {
    get: vi.fn(),
  },
}));

vi.mock('jsonwebtoken', () => ({
  default: {
    verify: vi.fn(),
  },
}));

describe('istokenValid', () => {
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;

  beforeEach(() => {
    mockReq = {
      get: vi.fn(),
    };
    mockRes = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
    };
    vi.clearAllMocks();
  });

  it('should return 401 if no authorization header is present', async () => {
    (mockReq.get as any).mockReturnValue(undefined);

    const result = await istokenValid(mockReq as Request, mockRes as Response);

    expect(mockRes.status).toHaveBeenCalledWith(401);
    expect(mockRes.json).toHaveBeenCalledWith({ message: UNAUTHORIZED_USER });
    expect(result).toBe(mockRes);
  });

  it('should return 401 if token is missing from header', async () => {
    (mockReq.get as any).mockReturnValue('Bearer');

    const result = await istokenValid(mockReq as Request, mockRes as Response);

    expect(mockRes.status).toHaveBeenCalledWith(401);
    expect(mockRes.json).toHaveBeenCalledWith({ message: UNAUTHORIZED_USER });
    expect(result).toBe(mockRes);
  });

  it('should return 401 if token is blacklisted', async () => {
    const token = 'valid-token';
    (mockReq.get as any).mockReturnValue(`Bearer ${token}`);
    (redis.get as any).mockResolvedValue('blacklisted');

    const result = await istokenValid(mockReq as Request, mockRes as Response);

    expect(redis.get).toHaveBeenCalledWith(token);
    expect(mockRes.status).toHaveBeenCalledWith(401);
    expect(result).toBe(mockRes);
  });

  it('should return token if valid and not blacklisted', async () => {
    const token = 'valid-token';
    (mockReq.get as any).mockReturnValue(`Bearer ${token}`);
    (redis.get as any).mockResolvedValue(null);

    const result = await istokenValid(mockReq as Request, mockRes as Response);

    expect(redis.get).toHaveBeenCalledWith(token);
    expect(result).toBe(token);
  });
});

describe('decodeToken', () => {
  let mockReq: Partial<Request>;
  let mockRes: Partial<Response>;
  let mockNext: NextFunction;

  beforeEach(() => {
    mockReq = {};
    mockRes = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
    };
    mockNext = vi.fn();
    vi.clearAllMocks();
  });

  it('should return 401 if token is invalid', async () => {
    const token = 'invalid-token';
    (jwt.verify as any).mockReturnValue(null);

    await decodeToken(token, mockReq as Request, mockRes as Response, mockNext);

    expect(mockRes.status).toHaveBeenCalledWith(401);
    expect(mockRes.json).toHaveBeenCalledWith({ message: UNAUTHORIZED_USER });
    expect(mockNext).not.toHaveBeenCalled();
  });

  it('should decode token and call next if valid', async () => {
    const token = 'valid-token';
    const decodedToken = { userId: '123', email: 'test@example.com' };
    (jwt.verify as any).mockReturnValue(decodedToken);

    await decodeToken(token, mockReq as Request, mockRes as Response, mockNext);

    expect(jwt.verify).toHaveBeenCalledWith(token, process.env.JWT_SECRET);
    expect(mockReq.user).toEqual({
      ...decodedToken,
      token,
    });
    expect(mockNext).toHaveBeenCalled();
  });
});

describe('handleTokenError', () => {
  let mockRes: Partial<Response>;

  beforeEach(() => {
    mockRes = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
    };
    vi.clearAllMocks();
  });

  it('should handle TokenExpiredError', () => {
    const error = { name: 'TokenExpiredError' };
    handleTokenError(error, mockRes as Response);
    expect(mockRes.status).toHaveBeenCalledWith(401);
    expect(mockRes.json).toHaveBeenCalledWith({ message: TOKEN_EXPIRED });
  });

  it('should handle JsonWebTokenError', () => {
    const error = { name: 'JsonWebTokenError' };
    handleTokenError(error, mockRes as Response);
    expect(mockRes.status).toHaveBeenCalledWith(401);
    expect(mockRes.json).toHaveBeenCalledWith({ message: INVALID_TOKEN });
  });

  it('should handle unknown errors', () => {
    const error = { name: 'UnknownError' };
    handleTokenError(error, mockRes as Response);
    expect(mockRes.status).toHaveBeenCalledWith(500);
    expect(mockRes.json).toHaveBeenCalledWith({
      message: SOMETHING_WENT_WRONG,
    });
  });
});
