import { describe, it, expect, beforeEach, vi } from 'vitest';
import { blackListToken, oauthSignupOrLogin } from '../auth';
import User from '../../../models/user';
import redis from '../../../services/redis';

vi.mock('../../../models/user', () => ({
  default: {
    findOne: vi.fn(),
    create: vi.fn(),
  },
}));

vi.mock('../../../services/redis', () => ({
  default: {
    set: vi.fn(),
    get: vi.fn(),
  },
}));

describe('blackListToken', () => {
  let realBlackListToken: typeof blackListToken;

  beforeEach(async () => {
    vi.clearAllMocks();
    const authUtils = await vi.importActual<typeof import('../auth')>('../auth');
    realBlackListToken = authUtils.blackListToken;
  });

  it('should successfully blacklist token when redis.set returns OK', async () => {
    const token = 'test-token-123';

    (redis.set as any).mockResolvedValue('OK');

    await realBlackListToken(token);

    expect(redis.set).toHaveBeenCalledWith(token, 'blacklisted', 'EX', 7 * 24 * 60 * 60);
  });

  it('should throw error when redis.set fails', async () => {
    const token = 'test-token-123';
    const redisError = new Error('Redis connection failed');

    (redis.set as any).mockRejectedValue(redisError);

    await expect(realBlackListToken(token)).rejects.toThrow('Redis connection failed');
    expect(redis.set).toHaveBeenCalledWith(token, 'blacklisted', 'EX', 7 * 24 * 60 * 60);
  });
});

describe('oauthSignupOrLogin', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should return existing user if provider id matches', async () => {
    const profile = {
      id: 'google-123',
      provider: 'google',
      emails: [{ value: 'test@example.com' }],
      displayName: 'Test User',
      photos: [{ value: 'https://example.com/photo.jpg' }],
    };

    const existingUser = {
      _id: 'user123',
      email: 'test@example.com',
      name: 'Test User',
      provider: {
        id: 'google-123',
        type: 'google',
      },
    };

    (User.findOne as any).mockResolvedValue(existingUser);

    const result = await oauthSignupOrLogin(profile);

    expect(User.findOne).toHaveBeenCalledWith({ email: profile.emails[0].value });
    expect(result).toBe(existingUser);
    expect(User.create).not.toHaveBeenCalled();
  });

  it('should throw error if user exists but provider id does not match', async () => {
    const profile = {
      id: 'google-123',
      provider: 'google',
      emails: [{ value: 'test@example.com' }],
      displayName: 'Test User',
      photos: [{ value: 'https://example.com/photo.jpg' }],
    };

    const existingUser = {
      _id: 'user123',
      email: 'test@example.com',
      name: 'Test User',
      provider: {
        id: 'github-456',
        type: 'github',
      },
    };

    (User.findOne as any).mockResolvedValue(existingUser);

    await expect(oauthSignupOrLogin(profile)).rejects.toThrow();

    expect(User.findOne).toHaveBeenCalledWith({ email: profile.emails[0].value });
    expect(User.create).not.toHaveBeenCalled();
  });

  it('should create new user if user does not exist', async () => {
    const profile = {
      id: 'google-123',
      provider: 'google',
      emails: [{ value: 'newuser@example.com' }],
      displayName: 'New User',
      photos: [{ value: 'https://example.com/photo.jpg' }],
    };

    const newUser = {
      _id: 'newUser123',
      email: 'newuser@example.com',
      name: 'New User',
      avatar: 'https://example.com/photo.jpg',
      provider: {
        id: 'google-123',
        type: 'google',
      },
    };

    (User.findOne as any).mockResolvedValue(null);
    (User.create as any).mockResolvedValue(newUser);

    const result = await oauthSignupOrLogin(profile);

    expect(User.findOne).toHaveBeenCalledWith({ email: profile.emails[0].value });
    expect(User.create).toHaveBeenCalledWith({
      name: profile.displayName,
      email: profile.emails[0].value,
      avatar: profile.photos[0].value,
      provider: {
        id: profile.id,
        type: profile.provider,
      },
    });
    expect(result).toBe(newUser);
  });
});
