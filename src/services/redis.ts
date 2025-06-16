import Redis from 'ioredis';
import dotenv from 'dotenv';
dotenv.config();

const redis = new Redis({
  host: process.env.REDIS_HOST as string,
  port: process.env.REDIS_PORT as number | undefined,
});

export default redis;
