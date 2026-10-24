import { randomBytes } from 'node:crypto';
import { hostname } from 'node:os';
import { z } from 'zod';

const schema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.coerce.number().int().positive().default(4000),
  MONGO_URL: z.string().default('mongodb://localhost:27017/echocrypt'),
  REDIS_URL: z.string().default('redis://localhost:6379'),
  JWT_SECRET: z.string().optional(),
  /** Shown in /health and the client's status bar, so you can see which instance served you. */
  INSTANCE_ID: z.string().default(hostname()),
  /** Directory with the built client; served by the API when set (single-container deploys). */
  STATIC_DIR: z.string().optional(),
  COOKIE_SECURE: z
    .enum(['true', 'false'])
    .optional()
    .transform((v) => (v === undefined ? undefined : v === 'true')),
  LOG_LEVEL: z.string().default('info'),
  /**
   * Express "trust proxy": how many proxy hops sit in front of the server (or true/false,
   * or a list of addresses). Decides which IP the per-IP rate limits see.
   */
  TRUST_PROXY: z
    .string()
    .default('1')
    .transform((v) => (v === 'true' ? true : v === 'false' ? false : /^\d+$/.test(v) ? Number(v) : v)),
  /** Sign-ups allowed per IP per hour. */
  REGISTER_LIMIT_PER_HOUR: z.coerce.number().int().positive().default(20),
});

const env = schema.parse(process.env);

if (env.NODE_ENV === 'production' && (!env.JWT_SECRET || env.JWT_SECRET.length < 32)) {
  throw new Error('JWT_SECRET must be set to at least 32 characters in production');
}

export const config = {
  ...env,
  JWT_SECRET: env.JWT_SECRET ?? randomBytes(32).toString('hex'),
  COOKIE_SECURE: env.COOKIE_SECURE ?? env.NODE_ENV === 'production',
};

export type Config = typeof config;
