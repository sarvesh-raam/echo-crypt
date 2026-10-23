import { PBKDF2_ITERATIONS, validatePublicKeys } from '@echocrypt/crypto';
import { Router } from 'express';
import { config } from '../config.js';
import { z } from 'zod';
import type { AppContext } from '../context.js';
import {
  clearSession,
  currentUser,
  decoySalt,
  hashAuthKey,
  issueSession,
  requireAuth,
  verifyAuthKey,
} from '../lib/auth.js';
import { HttpError, handler, parse } from '../lib/http.js';
import { rateLimit } from '../lib/rateLimit.js';
import { User, publicUser } from '../models/User.js';

const b64 = (max: number) => z.string().min(1).max(max).regex(/^[A-Za-z0-9+/]+={0,2}$/, 'Expected base64');
const wrapped = z.object({ iv: b64(32), data: b64(1024) });
const username = z
  .string()
  .trim()
  .toLowerCase()
  .regex(/^[a-z0-9_]{3,24}$/, 'Username: 3-24 letters, digits or underscores');

const registerBody = z.object({
  username,
  displayName: z.string().trim().min(1).max(48),
  kdfSalt: b64(64),
  kdfIterations: z.number().int().min(100_000).max(10_000_000),
  authKey: b64(64),
  publicKeys: z.object({ dh: b64(256), sign: b64(256) }),
  encryptedKeys: z.object({ dhPrivate: wrapped, signPrivate: wrapped }),
});

const loginBody = z.object({ username, authKey: b64(64) });

export function authRoutes(ctx: AppContext): Router {
  const r = Router();

  /** KDF parameters the client needs before it can derive its auth key. */
  r.get(
    '/params',
    handler(async (req, res) => {
      const name = parse(username, req.query.username);
      const user = await User.findOne({ username: name }, { kdfSalt: 1, kdfIterations: 1 }).lean();
      res.json(
        user
          ? { salt: user.kdfSalt, iterations: user.kdfIterations }
          : { salt: decoySalt(name), iterations: PBKDF2_ITERATIONS },
      );
    }),
  );

  r.post(
    '/register',
    handler(async (req, res) => {
      const retry = await rateLimit(ctx.redis, `register:${req.ip}`, config.REGISTER_LIMIT_PER_HOUR, 60 * 60_000);
      if (retry) throw new HttpError(429, 'Too many sign-ups from this address, try again later');

      const body = parse(registerBody, req.body);
      await validatePublicKeys(body.publicKeys).catch(() => {
        throw new HttpError(400, 'Invalid public keys');
      });
      if (await User.exists({ username: body.username })) throw new HttpError(409, 'Username is taken');

      const { hash, salt } = await hashAuthKey(body.authKey);
      let user;
      try {
        user = await User.create({
          username: body.username,
          displayName: body.displayName,
          kdfSalt: body.kdfSalt,
          kdfIterations: body.kdfIterations,
          authHash: hash,
          authSalt: salt,
          publicKeys: body.publicKeys,
          encryptedKeys: body.encryptedKeys,
        });
      } catch (err) {
        if ((err as { code?: number }).code === 11000) throw new HttpError(409, 'Username is taken');
        throw err;
      }
      issueSession(res, String(user._id));
      res.status(201).json({ user: publicUser(user) });
    }),
  );

  r.post(
    '/login',
    handler(async (req, res) => {
      const body = parse(loginBody, req.body);
      const retry = await rateLimit(ctx.redis, `login:${req.ip}:${body.username}`, 10, 15 * 60_000);
      if (retry) {
        res.setHeader('Retry-After', Math.ceil(retry / 1000));
        throw new HttpError(429, 'Too many attempts, try again later');
      }
      const user = await User.findOne({ username: body.username }).lean();
      // Same error (and similar work) for unknown users and wrong passwords.
      const ok = user
        ? await verifyAuthKey(body.authKey, user.authHash, user.authSalt)
        : (await hashAuthKey(body.authKey), false);
      if (!user || !ok) throw new HttpError(401, 'Wrong username or password');

      issueSession(res, String(user._id));
      res.json({ user: publicUser(user), encryptedKeys: user.encryptedKeys });
    }),
  );

  r.get(
    '/me',
    requireAuth,
    handler(async (req, res) => {
      const user = await User.findById(currentUser(req)).lean();
      if (!user) {
        clearSession(res);
        throw new HttpError(401, 'Not signed in');
      }
      res.json({ user: publicUser(user) });
    }),
  );

  r.post('/logout', (_req, res) => {
    clearSession(res);
    res.status(204).end();
  });

  return r;
}
