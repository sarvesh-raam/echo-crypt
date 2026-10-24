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
  limitOrThrow,
  requireAuth,
  verifyAuthKey,
} from '../lib/auth.js';
import { HttpError, handler, parse } from '../lib/http.js';
import { PROVIDERS } from '../lib/oauth.js';
import { clearPendingSignup, readPendingSignup, suggestUsername } from '../lib/signup.js';
import { rateLimit } from '../lib/rateLimit.js';
import { User, keyBundle, publicUser } from '../models/User.js';

export const b64 = (max: number) => z.string().min(1).max(max).regex(/^[A-Za-z0-9+/]+={0,2}$/, 'Expected base64');
export const wrapped = z.object({ iv: b64(32), data: b64(1024) });
export const username = z
  .string()
  .trim()
  .toLowerCase()
  .regex(/^[a-z0-9_]{3,24}$/, 'Username: 3-24 letters, digits or underscores');

const passwordFields = {
  kdfSalt: b64(64),
  kdfIterations: z.number().int().min(100_000).max(10_000_000),
  authKey: b64(64),
  /** The account key sealed under the password-derived key. */
  passwordSlot: wrapped,
};

const registerBody = z.object({
  username,
  displayName: z.string().trim().min(1).max(48),
  ...passwordFields,
  publicKeys: z.object({ dh: b64(256), sign: b64(256) }),
  encryptedKeys: z.object({ dhPrivate: wrapped, signPrivate: wrapped }),
  /** Recovery key slot, created together with the account. */
  recovery: z.object({ authKey: b64(64), slot: wrapped }).optional(),
  /** Link the Google/GitHub account from a pending "Continue with …" sign-up. */
  linkPending: z.boolean().optional(),
});

const loginBody = z.object({ username, authKey: b64(64) });
const recoverySetBody = z.object({ authKey: b64(64), slot: wrapped });
const recoveryFinishBody = z.object({ username, recoveryAuthKey: b64(64), ...passwordFields });
const passwordChangeBody = z.object({ currentAuthKey: b64(64), ...passwordFields });

const WRONG_RECOVERY = 'Wrong username or recovery key';

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

  /** Which optional sign-in methods this deployment offers. */
  r.get('/providers', (_req, res) => {
    res.json({
      google: !!ctx.oauth.google,
      github: !!ctx.oauth.github,
      email: !!ctx.mailer,
    });
  });

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

      const pending = body.linkPending ? readPendingSignup(req) : null;
      if (body.linkPending && !pending) throw new HttpError(400, 'Sign-up with Google/GitHub expired. Please start again.');

      const { hash, salt } = await hashAuthKey(body.authKey);
      const recovery = body.recovery ? await hashAuthKey(body.recovery.authKey) : null;
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
          keySlots: { password: body.passwordSlot, ...(body.recovery ? { recovery: body.recovery.slot } : {}) },
          ...(recovery ? { recoveryHash: recovery.hash, recoverySalt: recovery.salt } : {}),
          ...(pending ? { oauth: { [pending.provider]: { id: pending.account.id, label: pending.account.label } } } : {}),
        });
      } catch (err) {
        if ((err as { code?: number; keyPattern?: Record<string, unknown> }).code === 11000) {
          const field = Object.keys((err as { keyPattern?: Record<string, unknown> }).keyPattern ?? {})[0] ?? '';
          throw new HttpError(409, field.startsWith('oauth') ? 'That account is already linked to another user' : 'Username is taken');
        }
        throw err;
      }
      if (pending) clearPendingSignup(res);
      issueSession(res, String(user._id));
      res.status(201).json({ user: publicUser(user) });
    }),
  );

  r.post(
    '/login',
    handler(async (req, res) => {
      const body = parse(loginBody, req.body);
      await limitOrThrow(ctx.redis, res, `login:${req.ip}:${body.username}`, 10, 15 * 60_000);
      const user = await User.findOne({ username: body.username }).lean();
      // Same error (and similar work) for unknown users and wrong passwords.
      const ok = user
        ? await verifyAuthKey(body.authKey, user.authHash, user.authSalt)
        : (await hashAuthKey(body.authKey), false);
      if (!user || !ok) throw new HttpError(401, 'Wrong username or password');

      issueSession(res, String(user._id));
      res.json({ user: publicUser(user), ...keyBundle(user, user.keySlots!.password!) });
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

  /** Who the pending "Continue with Google/GitHub" sign-up is for, to prefill the form. */
  r.get(
    '/signup/pending',
    handler(async (req, res) => {
      const pending = readPendingSignup(req);
      if (!pending) throw new HttpError(404, 'No sign-up in progress');
      res.json({
        provider: pending.provider,
        label: pending.account.label,
        displayName: (pending.account.name ?? pending.account.handle).slice(0, 48) || null,
        username: await suggestUsername(pending.account.handle),
      });
    }),
  );

  r.delete('/signup/pending', (_req, res) => {
    clearPendingSignup(res);
    res.status(204).end();
  });

  /** Changes the password. Needs the current one (its auth key), so a stolen session is not enough. */
  r.post(
    '/password',
    requireAuth,
    handler(async (req, res) => {
      const userId = currentUser(req);
      const body = parse(passwordChangeBody, req.body);
      await limitOrThrow(ctx.redis, res, `password:${userId}`, 10, 15 * 60_000);
      const user = await User.findById(userId).lean();
      if (!user || !(await verifyAuthKey(body.currentAuthKey, user.authHash, user.authSalt))) {
        throw new HttpError(401, 'Current password is wrong');
      }
      const { hash, salt } = await hashAuthKey(body.authKey);
      await User.updateOne(
        { _id: userId },
        {
          $set: {
            kdfSalt: body.kdfSalt,
            kdfIterations: body.kdfIterations,
            authHash: hash,
            authSalt: salt,
            'keySlots.password': body.passwordSlot,
          },
        },
      );
      res.status(204).end();
    }),
  );

  r.post('/logout', (_req, res) => {
    clearSession(res);
    res.status(204).end();
  });

  /** Sign-in methods set up on this account, for the security settings screen. */
  r.get(
    '/security',
    requireAuth,
    handler(async (req, res) => {
      const user = await User.findById(currentUser(req)).lean();
      if (!user) throw new HttpError(401, 'Not signed in');
      res.json({
        recovery: !!user.keySlots?.recovery,
        passkeys: (user.passkeys ?? []).map((p) => ({
          id: p.credentialId,
          name: p.name,
          createdAt: p.createdAt.toISOString(),
          lastUsedAt: p.lastUsedAt?.toISOString() ?? null,
        })),
        email: user.email ?? null,
        oauth: Object.fromEntries(PROVIDERS.map((p) => [p, user.oauth?.[p]?.label ?? null])),
      });
    }),
  );

  // --- Recovery key -------------------------------------------------------

  /** Stores (or replaces) the recovery slot. The client made it from the unlocked account key. */
  r.put(
    '/recovery',
    requireAuth,
    handler(async (req, res) => {
      const body = parse(recoverySetBody, req.body);
      const { hash, salt } = await hashAuthKey(body.authKey);
      await User.updateOne(
        { _id: currentUser(req) },
        { $set: { 'keySlots.recovery': body.slot, recoveryHash: hash, recoverySalt: salt } },
      );
      res.status(204).end();
    }),
  );

  r.delete(
    '/recovery',
    requireAuth,
    handler(async (req, res) => {
      await User.updateOne({ _id: currentUser(req) }, { $unset: { 'keySlots.recovery': 1, recoveryHash: 1, recoverySalt: 1 } });
      res.status(204).end();
    }),
  );

  async function checkRecovery(name: string, authKey: string) {
    const user = await User.findOne({ username: name }).lean();
    const ok =
      user?.recoveryHash && user.recoverySalt && user.keySlots?.recovery
        ? await verifyAuthKey(authKey, user.recoveryHash, user.recoverySalt)
        : (await hashAuthKey(authKey), false);
    if (!user || !ok) throw new HttpError(401, WRONG_RECOVERY);
    return user;
  }

  /** Step 1 of "forgot password": proves the recovery key and hands back the recovery slot. */
  r.post(
    '/recovery/start',
    handler(async (req, res) => {
      const body = parse(loginBody, req.body);
      await limitOrThrow(ctx.redis, res, `recover:${req.ip}:${body.username}`, 10, 15 * 60_000);
      const user = await checkRecovery(body.username, body.authKey);
      res.json({ user: publicUser(user), ...keyBundle(user, user.keySlots!.recovery!) });
    }),
  );

  /** Step 2: sets the new password (and its slot, sealed client-side) and signs in. */
  r.post(
    '/recovery/finish',
    handler(async (req, res) => {
      const body = parse(recoveryFinishBody, req.body);
      await limitOrThrow(ctx.redis, res, `recover:${req.ip}:${body.username}`, 10, 15 * 60_000);
      const user = await checkRecovery(body.username, body.recoveryAuthKey);
      const { hash, salt } = await hashAuthKey(body.authKey);
      await User.updateOne(
        { _id: user._id },
        {
          $set: {
            kdfSalt: body.kdfSalt,
            kdfIterations: body.kdfIterations,
            authHash: hash,
            authSalt: salt,
            'keySlots.password': body.passwordSlot,
          },
        },
      );
      issueSession(res, String(user._id));
      res.json({ user: publicUser(user) });
    }),
  );

  return r;
}
