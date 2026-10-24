import { createHash, randomInt, timingSafeEqual } from 'node:crypto';
import { Router } from 'express';
import { z } from 'zod';
import type { AppContext } from '../context.js';
import { currentUser, issueSession, limitOrThrow, requireAuth } from '../lib/auth.js';
import { HttpError, handler, parse } from '../lib/http.js';
import { logger } from '../logger.js';
import { User, publicUser } from '../models/User.js';

/**
 * Email sign-in codes. Like Google/GitHub sign-in, a code proves who you are but cannot
 * unlock your keys; a new device still needs the password, a passkey or the recovery key.
 */
const CODE_TTL_SECONDS = 600;
const MAX_ATTEMPTS = 5;

const email = z.string().trim().toLowerCase().email().max(254);
const code = z.string().trim().regex(/^\d{6}$/, 'Enter the 6-digit code');

const digest = (s: string) => createHash('sha256').update(s).digest();

interface Pending {
  email: string;
  hash: string;
}

export function emailRoutes(ctx: AppContext): Router {
  const r = Router();

  function requireMailer() {
    if (!ctx.mailer) throw new HttpError(404, 'Email sign-in is not enabled');
    return ctx.mailer;
  }

  async function sendCode(key: string, to: string, intro: string) {
    const value = String(randomInt(0, 1_000_000)).padStart(6, '0');
    const pending: Pending = { email: to, hash: digest(value).toString('base64') };
    await ctx.redis.set(key, JSON.stringify(pending), 'EX', CODE_TTL_SECONDS);
    await ctx.redis.del(`${key}:tries`);
    try {
      await requireMailer().send(
        to,
        `Your EchoCrypt code: ${value}`,
        `${intro}\n\nYour code is ${value}. It expires in 10 minutes.\n\nIf you did not ask for this, you can ignore this email.`,
      );
    } catch (err) {
      logger.error({ err }, 'sending email failed');
      throw new HttpError(502, 'Could not send the email, try again later');
    }
  }

  /** Checks a code; each code allows MAX_ATTEMPTS guesses, then it is burned. */
  async function checkCode(key: string, guess: string): Promise<Pending> {
    const raw = await ctx.redis.get(key);
    const tries = await ctx.redis.incr(`${key}:tries`);
    await ctx.redis.expire(`${key}:tries`, CODE_TTL_SECONDS);
    const pending = raw ? (JSON.parse(raw) as Pending) : null;
    const ok = pending && tries <= MAX_ATTEMPTS && timingSafeEqual(digest(guess), Buffer.from(pending.hash, 'base64'));
    if (!pending || !ok) {
      if (tries >= MAX_ATTEMPTS) await ctx.redis.del(key);
      throw new HttpError(400, tries >= MAX_ATTEMPTS ? 'Too many wrong codes. Request a new one.' : 'That code is wrong or expired');
    }
    await ctx.redis.del(key, `${key}:tries`);
    return pending;
  }

  // --- Adding an address (signed in) -----------------------------------------

  r.post(
    '/email',
    requireAuth,
    handler(async (req, res) => {
      requireMailer();
      const userId = currentUser(req);
      const address = parse(z.object({ email }), req.body).email;
      await limitOrThrow(ctx.redis, res, `email-link:${userId}`, 5, 60 * 60_000);
      const taken = await User.exists({ email: address, _id: { $ne: userId } });
      if (taken) throw new HttpError(409, 'That email is already used by another account');
      await sendCode(`email:link:${userId}`, address, 'Confirm this address for signing in to EchoCrypt.');
      res.status(204).end();
    }),
  );

  r.post(
    '/email/verify',
    requireAuth,
    handler(async (req, res) => {
      const userId = currentUser(req);
      const guess = parse(z.object({ code }), req.body).code;
      const pending = await checkCode(`email:link:${userId}`, guess);
      await User.updateOne({ _id: userId }, { $set: { email: pending.email } }).catch((err: { code?: number }) => {
        if (err.code === 11000) throw new HttpError(409, 'That email is already used by another account');
        throw err;
      });
      res.json({ email: pending.email });
    }),
  );

  r.delete(
    '/email',
    requireAuth,
    handler(async (req, res) => {
      await User.updateOne({ _id: currentUser(req) }, { $unset: { email: 1 } });
      res.status(204).end();
    }),
  );

  // --- Signing in with a code -------------------------------------------------

  r.post(
    '/email/login/start',
    handler(async (req, res) => {
      requireMailer();
      const address = parse(z.object({ email }), req.body).email;
      await limitOrThrow(ctx.redis, res, `email-login:${req.ip}`, 10, 60 * 60_000);
      await limitOrThrow(ctx.redis, res, `email-login:${address}`, 5, 60 * 60_000);
      // Same response whether or not the address belongs to someone.
      if (await User.exists({ email: address })) {
        await sendCode(`email:login:${address}`, address, 'Someone (hopefully you) asked to sign in to EchoCrypt.');
      }
      res.status(204).end();
    }),
  );

  r.post(
    '/email/login',
    handler(async (req, res) => {
      const body = parse(z.object({ email, code }), req.body);
      const pending = await checkCode(`email:login:${body.email}`, body.code);
      const user = await User.findOne({ email: pending.email }).lean();
      if (!user) throw new HttpError(400, 'That code is wrong or expired');
      issueSession(res, String(user._id));
      res.json({ user: publicUser(user) });
    }),
  );

  return r;
}
