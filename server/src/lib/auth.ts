import { createHmac, randomBytes, scrypt as scryptCb, timingSafeEqual, type ScryptOptions } from 'node:crypto';
import { parse as parseCookie, serialize } from 'cookie';
import type { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config.js';
import { HttpError } from './http.js';

export const SESSION_COOKIE = 'ec_session';
const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;
const SCRYPT: ScryptOptions = { N: 1 << 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

const scrypt = (secret: Buffer, salt: Buffer) =>
  new Promise<Buffer>((resolve, reject) =>
    scryptCb(secret, salt, 32, SCRYPT, (err, key) => (err ? reject(err) : resolve(key))),
  );

/**
 * The client sends authKey = HKDF(PBKDF2(password)). It is already a strong secret,
 * but it is hashed again so a database leak does not hand out working login tokens.
 */
export async function hashAuthKey(authKey: string): Promise<{ hash: string; salt: string }> {
  const salt = randomBytes(16);
  const hash = await scrypt(Buffer.from(authKey, 'base64'), salt);
  return { hash: hash.toString('base64'), salt: salt.toString('base64') };
}

export async function verifyAuthKey(authKey: string, hash: string, salt: string): Promise<boolean> {
  const actual = await scrypt(Buffer.from(authKey, 'base64'), Buffer.from(salt, 'base64'));
  const expected = Buffer.from(hash, 'base64');
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

/** Deterministic decoy KDF salt for unknown usernames, so the params endpoint can't enumerate users. */
export function decoySalt(username: string): string {
  return createHmac('sha256', config.JWT_SECRET).update(`kdf-salt:${username}`).digest().subarray(0, 16).toString('base64');
}

export function issueSession(res: Response, userId: string): void {
  const token = jwt.sign({}, config.JWT_SECRET, { subject: userId, expiresIn: SESSION_TTL_SECONDS, algorithm: 'HS256' });
  res.setHeader(
    'Set-Cookie',
    serialize(SESSION_COOKIE, token, {
      httpOnly: true,
      secure: config.COOKIE_SECURE,
      sameSite: 'strict',
      path: '/',
      maxAge: SESSION_TTL_SECONDS,
    }),
  );
}

export function clearSession(res: Response): void {
  res.setHeader(
    'Set-Cookie',
    serialize(SESSION_COOKIE, '', { httpOnly: true, secure: config.COOKIE_SECURE, sameSite: 'strict', path: '/', maxAge: 0 }),
  );
}

/** Returns the user id from a Cookie header, or null if there is no valid session. */
export function userIdFromCookie(header: string | undefined): string | null {
  if (!header) return null;
  const token = parseCookie(header)[SESSION_COOKIE];
  if (!token) return null;
  try {
    const payload = jwt.verify(token, config.JWT_SECRET, { algorithms: ['HS256'] });
    return typeof payload === 'object' && typeof payload.sub === 'string' ? payload.sub : null;
  } catch {
    return null;
  }
}

declare module 'express-serve-static-core' {
  interface Request {
    userId?: string;
  }
}

export function requireAuth(req: Request, _res: Response, next: NextFunction): void {
  const userId = userIdFromCookie(req.headers.cookie);
  if (!userId) return next(new HttpError(401, 'Not signed in'));
  req.userId = userId;
  next();
}

export const currentUser = (req: Request): string => {
  if (!req.userId) throw new HttpError(401, 'Not signed in');
  return req.userId;
};
