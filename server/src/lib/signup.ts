import { parse as parseCookie, serialize } from 'cookie';
import type { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config.js';
import { User } from '../models/User.js';
import type { ProviderName, ProviderUser } from './oauth.js';

/**
 * "Continue with Google/GitHub" for someone without an account: the provider has told us
 * who they are, but the account (and its keys) can only be created in the browser. This
 * signed cookie carries the provider identity until the sign-up form is submitted.
 */
const COOKIE = 'ec_signup';
const PATH = '/api/auth';
const TTL_SECONDS = 15 * 60;

export interface PendingSignup {
  provider: ProviderName;
  account: ProviderUser;
}

export function setPendingSignup(res: Response, pending: PendingSignup): void {
  const token = jwt.sign({ p: pending.provider, a: pending.account }, config.JWT_SECRET, {
    expiresIn: TTL_SECONDS,
    algorithm: 'HS256',
  });
  res.append(
    'Set-Cookie',
    serialize(COOKIE, token, { httpOnly: true, secure: config.COOKIE_SECURE, sameSite: 'lax', path: PATH, maxAge: TTL_SECONDS }),
  );
}

export function clearPendingSignup(res: Response): void {
  res.append(
    'Set-Cookie',
    serialize(COOKIE, '', { httpOnly: true, secure: config.COOKIE_SECURE, sameSite: 'lax', path: PATH, maxAge: 0 }),
  );
}

export function readPendingSignup(req: Request): PendingSignup | null {
  const token = parseCookie(req.headers.cookie ?? '')[COOKIE];
  if (!token) return null;
  try {
    const payload = jwt.verify(token, config.JWT_SECRET, { algorithms: ['HS256'] }) as { p: ProviderName; a: ProviderUser };
    return { provider: payload.p, account: payload.a };
  } catch {
    return null;
  }
}

/** A free username based on the provider handle, e.g. "sarvesh" or "sarvesh_42". */
export async function suggestUsername(handle: string): Promise<string> {
  let root = handle
    .toLowerCase()
    .replace(/[^a-z0-9_]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 19);
  if (root.length < 3) root = `${root}user`.replace(/^_+/, '');
  if (!(await User.exists({ username: root }))) return root;
  for (let i = 0; i < 20; i++) {
    const candidate = `${root}_${Math.floor(Math.random() * 9000 + 1000)}`;
    if (!(await User.exists({ username: candidate }))) return candidate;
  }
  return root;
}
