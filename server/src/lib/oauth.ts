import { createHash, randomBytes } from 'node:crypto';
import { config } from '../config.js';

/**
 * "Sign in with Google / GitHub" (OAuth 2.0 authorization code flow).
 *
 * This only proves who the user is to the server. It cannot unlock their encryption keys:
 * on a device that has never been unlocked, the client still asks for the password, a
 * passkey or the recovery key. That is what keeps the server unable to read messages.
 */
export type ProviderName = 'google' | 'github';
export const PROVIDERS: readonly ProviderName[] = ['google', 'github'];

export interface ProviderConfig {
  clientId: string;
  clientSecret: string;
}

export type OAuthProviders = Partial<Record<ProviderName, ProviderConfig>>;

export function oauthFromConfig(): OAuthProviders {
  const out: OAuthProviders = {};
  if (config.GOOGLE_CLIENT_ID && config.GOOGLE_CLIENT_SECRET) {
    out.google = { clientId: config.GOOGLE_CLIENT_ID, clientSecret: config.GOOGLE_CLIENT_SECRET };
  }
  if (config.GITHUB_CLIENT_ID && config.GITHUB_CLIENT_SECRET) {
    out.github = { clientId: config.GITHUB_CLIENT_ID, clientSecret: config.GITHUB_CLIENT_SECRET };
  }
  return out;
}

const b64url = (b: Buffer) => b.toString('base64url');

export function newFlowSecrets(): { state: string; verifier: string } {
  return { state: b64url(randomBytes(24)), verifier: b64url(randomBytes(32)) };
}

export function authorizeUrl(name: ProviderName, p: ProviderConfig, redirectUri: string, state: string, verifier: string): string {
  const challenge = b64url(createHash('sha256').update(verifier).digest());
  const params = new URLSearchParams({
    client_id: p.clientId,
    redirect_uri: redirectUri,
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  });
  if (name === 'google') {
    params.set('response_type', 'code');
    params.set('scope', 'openid email profile');
    params.set('prompt', 'select_account');
    return `https://accounts.google.com/o/oauth2/v2/auth?${params}`;
  }
  params.set('scope', 'read:user');
  params.set('allow_signup', 'false');
  return `https://github.com/login/oauth/authorize?${params}`;
}

export interface ProviderUser {
  /** Stable id at the provider. */
  id: string;
  /** What to show for the link: an email (Google) or @login (GitHub). */
  label: string;
  /** Real name if the provider shares one; prefills sign-up. */
  name: string | null;
  /** Basis for a suggested username: the email's local part or the GitHub login. */
  handle: string;
}

/** Exchanges the code and returns who the user is at the provider. */
export async function fetchProviderUser(
  name: ProviderName,
  p: ProviderConfig,
  code: string,
  redirectUri: string,
  verifier: string,
): Promise<ProviderUser> {
  const form = new URLSearchParams({
    client_id: p.clientId,
    client_secret: p.clientSecret,
    code,
    redirect_uri: redirectUri,
    code_verifier: verifier,
    grant_type: 'authorization_code',
  });
  const tokenUrl = name === 'google' ? 'https://oauth2.googleapis.com/token' : 'https://github.com/login/oauth/access_token';
  const tokenRes = await fetch(tokenUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
    body: form,
  });
  const token = (await tokenRes.json().catch(() => ({}))) as { access_token?: string };
  if (!tokenRes.ok || !token.access_token) throw new Error(`${name} token exchange failed (${tokenRes.status})`);

  const headers = { authorization: `Bearer ${token.access_token}`, accept: 'application/json', 'user-agent': 'EchoCrypt' };
  if (name === 'google') {
    const res = await fetch('https://openidconnect.googleapis.com/v1/userinfo', { headers });
    const u = (await res.json().catch(() => ({}))) as { sub?: string; email?: string; name?: string };
    if (!res.ok || !u.sub) throw new Error(`google userinfo failed (${res.status})`);
    return { id: u.sub, label: u.email ?? 'Google account', name: u.name ?? null, handle: u.email?.split('@')[0] ?? '' };
  }
  const res = await fetch('https://api.github.com/user', { headers });
  const u = (await res.json().catch(() => ({}))) as { id?: number; login?: string; name?: string | null };
  if (!res.ok || typeof u.id !== 'number') throw new Error(`github user lookup failed (${res.status})`);
  return { id: String(u.id), label: u.login ? `@${u.login}` : 'GitHub account', name: u.name ?? null, handle: u.login ?? '' };
}
