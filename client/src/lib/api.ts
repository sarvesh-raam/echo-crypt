import type { WrappedSecret } from '@echocrypt/crypto';
import type { Conversation, KeyBundle, Providers, PublicUser, SecurityInfo, WireMessage } from './types';

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

async function request<T>(path: string, init: { method?: string; body?: unknown } = {}): Promise<T> {
  const res = await fetch(path, {
    method: init.method ?? (init.body === undefined ? 'GET' : 'POST'),
    credentials: 'same-origin',
    headers: init.body === undefined ? undefined : { 'content-type': 'application/json' },
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
  });
  if (res.status === 204) return undefined as T;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(res.status, (data as { error?: string }).error ?? `Request failed (${res.status})`);
  return data as T;
}

export type OAuthProvider = 'google' | 'github';

/** Full-page navigation: the provider redirects back to the server, which redirects to the app. */
export const oauthStartUrl = (provider: OAuthProvider, mode: 'login' | 'link') =>
  `/api/auth/oauth/${provider}/start?mode=${mode}`;

export const api = {
  params: (username: string) =>
    request<{ salt: string; iterations: number }>(`/api/auth/params?username=${encodeURIComponent(username)}`),
  register: (body: unknown) => request<{ user: PublicUser }>('/api/auth/register', { body }),
  login: (username: string, authKey: string) =>
    request<{ user: PublicUser } & KeyBundle>('/api/auth/login', { body: { username, authKey } }),
  providers: () => request<Providers>('/api/auth/providers'),
  pendingSignup: () =>
    request<{ provider: OAuthProvider; label: string; displayName: string | null; username: string }>('/api/auth/signup/pending'),
  cancelSignup: () => request<void>('/api/auth/signup/pending', { method: 'DELETE' }),
  changePassword: (body: unknown) => request<void>('/api/auth/password', { body }),
  security: () => request<SecurityInfo>('/api/auth/security'),

  passkeyOptions: () => request<Record<string, unknown>>('/api/auth/passkey/options', { method: 'POST' }),
  passkeyLogin: (credential: unknown) =>
    request<{ user: PublicUser } & KeyBundle>('/api/auth/passkey/login', { body: { credential } }),
  passkeyRegisterOptions: () => request<Record<string, unknown>>('/api/auth/passkeys/options', { method: 'POST' }),
  addPasskey: (credential: unknown, name: string, slot: WrappedSecret) =>
    request<{ id: string }>('/api/auth/passkeys', { body: { credential, name, slot } }),
  removePasskey: (id: string) => request<void>(`/api/auth/passkeys/${encodeURIComponent(id)}`, { method: 'DELETE' }),

  setRecovery: (authKey: string, slot: WrappedSecret) =>
    request<void>('/api/auth/recovery', { method: 'PUT', body: { authKey, slot } }),
  removeRecovery: () => request<void>('/api/auth/recovery', { method: 'DELETE' }),
  recoveryStart: (username: string, authKey: string) =>
    request<{ user: PublicUser } & KeyBundle>('/api/auth/recovery/start', { body: { username, authKey } }),
  recoveryFinish: (body: unknown) => request<{ user: PublicUser }>('/api/auth/recovery/finish', { body }),

  addEmail: (email: string) => request<void>('/api/auth/email', { body: { email } }),
  verifyEmail: (code: string) => request<{ email: string }>('/api/auth/email/verify', { body: { code } }),
  removeEmail: () => request<void>('/api/auth/email', { method: 'DELETE' }),
  emailLoginStart: (email: string) => request<void>('/api/auth/email/login/start', { body: { email } }),
  emailLogin: (email: string, code: string) => request<{ user: PublicUser }>('/api/auth/email/login', { body: { email, code } }),
  unlinkOAuth: (provider: OAuthProvider) => request<void>(`/api/auth/oauth/${provider}`, { method: 'DELETE' }),
  me: () => request<{ user: PublicUser }>('/api/auth/me'),
  logout: () => request<void>('/api/auth/logout', { method: 'POST' }),

  searchUsers: (q: string) => request<{ users: PublicUser[] }>(`/api/users/search?q=${encodeURIComponent(q)}`),
  user: (id: string) => request<{ user: PublicUser }>(`/api/users/${id}`),

  conversations: () => request<{ conversations: Conversation[] }>('/api/conversations'),
  createConversation: (memberIds: string[], name?: string) =>
    request<{ conversation: Conversation }>('/api/conversations', { body: { memberIds, ...(name ? { name } : {}) } }),
  addMembers: (id: string, memberIds: string[]) =>
    request<{ conversation: Conversation }>(`/api/conversations/${id}/members`, { body: { memberIds } }),
  leave: (id: string) => request<void>(`/api/conversations/${id}/leave`, { method: 'POST' }),
  messages: (id: string, before?: string) =>
    request<{ messages: WireMessage[]; hasMore: boolean }>(
      `/api/conversations/${id}/messages?limit=50${before ? `&before=${before}` : ''}`,
    ),
};
