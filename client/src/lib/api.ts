import type { Conversation, EncryptedKeys, PublicUser, WireMessage } from './types';

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

export const api = {
  params: (username: string) =>
    request<{ salt: string; iterations: number }>(`/api/auth/params?username=${encodeURIComponent(username)}`),
  register: (body: unknown) => request<{ user: PublicUser }>('/api/auth/register', { body }),
  login: (username: string, authKey: string) =>
    request<{ user: PublicUser; encryptedKeys: EncryptedKeys }>('/api/auth/login', { body: { username, authKey } }),
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
