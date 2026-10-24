import type { Redis } from 'ioredis';
import type { Server } from 'socket.io';
import type { Mailer } from './lib/mailer.js';
import type { OAuthProviders } from './lib/oauth.js';

export interface AppContext {
  redis: Redis;
  io: Server;
  /** Sends email sign-in codes; null when email sign-in is not configured. */
  mailer: Mailer | null;
  oauth: OAuthProviders;
}

export const userRoom = (userId: string) => `user:${userId}`;

/** Emits to every socket of the given users, on any instance (fan-out goes through Redis Pub/Sub). */
export function notifyUsers(ctx: AppContext, userIds: string[], event: string, payload: unknown): void {
  if (userIds.length === 0) return;
  ctx.io.to(userIds.map(userRoom)).emit(event, payload);
}
