import type { Redis } from 'ioredis';
import type { Server } from 'socket.io';

export interface AppContext {
  redis: Redis;
  io: Server;
}

export const userRoom = (userId: string) => `user:${userId}`;

/** Emits to every socket of the given users, on any instance (fan-out goes through Redis Pub/Sub). */
export function notifyUsers(ctx: AppContext, userIds: string[], event: string, payload: unknown): void {
  if (userIds.length === 0) return;
  ctx.io.to(userIds.map(userRoom)).emit(event, payload);
}
