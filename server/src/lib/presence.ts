import type { Redis } from 'ioredis';

/**
 * Presence across instances: each user has a sorted set of their live sockets,
 * scored by expiry time. Each instance refreshes its own sockets on a timer, so if
 * an instance dies its entries expire instead of leaving users "online" forever.
 */
export const PRESENCE_TTL_MS = 60_000;
export const PRESENCE_REFRESH_MS = 20_000;

const key = (userId: string) => `presence:${userId}`;

const liveCount = (redis: Redis, userId: string) => redis.zcount(key(userId), Date.now(), '+inf');

/** Registers a socket; returns true if the user just came online. */
export async function connectSocket(redis: Redis, userId: string, socketKey: string): Promise<boolean> {
  const before = await liveCount(redis, userId);
  await redis.multi().zadd(key(userId), Date.now() + PRESENCE_TTL_MS, socketKey).pexpire(key(userId), PRESENCE_TTL_MS * 2).exec();
  return before === 0;
}

/** Removes a socket; returns true if the user is now offline. */
export async function disconnectSocket(redis: Redis, userId: string, socketKey: string): Promise<boolean> {
  await redis.multi().zrem(key(userId), socketKey).zremrangebyscore(key(userId), '-inf', Date.now()).exec();
  return (await liveCount(redis, userId)) === 0;
}

export async function refreshSockets(redis: Redis, sockets: { userId: string; socketKey: string }[]): Promise<void> {
  if (sockets.length === 0) return;
  const expires = Date.now() + PRESENCE_TTL_MS;
  const pipe = redis.pipeline();
  for (const s of sockets) {
    pipe.zadd(key(s.userId), expires, s.socketKey);
    pipe.pexpire(key(s.userId), PRESENCE_TTL_MS * 2);
  }
  await pipe.exec();
}

export async function onlineUsers(redis: Redis, userIds: string[]): Promise<Set<string>> {
  if (userIds.length === 0) return new Set();
  const now = Date.now();
  const pipe = redis.pipeline();
  for (const id of userIds) pipe.zcount(key(id), now, '+inf');
  const results = (await pipe.exec()) ?? [];
  return new Set(userIds.filter((_, i) => Number(results[i]?.[1] ?? 0) > 0));
}
