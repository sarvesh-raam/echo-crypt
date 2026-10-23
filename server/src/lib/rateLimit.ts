import type { Redis } from 'ioredis';

/**
 * Fixed-window counter in Redis, shared by every server instance.
 * Returns how many ms to wait when the limit is exceeded (0 = allowed).
 */
export async function rateLimit(redis: Redis, key: string, limit: number, windowMs: number): Promise<number> {
  const k = `rl:${key}`;
  const results = await redis.multi().incr(k).pttl(k).exec();
  const count = Number(results?.[0]?.[1] ?? 0);
  let ttl = Number(results?.[1]?.[1] ?? -1);
  if (ttl < 0) {
    await redis.pexpire(k, windowMs);
    ttl = windowMs;
  }
  return count > limit ? ttl : 0;
}
