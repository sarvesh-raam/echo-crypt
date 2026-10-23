import { verifyEnvelope, type Envelope } from '@echocrypt/crypto';
import type { Server, Socket } from 'socket.io';
import { z } from 'zod';
import { config } from '../config.js';
import { notifyUsers, userRoom, type AppContext } from '../context.js';
import { userIdFromCookie } from '../lib/auth.js';
import { contactsOf, requireMembership } from '../lib/conversations.js';
import { objectId } from '../lib/http.js';
import { PRESENCE_REFRESH_MS, connectSocket, disconnectSocket, refreshSockets } from '../lib/presence.js';
import { rateLimit } from '../lib/rateLimit.js';
import { logger } from '../logger.js';
import { Conversation } from '../models/Conversation.js';
import { Message, toWire, type MessageDoc, type WireMessage } from '../models/Message.js';
import { User } from '../models/User.js';

const b64 = (max: number) => z.string().min(1).max(max).regex(/^[A-Za-z0-9+/]+={0,2}$/);

export const envelopeSchema = z.object({
  v: z.literal(1),
  conversationId: objectId,
  senderId: objectId,
  clientId: z.string().regex(/^[a-f0-9]{32}$/),
  iv: b64(24),
  // 4000 chars of UTF-8 (up to 16 KB) + JSON + padding, base64-encoded.
  ciphertext: b64(24_000),
  keys: z
    .array(z.object({ userId: objectId, epk: b64(200), iv: b64(24), wrapped: b64(100) }))
    .min(1)
    .max(32),
  signature: b64(200),
});

const typingSchema = z.object({ conversationId: objectId, typing: z.boolean() });

type Ack<T> = (res: ({ ok: true } & T) | { ok: false; error: string }) => void;

interface SocketData {
  userId: string;
}

const socketKey = (socket: Socket) => `${config.INSTANCE_ID}:${socket.id}`;

async function broadcastPresence(ctx: AppContext, userId: string, online: boolean) {
  notifyUsers(ctx, await contactsOf(userId), 'presence', { userId, online });
}

/** Validates, verifies and stores an envelope, then fans it out to every member. */
async function handleSend(ctx: AppContext, userId: string, raw: unknown): Promise<WireMessage> {
  const parsed = envelopeSchema.safeParse(raw);
  if (!parsed.success) throw new Error('Malformed message');
  const env = parsed.data as Envelope;
  if (env.senderId !== userId) throw new Error('Sender mismatch');

  const conv = await Conversation.findOne({ _id: env.conversationId, members: userId }, { members: 1 }).lean();
  if (!conv) throw new Error('Conversation not found');

  // The envelope must carry a key for exactly the current members: nobody left out, nobody extra.
  const members = conv.members.map(String).sort();
  const recipients = env.keys.map((k) => k.userId).sort();
  if (members.length !== recipients.length || members.some((m, i) => m !== recipients[i])) {
    throw new Error('Member list changed, refresh and try again');
  }

  const sender = await User.findById(userId, { publicKeys: 1 }).lean();
  if (!sender || !(await verifyEnvelope(env, sender.publicKeys!.sign))) throw new Error('Invalid signature');

  let doc: MessageDoc;
  try {
    doc = (await Message.create({ ...env })).toObject() as MessageDoc;
  } catch (err) {
    if ((err as { code?: number }).code !== 11000) throw err;
    // Same clientId resent (e.g. after reconnecting): return the stored copy.
    const existing = await Message.findOne({ senderId: userId, clientId: env.clientId }).lean<MessageDoc>();
    if (!existing) throw err;
    return toWire(existing);
  }

  await Conversation.updateOne({ _id: conv._id }, { $set: { lastMessageAt: doc.createdAt } });
  const message = toWire(doc);
  notifyUsers(ctx, members, 'message:new', message);
  return message;
}

export function attachSocketHandlers(io: Server, ctx: AppContext): () => void {
  io.use((socket, next) => {
    const userId = userIdFromCookie(socket.handshake.headers.cookie);
    if (!userId) return next(new Error('unauthorized'));
    (socket.data as SocketData).userId = userId;
    next();
  });

  io.on('connection', (socket) => {
    const { userId } = socket.data as SocketData;
    // Listeners are registered synchronously, before any await: a client that sends
    // right after 'session' must never hit a socket with no handler attached.
    socket.on('message:send', async (raw: unknown, ack?: Ack<{ message: WireMessage }>) => {
      const reply: Ack<{ message: WireMessage }> = typeof ack === 'function' ? ack : () => {};
      try {
        const wait = await rateLimit(ctx.redis, `msg:${userId}`, 30, 10_000);
        if (wait) return reply({ ok: false, error: 'Slow down: too many messages' });
        reply({ ok: true, message: await handleSend(ctx, userId, raw) });
      } catch (err) {
        logger.debug({ err }, 'message rejected');
        reply({ ok: false, error: err instanceof Error ? err.message : 'Could not send' });
      }
    });

    socket.on('typing', async (raw: unknown) => {
      const parsed = typingSchema.safeParse(raw);
      if (!parsed.success) return;
      try {
        if (await rateLimit(ctx.redis, `typing:${userId}`, 20, 5_000)) return;
        const conv = await requireMembership(parsed.data.conversationId, userId);
        const others = conv.members.map(String).filter((m) => m !== userId);
        socket.to(others.map(userRoom)).volatile.emit('typing', { ...parsed.data, userId });
      } catch {
        /* not a member: ignore */
      }
    });

    socket.on('disconnect', async () => {
      try {
        await ready;
        if (await disconnectSocket(ctx.redis, userId, socketKey(socket))) await broadcastPresence(ctx, userId, false);
      } catch (err) {
        logger.warn({ err }, 'presence disconnect failed');
      }
    });

    const ready = (async () => {
      await socket.join(userRoom(userId));
      socket.emit('session', { instance: config.INSTANCE_ID });
      if (await connectSocket(ctx.redis, userId, socketKey(socket))) await broadcastPresence(ctx, userId, true);
    })().catch((err) => logger.warn({ err }, 'socket setup failed'));
  });

  const timer = setInterval(() => {
    const sockets = [...io.of('/').sockets.values()].map((s) => ({
      userId: (s.data as SocketData).userId,
      socketKey: socketKey(s),
    }));
    refreshSockets(ctx.redis, sockets).catch((err) => logger.warn({ err }, 'presence refresh failed'));
  }, PRESENCE_REFRESH_MS);
  timer.unref();
  return () => clearInterval(timer);
}
