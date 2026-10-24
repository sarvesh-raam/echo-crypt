import { createHmac } from 'node:crypto';
import {
  createIdentity,
  decryptMessage,
  deriveAccountKeys,
  encryptMessage,
  fromB64,
  generateSalt,
  identityKey,
  newAccountKey,
  openAccountKey,
  sealAccountKey,
  unlockIdentity,
  type Envelope,
  type Identity,
} from '@echocrypt/crypto';
import { config } from '../config.js';
import { notifyUsers, type AppContext } from '../context.js';
import { hashAuthKey } from '../lib/auth.js';
import { logger } from '../logger.js';
import { Conversation } from '../models/Conversation.js';
import { Message, toWire, type MessageDoc } from '../models/Message.js';
import { User } from '../models/User.js';

/**
 * The demo bot: an ordinary chat participant, except that its private keys live on the
 * server. It can read messages sent to *it* (they are encrypted for it, like for any
 * member) and nothing else. It replies with what it decrypted and with what the server
 * actually stored, which makes the end-to-end encryption visible.
 */
export const BOT_USERNAME = 'echobot';
const BOT_ITERATIONS = 100_000;
const TYPING_MS = 900;

export interface DemoBot {
  id: string;
  onConversation(conversationId: string): void;
  onMessage(message: MessageDoc): void;
}

type Send = (ctx: AppContext, userId: string, envelope: Envelope) => Promise<unknown>;

/** The bot's password: derived from JWT_SECRET, so every instance can unlock the same keys. */
const botPassword = () => createHmac('sha256', config.JWT_SECRET).update('echocrypt/demo-bot').digest('base64');

async function loadOrCreateIdentity(): Promise<{ id: string; identity: Identity }> {
  const existing = await User.findOne({ username: BOT_USERNAME }).lean();
  if (existing) {
    const { wrapKey } = await deriveAccountKeys(botPassword(), existing.kdfSalt, existing.kdfIterations);
    const key = await openAccountKey(existing.keySlots!.password!, wrapKey, 'password');
    const identity = await unlockIdentity(
      { publicKeys: existing.publicKeys!, dhPrivate: existing.encryptedKeys!.dhPrivate!, signPrivate: existing.encryptedKeys!.signPrivate! },
      await identityKey(key),
    );
    return { id: String(existing._id), identity };
  }

  const salt = generateSalt();
  const { authKey, wrapKey } = await deriveAccountKeys(botPassword(), salt, BOT_ITERATIONS);
  const key = newAccountKey();
  const { identity, encrypted } = await createIdentity(await identityKey(key));
  const { hash, salt: authSalt } = await hashAuthKey(authKey);
  try {
    const user = await User.create({
      username: BOT_USERNAME,
      displayName: 'EchoCrypt Demo Bot',
      kdfSalt: salt,
      kdfIterations: BOT_ITERATIONS,
      authHash: hash,
      authSalt,
      publicKeys: encrypted.publicKeys,
      encryptedKeys: { dhPrivate: encrypted.dhPrivate, signPrivate: encrypted.signPrivate },
      keySlots: { password: await sealAccountKey(key, wrapKey, 'password') },
      bot: true,
    });
    return { id: String(user._id), identity };
  } catch (err) {
    // Another instance created it first: use theirs.
    if ((err as { code?: number }).code === 11000) return loadOrCreateIdentity();
    throw err;
  }
}

const GREETING = [
  '👋 Hi! I’m the EchoCrypt demo bot.',
  '',
  'Send me any message. I’ll decrypt it on my side and show you exactly what the server stored, which is only ciphertext.',
  '',
  'Things to try:',
  '• Tap the 🔒 in the header to compare safety numbers.',
  '• Open this site in a private window, create a second account and chat with yourself to see live delivery and typing indicators.',
].join('\n');

function describe(text: string, stored: MessageDoc): string {
  const quoted = text.length > 160 ? `${text.slice(0, 160)}…` : text;
  const bytes = fromB64(stored.ciphertext).length;
  return [
    `🔓 Decrypted on my side: “${quoted}”`,
    '',
    'What the server stored, all it ever sees:',
    `• ciphertext: ${stored.ciphertext.slice(0, 44)}… (${bytes} bytes, padded to hide the length)`,
    `• ${stored.keys.length} wrapped message keys, one per member`,
    '• your ECDSA signature, which I verified ✓',
    '',
    'The server can’t read it. I can only because you encrypted it for me too.',
  ].join('\n');
}

export async function startDemoBot(ctx: AppContext, send: Send): Promise<DemoBot | null> {
  let bot: { id: string; identity: Identity };
  try {
    bot = await loadOrCreateIdentity();
  } catch (err) {
    // Typically JWT_SECRET changed: the stored keys can no longer be unlocked.
    logger.warn({ err }, 'demo bot unavailable');
    return null;
  }

  async function say(conversationId: string, text: string) {
    const conv = await Conversation.findById(conversationId, { members: 1 }).lean();
    if (!conv) return;
    const members = await User.find({ _id: { $in: conv.members } }, { publicKeys: 1 }).lean();
    notifyUsers(ctx, conv.members.map(String), 'typing', { conversationId, userId: bot.id, typing: true });
    await new Promise((r) => setTimeout(r, TYPING_MS));
    const envelope = await encryptMessage({
      plaintext: { text, sentAt: Date.now() },
      conversationId,
      sender: { userId: bot.id, signPrivate: bot.identity.signPrivate },
      recipients: members.map((m) => ({ userId: String(m._id), dhPublic: m.publicKeys!.dh })),
    });
    await send(ctx, bot.id, envelope);
  }

  const guard = (what: string, p: Promise<unknown>) => p.catch((err) => logger.warn({ err }, `demo bot ${what} failed`));

  return {
    id: bot.id,
    onConversation(conversationId) {
      guard('greeting', say(conversationId, GREETING));
    },
    onMessage(stored) {
      if (String(stored.senderId) === bot.id || !stored.keys.some((k) => k.userId === bot.id)) return;
      guard(
        'reply',
        (async () => {
          const sender = await User.findById(stored.senderId, { publicKeys: 1 }).lean();
          if (!sender) return;
          // Exactly as stored, and verified against the sender's key like any client would.
          const plain = await decryptMessage(
            toWire(stored).envelope,
            { userId: bot.id, dhPrivate: bot.identity.dhPrivate },
            sender.publicKeys!.sign,
          );
          await say(String(stored.conversationId), describe(plain.text, stored));
        })(),
      );
    },
  };
}

export const GUEST_TTL_MS = 24 * 60 * 60 * 1000;

/** Deletes guest accounts older than GUEST_TTL, their direct chats, and their place in groups. */
export async function cleanupGuests(now = Date.now()): Promise<number> {
  const guests = await User.find({ guest: true, createdAt: { $lt: new Date(now - GUEST_TTL_MS) } }, { _id: 1 }).lean();
  if (guests.length === 0) return 0;
  const ids = guests.map((g) => g._id);
  const direct = await Conversation.find({ type: 'direct', members: { $in: ids } }, { _id: 1 }).lean();
  const directIds = direct.map((c) => c._id);
  await Message.deleteMany({ conversationId: { $in: directIds } });
  await Conversation.deleteMany({ _id: { $in: directIds } });
  await Conversation.updateMany({ members: { $in: ids } }, { $pull: { members: { $in: ids } } });
  await User.deleteMany({ _id: { $in: ids } });
  return ids.length;
}

/** Runs cleanupGuests every 30 minutes; a Redis lock keeps instances from doing it twice. */
export function scheduleGuestCleanup(ctx: AppContext): () => void {
  const run = async () => {
    if ((await ctx.redis.set('demo:guest-cleanup', config.INSTANCE_ID, 'EX', 25 * 60, 'NX')) !== 'OK') return;
    const removed = await cleanupGuests();
    if (removed) logger.info({ removed }, 'removed expired guest accounts');
  };
  const timer = setInterval(() => void run().catch((err) => logger.warn({ err }, 'guest cleanup failed')), 30 * 60_000);
  timer.unref();
  return () => clearInterval(timer);
}
