import type { AddressInfo } from 'node:net';
import {
  createIdentity,
  identityKey,
  newAccountKey,
  openAccountKey,
  sealAccountKey,
  unlockIdentity,
  type Bytes,
  type SlotKind,
  type WrappedSecret,
  decryptMessage,
  deriveAccountKeys,
  encryptMessage,
  generateSalt,
  type Envelope,
  type Identity,
} from '@echocrypt/crypto';
import { Redis } from 'ioredis';
import mongoose from 'mongoose';
import { io as ioClient, type Socket } from 'socket.io-client';
import { connectMongo, createApp, type App } from '../src/app.js';
import type { Mailer } from '../src/lib/mailer.js';
import type { OAuthProviders } from '../src/lib/oauth.js';

export const MONGO_URL = process.env.TEST_MONGO_URL ?? 'mongodb://localhost:27018/echocrypt_test';
export const REDIS_URL = process.env.TEST_REDIS_URL ?? 'redis://localhost:6380';
/** Lowest value the server accepts; keeps tests fast. Real clients use 600k. */
export const TEST_ITERATIONS = 100_000;

export interface Instance {
  app: App;
  url: string;
}

export async function startInstance(
  opts: { mailer?: Mailer | null; oauth?: OAuthProviders; demo?: boolean } = {},
): Promise<Instance> {
  const app = createApp({ redisUrl: REDIS_URL, mailer: opts.mailer ?? null, oauth: opts.oauth ?? {}, demo: opts.demo ?? false });
  await app.demoReady;
  await new Promise<void>((r) => app.httpServer.listen(0, '127.0.0.1', r));
  const { port } = app.httpServer.address() as AddressInfo;
  return { app, url: `http://127.0.0.1:${port}` };
}

export async function resetData(): Promise<void> {
  await connectMongo(MONGO_URL);
  await mongoose.connection.db!.dropDatabase();
  await mongoose.syncIndexes();
  const r = new Redis(REDIS_URL);
  await r.flushdb();
  await r.quit();
}

export async function api(
  base: string,
  path: string,
  opts: { method?: string; body?: unknown; cookie?: string } = {},
): Promise<{ status: number; body: any; cookie?: string }> {
  const res = await fetch(base + path, {
    method: opts.method ?? (opts.body ? 'POST' : 'GET'),
    headers: {
      ...(opts.body ? { 'content-type': 'application/json' } : {}),
      ...(opts.cookie ? { cookie: opts.cookie } : {}),
    },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  const text = await res.text();
  const setCookie = res.headers.getSetCookie().find((c) => c.startsWith('ec_session='));
  return {
    status: res.status,
    body: text ? JSON.parse(text) : null,
    cookie: setCookie ? setCookie.split(';')[0] : undefined,
  };
}

export interface TestUser {
  id: string;
  username: string;
  password: string;
  cookie: string;
  identity: Identity;
  accountKey: Bytes;
}

/** Registers a user exactly like the browser does: all key material is made locally. */
export async function register(
  base: string,
  username: string,
  password = `pw-${username}-secret`,
  opts: { cookie?: string; extra?: Record<string, unknown> } = {},
): Promise<TestUser> {
  const salt = generateSalt();
  const { authKey, wrapKey } = await deriveAccountKeys(password, salt, TEST_ITERATIONS);
  const accountKey = newAccountKey();
  const { identity, encrypted } = await createIdentity(await identityKey(accountKey));
  const res = await api(base, '/api/auth/register', {
    cookie: opts.cookie,
    body: {
      ...opts.extra,
      username,
      displayName: username.toUpperCase(),
      kdfSalt: salt,
      kdfIterations: TEST_ITERATIONS,
      authKey,
      passwordSlot: await sealAccountKey(accountKey, wrapKey, 'password'),
      publicKeys: encrypted.publicKeys,
      encryptedKeys: { dhPrivate: encrypted.dhPrivate, signPrivate: encrypted.signPrivate },
    },
  });
  if (res.status !== 201) throw new Error(`register failed: ${res.status} ${JSON.stringify(res.body)}`);
  return { id: res.body.user.id, username, password, cookie: res.cookie!, identity, accountKey };
}

/** Opens a { user, encryptedKeys, slot } response the way the client does. */
export async function openBundle(
  body: { user: { publicKeys: { dh: string; sign: string } }; encryptedKeys: { dhPrivate: WrappedSecret; signPrivate: WrappedSecret }; slot: WrappedSecret },
  kek: CryptoKey,
  kind: SlotKind,
): Promise<Identity> {
  const accountKey = await openAccountKey(body.slot, kek, kind);
  return unlockIdentity({ publicKeys: body.user.publicKeys, ...body.encryptedKeys }, await identityKey(accountKey));
}

export function connect(base: string, cookie?: string): Promise<Socket> {
  const socket = ioClient(base, {
    transports: ['websocket'],
    extraHeaders: cookie ? { cookie } : {},
    reconnection: false,
    forceNew: true,
  });
  return new Promise((resolve, reject) => {
    socket.once('session', () => resolve(socket));
    socket.once('connect_error', reject);
  });
}

export function nextEvent<T = any>(socket: Socket, event: string, timeoutMs = 5000): Promise<T> {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`timed out waiting for ${event}`)), timeoutMs);
    socket.once(event, (payload: T) => {
      clearTimeout(t);
      resolve(payload);
    });
  });
}

export function sendEnvelope(socket: Socket, envelope: unknown): Promise<any> {
  return socket.timeout(5000).emitWithAck('message:send', envelope);
}

export async function seal(
  from: TestUser,
  conversationId: string,
  members: TestUser[],
  text: string,
  clientId?: string,
): Promise<Envelope> {
  return encryptMessage({
    plaintext: { text, sentAt: Date.now() },
    conversationId,
    sender: { userId: from.id, signPrivate: from.identity.signPrivate },
    recipients: members.map((m) => ({ userId: m.id, dhPublic: m.identity.publicKeys.dh })),
    clientId,
  });
}

export const open = (envelope: Envelope, me: TestUser, sender: TestUser) =>
  decryptMessage(envelope, { userId: me.id, dhPrivate: me.identity.dhPrivate }, sender.identity.publicKeys.sign);

export async function createConversation(base: string, owner: TestUser, others: TestUser[], name?: string) {
  const res = await api(base, '/api/conversations', {
    cookie: owner.cookie,
    body: { memberIds: others.map((o) => o.id), ...(name ? { name } : {}) },
  });
  if (res.status !== 201) throw new Error(`create conversation failed: ${JSON.stringify(res.body)}`);
  return res.body.conversation as { id: string; type: string; members: { id: string; online: boolean }[] };
}
