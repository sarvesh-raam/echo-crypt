/**
 * Horizontal-scaling check against a running deployment (e.g. `docker compose up`).
 *
 * Registers two users, connects Alice to instance A and Bob to instance B, and sends
 * messages both ways. Every message must arrive on the other instance and decrypt.
 * Also checks that the load balancer actually spreads requests over both instances.
 *
 *   npm run build -w @echocrypt/crypto
 *   npm run scale-check -- http://localhost:4001 http://localhost:4002 http://localhost:8090
 */
import { io, type Socket } from 'socket.io-client';
import {
  createIdentity,
  decryptMessage,
  deriveAccountKeys,
  encryptMessage,
  generateSalt,
  type Envelope,
  type Identity,
} from '../packages/crypto/dist/index.js';

const [A = 'http://localhost:4001', B = 'http://localhost:4002', LB = 'http://localhost:8090'] = process.argv.slice(2);
const ROUNDS = Number(process.env.ROUNDS ?? 25);

interface User {
  id: string;
  cookie: string;
  identity: Identity;
}

async function post(base: string, path: string, body: unknown, cookie?: string) {
  const res = await fetch(base + path, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(cookie ? { cookie } : {}) },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${path}: ${res.status} ${await res.text()}`);
  return { body: (await res.json()) as any, cookie: res.headers.get('set-cookie')?.split(';')[0] };
}

async function register(base: string, username: string): Promise<User> {
  const salt = generateSalt();
  const { authKey, wrapKey } = await deriveAccountKeys('scale-check-password', salt, 100_000);
  const { identity, encrypted } = await createIdentity(wrapKey);
  const res = await post(base, '/api/auth/register', {
    username,
    displayName: username,
    kdfSalt: salt,
    kdfIterations: 100_000,
    authKey,
    publicKeys: encrypted.publicKeys,
    encryptedKeys: { dhPrivate: encrypted.dhPrivate, signPrivate: encrypted.signPrivate },
  });
  return { id: res.body.user.id, cookie: res.cookie!, identity };
}

function connect(base: string, cookie: string): Promise<{ socket: Socket; instance: string }> {
  const socket = io(base, { transports: ['websocket'], extraHeaders: { cookie }, reconnection: false, forceNew: true });
  return new Promise((resolve, reject) => {
    socket.once('session', ({ instance }) => resolve({ socket, instance }));
    socket.once('connect_error', reject);
  });
}

const pct = (xs: number[], p: number) => [...xs].sort((a, b) => a - b)[Math.min(xs.length - 1, Math.floor((p / 100) * xs.length))]!;

async function main() {
  // 1. The load balancer reaches both instances.
  const seen = new Map<string, number>();
  for (let i = 0; i < 20; i++) {
    const { instance } = (await (await fetch(`${LB}/health`)).json()) as { instance: string };
    seen.set(instance, (seen.get(instance) ?? 0) + 1);
  }
  console.log('load balancer spread over 20 requests:', Object.fromEntries(seen));
  if (seen.size < 2) throw new Error('load balancer only reached one instance');

  // 2. Users on different instances.
  const tag = Date.now().toString(36);
  const alice = await register(A, `alice_${tag}`);
  const bob = await register(B, `bob_${tag}`);
  const conv = (await post(A, '/api/conversations', { memberIds: [bob.id] }, alice.cookie)).body.conversation;
  const a = await connect(A, alice.cookie);
  const b = await connect(B, bob.cookie);
  console.log(`alice -> ${a.instance}, bob -> ${b.instance}`);
  if (a.instance === b.instance) throw new Error('both users landed on the same instance');

  const members = [alice, bob].map((u) => ({ userId: u.id, dhPublic: u.identity.publicKeys.dh }));
  const latencies: number[] = [];

  async function roundTrip(from: User, fromSock: Socket, to: User, toSock: Socket, text: string) {
    const env = await encryptMessage({
      plaintext: { text, sentAt: Date.now() },
      conversationId: conv.id,
      sender: { userId: from.id, signPrivate: from.identity.signPrivate },
      recipients: members,
    });
    const arrived = new Promise<Envelope>((resolve, reject) => {
      const t = setTimeout(() => reject(new Error(`"${text}" never arrived`)), 5000);
      const onMsg = (m: { envelope: Envelope }) => {
        if (m.envelope.clientId !== env.clientId) return;
        clearTimeout(t);
        toSock.off('message:new', onMsg);
        resolve(m.envelope);
      };
      toSock.on('message:new', onMsg);
    });
    const start = performance.now();
    const ack = await fromSock.timeout(5000).emitWithAck('message:send', env);
    if (!ack.ok) throw new Error(ack.error);
    const got = await arrived;
    latencies.push(performance.now() - start);
    const plain = await decryptMessage(got, { userId: to.id, dhPrivate: to.identity.dhPrivate }, from.identity.publicKeys.sign);
    if (plain.text !== text) throw new Error('decrypted text mismatch');
  }

  for (let i = 0; i < ROUNDS; i++) {
    await roundTrip(alice, a.socket, bob, b.socket, `a->b #${i}`);
    await roundTrip(bob, b.socket, alice, a.socket, `b->a #${i}`);
  }

  a.socket.disconnect();
  b.socket.disconnect();
  console.log(
    `${latencies.length}/${ROUNDS * 2} cross-instance messages delivered and decrypted · ` +
      `send→receive p50 ${pct(latencies, 50).toFixed(1)} ms, p95 ${pct(latencies, 95).toFixed(1)} ms`,
  );
}

main().then(
  () => process.exit(0),
  (err) => {
    console.error('FAILED:', err instanceof Error ? err.message : err);
    process.exit(1);
  },
);
