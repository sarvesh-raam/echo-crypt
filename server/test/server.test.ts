import { deriveAccountKeys } from '@echocrypt/crypto';
import mongoose from 'mongoose';
import type { Socket } from 'socket.io-client';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  TEST_ITERATIONS,
  api,
  connect,
  createConversation,
  nextEvent,
  open,
  openBundle,
  register,
  resetData,
  seal,
  sendEnvelope,
  startInstance,
  type Instance,
} from './helpers.js';

// Two server instances sharing Mongo + Redis: the same layout as a scaled deployment.
let A: Instance;
let B: Instance;
const sockets: Socket[] = [];

const track = async (p: Promise<Socket>) => {
  const s = await p;
  sockets.push(s);
  return s;
};

beforeAll(async () => {
  await resetData();
  [A, B] = await Promise.all([startInstance(), startInstance()]);
});

beforeEach(resetData);

afterEach(() => {
  for (const s of sockets.splice(0)) s.disconnect();
});

afterAll(async () => {
  await Promise.all([A?.app.close(), B?.app.close()]);
  await mongoose.disconnect();
});

describe('accounts', () => {
  it('registers, logs in and returns keys only the password can unlock', async () => {
    const alice = await register(A.url, 'alice');

    const params = await api(A.url, '/api/auth/params?username=alice');
    expect(params.body.iterations).toBe(TEST_ITERATIONS);

    const { authKey, wrapKey } = await deriveAccountKeys(alice.password, params.body.salt, params.body.iterations);
    const login = await api(B.url, '/api/auth/login', { body: { username: 'alice', authKey } });
    expect(login.status).toBe(200);
    expect(login.cookie).toMatch(/^ec_session=/);

    // The keys the server returns are encrypted; the password-derived key opens them.
    const identity = await openBundle(login.body, wrapKey, 'password');
    expect(identity.publicKeys).toEqual(alice.identity.publicKeys);

    const me = await api(B.url, '/api/auth/me', { cookie: login.cookie });
    expect(me.body.user.username).toBe('alice');
  });

  it('never stores the password or anything derived from the wrap key', async () => {
    await register(A.url, 'alice', 'my very secret password');
    const raw = await mongoose.connection.db!.collection('users').findOne({ username: 'alice' });
    const dump = JSON.stringify(raw);
    expect(dump).not.toContain('my very secret password');
    expect(raw).not.toHaveProperty('password');
    expect(raw!.encryptedKeys.dhPrivate.data).toBeTypeOf('string');
  });

  it('rejects wrong passwords and does not reveal which usernames exist', async () => {
    await register(A.url, 'alice');
    const { authKey } = await deriveAccountKeys('wrong', (await api(A.url, '/api/auth/params?username=alice')).body.salt, TEST_ITERATIONS);
    const bad = await api(A.url, '/api/auth/login', { body: { username: 'alice', authKey } });
    const ghost = await api(A.url, '/api/auth/login', { body: { username: 'nobody', authKey } });
    expect(bad.status).toBe(401);
    expect(ghost.status).toBe(401);
    expect(bad.body.error).toBe(ghost.body.error);

    // Unknown usernames get a stable decoy salt instead of a 404.
    const p1 = await api(A.url, '/api/auth/params?username=nobody');
    const p2 = await api(B.url, '/api/auth/params?username=nobody');
    expect(p1.status).toBe(200);
    expect(p1.body.salt).toBe(p2.body.salt);
  });

  it('rate-limits login attempts across instances', async () => {
    await register(A.url, 'alice');
    const body = { username: 'alice', authKey: Buffer.alloc(32).toString('base64') };
    const statuses: number[] = [];
    for (let i = 0; i < 11; i++) statuses.push((await api(i % 2 ? A.url : B.url, '/api/auth/login', { body })).status);
    expect(statuses.slice(0, 10).every((s) => s === 401)).toBe(true);
    expect(statuses[10]).toBe(429);
  });

  it('rejects duplicate usernames and invalid public keys', async () => {
    await register(A.url, 'alice');
    await expect(register(A.url, 'alice')).rejects.toThrow(/409/);
    const res = await api(A.url, '/api/auth/register', {
      body: {
        username: 'mallory',
        displayName: 'M',
        kdfSalt: 'AAAA',
        kdfIterations: TEST_ITERATIONS,
        authKey: 'AAAA',
        publicKeys: { dh: 'AAAA', sign: 'AAAA' },
        encryptedKeys: { dhPrivate: { iv: 'AAAA', data: 'AAAA' }, signPrivate: { iv: 'AAAA', data: 'AAAA' } },
      },
    });
    expect(res.status).toBe(400);
  });

  it('requires a session for the API and sockets', async () => {
    expect((await api(A.url, '/api/conversations')).status).toBe(401);
    await expect(connect(A.url)).rejects.toThrow(/unauthorized/);
  });
});

describe('messaging across instances', () => {
  it('delivers a message sent on instance A to a recipient on instance B, storing only ciphertext', async () => {
    const [alice, bob] = await Promise.all([register(A.url, 'alice'), register(B.url, 'bob')]);
    const conv = await createConversation(A.url, alice, [bob]);
    const sa = await track(connect(A.url, alice.cookie));
    const sb = await track(connect(B.url, bob.cookie));

    const received = nextEvent(sb, 'message:new');
    const secret = 'meet at the old library at 9';
    const ack = await sendEnvelope(sa, await seal(alice, conv.id, [alice, bob], secret));
    expect(ack.ok).toBe(true);

    const msg = await received;
    expect(msg.id).toBe(ack.message.id);
    expect((await open(msg.envelope, bob, alice)).text).toBe(secret);

    const stored = await mongoose.connection.db!.collection('messages').find().toArray();
    expect(stored).toHaveLength(1);
    expect(JSON.stringify(stored)).not.toContain('library');
  });

  it('serves history from any instance, newest page first, with pagination', async () => {
    const [alice, bob] = await Promise.all([register(A.url, 'alice'), register(A.url, 'bob')]);
    const conv = await createConversation(A.url, alice, [bob]);
    const sa = await track(connect(A.url, alice.cookie));
    for (let i = 0; i < 5; i++) {
      expect((await sendEnvelope(sa, await seal(alice, conv.id, [alice, bob], `m${i}`))).ok).toBe(true);
    }
    const page1 = await api(B.url, `/api/conversations/${conv.id}/messages?limit=3`, { cookie: bob.cookie });
    expect(page1.body.hasMore).toBe(true);
    const texts1 = await Promise.all(page1.body.messages.map(async (m: any) => (await open(m.envelope, bob, alice)).text));
    expect(texts1).toEqual(['m2', 'm3', 'm4']);

    const page2 = await api(B.url, `/api/conversations/${conv.id}/messages?limit=3&before=${page1.body.messages[0].id}`, {
      cookie: bob.cookie,
    });
    expect(page2.body.hasMore).toBe(false);
    expect(page2.body.messages).toHaveLength(2);
  });

  it('treats a resent envelope as the same message', async () => {
    const [alice, bob] = await Promise.all([register(A.url, 'alice'), register(A.url, 'bob')]);
    const conv = await createConversation(A.url, alice, [bob]);
    const sa = await track(connect(A.url, alice.cookie));
    const env = await seal(alice, conv.id, [alice, bob], 'once');
    const first = await sendEnvelope(sa, env);
    const second = await sendEnvelope(sa, env);
    expect(second.message.id).toBe(first.message.id);
    expect(await mongoose.connection.db!.collection('messages').countDocuments()).toBe(1);
  });

  it('rejects forged, incomplete and out-of-conversation envelopes', async () => {
    const [alice, bob, eve] = await Promise.all([register(A.url, 'alice'), register(A.url, 'bob'), register(A.url, 'eve')]);
    const conv = await createConversation(A.url, alice, [bob]);
    const se = await track(connect(A.url, eve.cookie));
    const sa = await track(connect(A.url, alice.cookie));

    // Eve is not a member.
    expect((await sendEnvelope(se, await seal(eve, conv.id, [alice, bob, eve], 'hi'))).ok).toBe(false);
    // Eve claims to be Alice.
    const spoofed = { ...(await seal(eve, conv.id, [alice, bob], 'hi')), senderId: alice.id };
    expect((await sendEnvelope(se, spoofed)).ok).toBe(false);
    // Alice leaves Bob out of the key list.
    const partial = await sendEnvelope(sa, await seal(alice, conv.id, [alice], 'hi'));
    expect(partial).toMatchObject({ ok: false, error: expect.stringMatching(/member/i) });
    // Alice's envelope modified in transit.
    const env = await seal(alice, conv.id, [alice, bob], 'hi');
    expect((await sendEnvelope(sa, { ...env, ciphertext: env.ciphertext.replace(/^./, (c) => (c === 'A' ? 'B' : 'A')) })).ok).toBe(false);
    // Garbage.
    expect((await sendEnvelope(sa, { hello: 'world' })).ok).toBe(false);

    expect(await mongoose.connection.db!.collection('messages').countDocuments()).toBe(0);
  });

  it('hides messages from before a member joined (they have no key for them)', async () => {
    const [alice, bob, carol] = await Promise.all([register(A.url, 'alice'), register(A.url, 'bob'), register(A.url, 'carol')]);
    const group = await createConversation(A.url, alice, [bob], 'Team');
    expect(group.type).toBe('group');
    const sa = await track(connect(A.url, alice.cookie));
    await sendEnvelope(sa, await seal(alice, group.id, [alice, bob], 'before carol'));

    const add = await api(A.url, `/api/conversations/${group.id}/members`, { cookie: alice.cookie, body: { memberIds: [carol.id] } });
    expect(add.status).toBe(200);
    // Old member list is now rejected...
    expect((await sendEnvelope(sa, await seal(alice, group.id, [alice, bob], 'stale'))).ok).toBe(false);
    // ...and the full list goes through.
    await sendEnvelope(sa, await seal(alice, group.id, [alice, bob, carol], 'welcome carol'));

    const carolView = await api(B.url, `/api/conversations/${group.id}/messages`, { cookie: carol.cookie });
    expect(carolView.body.messages).toHaveLength(1);
    expect((await open(carolView.body.messages[0].envelope, carol, alice)).text).toBe('welcome carol');

    const bobView = await api(B.url, `/api/conversations/${group.id}/messages`, { cookie: bob.cookie });
    expect(bobView.body.messages).toHaveLength(2);
  });

  it('keeps exactly one direct conversation per pair', async () => {
    const [alice, bob] = await Promise.all([register(A.url, 'alice'), register(A.url, 'bob')]);
    const [c1, c2] = await Promise.all([createConversation(A.url, alice, [bob]), createConversation(B.url, bob, [alice])]);
    expect(c1.id).toBe(c2.id);
  });

  it('notifies members of new conversations on whichever instance they use', async () => {
    const [alice, bob] = await Promise.all([register(A.url, 'alice'), register(B.url, 'bob')]);
    const sb = await track(connect(B.url, bob.cookie));
    const upsert = nextEvent(sb, 'conversation:upsert');
    const conv = await createConversation(A.url, alice, [bob]);
    expect((await upsert).id).toBe(conv.id);
  });
});

describe('presence and typing across instances', () => {
  it('reports online status and relays typing between instances', async () => {
    const [alice, bob] = await Promise.all([register(A.url, 'alice'), register(B.url, 'bob')]);
    const conv = await createConversation(A.url, alice, [bob]);
    const sa = await track(connect(A.url, alice.cookie));

    const cameOnline = nextEvent(sa, 'presence');
    const sb = await track(connect(B.url, bob.cookie));
    expect(await cameOnline).toEqual({ userId: bob.id, online: true });

    const list = await api(A.url, '/api/conversations', { cookie: alice.cookie });
    expect(list.body.conversations[0].members.find((m: any) => m.id === bob.id).online).toBe(true);

    const typing = nextEvent(sa, 'typing');
    sb.emit('typing', { conversationId: conv.id, typing: true });
    expect(await typing).toEqual({ conversationId: conv.id, typing: true, userId: bob.id });

    const wentOffline = nextEvent(sa, 'presence');
    sb.disconnect();
    expect(await wentOffline).toEqual({ userId: bob.id, online: false });
  });

  it('stays online while any of the user’s sockets is connected', async () => {
    const [alice, bob] = await Promise.all([register(A.url, 'alice'), register(B.url, 'bob')]);
    await createConversation(A.url, alice, [bob]);
    const sa = await track(connect(A.url, alice.cookie));
    const tab1 = await track(connect(A.url, bob.cookie));
    await track(connect(B.url, bob.cookie));

    let offline = false;
    sa.on('presence', (p: { online: boolean }) => {
      if (!p.online) offline = true;
    });
    tab1.disconnect();
    await new Promise((r) => setTimeout(r, 300));
    expect(offline).toBe(false);
  });
});
