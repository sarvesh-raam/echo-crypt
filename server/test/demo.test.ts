import mongoose from 'mongoose';
import type { Socket } from 'socket.io-client';
import { afterAll, afterEach, beforeEach, describe, expect, it } from 'vitest';
import { cleanupGuests, GUEST_TTL_MS } from '../src/demo/bot.js';
import { User } from '../src/models/User.js';
import { Conversation } from '../src/models/Conversation.js';
import { Message } from '../src/models/Message.js';
import { api, connect, createConversation, nextEvent, open, register, resetData, seal, sendEnvelope, startInstance, type Instance } from './helpers.js';

let A: Instance | undefined;
const sockets: Socket[] = [];

beforeEach(async () => {
  await resetData();
  // Started after the reset so the bot account it creates survives.
  A = await startInstance({ demo: true });
});

afterEach(async () => {
  for (const s of sockets.splice(0)) s.disconnect();
  await A?.app.close();
});

afterAll(() => mongoose.disconnect());

describe('demo bot', () => {
  it('greets, then decrypts and describes what the server stored', async () => {
    const url = A!.url;
    const info = await api(url, '/api/info');
    const botId: string = info.body.demoBotId;
    expect(botId).toMatch(/^[a-f0-9]{24}$/);
    const bot = (await api(url, `/api/users/${botId}`, { cookie: (await register(url, 'probe')).cookie })).body.user;
    expect(bot).toMatchObject({ username: 'echobot', bot: true });
    const asSender = { id: botId, identity: { publicKeys: bot.publicKeys } } as never;

    const guest = await register(url, 'guest_demo', undefined, { extra: { guest: true } });
    const socket = await connect(url, guest.cookie);
    sockets.push(socket);
    const greeting = nextEvent(socket, 'message:new', 10_000);
    const conv = await createConversation(url, guest, [{ id: botId } as never]);
    expect(conv.members.find((m) => m.id === botId)?.online).toBe(true);
    expect((await open((await greeting).envelope, guest, asSender)).text).toMatch(/demo bot/);

    const env = await seal(guest, conv.id, [guest, { id: botId, identity: { publicKeys: bot.publicKeys } } as never], 'top secret pancake recipe');
    const own = nextEvent(socket, 'message:new');
    const reply = (async () => {
      await own;
      return nextEvent(socket, 'message:new', 10_000);
    })();
    expect((await sendEnvelope(socket, env)).ok).toBe(true);
    const text = (await open((await reply).envelope, guest, asSender)).text;
    expect(text).toContain('top secret pancake recipe');
    expect(text).toContain(env.ciphertext.slice(0, 44));

    // The stored copy of the user's message is still only ciphertext.
    const stored = await mongoose.connection.db!.collection('messages').find().toArray();
    expect(JSON.stringify(stored)).not.toContain('pancake');
  });

  it('marks guest accounts and deletes them (with their direct chats) after a day', async () => {
    const url = A!.url;
    const guest = await register(url, 'guest_old', undefined, { extra: { guest: true } });
    const friend = await register(url, 'friend');
    expect((await api(url, '/api/auth/me', { cookie: guest.cookie })).body.user.guest).toBe(true);
    const direct = await createConversation(url, guest, [friend]);
    const group = await createConversation(url, friend, [guest, await register(url, 'third')], 'Crew');
    const socket = await connect(url, guest.cookie);
    sockets.push(socket);
    await sendEnvelope(socket, await seal(guest, direct.id, [guest, friend], 'hello'));

    expect(await cleanupGuests()).toBe(0); // too new
    expect(await cleanupGuests(Date.now() + GUEST_TTL_MS + 1000)).toBe(1);
    expect(await User.exists({ _id: guest.id })).toBeNull();
    expect(await User.exists({ _id: friend.id })).not.toBeNull();
    expect(await Conversation.exists({ _id: direct.id })).toBeNull();
    expect(await Message.countDocuments({ conversationId: direct.id })).toBe(0);
    expect((await Conversation.findById(group.id).lean())!.members.map(String)).not.toContain(guest.id);
  });
});
