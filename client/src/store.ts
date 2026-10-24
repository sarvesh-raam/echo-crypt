import {
  createIdentity,
  decryptMessage,
  deriveAccountKeys,
  deriveRecoveryKeys,
  encryptMessage,
  generateRecoveryCode,
  generateSalt,
  identityKey,
  newAccountKey,
  newClientId,
  openAccountKey,
  passkeyWrapKey,
  PBKDF2_ITERATIONS,
  sealAccountKey,
  unlockIdentity,
  type Bytes,
  type Identity,
  type PublicKeys,
  type SlotKind,
} from '@echocrypt/crypto';
import { io, type Socket } from 'socket.io-client';
import { create } from 'zustand';
import { api, ApiError } from './lib/api';
import { clearIdentities, loadIdentity, saveIdentity } from './lib/keystore';
import { createPasskey, deviceName, signInWithPasskey } from './lib/passkey';
import { generatePassword } from './lib/password';
import { acceptKeys, checkTrust, type TrustState } from './lib/trust';
import type { ChatMessage, Conversation, KeyBundle, PublicUser, WireMessage } from './lib/types';

interface Thread {
  messages: ChatMessage[];
  hasMore: boolean;
  loading: boolean;
  loaded: boolean;
}

type Phase = 'booting' | 'signedOut' | 'locked' | 'ready';

interface State {
  phase: Phase;
  me: PublicUser | null;
  connection: 'connecting' | 'online' | 'offline';
  instance: string | null;
  conversations: Conversation[];
  trust: Record<string, TrustState>;
  activeId: string | null;
  threads: Record<string, Thread>;
  unread: Record<string, number>;
  /** conversationId -> userId -> expiry timestamp */
  typing: Record<string, Record<string, number>>;

  boot(): Promise<void>;
  /**
   * Creates the account (keys, password slot, recovery slot) and signs in, but does not
   * enter the app until finish(): the sign-up screen first shows the recovery key and,
   * for passkey sign-ups, registers the passkey.
   */
  createAccount(opts: {
    username: string;
    displayName: string;
    /** null = protect the keys with a passkey instead of a password. */
    password: string | null;
    remember: boolean;
    /** Link the Google/GitHub account from a pending "Continue with …" sign-up. */
    linkPending?: boolean;
    onStep?: Step;
  }): Promise<NewAccount>;
  login(username: string, password: string, remember: boolean, onStep?: Step): Promise<void>;
  loginWithPasskey(remember: boolean, onStep?: Step): Promise<void>;
  /** "Forgot password": unlocks with the recovery key, sets a new password and signs in. */
  recover(username: string, code: string, newPassword: string, remember: boolean, onStep?: Step): Promise<void>;
  /** Signs in (session only) with an emailed code; keys may still need unlocking. */
  emailLogin(email: string, code: string): Promise<void>;
  logout(): Promise<void>;

  /** True when this tab holds the account key, which adding a passkey or recovery key needs. */
  canManageKeys(): boolean;
  /** Re-opens the account key for the signed-in user (settings ask for this after a reload). */
  confirmWithPassword(password: string): Promise<void>;
  confirmWithPasskey(): Promise<void>;
  createRecoveryKey(): Promise<string>;
  addPasskey(name: string): Promise<void>;
  select(id: string | null): void;
  loadOlder(id: string): Promise<void>;
  send(conversationId: string, text: string): Promise<void>;
  retry(conversationId: string, clientId: string): Promise<void>;
  setTyping(conversationId: string, typing: boolean): void;
  startConversation(memberIds: string[], name?: string): Promise<Conversation>;
  addMembers(conversationId: string, memberIds: string[]): Promise<void>;
  leave(conversationId: string): Promise<void>;
  acceptKey(userId: string, verified: boolean): Promise<void>;
}

type Step = (s: string) => void;

export interface NewAccount {
  user: PublicUser;
  /** Shown once on the sign-up screen. */
  recoveryCode: string;
  addPasskey(): Promise<void>;
  /** Sets a real password (used when a passkey sign-up could not create the passkey). */
  setPassword(password: string): Promise<void>;
  /** Saves the keys if "remember" was ticked and opens the app. */
  finish(): Promise<void>;
}

// Things that must not trigger re-renders live outside the store.
let identity: Identity | null = null;
/** Raw account key, kept in memory only (never stored) after an unlock in this tab. */
let accountKey: Bytes | null = null;
let socket: Socket | null = null;
const keyCache = new Map<string, PublicKeys>();

const sortConversations = (list: Conversation[]) =>
  [...list].sort((a, b) => (b.lastMessageAt ?? b.createdAt ?? '').localeCompare(a.lastMessageAt ?? a.createdAt ?? ''));

const byTime = (a: ChatMessage, b: ChatMessage) => a.createdAt.localeCompare(b.createdAt) || a.id.localeCompare(b.id);

/** Merges messages into a thread, matching on server id or (sender, clientId). */
function merge(existing: ChatMessage[], incoming: ChatMessage[]): ChatMessage[] {
  const out = [...existing];
  for (const m of incoming) {
    const i = out.findIndex((x) => x.id === m.id || (x.senderId === m.senderId && x.clientId === m.clientId));
    if (i === -1) out.push(m);
    else if (out[i]!.status !== 'sent' || m.status === 'sent') out[i] = { ...out[i]!, ...m };
  }
  return out.sort(byTime);
}

export const useStore = create<State>((set, get) => {
  const meId = () => get().me?.id ?? '';

  /** Opens the slot this sign-in method can open, then the identity sealed under the account key. */
  async function openBundle(user: PublicUser, bundle: KeyBundle, kek: CryptoKey, kind: SlotKind) {
    const key = await openAccountKey(bundle.slot, kek, kind);
    const id = await unlockIdentity({ publicKeys: user.publicKeys, ...bundle.encryptedKeys }, await identityKey(key));
    return { key, id };
  }

  async function finishUnlock(user: PublicUser, key: Bytes, id: Identity, remember: boolean) {
    accountKey = key;
    // "Remember this device" keeps the (non-extractable) keys in IndexedDB across reloads.
    await clearIdentities();
    if (remember) await saveIdentity(user.id, id);
    await startSession(user, id);
  }

  async function newPasswordFields(password: string, key: Bytes) {
    const kdfSalt = generateSalt();
    const { authKey, wrapKey } = await deriveAccountKeys(password, kdfSalt);
    return {
      kdfSalt,
      kdfIterations: PBKDF2_ITERATIONS,
      authKey,
      passwordSlot: await sealAccountKey(key, wrapKey, 'password'),
    };
  }

  async function passkeyUnlock() {
    const { credential, prf } = await signInWithPasskey(await api.passkeyOptions());
    const res = await api.passkeyLogin(credential);
    return { user: res.user, ...(await openBundle(res.user, res, await passkeyWrapKey(prf), 'passkey')) };
  }

  async function senderKeys(userId: string): Promise<PublicKeys | null> {
    if (userId === meId() && identity) return identity.publicKeys;
    const cached = keyCache.get(userId);
    if (cached) return cached;
    try {
      const { user } = await api.user(userId);
      keyCache.set(userId, user.publicKeys);
      return user.publicKeys;
    } catch {
      return null;
    }
  }

  async function decryptWire(w: WireMessage): Promise<ChatMessage> {
    const base = {
      id: w.id,
      clientId: w.envelope.clientId,
      conversationId: w.envelope.conversationId,
      senderId: w.envelope.senderId,
      createdAt: w.createdAt,
    };
    const keys = await senderKeys(w.envelope.senderId);
    try {
      if (!keys || !identity) throw new Error('Unknown sender');
      const plain = await decryptMessage(w.envelope, { userId: meId(), dhPrivate: identity.dhPrivate }, keys.sign);
      const changed = get().trust[w.envelope.senderId] === 'changed';
      return {
        ...base,
        text: plain.text,
        sentAt: plain.sentAt,
        status: 'sent',
        ...(changed ? { error: 'Sender’s safety number changed' } : {}),
      };
    } catch (err) {
      return {
        ...base,
        text: '',
        sentAt: Date.parse(w.createdAt),
        status: 'undecryptable',
        error: err instanceof Error ? err.message : 'Could not decrypt',
      };
    }
  }

  async function absorbConversations(list: Conversation[]) {
    const me = meId();
    const trust: Record<string, TrustState> = { ...get().trust };
    for (const c of list) {
      for (const m of c.members) {
        keyCache.set(m.id, m.publicKeys);
        if (m.id !== me && !(m.id in trust)) trust[m.id] = await checkTrust(me, m.id, m.publicKeys);
      }
    }
    set({ trust });
  }

  function upsertConversation(c: Conversation) {
    void absorbConversations([c]);
    set((s) => ({ conversations: sortConversations([c, ...s.conversations.filter((x) => x.id !== c.id)]) }));
  }

  function patchThread(id: string, fn: (t: Thread) => Partial<Thread>) {
    set((s) => {
      const t = s.threads[id] ?? { messages: [], hasMore: false, loading: false, loaded: false };
      return { threads: { ...s.threads, [id]: { ...t, ...fn(t) } } };
    });
  }

  async function refreshConversations() {
    const { conversations } = await api.conversations();
    // Re-check trust for everyone on every refresh: keys could have changed server-side.
    set({ trust: {} });
    await absorbConversations(conversations);
    set({ conversations: sortConversations(conversations) });
  }

  async function onIncoming(w: WireMessage) {
    const convId = w.envelope.conversationId;
    const s = get();
    const existing = s.threads[convId]?.messages.find(
      (m) => m.senderId === w.envelope.senderId && m.clientId === w.envelope.clientId,
    );
    // Our own message echoed back: we already have the plaintext.
    const msg = existing
      ? { ...existing, id: w.id, createdAt: w.createdAt, status: 'sent' as const, envelope: undefined }
      : await decryptWire(w);
    // Merge even while the first page is still loading: that response may predate this message.
    if (s.threads[convId]) patchThread(convId, (t) => ({ messages: merge(t.messages, [msg]) }));

    const conv = get().conversations.find((c) => c.id === convId);
    if (conv) upsertConversation({ ...conv, lastMessageAt: w.createdAt });
    else void refreshConversations();

    if (w.envelope.senderId !== meId() && (get().activeId !== convId || document.hidden)) {
      set((st) => ({ unread: { ...st.unread, [convId]: (st.unread[convId] ?? 0) + 1 } }));
    }
    // Message arrived, so that person is no longer typing.
    set((st) => {
      const t = { ...(st.typing[convId] ?? {}) };
      delete t[w.envelope.senderId];
      return { typing: { ...st.typing, [convId]: t } };
    });
  }

  async function resync() {
    await refreshConversations();
    // Catch up on anything missed while disconnected.
    for (const [id, t] of Object.entries(get().threads)) {
      if (!t.loaded) continue;
      try {
        const page = await api.messages(id);
        const msgs = await Promise.all(page.messages.map(decryptWire));
        patchThread(id, (th) => ({ messages: merge(th.messages, msgs) }));
      } catch {
        /* conversation may be gone */
      }
    }
  }

  function connect() {
    socket?.disconnect();
    set({ connection: 'connecting' });
    let first = true;
    // WebSocket only: no long-polling means no sticky sessions are needed behind a load balancer.
    socket = io({ transports: ['websocket'] });
    socket.on('session', ({ instance }: { instance: string }) => {
      set({ connection: 'online', instance });
      if (!first) void resync();
      first = false;
    });
    socket.on('disconnect', () => set({ connection: 'connecting' }));
    socket.on('connect_error', (err) => {
      set({ connection: 'offline' });
      if (err.message === 'unauthorized') void get().logout();
    });
    socket.on('message:new', (w: WireMessage) => void onIncoming(w));
    socket.on('conversation:upsert', (c: Conversation) => upsertConversation(c));
    socket.on('conversation:removed', ({ id }: { id: string }) =>
      set((s) => ({
        conversations: s.conversations.filter((c) => c.id !== id),
        activeId: s.activeId === id ? null : s.activeId,
      })),
    );
    socket.on('presence', ({ userId, online }: { userId: string; online: boolean }) =>
      set((s) => ({
        conversations: s.conversations.map((c) =>
          c.members.some((m) => m.id === userId)
            ? { ...c, members: c.members.map((m) => (m.id === userId ? { ...m, online } : m)) }
            : c,
        ),
      })),
    );
    socket.on('typing', ({ conversationId, userId, typing }: { conversationId: string; userId: string; typing: boolean }) =>
      set((s) => {
        const t = { ...(s.typing[conversationId] ?? {}) };
        if (typing) t[userId] = Date.now() + 5000;
        else delete t[userId];
        return { typing: { ...s.typing, [conversationId]: t } };
      }),
    );
  }

  async function startSession(me: PublicUser, id: Identity) {
    identity = id;
    set({ me, phase: 'ready' });
    await refreshConversations();
    connect();
  }

  async function emitEnvelope(conversationId: string, clientId: string) {
    const msg = get().threads[conversationId]?.messages.find((m) => m.clientId === clientId && m.senderId === meId());
    if (!msg?.envelope || !socket) return;
    const mark = (patch: Partial<ChatMessage>) =>
      patchThread(conversationId, (t) => ({
        messages: t.messages.map((m) => (m.clientId === clientId && m.senderId === meId() ? { ...m, ...patch } : m)),
      }));
    try {
      const res = (await socket.timeout(10_000).emitWithAck('message:send', msg.envelope)) as
        | { ok: true; message: WireMessage }
        | { ok: false; error: string };
      if (res.ok) {
        mark({ id: res.message.id, createdAt: res.message.createdAt, status: 'sent', envelope: undefined, error: undefined });
        patchThread(conversationId, (t) => ({ messages: [...t.messages].sort(byTime) }));
      } else {
        mark({ status: 'failed', error: res.error });
        if (/member/i.test(res.error)) void refreshConversations();
      }
    } catch {
      mark({ status: 'failed', error: 'No response from server' });
    }
  }

  return {
    phase: 'booting',
    me: null,
    connection: 'offline',
    instance: null,
    conversations: [],
    trust: {},
    activeId: null,
    threads: {},
    unread: {},
    typing: {},

    async boot() {
      try {
        const { user } = await api.me();
        const id = await loadIdentity(user.id);
        if (id) await startSession(user, id);
        else set({ me: user, phase: 'locked' });
      } catch {
        set({ phase: 'signedOut' });
      }
    },

    async createAccount({ username, displayName, password, remember, linkPending, onStep }) {
      onStep?.('Generating your keys…');
      const key = newAccountKey();
      // Passkey sign-ups still get a password slot, under a random password nobody sees;
      // it can be replaced with a real one if setting up the passkey fails.
      let passwordFields = await newPasswordFields(password ?? `${generatePassword()}-${generatePassword()}`, key);
      const { identity: id, encrypted } = await createIdentity(await identityKey(key));
      const recoveryCode = generateRecoveryCode();
      const recovery = await deriveRecoveryKeys(recoveryCode);
      onStep?.('Creating account…');
      const { user } = await api.register({
        username,
        displayName,
        ...passwordFields,
        publicKeys: encrypted.publicKeys,
        encryptedKeys: { dhPrivate: encrypted.dhPrivate, signPrivate: encrypted.signPrivate },
        recovery: { authKey: recovery.authKey, slot: await sealAccountKey(key, recovery.wrapKey, 'recovery') },
        ...(linkPending ? { linkPending: true } : {}),
      });
      accountKey = key;
      return {
        user,
        recoveryCode,
        addPasskey: () => get().addPasskey(deviceName()),
        async setPassword(newPassword: string) {
          const next = await newPasswordFields(newPassword, key);
          await api.changePassword({ currentAuthKey: passwordFields.authKey, ...next });
          passwordFields = next;
        },
        finish: () => finishUnlock(user, key, id, remember),
      };
    },

    async login(username, password, remember, onStep) {
      onStep?.('Deriving keys from your password…');
      const params = await api.params(username);
      const { authKey, wrapKey } = await deriveAccountKeys(password, params.salt, params.iterations);
      onStep?.('Signing in…');
      const res = await api.login(username, authKey);
      onStep?.('Unlocking your keys…');
      const { key, id } = await openBundle(res.user, res, wrapKey, 'password');
      await finishUnlock(res.user, key, id, remember);
    },

    async loginWithPasskey(remember, onStep) {
      onStep?.('Waiting for your passkey…');
      const { user, key, id } = await passkeyUnlock();
      onStep?.('Unlocking your keys…');
      await finishUnlock(user, key, id, remember);
    },

    async recover(username, code, newPassword, remember, onStep) {
      onStep?.('Checking your recovery key…');
      const recovery = await deriveRecoveryKeys(code);
      const res = await api.recoveryStart(username, recovery.authKey);
      const { key, id } = await openBundle(res.user, res, recovery.wrapKey, 'recovery');
      onStep?.('Setting your new password…');
      const { user } = await api.recoveryFinish({
        username,
        recoveryAuthKey: recovery.authKey,
        ...(await newPasswordFields(newPassword, key)),
      });
      await finishUnlock(user, key, id, remember);
    },

    async emailLogin(email, code) {
      await api.emailLogin(email, code);
      await get().boot();
    },

    canManageKeys: () => accountKey !== null,

    async confirmWithPassword(password) {
      const me = get().me;
      if (!me) throw new Error('Not signed in');
      const params = await api.params(me.username);
      const { authKey, wrapKey } = await deriveAccountKeys(password, params.salt, params.iterations);
      const res = await api.login(me.username, authKey);
      accountKey = (await openBundle(res.user, res, wrapKey, 'password')).key;
    },

    async confirmWithPasskey() {
      const { user, key } = await passkeyUnlock();
      if (user.id !== meId()) throw new Error('That passkey belongs to a different account.');
      accountKey = key;
    },

    async createRecoveryKey() {
      if (!accountKey) throw new Error('Confirm it is you first.');
      const code = generateRecoveryCode();
      const { authKey, wrapKey } = await deriveRecoveryKeys(code);
      await api.setRecovery(authKey, await sealAccountKey(accountKey, wrapKey, 'recovery'));
      return code;
    },

    async addPasskey(name) {
      if (!accountKey) throw new Error('Confirm it is you first.');
      const { credential, prf } = await createPasskey(await api.passkeyRegisterOptions());
      await api.addPasskey(credential, name, await sealAccountKey(accountKey, await passkeyWrapKey(prf), 'passkey'));
    },

    async logout() {
      socket?.disconnect();
      socket = null;
      identity = null;
      accountKey = null;
      keyCache.clear();
      await clearIdentities();
      await api.logout().catch(() => undefined);
      set({
        phase: 'signedOut',
        me: null,
        connection: 'offline',
        instance: null,
        conversations: [],
        trust: {},
        activeId: null,
        threads: {},
        unread: {},
        typing: {},
      });
    },

    select(id) {
      set((s) => ({ activeId: id, unread: id ? { ...s.unread, [id]: 0 } : s.unread }));
      if (id && !get().threads[id]?.loaded) void get().loadOlder(id);
    },

    async loadOlder(id) {
      const t = get().threads[id];
      if (t?.loading || (t?.loaded && !t.hasMore)) return;
      patchThread(id, () => ({ loading: true }));
      try {
        const before = t?.loaded ? t.messages.find((m) => m.status !== 'sending' && m.status !== 'failed')?.id : undefined;
        const page = await api.messages(id, before);
        const msgs = await Promise.all(page.messages.map(decryptWire));
        patchThread(id, (th) => ({ messages: merge(th.messages, msgs), hasMore: page.hasMore, loaded: true, loading: false }));
      } catch (err) {
        patchThread(id, () => ({ loading: false }));
        if (err instanceof ApiError && err.status === 404) {
          set((s) => ({ conversations: s.conversations.filter((c) => c.id !== id), activeId: null }));
        }
      }
    },

    async send(conversationId, text) {
      const conv = get().conversations.find((c) => c.id === conversationId);
      if (!conv || !identity) return;
      const changed = conv.members.filter((m) => get().trust[m.id] === 'changed');
      if (changed.length) throw new Error(`Safety number changed for ${changed.map((m) => m.displayName).join(', ')}`);

      const clientId = newClientId();
      const sentAt = Date.now();
      const envelope = await encryptMessage({
        plaintext: { text, sentAt },
        conversationId,
        sender: { userId: meId(), signPrivate: identity.signPrivate },
        recipients: conv.members.map((m) => ({ userId: m.id, dhPublic: m.publicKeys.dh })),
        clientId,
      });
      patchThread(conversationId, (t) => ({
        messages: merge(t.messages, [
          {
            id: clientId,
            clientId,
            conversationId,
            senderId: meId(),
            text,
            sentAt,
            createdAt: new Date(sentAt).toISOString(),
            status: 'sending',
            envelope,
          },
        ]),
      }));
      get().setTyping(conversationId, false);
      await emitEnvelope(conversationId, clientId);
    },

    async retry(conversationId, clientId) {
      patchThread(conversationId, (t) => ({
        messages: t.messages.map((m) => (m.clientId === clientId ? { ...m, status: 'sending', error: undefined } : m)),
      }));
      await emitEnvelope(conversationId, clientId);
    },

    setTyping(conversationId, typing) {
      socket?.emit('typing', { conversationId, typing });
    },

    async startConversation(memberIds, name) {
      const { conversation } = await api.createConversation(memberIds, name);
      upsertConversation(conversation);
      get().select(conversation.id);
      return conversation;
    },

    async addMembers(conversationId, memberIds) {
      const { conversation } = await api.addMembers(conversationId, memberIds);
      upsertConversation(conversation);
    },

    async leave(conversationId) {
      await api.leave(conversationId);
      set((s) => ({
        conversations: s.conversations.filter((c) => c.id !== conversationId),
        activeId: s.activeId === conversationId ? null : s.activeId,
      }));
    },

    async acceptKey(userId, verified) {
      const keys = keyCache.get(userId);
      if (!keys) return;
      await acceptKeys(meId(), userId, keys, verified);
      set((s) => ({ trust: { ...s.trust, [userId]: verified ? 'verified' : 'trusted' } }));
    },
  };
});

export const conversationTitle = (c: Conversation, meId: string): string =>
  c.type === 'group'
    ? (c.name ?? 'Group')
    : (c.members.find((m) => m.id !== meId)?.displayName ?? 'Just you');
