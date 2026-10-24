import { describe, expect, it } from 'vitest';
import {
  CryptoError,
  deriveRecoveryKeys,
  generateRecoveryCode,
  identityKey,
  newAccountKey,
  normalizeRecoveryCode,
  openAccountKey,
  passkeyWrapKey,
  sealAccountKey,
  createIdentity,
  decryptMessage,
  deriveAccountKeys,
  encryptMessage,
  fingerprint,
  fromB64,
  generateSalt,
  safetyNumber,
  toB64,
  unlockIdentity,
  validatePublicKeys,
  verifyEnvelope,
  type Envelope,
} from '../src/index.js';

// Low iteration count keeps tests fast; production uses PBKDF2_ITERATIONS.
const ITER = 1000;

async function makeUser(id: string, password = `pw-${id}`) {
  const salt = generateSalt();
  const { authKey, wrapKey } = await deriveAccountKeys(password, salt, ITER);
  const { identity, encrypted } = await createIdentity(wrapKey);
  return { userId: id, salt, password, authKey, identity, encrypted };
}

type User = Awaited<ReturnType<typeof makeUser>>;
const recipient = (u: User) => ({ userId: u.userId, dhPublic: u.identity.publicKeys.dh });

async function send(from: User, to: User[], text = 'hello', conversationId = 'conv1') {
  return encryptMessage({
    plaintext: { text, sentAt: 1_700_000_000_000 },
    conversationId,
    sender: { userId: from.userId, signPrivate: from.identity.signPrivate },
    recipients: [from, ...to].map(recipient),
  });
}

const decrypt = (env: Envelope, as: User, sender: User) =>
  decryptMessage(env, { userId: as.userId, dhPrivate: as.identity.dhPrivate }, sender.identity.publicKeys.sign);

const flipByte = (b64: string, index = 0) => {
  const bytes = fromB64(b64);
  bytes[index] = bytes[index]! ^ 0xff;
  return toB64(bytes);
};

describe('account keys', () => {
  it('is deterministic for the same password and salt', async () => {
    const salt = generateSalt();
    const a = await deriveAccountKeys('correct horse', salt, ITER);
    const b = await deriveAccountKeys('correct horse', salt, ITER);
    expect(a.authKey).toBe(b.authKey);
  });

  it('changes with the password or the salt', async () => {
    const salt = generateSalt();
    const base = await deriveAccountKeys('correct horse', salt, ITER);
    expect((await deriveAccountKeys('correct horsf', salt, ITER)).authKey).not.toBe(base.authKey);
    expect((await deriveAccountKeys('correct horse', generateSalt(), ITER)).authKey).not.toBe(base.authKey);
  });

  it('never exposes the wrap key', async () => {
    const { wrapKey } = await deriveAccountKeys('pw', generateSalt(), ITER);
    expect(wrapKey.extractable).toBe(false);
    await expect(crypto.subtle.exportKey('raw', wrapKey)).rejects.toThrow();
  });

  it('auth key cannot unlock the identity (keys are domain-separated)', async () => {
    const u = await makeUser('alice');
    // A server holding authKey tries to use it as an AES key against the wrapped private key.
    const fake = await crypto.subtle.importKey('raw', fromB64(u.authKey), 'AES-GCM', false, ['decrypt']);
    await expect(unlockIdentity(u.encrypted, fake)).rejects.toBeInstanceOf(CryptoError);
  });
});

describe('identity', () => {
  it('unlocks with the right password and yields non-extractable keys', async () => {
    const u = await makeUser('alice', 'hunter2');
    const { wrapKey } = await deriveAccountKeys('hunter2', u.salt, ITER);
    const id = await unlockIdentity(u.encrypted, wrapKey);
    expect(id.dhPrivate.extractable).toBe(false);
    expect(id.signPrivate.extractable).toBe(false);
  });

  it('refuses the wrong password', async () => {
    const u = await makeUser('alice', 'hunter2');
    const { wrapKey } = await deriveAccountKeys('hunter3', u.salt, ITER);
    await expect(unlockIdentity(u.encrypted, wrapKey)).rejects.toMatchObject({ code: 'DECRYPT_FAILED' });
  });

  it('validates public keys', async () => {
    const u = await makeUser('alice');
    await expect(validatePublicKeys(u.encrypted.publicKeys)).resolves.toBeUndefined();
    await expect(validatePublicKeys({ dh: 'AAAA', sign: u.encrypted.publicKeys.sign })).rejects.toThrow();
  });
});

describe('messages', () => {
  it('round-trips for every member, including the sender', async () => {
    const [a, b, c] = await Promise.all([makeUser('a'), makeUser('b'), makeUser('c')]);
    const env = await send(a, [b, c], 'group hello 👋');
    for (const u of [a, b, c]) {
      expect(await decrypt(env, u, a)).toEqual({ text: 'group hello 👋', sentAt: 1_700_000_000_000 });
    }
  });

  it('contains no plaintext and hides exact length', async () => {
    const [a, b] = await Promise.all([makeUser('a'), makeUser('b')]);
    const short = await send(a, [b], 'TOPSECRET');
    const longer = await send(a, [b], 'TOPSECRET, slightly longer');
    expect(JSON.stringify(short)).not.toContain('TOPSECRET');
    expect(fromB64(short.ciphertext).length).toBe(fromB64(longer.ciphertext).length);
  });

  it('uses fresh keys every time', async () => {
    const [a, b] = await Promise.all([makeUser('a'), makeUser('b')]);
    const e1 = await send(a, [b], 'same');
    const e2 = await send(a, [b], 'same');
    expect(e1.ciphertext).not.toBe(e2.ciphertext);
    expect(e1.keys[1]!.epk).not.toBe(e2.keys[1]!.epk);
  });

  it('rejects non-members', async () => {
    const [a, b, eve] = await Promise.all([makeUser('a'), makeUser('b'), makeUser('eve')]);
    const env = await send(a, [b]);
    await expect(decrypt(env, eve, a)).rejects.toMatchObject({ code: 'NOT_A_RECIPIENT' });
    // Eve relabels Bob's key entry as hers: she still cannot derive the key.
    const stolen = { ...env, keys: env.keys.map((k) => (k.userId === 'b' ? { ...k, userId: 'eve' } : k)) };
    await expect(decrypt(stolen, eve, a)).rejects.toBeInstanceOf(CryptoError);
  });

  it('detects tampering with any signed field', async () => {
    const [a, b] = await Promise.all([makeUser('a'), makeUser('b')]);
    const env = await send(a, [b]);
    const tampered: Envelope[] = [
      { ...env, ciphertext: flipByte(env.ciphertext) },
      { ...env, iv: flipByte(env.iv) },
      { ...env, conversationId: 'conv2' },
      { ...env, clientId: 'replayed' },
      { ...env, keys: env.keys.slice(0, 1) },
      { ...env, keys: env.keys.map((k) => ({ ...k, wrapped: flipByte(k.wrapped) })) },
    ];
    for (const t of tampered) {
      expect(await verifyEnvelope(t, a.identity.publicKeys.sign)).toBe(false);
      await expect(decrypt(t, b, a)).rejects.toMatchObject({ code: 'BAD_SIGNATURE' });
    }
  });

  it('rejects a message signed by someone else (server cannot forge senders)', async () => {
    const [a, b, mallory] = await Promise.all([makeUser('a'), makeUser('b'), makeUser('m')]);
    // Mallory builds a valid envelope but claims it is from Alice.
    const forged = await encryptMessage({
      plaintext: { text: 'send money', sentAt: Date.now() },
      conversationId: 'conv1',
      sender: { userId: 'a', signPrivate: mallory.identity.signPrivate },
      recipients: [recipient(a), recipient(b)],
    });
    await expect(decrypt(forged, b, a)).rejects.toMatchObject({ code: 'BAD_SIGNATURE' });
  });

  it('signature does not depend on key-entry order', async () => {
    const [a, b, c] = await Promise.all([makeUser('a'), makeUser('b'), makeUser('c')]);
    const env = await send(a, [b, c]);
    const reordered = { ...env, keys: [...env.keys].reverse() };
    expect(await decrypt(reordered, c, a)).toMatchObject({ text: 'hello' });
  });

  it('enforces input limits', async () => {
    const [a, b] = await Promise.all([makeUser('a'), makeUser('b')]);
    await expect(send(a, [b], '')).rejects.toMatchObject({ code: 'BAD_INPUT' });
    await expect(send(a, [b], 'x'.repeat(4001))).rejects.toMatchObject({ code: 'BAD_INPUT' });
    await expect(send(a, [b, b])).rejects.toMatchObject({ code: 'BAD_INPUT' });
  });
});

describe('safety numbers', () => {
  it('match on both sides and change when a key changes', async () => {
    const [a, b, b2] = await Promise.all([makeUser('a'), makeUser('b'), makeUser('b')]);
    const pa = { userId: 'a', keys: a.identity.publicKeys };
    const pb = { userId: 'b', keys: b.identity.publicKeys };
    const ab = await safetyNumber(pa, pb);
    expect(ab).toBe(await safetyNumber(pb, pa));
    expect(ab).toMatch(/^(\d{5} ){11}\d{5}$/);
    expect(await safetyNumber(pa, { userId: 'b', keys: b2.identity.publicKeys })).not.toBe(ab);
  });

  it('fingerprints are stable', async () => {
    const a = await makeUser('a');
    expect(await fingerprint(a.identity.publicKeys)).toBe(await fingerprint({ ...a.identity.publicKeys }));
    expect(await fingerprint(a.identity.publicKeys)).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('key slots', () => {
  it('opens the same account key from every slot, and the identity with it', async () => {
    const accountKey = newAccountKey();
    const { identity, encrypted } = await createIdentity(await identityKey(accountKey));

    const { wrapKey: pwKey } = await deriveAccountKeys('hunter2', generateSalt(), ITER);
    const code = generateRecoveryCode();
    const { wrapKey: recKey } = await deriveRecoveryKeys(code);
    const pkKey = await passkeyWrapKey(crypto.getRandomValues(new Uint8Array(32)));

    const slots = {
      password: await sealAccountKey(accountKey, pwKey, 'password'),
      recovery: await sealAccountKey(accountKey, recKey, 'recovery'),
      passkey: await sealAccountKey(accountKey, pkKey, 'passkey'),
    };
    for (const [kind, kek] of [['password', pwKey], ['recovery', recKey], ['passkey', pkKey]] as const) {
      const opened = await openAccountKey(slots[kind], kek, kind);
      expect(opened).toEqual(accountKey);
      const id = await unlockIdentity(encrypted, await identityKey(opened));
      expect(id.publicKeys).toEqual(identity.publicKeys);
    }
  });

  it('binds each slot to its kind and rejects the wrong key', async () => {
    const accountKey = newAccountKey();
    const { wrapKey } = await deriveAccountKeys('pw', generateSalt(), ITER);
    const slot = await sealAccountKey(accountKey, wrapKey, 'password');
    await expect(openAccountKey(slot, wrapKey, 'recovery')).rejects.toMatchObject({ code: 'DECRYPT_FAILED' });
    const { wrapKey: other } = await deriveAccountKeys('pw2', generateSalt(), ITER);
    await expect(openAccountKey(slot, other, 'password')).rejects.toMatchObject({ code: 'DECRYPT_FAILED' });
  });

  it('accepts recovery codes however they are typed', async () => {
    const code = generateRecoveryCode();
    expect(code).toMatch(/^([0-9A-HJKMNP-TV-Z]{4}-){5}[0-9A-HJKMNP-TV-Z]{4}$/);
    const a = await deriveRecoveryKeys(code);
    const b = await deriveRecoveryKeys(` ${code.toLowerCase().replace(/-/g, ' ')} `);
    expect(b.authKey).toBe(a.authKey);
    expect(normalizeRecoveryCode('o0-il')).toBe('0011');
    await expect(deriveRecoveryKeys('too-short')).rejects.toMatchObject({ code: 'BAD_INPUT' });
  });

  it('derives a different passkey key for a different PRF output', async () => {
    const accountKey = newAccountKey();
    const slot = await sealAccountKey(accountKey, await passkeyWrapKey(new Uint8Array(32).fill(1)), 'passkey');
    await expect(openAccountKey(slot, await passkeyWrapKey(new Uint8Array(32).fill(2)), 'passkey')).rejects.toThrow();
  });
});
