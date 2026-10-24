/**
 * EchoCrypt cryptographic core.
 *
 * Everything here runs on the client (browser or Node >= 20, via Web Crypto).
 * The server only ever sees the outputs: public keys, wrapped private keys,
 * an auth key it hashes again, and message envelopes.
 *
 *  Account:  password --PBKDF2-SHA256--> master --HKDF--> authKey (sent to server, hashed again)
 *                                                  \--HKDF--> wrapKey (never leaves the client)
 *            A random account key is sealed under wrapKey (the "password slot"); a recovery
 *            code and each passkey (WebAuthn PRF) can hold slots of their own.
 *  Identity: ECDH P-256 key (key agreement) + ECDSA P-256 key (signatures),
 *            private halves AES-GCM-encrypted under the account key before upload.
 *  Message:  random 256-bit message key encrypts the padded plaintext (AES-256-GCM).
 *            For every member, a fresh ephemeral ECDH key + HKDF derives a key that
 *            wraps the message key. The sender signs the whole envelope with ECDSA.
 */
import { type Bytes, encodeFields, fromB64, fromUtf8, randomBytes, toB64, toHex, utf8 } from './encoding.js';

export * from './encoding.js';

export const PROTOCOL_VERSION = 1 as const;
export const PBKDF2_ITERATIONS = 600_000;
export const MAX_MESSAGE_CHARS = 4000;
const PAD_BLOCK = 128;

const EC_DH = { name: 'ECDH', namedCurve: 'P-256' } as const;
const EC_SIGN = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const SIGN_PARAMS = { name: 'ECDSA', hash: 'SHA-256' } as const;

const subtle = (): SubtleCrypto => {
  if (!globalThis.crypto?.subtle) {
    throw new Error('Web Crypto is unavailable (a secure context is required: https or localhost)');
  }
  return globalThis.crypto.subtle;
};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface WrappedSecret {
  iv: string;
  data: string;
}

/** Base64 SPKI public keys, as published to the server. */
export interface PublicKeys {
  dh: string;
  sign: string;
}

export interface EncryptedIdentity {
  publicKeys: PublicKeys;
  dhPrivate: WrappedSecret;
  signPrivate: WrappedSecret;
}

export interface Identity {
  publicKeys: PublicKeys;
  dhPrivate: CryptoKey;
  signPrivate: CryptoKey;
}

export interface KeyEntry {
  userId: string;
  /** Ephemeral ECDH public key (base64 SPKI) generated for this recipient. */
  epk: string;
  iv: string;
  /** Message key encrypted under the ECDH/HKDF-derived key. */
  wrapped: string;
}

export interface Envelope {
  v: typeof PROTOCOL_VERSION;
  conversationId: string;
  senderId: string;
  /** Client-generated id; makes resends idempotent and is bound into the signature. */
  clientId: string;
  iv: string;
  ciphertext: string;
  keys: KeyEntry[];
  signature: string;
}

export interface Plaintext {
  text: string;
  /** Sender's clock (ms). Signed, so the server cannot change it. */
  sentAt: number;
}

export interface Recipient {
  userId: string;
  dhPublic: string;
}

export class CryptoError extends Error {
  constructor(
    message: string,
    readonly code: 'BAD_SIGNATURE' | 'NOT_A_RECIPIENT' | 'DECRYPT_FAILED' | 'BAD_INPUT',
  ) {
    super(message);
    this.name = 'CryptoError';
  }
}

// ---------------------------------------------------------------------------
// Account keys (password -> authKey + wrapKey)
// ---------------------------------------------------------------------------

export function generateSalt(): string {
  return toB64(randomBytes(16));
}

export async function deriveAccountKeys(
  password: string,
  saltB64: string,
  iterations: number = PBKDF2_ITERATIONS,
): Promise<{ authKey: string; wrapKey: CryptoKey }> {
  const s = subtle();
  const base = await s.importKey('raw', utf8(password.normalize('NFKC')), 'PBKDF2', false, ['deriveBits']);
  const master = await s.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: fromB64(saltB64), iterations },
    base,
    256,
  );
  const hk = await s.importKey('raw', master, 'HKDF', false, ['deriveBits', 'deriveKey']);
  const empty = new Uint8Array(0);
  const authBits = await s.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: empty, info: utf8('echocrypt/v1/auth') },
    hk,
    256,
  );
  const wrapKey = await s.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: empty, info: utf8('echocrypt/v1/wrap') },
    hk,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
  return { authKey: toB64(authBits), wrapKey };
}

// ---------------------------------------------------------------------------
// Account key and key slots
//
// The identity's private keys are sealed under one random account key. Each way of
// unlocking (password, recovery key, every passkey) stores its own copy of the account
// key, sealed under a key only that method can produce. Adding or removing a method
// never re-encrypts the identity, and the server holds nothing that opens any slot.
// ---------------------------------------------------------------------------

export type SlotKind = 'password' | 'recovery' | 'passkey';

export function newAccountKey(): Bytes {
  return randomBytes(32);
}

/** The key that seals the identity (pass it to createIdentity / unlockIdentity). */
export function identityKey(accountKey: Bytes): Promise<CryptoKey> {
  return subtle().importKey('raw', accountKey, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

export async function sealAccountKey(accountKey: Bytes, kek: CryptoKey, kind: SlotKind): Promise<WrappedSecret> {
  const iv = randomBytes(12);
  const data = await subtle().encrypt({ name: 'AES-GCM', iv, additionalData: utf8(`echocrypt/v1/slot/${kind}`) }, kek, accountKey);
  return { iv: toB64(iv), data: toB64(data) };
}

export async function openAccountKey(slot: WrappedSecret, kek: CryptoKey, kind: SlotKind): Promise<Bytes> {
  try {
    const raw = await subtle().decrypt(
      { name: 'AES-GCM', iv: fromB64(slot.iv), additionalData: utf8(`echocrypt/v1/slot/${kind}`) },
      kek,
      fromB64(slot.data),
    );
    return new Uint8Array(raw);
  } catch {
    throw new CryptoError(`Could not unlock your keys with this ${kind === 'password' ? 'password' : `${kind} key`}`, 'DECRYPT_FAILED');
  }
}

// Crockford base32: no I, L, O or U, so a written-down code is hard to misread.
const RECOVERY_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/** 24 random characters (120 bits) in groups of four, e.g. "7KQ2-M9XD-…". Shown to the user once. */
export function generateRecoveryCode(): string {
  const chars = Array.from(randomBytes(24), (b) => RECOVERY_ALPHABET[b & 31]!).join('');
  return chars.match(/.{4}/g)!.join('-');
}

export function normalizeRecoveryCode(code: string): string {
  return code
    .toUpperCase()
    .replace(/[\s-]/g, '')
    .replace(/O/g, '0')
    .replace(/[IL]/g, '1');
}

async function hkdfPair(secret: Bytes, label: string): Promise<{ authKey: string; wrapKey: CryptoKey }> {
  const s = subtle();
  const hk = await s.importKey('raw', secret, 'HKDF', false, ['deriveBits', 'deriveKey']);
  const salt = utf8(label);
  const authBits = await s.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: utf8('auth') }, hk, 256);
  const wrapKey = await s.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: utf8('wrap') },
    hk,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
  return { authKey: toB64(authBits), wrapKey };
}

/**
 * The recovery code already has 120 bits of entropy, so no slow KDF is needed. Like the
 * password, it yields an authKey for the server and a wrapKey that never leaves the client.
 */
export async function deriveRecoveryKeys(code: string): Promise<{ authKey: string; wrapKey: CryptoKey }> {
  const normalized = normalizeRecoveryCode(code);
  if (!/^[0-9A-HJKMNP-TV-Z]{24}$/.test(normalized)) throw new CryptoError('That is not a valid recovery key', 'BAD_INPUT');
  return hkdfPair(utf8(normalized), 'echocrypt/v1/recovery');
}

/** Fixed input for the WebAuthn PRF extension; each passkey turns it into its own secret. */
export const PASSKEY_PRF_SALT = utf8('echocrypt/v1/passkey-prf');

/** Turns a passkey's PRF output into the key that seals that passkey's slot. */
export async function passkeyWrapKey(prfOutput: ArrayBuffer | Uint8Array): Promise<CryptoKey> {
  const bytes = new Uint8Array(prfOutput.byteLength);
  bytes.set(prfOutput instanceof Uint8Array ? prfOutput : new Uint8Array(prfOutput));
  return (await hkdfPair(bytes, 'echocrypt/v1/passkey')).wrapKey;
}

// ---------------------------------------------------------------------------
// Identity keys
// ---------------------------------------------------------------------------

async function sealPrivate(key: CryptoKey, wrapKey: CryptoKey, label: string): Promise<WrappedSecret> {
  const s = subtle();
  const pkcs8 = await s.exportKey('pkcs8', key);
  const iv = randomBytes(12);
  const data = await s.encrypt({ name: 'AES-GCM', iv, additionalData: utf8(label) }, wrapKey, pkcs8);
  return { iv: toB64(iv), data: toB64(data) };
}

async function openPrivate(
  sealed: WrappedSecret,
  wrapKey: CryptoKey,
  label: string,
  algorithm: EcKeyImportParams,
  usages: KeyUsage[],
): Promise<CryptoKey> {
  const s = subtle();
  let pkcs8: ArrayBuffer;
  try {
    pkcs8 = await s.decrypt(
      { name: 'AES-GCM', iv: fromB64(sealed.iv), additionalData: utf8(label) },
      wrapKey,
      fromB64(sealed.data),
    );
  } catch {
    throw new CryptoError('Could not unlock private key (wrong password?)', 'DECRYPT_FAILED');
  }
  // Re-imported as non-extractable: page scripts can use the key but never read it out.
  return s.importKey('pkcs8', pkcs8, algorithm, false, usages);
}

/** Creates a fresh identity and returns both the usable keys and the encrypted form to upload. */
export async function createIdentity(wrapKey: CryptoKey): Promise<{ identity: Identity; encrypted: EncryptedIdentity }> {
  const s = subtle();
  const dh = await s.generateKey(EC_DH, true, ['deriveBits']);
  const sign = await s.generateKey(EC_SIGN, true, ['sign', 'verify']);
  const publicKeys: PublicKeys = {
    dh: toB64(await s.exportKey('spki', dh.publicKey)),
    sign: toB64(await s.exportKey('spki', sign.publicKey)),
  };
  const encrypted: EncryptedIdentity = {
    publicKeys,
    dhPrivate: await sealPrivate(dh.privateKey, wrapKey, 'echocrypt/v1/key/dh'),
    signPrivate: await sealPrivate(sign.privateKey, wrapKey, 'echocrypt/v1/key/sign'),
  };
  // Hand back non-extractable copies, same as a later unlock would.
  const identity = await unlockIdentity(encrypted, wrapKey);
  return { identity, encrypted };
}

export async function unlockIdentity(encrypted: EncryptedIdentity, wrapKey: CryptoKey): Promise<Identity> {
  const [dhPrivate, signPrivate] = await Promise.all([
    openPrivate(encrypted.dhPrivate, wrapKey, 'echocrypt/v1/key/dh', EC_DH, ['deriveBits']),
    openPrivate(encrypted.signPrivate, wrapKey, 'echocrypt/v1/key/sign', EC_SIGN, ['sign']),
  ]);
  return { publicKeys: encrypted.publicKeys, dhPrivate, signPrivate };
}

const importDhPublic = (spki: string) => subtle().importKey('spki', fromB64(spki), EC_DH, true, []);
const importSignPublic = (spki: string) => subtle().importKey('spki', fromB64(spki), EC_SIGN, true, ['verify']);

/** Throws if the strings are not valid P-256 SPKI keys. */
export async function validatePublicKeys(keys: PublicKeys): Promise<void> {
  try {
    await Promise.all([importDhPublic(keys.dh), importSignPublic(keys.sign)]);
  } catch {
    throw new CryptoError('Invalid public key', 'BAD_INPUT');
  }
}

// ---------------------------------------------------------------------------
// Fingerprints & safety numbers
// ---------------------------------------------------------------------------

/** Short stable hash of a user's public keys; used for trust-on-first-use pinning. */
export async function fingerprint(keys: PublicKeys): Promise<string> {
  const digest = await subtle().digest('SHA-256', encodeFields(['echocrypt/v1/fp', keys.dh, keys.sign]));
  return toHex(digest);
}

async function displayableHalf(userId: string, keys: PublicKeys): Promise<string> {
  let data = encodeFields(['echocrypt/v1/safety', userId, keys.dh, keys.sign]);
  // Iterated so that brute-forcing a colliding key pair is more expensive.
  for (let i = 0; i < 1024; i++) {
    data = new Uint8Array(await subtle().digest('SHA-512', data));
  }
  let out = '';
  for (let chunk = 0; chunk < 6; chunk++) {
    let n = 0;
    for (let i = 0; i < 5; i++) n = n * 256 + data[chunk * 5 + i]!;
    out += String(n % 100000).padStart(5, '0');
  }
  return out;
}

/**
 * A 60-digit number both people compute independently and compare in person or
 * over another channel. If it matches, nobody (including the server) swapped keys.
 */
export async function safetyNumber(
  a: { userId: string; keys: PublicKeys },
  b: { userId: string; keys: PublicKeys },
): Promise<string> {
  const [first, second] = a.userId < b.userId ? [a, b] : [b, a];
  const digits = (await displayableHalf(first.userId, first.keys)) + (await displayableHalf(second.userId, second.keys));
  return digits.match(/.{5}/g)!.join(' ');
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

function pad(data: Bytes): Bytes {
  // Hides exact message length (to the nearest PAD_BLOCK bytes). JSON never contains NUL.
  const size = Math.ceil((data.length + 1) / PAD_BLOCK) * PAD_BLOCK;
  const out = new Uint8Array(size);
  out.set(data);
  return out;
}

function unpad(data: Uint8Array): Uint8Array {
  let end = data.length;
  while (end > 0 && data[end - 1] === 0) end--;
  return data.subarray(0, end);
}

function signedBytes(e: Omit<Envelope, 'signature'>): Bytes {
  const keys = [...e.keys].sort((x, y) => (x.userId < y.userId ? -1 : x.userId > y.userId ? 1 : 0));
  return encodeFields([
    `echocrypt/v${e.v}/msg`,
    e.conversationId,
    e.senderId,
    e.clientId,
    e.iv,
    e.ciphertext,
    String(keys.length),
    ...keys.flatMap((k) => [k.userId, k.epk, k.iv, k.wrapped]),
  ]);
}

const contentAad = (conversationId: string, senderId: string, clientId: string) =>
  encodeFields(['echocrypt/v1/content', conversationId, senderId, clientId]);

const wrapInfo = (conversationId: string, clientId: string, userId: string, epk: string) =>
  encodeFields(['echocrypt/v1/msgkey', conversationId, clientId, userId, epk]);

async function deriveWrapKey(
  privateKey: CryptoKey,
  publicKey: CryptoKey,
  info: Bytes,
  usage: 'encrypt' | 'decrypt',
): Promise<CryptoKey> {
  const s = subtle();
  const shared = await s.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 256);
  const hk = await s.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  return s.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info },
    hk,
    { name: 'AES-GCM', length: 256 },
    false,
    [usage],
  );
}

export function newClientId(): string {
  return toHex(randomBytes(16));
}

export async function encryptMessage(params: {
  plaintext: Plaintext;
  conversationId: string;
  sender: { userId: string; signPrivate: CryptoKey };
  /** Every member of the conversation, including the sender (so they can read their own history). */
  recipients: Recipient[];
  clientId?: string;
}): Promise<Envelope> {
  const { plaintext, conversationId, sender, recipients } = params;
  if (plaintext.text.length === 0 || plaintext.text.length > MAX_MESSAGE_CHARS) {
    throw new CryptoError(`Message must be 1-${MAX_MESSAGE_CHARS} characters`, 'BAD_INPUT');
  }
  if (new Set(recipients.map((r) => r.userId)).size !== recipients.length) {
    throw new CryptoError('Duplicate recipient', 'BAD_INPUT');
  }
  const s = subtle();
  const clientId = params.clientId ?? newClientId();

  const rawKey = randomBytes(32);
  const msgKey = await s.importKey('raw', rawKey, 'AES-GCM', false, ['encrypt']);
  const iv = randomBytes(12);
  const body = pad(utf8(JSON.stringify({ t: plaintext.text, at: plaintext.sentAt })));
  const ciphertext = await s.encrypt(
    { name: 'AES-GCM', iv, additionalData: contentAad(conversationId, sender.userId, clientId) },
    msgKey,
    body,
  );

  const keys = await Promise.all(
    recipients.map(async (r): Promise<KeyEntry> => {
      const eph = await s.generateKey(EC_DH, true, ['deriveBits']);
      const epk = toB64(await s.exportKey('spki', eph.publicKey));
      const kek = await deriveWrapKey(
        eph.privateKey,
        await importDhPublic(r.dhPublic),
        wrapInfo(conversationId, clientId, r.userId, epk),
        'encrypt',
      );
      const wrapIv = randomBytes(12);
      const wrapped = await s.encrypt({ name: 'AES-GCM', iv: wrapIv }, kek, rawKey);
      return { userId: r.userId, epk, iv: toB64(wrapIv), wrapped: toB64(wrapped) };
    }),
  );
  rawKey.fill(0);

  const unsigned: Omit<Envelope, 'signature'> = {
    v: PROTOCOL_VERSION,
    conversationId,
    senderId: sender.userId,
    clientId,
    iv: toB64(iv),
    ciphertext: toB64(ciphertext),
    keys,
  };
  const signature = await s.sign(SIGN_PARAMS, sender.signPrivate, signedBytes(unsigned));
  return { ...unsigned, signature: toB64(signature) };
}

export async function verifyEnvelope(envelope: Envelope, senderSignPublic: string): Promise<boolean> {
  try {
    const { signature, ...unsigned } = envelope;
    return await subtle().verify(
      SIGN_PARAMS,
      await importSignPublic(senderSignPublic),
      fromB64(signature),
      signedBytes(unsigned),
    );
  } catch {
    return false;
  }
}

/**
 * Verifies the sender's signature, then decrypts. Throws CryptoError on any failure;
 * a message that fails verification is never decrypted or shown.
 */
export async function decryptMessage(
  envelope: Envelope,
  me: { userId: string; dhPrivate: CryptoKey },
  senderSignPublic: string,
): Promise<Plaintext> {
  if (envelope.v !== PROTOCOL_VERSION) {
    throw new CryptoError(`Unsupported protocol version ${String(envelope.v)}`, 'BAD_INPUT');
  }
  if (!(await verifyEnvelope(envelope, senderSignPublic))) {
    throw new CryptoError('Signature does not match the sender’s key', 'BAD_SIGNATURE');
  }
  const entry = envelope.keys.find((k) => k.userId === me.userId);
  if (!entry) throw new CryptoError('This message was not encrypted for you', 'NOT_A_RECIPIENT');

  const s = subtle();
  try {
    const kek = await deriveWrapKey(
      me.dhPrivate,
      await importDhPublic(entry.epk),
      wrapInfo(envelope.conversationId, envelope.clientId, me.userId, entry.epk),
      'decrypt',
    );
    const rawKey = await s.decrypt({ name: 'AES-GCM', iv: fromB64(entry.iv) }, kek, fromB64(entry.wrapped));
    const msgKey = await s.importKey('raw', rawKey, 'AES-GCM', false, ['decrypt']);
    const body = await s.decrypt(
      {
        name: 'AES-GCM',
        iv: fromB64(envelope.iv),
        additionalData: contentAad(envelope.conversationId, envelope.senderId, envelope.clientId),
      },
      msgKey,
      fromB64(envelope.ciphertext),
    );
    const parsed = JSON.parse(fromUtf8(unpad(new Uint8Array(body)))) as { t: unknown; at: unknown };
    if (typeof parsed.t !== 'string' || typeof parsed.at !== 'number') throw new Error('bad body');
    return { text: parsed.t, sentAt: parsed.at };
  } catch {
    throw new CryptoError('Could not decrypt message', 'DECRYPT_FAILED');
  }
}
