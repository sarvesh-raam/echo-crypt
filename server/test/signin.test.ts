import {
  deriveAccountKeys,
  deriveRecoveryKeys,
  generateRecoveryCode,
  generateSalt,
  identityKey,
  openAccountKey,
  passkeyWrapKey,
  sealAccountKey,
} from '@echocrypt/crypto';
import mongoose from 'mongoose';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { TEST_ITERATIONS, api, openBundle, register, resetData, startInstance, type Instance } from './helpers.js';
import { SoftPasskey } from './webauthn.js';

const sent: { to: string; text: string }[] = [];
const mailer = { send: async (to: string, _subject: string, text: string) => void sent.push({ to, text }) };
const lastCode = () => /code is (\d{6})/.exec(sent.at(-1)?.text ?? '')?.[1] ?? '';

// A and B share Mongo + Redis, as two instances of one deployment would.
let A: Instance;
let B: Instance;

beforeAll(async () => {
  await resetData();
  const opts = { mailer, oauth: { github: { clientId: 'gh-client', clientSecret: 'gh-secret' } } };
  [A, B] = await Promise.all([startInstance(opts), startInstance(opts)]);
});

beforeEach(async () => {
  await resetData();
  sent.length = 0;
});

afterEach(() => vi.restoreAllMocks());

afterAll(async () => {
  await Promise.all([A?.app.close(), B?.app.close()]);
  await mongoose.disconnect();
});

describe('passkeys', () => {
  async function addPasskey(base: string, user: Awaited<ReturnType<typeof register>>) {
    const passkey = new SoftPasskey(base);
    const options = await api(base, '/api/auth/passkeys/options', { cookie: user.cookie, method: 'POST' });
    expect(options.status).toBe(200);
    expect(options.body.authenticatorSelection.userVerification).toBe('required');
    const slot = await sealAccountKey(user.accountKey, await passkeyWrapKey(passkey.prf), 'passkey');
    const res = await api(base, '/api/auth/passkeys', {
      cookie: user.cookie,
      body: { credential: passkey.register(options.body), name: 'Test laptop', slot },
    });
    expect(res.status).toBe(201);
    return passkey;
  }

  async function signIn(base: string, passkey: SoftPasskey) {
    const options = await api(base, '/api/auth/passkey/options', { method: 'POST' });
    return api(base, '/api/auth/passkey/login', { body: { credential: passkey.login(options.body) } });
  }

  it('signs in without a password and unlocks the same identity', async () => {
    const alice = await register(A.url, 'alice');
    const passkey = await addPasskey(A.url, alice);

    const res = await signIn(A.url, passkey);
    expect(res.status).toBe(200);
    expect(res.cookie).toMatch(/^ec_session=/);
    const identity = await openBundle(res.body, await passkeyWrapKey(passkey.prf), 'passkey');
    expect(identity.publicKeys).toEqual(alice.identity.publicKeys);

    const security = await api(A.url, '/api/auth/security', { cookie: res.cookie });
    expect(security.body.passkeys).toMatchObject([{ id: passkey.id, name: 'Test laptop' }]);
    expect(security.body.passkeys[0].lastUsedAt).toBeTruthy();
  });

  it('rejects replays, unknown passkeys and removed passkeys', async () => {
    const alice = await register(A.url, 'alice');
    const passkey = await addPasskey(A.url, alice);

    const options = await api(A.url, '/api/auth/passkey/options', { method: 'POST' });
    const answer = passkey.login(options.body);
    expect((await api(A.url, '/api/auth/passkey/login', { body: { credential: answer } })).status).toBe(200);
    expect((await api(A.url, '/api/auth/passkey/login', { body: { credential: answer } })).status).toBe(400);

    expect((await signIn(A.url, new SoftPasskey(A.url))).status).toBe(401);

    await api(A.url, `/api/auth/passkeys/${passkey.id}`, { cookie: alice.cookie, method: 'DELETE' });
    expect((await signIn(A.url, passkey)).status).toBe(401);
  });

  it('rejects a registration signed for a different site', async () => {
    const alice = await register(A.url, 'alice');
    const options = await api(A.url, '/api/auth/passkeys/options', { cookie: alice.cookie, method: 'POST' });
    const phishing = new SoftPasskey('https://echocrypt.evil.example');
    const slot = await sealAccountKey(alice.accountKey, await passkeyWrapKey(phishing.prf), 'passkey');
    const res = await api(A.url, '/api/auth/passkeys', {
      cookie: alice.cookie,
      body: { credential: phishing.register(options.body), name: 'x', slot },
    });
    expect(res.status).toBe(400);
  });
});

describe('recovery key', () => {
  it('resets a forgotten password and keeps the same keys', async () => {
    const alice = await register(A.url, 'alice', 'original password');
    const code = generateRecoveryCode();
    const recovery = await deriveRecoveryKeys(code);
    const set = await api(A.url, '/api/auth/recovery', {
      cookie: alice.cookie,
      method: 'PUT',
      body: { authKey: recovery.authKey, slot: await sealAccountKey(alice.accountKey, recovery.wrapKey, 'recovery') },
    });
    expect(set.status).toBe(204);

    const wrong = await deriveRecoveryKeys(generateRecoveryCode());
    expect((await api(A.url, '/api/auth/recovery/start', { body: { username: 'alice', authKey: wrong.authKey } })).status).toBe(401);
    expect((await api(A.url, '/api/auth/recovery/start', { body: { username: 'nobody', authKey: recovery.authKey } })).status).toBe(401);

    // Typed differently from how it was shown: still accepted.
    const typed = await deriveRecoveryKeys(code.toLowerCase().replace(/-/g, ' '));
    const start = await api(B.url, '/api/auth/recovery/start', { body: { username: 'alice', authKey: typed.authKey } });
    expect(start.status).toBe(200);
    expect(start.cookie).toBeUndefined();
    const accountKey = await openAccountKey(start.body.slot, typed.wrapKey, 'recovery');

    const salt = generateSalt();
    const next = await deriveAccountKeys('brand new password', salt, TEST_ITERATIONS);
    const finish = await api(B.url, '/api/auth/recovery/finish', {
      body: {
        username: 'alice',
        recoveryAuthKey: typed.authKey,
        kdfSalt: salt,
        kdfIterations: TEST_ITERATIONS,
        authKey: next.authKey,
        passwordSlot: await sealAccountKey(accountKey, next.wrapKey, 'password'),
      },
    });
    expect(finish.status).toBe(200);
    expect(finish.cookie).toMatch(/^ec_session=/);

    const params = await api(A.url, '/api/auth/params?username=alice');
    const old = await deriveAccountKeys('original password', params.body.salt, params.body.iterations);
    expect((await api(A.url, '/api/auth/login', { body: { username: 'alice', authKey: old.authKey } })).status).toBe(401);
    const login = await api(A.url, '/api/auth/login', { body: { username: 'alice', authKey: next.authKey } });
    expect(login.status).toBe(200);
    const identity = await openBundle(login.body, next.wrapKey, 'password');
    expect(identity.publicKeys).toEqual(alice.identity.publicKeys);
    // Sanity: the account key itself never changed.
    expect(await identityKey(accountKey)).toBeTruthy();
  });

  it('can be created together with the account', async () => {
    const recovery = await deriveRecoveryKeys(generateRecoveryCode());
    const placeholder = await deriveAccountKeys('unused', generateSalt(), TEST_ITERATIONS);
    // The slot content is opaque to the server; what matters is that it is stored and checked.
    const slot = await sealAccountKey(new Uint8Array(32), placeholder.wrapKey, 'recovery');
    const alice = await register(A.url, 'alice', undefined, { extra: { recovery: { authKey: recovery.authKey, slot } } });
    expect((await api(A.url, '/api/auth/security', { cookie: alice.cookie })).body.recovery).toBe(true);
    expect((await api(A.url, '/api/auth/recovery/start', { body: { username: 'alice', authKey: recovery.authKey } })).status).toBe(200);
  });

  it('changes the password only with the current one', async () => {
    const alice = await register(A.url, 'alice', 'first password');
    const params = await api(A.url, '/api/auth/params?username=alice');
    const current = await deriveAccountKeys('first password', params.body.salt, params.body.iterations);
    const salt = generateSalt();
    const next = await deriveAccountKeys('second password', salt, TEST_ITERATIONS);
    const body = {
      kdfSalt: salt,
      kdfIterations: TEST_ITERATIONS,
      authKey: next.authKey,
      passwordSlot: await sealAccountKey(alice.accountKey, next.wrapKey, 'password'),
    };
    const wrong = await deriveAccountKeys('not it', params.body.salt, params.body.iterations);
    expect((await api(A.url, '/api/auth/password', { cookie: alice.cookie, body: { ...body, currentAuthKey: wrong.authKey } })).status).toBe(401);
    expect((await api(A.url, '/api/auth/password', { cookie: alice.cookie, body: { ...body, currentAuthKey: current.authKey } })).status).toBe(204);
    const login = await api(B.url, '/api/auth/login', { body: { username: 'alice', authKey: next.authKey } });
    expect((await openBundle(login.body, next.wrapKey, 'password')).publicKeys).toEqual(alice.identity.publicKeys);
  });

  it('can be removed', async () => {
    const alice = await register(A.url, 'alice');
    const recovery = await deriveRecoveryKeys(generateRecoveryCode());
    await api(A.url, '/api/auth/recovery', {
      cookie: alice.cookie,
      method: 'PUT',
      body: { authKey: recovery.authKey, slot: await sealAccountKey(alice.accountKey, recovery.wrapKey, 'recovery') },
    });
    expect((await api(A.url, '/api/auth/security', { cookie: alice.cookie })).body.recovery).toBe(true);
    await api(A.url, '/api/auth/recovery', { cookie: alice.cookie, method: 'DELETE' });
    expect((await api(A.url, '/api/auth/security', { cookie: alice.cookie })).body.recovery).toBe(false);
    expect((await api(A.url, '/api/auth/recovery/start', { body: { username: 'alice', authKey: recovery.authKey } })).status).toBe(401);
  });
});

describe('email codes', () => {
  it('verifies an address, then signs in with a code (session only, no keys)', async () => {
    const alice = await register(A.url, 'alice');
    expect((await api(A.url, '/api/auth/email', { cookie: alice.cookie, body: { email: 'Alice@Example.com' } })).status).toBe(204);
    expect(sent.at(-1)?.to).toBe('alice@example.com');
    expect((await api(A.url, '/api/auth/email/verify', { cookie: alice.cookie, body: { code: '000000' } })).status).toBe(400);
    const verify = await api(B.url, '/api/auth/email/verify', { cookie: alice.cookie, body: { code: lastCode() } });
    expect(verify.body.email).toBe('alice@example.com');

    sent.length = 0;
    expect((await api(A.url, '/api/auth/email/login/start', { body: { email: 'nobody@example.com' } })).status).toBe(204);
    expect(sent).toHaveLength(0);

    await api(A.url, '/api/auth/email/login/start', { body: { email: 'alice@example.com' } });
    const login = await api(B.url, '/api/auth/email/login', { body: { email: 'alice@example.com', code: lastCode() } });
    expect(login.status).toBe(200);
    expect(login.body).not.toHaveProperty('encryptedKeys');
    expect((await api(A.url, '/api/auth/me', { cookie: login.cookie })).body.user.username).toBe('alice');

    // Codes are single-use.
    expect((await api(A.url, '/api/auth/email/login', { body: { email: 'alice@example.com', code: lastCode() } })).status).toBe(400);
  });

  it('burns a code after five wrong guesses', async () => {
    const alice = await register(A.url, 'alice');
    await api(A.url, '/api/auth/email', { cookie: alice.cookie, body: { email: 'alice@example.com' } });
    await api(A.url, '/api/auth/email/verify', { cookie: alice.cookie, body: { code: lastCode() } });
    await api(A.url, '/api/auth/email/login/start', { body: { email: 'alice@example.com' } });
    const code = lastCode();
    const wrong = code === '123456' ? '654321' : '123456';
    for (let i = 0; i < 5; i++) await api(A.url, '/api/auth/email/login', { body: { email: 'alice@example.com', code: wrong } });
    expect((await api(A.url, '/api/auth/email/login', { body: { email: 'alice@example.com', code } })).status).toBe(400);
  });

  it('is hidden when no mailer is configured', async () => {
    const plain = await startInstance();
    try {
      expect((await api(plain.url, '/api/auth/providers')).body).toEqual({ google: false, github: false, email: false });
      expect((await api(plain.url, '/api/auth/email/login/start', { body: { email: 'a@b.co' } })).status).toBe(404);
    } finally {
      await plain.app.close();
    }
  });
});

describe('GitHub sign-in', () => {
  const realFetch = globalThis.fetch;

  /** Fakes GitHub's token and user endpoints; everything else goes to the real network stack. */
  function fakeGitHub(githubId: number, login: string) {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      const url = String(input instanceof Request ? input.url : input);
      if (url === 'https://github.com/login/oauth/access_token') {
        const form = new URLSearchParams(String(init?.body));
        expect(form.get('client_secret')).toBe('gh-secret');
        expect(form.get('code_verifier')).toBeTruthy();
        return Response.json(form.get('code') === 'good' ? { access_token: 'tok' } : { error: 'bad_verification_code' });
      }
      if (url === 'https://api.github.com/user') return Response.json({ id: githubId, login });
      return realFetch(input, init);
    });
  }

  async function start(base: string, query: string, cookie?: string) {
    const res = await realFetch(`${base}/api/auth/oauth/github/start?${query}`, {
      redirect: 'manual',
      headers: cookie ? { cookie } : {},
    });
    const location = new URL(res.headers.get('location') ?? '', 'http://x');
    return { status: res.status, location, flowCookie: res.headers.getSetCookie()[0]?.split(';')[0] ?? '' };
  }

  async function callback(base: string, state: string, flowCookie: string, code = 'good') {
    const res = await realFetch(`${base}/api/auth/oauth/github/callback?code=${code}&state=${state}`, {
      redirect: 'manual',
      headers: { cookie: flowCookie },
    });
    const location = new URL(res.headers.get('location') ?? '', 'http://x');
    const cookies = res.headers.getSetCookie();
    const session = cookies.find((c) => c.startsWith('ec_session='))?.split(';')[0];
    const signup = cookies.find((c) => c.startsWith('ec_signup='))?.split(';')[0];
    return { status: res.status, location, session, signup };
  }

  it('links an account, then signs in with it on another instance', async () => {
    fakeGitHub(4242, 'alice-gh');
    const alice = await register(A.url, 'alice');

    const link = await start(A.url, 'mode=link', alice.cookie);
    expect(link.status).toBe(302);
    expect(link.location.origin).toBe('https://github.com');
    expect(link.location.searchParams.get('code_challenge_method')).toBe('S256');
    const linked = await callback(A.url, link.location.searchParams.get('state')!, link.flowCookie);
    expect(linked.location.searchParams.get('notice')).toMatch(/linked/);
    expect((await api(A.url, '/api/auth/security', { cookie: alice.cookie })).body.oauth.github).toBe('@alice-gh');

    const login = await start(B.url, 'mode=login');
    const done = await callback(B.url, login.location.searchParams.get('state')!, login.flowCookie);
    expect(done.location.searchParams.get('auth_error')).toBeNull();
    expect((await api(A.url, '/api/auth/me', { cookie: done.session })).body.user.username).toBe('alice');
  });

  it('refuses forged state and linking without a session', async () => {
    fakeGitHub(777, 'stranger');
    const login = await start(A.url, 'mode=login');
    const forged = await callback(A.url, 'not-the-state', login.flowCookie);
    expect(forged.session).toBeUndefined();
    expect(forged.signup).toBeUndefined();
    expect(forged.location.searchParams.get('auth_error')).toMatch(/expired/);
    expect((await start(A.url, 'mode=link')).status).toBe(401);
  });

  it('signs up a new user with "Continue with GitHub", linking the account', async () => {
    fakeGitHub(9001, 'Sarvesh-Raam');
    await register(A.url, 'sarvesh_raam'); // the obvious username is taken
    const login = await start(A.url, 'mode=login');
    const back = await callback(A.url, login.location.searchParams.get('state')!, login.flowCookie);
    expect(back.session).toBeUndefined(); // no account yet, so no session
    expect(back.location.searchParams.get('signup')).toBe('github');
    expect(back.signup).toMatch(/^ec_signup=/);

    const pending = await api(B.url, '/api/auth/signup/pending', { cookie: back.signup });
    expect(pending.body).toMatchObject({ provider: 'github', label: '@Sarvesh-Raam', displayName: 'Sarvesh-Raam' });
    expect(pending.body.username).toMatch(/^sarvesh_raam_\d{4}$/);

    // Without the cookie, linkPending is refused rather than silently ignored.
    await expect(register(A.url, 'someone', undefined, { extra: { linkPending: true } })).rejects.toThrow(/400/);

    const user = await register(B.url, pending.body.username, undefined, { cookie: back.signup, extra: { linkPending: true } });
    expect((await api(A.url, '/api/auth/security', { cookie: user.cookie })).body.oauth.github).toBe('@Sarvesh-Raam');

    const again = await start(A.url, 'mode=login');
    const done = await callback(A.url, again.location.searchParams.get('state')!, again.flowCookie);
    expect(done.signup).toBeUndefined();
    expect((await api(A.url, '/api/auth/me', { cookie: done.session })).body.user.id).toBe(user.id);
  });

  it('only offers configured providers', async () => {
    expect((await api(A.url, '/api/auth/providers')).body).toEqual({ google: false, github: true, email: true });
    expect((await realFetch(`${A.url}/api/auth/oauth/google/start`, { redirect: 'manual' })).status).toBe(404);
  });
});
