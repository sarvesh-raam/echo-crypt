import { PASSKEY_PRF_SALT, randomBytes } from '@echocrypt/crypto';

/**
 * WebAuthn in the browser, plus the PRF extension that lets a passkey produce a secret
 * for unlocking keys. Written against the raw API (no library) so the PRF output stays
 * in this page and only the signed WebAuthn response goes to the server.
 */
export class PasskeyError extends Error {}

const toB64url = (buf: ArrayBuffer | Uint8Array) => {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

const fromB64url = (s: string) => {
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(s.length / 4) * 4, '='));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};

export const passkeysSupported = () => typeof window !== 'undefined' && !!window.PublicKeyCredential && window.isSecureContext;

interface PrfResults {
  prf?: { enabled?: boolean; results?: { first?: ArrayBuffer } };
}

const prfInput = { prf: { eval: { first: PASSKEY_PRF_SALT } } } as AuthenticationExtensionsClientInputs;

function prfOutput(cred: PublicKeyCredential): Uint8Array | null {
  const first = (cred.getClientExtensionResults() as PrfResults).prf?.results?.first;
  return first ? new Uint8Array(first) : null;
}

function cancelled(err: unknown): never {
  if (err instanceof DOMException && (err.name === 'NotAllowedError' || err.name === 'AbortError')) {
    throw new PasskeyError('Passkey request was cancelled.');
  }
  if (err instanceof DOMException && err.name === 'InvalidStateError') {
    throw new PasskeyError('This device already has a passkey for your account.');
  }
  throw err;
}

const NO_PRF =
  'This passkey can sign in but cannot unlock encryption keys (it lacks the PRF feature). ' +
  'Try your phone, Google Password Manager, iCloud Keychain or a recent security key.';

interface CreationOptionsJSON {
  challenge: string;
  rp: { id?: string; name: string };
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: PublicKeyCredentialParameters[];
  timeout?: number;
  excludeCredentials?: { id: string; type: 'public-key'; transports?: AuthenticatorTransport[] }[];
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  attestation?: AttestationConveyancePreference;
}

interface RequestOptionsJSON {
  challenge: string;
  rpId?: string;
  timeout?: number;
  userVerification?: UserVerificationRequirement;
}

/** Asks the passkey for its PRF output only (no server involvement). */
async function evaluatePrf(credentialId: ArrayBuffer, rpId: string | undefined): Promise<Uint8Array | null> {
  const cred = (await navigator.credentials
    .get({
      publicKey: {
        challenge: randomBytes(32),
        rpId,
        allowCredentials: [{ id: credentialId, type: 'public-key' }],
        userVerification: 'required',
        extensions: prfInput,
      },
    })
    .catch(cancelled)) as PublicKeyCredential;
  return prfOutput(cred);
}

/** Creates a passkey and returns the server's registration payload plus the PRF secret. */
export async function createPasskey(optionsJSON: unknown): Promise<{ credential: unknown; prf: Uint8Array }> {
  const o = optionsJSON as CreationOptionsJSON;
  const cred = (await navigator.credentials
    .create({
      publicKey: {
        ...o,
        challenge: fromB64url(o.challenge),
        user: { ...o.user, id: fromB64url(o.user.id) },
        excludeCredentials: o.excludeCredentials?.map((c) => ({ ...c, id: fromB64url(c.id) })),
        extensions: prfInput,
      },
    })
    .catch(cancelled)) as PublicKeyCredential | null;
  if (!cred) throw new PasskeyError('No passkey was created.');

  const ext = cred.getClientExtensionResults() as PrfResults;
  if (ext.prf?.enabled === false) throw new PasskeyError(NO_PRF);
  // Some authenticators only evaluate PRF on sign-in, not at creation.
  const prf = prfOutput(cred) ?? (await evaluatePrf(cred.rawId, o.rp.id));
  if (!prf) throw new PasskeyError(NO_PRF);

  const res = cred.response as AuthenticatorAttestationResponse;
  return {
    prf,
    credential: {
      id: cred.id,
      rawId: toB64url(cred.rawId),
      type: 'public-key',
      response: {
        clientDataJSON: toB64url(res.clientDataJSON),
        attestationObject: toB64url(res.attestationObject),
        transports: res.getTransports?.() ?? [],
      },
      clientExtensionResults: {},
      authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
    },
  };
}

/** Signs in with any passkey this browser has for the site; returns the assertion and PRF secret. */
export async function signInWithPasskey(optionsJSON: unknown): Promise<{ credential: unknown; prf: Uint8Array }> {
  const o = optionsJSON as RequestOptionsJSON;
  const cred = (await navigator.credentials
    .get({
      publicKey: { ...o, challenge: fromB64url(o.challenge), extensions: prfInput },
    })
    .catch(cancelled)) as PublicKeyCredential | null;
  if (!cred) throw new PasskeyError('No passkey was selected.');
  const prf = prfOutput(cred);
  if (!prf) throw new PasskeyError(NO_PRF);

  const res = cred.response as AuthenticatorAssertionResponse;
  return {
    prf,
    credential: {
      id: cred.id,
      rawId: toB64url(cred.rawId),
      type: 'public-key',
      response: {
        clientDataJSON: toB64url(res.clientDataJSON),
        authenticatorData: toB64url(res.authenticatorData),
        signature: toB64url(res.signature),
        ...(res.userHandle ? { userHandle: toB64url(res.userHandle) } : {}),
      },
      clientExtensionResults: {},
      authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
    },
  };
}

/** A friendly default name for a new passkey, e.g. "Chrome on Windows". */
export function deviceName(): string {
  const ua = navigator.userAgent;
  const browser = /Edg\//.test(ua) ? 'Edge' : /Firefox\//.test(ua) ? 'Firefox' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
  const os = /Windows/.test(ua) ? 'Windows' : /Android/.test(ua) ? 'Android' : /iPhone|iPad/.test(ua) ? 'iOS' : /Mac OS/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : 'this device';
  return `${browser} on ${os}`;
}
