import { fingerprint, type PublicKeys } from '@echocrypt/crypto';

/**
 * Trust on first use. The first time we see a contact's keys we remember their
 * fingerprint. If the server later hands us different keys for the same person,
 * that is either a new account or the server attempting a man-in-the-middle, so
 * the app warns and refuses to encrypt to them until the user accepts the change.
 */
export type TrustState = 'new' | 'trusted' | 'verified' | 'changed';

interface Pin {
  fp: string;
  verified: boolean;
}

const storageKey = (me: string) => `echocrypt:pins:${me}`;

function read(me: string): Record<string, Pin> {
  try {
    return JSON.parse(localStorage.getItem(storageKey(me)) ?? '{}') as Record<string, Pin>;
  } catch {
    return {};
  }
}

function write(me: string, pins: Record<string, Pin>): void {
  try {
    localStorage.setItem(storageKey(me), JSON.stringify(pins));
  } catch {
    /* storage unavailable: pins last for this session only */
  }
}

/** Checks a contact's current keys against the pin, pinning them if this is the first sighting. */
export async function checkTrust(me: string, userId: string, keys: PublicKeys): Promise<TrustState> {
  const fp = await fingerprint(keys);
  const pins = read(me);
  const pin = pins[userId];
  if (!pin) {
    pins[userId] = { fp, verified: false };
    write(me, pins);
    return 'new';
  }
  if (pin.fp !== fp) return 'changed';
  return pin.verified ? 'verified' : 'trusted';
}

export async function acceptKeys(me: string, userId: string, keys: PublicKeys, verified: boolean): Promise<void> {
  const pins = read(me);
  pins[userId] = { fp: await fingerprint(keys), verified };
  write(me, pins);
}
