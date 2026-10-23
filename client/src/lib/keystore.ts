import type { Identity } from '@echocrypt/crypto';

/**
 * Keeps the unlocked identity in IndexedDB so a page reload doesn't ask for the
 * password again. The private keys are non-extractable CryptoKey objects: the
 * browser can store and use them, but no script can read their bytes.
 */
const DB = 'echocrypt';
const STORE = 'identity';

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function tx<T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const db = await open();
  try {
    return await new Promise<T>((resolve, reject) => {
      const req = fn(db.transaction(STORE, mode).objectStore(STORE));
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  } finally {
    db.close();
  }
}

export async function saveIdentity(userId: string, identity: Identity): Promise<void> {
  try {
    await tx('readwrite', (s) => s.put(identity, userId));
  } catch {
    /* private mode etc.: the session just won't survive a reload */
  }
}

export async function loadIdentity(userId: string): Promise<Identity | null> {
  try {
    const id = await tx<Identity | undefined>('readonly', (s) => s.get(userId));
    return id?.dhPrivate && id.signPrivate ? id : null;
  } catch {
    return null;
  }
}

export async function clearIdentities(): Promise<void> {
  try {
    await tx('readwrite', (s) => s.clear());
  } catch {
    /* nothing stored */
  }
}
