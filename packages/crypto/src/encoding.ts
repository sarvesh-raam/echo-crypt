export type Bytes = Uint8Array<ArrayBuffer>;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export const utf8 = (s: string): Bytes => encoder.encode(s);
export const fromUtf8 = (b: ArrayBuffer | Uint8Array): string => decoder.decode(b);

export function toB64(data: ArrayBuffer | Uint8Array): string {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin);
}

export function fromB64(s: string): Bytes {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function toHex(data: ArrayBuffer | Uint8Array): string {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function randomBytes(n: number): Bytes {
  return crypto.getRandomValues(new Uint8Array(n));
}

/**
 * Unambiguous encoding of a list of strings: each field is a 4-byte big-endian
 * length followed by its UTF-8 bytes. Used for signatures, AAD and HKDF info so
 * that ("ab","c") and ("a","bc") can never produce the same bytes.
 */
export function encodeFields(fields: readonly string[]): Bytes {
  const parts = fields.map(utf8);
  const total = parts.reduce((n, p) => n + 4 + p.length, 0);
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  let off = 0;
  for (const p of parts) {
    view.setUint32(off, p.length);
    out.set(p, off + 4);
    off += 4 + p.length;
  }
  return out;
}
