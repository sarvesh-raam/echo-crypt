import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { isoCBOR } from '@simplewebauthn/server/helpers';

const sha256 = (data: Buffer | string) => createHash('sha256').update(data).digest();
const b64url = (b: Uint8Array) => Buffer.from(b).toString('base64url');

/**
 * A software passkey (P-256, "none" attestation) that produces the same messages a
 * browser would, so the server's real WebAuthn verification runs in tests. The PRF
 * output stands in for what a real passkey would compute for this credential.
 */
export class SoftPasskey {
  private readonly keys = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  readonly credentialId = randomBytes(16);
  readonly prf = randomBytes(32);
  private counter = 0;

  constructor(private readonly origin: string) {}

  get id(): string {
    return b64url(this.credentialId);
  }

  private authData(attested: boolean): Buffer {
    const rpIdHash = sha256(new URL(this.origin).hostname);
    const flags = Buffer.from([0x01 | 0x04 | (attested ? 0x40 : 0)]); // user present + verified (+ attested data)
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(this.counter);
    if (!attested) return Buffer.concat([rpIdHash, flags, counter]);

    const jwk = this.keys.publicKey.export({ format: 'jwk' });
    const cose = isoCBOR.encode(
      new Map<number, number | Uint8Array>([
        [1, 2], // kty: EC2
        [3, -7], // alg: ES256
        [-1, 1], // crv: P-256
        [-2, Buffer.from(jwk.x!, 'base64url')],
        [-3, Buffer.from(jwk.y!, 'base64url')],
      ]),
    );
    const idLength = Buffer.alloc(2);
    idLength.writeUInt16BE(this.credentialId.length);
    return Buffer.concat([rpIdHash, flags, counter, Buffer.alloc(16), idLength, this.credentialId, Buffer.from(cose)]);
  }

  private clientData(type: string, challenge: string): Buffer {
    return Buffer.from(JSON.stringify({ type, challenge, origin: this.origin, crossOrigin: false }));
  }

  register(options: { challenge: string }) {
    const attestationObject = isoCBOR.encode(
      new Map<string, unknown>([
        ['fmt', 'none'],
        ['attStmt', new Map()],
        ['authData', this.authData(true)],
      ]) as never,
    );
    return {
      id: this.id,
      rawId: this.id,
      type: 'public-key' as const,
      response: {
        clientDataJSON: b64url(this.clientData('webauthn.create', options.challenge)),
        attestationObject: b64url(attestationObject),
        transports: ['internal'],
      },
      clientExtensionResults: {},
      authenticatorAttachment: 'platform',
    };
  }

  login(options: { challenge: string }) {
    this.counter++;
    const authData = this.authData(false);
    const clientDataJSON = this.clientData('webauthn.get', options.challenge);
    const signature = sign('sha256', Buffer.concat([authData, sha256(clientDataJSON)]), this.keys.privateKey);
    return {
      id: this.id,
      rawId: this.id,
      type: 'public-key' as const,
      response: {
        clientDataJSON: b64url(clientDataJSON),
        authenticatorData: b64url(authData),
        signature: b64url(signature),
      },
      clientExtensionResults: {},
      authenticatorAttachment: 'platform',
    };
  }
}
