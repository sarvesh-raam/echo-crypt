import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type AuthenticatorTransportFuture,
  type RegistrationResponseJSON,
} from '@simplewebauthn/server';
import { Router, type Request } from 'express';
import { z } from 'zod';
import type { AppContext } from '../context.js';
import { currentUser, issueSession, limitOrThrow, publicOrigin, requireAuth } from '../lib/auth.js';
import { HttpError, handler, parse } from '../lib/http.js';
import { logger } from '../logger.js';
import { User, keyBundle, publicUser } from '../models/User.js';
import { wrapped } from './auth.js';

/**
 * Passkeys (WebAuthn) as a passwordless way to sign in AND unlock keys.
 *
 * The browser asks the passkey for a PRF output (a secret only that passkey can produce
 * for this site). The client turns it into a key that seals a copy of the account key.
 * The server verifies the WebAuthn signature to sign the user in, then hands back that
 * sealed copy; it never sees the PRF output, so it still cannot open it.
 */
const CHALLENGE_TTL_SECONDS = 300;
const MAX_PASSKEYS = 10;

const credentialJson = z
  .object({
    id: z.string().min(1).max(1024),
    rawId: z.string().min(1).max(1024),
    type: z.literal('public-key'),
    response: z.record(z.unknown()),
    clientExtensionResults: z.record(z.unknown()).default({}),
    authenticatorAttachment: z.string().optional(),
  })
  .passthrough();

const registerBody = z.object({
  credential: credentialJson,
  name: z.string().trim().min(1).max(48),
  slot: wrapped,
});

const relyingParty = (req: Request) => {
  const origin = publicOrigin(req);
  return { origin, rpID: new URL(origin).hostname };
};

/** The challenge the browser signed, read back from clientDataJSON. */
function challengeOf(credential: { response: Record<string, unknown> }): string {
  try {
    const clientData = JSON.parse(Buffer.from(String(credential.response.clientDataJSON), 'base64url').toString('utf8'));
    return typeof clientData.challenge === 'string' ? clientData.challenge : '';
  } catch {
    return '';
  }
}

export function passkeyRoutes(ctx: AppContext): Router {
  const r = Router();

  // --- Adding a passkey (signed in) -----------------------------------------

  r.post(
    '/passkeys/options',
    requireAuth,
    handler(async (req, res) => {
      const user = await User.findById(currentUser(req)).lean();
      if (!user) throw new HttpError(401, 'Not signed in');
      if ((user.passkeys?.length ?? 0) >= MAX_PASSKEYS) throw new HttpError(400, `At most ${MAX_PASSKEYS} passkeys`);
      const { rpID } = relyingParty(req);
      const options = await generateRegistrationOptions({
        rpName: 'EchoCrypt',
        rpID,
        userName: user.username,
        userDisplayName: user.displayName,
        userID: new TextEncoder().encode(String(user._id)),
        attestationType: 'none',
        excludeCredentials: (user.passkeys ?? []).map((p) => ({
          id: p.credentialId,
          transports: p.transports as AuthenticatorTransportFuture[],
        })),
        authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
        supportedAlgorithmIDs: [-7, -257],
      });
      await ctx.redis.set(`webauthn:reg:${user._id}`, options.challenge, 'EX', CHALLENGE_TTL_SECONDS);
      res.json(options);
    }),
  );

  r.post(
    '/passkeys',
    requireAuth,
    handler(async (req, res) => {
      const userId = currentUser(req);
      const body = parse(registerBody, req.body);
      const expectedChallenge = await ctx.redis.getdel(`webauthn:reg:${userId}`);
      if (!expectedChallenge) throw new HttpError(400, 'Passkey setup expired, try again');

      const { origin, rpID } = relyingParty(req);
      let verification;
      try {
        verification = await verifyRegistrationResponse({
          response: body.credential as unknown as RegistrationResponseJSON,
          expectedChallenge,
          expectedOrigin: origin,
          expectedRPID: rpID,
          requireUserVerification: true,
        });
      } catch (err) {
        logger.info({ err }, 'passkey registration rejected');
        throw new HttpError(400, 'Passkey could not be verified');
      }
      if (!verification.verified) throw new HttpError(400, 'Passkey could not be verified');

      const { credential } = verification.registrationInfo;
      const result = await User.updateOne(
        { _id: userId, [`passkeys.${MAX_PASSKEYS - 1}`]: { $exists: false } },
        {
          $push: {
            passkeys: {
              credentialId: credential.id,
              publicKey: Buffer.from(credential.publicKey).toString('base64'),
              counter: credential.counter,
              transports: credential.transports ?? [],
              name: body.name,
              slot: body.slot,
              createdAt: new Date(),
            },
          },
        },
      ).catch((err: { code?: number }) => {
        if (err.code === 11000) throw new HttpError(409, 'This passkey is already registered');
        throw err;
      });
      if (result.modifiedCount === 0) throw new HttpError(400, `At most ${MAX_PASSKEYS} passkeys`);
      res.status(201).json({ id: credential.id });
    }),
  );

  r.delete(
    '/passkeys/:id',
    requireAuth,
    handler(async (req, res) => {
      const id = parse(z.string().min(1).max(1024), req.params.id);
      await User.updateOne({ _id: currentUser(req) }, { $pull: { passkeys: { credentialId: id } } });
      res.status(204).end();
    }),
  );

  // --- Signing in with a passkey --------------------------------------------

  r.post(
    '/passkey/options',
    handler(async (req, res) => {
      await limitOrThrow(ctx.redis, res, `passkey-options:${req.ip}`, 60, 15 * 60_000);
      const { rpID } = relyingParty(req);
      // No allowCredentials: the browser offers whichever passkeys it holds for this site.
      const options = await generateAuthenticationOptions({ rpID, userVerification: 'required' });
      await ctx.redis.set(`webauthn:auth:${options.challenge}`, '1', 'EX', CHALLENGE_TTL_SECONDS);
      res.json(options);
    }),
  );

  r.post(
    '/passkey/login',
    handler(async (req, res) => {
      await limitOrThrow(ctx.redis, res, `passkey-login:${req.ip}`, 30, 15 * 60_000);
      const credential = parse(z.object({ credential: credentialJson }), req.body).credential;
      const challenge = challengeOf(credential);
      if (!challenge || !(await ctx.redis.getdel(`webauthn:auth:${challenge}`))) {
        throw new HttpError(400, 'Sign-in expired, try again');
      }
      const user = await User.findOne({ 'passkeys.credentialId': credential.id }).lean();
      const passkey = user?.passkeys?.find((p) => p.credentialId === credential.id);
      if (!user || !passkey) throw new HttpError(401, 'This passkey is not registered with EchoCrypt');

      const { origin, rpID } = relyingParty(req);
      let verification;
      try {
        verification = await verifyAuthenticationResponse({
          response: credential as unknown as AuthenticationResponseJSON,
          expectedChallenge: challenge,
          expectedOrigin: origin,
          expectedRPID: rpID,
          requireUserVerification: true,
          credential: {
            id: passkey.credentialId,
            publicKey: new Uint8Array(Buffer.from(passkey.publicKey, 'base64')),
            counter: passkey.counter,
            transports: passkey.transports as AuthenticatorTransportFuture[],
          },
        });
      } catch (err) {
        logger.info({ err }, 'passkey sign-in rejected');
        throw new HttpError(401, 'Passkey could not be verified');
      }
      if (!verification.verified) throw new HttpError(401, 'Passkey could not be verified');

      await User.updateOne(
        { _id: user._id, 'passkeys.credentialId': passkey.credentialId },
        {
          $set: {
            'passkeys.$.counter': verification.authenticationInfo.newCounter,
            'passkeys.$.lastUsedAt': new Date(),
          },
        },
      );
      issueSession(res, String(user._id));
      res.json({ user: publicUser(user), ...keyBundle(user, passkey.slot) });
    }),
  );

  return r;
}
