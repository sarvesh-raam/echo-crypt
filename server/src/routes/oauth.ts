import { parse as parseCookie, serialize } from 'cookie';
import { Router, type Response } from 'express';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import { config } from '../config.js';
import type { AppContext } from '../context.js';
import { currentUser, issueSession, publicOrigin, requireAuth, userIdFromCookie } from '../lib/auth.js';
import { HttpError, handler, parse } from '../lib/http.js';
import { PROVIDERS, authorizeUrl, fetchProviderUser, newFlowSecrets, type ProviderName, type ProviderUser } from '../lib/oauth.js';
import { setPendingSignup } from '../lib/signup.js';
import { logger } from '../logger.js';
import { User } from '../models/User.js';

const FLOW_COOKIE = 'ec_oauth';
const FLOW_PATH = '/api/auth/oauth';
const FLOW_TTL_SECONDS = 600;

interface Flow {
  p: ProviderName;
  s: string;
  v: string;
  /** Set when linking: the signed-in user who started the flow. */
  u?: string;
}

const providerParam = z.enum(PROVIDERS as [ProviderName, ...ProviderName[]]);
const startQuery = z.object({ mode: z.enum(['login', 'link']).default('login') });
const callbackQuery = z.object({ code: z.string().max(2048).optional(), state: z.string().max(256).optional(), error: z.string().max(256).optional() });

const redirectUri = (origin: string, p: ProviderName) => `${origin}${FLOW_PATH}/${p}/callback`;

function setFlowCookie(res: Response, value: string, maxAge: number) {
  res.append(
    'Set-Cookie',
    // Lax, not Strict: it has to come back on the provider's cross-site redirect.
    serialize(FLOW_COOKIE, value, { httpOnly: true, secure: config.COOKIE_SECURE, sameSite: 'lax', path: FLOW_PATH, maxAge }),
  );
}

export function oauthRoutes(ctx: AppContext): Router {
  const r = Router();

  r.get(
    '/oauth/:provider/start',
    handler(async (req, res) => {
      const name = parse(providerParam, req.params.provider);
      const provider = ctx.oauth[name];
      if (!provider) throw new HttpError(404, 'This sign-in method is not enabled');
      const { mode } = parse(startQuery, req.query);

      const { state, verifier } = newFlowSecrets();
      const flow: Flow = { p: name, s: state, v: verifier };
      if (mode === 'link') {
        const userId = userIdFromCookie(req.headers.cookie);
        if (!userId) throw new HttpError(401, 'Not signed in');
        flow.u = userId;
      }
      setFlowCookie(res, jwt.sign(flow, config.JWT_SECRET, { expiresIn: FLOW_TTL_SECONDS, algorithm: 'HS256' }), FLOW_TTL_SECONDS);
      res.redirect(authorizeUrl(name, provider, redirectUri(publicOrigin(req), name), flow.s, flow.v));
    }),
  );

  r.get(
    '/oauth/:provider/callback',
    handler(async (req, res) => {
      const name = parse(providerParam, req.params.provider);
      const provider = ctx.oauth[name];
      const query = parse(callbackQuery, req.query);
      setFlowCookie(res, '', 0);

      let flow: Flow | null = null;
      try {
        const token = parseCookie(req.headers.cookie ?? '')[FLOW_COOKIE];
        flow = token ? (jwt.verify(token, config.JWT_SECRET, { algorithms: ['HS256'] }) as Flow) : null;
      } catch {
        flow = null;
      }
      const back = (params: Record<string, string>) =>
        res.redirect(`/?${new URLSearchParams({ ...(flow?.u ? { settings: 'security' } : {}), ...params })}`);

      if (!provider || !flow || flow.p !== name || !query.state || query.state !== flow.s) {
        return back({ auth_error: 'Sign-in expired or was started in another tab. Please try again.' });
      }
      if (query.error || !query.code) return back({ auth_error: 'Sign-in was cancelled.' });

      let account: ProviderUser;
      try {
        account = await fetchProviderUser(name, provider, query.code, redirectUri(publicOrigin(req), name), flow.v);
      } catch (err) {
        logger.warn({ err, provider: name }, 'oauth exchange failed');
        return back({ auth_error: `Could not reach ${name === 'google' ? 'Google' : 'GitHub'}. Please try again.` });
      }

      const label = name === 'google' ? 'Google' : 'GitHub';
      const owner = await User.findOne({ [`oauth.${name}.id`]: account.id }, { _id: 1 }).lean();

      if (flow.u) {
        if (owner && String(owner._id) !== flow.u) {
          return back({ auth_error: `That ${label} account is already linked to another EchoCrypt user.` });
        }
        await User.updateOne({ _id: flow.u }, { $set: { [`oauth.${name}`]: { id: account.id, label: account.label } } });
        return back({ notice: `${label} account linked.` });
      }

      if (!owner) {
        // New here: the browser finishes sign-up (it has to create the keys).
        setPendingSignup(res, { provider: name, account });
        return back({ signup: name });
      }
      issueSession(res, String(owner._id));
      return back({});
    }),
  );

  r.delete(
    '/oauth/:provider',
    requireAuth,
    handler(async (req, res) => {
      const name = parse(providerParam, req.params.provider);
      await User.updateOne({ _id: currentUser(req) }, { $unset: { [`oauth.${name}`]: 1 } });
      res.status(204).end();
    }),
  );

  return r;
}
