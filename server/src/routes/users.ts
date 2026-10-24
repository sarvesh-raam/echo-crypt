import { Router } from 'express';
import { z } from 'zod';
import { currentUser, requireAuth } from '../lib/auth.js';
import { HttpError, handler, objectId, parse } from '../lib/http.js';
import { User, publicUser } from '../models/User.js';

const escapeRegex = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

export function userRoutes(): Router {
  const r = Router();
  r.use(requireAuth);

  r.get(
    '/search',
    handler(async (req, res) => {
      const q = parse(z.string().trim().toLowerCase().min(1).max(24), req.query.q);
      const users = await User.find(
        { username: { $regex: `^${escapeRegex(q)}` }, _id: { $ne: currentUser(req) } },
        { username: 1, displayName: 1, publicKeys: 1, guest: 1, bot: 1 },
      )
        .sort({ username: 1 })
        .limit(10)
        .lean();
      res.json({ users: users.map(publicUser) });
    }),
  );

  r.get(
    '/:id',
    handler(async (req, res) => {
      const user = await User.findById(parse(objectId, req.params.id), { username: 1, displayName: 1, publicKeys: 1, guest: 1, bot: 1 }).lean();
      if (!user) throw new HttpError(404, 'User not found');
      res.json({ user: publicUser(user) });
    }),
  );

  return r;
}
