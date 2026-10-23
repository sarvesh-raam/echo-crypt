import { Router } from 'express';
import { z } from 'zod';
import { notifyUsers, type AppContext } from '../context.js';
import { currentUser, requireAuth } from '../lib/auth.js';
import { MAX_GROUP_MEMBERS, requireMembership, viewConversations } from '../lib/conversations.js';
import { HttpError, handler, objectId, parse } from '../lib/http.js';
import { Conversation } from '../models/Conversation.js';
import { Message, toWire, type MessageDoc } from '../models/Message.js';
import { User } from '../models/User.js';

const createBody = z.object({
  memberIds: z.array(objectId).min(1).max(MAX_GROUP_MEMBERS - 1),
  name: z.string().trim().min(1).max(64).optional(),
});

const addMembersBody = z.object({ memberIds: z.array(objectId).min(1).max(MAX_GROUP_MEMBERS - 1) });

const historyQuery = z.object({
  before: objectId.optional(),
  limit: z.coerce.number().int().min(1).max(100).default(50),
});

export function conversationRoutes(ctx: AppContext): Router {
  const r = Router();
  r.use(requireAuth);

  r.get(
    '/',
    handler(async (req, res) => {
      const convs = await Conversation.find({ members: currentUser(req) })
        .sort({ lastMessageAt: -1, updatedAt: -1 })
        .limit(200)
        .lean();
      res.json({ conversations: await viewConversations(ctx, convs) });
    }),
  );

  r.post(
    '/',
    handler(async (req, res) => {
      const me = currentUser(req);
      const body = parse(createBody, req.body);
      const members = [...new Set([me, ...body.memberIds])];
      if (members.length < 2) throw new HttpError(400, 'Pick at least one other person');
      if ((await User.countDocuments({ _id: { $in: members } })) !== members.length) {
        throw new HttpError(400, 'Unknown user in member list');
      }

      const isDirect = members.length === 2 && !body.name;
      let conv;
      if (isDirect) {
        const directKey = [...members].sort().join(':');
        // Upsert so two people starting a chat at the same moment still get one conversation.
        conv = await Conversation.findOneAndUpdate(
          { directKey },
          { $setOnInsert: { type: 'direct', members, createdBy: me, directKey } },
          { upsert: true, new: true, lean: true },
        );
      } else {
        if (!body.name) throw new HttpError(400, 'Groups need a name');
        conv = (await Conversation.create({ type: 'group', members, name: body.name, createdBy: me })).toObject();
      }

      const [view] = await viewConversations(ctx, [conv!]);
      notifyUsers(ctx, members, 'conversation:upsert', view);
      res.status(201).json({ conversation: view });
    }),
  );

  r.post(
    '/:id/members',
    handler(async (req, res) => {
      const me = currentUser(req);
      const conv = await requireMembership(parse(objectId, req.params.id), me);
      if (conv.type !== 'group') throw new HttpError(400, 'Only groups can add members');
      const { memberIds } = parse(addMembersBody, req.body);
      const members = [...new Set([...conv.members.map(String), ...memberIds])];
      if (members.length > MAX_GROUP_MEMBERS) throw new HttpError(400, `Groups are limited to ${MAX_GROUP_MEMBERS} members`);
      if ((await User.countDocuments({ _id: { $in: memberIds } })) !== new Set(memberIds).size) {
        throw new HttpError(400, 'Unknown user in member list');
      }
      const updated = await Conversation.findByIdAndUpdate(conv._id, { $addToSet: { members: { $each: memberIds } } }, { new: true, lean: true });
      const [view] = await viewConversations(ctx, [updated!]);
      notifyUsers(ctx, members, 'conversation:upsert', view);
      res.json({ conversation: view });
    }),
  );

  r.post(
    '/:id/leave',
    handler(async (req, res) => {
      const me = currentUser(req);
      const conv = await requireMembership(parse(objectId, req.params.id), me);
      if (conv.type !== 'group') throw new HttpError(400, 'You can only leave groups');
      const updated = await Conversation.findByIdAndUpdate(conv._id, { $pull: { members: me } }, { new: true, lean: true });
      notifyUsers(ctx, [me], 'conversation:removed', { id: String(conv._id) });
      if (updated && updated.members.length > 0) {
        const [view] = await viewConversations(ctx, [updated]);
        notifyUsers(ctx, updated.members.map(String), 'conversation:upsert', view);
      }
      res.status(204).end();
    }),
  );

  r.get(
    '/:id/messages',
    handler(async (req, res) => {
      const me = currentUser(req);
      const conv = await requireMembership(parse(objectId, req.params.id), me);
      const q = parse(historyQuery, req.query);
      // Only envelopes that carry a key for this user: people added to a group later
      // could not decrypt earlier messages anyway, so they are not sent.
      const docs = await Message.find({
        conversationId: conv._id,
        'keys.userId': me,
        ...(q.before ? { _id: { $lt: q.before } } : {}),
      })
        .sort({ _id: -1 })
        .limit(q.limit + 1)
        .lean<MessageDoc[]>();
      const hasMore = docs.length > q.limit;
      res.json({ messages: docs.slice(0, q.limit).reverse().map(toWire), hasMore });
    }),
  );

  return r;
}
