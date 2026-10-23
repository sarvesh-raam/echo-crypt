import type { Types } from 'mongoose';
import type { AppContext } from '../context.js';
import { Conversation, type ConversationDoc } from '../models/Conversation.js';
import { User, publicUser } from '../models/User.js';
import { HttpError } from './http.js';
import { onlineUsers } from './presence.js';

export const MAX_GROUP_MEMBERS = 32;

type ConvLike = Pick<ConversationDoc, '_id' | 'type' | 'name' | 'members' | 'createdBy' | 'lastMessageAt'> & {
  createdAt?: Date;
};

/** Conversations as the client sees them: members expanded with public keys and presence. */
export async function viewConversations(ctx: AppContext, convs: ConvLike[]) {
  const ids = [...new Set(convs.flatMap((c) => c.members.map(String)))];
  const [users, online] = await Promise.all([
    User.find({ _id: { $in: ids } }, { username: 1, displayName: 1, publicKeys: 1 }).lean(),
    onlineUsers(ctx.redis, ids),
  ]);
  const byId = new Map(users.map((u) => [String(u._id), publicUser(u)]));
  return convs.map((c) => ({
    id: String(c._id),
    type: c.type,
    name: c.name ?? null,
    createdBy: String(c.createdBy),
    createdAt: c.createdAt?.toISOString() ?? null,
    lastMessageAt: c.lastMessageAt?.toISOString() ?? null,
    members: c.members
      .map((m) => byId.get(String(m)))
      .filter((u): u is NonNullable<typeof u> => !!u)
      .map((u) => ({ ...u, online: online.has(u.id) })),
  }));
}

export type ConversationView = Awaited<ReturnType<typeof viewConversations>>[number];

export async function requireMembership(conversationId: string, userId: string) {
  const conv = await Conversation.findOne({ _id: conversationId, members: userId }).lean();
  if (!conv) throw new HttpError(404, 'Conversation not found');
  return conv;
}

/** Everyone who shares at least one conversation with the user (for presence updates). */
export async function contactsOf(userId: string | Types.ObjectId): Promise<string[]> {
  const ids = await Conversation.distinct('members', { members: userId });
  return ids.map(String).filter((id) => id !== String(userId));
}
