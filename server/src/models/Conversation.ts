import { Schema, Types, model, type InferSchemaType } from 'mongoose';

const conversationSchema = new Schema(
  {
    type: { type: String, enum: ['direct', 'group'], required: true },
    members: { type: [{ type: Schema.Types.ObjectId, ref: 'User' }], required: true },
    /** Group name is metadata, visible to the server (message contents are not). */
    name: { type: String, trim: true },
    createdBy: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    /** Sorted member ids for direct chats, so each pair has exactly one conversation. */
    directKey: { type: String },
    lastMessageAt: { type: Date },
  },
  { timestamps: true },
);

conversationSchema.index({ members: 1, lastMessageAt: -1 });
conversationSchema.index({ directKey: 1 }, { unique: true, partialFilterExpression: { directKey: { $type: 'string' } } });

export type ConversationDoc = InferSchemaType<typeof conversationSchema> & { _id: Types.ObjectId };
export const Conversation = model('Conversation', conversationSchema);
