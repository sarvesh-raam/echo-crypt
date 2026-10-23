import { Schema, model, type InferSchemaType, type Types } from 'mongoose';

/**
 * A stored message is exactly the encrypted envelope produced by the sender.
 * There is deliberately no plaintext field: the server cannot read what it stores.
 */
const messageSchema = new Schema(
  {
    conversationId: { type: Schema.Types.ObjectId, ref: 'Conversation', required: true },
    senderId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    clientId: { type: String, required: true },
    v: { type: Number, required: true },
    iv: { type: String, required: true },
    ciphertext: { type: String, required: true },
    keys: {
      type: [
        {
          _id: false,
          userId: { type: String, required: true },
          epk: { type: String, required: true },
          iv: { type: String, required: true },
          wrapped: { type: String, required: true },
        },
      ],
      required: true,
    },
    signature: { type: String, required: true },
  },
  { timestamps: { createdAt: true, updatedAt: false } },
);

messageSchema.index({ conversationId: 1, _id: -1 });
// Resending the same envelope (e.g. after a reconnect) is a no-op.
messageSchema.index({ senderId: 1, clientId: 1 }, { unique: true });

export type MessageDoc = InferSchemaType<typeof messageSchema> & { _id: Types.ObjectId; createdAt: Date };
export const Message = model('Message', messageSchema);

export const toWire = (m: MessageDoc) => ({
  id: String(m._id),
  createdAt: m.createdAt.toISOString(),
  envelope: {
    v: m.v as 1,
    conversationId: String(m.conversationId),
    senderId: String(m.senderId),
    clientId: m.clientId,
    iv: m.iv,
    ciphertext: m.ciphertext,
    keys: m.keys.map((k) => ({ userId: k.userId, epk: k.epk, iv: k.iv, wrapped: k.wrapped })),
    signature: m.signature,
  },
});

export type WireMessage = ReturnType<typeof toWire>;
