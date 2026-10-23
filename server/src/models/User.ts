import { Schema, model, type InferSchemaType } from 'mongoose';

const wrapped = { iv: { type: String, required: true }, data: { type: String, required: true } };

const userSchema = new Schema(
  {
    username: { type: String, required: true, unique: true, lowercase: true, trim: true },
    displayName: { type: String, required: true, trim: true },
    /** Client-side PBKDF2 salt (public: the client needs it before it can log in). */
    kdfSalt: { type: String, required: true },
    kdfIterations: { type: Number, required: true },
    /** scrypt(authKey). The password itself never reaches the server. */
    authHash: { type: String, required: true },
    authSalt: { type: String, required: true },
    publicKeys: {
      dh: { type: String, required: true },
      sign: { type: String, required: true },
    },
    /** Private keys encrypted with a key only the user's password can derive. */
    encryptedKeys: {
      dhPrivate: wrapped,
      signPrivate: wrapped,
    },
  },
  { timestamps: true },
);

export type UserDoc = InferSchemaType<typeof userSchema> & { _id: import('mongoose').Types.ObjectId };
export const User = model('User', userSchema);

export const publicUser = (u: Pick<UserDoc, '_id' | 'username' | 'displayName' | 'publicKeys'>) => ({
  id: String(u._id),
  username: u.username,
  displayName: u.displayName,
  // Required in the schema; Mongoose types nested paths as optional.
  publicKeys: { dh: u.publicKeys!.dh, sign: u.publicKeys!.sign },
});
