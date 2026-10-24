import { Schema, model, type InferSchemaType } from 'mongoose';

const wrapped = { iv: { type: String, required: true }, data: { type: String, required: true } };
const wrappedSchema = new Schema(wrapped, { _id: false });

const passkeySchema = new Schema(
  {
    /** base64url credential id, as WebAuthn reports it. */
    credentialId: { type: String, required: true },
    publicKey: { type: String, required: true },
    counter: { type: Number, required: true },
    transports: { type: [String], default: [] },
    name: { type: String, required: true },
    /** The account key sealed under this passkey's PRF output. */
    slot: { type: wrappedSchema, required: true },
    createdAt: { type: Date, required: true },
    lastUsedAt: { type: Date },
  },
  { _id: false },
);

const linkedAccount = new Schema({ id: { type: String, required: true }, label: { type: String, required: true } }, { _id: false });

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
    /** Private keys encrypted under the account key, which the server never sees. */
    encryptedKeys: {
      dhPrivate: wrapped,
      signPrivate: wrapped,
    },
    /** Copies of the account key, each sealed under a key only one sign-in method can derive. */
    keySlots: {
      password: { type: wrappedSchema, required: true },
      recovery: { type: wrappedSchema },
    },
    /** scrypt(recovery authKey); set together with keySlots.recovery. */
    recoveryHash: { type: String },
    recoverySalt: { type: String },
    passkeys: { type: [passkeySchema], default: [] },
    /** Verified address for email sign-in codes. */
    email: { type: String, lowercase: true, trim: true },
    oauth: {
      google: { type: linkedAccount },
      github: { type: linkedAccount },
    },
  },
  { timestamps: true },
);

const whenSet = (path: string) => ({ unique: true, partialFilterExpression: { [path]: { $type: 'string' } } });
userSchema.index({ 'passkeys.credentialId': 1 }, whenSet('passkeys.credentialId'));
userSchema.index({ email: 1 }, whenSet('email'));
userSchema.index({ 'oauth.google.id': 1 }, whenSet('oauth.google.id'));
userSchema.index({ 'oauth.github.id': 1 }, whenSet('oauth.github.id'));

export type UserDoc = InferSchemaType<typeof userSchema> & { _id: import('mongoose').Types.ObjectId };
export const User = model('User', userSchema);

export const publicUser = (u: Pick<UserDoc, '_id' | 'username' | 'displayName' | 'publicKeys'>) => ({
  id: String(u._id),
  username: u.username,
  displayName: u.displayName,
  // Required in the schema; Mongoose types nested paths as optional.
  publicKeys: { dh: u.publicKeys!.dh, sign: u.publicKeys!.sign },
});

const plainWrapped = (w: { iv: string; data: string }) => ({ iv: w.iv, data: w.data });

/** What a client needs to rebuild the identity after opening one slot. */
export const keyBundle = (u: Pick<UserDoc, 'encryptedKeys'>, slot: { iv: string; data: string }) => ({
  encryptedKeys: {
    dhPrivate: plainWrapped(u.encryptedKeys!.dhPrivate!),
    signPrivate: plainWrapped(u.encryptedKeys!.signPrivate!),
  },
  slot: plainWrapped(slot),
});
