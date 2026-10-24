import type { Envelope, PublicKeys, WrappedSecret } from '@echocrypt/crypto';

export interface PublicUser {
  id: string;
  username: string;
  displayName: string;
  publicKeys: PublicKeys;
  /** One-click demo account, deleted after a day. */
  guest?: boolean;
  /** The demo bot (its keys live on the server). */
  bot?: boolean;
}

export interface Member extends PublicUser {
  online: boolean;
}

export interface Conversation {
  id: string;
  type: 'direct' | 'group';
  name: string | null;
  createdBy: string;
  createdAt: string | null;
  lastMessageAt: string | null;
  members: Member[];
}

export interface WireMessage {
  id: string;
  createdAt: string;
  envelope: Envelope;
}

export interface EncryptedKeys {
  dhPrivate: WrappedSecret;
  signPrivate: WrappedSecret;
}

/** The sealed identity plus the one key slot the chosen sign-in method can open. */
export interface KeyBundle {
  encryptedKeys: EncryptedKeys;
  slot: WrappedSecret;
}

export interface Providers {
  google: boolean;
  github: boolean;
  email: boolean;
}

export interface SecurityInfo {
  recovery: boolean;
  passkeys: { id: string; name: string; createdAt: string; lastUsedAt: string | null }[];
  email: string | null;
  oauth: { google: string | null; github: string | null };
}

export type MessageStatus = 'sending' | 'sent' | 'failed' | 'undecryptable';

export interface ChatMessage {
  /** Server id once stored; the clientId while still sending. */
  id: string;
  clientId: string;
  conversationId: string;
  senderId: string;
  text: string;
  sentAt: number;
  createdAt: string;
  status: MessageStatus;
  error?: string;
  /** Kept for retries of failed sends (resending the same envelope is idempotent). */
  envelope?: Envelope;
}
