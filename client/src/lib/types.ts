import type { Envelope, PublicKeys, WrappedSecret } from '@echocrypt/crypto';

export interface PublicUser {
  id: string;
  username: string;
  displayName: string;
  publicKeys: PublicKeys;
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
