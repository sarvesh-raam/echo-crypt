import { MAX_MESSAGE_CHARS } from '@echocrypt/crypto';
import {
  AlertTriangle,
  ArrowLeft,
  Check,
  Clock,
  Loader2,
  Lock,
  LogOut,
  RotateCcw,
  SendHorizontal,
  ShieldAlert,
  UserPlus,
  Users,
} from 'lucide-react';
import { Fragment, useEffect, useLayoutEffect, useRef, useState, type KeyboardEvent } from 'react';
import type { ChatMessage } from '../lib/types';
import { conversationTitle, useStore } from '../store';
import { NewChatDialog } from './NewChatDialog';
import { SafetyDialog } from './SafetyDialog';
import { Avatar, ErrorText } from './ui';

const EMPTY: ChatMessage[] = [];

const dayLabel = (iso: string) => {
  const d = new Date(iso);
  const today = new Date();
  const yesterday = new Date(Date.now() - 86_400_000);
  if (d.toDateString() === today.toDateString()) return 'Today';
  if (d.toDateString() === yesterday.toDateString()) return 'Yesterday';
  return d.toLocaleDateString([], { weekday: 'long', day: 'numeric', month: 'long' });
};

export function ChatView({ conversationId }: { conversationId: string }) {
  const me = useStore((s) => s.me)!;
  const conv = useStore((s) => s.conversations.find((c) => c.id === conversationId))!;
  const thread = useStore((s) => s.threads[conversationId]);
  const trust = useStore((s) => s.trust);
  const typingMap = useStore((s) => s.typing[conversationId]);
  const { select, loadOlder, leave } = useStore.getState();

  const [safety, setSafety] = useState(false);
  const [adding, setAdding] = useState(false);
  const [, tick] = useState(0);

  const others = conv.members.filter((m) => m.id !== me.id);
  const title = conversationTitle(conv, me.id);
  const changed = others.filter((m) => trust[m.id] === 'changed');
  const allVerified = others.length > 0 && others.every((m) => trust[m.id] === 'verified');
  const messages = thread?.messages ?? EMPTY;
  const typers = Object.entries(typingMap ?? {})
    .filter(([, exp]) => exp > Date.now())
    .map(([id]) => conv.members.find((m) => m.id === id)?.displayName)
    .filter(Boolean);

  // Re-render while someone is typing so stale indicators expire.
  useEffect(() => {
    if (!typers.length) return;
    const t = setInterval(() => tick((n) => n + 1), 1000);
    return () => clearInterval(t);
  }, [typers.length]);

  const scroller = useRef<HTMLDivElement>(null);
  const stick = useRef(true);
  const prevHeight = useRef(0);
  const firstId = messages[0]?.id;

  useLayoutEffect(() => {
    const el = scroller.current;
    if (!el) return;
    if (stick.current) el.scrollTop = el.scrollHeight;
    else if (prevHeight.current && el.scrollHeight > prevHeight.current && el.scrollTop < 50) {
      // Older messages were prepended: keep the view anchored.
      el.scrollTop += el.scrollHeight - prevHeight.current;
    }
    prevHeight.current = el.scrollHeight;
  }, [messages.length, firstId, typers.length]);

  const onScroll = () => {
    const el = scroller.current!;
    stick.current = el.scrollHeight - el.scrollTop - el.clientHeight < 80;
    if (el.scrollTop < 60 && thread?.hasMore && !thread.loading) void loadOlder(conversationId);
  };

  const subtitle =
    conv.type === 'direct'
      ? others[0]?.online
        ? 'Online'
        : 'Offline'
      : `${conv.members.length} members · ${conv.members.filter((m) => m.online).length} online`;

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <header className="flex items-center gap-3 border-b border-ink-800 bg-ink-900/80 px-3 py-2.5 backdrop-blur sm:px-4">
        <button className="icon-btn md:hidden" onClick={() => select(null)} aria-label="Back">
          <ArrowLeft className="h-5 w-5" />
        </button>
        {conv.type === 'group' ? (
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-ink-700 text-ink-300">
            <Users className="h-[18px] w-[18px]" />
          </div>
        ) : (
          <Avatar name={title} seed={others[0]?.id ?? conv.id} online={others[0]?.online} size={36} />
        )}
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-semibold">{title}</p>
          <p className="truncate text-xs text-ink-400">{subtitle}</p>
        </div>
        <button
          onClick={() => setSafety(true)}
          className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1.5 text-xs font-medium transition ${
            changed.length
              ? 'bg-warn/15 text-warn hover:bg-warn/25'
              : allVerified
                ? 'bg-accent/15 text-accent hover:bg-accent/25'
                : 'bg-ink-800 text-ink-300 hover:text-ink-100'
          }`}
          title="End-to-end encrypted. Click to verify safety numbers."
        >
          {changed.length ? <ShieldAlert className="h-3.5 w-3.5" /> : <Lock className="h-3.5 w-3.5" />}
          <span className="hidden sm:inline">{changed.length ? 'Keys changed' : allVerified ? 'Verified' : 'Encrypted'}</span>
        </button>
        {conv.type === 'group' && (
          <>
            <button className="icon-btn" onClick={() => setAdding(true)} title="Add people" aria-label="Add people">
              <UserPlus className="h-[18px] w-[18px]" />
            </button>
            <button
              className="icon-btn"
              title="Leave group"
              aria-label="Leave group"
              onClick={() => {
                if (confirm(`Leave “${title}”? You will stop receiving its messages.`)) void leave(conv.id);
              }}
            >
              <LogOut className="h-[18px] w-[18px]" />
            </button>
          </>
        )}
      </header>

      {changed.length > 0 && (
        <div className="flex items-start gap-3 border-b border-warn/30 bg-warn/10 px-4 py-3 text-sm text-amber-200">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          <p className="flex-1">
            The safety number for {changed.map((m) => m.displayName).join(', ')} changed. Sending is paused until you
            check it.{' '}
            <button className="font-semibold underline underline-offset-2" onClick={() => setSafety(true)}>
              Review
            </button>
          </p>
        </div>
      )}

      <div ref={scroller} onScroll={onScroll} className="scroll-thin flex-1 overflow-y-auto px-3 py-4 sm:px-6">
        {thread?.loading && (
          <div className="flex justify-center py-3 text-ink-400">
            <Loader2 className="h-4 w-4 animate-spin" />
          </div>
        )}
        {thread?.loaded && !thread.hasMore && (
          <div className="mx-auto mb-6 max-w-sm rounded-xl border border-ink-800 bg-ink-850 px-4 py-3 text-center text-xs text-ink-400">
            <Lock className="mx-auto mb-1.5 h-4 w-4 text-accent" />
            Messages here are end-to-end encrypted. Only the people in this chat can read them.
          </div>
        )}
        {messages.map((m, i) => {
          const prev = messages[i - 1];
          const newDay = !prev || new Date(prev.createdAt).toDateString() !== new Date(m.createdAt).toDateString();
          const grouped = !newDay && prev?.senderId === m.senderId && Date.parse(m.createdAt) - Date.parse(prev.createdAt) < 120_000;
          const sender = conv.members.find((x) => x.id === m.senderId);
          return (
            <Fragment key={m.clientId + m.senderId}>
              {newDay && (
                <div className="my-4 flex justify-center">
                  <span className="rounded-full bg-ink-850 px-3 py-1 text-[11px] text-ink-400">{dayLabel(m.createdAt)}</span>
                </div>
              )}
              <Bubble
                message={m}
                mine={m.senderId === me.id}
                grouped={grouped}
                senderName={conv.type === 'group' ? (sender?.displayName ?? 'Former member') : undefined}
              />
            </Fragment>
          );
        })}
        {typers.length > 0 && (
          <div className="mt-2 flex items-center gap-2 text-xs text-ink-400">
            <span className="inline-flex gap-0.5 rounded-full bg-ink-800 px-3 py-2">
              {[0, 1, 2].map((d) => (
                <span key={d} className="typing-dot h-1.5 w-1.5 rounded-full bg-ink-300" style={{ animationDelay: `${d * 0.2}s` }} />
              ))}
            </span>
            {conv.type === 'group' && <span>{typers.join(', ')}</span>}
          </div>
        )}
      </div>

      <Composer conversationId={conversationId} blocked={changed.length > 0} />

      {safety && <SafetyDialog members={others} onClose={() => setSafety(false)} />}
      {adding && (
        <NewChatDialog onClose={() => setAdding(false)} addTo={{ id: conv.id, memberIds: conv.members.map((m) => m.id) }} />
      )}
    </div>
  );
}

function Bubble({
  message: m,
  mine,
  grouped,
  senderName,
}: {
  message: ChatMessage;
  mine: boolean;
  grouped: boolean;
  senderName?: string;
}) {
  const retry = useStore((s) => s.retry);
  const time = new Date(m.sentAt || m.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  if (m.status === 'undecryptable') {
    return (
      <div className={`flex ${mine ? 'justify-end' : 'justify-start'} ${grouped ? 'mt-1' : 'mt-3'}`}>
        <div className="max-w-[80%] rounded-2xl border border-danger/30 bg-danger/5 px-3.5 py-2 text-sm text-red-300 italic">
          <ShieldAlert className="mr-1.5 inline h-4 w-4 align-[-3px]" />
          Couldn’t verify or decrypt this message ({m.error}).
        </div>
      </div>
    );
  }

  return (
    <div className={`flex ${mine ? 'justify-end' : 'justify-start'} ${grouped ? 'mt-1' : 'mt-3'}`}>
      <div className={`max-w-[80%] sm:max-w-[65%] ${mine ? 'items-end' : 'items-start'} flex flex-col`}>
        {senderName && !mine && !grouped && <span className="mb-1 ml-3 text-xs font-medium text-ink-400">{senderName}</span>}
        <div
          className={`rounded-2xl px-3.5 py-2 text-[15px] leading-relaxed break-words whitespace-pre-wrap ${
            mine ? 'rounded-br-md bg-accent text-ink-950' : 'rounded-bl-md bg-ink-800 text-ink-100'
          } ${m.status === 'failed' ? 'opacity-60' : ''}`}
        >
          {m.text}
          <span className={`ml-2 inline-flex translate-y-0.5 items-center gap-1 text-[10px] ${mine ? 'text-ink-950/60' : 'text-ink-400'}`}>
            {time}
            {mine && m.status === 'sending' && <Clock className="h-3 w-3" />}
            {mine && m.status === 'sent' && <Check className="h-3 w-3" />}
          </span>
        </div>
        {m.error && m.status === 'sent' && (
          <span className="mt-1 inline-flex items-center gap-1 text-[11px] text-warn">
            <AlertTriangle className="h-3 w-3" /> {m.error}
          </span>
        )}
        {m.status === 'failed' && (
          <button
            onClick={() => void retry(m.conversationId, m.clientId)}
            className="mt-1 inline-flex items-center gap-1 text-[11px] text-red-300 hover:underline"
          >
            <RotateCcw className="h-3 w-3" /> {m.error ?? 'Not sent'}. Tap to retry
          </button>
        )}
      </div>
    </div>
  );
}

function Composer({ conversationId, blocked }: { conversationId: string; blocked: boolean }) {
  const send = useStore((s) => s.send);
  const setTyping = useStore((s) => s.setTyping);
  const [text, setText] = useState('');
  const [error, setError] = useState<string | null>(null);
  const area = useRef<HTMLTextAreaElement>(null);
  const typingSent = useRef(0);
  const stopTimer = useRef<ReturnType<typeof setTimeout>>();

  useEffect(() => {
    const el = area.current;
    if (!el) return;
    el.style.height = 'auto';
    el.style.height = `${Math.min(el.scrollHeight, 160)}px`;
  }, [text]);

  useEffect(
    () => () => {
      clearTimeout(stopTimer.current);
      if (typingSent.current) setTyping(conversationId, false);
    },
    [conversationId, setTyping],
  );

  const onChange = (value: string) => {
    setText(value);
    if (Date.now() - typingSent.current > 3000) {
      setTyping(conversationId, true);
      typingSent.current = Date.now();
    }
    clearTimeout(stopTimer.current);
    stopTimer.current = setTimeout(() => {
      setTyping(conversationId, false);
      typingSent.current = 0;
    }, 4000);
  };

  const submit = async () => {
    const value = text.trim();
    if (!value || blocked) return;
    setError(null);
    setText('');
    clearTimeout(stopTimer.current);
    typingSent.current = 0;
    try {
      await send(conversationId, value);
    } catch (err) {
      setText(value);
      setError(err instanceof Error ? err.message : 'Could not send');
    }
    area.current?.focus();
  };

  const onKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey && !e.nativeEvent.isComposing) {
      e.preventDefault();
      void submit();
    }
  };

  const over = text.length > MAX_MESSAGE_CHARS;

  return (
    <div className="border-t border-ink-800 bg-ink-900 px-3 py-3 sm:px-4">
      {error && (
        <div className="mb-2">
          <ErrorText>{error}</ErrorText>
        </div>
      )}
      <div className="flex items-end gap-2">
        <textarea
          ref={area}
          rows={1}
          value={text}
          onChange={(e) => onChange(e.target.value)}
          onKeyDown={onKeyDown}
          disabled={blocked}
          placeholder={blocked ? 'Verify the changed safety number to continue' : 'Write an encrypted message…'}
          className="input max-h-40 min-h-[44px] flex-1 resize-none py-2.5 leading-6"
          aria-label="Message"
          autoFocus
        />
        <button
          className="btn-primary h-11 w-11 shrink-0 p-0"
          onClick={() => void submit()}
          disabled={!text.trim() || over || blocked}
          aria-label="Send"
        >
          <SendHorizontal className="h-[18px] w-[18px]" />
        </button>
      </div>
      {text.length > MAX_MESSAGE_CHARS - 500 && (
        <p className={`mt-1 text-right text-[11px] ${over ? 'text-danger' : 'text-ink-400'}`}>
          {text.length}/{MAX_MESSAGE_CHARS}
        </p>
      )}
    </div>
  );
}
