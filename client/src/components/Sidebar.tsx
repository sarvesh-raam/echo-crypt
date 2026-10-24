import { LogOut, PenSquare, Search, Shield, Users } from 'lucide-react';
import { useMemo, useState } from 'react';
import { conversationTitle, useStore } from '../store';
import { takeSecurityFlash } from '../lib/flash';
import { NewChatDialog } from './NewChatDialog';
import { SecurityDialog } from './SecurityDialog';
import { Avatar, BotBadge } from './ui';

function shortTime(iso: string | null) {
  if (!iso) return '';
  const d = new Date(iso);
  const now = new Date();
  if (d.toDateString() === now.toDateString()) return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  if (now.getTime() - d.getTime() < 6 * 86_400_000) return d.toLocaleDateString([], { weekday: 'short' });
  return d.toLocaleDateString([], { day: 'numeric', month: 'short' });
}

export function Sidebar() {
  const me = useStore((s) => s.me)!;
  const conversations = useStore((s) => s.conversations);
  const activeId = useStore((s) => s.activeId);
  const unread = useStore((s) => s.unread);
  const trust = useStore((s) => s.trust);
  const typing = useStore((s) => s.typing);
  const connection = useStore((s) => s.connection);
  const instance = useStore((s) => s.instance);
  const { select, logout } = useStore.getState();

  const [filter, setFilter] = useState('');
  const [dialog, setDialog] = useState(false);
  // Opens by itself when returning from linking Google/GitHub.
  const [linkResult] = useState(takeSecurityFlash);
  const [security, setSecurity] = useState(linkResult !== null);

  const visible = useMemo(() => {
    const q = filter.trim().toLowerCase();
    if (!q) return conversations;
    return conversations.filter(
      (c) =>
        conversationTitle(c, me.id).toLowerCase().includes(q) ||
        c.members.some((m) => m.username.includes(q)),
    );
  }, [conversations, filter, me.id]);

  return (
    <aside className="flex w-full flex-col bg-ink-900">
      <header className="flex items-center gap-3 border-b border-ink-800 px-4 py-3">
        <Avatar name={me.displayName} seed={me.id} size={36} />
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-semibold">{me.displayName}</p>
          <p className="truncate text-xs text-ink-400">@{me.username}</p>
        </div>
        <button className="icon-btn" onClick={() => setDialog(true)} title="New chat" aria-label="New chat">
          <PenSquare className="h-[18px] w-[18px]" />
        </button>
        <button className="icon-btn" onClick={() => setSecurity(true)} title="Security" aria-label="Security">
          <Shield className="h-[18px] w-[18px]" />
        </button>
        <button className="icon-btn" onClick={() => void logout()} title="Sign out" aria-label="Sign out">
          <LogOut className="h-[18px] w-[18px]" />
        </button>
      </header>

      {me.guest && (
        <div className="mx-4 mt-3 rounded-lg border border-accent/30 bg-accent/5 px-3 py-2.5 text-xs text-ink-300">
          <p>
            <span className="font-semibold text-accent">Demo account.</span> It and its chats are deleted after 24 hours.
          </p>
          <button className="mt-1.5 font-semibold text-accent hover:underline" onClick={() => void logout()}>
            Create a real account →
          </button>
        </div>
      )}

      <div className="px-4 py-3">
        <div className="relative">
          <Search className="pointer-events-none absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-ink-400" />
          <input
            className="input pl-9"
            placeholder="Search conversations"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            aria-label="Search conversations"
          />
        </div>
      </div>

      <nav className="scroll-thin flex-1 overflow-y-auto px-2 pb-2">
        {visible.length === 0 && (
          <div className="px-4 py-10 text-center text-sm text-ink-400">
            {conversations.length === 0 ? (
              <>
                <p>No conversations yet.</p>
                <button className="btn-primary mt-4" onClick={() => setDialog(true)}>
                  <PenSquare className="h-4 w-4" /> Start a chat
                </button>
              </>
            ) : (
              'No matches.'
            )}
          </div>
        )}
        {visible.map((c) => {
          const others = c.members.filter((m) => m.id !== me.id);
          const other = c.type === 'direct' ? others[0] : undefined;
          const title = conversationTitle(c, me.id);
          const count = unread[c.id] ?? 0;
          const changed = others.some((m) => trust[m.id] === 'changed');
          const typers = Object.entries(typing[c.id] ?? {}).filter(([, exp]) => exp > Date.now());
          return (
            <button
              key={c.id}
              onClick={() => select(c.id)}
              className={`flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-left transition ${
                activeId === c.id ? 'bg-ink-800' : 'hover:bg-ink-850'
              }`}
            >
              {c.type === 'group' ? (
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-ink-700 text-ink-300">
                  <Users className="h-5 w-5" />
                </div>
              ) : (
                <Avatar name={title} seed={other?.id ?? c.id} online={other?.online} />
              )}
              <div className="min-w-0 flex-1">
                <div className="flex items-baseline justify-between gap-2">
                  <p className={`truncate text-sm ${count ? 'font-semibold' : 'font-medium'}`}>
                    {title}
                    {other?.bot && <BotBadge />}
                  </p>
                  <span className="shrink-0 text-[11px] text-ink-400">{shortTime(c.lastMessageAt)}</span>
                </div>
                <div className="flex items-center justify-between gap-2">
                  <p className={`truncate text-xs ${changed ? 'text-warn' : typers.length ? 'text-accent' : 'text-ink-400'}`}>
                    {changed
                      ? 'Safety number changed'
                      : typers.length
                        ? 'typing…'
                        : c.type === 'group'
                          ? `${c.members.length} members`
                          : `@${other?.username ?? ''}`}
                  </p>
                  {count > 0 && (
                    <span className="rounded-full bg-accent px-1.5 text-[11px] leading-[18px] font-semibold text-ink-950">
                      {count > 99 ? '99+' : count}
                    </span>
                  )}
                </div>
              </div>
            </button>
          );
        })}
      </nav>

      <footer className="flex items-center gap-2 border-t border-ink-800 px-4 py-2.5 text-xs text-ink-400">
        <span
          className={`h-2 w-2 rounded-full ${connection === 'online' ? 'bg-accent' : connection === 'connecting' ? 'animate-pulse bg-warn' : 'bg-danger'}`}
        />
        <span>{connection === 'online' ? 'Connected' : connection === 'connecting' ? 'Reconnecting…' : 'Offline'}</span>
        {instance && connection === 'online' && (
          <span className="ml-auto truncate font-mono" title="Server instance handling this connection">
            node: {instance}
          </span>
        )}
      </footer>

      {dialog && <NewChatDialog onClose={() => setDialog(false)} />}
      {security && (
        <SecurityDialog
          onClose={() => setSecurity(false)}
          initial={linkResult ?? undefined}
        />
      )}
    </aside>
  );
}
