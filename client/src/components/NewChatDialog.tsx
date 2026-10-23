import { Check, Loader2, Search, X } from 'lucide-react';
import { useEffect, useState } from 'react';
import { api } from '../lib/api';
import type { PublicUser } from '../lib/types';
import { useStore } from '../store';
import { Avatar, ErrorText, Modal } from './ui';

/** Starts a direct chat (one person) or a group (two or more), or adds people to an existing group. */
export function NewChatDialog({
  onClose,
  addTo,
}: {
  onClose: () => void;
  addTo?: { id: string; memberIds: string[] };
}) {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<PublicUser[]>([]);
  const [picked, setPicked] = useState<PublicUser[]>([]);
  const [name, setName] = useState('');
  const [searching, setSearching] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const q = query.trim().toLowerCase();
    if (!q) {
      setResults([]);
      return;
    }
    setSearching(true);
    const t = setTimeout(() => {
      api
        .searchUsers(q)
        .then((r) => setResults(r.users.filter((u) => !addTo?.memberIds.includes(u.id))))
        .catch(() => setResults([]))
        .finally(() => setSearching(false));
    }, 200);
    return () => clearTimeout(t);
  }, [query, addTo]);

  const toggle = (u: PublicUser) =>
    setPicked((p) => (p.some((x) => x.id === u.id) ? p.filter((x) => x.id !== u.id) : [...p, u]));

  const isGroup = !addTo && picked.length > 1;

  async function submit() {
    setError(null);
    if (isGroup && !name.trim()) return setError('Give the group a name.');
    setBusy(true);
    try {
      const ids = picked.map((u) => u.id);
      if (addTo) await useStore.getState().addMembers(addTo.id, ids);
      else await useStore.getState().startConversation(ids, isGroup ? name.trim() : undefined);
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Something went wrong');
      setBusy(false);
    }
  }

  return (
    <Modal title={addTo ? 'Add people' : 'New conversation'} onClose={onClose}>
      <div className="space-y-4">
        <div className="relative">
          <Search className="pointer-events-none absolute top-1/2 left-3 h-4 w-4 -translate-y-1/2 text-ink-400" />
          <input
            className="input pl-9"
            placeholder="Search by username"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            autoFocus
            autoCapitalize="none"
            spellCheck={false}
            aria-label="Search by username"
          />
          {searching && <Loader2 className="absolute top-1/2 right-3 h-4 w-4 -translate-y-1/2 animate-spin text-ink-400" />}
        </div>

        {picked.length > 0 && (
          <div className="flex flex-wrap gap-2">
            {picked.map((u) => (
              <button
                key={u.id}
                onClick={() => toggle(u)}
                className="inline-flex items-center gap-1.5 rounded-full bg-accent/15 py-1 pr-2 pl-3 text-xs text-accent"
              >
                {u.displayName} <X className="h-3 w-3" />
              </button>
            ))}
          </div>
        )}

        <ul className="space-y-1">
          {results.map((u) => {
            const on = picked.some((x) => x.id === u.id);
            return (
              <li key={u.id}>
                <button
                  onClick={() => toggle(u)}
                  className={`flex w-full items-center gap-3 rounded-lg px-2 py-2 text-left transition ${on ? 'bg-ink-800' : 'hover:bg-ink-800/60'}`}
                >
                  <Avatar name={u.displayName} seed={u.id} size={34} />
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-medium">{u.displayName}</p>
                    <p className="truncate text-xs text-ink-400">@{u.username}</p>
                  </div>
                  {on && <Check className="h-4 w-4 text-accent" />}
                </button>
              </li>
            );
          })}
          {query.trim() && !searching && results.length === 0 && (
            <li className="py-4 text-center text-sm text-ink-400">No users found.</li>
          )}
        </ul>

        {isGroup && (
          <input className="input" placeholder="Group name" value={name} onChange={(e) => setName(e.target.value)} maxLength={64} />
        )}
        {isGroup && (
          <p className="text-xs text-ink-400">The group name is visible to the server. Messages are not.</p>
        )}
        <ErrorText>{error}</ErrorText>
        <button className="btn-primary w-full" disabled={picked.length === 0 || busy} onClick={() => void submit()}>
          {busy && <Loader2 className="h-4 w-4 animate-spin" />}
          {addTo ? `Add ${picked.length || ''}`.trim() : isGroup ? 'Create group' : 'Start chat'}
        </button>
      </div>
    </Modal>
  );
}
