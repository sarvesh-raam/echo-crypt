import { safetyNumber } from '@echocrypt/crypto';
import { AlertTriangle, BadgeCheck, Loader2, ShieldQuestion } from 'lucide-react';
import { useEffect, useState } from 'react';
import type { Member } from '../lib/types';
import { useStore } from '../store';
import { Avatar, Modal } from './ui';

function SafetyRow({ member }: { member: Member }) {
  const me = useStore((s) => s.me)!;
  const state = useStore((s) => s.trust[member.id]);
  const acceptKey = useStore((s) => s.acceptKey);
  const [number, setNumber] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    void safetyNumber({ userId: me.id, keys: me.publicKeys }, { userId: member.id, keys: member.publicKeys }).then(
      (n) => live && setNumber(n),
    );
    return () => {
      live = false;
    };
  }, [me, member]);

  return (
    <li className="rounded-xl border border-ink-700 bg-ink-900 p-4">
      <div className="flex items-center gap-3">
        <Avatar name={member.displayName} seed={member.id} size={34} />
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-medium">{member.displayName}</p>
          <p className="truncate text-xs text-ink-400">@{member.username}</p>
        </div>
        {state === 'verified' && (
          <span className="inline-flex items-center gap-1 text-xs text-accent">
            <BadgeCheck className="h-4 w-4" /> Verified
          </span>
        )}
        {state === 'changed' && (
          <span className="inline-flex items-center gap-1 text-xs text-warn">
            <AlertTriangle className="h-4 w-4" /> Changed
          </span>
        )}
        {(state === 'trusted' || state === 'new') && (
          <span className="inline-flex items-center gap-1 text-xs text-ink-400">
            <ShieldQuestion className="h-4 w-4" /> Not verified
          </span>
        )}
      </div>

      <div className="mt-3 rounded-lg bg-ink-850 px-3 py-2.5 font-mono text-[13px] leading-6 tracking-wide text-ink-300">
        {number ? (
          <div className="grid grid-cols-4 gap-x-3">
            {number.split(' ').map((g, i) => (
              <span key={i}>{g}</span>
            ))}
          </div>
        ) : (
          <Loader2 className="mx-auto my-2 h-4 w-4 animate-spin" />
        )}
      </div>

      {state === 'changed' ? (
        <div className="mt-3 space-y-2">
          <p className="text-xs text-warn">
            The server is now presenting different keys for this person. That happens if they made a new account, or if
            someone is trying to intercept your messages. Check the number with them before accepting.
          </p>
          <button className="btn-primary w-full" onClick={() => void acceptKey(member.id, true)}>
            I checked it: accept new keys
          </button>
        </div>
      ) : state !== 'verified' ? (
        <button className="btn-ghost mt-2 w-full" onClick={() => void acceptKey(member.id, true)}>
          Numbers match: mark as verified
        </button>
      ) : null}
    </li>
  );
}

export function SafetyDialog({ members, onClose }: { members: Member[]; onClose: () => void }) {
  return (
    <Modal title="Verify encryption" onClose={onClose}>
      <p className="mb-4 text-sm text-ink-400">
        Compare these numbers with each person in person or over a call. If they match on both screens, nobody (not
        even the server) has swapped the keys your messages are encrypted to.
      </p>
      <ul className="space-y-3">
        {members.map((m) => (
          <SafetyRow key={m.id} member={m} />
        ))}
      </ul>
    </Modal>
  );
}
