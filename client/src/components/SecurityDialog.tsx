import { Download, Fingerprint, KeyRound, LifeBuoy, Link2, Loader2, Mail, Trash2 } from 'lucide-react';
import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from 'react';
import { api, oauthStartUrl, type OAuthProvider } from '../lib/api';
import { deviceName, passkeysSupported } from '../lib/passkey';
import type { Providers, SecurityInfo } from '../lib/types';
import { useStore } from '../store';
import { CopyButton, PasswordInput, ProviderIcon } from './forms';
import { ErrorText, Modal } from './ui';

type KeyAction = 'passkey' | 'recovery';

const PROVIDER_LABEL: Record<OAuthProvider, string> = { google: 'Google', github: 'GitHub' };

/**
 * Sign-in methods. Passkeys and the recovery key hold their own copy of the account key,
 * so adding one needs the account key in this tab; after a reload we ask the user to
 * confirm with their password or an existing passkey first.
 */
export function SecurityDialog({ onClose, initial }: { onClose: () => void; initial?: { notice?: string | null; error?: string | null } }) {
  const me = useStore((s) => s.me)!;
  const { canManageKeys, confirmWithPassword, confirmWithPasskey, createRecoveryKey, addPasskey } = useStore.getState();

  const [info, setInfo] = useState<SecurityInfo | null>(null);
  const [providers, setProviders] = useState<Providers>({ google: false, github: false, email: false });
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(initial?.error ?? null);
  const [notice, setNotice] = useState<string | null>(initial?.notice ?? null);
  const [confirming, setConfirming] = useState<KeyAction | null>(null);
  const [newCode, setNewCode] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    const [s, p] = await Promise.all([api.security(), api.providers()]);
    setInfo(s);
    setProviders(p);
  }, []);

  useEffect(() => {
    refresh().catch((err: Error) => setError(err.message));
  }, [refresh]);

  async function run(label: string, action: () => Promise<void>) {
    setError(null);
    setNotice(null);
    setBusy(label);
    try {
      await action();
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Something went wrong');
    }
    setBusy(null);
  }

  async function perform(action: KeyAction) {
    if (action === 'passkey') {
      await addPasskey(deviceName());
      setNotice('Passkey added. You can now sign in and unlock with it.');
    } else {
      setNewCode(await createRecoveryKey());
    }
  }

  function start(action: KeyAction) {
    if (!canManageKeys()) {
      setConfirming(action);
      return;
    }
    void run(action === 'passkey' ? 'Waiting for your passkey…' : 'Creating recovery key…', () => perform(action));
  }

  if (!info) {
    return (
      <Modal title="Security" onClose={onClose}>
        <div className="flex justify-center py-8 text-ink-400">
          {error ? <ErrorText>{error}</ErrorText> : <Loader2 className="h-5 w-5 animate-spin" />}
        </div>
      </Modal>
    );
  }

  return (
    <Modal title="Security" onClose={onClose}>
      <div className="space-y-6">
        {notice && <p className="rounded-lg bg-accent/10 px-3 py-2 text-sm text-accent">{notice}</p>}
        <ErrorText>{error}</ErrorText>

        {confirming && (
          <ConfirmIdentity
            onCancel={() => setConfirming(null)}
            onPassword={(pw) =>
              run('Checking password…', async () => {
                await confirmWithPassword(pw);
                const action = confirming;
                setConfirming(null);
                await perform(action);
              })
            }
            onPasskey={() =>
              run('Waiting for your passkey…', async () => {
                await confirmWithPasskey();
                const action = confirming;
                setConfirming(null);
                await perform(action);
              })
            }
            busy={busy}
          />
        )}

        {newCode && <RecoveryCode code={newCode} username={me.username} onDone={() => setNewCode(null)} />}

        <Section icon={<Fingerprint className="h-4 w-4" />} title="Passkeys" text="Sign in and unlock with your fingerprint, face or device PIN. No password needed.">
          {info.passkeys.map((p) => (
            <Row key={p.id} label={p.name} sub={`Added ${new Date(p.createdAt).toLocaleDateString()}${p.lastUsedAt ? ` · last used ${new Date(p.lastUsedAt).toLocaleDateString()}` : ''}`}>
              <IconButton
                label={`Remove passkey ${p.name}`}
                onClick={() => {
                  if (window.confirm(`Remove the passkey "${p.name}"? You will no longer be able to sign in with it.`)) {
                    void run('Removing…', () => api.removePasskey(p.id));
                  }
                }}
              />
            </Row>
          ))}
          {passkeysSupported() ? (
            <button className="btn-ghost w-full border border-ink-700" disabled={!!busy} onClick={() => start('passkey')}>
              <Fingerprint className="h-4 w-4" /> Add a passkey on this device
            </button>
          ) : (
            <p className="text-xs text-ink-400">This browser does not support passkeys.</p>
          )}
        </Section>

        <Section icon={<LifeBuoy className="h-4 w-4" />} title="Recovery key" text="If you forget your password, this one-time key lets you reset it without losing messages.">
          <Row label={info.recovery ? 'Recovery key is set' : 'No recovery key yet'} sub={info.recovery ? 'Keep it somewhere safe, offline.' : 'Strongly recommended.'}>
            {info.recovery && (
              <IconButton
                label="Remove recovery key"
                onClick={() => {
                  if (window.confirm('Remove your recovery key? If you then forget your password, your messages cannot be recovered.')) {
                    void run('Removing…', () => api.removeRecovery());
                  }
                }}
              />
            )}
          </Row>
          <button className="btn-ghost w-full border border-ink-700" disabled={!!busy} onClick={() => start('recovery')}>
            <KeyRound className="h-4 w-4" /> {info.recovery ? 'Replace recovery key' : 'Create recovery key'}
          </button>
        </Section>

        {providers.email && <EmailSection email={info.email} busy={!!busy} run={run} />}

        {(providers.google || providers.github) && (
          <Section icon={<Link2 className="h-4 w-4" />} title="Linked accounts" text="Sign in with one click. On a new device you still unlock with your password or a passkey.">
            {(['google', 'github'] as const)
              .filter((p) => providers[p])
              .map((p) => (
                <Row key={p} label={PROVIDER_LABEL[p]} sub={info.oauth[p] ?? 'Not linked'} icon={<ProviderIcon provider={p} />}>
                  {info.oauth[p] ? (
                    <button className="btn-ghost px-3 py-1.5 text-xs" disabled={!!busy} onClick={() => void run('Unlinking…', () => api.unlinkOAuth(p))}>
                      Unlink
                    </button>
                  ) : (
                    <a className="btn-ghost border border-ink-700 px-3 py-1.5 text-xs" href={oauthStartUrl(p, 'link')}>
                      Link
                    </a>
                  )}
                </Row>
              ))}
          </Section>
        )}

        {busy && (
          <p className="flex items-center gap-2 text-sm text-ink-400" aria-live="polite">
            <Loader2 className="h-4 w-4 animate-spin" /> {busy}
          </p>
        )}
      </div>
    </Modal>
  );
}

function ConfirmIdentity({
  onCancel,
  onPassword,
  onPasskey,
  busy,
}: {
  onCancel: () => void;
  onPassword: (password: string) => void;
  onPasskey: () => void;
  busy: string | null;
}) {
  const [password, setPassword] = useState('');
  const submit = (e: FormEvent) => {
    e.preventDefault();
    onPassword(password);
  };
  return (
    <form onSubmit={submit} className="space-y-3 rounded-xl border border-accent/30 bg-accent/5 p-4">
      <p className="text-sm font-medium">Confirm it’s you</p>
      <p className="text-xs text-ink-400">Your keys are needed to set this up. They stay in this browser.</p>
      <PasswordInput value={password} onChange={setPassword} autoFocus />
      <div className="flex flex-wrap gap-2">
        <button className="btn-primary flex-1" disabled={!!busy}>
          Continue
        </button>
        {passkeysSupported() && (
          <button type="button" className="btn-ghost border border-ink-700" disabled={!!busy} onClick={onPasskey}>
            <Fingerprint className="h-4 w-4" /> Passkey
          </button>
        )}
        <button type="button" className="btn-ghost" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}

export function RecoveryCode({
  code,
  username,
  onDone,
  replacing = true,
}: {
  code: string;
  username: string;
  onDone: () => void;
  /** False on sign-up, where there is no earlier key to invalidate. */
  replacing?: boolean;
}) {
  const download = () => {
    const text = `EchoCrypt recovery key\n\nUsername: ${username}\nRecovery key: ${code}\n\nUse it on the sign-in page under "Forgot password?".\nAnyone with this key and your username can reset your password. Keep it private.\n`;
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
    const a = Object.assign(document.createElement('a'), { href: url, download: `echocrypt-recovery-${username}.txt` });
    a.click();
    URL.revokeObjectURL(url);
  };
  return (
    <div className="space-y-3 rounded-xl border border-warn/40 bg-warn/5 p-4">
      <p className="text-sm font-medium">Save your recovery key now</p>
      <p className="text-xs text-ink-400">It is shown only once.{replacing && ' Any previous recovery key no longer works.'}</p>
      <p className="rounded-lg bg-ink-950 px-3 py-3 text-center font-mono text-sm tracking-wider break-all select-all" data-testid="recovery-code">
        {code}
      </p>
      <div className="flex flex-wrap gap-2">
        <CopyButton text={code} />
        <button type="button" className="btn-ghost" onClick={download}>
          <Download className="h-4 w-4" /> Download
        </button>
        <button type="button" className="btn-primary ml-auto" onClick={onDone}>
          I saved it
        </button>
      </div>
    </div>
  );
}

function EmailSection({
  email,
  busy,
  run,
}: {
  email: string | null;
  busy: boolean;
  run: (label: string, action: () => Promise<void>) => Promise<void>;
}) {
  const [address, setAddress] = useState('');
  const [code, setCode] = useState('');
  const [sent, setSent] = useState(false);

  return (
    <Section icon={<Mail className="h-4 w-4" />} title="Email sign-in" text="Get a 6-digit code by email instead of typing your password.">
      {email ? (
        <Row label={email} sub="Verified">
          <IconButton label="Remove email" onClick={() => void run('Removing…', () => api.removeEmail())} />
        </Row>
      ) : (
        <form
          className="space-y-2"
          onSubmit={(e) => {
            e.preventDefault();
            if (!sent) void run('Sending code…', async () => {
              await api.addEmail(address.trim());
              setSent(true);
            });
            else void run('Verifying…', async () => {
              await api.verifyEmail(code);
              setSent(false);
              setCode('');
            });
          }}
        >
          <input className="input" type="email" placeholder="you@example.com" value={address} onChange={(e) => setAddress(e.target.value)} disabled={sent} required aria-label="Email address" />
          {sent && (
            <input
              className="input font-mono tracking-[0.4em]"
              placeholder="6-digit code"
              value={code}
              onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
              inputMode="numeric"
              autoComplete="one-time-code"
              aria-label="Code from the email"
              required
              autoFocus
            />
          )}
          <button className="btn-ghost w-full border border-ink-700" disabled={busy}>
            {sent ? 'Verify code' : 'Send verification code'}
          </button>
        </form>
      )}
    </Section>
  );
}

function Section({ icon, title, text, children }: { icon: ReactNode; title: string; text: string; children: ReactNode }) {
  return (
    <section className="space-y-3">
      <div>
        <h3 className="flex items-center gap-2 text-sm font-semibold">
          <span className="text-accent">{icon}</span> {title}
        </h3>
        <p className="mt-1 text-xs text-ink-400">{text}</p>
      </div>
      {children}
    </section>
  );
}

function Row({ label, sub, icon, children }: { label: string; sub?: string; icon?: ReactNode; children?: ReactNode }) {
  return (
    <div className="flex items-center gap-3 rounded-lg bg-ink-900 px-3 py-2.5">
      {icon && <span className="text-ink-300">{icon}</span>}
      <div className="min-w-0 flex-1">
        <p className="truncate text-sm">{label}</p>
        {sub && <p className="truncate text-xs text-ink-400">{sub}</p>}
      </div>
      {children}
    </div>
  );
}

function IconButton({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <button className="icon-btn h-8 w-8 hover:text-red-300" onClick={onClick} aria-label={label} title={label}>
      <Trash2 className="h-4 w-4" />
    </button>
  );
}
