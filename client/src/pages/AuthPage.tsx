import { KeyRound, Loader2, Lock, ServerOff, ShieldCheck } from 'lucide-react';
import { useState, type FormEvent } from 'react';
import { ErrorText } from '../components/ui';
import { useStore } from '../store';

const FEATURES = [
  { icon: Lock, title: 'Encrypted on your device', text: 'AES-256-GCM with a fresh key per message, wrapped for each member over ECDH P-256.' },
  { icon: ServerOff, title: 'The server only sees ciphertext', text: 'Your password and private keys never leave the browser unencrypted.' },
  { icon: ShieldCheck, title: 'Signed and verifiable', text: 'Every message is ECDSA-signed. Compare safety numbers to rule out a man in the middle.' },
];

export function AuthPage() {
  const locked = useStore((s) => s.phase === 'locked');
  const lockedUser = useStore((s) => s.me);
  const { login, register, logout } = useStore.getState();

  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [username, setUsername] = useState(lockedUser?.username ?? '');
  const [displayName, setDisplayName] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [step, setStep] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const isRegister = mode === 'register' && !locked;

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (isRegister) {
      if (!/^[a-zA-Z0-9_]{3,24}$/.test(username)) return setError('Username: 3–24 letters, digits or underscores.');
      if (password.length < 10) return setError('Use at least 10 characters. Your password protects your private keys.');
      if (password !== confirm) return setError('Passwords do not match.');
    }
    try {
      if (isRegister) await register(username.toLowerCase(), displayName.trim() || username, password, setStep);
      else await login(username.toLowerCase(), password, setStep);
    } catch (err) {
      setError(
        err instanceof Error && /unlock/i.test(err.message)
          ? 'Signed in, but your keys could not be unlocked with this password.'
          : err instanceof Error
            ? err.message
            : 'Something went wrong',
      );
      setStep(null);
    }
  }

  return (
    <div className="flex min-h-full flex-col lg:flex-row">
      <section className="hidden flex-1 flex-col justify-between bg-gradient-to-br from-ink-950 via-ink-900 to-emerald-950/40 p-12 lg:flex">
        <Brand />
        <div className="max-w-md space-y-8">
          <h1 className="text-4xl leading-tight font-semibold tracking-tight">
            Private conversations,
            <br />
            <span className="text-accent">not even we can read.</span>
          </h1>
          <ul className="space-y-6">
            {FEATURES.map(({ icon: Icon, title, text }) => (
              <li key={title} className="flex gap-4">
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-accent/10 text-accent">
                  <Icon className="h-5 w-5" />
                </div>
                <div>
                  <p className="font-medium">{title}</p>
                  <p className="mt-1 text-sm text-ink-400">{text}</p>
                </div>
              </li>
            ))}
          </ul>
        </div>
        <p className="text-xs text-ink-400">Open source · MIT licensed</p>
      </section>

      <main className="flex flex-1 items-center justify-center px-4 py-10 sm:px-6">
        <div className="w-full max-w-sm">
          <div className="mb-8 lg:hidden">
            <Brand />
          </div>
          <h2 className="text-2xl font-semibold tracking-tight">
            {locked ? 'Unlock your keys' : isRegister ? 'Create your account' : 'Welcome back'}
          </h2>
          <p className="mt-2 text-sm text-ink-400">
            {locked
              ? 'Your session is active, but this browser no longer holds your private keys. Enter your password to unlock them.'
              : isRegister
                ? 'Your keys are generated in this browser. If you forget your password, nobody can recover your messages.'
                : 'Your password unlocks your keys locally. It is never sent to the server.'}
          </p>

          {!locked && (
            <div className="mt-6 grid grid-cols-2 rounded-lg bg-ink-850 p-1 text-sm" role="tablist">
              {(['login', 'register'] as const).map((m) => (
                <button
                  key={m}
                  role="tab"
                  aria-selected={mode === m}
                  onClick={() => {
                    setMode(m);
                    setError(null);
                  }}
                  className={`rounded-md py-2 font-medium transition ${mode === m ? 'bg-ink-700 text-ink-100' : 'text-ink-400 hover:text-ink-100'}`}
                >
                  {m === 'login' ? 'Sign in' : 'Register'}
                </button>
              ))}
            </div>
          )}

          <form onSubmit={submit} className="mt-6 space-y-4">
            <Field label="Username">
              <input
                className="input"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
                autoCapitalize="none"
                spellCheck={false}
                disabled={locked}
                required
              />
            </Field>
            {isRegister && (
              <Field label="Display name" hint="optional">
                <input className="input" value={displayName} onChange={(e) => setDisplayName(e.target.value)} maxLength={48} />
              </Field>
            )}
            <Field label="Password">
              <input
                className="input"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete={isRegister ? 'new-password' : 'current-password'}
                required
                autoFocus={locked}
              />
            </Field>
            {isRegister && (
              <Field label="Confirm password">
                <input
                  className="input"
                  type="password"
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  autoComplete="new-password"
                  required
                />
              </Field>
            )}
            <ErrorText>{error}</ErrorText>
            <button className="btn-primary w-full" disabled={!!step}>
              {step ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" /> {step}
                </>
              ) : (
                <>
                  <KeyRound className="h-4 w-4" /> {locked ? 'Unlock' : isRegister ? 'Create account' : 'Sign in'}
                </>
              )}
            </button>
            {locked && (
              <button type="button" className="btn-ghost w-full" onClick={() => void logout()}>
                Use a different account
              </button>
            )}
          </form>
        </div>
      </main>
    </div>
  );
}

function Brand() {
  return (
    <div className="flex items-center gap-2.5">
      <img src="/favicon.svg" alt="" className="h-8 w-8" />
      <span className="text-lg font-semibold tracking-tight">EchoCrypt</span>
    </div>
  );
}

function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <label className="block space-y-1.5">
      <span className="text-sm font-medium text-ink-300">
        {label} {hint && <span className="font-normal text-ink-400">({hint})</span>}
      </span>
      {children}
    </label>
  );
}
