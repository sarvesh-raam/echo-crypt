import { ArrowLeft, ArrowRight, Fingerprint, KeyRound, LifeBuoy, Loader2, Lock, Mail, ServerOff, ShieldCheck, X } from 'lucide-react';
import { useEffect, useState, type FormEvent, type ReactNode } from 'react';
import { Divider, Field, PasswordInput, ProviderIcon, RememberDevice } from '../components/forms';
import { RecoveryCode } from '../components/SecurityDialog';
import { ErrorText } from '../components/ui';
import { api, oauthStartUrl, type OAuthProvider } from '../lib/api';
import { takeAuthError, takeSignup } from '../lib/flash';
import { passkeysSupported } from '../lib/passkey';
import type { Providers } from '../lib/types';
import { useStore, type NewAccount } from '../store';

const FEATURES = [
  { icon: Lock, title: 'Encrypted on your device', text: 'AES-256-GCM with a fresh key per message, wrapped for each member over ECDH P-256.' },
  { icon: ServerOff, title: 'The server only sees ciphertext', text: 'Your password and private keys never leave the browser unencrypted.' },
  { icon: ShieldCheck, title: 'Signed and verifiable', text: 'Every message is ECDSA-signed. Compare safety numbers to rule out a man in the middle.' },
];

/** "setup" follows account creation: save the recovery key (and fix a failed passkey). */
type View = 'login' | 'register' | 'recover' | 'email' | 'setup';

const PROVIDER_LABEL: Record<OAuthProvider, string> = { google: 'Google', github: 'GitHub' };

interface Pending {
  provider: OAuthProvider;
  label: string;
}

export function AuthPage() {
  const locked = useStore((s) => s.phase === 'locked');
  const lockedUser = useStore((s) => s.me);
  const { login, createAccount, startDemo, loginWithPasskey, recover, emailLogin, logout } = useStore.getState();

  const [view, setView] = useState<View>('login');
  const [providers, setProviders] = useState<Providers>({ google: false, github: false, email: false });
  const [username, setUsername] = useState(lockedUser?.username ?? '');
  const [displayName, setDisplayName] = useState('');
  const [password, setPassword] = useState('');
  const [recoveryCode, setRecoveryCode] = useState('');
  const [email, setEmail] = useState('');
  const [emailCode, setEmailCode] = useState('');
  const [codeSent, setCodeSent] = useState(false);
  const [remember, setRemember] = useState(true);
  const [step, setStep] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(takeAuthError);
  const [notice, setNotice] = useState<string | null>(null);
  /** A Google/GitHub identity waiting for this sign-up form. */
  const [pending, setPending] = useState<Pending | null>(null);
  const [account, setAccount] = useState<NewAccount | null>(null);
  /** Why the passkey of a passkey sign-up could not be created (then a password is set instead). */
  const [passkeyFailed, setPasskeyFailed] = useState<string | null>(null);
  const [demo, setDemo] = useState(false);

  useEffect(() => {
    api.providers().then(setProviders, () => undefined);
    api.info().then((i) => setDemo(!!i.demoBotId), () => undefined);
    if (takeSignup()) {
      api.pendingSignup().then(
        (p) => {
          setPending({ provider: p.provider, label: p.label });
          setUsername(p.username);
          setDisplayName(p.displayName ?? '');
          setView('register');
        },
        () => setError('Sign-up with Google/GitHub expired. Please try again.'),
      );
    }
  }, []);

  const go = (v: View) => {
    setView(v);
    setError(null);
    setNotice(null);
    setPassword('');
  };

  /** Runs an action with the busy state and error display every form shares. */
  async function run(action: () => Promise<void>, busy = 'Working…') {
    setError(null);
    setStep(busy);
    try {
      await action();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Something went wrong');
    }
    setStep(null);
  }

  function signUp(withPasskey: boolean) {
    const name = username.trim().toLowerCase();
    if (!/^[a-z0-9_]{3,24}$/.test(name)) return setError('Username: 3–24 letters, digits or underscores.');
    if (!withPasskey && password.length < 10) {
      return setError('Use at least 10 characters. Your password protects your private keys.');
    }
    void run(async () => {
      const created = await createAccount({
        username: name,
        displayName: displayName.trim() || username.trim(),
        password: withPasskey ? null : password,
        remember,
        linkPending: !!pending,
        onStep: setStep,
      });
      setPending(null);
      setAccount(created);
      if (withPasskey) {
        setStep('Waiting for your passkey…');
        try {
          await created.addPasskey();
        } catch (err) {
          setPasskeyFailed(err instanceof Error ? err.message : 'The passkey could not be created.');
        }
      }
      go('setup');
    });
  }

  function submit(e: FormEvent) {
    e.preventDefault();
    const name = username.trim().toLowerCase();
    if (view === 'register') return signUp(false);
    if (view === 'setup' && account) {
      if (password.length < 10) return setError('Use at least 10 characters. Your password protects your private keys.');
      return void run(async () => {
        await account.setPassword(password);
        setPasskeyFailed(null);
        setPassword('');
      }, 'Saving password…');
    }
    if (view === 'recover') {
      if (password.length < 10) return setError('Use at least 10 characters for the new password.');
      return void run(() => recover(name, recoveryCode, password, remember, setStep));
    }
    if (view === 'email') {
      if (!codeSent) {
        return void run(async () => {
          await api.emailLoginStart(email.trim());
          setCodeSent(true);
          setNotice(`If ${email.trim()} belongs to an account, a 6-digit code is on its way.`);
        }, 'Sending code…');
      }
      return void run(() => emailLogin(email.trim(), emailCode), 'Signing in…');
    }
    void run(() => login(name, password, remember, setStep));
  }

  const busy = !!step;
  const canPasskey = passkeysSupported();
  const oauthProviders = (['google', 'github'] as const).filter((p) => providers[p]);
  const unlocking = locked && view === 'login';

  const heading = unlocking
    ? 'Unlock your keys'
    : view === 'setup'
      ? passkeyFailed
        ? 'Set a password instead'
        : 'Save your recovery key'
      : { login: 'Welcome back', register: 'Create your account', recover: 'Reset your password', email: 'Sign in with email' }[view];
  const intro = unlocking
    ? 'You are signed in, but this browser does not hold your private keys. Unlock them with your password, a passkey or your recovery key.'
    : view === 'setup'
      ? passkeyFailed
        ? `Your account is ready, but the passkey could not be added: ${passkeyFailed} Choose a password to protect your messages.`
        : 'If you ever lose your password or device, this key is the only way back into your messages. Nobody, including us, can recover them without it.'
      : view === 'register' && pending
        ? `${PROVIDER_LABEL[pending.provider]} confirmed who you are. Pick a username, then lock your messages with a passkey or a password. Only you can unlock them.`
        : {
            login: 'Your password unlocks your keys locally. It is never sent to the server.',
            register: 'Your keys are generated in this browser. Lock them with a passkey (fingerprint or face) or a password.',
            recover: 'Your recovery key unlocks your keys and lets you choose a new password. Your messages stay intact.',
            email: 'We email you a 6-digit code. On a new device you will then unlock your keys with your password or a passkey.',
          }[view];

  const submitLabel =
    view === 'email'
      ? codeSent
        ? 'Sign in'
        : 'Email me a code'
      : view === 'recover'
        ? 'Reset password'
        : view === 'setup'
          ? 'Save password'
          : view === 'register'
            ? 'Create account'
            : locked
              ? 'Unlock'
              : 'Sign in';

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
        <p className="text-xs text-ink-400">
          Open source · MIT licensed · <a href="/privacy" className="hover:text-ink-100">Privacy</a> ·{' '}
          <a href="/terms" className="hover:text-ink-100">Terms</a>
        </p>
      </section>

      <main className="flex flex-1 items-center justify-center px-4 py-10 sm:px-6">
        <div className="w-full max-w-sm">
          <div className="mb-8 lg:hidden">
            <Brand />
          </div>
          {(view === 'recover' || view === 'email') && (
            <BackLink onClick={() => go('login')}>{locked ? 'Back to unlock' : 'Back to sign in'}</BackLink>
          )}
          {demo && !locked && !pending && (view === 'login' || view === 'register') && (
            <button
              type="button"
              className="group mb-8 flex w-full items-center gap-3 rounded-xl border border-accent/30 bg-accent/5 px-4 py-3 text-left transition hover:border-accent/60 hover:bg-accent/10 disabled:opacity-60"
              disabled={busy}
              onClick={() => void run(() => startDemo(setStep), 'Creating a guest account…')}
            >
              <span className="min-w-0 flex-1">
                <span className="block text-sm font-semibold text-accent">Just looking? Try the live demo</span>
                <span className="block text-xs text-ink-400">No sign-up. A guest account and a bot that shows what the server stores.</span>
              </span>
              <ArrowRight className="h-4 w-4 shrink-0 text-accent transition group-hover:translate-x-0.5" />
            </button>
          )}
          <h2 className="text-2xl font-semibold tracking-tight">{heading}</h2>
          <p className="mt-2 text-sm text-ink-400">{intro}</p>

          {!locked && !pending && (view === 'login' || view === 'register') && (
            <div className="mt-6 grid grid-cols-2 rounded-lg bg-ink-850 p-1 text-sm" role="tablist">
              {(['login', 'register'] as const).map((m) => (
                <button
                  key={m}
                  role="tab"
                  aria-selected={view === m}
                  onClick={() => go(m)}
                  className={`rounded-md py-2 font-medium transition ${view === m ? 'bg-ink-700 text-ink-100' : 'text-ink-400 hover:text-ink-100'}`}
                >
                  {m === 'login' ? 'Sign in' : 'Register'}
                </button>
              ))}
            </div>
          )}

          {view === 'register' && pending && (
            <div className="mt-6 flex items-center gap-3 rounded-lg border border-ink-700 bg-ink-900 px-3 py-2.5 text-sm">
              <ProviderIcon provider={pending.provider} />
              <span className="min-w-0 flex-1 truncate">
                Signing up with {PROVIDER_LABEL[pending.provider]} · <span className="text-ink-400">{pending.label}</span>
              </span>
              <button
                type="button"
                className="rounded p-1 text-ink-400 hover:text-ink-100"
                aria-label="Cancel and sign up another way"
                title="Cancel"
                onClick={() => {
                  void api.cancelSignup().catch(() => undefined);
                  setPending(null);
                }}
              >
                <X className="h-4 w-4" />
              </button>
            </div>
          )}

          {view === 'setup' && account && !passkeyFailed ? (
            <div className="mt-6 space-y-4">
              <RecoveryCode code={account.recoveryCode} username={account.user.username} replacing={false} onDone={() => void run(account.finish, 'Opening EchoCrypt…')} />
              <ErrorText>{error}</ErrorText>
            </div>
          ) : (
            <form onSubmit={submit} className="mt-6 space-y-4">
              {view === 'email' ? (
                <>
                  <Field label="Email">
                    <input
                      className="input"
                      type="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      autoComplete="email"
                      disabled={codeSent}
                      required
                      autoFocus
                    />
                  </Field>
                  {codeSent && (
                    <Field label="6-digit code">
                      <input
                        className="input font-mono tracking-[0.4em]"
                        value={emailCode}
                        onChange={(e) => setEmailCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                        inputMode="numeric"
                        autoComplete="one-time-code"
                        required
                        autoFocus
                      />
                    </Field>
                  )}
                </>
              ) : view === 'setup' ? (
                <PasswordInput value={password} onChange={setPassword} isNew autoFocus />
              ) : (
                <>
                  <Field label="Username">
                    <input
                      className="input"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      autoComplete="username webauthn"
                      autoCapitalize="none"
                      spellCheck={false}
                      disabled={locked}
                      required
                    />
                  </Field>
                  {view === 'register' && (
                    <Field label="Display name" hint="optional">
                      <input className="input" value={displayName} onChange={(e) => setDisplayName(e.target.value)} maxLength={48} />
                    </Field>
                  )}
                  {view === 'register' && canPasskey && (
                    <>
                      <button type="button" className="btn-primary w-full" disabled={busy} onClick={() => signUp(true)}>
                        <Fingerprint className="h-4 w-4" /> Create account with a passkey
                      </button>
                      <p className="-mt-2 text-center text-xs text-ink-400">Fingerprint, face or device PIN. No password to remember.</p>
                      <Divider>or use a password</Divider>
                    </>
                  )}
                  {view === 'recover' && (
                    <Field label="Recovery key">
                      <input
                        className="input font-mono uppercase"
                        value={recoveryCode}
                        onChange={(e) => setRecoveryCode(e.target.value)}
                        placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"
                        autoCapitalize="characters"
                        spellCheck={false}
                        required
                      />
                    </Field>
                  )}
                  <PasswordInput
                    label={view === 'recover' ? 'New password' : 'Password'}
                    value={password}
                    onChange={setPassword}
                    isNew={view === 'register' || view === 'recover'}
                    autoFocus={locked && view === 'login'}
                  />
                  {view === 'login' && (
                    <div className="-mt-2 text-right">
                      <button type="button" className="text-xs text-ink-400 hover:text-accent" onClick={() => go('recover')}>
                        Forgot password?
                      </button>
                    </div>
                  )}
                  <RememberDevice checked={remember} onChange={setRemember} />
                </>
              )}

              {notice && <p className="text-sm text-accent">{notice}</p>}
              <ErrorText>{error}</ErrorText>

              <button
                key={view}
                className={view === 'register' && canPasskey ? 'btn-ghost w-full border border-ink-700' : 'btn-primary w-full'}
                disabled={busy}
              >
                {busy ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" /> {step}
                  </>
                ) : (
                  <>
                    <KeyRound className="h-4 w-4" /> {submitLabel}
                  </>
                )}
              </button>
            </form>
          )}

          {view === 'register' && (
            <p className="mt-4 text-center text-xs text-ink-400">
              By creating an account you agree to the{' '}
              <a href="/terms" className="text-accent hover:underline">
                Terms
              </a>{' '}
              and{' '}
              <a href="/privacy" className="text-accent hover:underline">
                Privacy Policy
              </a>
              .
            </p>
          )}

          {!locked && !pending && (view === 'login' || view === 'register') && oauthProviders.length > 0 && (
            <div className="mt-6 space-y-3">
              <Divider>{view === 'register' ? 'or sign up with' : 'or continue with'}</Divider>
              <div className="grid grid-cols-2 gap-3">
                {oauthProviders.map((p) => (
                  <a key={p} href={oauthStartUrl(p, 'login')} className={`btn-ghost border border-ink-700 ${oauthProviders.length === 1 ? 'col-span-2' : ''}`}>
                    <ProviderIcon provider={p} /> {view === 'register' ? `Continue with ${PROVIDER_LABEL[p]}` : PROVIDER_LABEL[p]}
                  </a>
                ))}
              </div>
            </div>
          )}

          {view === 'login' && (
            <div className="mt-3 space-y-3">
              {(locked || oauthProviders.length === 0) && <Divider>{locked ? 'or unlock with' : 'or'}</Divider>}
              {canPasskey && (
                <button
                  type="button"
                  className="btn-ghost w-full border border-ink-700"
                  disabled={busy}
                  onClick={() => void run(() => loginWithPasskey(remember, setStep))}
                >
                  <Fingerprint className="h-4 w-4" /> {locked ? 'Unlock with a passkey' : 'Sign in with a passkey'}
                </button>
              )}
              {!locked && providers.email && (
                <button type="button" className="btn-ghost w-full border border-ink-700" onClick={() => go('email')}>
                  <Mail className="h-4 w-4" /> Email me a code
                </button>
              )}
              {locked && (
                <>
                  <button type="button" className="btn-ghost w-full border border-ink-700" onClick={() => go('recover')}>
                    <LifeBuoy className="h-4 w-4" /> Use my recovery key
                  </button>
                  <button type="button" className="btn-ghost w-full" onClick={() => void logout()}>
                    Use a different account
                  </button>
                </>
              )}
              {!locked && (oauthProviders.length > 0 || providers.email) && (
                <p className="text-center text-xs text-ink-400">
                  Google, GitHub and email sign you in. On a new device you then unlock your messages with your password or a passkey.
                </p>
              )}
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

function BackLink({ onClick, children }: { onClick: () => void; children: ReactNode }) {
  return (
    <button type="button" onClick={onClick} className="mb-4 inline-flex items-center gap-1.5 text-sm text-ink-400 hover:text-ink-100">
      <ArrowLeft className="h-4 w-4" /> {children}
    </button>
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
