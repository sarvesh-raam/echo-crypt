import { Check, Copy, Eye, EyeOff, Sparkles } from 'lucide-react';
import { useState, type ReactNode } from 'react';
import { generatePassword, passwordStrength } from '../lib/password';

export function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
  return (
    <label className="block space-y-1.5">
      <span className="text-sm font-medium text-ink-300">
        {label} {hint && <span className="font-normal text-ink-400">({hint})</span>}
      </span>
      {children}
    </label>
  );
}

const STRENGTH = [
  { label: 'Too short', color: 'bg-red-500', width: 'w-1/4' },
  { label: 'Weak', color: 'bg-amber-500', width: 'w-2/4' },
  { label: 'Okay', color: 'bg-lime-500', width: 'w-3/4' },
  { label: 'Strong', color: 'bg-accent', width: 'w-full' },
] as const;

/** Password input with a show/hide toggle; in "new" mode also a generator and a strength bar. */
export function PasswordInput({
  label = 'Password',
  value,
  onChange,
  isNew = false,
  autoFocus = false,
}: {
  label?: string;
  value: string;
  onChange: (v: string) => void;
  isNew?: boolean;
  autoFocus?: boolean;
}) {
  const [visible, setVisible] = useState(false);
  const strength = STRENGTH[passwordStrength(value)];
  return (
    <div className="space-y-1.5">
      <Field label={label}>
        <div className="relative">
          <input
            className="input pr-10"
            type={visible ? 'text' : 'password'}
            value={value}
            onChange={(e) => onChange(e.target.value)}
            autoComplete={isNew ? 'new-password' : 'current-password'}
            minLength={isNew ? 10 : undefined}
            autoFocus={autoFocus}
            required
          />
          <button
            type="button"
            className="absolute top-1/2 right-2 -translate-y-1/2 rounded p-1 text-ink-400 hover:text-ink-100"
            onClick={() => setVisible((v) => !v)}
            aria-label={visible ? 'Hide password' : 'Show password'}
            title={visible ? 'Hide password' : 'Show password'}
          >
            {visible ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
          </button>
        </div>
      </Field>
      {isNew && (
        <div className="flex items-center gap-3">
          <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-ink-800" aria-hidden>
            {value && <div className={`h-full rounded-full transition-all ${strength.color} ${strength.width}`} />}
          </div>
          <span className="w-16 text-xs text-ink-400" aria-live="polite">
            {value ? strength.label : ''}
          </span>
          <button
            type="button"
            className="inline-flex items-center gap-1 text-xs font-medium text-accent hover:underline"
            onClick={() => {
              onChange(generatePassword());
              setVisible(true);
            }}
          >
            <Sparkles className="h-3.5 w-3.5" /> Generate
          </button>
        </div>
      )}
    </div>
  );
}

export function RememberDevice({ checked, onChange }: { checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="flex items-start gap-2.5 text-sm text-ink-300">
      <input
        type="checkbox"
        className="mt-0.5 h-4 w-4 accent-[var(--color-accent)]"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span>
        Remember this device
        <span className="block text-xs text-ink-400">Stay unlocked here for 7 days. Untick on shared computers.</span>
      </span>
    </label>
  );
}

export function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className="btn-ghost"
      onClick={() => {
        void navigator.clipboard.writeText(text).then(() => {
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        });
      }}
    >
      {done ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />} {done ? 'Copied' : label}
    </button>
  );
}

export function Divider({ children }: { children: ReactNode }) {
  return (
    <div className="flex items-center gap-3 text-xs text-ink-400">
      <span className="h-px flex-1 bg-ink-800" />
      {children}
      <span className="h-px flex-1 bg-ink-800" />
    </div>
  );
}

const GOOGLE_PATH =
  'M21.8 12.2c0-.7-.1-1.4-.2-2H12v3.8h5.5a4.7 4.7 0 0 1-2 3.1v2.6h3.3c1.9-1.8 3-4.4 3-7.5ZM12 22c2.7 0 5-.9 6.7-2.4l-3.3-2.6c-.9.6-2 1-3.4 1-2.6 0-4.8-1.8-5.6-4.1H3v2.6A10 10 0 0 0 12 22Zm-5.6-8.1a6 6 0 0 1 0-3.8V7.5H3a10 10 0 0 0 0 9l3.4-2.6ZM12 6c1.5 0 2.8.5 3.8 1.5l2.9-2.9A10 10 0 0 0 3 7.5l3.4 2.6C7.2 7.8 9.4 6 12 6Z';
const GITHUB_PATH =
  'M12 2a10 10 0 0 0-3.2 19.5c.5.1.7-.2.7-.5v-1.7c-2.8.6-3.4-1.3-3.4-1.3-.5-1.2-1.1-1.5-1.1-1.5-.9-.6.1-.6.1-.6 1 .1 1.5 1 1.5 1 .9 1.6 2.4 1.1 3 .9.1-.7.4-1.1.6-1.4-2.2-.2-4.6-1.1-4.6-5 0-1.1.4-2 1-2.7-.1-.3-.4-1.3.1-2.7 0 0 .8-.3 2.8 1a9.6 9.6 0 0 1 5 0c1.9-1.3 2.8-1 2.8-1 .5 1.4.2 2.4.1 2.7.6.7 1 1.6 1 2.7 0 3.9-2.4 4.8-4.6 5 .4.3.7.9.7 1.9V21c0 .3.2.6.7.5A10 10 0 0 0 12 2Z';

export function ProviderIcon({ provider }: { provider: 'google' | 'github' }) {
  return (
    <svg viewBox="0 0 24 24" className="h-4 w-4" aria-hidden fill="currentColor">
      <path d={provider === 'google' ? GOOGLE_PATH : GITHUB_PATH} />
    </svg>
  );
}
