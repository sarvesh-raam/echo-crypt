/**
 * Messages the server passes back in the URL after a full-page redirect (Google/GitHub
 * sign-in). Read once at startup, then removed from the address bar.
 */
const params = new URLSearchParams(window.location.search);

export const flash = {
  error: params.get('auth_error'),
  notice: params.get('notice'),
  openSecurity: params.get('settings') === 'security',
  /** Set after "Continue with Google/GitHub" for someone who has no account yet. */
  signup: params.get('signup'),
};

if (['auth_error', 'notice', 'settings', 'signup'].some((k) => params.has(k))) {
  window.history.replaceState(null, '', window.location.pathname);
}

/** The sign-in error, once (so it does not reappear after signing out later). */
export function takeAuthError(): string | null {
  const e = flash.openSecurity ? null : flash.error;
  if (!flash.openSecurity) flash.error = null;
  return e;
}

/** What the Security dialog should open with after a link attempt, once. */
export function takeSecurityFlash(): { notice: string | null; error: string | null } | null {
  if (!flash.openSecurity) return null;
  flash.openSecurity = false;
  const out = { notice: flash.notice, error: flash.error };
  flash.notice = flash.error = null;
  return out;
}

/** True once if the page opened to finish a Google/GitHub sign-up. */
export function takeSignup(): boolean {
  const pending = !!flash.signup;
  flash.signup = null;
  return pending;
}
