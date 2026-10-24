import { ArrowLeft } from 'lucide-react';
import { useEffect, useState, type ReactNode } from 'react';

const UPDATED = '24 October 2026';
const REPO = 'https://github.com/sarvesh-raam/echo-crypt';

/** Privacy policy and terms. Plain routes (/privacy, /terms) so OAuth providers can link to them. */
export function LegalPage({ page }: { page: 'privacy' | 'terms' }) {
  const [contact, setContact] = useState<string | null>(null);

  useEffect(() => {
    document.title = page === 'privacy' ? 'Privacy Policy · EchoCrypt' : 'Terms of Service · EchoCrypt';
    fetch('/api/info')
      .then((r) => r.json())
      .then((d: { contactEmail: string | null }) => setContact(d.contactEmail))
      .catch(() => undefined);
  }, [page]);

  const reach = contact ? (
    <a href={`mailto:${contact}`}>{contact}</a>
  ) : (
    <>
      an issue on <a href={`${REPO}/issues`}>GitHub</a>
    </>
  );

  return (
    <div className="min-h-full bg-ink-950 px-4 py-10 sm:px-6">
      <article className="legal mx-auto max-w-2xl">
        <a href="/" className="mb-8 inline-flex items-center gap-1.5 text-sm text-ink-400 no-underline hover:text-ink-100">
          <ArrowLeft className="h-4 w-4" /> Back to EchoCrypt
        </a>
        {page === 'privacy' ? <Privacy reach={reach} /> : <Terms reach={reach} />}
        <p className="mt-10 text-xs text-ink-400">
          Last updated {UPDATED}. {page === 'privacy' ? <a href="/terms">Terms of Service</a> : <a href="/privacy">Privacy Policy</a>}
        </p>
      </article>
    </div>
  );
}

function Privacy({ reach }: { reach: ReactNode }) {
  return (
    <>
      <h1>Privacy Policy</h1>
      <p>
        EchoCrypt is an end-to-end encrypted chat app. Messages are encrypted on your device before they are sent, and
        only the members of a conversation hold the keys. We cannot read your messages, and this policy explains the
        little we can see.
      </p>

      <h2>What we store</h2>
      <ul>
        <li>
          <strong>Account:</strong> your username and display name, your public keys, and your private keys in encrypted
          form. We cannot decrypt them.
        </li>
        <li>
          <strong>Sign-in data:</strong> a hash of a value derived from your password (never the password itself), and the
          same kind of hash for your recovery key if you create one. For each passkey: its public key, a name such as
          &ldquo;Chrome on Windows&rdquo;, and when it was added and last used.
        </li>
        <li>
          <strong>Optional sign-in methods:</strong> if you link Google or GitHub, we store that account&rsquo;s id and your
          email address (Google) or username (GitHub). If you add an email for sign-in codes, we store that address.
        </li>
        <li>
          <strong>Messages:</strong> encrypted messages, who sent them, which conversation they belong to and when. Their
          content is unreadable to us. Group names are stored readable.
        </li>
        <li>
          <strong>Conversations:</strong> who is a member of which conversation.
        </li>
      </ul>

      <h2>What we see while you use the app</h2>
      <ul>
        <li>Your IP address, used for rate limiting and kept briefly in server logs.</li>
        <li>Whether you are online, and when you are typing. This is not stored.</li>
      </ul>

      <h2>What we never see</h2>
      <p>
        Message contents, your password, your recovery key, or your private keys. Your browser keeps your keys in a form
        that even its own scripts cannot read out.
      </p>

      <h2>Cookies and local storage</h2>
      <p>
        One sign-in cookie, valid for 7 days, and a short-lived cookie during Google or GitHub sign-in. Your browser also
        stores your keys and the safety numbers of your contacts locally. There are no ads, no analytics and no tracking
        cookies.
      </p>

      <h2>Who processes data for us</h2>
      <ul>
        <li>Render (hosting and temporary data such as presence and rate-limit counters)</li>
        <li>MongoDB Atlas (database)</li>
        <li>Brevo (only if you use email sign-in codes, to send the email)</li>
        <li>Google and GitHub (only if you choose to sign in with them)</li>
      </ul>
      <p>We do not sell or share your data with anyone else, and we never use it for advertising.</p>

      <h2>Your choices</h2>
      <p>
        You can remove passkeys, your recovery key, your sign-in email and linked accounts at any time under Security.
        To delete your account, or to get a copy of the data we hold about you, contact {reach}. We delete account data
        within 30 days of a verified request.
      </p>

      <h2>Children</h2>
      <p>EchoCrypt is not meant for children under 13.</p>

      <h2>Changes</h2>
      <p>If this policy changes, we update this page and the date below.</p>
    </>
  );
}

function Terms({ reach }: { reach: ReactNode }) {
  return (
    <>
      <h1>Terms of Service</h1>
      <p>By creating an account or using EchoCrypt you agree to these terms.</p>

      <h2>Your account</h2>
      <ul>
        <li>Keep your password and recovery key safe. You are responsible for activity on your account.</li>
        <li>
          Because your messages are end-to-end encrypted, <strong>we cannot recover them</strong>. If you lose your
          password, every passkey and your recovery key, your message history is gone for good.
        </li>
      </ul>

      <h2>Acceptable use</h2>
      <p>
        Do not use EchoCrypt to break the law, to harass, threaten or spam others, to share content that exploits
        children, or to attack or overload the service. We may suspend accounts that do.
      </p>

      <h2>The service</h2>
      <p>
        EchoCrypt is provided free of charge and &ldquo;as is&rdquo;, without warranties of any kind. It may be
        unavailable at times, and features may change. It has not been independently security-audited. Do not rely on it
        where your safety depends on it.
      </p>

      <h2>Liability</h2>
      <p>To the extent the law allows, we are not liable for any loss arising from your use of the service.</p>

      <h2>Open source</h2>
      <p>
        The code is available under the MIT license at <a href={REPO}>github.com/sarvesh-raam/echo-crypt</a>.
      </p>

      <h2>Contact</h2>
      <p>Questions about these terms: {reach}.</p>
    </>
  );
}
