import { config } from '../config.js';
import { logger } from '../logger.js';

export interface Mailer {
  send(to: string, subject: string, text: string): Promise<void>;
}

/** Brevo's transactional email API. Plain HTTPS, so it also works where outbound SMTP is blocked. */
function brevoMailer(apiKey: string, from: string): Mailer {
  return {
    async send(to, subject, text) {
      const res = await fetch('https://api.brevo.com/v3/smtp/email', {
        method: 'POST',
        headers: { 'api-key': apiKey, 'content-type': 'application/json', accept: 'application/json' },
        body: JSON.stringify({ sender: { email: from, name: 'EchoCrypt' }, to: [{ email: to }], subject, textContent: text }),
      });
      if (!res.ok) throw new Error(`Brevo responded ${res.status}: ${await res.text()}`);
    },
  };
}

/** Local development without an email account: the code shows up in the server log. */
const logMailer: Mailer = {
  async send(to, subject, text) {
    logger.warn({ to, subject, text }, 'email not sent (no BREVO_API_KEY); logged for development');
  },
};

export function mailerFromConfig(): Mailer | null {
  if (config.BREVO_API_KEY && config.MAIL_FROM) return brevoMailer(config.BREVO_API_KEY, config.MAIL_FROM);
  return config.NODE_ENV === 'development' ? logMailer : null;
}
