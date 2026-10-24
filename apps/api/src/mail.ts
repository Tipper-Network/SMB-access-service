import type { AccessConfig } from './config.js';

export type SendMailInput = {
  to: string;
  subject: string;
  text: string;
};

/**
 * Sends mail via Resend when configured. Returns false when mail is disabled (dev/tests).
 */
export async function sendAccessMail(config: AccessConfig, input: SendMailInput): Promise<boolean> {
  if (!config.resendApiKey || !config.mailFrom) {
    if (process.env.NODE_ENV !== 'test') {
      console.info('[access] mail skipped (RESEND not configured)', { to: input.to, subject: input.subject });
    }
    return false;
  }

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${config.resendApiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: config.mailFrom,
      to: [input.to],
      subject: input.subject,
      text: input.text,
    }),
  });

  if (!res.ok) {
    const body = await res.text().catch(() => '');
    console.error('[access] resend failed', res.status, body.slice(0, 200));
    return false;
  }

  return true;
}
