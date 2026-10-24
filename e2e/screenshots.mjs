/**
 * Regenerates the README screenshots from a running stack:
 *
 *   docker compose up -d --build
 *   cd e2e && node screenshots.mjs
 */
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const BASE = process.env.BASE_URL ?? 'http://localhost:8090';
const MONGO_CONTAINER = process.env.MONGO_CONTAINER ?? 'echocrypt-mongo-1';
const OUT = fileURLToPath(new URL('../docs/screenshots/', import.meta.url));
const PASSWORD = 'correct horse battery';
const tag = Date.now().toString(36).slice(-4);
const browser = await chromium.launch();

async function device(viewport = { width: 1280, height: 800 }) {
  const ctx = await browser.newContext({ viewport, deviceScaleFactor: 1, colorScheme: 'dark' });
  const page = await ctx.newPage();
  await page.goto(BASE);
  return page;
}

async function withPasskeys(page) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      ctap2Version: 'ctap2_1',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      hasPrf: true,
      automaticPresenceSimulation: true,
    },
  });
}

async function register(page, name, display) {
  await page.getByRole('tab', { name: 'Register' }).click();
  await page.getByLabel('Username').fill(`${name}_${tag}`);
  await page.getByLabel('Display name').fill(display);
  await page.getByLabel('Password', { exact: true }).fill(PASSWORD);
  await page.getByRole('button', { name: 'Create account', exact: true }).click();
  await page.getByRole('button', { name: 'I saved it' }).click();
  await page.getByText('Connected').waitFor({ timeout: 30_000 });
}

async function send(page, text) {
  await page.getByLabel('Message').fill(text);
  await page.getByLabel('Message').press('Enter');
  await page.getByText(text).waitFor();
}

const shot = (page, name) => page.screenshot({ path: `${OUT}${name}.png` });

try {
  const signIn = await device();
  await signIn.getByText('Welcome back').waitFor();
  await shot(signIn, 'sign-in');

  const alice = await device();
  await withPasskeys(alice);
  await register(alice, 'alice', 'Alice Liddell');
  const bob = await device();
  await register(bob, 'bob', 'Bob Builder');

  await alice.getByRole('button', { name: 'New chat' }).click();
  await alice.getByLabel('Search by username').fill(`bob_${tag}`);
  await alice.getByRole('button', { name: /Bob Builder/ }).click();
  await alice.getByRole('button', { name: 'Start chat' }).click();
  await send(alice, 'Hey Bob! Did the deploy go through?');
  await bob.getByRole('button', { name: /Alice Liddell/ }).click();
  await send(bob, 'Yes, both instances are up behind nginx 🚀');
  await send(alice, 'Nice. And the database only has ciphertext?');
  await send(bob, 'Only ciphertext. Even I can’t read it on the server 🔐');
  await alice.getByText('Only ciphertext. Even I can’t read it on the server 🔐').waitFor();
  await bob.getByLabel('Message').pressSequentially('Want to compare safety numb', { delay: 20 });
  await alice.locator('.typing-dot').first().waitFor();
  await shot(alice, 'chat');

  await alice.getByTitle(/End-to-end encrypted/).click();
  await alice.getByRole('dialog').locator('.grid span').first().waitFor();
  await shot(alice, 'safety-number');
  await alice.keyboard.press('Escape');

  await alice.getByRole('button', { name: 'Security' }).click();
  await alice.getByRole('button', { name: 'Add a passkey on this device' }).click();
  await alice.getByText('Passkey added').waitFor({ timeout: 15_000 });
  await shot(alice, 'security');
  await alice.keyboard.press('Escape');

  const visitor = await device();
  await visitor.getByRole('button', { name: /Try the live demo/ }).click();
  await visitor.getByText(/I’m the EchoCrypt demo bot/).waitFor({ timeout: 30_000 });
  await send(visitor, 'Can the server read this?');
  await visitor.getByText(/Decrypted on my side/).waitFor({ timeout: 15_000 });
  await visitor.waitForTimeout(300);
  await shot(visitor, 'demo-bot');

  const phone = await device({ width: 390, height: 844 });
  await phone.getByLabel('Username').fill(`bob_${tag}`);
  await phone.getByLabel('Password', { exact: true }).fill(PASSWORD);
  await phone.getByRole('button', { name: 'Sign in', exact: true }).click();
  await phone.getByText('Connected').waitFor({ timeout: 30_000 });
  await phone.getByRole('button', { name: /Alice Liddell/ }).click();
  await phone.getByText('Hey Bob! Did the deploy go through?').waitFor();
  await shot(phone, 'mobile');

  // A malicious server swaps Bob's keys: Alice is warned and cannot send.
  const mallory = await device();
  await register(mallory, 'mallory', 'Mallory');
  execFileSync('docker', [
    'exec', MONGO_CONTAINER, 'mongosh', 'echocrypt', '--quiet', '--eval',
    `const m = db.users.findOne({ username: 'mallory_${tag}' }); db.users.updateOne({ username: 'bob_${tag}' }, { $set: { publicKeys: m.publicKeys } })`,
  ]);
  await alice.reload();
  await alice.getByText('Connected').waitFor({ timeout: 15_000 });
  await alice.getByRole('button', { name: /Bob Builder/ }).click();
  await alice.getByText(/safety number for .* changed/i).waitFor({ timeout: 10_000 });
  await alice.getByText('Hey Bob! Did the deploy go through?').waitFor({ timeout: 10_000 });
  await alice.waitForTimeout(300);
  await shot(alice, 'key-change-warning');

  console.log(`Screenshots written to ${OUT}`);
} finally {
  await browser.close();
}
