/**
 * End-to-end browser test against a running stack:
 *
 *   docker compose up -d --build
 *   cd e2e && npm install && npx playwright install chromium && npm test
 *
 * Drives several real browsers (separate contexts = separate devices) through
 * registration, direct and group chat, typing, safety numbers, reloads, signing
 * in on a new device, recovery keys, passkeys (Chrome's virtual authenticator with
 * PRF) and a simulated server-side key swap.
 */
import { execFileSync } from 'node:child_process';
import { chromium } from 'playwright';

const BASE = process.env.BASE_URL ?? 'http://localhost:8090';
const MONGO_CONTAINER = process.env.MONGO_CONTAINER ?? 'echocrypt-mongo-1';
const PASSWORD = 'correct horse battery';
const tag = Date.now().toString(36).slice(-5);
const errors = [];
const browser = await chromium.launch();

const step = (s) => console.log(`  ✓ ${s}`);

async function device(label) {
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 800 } });
  const page = await ctx.newPage();
  page.on('pageerror', (e) => errors.push(`${label}: ${e.message}`));
  page.on('console', (m) => {
    // The 401 from /api/auth/me before signing in is expected.
    if (m.type() === 'error' && !m.text().includes('401')) errors.push(`${label}: ${m.text()}`);
  });
  await page.goto(BASE);
  return page;
}

async function register(name, display) {
  const page = await device(name);
  await page.getByRole('tab', { name: 'Register' }).click();
  await page.getByLabel('Username').fill(`${name}_${tag}`);
  await page.getByLabel('Display name').fill(display);
  await page.getByLabel('Password', { exact: true }).fill(PASSWORD);
  await page.getByRole('button', { name: 'Create account' }).click();
  await page.getByText('Connected').waitFor({ timeout: 30_000 });
  return page;
}

async function send(page, text) {
  await page.getByLabel('Message').fill(text);
  await page.getByLabel('Message').press('Enter');
  await page.getByText(text).waitFor();
}

async function safetyDigits(page) {
  await page.getByTitle(/End-to-end encrypted/).click();
  const cell = page.getByRole('dialog').locator('.grid span');
  await cell.first().waitFor();
  return (await cell.allInnerTexts()).join('');
}

try {
  const alice = await register('alice', 'Alice Liddell');
  const bob = await register('bob', 'Bob Builder');
  const carol = await register('carol', 'Carol Danvers');
  step('three accounts registered (keys generated in the browser)');

  await alice.getByRole('button', { name: 'New chat' }).click();
  await alice.getByLabel('Search by username').fill(`bob_${tag}`);
  await alice.getByRole('button', { name: /Bob Builder/ }).click();
  await alice.getByRole('button', { name: 'Start chat' }).click();
  await send(alice, 'Hey Bob, this is end-to-end encrypted 🔐');

  await bob.getByRole('button', { name: /Alice Liddell/ }).click();
  await bob.getByText('Hey Bob, this is end-to-end encrypted 🔐').waitFor({ timeout: 10_000 });
  step('direct message delivered live and decrypted');

  await bob.getByLabel('Message').pressSequentially('Hi Al', { delay: 30 });
  await alice.locator('.typing-dot').first().waitFor({ timeout: 5000 });
  step('typing indicator');

  await send(bob, 'Hi Alice! Works on my side too.');
  await alice.getByText('Hi Alice! Works on my side too.').waitFor({ timeout: 10_000 });
  step('reply delivered');

  const a = await safetyDigits(alice);
  const b = await safetyDigits(bob);
  if (a !== b || a.length !== 60) throw new Error(`safety numbers differ: ${a} / ${b}`);
  await alice.getByRole('button', { name: /mark as verified/ }).click();
  await alice.keyboard.press('Escape');
  await bob.keyboard.press('Escape');
  step('safety numbers match on both devices');

  await alice.getByRole('button', { name: 'New chat' }).click();
  for (const [username, display] of [[`bob_${tag}`, /Bob Builder/], [`carol_${tag}`, /Carol Danvers/]]) {
    await alice.getByLabel('Search by username').fill(username);
    await alice.getByRole('listitem').getByRole('button', { name: display }).click();
  }
  await alice.getByPlaceholder('Group name').fill('Launch crew');
  await alice.getByRole('button', { name: 'Create group' }).click();
  await alice.locator('header p.font-semibold', { hasText: 'Launch crew' }).waitFor();
  await send(alice, 'Group message for both of you');
  await carol.getByRole('button', { name: /Launch crew/ }).click();
  await carol.getByText('Group message for both of you').waitFor({ timeout: 10_000 });
  step('group message decrypted by every member');

  await bob.reload();
  await bob.getByText('Connected').waitFor({ timeout: 15_000 });
  await bob.getByRole('button', { name: /Alice Liddell/ }).click();
  await bob.getByText('Hey Bob, this is end-to-end encrypted 🔐').waitFor({ timeout: 10_000 });
  step('reload keeps the session; history decrypts');

  const laptop = await device('bob-laptop');
  await laptop.getByLabel('Username').fill(`bob_${tag}`);
  await laptop.getByLabel('Password', { exact: true }).fill(PASSWORD);
  await laptop.getByRole('button', { name: 'Sign in', exact: true }).click();
  await laptop.getByText('Connected').waitFor({ timeout: 30_000 });
  await laptop.getByRole('button', { name: /Alice Liddell/ }).click();
  await laptop.getByText('Hi Alice! Works on my side too.').waitFor({ timeout: 10_000 });
  step('sign-in on a new device unlocks keys; history decrypts');

  const eve = await device('eve');
  await eve.getByLabel('Username').fill(`bob_${tag}`);
  await eve.getByLabel('Password', { exact: true }).fill('not the password');
  await eve.getByRole('button', { name: 'Sign in', exact: true }).click();
  await eve.getByText('Wrong username or password').waitFor({ timeout: 30_000 });
  step('wrong password rejected');

  await carol.getByRole('button', { name: 'Security' }).click();
  await carol.getByRole('button', { name: 'Create recovery key' }).click();
  const code = (await carol.getByTestId('recovery-code').innerText()).trim();
  await carol.getByRole('button', { name: 'I saved it' }).click();
  await carol.getByText('Recovery key is set').waitFor();
  await carol.keyboard.press('Escape');
  const carolPhone = await device('carol-phone');
  await carolPhone.getByRole('button', { name: 'Forgot password?' }).click();
  await carolPhone.getByLabel('Username').fill(`carol_${tag}`);
  await carolPhone.getByLabel('Recovery key').fill(code.toLowerCase());
  await carolPhone.getByLabel('New password').fill('a whole new password');
  await carolPhone.getByRole('button', { name: 'Reset password' }).click();
  await carolPhone.getByText('Connected').waitFor({ timeout: 30_000 });
  await carolPhone.getByRole('button', { name: /Launch crew/ }).click();
  await carolPhone.getByText('Group message for both of you').waitFor({ timeout: 10_000 });
  step('forgotten password reset with the recovery key; history still decrypts');

  const dave = await register('dave', 'Dave Grohl');
  const cdp = await dave.context().newCDPSession(dave);
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
  await dave.getByRole('button', { name: 'Security' }).click();
  await dave.getByRole('button', { name: 'Add a passkey on this device' }).click();
  await dave.getByText('Passkey added').waitFor({ timeout: 15_000 });
  await dave.keyboard.press('Escape');
  await dave.getByRole('button', { name: 'Sign out' }).click();
  await dave.getByRole('button', { name: 'Sign in with a passkey' }).click();
  await dave.getByText('Connected').waitFor({ timeout: 30_000 });
  step('passkey added, then used to sign in and unlock without a password');

  // A malicious server swaps Bob's public keys for Carol's.
  execFileSync('docker', [
    'exec', MONGO_CONTAINER, 'mongosh', 'echocrypt', '--quiet', '--eval',
    `const c = db.users.findOne({ username: 'carol_${tag}' }); db.users.updateOne({ username: 'bob_${tag}' }, { $set: { publicKeys: c.publicKeys } })`,
  ]);
  await alice.reload();
  await alice.getByText('Connected').waitFor({ timeout: 15_000 });
  await alice.getByRole('button', { name: /Bob Builder/ }).click();
  await alice.getByText(/safety number for .* changed/i).waitFor({ timeout: 10_000 });
  if (!(await alice.getByLabel('Message').isDisabled())) throw new Error('composer should be locked after a key change');
  step('server-side key swap detected; sending blocked');

  if (errors.length) throw new Error(`browser errors:\n${errors.join('\n')}`);
  console.log('\nAll UI checks passed.');
} finally {
  await browser.close();
}
