// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// End-to-end smoke test of a fresh Central instance in a real browser:
// setup wizard → owner → sign-in → TOTP enrollment → dashboard, then simulated agents and
// screenshots of the fleet dashboard and a host overview (light and dark).
//
//   CENTRAL_URL=http://localhost:18080 CENTRAL_DATA_DIR=./data CENTRAL_SIM=./central-sim \
//   CENTRAL_AGENT_URL=https://localhost:19443 OUT_DIR=./shots node e2e/smoke.mjs
//
// Fails on page errors and on Content-Security-Policy / Trusted Types violations.
import { spawn } from 'node:child_process';
import { createHmac } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { chromium } from 'playwright-core';

const URL = process.env.CENTRAL_URL ?? 'http://localhost:18080';
const DATA = process.env.CENTRAL_DATA_DIR ?? './data';
const OUT = process.env.OUT_DIR ?? './shots';
const SIM = process.env.CENTRAL_SIM ?? '';
const AGENT_URL = process.env.CENTRAL_AGENT_URL ?? 'https://localhost:19443';
const AGENTS = Number(process.env.SIM_AGENTS ?? 40);
const WAIT_METRICS_S = Number(process.env.WAIT_METRICS_S ?? 20);
const BACKFILL = process.env.SIM_BACKFILL ?? '1h';
mkdirSync(OUT, { recursive: true });

function base32(s) {
  const a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of s.replace(/=+$/, '').toUpperCase())
    bits += a.indexOf(c).toString(2).padStart(5, '0');
  const out = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(out);
}

function totp(secret, t = Date.now()) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(Math.floor(t / 30000)));
  const h = createHmac('sha1', base32(secret)).update(buf).digest();
  const o = h[19] & 0xf;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1e6).padStart(6, '0');
}

const problems = [];
const browser = await chromium.launch();
const ctx = await browser.newContext({
  viewport: { width: 1440, height: 900 },
  colorScheme: 'light',
  locale: 'en-US',
  timezoneId: 'UTC',
});
const page = await ctx.newPage();
page.on('pageerror', (e) => problems.push(`page error: ${e.message}`));
page.on('console', (m) => {
  const t = m.text();
  if (
    m.type() === 'error' &&
    /Content Security Policy|Trusted Type|TrustedHTML|TrustedScript/i.test(t)
  )
    problems.push(`CSP: ${t}`);
  if (m.type() === 'error') console.log('console error:', t.slice(0, 300));
});
const step = async (name, fn) => {
  process.stdout.write(`• ${name}… `);
  await fn();
  console.log('ok');
};
const shot = (name) => page.screenshot({ path: join(OUT, `${name}.png`) });

await step('setup wizard redirect', async () => {
  await page.goto(URL);
  await page.waitForURL('**/setup');
  await shot('01-setup-token');
});
await step('setup token', async () => {
  await page.getByLabel('Setup token').fill(readFileSync(join(DATA, 'setup-token'), 'utf8').trim());
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByLabel('Agent address').waitFor();
});
await step('endpoints', async () => {
  await page.getByLabel('Agent address').fill(AGENT_URL);
  await shot('02-setup-endpoints');
  await page.getByRole('button', { name: 'Save and continue' }).click();
  await page.getByLabel('Your name').waitFor();
});
const password = 'amber-harbor-lantern-2026';
await step('owner account', async () => {
  await page.getByLabel('Your name').fill('Alex Admin');
  await page.getByLabel('Organization').fill('Acme Infrastructure');
  await page.getByLabel('Email').fill('alex@acme.example');
  await page.getByLabel('Password', { exact: true }).fill(password);
  await page.getByLabel('Confirm password').fill(password);
  await shot('03-setup-owner');
  await page.getByRole('button', { name: 'Create owner' }).click();
  await page.getByRole('heading', { name: 'Central is ready' }).waitFor();
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.waitForURL('**/login**');
});
await step('sign in', async () => {
  await page.getByLabel('Password').fill(password);
  await shot('04-login');
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await page.waitForURL('**/mfa**');
});
await step('TOTP enrollment', async () => {
  await page.getByRole('button', { name: /Authenticator app/ }).click();
  const secret = (await page.locator('.secret code').innerText()).replace(/\s+/g, '');
  await shot('05-mfa-totp');
  await page.getByLabel('6-digit code').fill(totp(secret));
  await page.getByRole('button', { name: 'Confirm' }).click();
  await page.getByText('Save these recovery codes').waitFor();
  await page.getByRole('button', { name: /I saved them/ }).click();
  await page.waitForURL(URL + '/');
  await page.getByRole('heading', { name: 'Fleet' }).waitFor();
  await shot('06-dashboard-empty');
});

// JSON Connect calls with the browser's session (CSRF token from GetSession).
const call = async (method, body) => {
  const csrf = (
    await (
      await page.request.post(`${URL}/api/central.api.v1.AuthService/GetSession`, { data: {} })
    ).json()
  ).csrfToken;
  const res = await page.request.post(`${URL}/api/central.api.v1.${method}`, {
    data: body,
    headers: { 'X-CSRF-Token': csrf },
  });
  if (!res.ok()) throw new Error(`${method}: ${res.status()} ${await res.text()}`);
  return res.json();
};

let sim;
if (SIM) {
  await step('enrollment token and 5-second metrics', async () => {
    const org = await call('OrganizationService/GetOrganization', {});
    await call('OrganizationService/UpdateOrganization', {
      name: org.organization.name,
      settings: { ...org.organization.settings, metricsInterval: '5s' },
    });
    const tok = await call('EnrollmentAdminService/CreateEnrollmentToken', {
      name: 'simulated fleet',
      approvalMode: 'APPROVAL_MODE_AUTO',
      maxUses: AGENTS + 5,
      expiresIn: '3600s',
      defaultTags: ['sim'],
    });
    writeFileSync(join(OUT, '.key'), tok.enrollmentKey, { mode: 0o600 });
  });
  await step(`start ${AGENTS} simulated agents`, async () => {
    sim = spawn(
      SIM,
      [
        '--agent-url',
        AGENT_URL,
        '--key-file',
        join(OUT, '.key'),
        '--agents',
        String(AGENTS),
        '--state-dir',
        join(OUT, 'sim'),
        '--ramp-up',
        '3s',
        '--stats',
        '30s',
        '--backfill',
        BACKFILL,
      ],
      { stdio: ['ignore', 'ignore', 'pipe'] },
    );
    sim.stderr.on('data', (d) => {
      const s = d.toString();
      if (/level=(ERROR|WARN)/.test(s))
        process.stdout.write(`\n  sim: ${s.trim().slice(0, 300)}\n`);
    });
    await page.getByText(`of ${AGENTS} hosts`).waitFor({ timeout: 60_000 });
    await page.waitForFunction(
      (n) => document.querySelectorAll('.row').length >= Math.min(n, 12),
      AGENTS,
      { timeout: 60_000 },
    );
  });
  await step(`collect ${WAIT_METRICS_S}s of metrics`, async () => {
    await page.waitForTimeout(WAIT_METRICS_S * 1000);
  });
  await step('dashboard screenshots', async () => {
    await shot('07-dashboard-light');
    await page.emulateMedia({ colorScheme: 'dark' });
    await page.waitForTimeout(500);
    await shot('08-dashboard-dark');
    await page.getByRole('button', { name: /Security updates/ }).click();
    await page.waitForTimeout(300);
    await shot('09-dashboard-security-filter-dark');
    await page.getByRole('button', { name: /Security updates/ }).click();
  });
  await step('host overview screenshots', async () => {
    await page.locator('.row').nth(2).click();
    await page.waitForURL('**/hosts/**/overview');
    await page.locator('app-chart canvas').first().waitFor();
    await page.waitForTimeout(1500);
    await shot('10-host-overview-dark');
    await page.emulateMedia({ colorScheme: 'light' });
    await page.waitForTimeout(500);
    await shot('11-host-overview-light');
    await page
      .getByRole('radio', { name: '24h' })
      .click()
      .catch(() => page.getByText('24h').click());
    await page.waitForTimeout(800);
    await shot('12-host-overview-24h-light');
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto(URL + '/');
    await page.getByRole('heading', { name: 'Fleet' }).waitFor();
    await page.waitForTimeout(800);
    await shot('13-dashboard-mobile');
  });
}

sim?.kill('SIGTERM');
await browser.close();
if (problems.length) {
  console.error('\nProblems:\n' + problems.map((p) => '  - ' + p).join('\n'));
  process.exit(1);
}
console.log(`\nAll good. Screenshots in ${OUT}`);
