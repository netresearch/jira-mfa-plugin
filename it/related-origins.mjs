// Passkeys across two host names in a real browser. A TLS proxy serves Jira as
// https://jira.example.com (old) and https://jira.example.org (new); Chromium
// resolves both to it and reads /.well-known/webauthn through it.
// Usage: JIRA_ADMIN_PAT=<token> JIRA_RECOVERY_PASS=<secret> node related-origins.mjs
// With JIRA_UPGRADE_JAR=<jar> the plugin is updated after the first passkey has
// been registered, so that passkey comes from the version installed before.
import { chromium } from 'playwright-core';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import { BASE, assert, chromiumPath, rawGet, rawRequest } from './lib.mjs';

const OLD = 'https://jira.example.com';
const NEW = 'https://jira.example.org';
const PATH = '/.well-known/webauthn';
const { JIRA_ADMIN_PAT: PAT, JIRA_RECOVERY_PASS: RECOVERY_PASS, JIRA_UPGRADE_JAR: UPGRADE_JAR } = process.env;
if (!PAT || !RECOVERY_PASS) throw new Error('JIRA_ADMIN_PAT and JIRA_RECOVERY_PASS must be set');
const USER = { name: 'olga' + Date.now(), pass: 'Olga-Pass-1' };

async function admin(method, p, body, type = 'application/json') {
  const r = await fetch(BASE + p, { method, body, headers: { Authorization: 'Bearer ' + PAT, 'Content-Type': type, Accept: 'application/json' } });
  assert(r.ok, `${method} ${p} (HTTP ${r.status})`);
}
const setBaseUrl = (url) => admin('PUT', '/rest/api/2/settings/baseUrl', url);

async function startProxy() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'jira-mfa-tls-'));
  const [key, cert] = [path.join(dir, 'key.pem'), path.join(dir, 'cert.pem')];
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2', '-subj', '/CN=jira.example.com',
    '-addext', 'subjectAltName=DNS:jira.example.com,DNS:jira.example.org', '-keyout', key, '-out', cert], { stdio: 'ignore' });
  const target = new URL(BASE);
  const server = https.createServer({ key: fs.readFileSync(key), cert: fs.readFileSync(cert) }, (req, res) => {
    const up = http.request({ host: target.hostname, port: target.port || 80, method: req.method, path: req.url, headers: req.headers }, (r) => {
      const headers = { ...r.headers };
      if (headers.location) headers.location = headers.location.replace(/^http:\/\/(jira\.example\.)/, 'https://$1');
      if (req.url === PATH) wellKnownReads.push({ host: req.headers.host, status: r.statusCode });
      res.writeHead(r.statusCode, headers);
      r.pipe(res);
    });
    up.on('error', () => res.destroy());
    req.pipe(up);
  });
  fs.rmSync(dir, { recursive: true });
  await new Promise((resolve) => { server.listen(0, '127.0.0.1', resolve); });
  return server;
}

const wellKnownReads = [];
const proxy = await startProxy();
const browser = await chromium.launch({
  headless: true, executablePath: chromiumPath(),
  args: ['--ignore-certificate-errors', `--host-resolver-rules=MAP jira.example.com:443 127.0.0.1:${proxy.address().port},MAP jira.example.org:443 127.0.0.1:${proxy.address().port}`],
});

async function login(page, base, u) {
  await page.goto(base + '/login.jsp');
  await page.fill('#login-form-username', u.name);
  await page.fill('#login-form-password', u.pass);
  await Promise.all([page.waitForNavigation(), page.click('#login-form-submit')]);
}

// Runs fn on the plugin's admin page as recovery_admin.
async function onAdminPage(fn) {
  const ctx = await browser.newContext();
  const p = await ctx.newPage();
  try {
    const url = BASE + '/plugins/servlet/mfa/admin';
    await login(p, BASE, { name: 'recovery_admin', pass: RECOVERY_PASS });
    await p.goto(url);
    if (p.url().includes('WebSudo')) {
      await p.fill('#login-form-authenticatePassword', RECOVERY_PASS);
      await Promise.all([p.waitForNavigation(), p.click('#login-form-submit')]);
      if (!p.url().includes('/mfa/admin')) await p.goto(url);
    }
    return await fn(p);
  } finally {
    await ctx.close();
  }
}

// Saves plugin settings and returns the page's answer.
const saveSettings = (fields) => onAdminPage(async (p) => {
  for (const [id, value] of Object.entries(fields)) await p.fill('#' + id, value);
  await Promise.all([p.waitForNavigation(), p.click('#save-settings')]);
  return p.locator('#admin-message, p.error').first().innerText();
});
const knowsLegacyRpId = () => onAdminPage(async (p) => await p.locator('#legacyRpId').count() === 1);

// The user's passkeys in the users overview: the table cell and the CSV row.
const overview = () => onAdminPage(async (p) => {
  const url = BASE + '/plugins/servlet/mfa/admin/users';
  await p.goto(url);
  const cell = (await p.locator(`#users tr[data-user="${USER.name}"] td`).nth(3).innerText()).trim();
  const csv = await (await p.request.get(url + '?format=csv')).text();
  return { cell, head: csv.split('\r\n')[0], row: csv.split('\r\n').find((l) => l.startsWith(USER.name + ',')) };
});

const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
const page = await ctx.newPage();
page.setDefaultTimeout(30000);

// Logs in on a host; the verify page opens the passkey prompt by itself. Returns the answer of authenticate/options.
async function passkeyLogin(base) {
  await ctx.clearCookies();
  let options = null;
  const read = async (r) => { if (r.url().endsWith('/webauthn/authenticate/options')) options = await r.json(); };
  page.on('response', read);
  await login(page, base, USER);
  await page.waitForURL((u) => !u.toString().includes('/mfa/verify'));
  page.off('response', read);
  assert(page.url().startsWith(base + '/'), `the second step on ${base} ends on that host (${page.url()})`);
  return options.publicKey;
}

async function addPasskey(base, label) {
  await page.goto(base + '/plugins/servlet/mfa/setup');
  await page.fill('#passkey-label', label);
  await Promise.all([page.waitForNavigation(), page.click('#passkey-add')]);
  assert(await page.getByText(label).count() >= 1, `passkey "${label}" added on ${base}`);
}

try {
  await admin('POST', '/rest/api/2/user', JSON.stringify({ name: USER.name, password: USER.pass, emailAddress: 'olga@example.com', displayName: USER.name }));
  await setBaseUrl(OLD);
  if (UPGRADE_JAR) assert(!(await knowsLegacyRpId()), 'the installed version does not store relying party IDs');
  const cdp = await ctx.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true },
  });
  await login(page, OLD, USER);
  await addPasskey(OLD, 'Old host key');
  if (UPGRADE_JAR) {
    console.log(execFileSync(new URL('install-plugin.sh', import.meta.url).pathname, [UPGRADE_JAR],
      { env: { ...process.env, JIRA_BASE_URL: BASE, JIRA_PAT: PAT } }).toString().trim());
    // an update to the same version reports enabled before it has happened
    for (let i = 0; !(await knowsLegacyRpId()); i++) {
      if (i === 30) throw new Error('the updated plugin does not show up');
      await page.waitForTimeout(2000);
    }
    await saveSettings({ legacyRpId: 'legacy.example.net' });
    await ctx.clearCookies();
    const [asked] = await Promise.all([
      page.waitForResponse((r) => r.url().endsWith('/webauthn/authenticate/options')), login(page, OLD, USER)]);
    const { rpId } = (await asked.json()).publicKey;
    assert(rpId === 'legacy.example.net', `the passkey from before the update has no stored ID and follows the setting (${rpId})`);
    await page.goto('about:blank');
  }

  await saveSettings({ relatedOrigins: '', legacyRpId: '', rpId: '' });
  const unserved = async () => { const r = await rawGet(PATH); return r.status !== 200 && !r.text.includes('"origins"'); };
  assert(await unserved(), 'without related origins the document is not served');
  const same = await passkeyLogin(OLD);
  assert(same.rpId === 'jira.example.com', 'default settings: the old host uses its own ID');
  const before = await overview();
  assert(before.cell === '1' && before.row.endsWith(',1,10,,jira.example.com: 1'), `the overview shows one passkey of the current ID (${JSON.stringify(before)})`);
  assert(before.head.endsWith(',grace_period_ends,passkey_rp_ids'), 'the relying party IDs are the last CSV column');

  const refused = await saveSettings({ relatedOrigins: 'https://jira.example.org/jira' });
  assert(refused.includes('is not a valid related origin'), 'an origin with a path is refused: ' + refused);
  assert(await unserved(), 'the refused value is not stored');
  assert((await saveSettings({ relatedOrigins: OLD + '\n' + NEW })).includes('saved'), 'both origins saved');

  const wk = await rawGet(PATH);
  assert(wk.status === 200 && /^application\/json(;|$)/.test(wk.headers['content-type']), `well-known answers 200 ${wk.headers['content-type']} without a login`);
  assert(wk.text === JSON.stringify({ origins: [OLD, NEW] }), 'well-known lists both origins: ' + wk.text);
  assert(!wk.headers['set-cookie'], 'well-known starts no session');
  const head = await rawRequest('HEAD', PATH);
  assert(head.status === 200 && head.text === '', 'HEAD answers 200 without a body');
  for (const m of ['POST', 'PUT', 'DELETE', 'OPTIONS']) {
    const r = await rawRequest(m, PATH);
    assert(r.status === 405, `${m} answers 405 (HTTP ${r.status})`);
  }
  for (const p of [PATH + '/', PATH + '/x', PATH + ';x=1', '/.well-known/%77ebauthn', '//.well-known/webauthn', '/x/..;' + PATH, '/x/..' + PATH, '/.well-known/']) {
    const r = await rawGet(p);
    assert(r.status !== 200 && !r.text.includes('"origins"'), `${p} is not served (HTTP ${r.status})`);
  }
  // a password-only session reaches the document and nothing around it
  await ctx.clearCookies();
  await cdp.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId, enabled: false });
  await login(page, OLD, USER);
  const cookie = (await ctx.cookies(OLD)).map((c) => c.name + '=' + c.value).join('; ');
  const own = await rawGet(PATH, { Cookie: cookie });
  assert(own.status === 200 && own.text === wk.text, 'an unverified session gets the same document');
  for (const p of [PATH + '/', PATH + '/x', PATH + ';x=1', PATH + '/../../secure/Dashboard.jspa', PATH + '/..;/..;/secure/Dashboard.jspa']) {
    const r = await rawGet(p, { Cookie: cookie, Accept: 'text/html' });
    assert(r.status === 302 && r.headers.location.includes('/mfa/verify'), `${p} is challenged for an unverified session (HTTP ${r.status})`);
  }
  // leave the verify page first, or its waiting prompt would be answered and log the old session in
  await page.goto('about:blank');
  await cdp.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId, enabled: true });

  wellKnownReads.length = 0;
  const viaNew = await passkeyLogin(NEW);
  assert(viaNew.rpId === 'jira.example.com' && viaNew.allowCredentials.length === 1, 'the new host asks for the passkey of the old ID');
  assert(wellKnownReads.some((r) => r.host === 'jira.example.com' && r.status === 200), 'the browser read the list on the old host');

  // the move: legacy ID first, then the base URL
  assert((await saveSettings({ legacyRpId: 'jira.example.com' })).includes('saved'), 'legacy relying party ID saved');
  await setBaseUrl(NEW);
  const moved = await passkeyLogin(NEW);
  assert(moved.rpId === 'jira.example.com', 'after the move the old passkey still works on the new host');
  const oldOnly = await overview();
  assert(oldOnly.cell === '1\njira.example.com: 1' && oldOnly.row.endsWith(',1,10,,jira.example.com: 1'), `the overview shows who has only an old passkey (${JSON.stringify(oldOnly)})`);
  await addPasskey(NEW, 'New host key');
  const creds = (await cdp.send('WebAuthn.getCredentials', { authenticatorId })).credentials.map((c) => c.rpId).sort();
  assert(JSON.stringify(creds) === '["jira.example.com","jira.example.org"]', 'the authenticator holds one passkey per ID: ' + creds);
  const both = await overview();
  assert(both.cell === '2\njira.example.com: 1, jira.example.org: 1' && both.row.endsWith(',2,10,,"jira.example.com: 1, jira.example.org: 1"'),
    `the overview shows the passkeys of both IDs (${JSON.stringify(both)})`);
  const onNew = await passkeyLogin(NEW);
  assert(onNew.rpId === 'jira.example.org' && onNew.allowCredentials.length === 1, 'on the new host the new passkey is asked for, alone');
  const onOld = await passkeyLogin(OLD);
  assert(onOld.rpId === 'jira.example.com' && onOld.allowCredentials.length === 1, 'on the old host the old passkey is asked for, alone');
  console.log('ALL OK');
} finally {
  await saveSettings({ relatedOrigins: '', legacyRpId: '', rpId: '' }).catch((e) => console.error('settings not restored: ' + e.message));
  // a timebomb licence has 10 users, and e2e.mjs needs most of them
  await admin('DELETE', '/rest/api/2/user?username=' + USER.name).catch((e) => console.error('user not deleted: ' + e.message));
  await setBaseUrl(BASE).catch((e) => console.error('base URL not restored: ' + e.message));
  await browser.close();
  proxy.close();
}
