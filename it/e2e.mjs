// End-to-end test of the MFA plugin in a real headless Chromium against a
// running Jira with the plugin installed.
// Env: JIRA_BASE_URL, JIRA_ADMIN_USER/PASS, JIRA_ADMIN_PAT (admin token for setup calls),
//      JIRA_RECOVERY_PASS (recovery_admin password; changes settings and is checked itself).
import { authenticator } from 'otplib';
import { launch, shot, assert, basicAuth, rawGet, cookieHeader, BASE, ADMIN_USER, ADMIN_PASS } from './lib.mjs';

authenticator.options = { digits: 6, step: 30, window: 0 };
const ADMIN_PAT = process.env.JIRA_ADMIN_PAT;
if (!ADMIN_PAT) throw new Error('JIRA_ADMIN_PAT is required');
const RECOVERY_PASS = process.env.JIRA_RECOVERY_PASS;
if (!RECOVERY_PASS) throw new Error('JIRA_RECOVERY_PASS is required');
const RUN = Date.now().toString(36);
const ALICE = { name: 'alice' + RUN, pass: 'Alice-Pass-' + RUN };
const BOB = { name: 'bob' + RUN, pass: 'Bob-Pass-' + RUN };
const CAROL = { name: 'carol' + RUN, pass: 'Carol-Pass-' + RUN };
const DAVE = { name: 'dave' + RUN, pass: 'Dave-Pass-' + RUN };
const EVE = { name: 'eve' + RUN, pass: 'Eve-Pass-' + RUN };
const GINA = { name: 'gina' + RUN, pass: 'Gina-Pass-' + RUN };

async function api(method, path, body, headers = {}) {
  const r = await fetch(BASE + path, {
    method,
    headers: { 'Content-Type': 'application/json', Accept: 'application/json', ...headers },
    body: body ? JSON.stringify(body) : undefined,
    redirect: 'manual',
  });
  const text = await r.text();
  return { status: r.status, text, json: () => JSON.parse(text) };
}
const adminApi = (m, p, b) => api(m, p, b, { Authorization: 'Bearer ' + ADMIN_PAT });

async function createUser(u) {
  const r = await adminApi('POST', '/rest/api/2/user', {
    name: u.name, password: u.pass, emailAddress: u.name + '@example.com', displayName: u.name,
  });
  assert(r.status === 201, `user ${u.name} created (HTTP ${r.status})`);
}

async function login(page, u) {
  await page.goto(BASE + '/login.jsp');
  await page.fill('#login-form-username', u.name);
  await page.fill('#login-form-password', u.pass);
  await Promise.all([page.waitForNavigation(), page.click('#login-form-submit')]);
}

let lastStep = 0;
async function nextFreshCode(secret) {
  // The plugin rejects a code from an already used 30 s step (replay
  // protection), so wait for a new step, and avoid the last 3 s of a step.
  for (;;) {
    const step = Math.floor(Date.now() / 30000);
    if (step > lastStep && authenticator.timeRemaining() >= 3) {
      lastStep = step;
      return authenticator.generate(secret);
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
}

// Opens the MFA admin page (with an optional query) as recovery_admin, who is
// never challenged and so is unaffected by a grace period of 0 days, and runs
// fn on it.
async function asRecoveryAdmin(query, fn) {
  const c = await browser.newContext();
  const p = await c.newPage();
  const url = BASE + '/plugins/servlet/mfa/admin' + query;
  try {
    await login(p, { name: 'recovery_admin', pass: RECOVERY_PASS });
    await p.goto(url);
    if (p.url().includes('WebSudo')) {
      await p.fill('#login-form-authenticatePassword', RECOVERY_PASS);
      await Promise.all([p.waitForNavigation(), p.click('#login-form-submit')]);
      if (!p.url().includes('/mfa/admin')) await p.goto(url);
    }
    return await fn(p);
  } finally {
    await c.close();
  }
}

// Changes plugin settings through the admin form.
async function saveSettings(fields) {
  return asRecoveryAdmin('', async (p) => {
    for (const [id, value] of Object.entries(fields)) await p.fill('#' + id, value);
    await Promise.all([p.waitForNavigation(), p.click('#save-settings')]);
    return (await p.locator('#admin-message').innerText()).includes('Settings saved');
  });
}

// A cell of the admin status lookup of a user, by its row heading.
async function statusCell(username, row) {
  return asRecoveryAdmin('?user=' + encodeURIComponent(username), async (p) =>
    (await p.locator('#user-status tr', { hasText: row }).locator('td').innerText()).trim());
}
const graceCell = (username) => statusCell(username, 'Grace period ends');

// Removes all factors of a user through the admin page.
async function adminReset(username) {
  return asRecoveryAdmin('?user=' + encodeURIComponent(username), async (p) => {
    await Promise.all([p.waitForNavigation(), p.click('#reset-user')]);
    return (await p.locator('#admin-message').innerText()).includes('were removed');
  });
}

// Enrols TOTP for a user who has no factor; the page stays on the setup page
// with a verified session. Returns the secret.
async function enrolTotp(page, u) {
  await login(page, u);
  if (!page.url().includes('/mfa/setup')) await page.goto(BASE + '/plugins/servlet/mfa/setup');
  const s = (await page.locator('#totp-secret').innerText()).trim();
  await page.fill('#totp-code', await nextFreshCode(s));
  await Promise.all([page.waitForNavigation(), page.click('#totp-confirm')]);
  assert(await page.locator('#recovery-codes code').count() === 10, `${u.name} enrols TOTP`);
  return s;
}

// Completes the second step with a fresh TOTP code on the verify page and
// returns the Location header the code form's POST answered with (null when
// it did not redirect).
async function verifyTotp(page, s) {
  if (!page.url().includes('/mfa/verify')) await page.goto(BASE + '/plugins/servlet/mfa/verify');
  await page.fill('#code', await nextFreshCode(s));
  const [nav] = await Promise.all([page.waitForNavigation(), page.click('#verify-submit')]);
  // walk the redirect chain back to the POST; Jira may redirect the target again
  let req = nav && nav.request().redirectedFrom();
  while (req && req.method() !== 'POST') req = req.redirectedFrom();
  const res = req && await req.response();
  return res ? res.headers().location || null : null;
}

const myselfStatus = async (page, headers = {}) => (await page.request.get(BASE + '/rest/api/2/myself', { headers })).status();

// Any Jira page outside the plugin's own pages and the login page.
function inJira(page) {
  const u = page.url();
  return u.startsWith(BASE) && !u.includes('/plugins/servlet/mfa/') && !u.includes('login.jsp');
}

const browser = await launch();
let failed = false;
try {
  await createUser(ALICE);
  await createUser(BOB);

  // ---- 1. grace period: enrolment is offered, can be postponed -------------
  let ctx = await browser.newContext();
  let page = await ctx.newPage();
  await login(page, ALICE);
  assert(page.url().includes('/plugins/servlet/mfa/setup'), 'after password login a new user lands on the enrolment page');
  assert(await page.getByText('will require a second factor from').count() === 1, 'grace period notice is shown');
  assert(await page.locator('body > header.topbar #logout').count() === 1, 'the enrolment page has Log out in the bar at the top');
  await shot(page, 'e2e-01-grace');
  await Promise.all([page.waitForURL((u) => !u.toString().includes('/mfa/setup')), page.click('#later')]);
  assert(inJira(page), '"Remind me later" continues to Jira during the grace period (at ' + page.url() + ')');

  // ---- 2. TOTP enrolment ------------------------------------------------------
  await page.goto(BASE + '/plugins/servlet/mfa/setup');
  const secret = (await page.locator('#totp-secret').innerText()).trim();
  assert(/^[A-Z2-7]{32}$/.test(secret), 'base32 TOTP secret is displayed for manual entry');
  assert(await page.locator('svg[role=img]').count() === 1, 'QR code is rendered');
  await page.fill('#totp-code', '000000');
  await Promise.all([page.waitForNavigation(), page.click('#totp-confirm')]);
  assert(await page.getByText('That code does not match').count() === 1, 'a wrong enrolment code is rejected');
  await page.fill('#totp-code', await nextFreshCode(secret));
  await Promise.all([page.waitForNavigation(), page.click('#totp-confirm')]);
  const codes = await page.locator('#recovery-codes code').allInnerTexts();
  assert(codes.length === 10, 'ten recovery codes are shown after enrolment');
  assert(await page.locator('body > header.topbar #back-to-jira').count() === 1, 'once verified, the bar at the top links back to Jira');
  await shot(page, 'e2e-02-enrolled');
  await page.goto(BASE + '/secure/Dashboard.jspa');
  assert(inJira(page), 'the enrolling session counts as verified');
  await ctx.close();

  // ---- 3. second step required on next login ---------------------------------
  ctx = await browser.newContext();
  page = await ctx.newPage();
  await login(page, ALICE);
  assert(page.url().includes('/plugins/servlet/mfa/verify'), 'enrolled user is sent to the second step after the password');
  assert(await page.locator('body > header.topbar #logout').count() === 1, 'the second step has Log out in the bar at the top');
  assert(await page.locator('#back-to-jira').count() === 0, 'the second step offers no way back to Jira before it is passed');
  await shot(page, 'e2e-03-verify');
  let r = await page.request.get(BASE + '/rest/api/2/myself');
  assert(r.status() === 401, `unverified session cannot call REST (HTTP ${r.status()})`);
  r = await page.request.get(BASE + '/rest/api/2/myself', { headers: { Authorization: 'Bearer not-a-token' } });
  assert(r.status() === 401, `unverified session + garbage Bearer header is still blocked (HTTP ${r.status()})`);
  r = await page.request.get(BASE + '/secure/Dashboard.jspa', { maxRedirects: 0 });
  assert(r.status() === 302 && r.headers().location.includes('/mfa/verify'), 'unverified session is redirected away from pages');
  for (const probe of ['/browse/TEST-1', '/secure/attachment/10000/x.txt', '/secure/ViewProfile.jspa',
    '/plugins/servlet/mfa/verify/%2e%2e/%2e%2e/%2e%2e/secure/Dashboard.jspa',
    '/plugins/servlet/mfa/setup/..;/..;/..;/secure/Dashboard.jspa',
    '/plugins/servlet/mfa/admin',
    '/plugins/servlet/mfa/admin/users']) {
    r = await page.request.get(BASE + probe, { maxRedirects: 0, headers: { Accept: 'text/html' } });
    const loc = r.headers().location || '';
    const blocked = (r.status() === 302 && loc.includes('/mfa/verify')) || r.status() === 401 || r.status() === 400;
    assert(blocked, `unverified session cannot open ${probe} (HTTP ${r.status()} ${loc})`);
  }
  await page.fill('#code', '123456');
  await Promise.all([page.waitForNavigation(), page.click('#verify-submit')]);
  assert(await page.getByText('That code is not valid').count() === 1, 'wrong TOTP code is rejected');
  const code = await nextFreshCode(secret);
  await page.fill('#code', code);
  await Promise.all([page.waitForNavigation(), page.click('#verify-submit')]);
  assert(inJira(page), 'correct TOTP code completes the login');
  r = await page.request.get(BASE + '/rest/api/2/myself');
  assert(r.status() === 200, 'verified session can call REST');
  r = await page.request.get(BASE + '/plugins/servlet/mfa/admin/users', { maxRedirects: 0 });
  assert(r.status() === 403, `a verified non-administrator cannot open the user overview (HTTP ${r.status()})`);

  // PAT for alice, created from her verified session
  // from the page itself, as the profile page's "Create token" button would
  const pat = await page.evaluate(async () => {
    const res = await fetch('/rest/pat/latest/tokens', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-Atlassian-Token': 'no-check' },
      body: JSON.stringify({ name: 'e2e', expirationDuration: 1 }),
    });
    return { status: res.status, body: await res.text() };
  });
  assert(pat.status === 201, `alice creates a personal access token (HTTP ${pat.status} ${pat.status === 201 ? '' : pat.body})`);
  const alicePat = JSON.parse(pat.body).rawToken;
  await ctx.close();

  // the verify page's "Log out" link ends the password-only session
  ctx = await browser.newContext();
  page = await ctx.newPage();
  await login(page, ALICE);
  assert(page.url().includes('/mfa/verify'), 'second step shown again');
  await Promise.all([page.waitForNavigation(), page.click('#logout')]);
  await page.waitForLoadState('load');
  r = await page.request.get(BASE + '/rest/api/2/myself');
  assert(r.status() === 401 && !(await r.text()).includes('Two-step verification required'),
    `"Log out" on the verify page logs the user out (HTTP ${r.status()}, at ${page.url()})`);
  await ctx.close();

  // replay of the same code in another session
  ctx = await browser.newContext();
  page = await ctx.newPage();
  await login(page, ALICE);
  await page.fill('#code', code);
  await Promise.all([page.waitForNavigation(), page.click('#verify-submit')]);
  assert(await page.getByText('That code is not valid').count() === 1, 'a TOTP code cannot be replayed');
  await ctx.close();

  // ---- 4. non-browser clients --------------------------------------------------
  let a = await api('GET', '/rest/api/2/myself', null, { Authorization: 'Bearer ' + alicePat });
  assert(a.status === 200 && a.json().name === ALICE.name, 'REST with alice\'s PAT works without a second step');
  a = await api('GET', '/rest/api/2/myself', null, { Authorization: basicAuth(ALICE.name, ALICE.pass) });
  assert(a.status === 401 && a.text.includes('personal access token'), 'Basic auth with alice\'s password is refused');
  a = await api('GET', '/rest/api/2/myself', null, { Authorization: basicAuth(ALICE.name, 'wrong') });
  assert(a.status === 401, 'Basic auth with a wrong password is refused');
  a = await api('GET', '/rest/api/2/myself', null, { Authorization: 'Bearer garbage' });
  assert(a.status === 401, 'an invalid PAT is refused');

  // ---- 4b. Basic authentication follows the grace period -----------------------
  const carolBasic = () => api('GET', '/rest/api/2/myself', null, { Authorization: basicAuth(CAROL.name, CAROL.pass) });
  await createUser(CAROL);
  a = await carolBasic();
  assert(a.status === 200 && a.json().name === CAROL.name, `Basic auth works during the grace period for a user without a factor (HTTP ${a.status})`);
  assert(await saveSettings({ graceDays: '0' }), 'administrator sets the grace period to 0 days through the admin form');
  a = await carolBasic();
  assert(a.status === 401 && a.text.includes('personal access token'), `Basic auth is refused once the grace period has expired (HTTP ${a.status})`);
  ctx = await browser.newContext();
  page = await ctx.newPage();
  await login(page, CAROL);
  assert(page.url().includes('/plugins/servlet/mfa/setup') && await page.locator('#later').count() === 0,
    'after the grace period enrolment is mandatory (no "Remind me later")');
  r = await page.request.get(BASE + '/rest/api/2/myself');
  assert(r.status() === 401, `after the grace period an unenrolled session cannot use REST (HTTP ${r.status()})`);
  await ctx.close();
  assert(await saveSettings({ basicAuthAllowedUsers: CAROL.name }), 'administrator allow-lists carol for Basic auth');
  a = await carolBasic();
  assert(a.status === 200, `an allow-listed user keeps Basic auth after the grace period (HTTP ${a.status})`);
  assert(await saveSettings({ graceDays: '14', basicAuthAllowedUsers: '' }), 'settings restored (14 days, empty allow-list)');
  a = await carolBasic();
  assert(a.status === 200, `with the grace period back at 14 days Basic works again for carol (HTTP ${a.status})`);

  // ---- 5. recovery code -------------------------------------------------------
  ctx = await browser.newContext();
  page = await ctx.newPage();
  await login(page, ALICE);
  await page.fill('#code', codes[0].toLowerCase());
  await Promise.all([page.waitForNavigation(), page.click('#verify-submit')]);
  assert(inJira(page), 'a recovery code (case-insensitive) completes the login');
  await page.goto(BASE + '/plugins/servlet/mfa/setup');
  assert(await page.getByText('9 unused recovery codes left').count() === 1, 'the used recovery code is consumed');
  await ctx.close();
  ctx = await browser.newContext();
  page = await ctx.newPage();
  await login(page, ALICE);
  await page.fill('#code', codes[0]);
  await Promise.all([page.waitForNavigation(), page.click('#verify-submit')]);
  assert(await page.getByText('That code is not valid').count() === 1, 'a used recovery code does not work twice');

  // ---- 6. rate limiting ----------------------------------------------------------
  for (let i = 0; i < 5; i++) {
    if (await page.locator('#code').count() === 0) break;
    await page.fill('#code', '000000');
    await Promise.all([page.waitForNavigation(), page.click('#verify-submit')]);
  }
  assert(await page.getByText('Too many failed attempts').count() === 1, 'repeated failures lock the second step');
  assert(await page.locator('#code').count() === 0, 'no code field while locked');
  await shot(page, 'e2e-06-locked');
  await ctx.close();

  // ---- 7. admin reset ---------------------------------------------------------------
  ctx = await browser.newContext();
  page = await ctx.newPage();
  await login(page, { name: ADMIN_USER, pass: ADMIN_PASS });
  if (page.url().includes('/mfa/setup')) {
    await Promise.all([page.waitForNavigation(), page.click('#later')]);
  }
  await page.goto(BASE + '/plugins/servlet/mfa/admin?user=' + ALICE.name);
  if (page.url().includes('WebSudo')) {
    await page.fill('#login-form-authenticatePassword', ADMIN_PASS);
    await Promise.all([page.waitForNavigation(), page.click('#login-form-submit')]);
    if (!page.url().includes('/mfa/admin')) await page.goto(BASE + '/plugins/servlet/mfa/admin?user=' + ALICE.name);
  }
  assert(page.url().includes('/plugins/servlet/mfa/admin'), 'admin reaches the MFA administration page (after websudo)');
  assert(await page.locator('#user-status').getByText('Locked until').count() === 1, 'admin sees the user status');
  await shot(page, 'e2e-07-admin');
  assert(await page.locator('#users-overview-link').count() === 1, 'the administration page links to the user overview');
  await page.goto(BASE + '/plugins/servlet/mfa/admin/users');
  assert(page.url().includes('/plugins/servlet/mfa/admin/users'), 'admin opens the user overview');
  const aliceRow = page.locator(`#users tr[data-user="${ALICE.name}"]`);
  assert(await aliceRow.getAttribute('data-state') === 'SET_UP', 'the overview lists alice as set up');
  assert((await aliceRow.locator('td').nth(2).innerText()).trim() === 'yes', 'the overview shows alice\'s authenticator app');
  const adminRow = page.locator(`#users tr[data-user="${ADMIN_USER}"]`);
  assert(await adminRow.getAttribute('data-state') === 'IN_GRACE_PERIOD', 'the overview shows the administrator in the grace period');
  assert(/^\d{4}-\d{2}-\d{2}$/.test((await adminRow.locator('td').nth(5).innerText()).trim()), 'the overview shows when the grace period ends');
  assert(Number(await page.locator('#state-counts td[data-state="SET_UP"]').innerText()) >= 1, 'the counts include the set-up users');
  await shot(page, 'e2e-07b-users');
  await page.goto(BASE + '/plugins/servlet/mfa/admin/users?state=IN_GRACE_PERIOD');
  const states = await page.locator('#users tbody tr').evaluateAll((rows) => rows.map((tr) => tr.dataset.state));
  assert(states.length > 0 && states.every((st) => st === 'IN_GRACE_PERIOD'), 'the state filter shows only that state');
  assert(await page.locator(`#users tr[data-user="${ALICE.name}"]`).count() === 0, 'the state filter hides alice');
  r = await page.request.get(BASE + '/plugins/servlet/mfa/admin/users?format=csv');
  const csv = await r.text();
  assert(r.status() === 200 && (r.headers()['content-type'] || '').startsWith('text/csv'), `the overview downloads as CSV (HTTP ${r.status()})`);
  assert(csv.startsWith('username,display_name,email,active,state,') && csv.split('\r\n').some((l) => l.startsWith(ALICE.name + ',') && l.includes(',SET_UP,yes,')),
    'the CSV has a header and alice\'s row');
  await page.goto(BASE + '/secure/admin/user/UserBrowser.jspa');
  assert(await page.locator('#mfa-admin-users-link').count() === 1, 'User management links to the overview');
  await page.goto(BASE + '/plugins/servlet/mfa/admin?user=' + ALICE.name);
  await Promise.all([page.waitForNavigation(), page.click('#reset-user')]);
  assert((await page.locator('#admin-message').innerText()).includes('were removed'), 'admin resets alice\'s factors');
  await ctx.close();

  ctx = await browser.newContext();
  page = await ctx.newPage();
  await login(page, ALICE);
  assert(page.url().includes('/plugins/servlet/mfa/setup'), 'after the reset alice is offered enrolment again, not the second step');
  await ctx.close();

  // ---- 8. passkey with a virtual authenticator --------------------------------------
  ctx = await browser.newContext();
  page = await ctx.newPage();
  const cdp = await ctx.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true },
  });
  await login(page, BOB);
  assert(page.url().includes('/plugins/servlet/mfa/setup'), 'bob lands on enrolment');
  await page.fill('#passkey-label', 'Virtual key');
  await Promise.all([page.waitForNavigation(), page.click('#passkey-add')]);
  const bobCodes = await page.locator('#recovery-codes code').allInnerTexts();
  assert(bobCodes.length === 10, 'passkey registration issues recovery codes');
  assert(await page.getByText('Virtual key').count() >= 1, 'the passkey is listed');
  const creds = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
  assert(creds.credentials.length === 1, 'the virtual authenticator holds one credential');
  await shot(page, 'e2e-08-passkey');
  // log out, keep the authenticator (same page/target), log in again
  await ctx.clearCookies();
  await login(page, BOB);
  assert(page.url().includes('/plugins/servlet/mfa/verify'), 'bob is asked for the second step');
  await Promise.all([page.waitForURL((u) => !u.toString().includes('/mfa/verify')), page.click('#passkey-login')]);
  assert(inJira(page), 'the passkey completes the login');
  const after = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
  assert(after.credentials[0].signCount >= 1, 'the authenticator signed (sign count advanced)');
  // a passkey assertion from a different authenticator fails
  await ctx.clearCookies();
  await cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId });
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });
  await login(page, BOB);
  await page.click('#passkey-login');
  await page.locator('#passkey-error').waitFor({ state: 'visible', timeout: 30000 });
  assert(page.url().includes('/mfa/verify'), 'an unknown authenticator does not complete the login');
  await ctx.close();

  // ---- 9b. an enrolled administrator cannot reach the MFA admin page with the password alone
  const BOSS = { name: 'boss' + RUN, pass: 'Boss-Pass-' + RUN };
  await createUser(BOSS);
  a = await adminApi('POST', '/rest/api/2/group/user?groupname=jira-administrators', { name: BOSS.name });
  assert(a.status === 201, `boss added to jira-administrators (HTTP ${a.status})`);
  ctx = await browser.newContext();
  page = await ctx.newPage();
  await login(page, BOSS);
  const bossSecret = (await page.locator('#totp-secret').innerText()).trim();
  await page.fill('#totp-code', await nextFreshCode(bossSecret));
  await Promise.all([page.waitForNavigation(), page.click('#totp-confirm')]);
  assert(await page.locator('#recovery-codes code').count() === 10, 'administrator enrols TOTP');
  await ctx.close();
  ctx = await browser.newContext();
  page = await ctx.newPage();
  await login(page, BOSS);
  assert(page.url().includes('/mfa/verify'), 'administrator is asked for the second step');
  r = await page.request.get(BASE + '/plugins/servlet/mfa/admin?user=' + BOSS.name, { maxRedirects: 0 });
  assert(r.status() === 302 && r.headers().location.includes('/mfa/verify'),
    `MFA admin page is not reachable before the second step (HTTP ${r.status()} ${r.headers().location || ''})`);
  r = await page.request.post(BASE + '/plugins/servlet/mfa/admin', {
    form: { action: 'reset', user: BOSS.name, csrf: 'x' }, maxRedirects: 0, headers: { Accept: 'text/html' },
  });
  assert(r.status() === 401 || r.status() === 302, `POST to the admin page is refused before the second step (HTTP ${r.status()})`);
  r = await page.request.get(BASE + '/rest/plugins/1.0/', { maxRedirects: 0 });
  assert(r.status() === 401, `UPM REST is refused before the second step (HTTP ${r.status()})`);
  await ctx.close();
  await adminApi('DELETE', '/rest/api/2/user?username=' + BOSS.name);

  // ---- 9c. recovery_admin (Jira recovery mode) is never challenged
  {
    ctx = await browser.newContext();
    page = await ctx.newPage();
    await login(page, { name: 'recovery_admin', pass: RECOVERY_PASS });
    assert(inJira(page), `recovery_admin reaches Jira in the browser without a second step (at ${page.url()})`);
    r = await page.request.get(BASE + '/plugins/servlet/mfa/admin', { maxRedirects: 0 });
    assert(r.status() === 200 || (r.status() === 302 && (r.headers().location || '').includes('WebSudo')),
      `recovery_admin can open the MFA admin page (HTTP ${r.status()})`);
    await ctx.close();
  }

  // ---- 10. Jira's cache prefix /s/<keys>/_/ opens only static resources --------------------
  await createUser(EVE);
  const ctxV = await browser.newContext(); // eve, verified
  const pageV = await ctxV.newPage();
  const eveSecret = await enrolTotp(pageV, EVE);
  // [path, Accept]; the control shows Jira serves each behind the prefix
  const cacheProbes = [['/s/1/_/secure/ViewProfile.jspa', 'text/html'], ['/s/1/_/rest/api/2/myself', 'application/json'],
    ['/s/1/_/secure/Dashboard.jspa', 'text/html']];
  for (const [probe, accept] of cacheProbes) {
    r = await pageV.request.get(BASE + probe, { maxRedirects: 0, headers: { Accept: accept } });
    const loc = r.headers().location || '';
    // Jira sends a user who has no dashboard yet to its welcome page
    const served = probe.includes('Dashboard') ? r.status() === 302 && loc.includes('/secure/WelcomeToJIRA.jspa')
      : r.status() === 200 && (await r.text()).includes(EVE.name);
    assert(served, `control: Jira answers ${probe} for a verified session (HTTP ${r.status()} ${loc})`);
  }
  let ctxU = await browser.newContext(); // eve, password only
  let pageU = await ctxU.newPage();
  await login(pageU, EVE);
  assert(pageU.url().includes('/mfa/verify'), 'eve is asked for the second step');
  for (const [probe, accept] of cacheProbes) {
    r = await pageU.request.get(BASE + probe, { maxRedirects: 0, headers: { Accept: accept } });
    const loc = r.headers().location || '';
    const blocked = (r.status() === 302 && loc.includes('/mfa/verify')) || r.status() === 401;
    assert(blocked && !(await r.text()).includes(EVE.name),
      `unverified session cannot open ${probe} behind the cache prefix (HTTP ${r.status()} ${loc})`);
  }
  {
    const anon = await browser.newContext();
    const ap = await anon.newPage();
    await ap.goto(BASE + '/login.jsp');
    const urls = await ap.evaluate(() => [...document.querySelectorAll('script[src], link[rel=stylesheet][href]')]
      .map((e) => e.getAttribute('src') || e.getAttribute('href')));
    await anon.close();
    const staticUrl = urls.find((u) => /\/s\/[^?]+\/_\/download\//.test(u));
    assert(!!staticUrl, `the login page references a static resource behind /s/…/_/download/ (${staticUrl})`);
    r = await pageU.request.get(new URL(staticUrl, BASE).toString(), { maxRedirects: 0 });
    const type = r.headers()['content-type'] || '';
    assert(r.status() === 200 && /javascript|css/.test(type),
      `unverified session still loads ${staticUrl} (HTTP ${r.status()} ${type})`);
  }

  // ---- 11. Basic header on top of a session -----------------------------------------------------
  // Seraph checks a Basic header on every request, also next to a session
  // cookie, and records the result as os_authstatus; the plugin treats the
  // request as Basic only when that result is "success".
  const eveBasic = { Authorization: basicAuth(EVE.name, EVE.pass), Accept: 'application/json' };
  r = await pageU.request.get(BASE + '/rest/api/2/myself', { headers: eveBasic, maxRedirects: 0 });
  let body = await r.text();
  assert(r.status() === 401 && body.includes('Password (Basic) authentication is disabled'),
    `unverified session + correct Basic password of an enrolled user who is not allow-listed gets the Basic refusal (HTTP ${r.status()})`);
  assert(await saveSettings({ basicAuthAllowedUsers: EVE.name }), 'administrator allow-lists eve for Basic auth');
  try {
    const wrongBasic = { Authorization: basicAuth(EVE.name, 'wrong-' + RUN), Accept: 'application/json' };
    r = await pageU.request.get(BASE + '/rest/api/2/myself', { headers: wrongBasic, maxRedirects: 0 });
    const h = r.headers();
    assert(r.status() !== 200 && !(await r.text()).includes(EVE.name),
      `unverified session + Basic with a wrong password is not served for an allow-listed user (HTTP ${r.status()}, `
      + `X-AUSERNAME ${h['x-ausername']}, X-Seraph-LoginReason ${h['x-seraph-loginreason']})`);
    // A verified session passes the filter's session check, so this is Jira's
    // own answer: the wrong-password case above holds without the plugin.
    r = await pageV.request.get(BASE + '/rest/api/2/myself', { headers: wrongBasic, maxRedirects: 0 });
    assert(r.status() === 401 && r.headers()['x-seraph-loginreason'] === 'AUTHENTICATED_FAILED',
      `control: Jira itself refuses a wrong Basic password even next to a verified session (HTTP ${r.status()}, `
      + `X-Seraph-LoginReason ${r.headers()['x-seraph-loginreason']})`);
    // with the correct password Seraph reports success, so the allow-list decides
    r = await pageU.request.get(BASE + '/rest/api/2/myself', { headers: eveBasic, maxRedirects: 0 });
    body = await r.text();
    assert(r.status() === 200 && body.includes(EVE.name),
      `unverified session + correct Basic password of an allow-listed enrolled user is served as Basic (HTTP ${r.status()})`);
    r = await pageU.request.get(BASE + '/rest/api/2/myself', { headers: { Accept: 'application/json' }, maxRedirects: 0 });
    assert(r.status() === 401, `the accepted Basic request did not verify the browser session (HTTP ${r.status()})`);

    const goodBasic = basicAuth(EVE.name, EVE.pass);
    const first = await fetch(BASE + '/rest/api/2/myself', {
      headers: { Authorization: goodBasic, Accept: 'application/json' }, redirect: 'manual',
    });
    const firstBody = await first.text();
    assert(first.status === 200 && firstBody.includes(EVE.name),
      `Basic without cookies works for an allow-listed enrolled user (HTTP ${first.status})`);
    // a script with a cookie jar sends the session the first Basic request created
    const jsession = first.headers.getSetCookie().map((c) => c.split(';')[0]).find((c) => c.startsWith('JSESSIONID='));
    assert(!!jsession, 'the cookie-less Basic request sets a JSESSIONID (as a cookie-jar script would keep it)');
    const second = await fetch(BASE + '/rest/api/2/myself', {
      headers: { Authorization: goodBasic, Accept: 'application/json', Cookie: jsession }, redirect: 'manual',
    });
    const secondBody = await second.text();
    assert(second.status === 200 && secondBody.includes(EVE.name),
      `a second Basic request reusing the session the first one created still works (HTTP ${second.status} ${second.status === 200 ? '' : secondBody})`);
  } finally {
    assert(await saveSettings({ basicAuthAllowedUsers: '' }), 'Basic allow-list emptied again');
  }

  // ---- 12. return target after the second step ------------------------------------------------
  r = await rawGet('/secure/ViewProfile.jspa', { Cookie: await cookieHeader(ctxU), Accept: 'text/html' });
  assert(r.status === 302 && (r.headers.location || '').includes('/mfa/verify'),
    `control: a page request of an unverified session goes to the second step (HTTP ${r.status} ${r.headers.location})`);
  let target = await verifyTotp(pageU, eveSecret);
  assert(!!target && new URL(target, BASE).pathname === '/secure/ViewProfile.jspa',
    `control: after the second step the interrupted page is opened (${target})`);
  await ctxU.close();
  ctxU = await browser.newContext();
  pageU = await ctxU.newPage();
  await login(pageU, EVE);
  r = await rawGet('/%09/evil.example', { Cookie: await cookieHeader(ctxU), Accept: 'text/html' });
  assert(r.status === 302 && (r.headers.location || '').includes('/mfa/verify'),
    `raw /%09/evil.example from an unverified session reaches the plugin's challenge (HTTP ${r.status} ${r.headers.location})`);
  target = await verifyTotp(pageU, eveSecret);
  const t = target ? new URL(target, BASE) : null;
  // Jira itself sends the dashboard of a user who has none yet on to its
  // welcome page (see the control in section 10), and rewrites the plugin's
  // redirect accordingly.
  assert(!!t && t.host === new URL(BASE).host && !target.includes('evil')
    && ['/secure/Dashboard.jspa', '/secure/WelcomeToJIRA.jspa'].includes(t.pathname),
    `after the second step a /%09/evil.example return target leads to the dashboard on Jira (Location ${target})`);
  assert(pageU.url().startsWith(BASE) && !pageU.url().includes('evil'), `the browser stays on Jira (at ${pageU.url()})`);
  await ctxU.close();
  await ctxV.close();

  // ---- 13. removing a factor or an admin reset ends other verified sessions -------------------
  await createUser(DAVE);
  const ctxA = await browser.newContext();
  const pageA = await ctxA.newPage();
  const cdpA = await ctxA.newCDPSession(pageA);
  await cdpA.send('WebAuthn.enable');
  await cdpA.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true },
  });
  const daveSecret = await enrolTotp(pageA, DAVE);
  const daveCodes = await pageA.locator('#recovery-codes code').allInnerTexts();
  await pageA.goto(BASE + '/plugins/servlet/mfa/setup');
  await pageA.fill('#passkey-label', 'Second key');
  await Promise.all([pageA.waitForNavigation(), pageA.click('#passkey-add')]);
  assert(await pageA.getByText('Second key').count() >= 1, 'dave adds a passkey as second factor');
  const ctxB = await browser.newContext();
  const pageB = await ctxB.newPage();
  await login(pageB, DAVE);
  assert(pageB.url().includes('/mfa/verify'), 'dave is asked for the second step in a second browser');
  await verifyTotp(pageB, daveSecret);
  assert(await myselfStatus(pageA) === 200 && await myselfStatus(pageB) === 200, 'both of dave\'s sessions are verified');
  // new recovery codes end the other verified session as well
  await pageA.goto(BASE + '/plugins/servlet/mfa/setup');
  await Promise.all([pageA.waitForNavigation(), pageA.click('#recovery-regenerate')]);
  const newDaveCodes = await pageA.locator('#recovery-codes code').allInnerTexts();
  assert(newDaveCodes.length === 10 && !newDaveCodes.some((c) => daveCodes.includes(c)),
    'dave creates new recovery codes in session A (ten, none of the old ones)');
  assert(await myselfStatus(pageA) === 200, 'the session that created new recovery codes stays verified');
  let s = await myselfStatus(pageB);
  assert(s === 401, `after new recovery codes the other verified session can no longer call REST (HTTP ${s})`);
  r = await pageB.request.get(BASE + '/secure/Dashboard.jspa', { maxRedirects: 0, headers: { Accept: 'text/html' } });
  assert(r.status() === 302 && (r.headers().location || '').includes('/mfa/verify'),
    `after new recovery codes the other session is sent to the second step (HTTP ${r.status()} ${r.headers().location || ''})`);
  await verifyTotp(pageB, daveSecret);
  assert(await myselfStatus(pageB) === 200, 'dave verifies session B again');
  await pageA.goto(BASE + '/plugins/servlet/mfa/setup');
  await Promise.all([pageA.waitForNavigation(), pageA.getByRole('button', { name: 'Remove authenticator app' }).click()]);
  assert(await pageA.getByText('Authenticator app removed.').count() === 1, 'dave removes the authenticator app in session A');
  assert(await myselfStatus(pageA) === 200, 'the session that removed the factor stays verified');
  s = await myselfStatus(pageB);
  assert(s === 401, `the other verified session can no longer call REST (HTTP ${s})`);
  r = await pageB.request.get(BASE + '/secure/Dashboard.jspa', { maxRedirects: 0, headers: { Accept: 'text/html' } });
  assert(r.status() === 302 && (r.headers().location || '').includes('/mfa/verify'),
    `the other session is sent to the second step again (HTTP ${r.status()} ${r.headers().location || ''})`);
  // session C: a fresh password login stopped at the second step, never verified
  const ctxC = await browser.newContext();
  const pageC = await ctxC.newPage();
  await login(pageC, DAVE);
  assert(pageC.url().includes('/mfa/verify'), 'dave logs in in a third browser and stops at the second step (passkey left)');
  // session R: a password login with "Remember my login"; only its remember-me cookie is kept
  let rememberCookie;
  {
    const ctxR = await browser.newContext();
    const pageR = await ctxR.newPage();
    await pageR.goto(BASE + '/login.jsp');
    await pageR.fill('#login-form-username', DAVE.name);
    await pageR.fill('#login-form-password', DAVE.pass);
    // the checkbox's label lies over it, so tick it as a user does, through the label
    await pageR.click('label[for=login-form-remember-me]');
    assert(await pageR.isChecked('#login-form-remember-me'), '"Remember my login" is ticked');
    await Promise.all([pageR.waitForNavigation(), pageR.click('#login-form-submit')]);
    rememberCookie = (await ctxR.cookies(BASE)).find((c) => c.name === 'seraph.rememberme.cookie');
    await ctxR.close();
  }
  assert(!!rememberCookie, 'a login with "Remember my login" sets the remember-me cookie');
  const rememberOnly = () => rawGet('/secure/Dashboard.jspa',
    { Cookie: 'seraph.rememberme.cookie=' + rememberCookie.value, Accept: 'text/html' });
  r = await rememberOnly();
  assert(r.status === 302 && (r.headers.location || '').includes('/mfa/verify'),
    `control: the remember-me cookie alone logs dave in before the reset (HTTP ${r.status} ${r.headers.location})`);
  assert(await adminReset(DAVE.name), 'administrator resets dave');
  r = await rememberOnly();
  {
    const loc = r.headers.location || '';
    const user = r.headers['x-ausername'];
    assert(!loc.includes('/plugins/servlet/mfa/') && user !== DAVE.name && !r.text.includes(DAVE.name),
      `after the admin reset the remember-me cookie alone does not log dave in (HTTP ${r.status} ${loc}, X-AUSERNAME ${user})`);
  }
  r = await rawGet('/rest/api/2/myself', { Cookie: 'seraph.rememberme.cookie=' + rememberCookie.value, Accept: 'application/json' });
  assert(r.status === 401 && !r.text.includes(DAVE.name),
    `after the admin reset the remember-me cookie alone gets no REST access (HTTP ${r.status})`);
  {
    // the first request of session C after the reset, as the browser sends it
    const res = await pageC.goto(BASE + '/plugins/servlet/mfa/setup');
    let first = res.request();
    while (first.redirectedFrom()) first = first.redirectedFrom();
    const firstRes = await first.response();
    const loc = (firstRes && firstRes.headers().location) || '';
    assert(firstRes && firstRes.status() === 302 && new URL(loc, BASE).pathname === '/login.jsp',
      `after the admin reset the never-verified session's GET of the setup page goes to the login page (HTTP ${firstRes && firstRes.status()} ${loc})`);
    assert(await pageC.locator('#totp-secret').count() === 0 && await pageC.locator('#login-form-username').count() === 1,
      `the never-verified session is shown the login form, not the enrolment page (at ${pageC.url()})`);
    await ctxC.close();
  }
  // The reset ends every session that existed before it, verified (A) or not (B).
  r = await pageA.request.get(BASE + '/secure/Dashboard.jspa', { maxRedirects: 0, headers: { Accept: 'text/html' } });
  assert(r.status() === 302 && (r.headers().location || '').includes('/login.jsp'),
    `after the admin reset the verified session is sent to the login page (HTTP ${r.status()} ${r.headers().location || ''})`);
  r = await pageB.request.get(BASE + '/plugins/servlet/mfa/setup', { maxRedirects: 0, headers: { Accept: 'text/html' } });
  assert(r.status() === 302 && (r.headers().location || '').includes('/login.jsp'),
    `after the admin reset an unverified session cannot reach enrolment (HTTP ${r.status()} ${r.headers().location || ''})`);
  s = await myselfStatus(pageA);
  assert(s === 401, `the ended session is no longer logged in for REST (HTTP ${s})`);
  {
    const fresh = await browser.newContext();
    const pageC = await fresh.newPage();
    await login(pageC, DAVE);
    assert(pageC.url().includes('/plugins/servlet/mfa/setup'), 'a new login after the reset is offered enrolment');
    await fresh.close();
  }
  await ctxA.close();
  await ctxB.close();

  // ---- 14. the admin status lookup does not start a grace period -----------------------------------
  await createUser(GINA);
  let cell = await graceCell(GINA.name);
  assert(cell === 'not started', `status of a user who never logged in: grace period "${cell}"`);
  cell = await graceCell(GINA.name);
  assert(cell === 'not started', `a second lookup still shows the grace period "${cell}"`);
  ctx = await browser.newContext();
  page = await ctx.newPage();
  await login(page, GINA);
  assert(page.url().includes('/mfa/setup') && await page.locator('#later').count() === 1, 'gina\'s first login offers enrolment');
  await ctx.close();
  cell = await graceCell(GINA.name);
  assert(cell !== 'not started' && cell.length > 0, `control: after her first login the grace period has started ("${cell}")`);

  // ---- 15. the first factor of a user who is not enforced ends "no factor needed" sessions -------
  assert(await saveSettings({ enforcedGroups: 'jira-administrators' }), 'administrator limits enforcement to jira-administrators');
  try {
    cell = await statusCell(ALICE.name, 'Second factor enforced');
    assert(cell === 'no', `alice (reset, no factor) is outside the enforced groups ("${cell}")`);
    const ctxN = await browser.newContext(); // session B: needs no factor
    const pageN = await ctxN.newPage();
    await login(pageN, ALICE);
    assert(inJira(pageN), `a user who is not enforced and has no factor reaches Jira without a second step (at ${pageN.url()})`);
    // this request caches "no second factor needed" in session B
    assert(await myselfStatus(pageN) === 200, 'session B of alice can call REST without a factor');
    const ctxE = await browser.newContext(); // session A: enrols the first factor
    const pageE = await ctxE.newPage();
    await enrolTotp(pageE, ALICE);
    assert(await myselfStatus(pageE) === 200, 'the enrolling session A is verified');
    r = await pageN.request.get(BASE + '/secure/Dashboard.jspa', { maxRedirects: 0, headers: { Accept: 'text/html' } });
    assert(r.status() === 302 && (r.headers().location || '').includes('/mfa/verify'),
      `after the first factor session B is sent to the second step on its next page view (HTTP ${r.status()} ${r.headers().location || ''})`);
    s = await myselfStatus(pageN);
    assert(s === 401, `after the first factor session B can no longer call REST (HTTP ${s})`);
    await ctxN.close();
    await ctxE.close();
  } finally {
    assert(await saveSettings({ enforcedGroups: '' }), 'enforced groups emptied again (all users)');
  }

  // ---- 16. a lockout survives a change of the attempt settings ------------------------------------
  ctx = await browser.newContext();
  page = await ctx.newPage();
  await login(page, EVE);
  assert(page.url().includes('/mfa/verify'), 'eve is asked for the second step');
  // the plugin's form token stays in the session; the locked page has no form
  const eveCsrf = await page.locator('input[name=csrf]').first().inputValue();
  for (let i = 0; i < 5; i++) {
    if (await page.locator('#code').count() === 0) break;
    await page.fill('#code', '000000');
    await Promise.all([page.waitForNavigation(), page.click('#verify-submit')]);
  }
  assert(await page.getByText('Too many failed attempts').count() === 1, 'five wrong codes lock eve\'s second step');
  cell = await statusCell(EVE.name, 'Locked until');
  assert(cell !== '-', `the admin status shows eve locked (until ${cell})`);
  try {
    assert(await saveSettings({ lockoutMinutes: '1' }), 'administrator changes the lockout duration to 1 minute');
    await page.goto(BASE + '/plugins/servlet/mfa/verify');
    assert(await page.getByText('Too many failed attempts').count() === 1 && await page.locator('#code').count() === 0,
      'after the settings change the verify page still reports eve locked');
    r = await page.request.post(BASE + '/plugins/servlet/mfa/verify', {
      form: { code: await nextFreshCode(eveSecret), csrf: eveCsrf }, maxRedirects: 0, headers: { Accept: 'text/html' },
    });
    assert(r.status() === 429, `a correct TOTP code is refused while the lockout lasts (HTTP ${r.status()})`);
    s = await myselfStatus(page);
    assert(s === 401, `eve's session is still not verified (HTTP ${s})`);
    cell = await statusCell(EVE.name, 'Locked until');
    assert(cell !== '-', `the admin status still shows eve locked (until ${cell})`);
  } finally {
    assert(await saveSettings({ lockoutMinutes: '15' }), 'lockout duration restored to 15 minutes');
  }
  await ctx.close();

  // ---- 17. user switch in one browser: pending enrolment values belong to their user ---------------
  ctx = await browser.newContext();
  page = await ctx.newPage();
  await login(page, CAROL);
  assert(page.url().includes('/mfa/setup'), 'carol (no factor) lands on enrolment');
  const carolKey = (await page.locator('#totp-secret').innerText()).trim();
  const carolCsrf = await page.locator('input[name=csrf]').first().inputValue();
  const jsessionOf = async (c) => ((await c.cookies(BASE)).find((k) => k.name === 'JSESSIONID') || {}).value;
  const carolJsession = await jsessionOf(ctx);
  await page.goto(BASE + '/login.jsp');
  const formShown = await page.locator('#login-form-username').count() === 1;
  console.log(`note - /login.jsp while logged in as carol: ${formShown ? 'the login form is shown' : 'no login form'} (at ${page.url()})`);
  await shot(page, 'e2e-17-login-over-session');
  if (formShown) {
    await page.fill('#login-form-username', GINA.name);
    await page.fill('#login-form-password', GINA.pass);
    await Promise.all([page.waitForNavigation(), page.click('#login-form-submit')]);
  } else {
    // the same form fields, posted directly
    r = await page.request.post(BASE + '/login.jsp', { form: { os_username: GINA.name, os_password: GINA.pass, login: 'Log In' } });
    console.log(`note - login.jsp POST for gina over carol's session: HTTP ${r.status()}`);
  }
  r = await page.request.get(BASE + '/rest/api/2/myself');
  const who = r.status() === 200 ? (await r.json()).name : null;
  assert(who === GINA.name, `logging in as gina over carol's session in the same browser switches the user (myself: ${who}, HTTP ${r.status()})`);
  if (!page.url().includes('/mfa/setup')) await page.goto(BASE + '/plugins/servlet/mfa/setup');
  const ginaKey = (await page.locator('#totp-secret').innerText()).trim();
  const ginaCsrf = await page.locator('input[name=csrf]').first().inputValue();
  const ginaJsession = await jsessionOf(ctx);
  if (ginaCsrf === carolCsrf) {
    assert(true, `control: the plugin's unbound form token carried over the re-login, so Jira copied the session attributes `
      + `(JSESSIONID ${ginaJsession !== carolJsession ? 'changed' : 'unchanged'})`);
  } else {
    console.log(`note - the plugin's form token did not carry over the re-login (JSESSIONID ${ginaJsession !== carolJsession ? 'changed' : 'unchanged'}); `
      + 'the key comparison below then does not exercise the user binding');
  }
  assert(/^[A-Z2-7]{32}$/.test(ginaKey) && ginaKey !== carolKey, 'gina\'s setup page shows a different manual key than carol\'s');
  await page.fill('#totp-code', await nextFreshCode(carolKey));
  await Promise.all([page.waitForNavigation(), page.click('#totp-confirm')]);
  assert(await page.getByText('That code does not match').count() === 1 && await page.locator('#recovery-codes code').count() === 0,
    'a code from carol\'s pending key does not enrol gina');
  await ctx.close();

  // ---- 9. audit log -------------------------------------------------------------------------
  a = await adminApi('GET', '/rest/auditing/1.0/events?limit=200');
  if (a.status === 200) {
    const actions = a.json().entities.map((e) => e.type && e.type.actionI18nKey).filter(Boolean);
    for (const want of ['totp_enrolled', 'second_step_succeeded', 'second_step_failed', 'recovery_code_used',
      'locked_out', 'admin_reset', 'passkey_registered', 'basic_auth_rejected'].map((k) => 'de.netresearch.jira.mfa.audit.' + k)) {
      assert(actions.includes(want), 'audit log has "' + want + '"');
    }
  } else {
    console.log('note - audit REST answered HTTP ' + a.status + '; audit entries not checked via REST');
    failed = true;
  }
} catch (e) {
  failed = true;
  console.error(e);
} finally {
  for (const u of [ALICE, BOB, CAROL, DAVE, EVE, GINA]) {
    await adminApi('DELETE', '/rest/api/2/user?username=' + u.name);
  }
  await browser.close();
}
if (failed) {
  console.error('E2E FAILED');
  process.exit(1);
}
console.log('E2E PASSED');
