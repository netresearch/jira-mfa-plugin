// End-to-end test of the MFA plugin in a real headless Chromium against a
// running Jira with the plugin installed.
// Env: JIRA_BASE_URL, JIRA_ADMIN_USER/PASS, JIRA_ADMIN_PAT (admin token for setup calls),
//      JIRA_RECOVERY_PASS (recovery_admin password; changes settings and is checked itself).
import { authenticator } from 'otplib';
import { launch, shot, assert, basicAuth, BASE, ADMIN_USER, ADMIN_PASS } from './lib.mjs';

authenticator.options = { digits: 6, step: 30, window: 0 };
const ADMIN_PAT = process.env.JIRA_ADMIN_PAT;
if (!ADMIN_PAT) throw new Error('JIRA_ADMIN_PAT is required');
const RECOVERY_PASS = process.env.JIRA_RECOVERY_PASS;
if (!RECOVERY_PASS) throw new Error('JIRA_RECOVERY_PASS is required');
const RUN = Date.now().toString(36);
const ALICE = { name: 'alice' + RUN, pass: 'Alice-Pass-' + RUN };
const BOB = { name: 'bob' + RUN, pass: 'Bob-Pass-' + RUN };
const CAROL = { name: 'carol' + RUN, pass: 'Carol-Pass-' + RUN };

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

// Changes plugin settings through the admin form as recovery_admin, who is
// never challenged and so is unaffected by a grace period of 0 days.
async function saveSettings(fields) {
  const c = await browser.newContext();
  const p = await c.newPage();
  try {
    await login(p, { name: 'recovery_admin', pass: RECOVERY_PASS });
    await p.goto(BASE + '/plugins/servlet/mfa/admin');
    if (p.url().includes('WebSudo')) {
      await p.fill('#login-form-authenticatePassword', RECOVERY_PASS);
      await Promise.all([p.waitForNavigation(), p.click('#login-form-submit')]);
      if (!p.url().includes('/mfa/admin')) await p.goto(BASE + '/plugins/servlet/mfa/admin');
    }
    for (const [id, value] of Object.entries(fields)) await p.fill('#' + id, value);
    await Promise.all([p.waitForNavigation(), p.click('#save-settings')]);
    return (await p.locator('#admin-message').innerText()).includes('Settings saved');
  } finally {
    await c.close();
  }
}

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
  await shot(page, 'e2e-02-enrolled');
  await page.goto(BASE + '/secure/Dashboard.jspa');
  assert(inJira(page), 'the enrolling session counts as verified');
  await ctx.close();

  // ---- 3. second step required on next login ---------------------------------
  ctx = await browser.newContext();
  page = await ctx.newPage();
  await login(page, ALICE);
  assert(page.url().includes('/plugins/servlet/mfa/verify'), 'enrolled user is sent to the second step after the password');
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
    '/plugins/servlet/mfa/admin']) {
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
  for (const u of [ALICE, BOB, CAROL]) {
    await adminApi('DELETE', '/rest/api/2/user?username=' + u.name);
  }
  await browser.close();
}
if (failed) {
  console.error('E2E FAILED');
  process.exit(1);
}
console.log('E2E PASSED');
