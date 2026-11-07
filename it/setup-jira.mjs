// Drives the Jira 9.12 setup wizard of a fresh container (built-in database,
// application properties, timebomb licence, administrator, no mail) as a
// state machine, so it can resume at whichever step Jira is on.
// Usage: node setup-jira.mjs <licence-file>
import fs from 'node:fs';
import { launch, shot, BASE, ADMIN_USER, ADMIN_PASS } from './lib.mjs';

const licence = fs.readFileSync(process.argv[2], 'utf8').trim();
const browser = await launch();
const page = await browser.newPage();
page.setDefaultTimeout(30000);

async function submitAndLeave(selector, urlPart) {
  await Promise.all([
    page.waitForURL((u) => !u.toString().includes(urlPart), { timeout: 900000 }),
    page.locator(selector).first().click(),
  ]);
  await page.waitForLoadState('domcontentloaded');
}

try {
  await page.goto(BASE + '/', { timeout: 900000 });
  for (let i = 0; i < 12; i++) {
    const url = page.url();
    console.log('step ' + i + ': ' + url);
    await shot(page, 'setup-' + i);
    if (url.includes('SetupMode')) {
      await page.getByText("I'll set it up myself").click();
      // the mode page has no #jira-setupwizard-submit; its button reads "Next" once a mode is chosen
      await submitAndLeave('form button[type=submit], form input[type=submit]', 'SetupMode');
    } else if (url.includes('SetupDatabase')) {
      await submitAndLeave('#jira-setup-database-submit', 'SetupDatabase');
    } else if (url.includes('SetupApplicationProperties')) {
      await page.fill('input[name="title"]', 'Jira MFA test');
      await page.fill('input[name="baseURL"]', BASE);
      await submitAndLeave('#jira-setupwizard-submit', 'SetupApplicationProperties');
    } else if (url.includes('SetupLicense')) {
      await page.fill('#licenseKey', licence);
      await submitAndLeave('#setupLicenseForm [type=submit], form [type=submit]', 'SetupLicense');
    } else if (await page.getByText('Set up email notifications').count()) {
      // the mail step is rendered under the SetupAdminAccount URL
      await Promise.all([
        page.waitForURL((u) => !/Setup/.test(u.toString()), { timeout: 900000 }),
        page.getByRole('button', { name: 'Finish' }).click(),
      ]);
    } else if (url.includes('SetupAdminAccount')) {
      await page.fill('input[name="fullname"]', 'Test Admin');
      await page.fill('input[name="email"]', 'admin@example.com');
      await page.fill('input[name="username"]', ADMIN_USER);
      await page.fill('input[name="password"]', ADMIN_PASS);
      await page.fill('input[name="confirm"]', ADMIN_PASS);
      await page.locator('#jira-setupwizard-submit').click();
      // the next (mail) step keeps the SetupAdminAccount URL, so wait for its content
      await page.getByText('Set up email notifications').waitFor({ timeout: 900000 });
    } else if (url.includes('SetupMailNotifications')) {
      await submitAndLeave('#jira-setupwizard-submit', 'SetupMailNotifications');
    } else if (url.includes('/Setup')) {
      await page.waitForTimeout(5000);
      await page.goto(BASE + '/');
    } else {
      console.log('setup finished at ' + url);
      break;
    }
    const errs = await page.locator('.aui-message-error, .error').allInnerTexts();
    if (errs.some((e) => e.trim())) console.log('page errors: ' + JSON.stringify(errs));
  }
} catch (e) {
  await shot(page, 'setup-error');
  console.error('failed at ' + page.url());
  throw e;
} finally {
  await browser.close();
}
