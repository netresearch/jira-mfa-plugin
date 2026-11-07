// Shared helpers for the browser integration tests.
import { chromium } from 'playwright-core';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

export const BASE = process.env.JIRA_BASE_URL || 'http://localhost:18080';
export const ADMIN_USER = process.env.JIRA_ADMIN_USER || 'admin';
export const ADMIN_PASS = process.env.JIRA_ADMIN_PASS || 'admin-Pass-4886';
export const OUT = process.env.IT_OUT || path.join(process.cwd(), 'out');

export function chromiumPath() {
  if (process.env.CHROMIUM_PATH) return process.env.CHROMIUM_PATH;
  const root = path.join(os.homedir(), '.cache', 'ms-playwright');
  const dirs = fs.readdirSync(root).filter((d) => /^chromium-\d+$/.test(d))
    .sort((a, b) => Number(a.split('-')[1]) - Number(b.split('-')[1]));
  if (!dirs.length) throw new Error('no chromium under ' + root);
  return path.join(root, dirs[dirs.length - 1], 'chrome-linux64', 'chrome');
}

export async function launch() {
  fs.mkdirSync(OUT, { recursive: true });
  return chromium.launch({ headless: true, executablePath: chromiumPath() });
}

export async function shot(page, name) {
  await page.screenshot({ path: path.join(OUT, name + '.png'), fullPage: true });
}

export function assert(cond, msg) {
  if (!cond) throw new Error('ASSERTION FAILED: ' + msg);
  console.log('ok - ' + msg);
}

export function basicAuth(user, pass) {
  return 'Basic ' + Buffer.from(user + ':' + pass).toString('base64');
}
