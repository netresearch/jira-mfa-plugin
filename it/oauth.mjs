// OAuth 1.0a (RSA-SHA1) client for the integration tests: an incoming
// application link in Jira, and requests signed as that link's consumer, the
// way clients such as the TimeTracker call Jira on behalf of a user.
import crypto from 'node:crypto';
import { BASE } from './lib.mjs';

// RFC 3986 percent-encoding as OAuth 1.0a requires (section 3.6).
const enc = (s) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());

export function consumer(key) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const der = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  return { key, privateKey, publicKeyBase64: der };
}

// The Authorization header for one request. extra holds further oauth_*
// parameters (oauth_token, oauth_verifier, oauth_callback).
export function authorization(c, method, url, extra = {}) {
  const u = new URL(url);
  const oauth = {
    oauth_consumer_key: c.key,
    oauth_nonce: crypto.randomBytes(16).toString('hex'),
    oauth_signature_method: 'RSA-SHA1',
    oauth_timestamp: Math.floor(Date.now() / 1000).toString(),
    oauth_version: '1.0',
    ...extra,
  };
  const params = [...u.searchParams.entries(), ...Object.entries(oauth)]
    .map(([k, v]) => [enc(k), enc(v)])
    .sort((a, b) => (a[0] === b[0] ? (a[1] < b[1] ? -1 : 1) : a[0] < b[0] ? -1 : 1))
    .map(([k, v]) => k + '=' + v).join('&');
  const baseString = [method.toUpperCase(), enc(u.origin + u.pathname), enc(params)].join('&');
  oauth.oauth_signature = crypto.sign('RSA-SHA1', Buffer.from(baseString), c.privateKey).toString('base64');
  return 'OAuth ' + Object.entries(oauth).map(([k, v]) => `${enc(k)}="${enc(v)}"`).join(', ');
}

// A signed request; returns status and body.
export async function signed(c, method, path, extra = {}, headers = {}) {
  const url = BASE + path;
  const r = await fetch(url, {
    method,
    headers: { Accept: 'application/json', ...headers, Authorization: authorization(c, method, url, extra) },
    redirect: 'manual',
  });
  return { status: r.status, text: await r.text() };
}

// Creates a generic application link with an incoming OAuth consumer, as an
// administrator sets one up for the TimeTracker. adminApi(method, path, body)
// sends an authenticated administrator request. Returns the link id.
export async function createIncomingLink(adminApi, c, name) {
  const linkUrl = 'https://' + name + '.example.com';
  let r = await adminApi('POST', '/rest/applinks/1.0/applicationlinkForm/createAppLink', {
    applicationLink: { typeId: 'generic', name, rpcUrl: linkUrl, displayUrl: linkUrl, isPrimary: false },
    username: '', password: '', createTwoWayLink: false, customRpcURL: false, rpcUrl: linkUrl,
    configFormValues: { trustEachOther: false, shareUserbase: false },
  });
  if (r.status !== 200 && r.status !== 201) throw new Error(`application link not created (HTTP ${r.status} ${r.text.slice(0, 300)})`);
  const id = r.json().applicationLink.id;
  r = await adminApi('PUT', `/rest/applinks-oauth/1.0/applicationlink/${id}/authentication/consumer?autoConfigure=false`, {
    key: c.key, name, publicKey: c.publicKeyBase64, description: 'jira-mfa-plugin integration test',
    callback: '', twoLOAllowed: false, executingTwoLOUser: '', twoLOImpersonationAllowed: false, outgoing: false,
  });
  if (r.status !== 200 && r.status !== 201) throw new Error(`incoming consumer not configured (HTTP ${r.status} ${r.text.slice(0, 300)})`);
  return id;
}

export const formField = (body, name) => new URLSearchParams(body).get(name);
