# Netresearch Jira MFA

A Jira Server / Data Center 9.12 app that makes a second factor mandatory for browser logins. After the normal password (LDAP/AD or internal directory) login, a browser session must confirm one of:

- a code from an authenticator app (TOTP, RFC 6238: SHA-1, 6 digits, 30 seconds),
- a passkey or hardware security key (WebAuthn),
- a one-time recovery code.

Until it does, Jira serves nothing but the plugin's own pages, static resources and logout. Users without a factor are sent to enrolment, during a configurable grace period (default 14 days) with a "Remind me later" option, after it without one.

Built for Jira Software 9.12.3 (compiled for Java 11) and tested against it on Java 17 and on Java 11, with a Server and with a Data Center licence.

## How it works

| Part | Implementation |
|---|---|
| Enforcement | Servlet filter module at `before-dispatch` on `/*`. At that point Seraph and the token filters have identified the user, so the plugin needs no change to Jira's `seraph-config.xml` (a custom Seraph authenticator would). |
| Session state | A verified session carries the user key and the time of verification in a session attribute; the session ID is rotated on verification. Removing a factor, creating new recovery codes or an admin reset ends every other verified session of that user (the session that made the change stays verified); enrolling the first factor ends other sessions that were let through because no factor was needed. A new session, including one created by the "remember me" cookie, must verify again (tested: a request with only the remember-me cookie is sent to the plugin's page). |
| TOTP | Codes from [java-otp](https://github.com/jchambers/java-otp); one step of clock drift either way; a code from an already used step is rejected (replay). |
| Passkeys | [Yubico java-webauthn-server](https://github.com/Yubico/java-webauthn-server) does all parsing and signature checks. Relying party ID = host of the Jira base URL (configurable), origin = base URL. ES256 and RS256. Non-discoverable credentials, user verification preferred. |
| Storage | Active Objects tables `AO_..._USER_STATE`, `..._PASSKEY`, `..._RECOVERY_CODE` (namespace `NRMFA`). TOTP secrets are AES-256-GCM encrypted. |
| Encryption key | `$JIRA_HOME/data/mfa/secret.key`, created on first use with mode 600. **It is part of the backup.** Without it, every stored TOTP secret is unreadable. The plugin then does not create a new key while TOTP secrets exist: TOTP codes are refused (logged as an error), recovery codes and passkeys still work, TOTP users without either must be reset, and nobody can add an authenticator app until the file is restored or every TOTP user is reset. Restoring the right file brings TOTP back without a restart (the key is read again after a failed decryption). |
| Recovery codes | 10 codes of 10 characters (50 bits each), stored as salted PBKDF2-HMAC-SHA256 hashes, deleted when used. Issued automatically with the first factor. |
| Rate limiting | 5 second-step attempts within 15 minutes that do not succeed lock the second step for 15 minutes (both configurable). An attempt is counted when it starts, so parallel requests cannot test more codes than the limit. In memory, per node; a restart clears it. |
| Audit | Enrolment, removal, success, failure, lockout, recovery-code use, admin reset, settings change and rejected Basic authentication go to Jira's audit log (category "Multi-factor authentication", area Security) and to the logger `de.netresearch.jira.mfa.audit`. |

### Requests that are not browser sessions

- **Personal access tokens** (`Authorization: Bearer`) pass without a second step. The plugin recognises a token login by the request attribute `access.token.request`, which Jira's bundled `pats-plugin` sets only after a valid token. The header alone is not trusted: Jira serves a request that carries a valid session cookie and an invalid Bearer token as the session user, so header-based skipping would let a password-only session through.
- **HTTP Basic authentication** (username and password on REST) bypasses the second factor, so it ends when the second factor becomes binding for a user (see "Basic authentication and the grace period" below). A refused request gets `401` and a hint to use a personal access token. A Basic request counts as Basic only when Seraph accepted the header's password in that same request (request attribute `os_authstatus` = `success`; Seraph checks a Basic header on every request, also when a session cookie is sent). With a wrong password the user may still come from a session or remember-me cookie; such a request is treated as a session request.
- **Cookie sessions created through `/rest/auth/1/session`** are ordinary sessions and must verify like a browser login (API calls get `401` JSON).
- **Incoming mail handlers and other background jobs** do not pass through the servlet filter and are not affected.
- **OAuth (application links)**: not exempted. See "Open risks".

### Basic authentication and the grace period

| User state | Basic authentication |
|---|---|
| Not enforced and no factor | allowed |
| Enforced, no factor, grace period running | allowed, so existing scripts keep working while people enrol |
| Enforced, no factor, grace period expired | refused |
| Has a factor (TOTP or passkey), also during the grace period | refused |
| On the Basic allow-list (service accounts), or policy set to "Allow" | allowed |

Refusing Basic as soon as a user has enrolled is deliberate: if the password alone still opened the REST API, the factor would not protect against a leaked password. An enrolled user can create a personal access token from a verified browser session (*Profile > Personal Access Tokens*).

## Build

The host needs only Docker. Maven runs in `maven:3.9.9-eclipse-temurin-11` (the Atlassian public repository is declared in `pom.xml`) and a local repository in `~/.cache/jira-mfa-m2` (override with `MAVEN_CACHE`), which the script creates:

```bash
build/mvn.sh -B package          # runs the unit tests
ls target/jira-mfa-plugin-*.jar
```

Host versions are pinned in `pom.xml` to what Jira 9.12.3 ships (Active Objects 5.0.3, SAL 5.0.3, audit API 1.15.1, Spring Scanner 3.0.3). The WebAuthn library and its Jackson, Guava and CBOR dependencies are embedded in the jar and not imported from Jira.

## Install

1. Back up the database and `$JIRA_HOME`.
2. Start Jira with the recovery account configured, so a way in exists that never needs a second factor (see "Lockout and emergencies"), or make sure you know how to set it.
3. Upload the jar in *Administration > Manage apps > Upload app*. Uploading must be enabled (`-Dupm.plugin.upload.enabled=true` on Jira 9.x). Alternatively use `it/install-plugin.sh <jar>` (UPM REST API; needs Basic authentication of an administrator, because UPM did not issue its upload token to a personal access token in the test). Once an administrator has enrolled or the grace period has expired, Basic authentication of that administrator is refused; use `recovery_admin` (recovery mode) or an allow-listed administrator for scripted updates.
4. Open *Administration > System > Security > Two-step verification* (`/plugins/servlet/mfa/admin`) and review the settings before users log in. The plugin is **active immediately after installation** with the defaults below.

### Settings

| Setting | Default | Notes |
|---|---|---|
| Active | on | Off = no checks at all. |
| Groups that must use a second factor | empty = all users | One group per line. Users outside these groups are not forced, but once they enrol they are always challenged. |
| Exempt groups / exempt users | empty | Never challenged, even with a factor. Use for emergencies, not as a standing policy. |
| Grace period | 14 days | Counted from the first request at which the user is enforced and has no factor. Users who become enforced later, for example when the group list is widened, get the full period from then. A grace period that has started is not restarted by leaving and re-entering an enforced group; removing one's last factor (possible only while not enforced) or an admin reset clears it, and it starts again at the next request as an enforced user. 0 = enrol at the next login. |
| HTTP Basic authentication | Block | Block for users who have a factor or whose grace period has expired. |
| Users still allowed to use Basic | empty | Service accounts and scripts that cannot use a token yet. `*` allows everyone. |
| Passkey relying party ID | empty = base URL host | Changing it invalidates every registered passkey. |
| Name shown in authenticator apps | `Jira` | Issuer in the otpauth URI. |
| Failed attempts / lockout minutes | 5 / 15 | |

## Use

- Users manage their factors at *Profile menu > Two-step verification* (`/plugins/servlet/mfa/setup`): add an authenticator app (QR code or manual key), add passkeys or security keys, remove factors (the last factor of an enforced user cannot be removed) and create new recovery codes.
- A session that has not passed the second step can open the setup page only while the user has no factor at all. Otherwise somebody holding only the password could add their own authenticator.

## Lockout and emergencies

### A user lost their phone or key

1. If the user still has recovery codes: they enter one instead of the TOTP code and then add a new factor and create new recovery codes on the setup page.
2. Otherwise an administrator opens `/plugins/servlet/mfa/admin`, looks up the username and presses *Remove all second factors*. That deletes the user's TOTP secret, passkeys and recovery codes, clears a lockout and ends every session verified with the old factors. Personal access tokens are not touched: revoke the user's tokens as well, or a token created from a session verified with the lost factor keeps working. The grace period starts again at the user's next request (if the user is enforced), so the user can log in with the password and enrol again. Confirm the user's identity out of band before resetting: the reset reduces the account to its password.

### A user is locked out after failed attempts

Wait for the lockout period (default 15 minutes), or have an administrator reset the user (which also removes the factors), or restart Jira (the counter is in memory). If the user did not make the failed attempts, someone else knows the password: change the password first. A reset without a password change hands the account to whoever enrols first.

### All administrators are locked out

Use Jira's recovery mode, which the plugin honours:

1. Stop Jira and add `-Datlassian.recovery.password=<a long random password>` to `JVM_SUPPORT_RECOMMENDED_ARGS` (`bin/setenv.sh`, or the Docker environment variable).
2. Start Jira and log in as `recovery_admin` with that password. The plugin never challenges `recovery_admin` while that system property is set.
3. Fix the situation: reset an administrator's factors on the MFA admin page, add an exempt user, uncheck *Active*, or disable the app in *Manage apps*.
4. Remove the system property and restart.

### Disable the plugin without logging in

- **Remove the jar (tested):** stop Jira, delete `$JIRA_HOME/plugins/installed-plugins/plugin_<number>_jira-mfa-plugin-<version>.jar`, start Jira. In the test the plugin was gone afterwards and password logins worked without a second step. The Active Objects tables and `$JIRA_HOME/data/mfa/secret.key` stay; reinstalling restores the previous state.
- **Recovery mode (tested):** see above; `recovery_admin` can disable the app in *Manage apps* or uncheck *Active* on the MFA admin page.
- **Safe mode** (*Manage apps > Enter safe mode*) disables every user-installed app, this one included. It needs an administrator session, so use recovery mode first if no administrator can log in. Not tested.
- **Disable at startup (Server licence only):** `-Datlassian.plugins.startup.options="--disable-addons=de.netresearch.jira.jira-mfa-plugin"` ([Atlassian: Start and stop Jira applications](https://confluence.atlassian.com/adminjiraserver0900/start-and-stop-jira-applications-1142255793.html)). Atlassian states that it "does not work for Jira Data Center applications", and on the Data-Center-licensed test instance the plugin indeed stayed enabled. Untested with a Server licence; prefer removing the jar.

Disabling the plugin removes the second factor for everybody. Basic authentication is then accepted again.

## Tests

- **Unit tests** (`build/mvn.sh -B test`): RFC 6238 test vectors, drift window and replay rejection, recovery code generation, normalisation and hashing, the attempt limiter (including parallel attempts), the enforcement policy, request classification (including Jira's `/s/` cache prefix), the verified-session mark, the passkey origin and the AES-GCM key handling (including a missing key file and a leftover temporary file).
- **Integration test** (`it/`) against `atlassian/jira-software:9.12.3` in Docker, driven by headless Chromium (Playwright) and `otplib` as an independent TOTP implementation:

```bash
docker network create jira-mfa-net
docker volume create jira-mfa-home
docker run -d --name jira-mfa-jira --network jira-mfa-net -p 127.0.0.1:18080:8080 \
  -v jira-mfa-home:/var/atlassian/application-data/jira \
  -e JVM_SUPPORT_RECOMMENDED_ARGS="-Dupm.plugin.upload.enabled=true -Datlassian.recovery.password=<secret>" \
  atlassian/jira-software:9.12.3
cd it && npm ci
node setup-jira.mjs <file with a timebomb licence>   # setup wizard
./install-plugin.sh ../target/jira-mfa-plugin-*.jar
JIRA_ADMIN_PAT=<admin token> JIRA_RECOVERY_PASS=<secret> node e2e.mjs
```

Not covered by the automated tests: the last-factor rule, exempt groups and users, OAuth/application links, Service Management and the mobile app.

Licences come from [Atlassian's timebomb licences](https://developer.atlassian.com/platform/marketplace/timebomb-licenses-for-testing-server-apps/): the "10 user Jira Software Data Center license, expires in 3 hours", or for a Server licence the "10 user starter non-eval host product license, expires in 3 hours" (Jira reports it as `dataCenter: false`, type Starter). For a Java 11 runtime use the image tag `9.12.3-jdk11`; the plain `9.12.3` tag runs Java 17. `e2e.mjs` covers: grace-period offer and postponement, TOTP enrolment with QR code and manual key, recovery codes issued, second step after the next login, wrong code, replayed code, REST blocked for an unverified session (also with a garbage Bearer header), personal access token accepted, Basic authentication allowed during the grace period and refused after enrolment, after the grace period expired (set to 0 days through the admin form) and accepted again for an allow-listed user, recovery code use and single use, lockout after five failures, admin reset behind websudo, an enrolled administrator unable to reach the MFA admin page or UPM before the second step, passkey registration and login with a Chromium virtual authenticator (CDP `WebAuthn.addVirtualAuthenticator`), rejection of an unknown authenticator, "Log out" from the verify page, `recovery_admin` reaching Jira without a second step, blocked deep links and path tricks (`/browse/…`, attachments, `%2e%2e` and `..;` traversal behind an open prefix, pages and REST behind Jira's `/s/…/_/` cache prefix), Basic with and without a session cookie (correct and wrong password, allow-listed or not), a return target with a tab character, removing a factor and creating new recovery codes ending the user's other verified sessions, an admin reset sending the user back to enrolment, a not-enforced user's other session being challenged after the first factor, a lockout surviving a settings change, the grace period not started by an admin lookup, another user logging in over a session not seeing the previous user's pending TOTP key, and the audit log entries.

## Open risks for a production rollout

- **Licence type and Jira's own Basic block.** `/rest/api/2/serverInfo` reports `deploymentType: Server` with both licence types; *Versions & licenses* shows which one is installed. Jira 9.12.3 also ships a global Basic-authentication block ([Atlassian: allowlist when basic authentication is disabled](https://confluence.atlassian.com/enterprise/creating-an-allowlist-when-basic-authentication-is-disabled-1044106574.html)). Atlassian documents it for Data Center, but in the test it also worked with a Server (starter) licence: after `PUT /rest/basicauth/1.0/config` with `block-requests: true`, Basic requests got `403` and allow-listed users still passed. That switch applies to everybody at once; this plugin's rule follows each user's grace period and enrolment. If both are active, a Basic request has to pass both.
- **Basic authentication stops per user at enrolment or at the end of the grace period.** Scripts running under a personal account break when that person enrols. Every refused Basic request writes an audit event; a misconfigured script polling Jira fills the audit log (an install script polling every two seconds produced 62 events in two minutes in the test).
- **Lockout.** Every enforced user who loses the factor and the recovery codes needs an administrator. Keep at least two administrators enrolled with two factors each, and store the recovery-mode password in your secrets manager before rollout.
- **Basic authentication users.** Scripts, CI jobs and integrations that log in with a password stop working for enforced users at the latest when the grace period ends. Inventory them (Jira access log, `X-AUSERNAME` with Basic) before enabling, switch them to personal access tokens or allow-list the service accounts.
- **Application links (OAuth 1.0a), Jira mobile app, Service Management portal, Confluence/Bitbucket integrations:** not tested; the test image contains neither Service Management nor linked applications. OAuth-authenticated requests are not exempted, so a Jira macro in Confluence acting as an enforced user may be refused. Customer accounts of the Service Management portal are treated like all other users (the portal's own login page leads to the plugin's verify/setup page); exempt the customer group if they should not need a second factor.
- **Personal access tokens are not revoked by enrolment or reset.** A token passes without a second step. Whoever had the password while the user had no factor (grace period, or not enforced) could have created one, through the browser, or through Basic (during the grace period or while not enforced); it keeps working after the user enrols. Revoke a user's tokens after enrolment or reset when the password may have leaked.
- **PAT detection is coupled to `pats-plugin` internals** (`access.token.request`, verified in `pats-plugin` 1.4.5 of Jira 9.12.3). If a Jira upgrade changes it, token requests are challenged (fail closed) rather than let through; re-test after upgrades.
- **Data Center clusters:** the attempt limiter is per node, and another node notices saved settings, a removed factor or an admin reset up to 30 seconds late (sessions verified there stay valid that long). Fine for a single node.
- **Settings take effect with a delay of up to 5 minutes for running sessions of users who needed no second factor**: that result is cached in the session to avoid database reads on every request. New logins see changes immediately.
- **Concurrent use of one TOTP code:** replay protection is a read-then-write per user, so two requests with the same code in the same instant can both succeed.
