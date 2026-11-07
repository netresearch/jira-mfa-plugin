package de.netresearch.jira.mfa.service;

import com.atlassian.jira.user.ApplicationUser;
import de.netresearch.jira.mfa.ao.MfaRecoveryCode;
import de.netresearch.jira.mfa.ao.MfaUser;
import de.netresearch.jira.mfa.core.AttemptLimiter;
import de.netresearch.jira.mfa.core.EnforcementPolicy;
import de.netresearch.jira.mfa.core.EnforcementPolicy.Requirement;
import de.netresearch.jira.mfa.core.MfaSettings;
import de.netresearch.jira.mfa.core.RecoveryCodes;
import de.netresearch.jira.mfa.core.SecretCipher;
import de.netresearch.jira.mfa.core.Totp;
import de.netresearch.jira.mfa.core.VerifiedMark;

import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.OptionalLong;
import java.util.concurrent.ConcurrentHashMap;

/** Second-factor business logic shared by the filter and the servlets. */
@Named
public class MfaService {
    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(MfaService.class);
    public static final String S_VERIFIED = "de.netresearch.jira.mfa.verified";
    public static final String S_GRACE_ACK = "de.netresearch.jira.mfa.graceAck";
    public static final String S_PENDING_TOTP = "de.netresearch.jira.mfa.pendingTotp";
    public static final String S_REG_REQUEST = "de.netresearch.jira.mfa.regRequest";
    public static final String S_AUTH_REQUEST = "de.netresearch.jira.mfa.authRequest";
    public static final String S_CSRF = "de.netresearch.jira.mfa.csrf";
    public static final String S_RETURN = "de.netresearch.jira.mfa.return";

    public enum VerifyOutcome { OK, WRONG, LOCKED }

    private final MfaStore store;
    private final SettingsStore settings;
    private final JiraEnvironment env;
    private final AuditLogger audit;
    private final PasskeyService passkeys;
    private final Totp totp = new Totp();
    private final RecoveryCodes recoveryCodes = new RecoveryCodes();
    private final SecureRandom random = new SecureRandom();
    private final Clock clock = Clock.systemUTC();
    private volatile SecretCipher cipher;
    private volatile AttemptLimiter limiter;
    private volatile String limiterConfig = "";
    /** user key -> {factors changed, cached at} */
    private final Map<String, long[]> factorsChanged = new ConcurrentHashMap<>();

    @Inject
    public MfaService(MfaStore store, SettingsStore settings, JiraEnvironment env, AuditLogger audit, PasskeyService passkeys) {
        this.store = store;
        this.settings = settings;
        this.env = env;
        this.audit = audit;
        this.passkeys = passkeys;
    }

    public MfaSettings settings() {
        return settings.get();
    }

    private SecretCipher cipher() {
        SecretCipher c = cipher;
        if (c == null) {
            synchronized (this) {
                if (cipher == null) {
                    try {
                        cipher = SecretCipher.fromKeyFile(env.keyFile(), store.countEnrolledUsers() == 0);
                    } catch (IOException e) {
                        throw new UncheckedIOException("cannot read or create MFA key file " + env.keyFile(), e);
                    }
                }
                c = cipher;
            }
        }
        return c;
    }

    private AttemptLimiter limiter() {
        MfaSettings s = settings.get();
        String cfg = s.maxFailures + "/" + s.lockoutMinutes;
        if (limiter == null || !cfg.equals(limiterConfig)) {
            synchronized (this) {
                if (limiter == null) {
                    limiter = new AttemptLimiter(s.maxFailures, Duration.ofMinutes(s.lockoutMinutes),
                            Duration.ofMinutes(s.lockoutMinutes), clock);
                    limiterConfig = cfg;
                } else if (!cfg.equals(limiterConfig)) {
                    // keep running lockouts: a settings change must not lift them
                    limiter = limiter.reconfigured(s.maxFailures, Duration.ofMinutes(s.lockoutMinutes),
                            Duration.ofMinutes(s.lockoutMinutes));
                    limiterConfig = cfg;
                }
            }
        }
        return limiter;
    }

    // ---- state ------------------------------------------------------------

    public boolean hasTotp(String userKey) {
        return store.findUser(userKey).map(u -> u.getTotpSecret() != null).orElse(false);
    }

    public boolean hasFactor(String userKey) {
        return hasTotp(userKey) || !store.passkeys(userKey).isEmpty();
    }

    public int remainingRecoveryCodes(String userKey) {
        return store.recoveryCodes(userKey).size();
    }

    /** Start of the user's grace period, starting it now if it has not started. */
    private Instant startGrace(String userKey) {
        return Instant.ofEpochMilli(store.startGrace(userKey, clock.millis()));
    }

    /** End of the user's grace period, or empty when it has not started (the user was never enforced without a factor). */
    public java.util.Optional<Instant> graceEndIfStarted(String userKey) {
        return store.findUser(userKey).filter(u -> u.getFirstSeen() > 0)
                .map(u -> EnforcementPolicy.graceEnd(settings.get(), Instant.ofEpochMilli(u.getFirstSeen())));
    }

    /** What the user needs now. For an enforced user without a factor this starts the grace period. */
    public Requirement requirement(ApplicationUser user) {
        return requirement(user, true);
    }

    /** As {@link #requirement(ApplicationUser)}, without starting a grace period (for the admin page). */
    public Requirement requirementPreview(ApplicationUser user) {
        return requirement(user, false);
    }

    private Requirement requirement(ApplicationUser user, boolean mayStartGrace) {
        if (env.isRecoveryAdmin(user)) {
            return Requirement.NONE;
        }
        MfaSettings s = settings.get();
        if (!s.enabled) {
            return Requirement.NONE;
        }
        String key = user.getKey();
        java.util.Collection<String> groups = env.groups(user);
        boolean hasFactor = hasFactor(key);
        // The grace period starts when the user is first seen enforced and without
        // a factor, not at an earlier visit: when enforcement is widened later, the
        // newly enforced users still get their full grace period.
        Instant first = null;
        if (!hasFactor && EnforcementPolicy.isEnforced(s, user.getUsername(), groups)) {
            first = mayStartGrace ? startGrace(key)
                    : graceEndIfStarted(key).map(end -> end.minus(java.time.Duration.ofDays(s.graceDays))).orElse(clock.instant());
        }
        return EnforcementPolicy.evaluate(s, user.getUsername(), groups, hasFactor, first, clock.instant());
    }

    public boolean isEnforced(ApplicationUser user) {
        return !env.isRecoveryAdmin(user) && EnforcementPolicy.isEnforced(settings.get(), user.getUsername(), env.groups(user));
    }

    // ---- session ----------------------------------------------------------

    public boolean isVerified(HttpSession session, ApplicationUser user) {
        if (session == null || user == null) {
            return false;
        }
        Object mark = session.getAttribute(S_VERIFIED);
        return mark != null && VerifiedMark.isValid(mark, user.getKey(), factorsChanged(user.getKey()));
    }

    /** Marks the session as verified and rotates the session ID (session fixation defence). */
    public void markVerified(HttpServletRequest req, ApplicationUser user) {
        req.getSession(true).setAttribute(S_VERIFIED, VerifiedMark.create(user.getKey(), clock.millis()));
        req.changeSessionId();
    }

    /**
     * Read on every request of a verified session, so cached briefly. The node
     * that makes the change updates its cache at once; other nodes of a Data
     * Center cluster see it within {@link #FACTORS_CHANGED_TTL_MILLIS}.
     */
    private long factorsChanged(String userKey) {
        long now = clock.millis();
        long[] cached = factorsChanged.get(userKey);
        if (cached != null && now - cached[1] < FACTORS_CHANGED_TTL_MILLIS) {
            return cached[0];
        }
        long value = store.factorsChanged(userKey);
        factorsChanged.put(userKey, new long[]{value, now});
        return value;
    }

    static final long FACTORS_CHANGED_TTL_MILLIS = 30_000L;

    /**
     * Ends every verified session of the user except, when given, the one
     * making the change: a removed or reset factor must not leave a session
     * that was verified with it. When the last factor is gone (only allowed
     * for users who are not enforced), the grace period is cleared, so it
     * starts afresh if the user becomes enforced later.
     */
    private void endVerifiedSessions(ApplicationUser user, HttpServletRequest keepVerified) {
        boolean keep = keepVerified != null && isVerified(keepVerified.getSession(false), user);
        long now = clock.millis();
        store.setFactorsChanged(user.getKey(), now, !hasFactor(user.getKey()));
        factorsChanged.put(user.getKey(), new long[]{now, now});
        if (keep) {
            markVerified(keepVerified, user);
        }
    }

    /**
     * Records the first factor of a user. Other sessions of the user that were
     * let through because no second factor was needed must now verify; the
     * filter compares their "nothing needed" mark with this time.
     */
    public void firstFactorAdded(ApplicationUser user) {
        long now = clock.millis();
        store.setFactorsChanged(user.getKey(), now, false);
        factorsChanged.put(user.getKey(), new long[]{now, now});
    }

    /** True when a factor was added, removed or reset at or after {@code millis}. */
    public boolean factorsChangedSince(String userKey, long millis) {
        return factorsChanged(userKey) >= millis;
    }

    public String csrfToken(HttpSession session) {
        Object t = session.getAttribute(S_CSRF);
        if (t instanceof String) {
            return (String) t;
        }
        byte[] raw = new byte[24];
        random.nextBytes(raw);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        session.setAttribute(S_CSRF, token);
        return token;
    }

    public static boolean csrfValid(HttpServletRequest req) {
        HttpSession session = req.getSession(false);
        if (session == null) {
            return false;
        }
        Object expected = session.getAttribute(S_CSRF);
        String given = req.getParameter("csrf");
        if (given == null) {
            given = req.getHeader("X-MFA-Token");
        }
        return expected instanceof String && given != null
                && java.security.MessageDigest.isEqual(((String) expected).getBytes(), given.getBytes());
    }

    // ---- user-bound session values ------------------------------------------

    /**
     * Stores a value for one user. Jira copies all session attributes into the
     * new session when someone logs in over an existing session in the same
     * browser, so second-step data must name its user: otherwise the next user
     * would see, for example, the previous user's pending TOTP secret.
     */
    public static void putForUser(HttpSession session, String name, String userKey, String value) {
        session.setAttribute(name, new String[]{userKey, value});
    }

    /** The value stored for this user, or null; a value of another user is discarded. */
    public static String getForUser(HttpSession session, String name, String userKey) {
        Object v = session.getAttribute(name);
        if (v instanceof String[]) {
            String[] pair = (String[]) v;
            if (pair.length == 2 && pair[0] != null && pair[0].equals(userKey)) {
                return pair[1];
            }
        }
        if (v != null) {
            session.removeAttribute(name);
        }
        return null;
    }

    /** As {@link #getForUser}, and removes the value (single use). */
    public static String takeForUser(HttpSession session, String name, String userKey) {
        String v = getForUser(session, name, userKey);
        session.removeAttribute(name);
        return v;
    }

    // ---- TOTP -------------------------------------------------------------

    /** Creates a pending secret for enrolment, kept encrypted in the session until confirmed. */
    public byte[] pendingTotpSecret(HttpSession session, String userKey) {
        String pending = getForUser(session, S_PENDING_TOTP, userKey);
        if (pending != null) {
            try {
                return cipher().decrypt(pending);
            } catch (RuntimeException e) {
                // encrypted with a key file that has since been replaced: start over with a new secret
                LOG.warn("discarding a pending TOTP secret that the current key file cannot read", e);
                session.removeAttribute(S_PENDING_TOTP);
                cipher = null;
            }
        }
        byte[] secret = totp.newSecret();
        putForUser(session, S_PENDING_TOTP, userKey, cipher().encrypt(secret));
        return secret;
    }

    /** Confirms the pending secret with a code from the app; stores it on success. */
    public boolean confirmTotp(ApplicationUser user, HttpSession session, String code) {
        String pending = getForUser(session, S_PENDING_TOTP, user.getKey());
        if (pending == null) {
            return false;
        }
        byte[] secret = cipher().decrypt(pending);
        OptionalLong step = totp.verify(secret, code, clock.instant(), Long.MIN_VALUE);
        if (!step.isPresent()) {
            return false;
        }
        store.setTotp(user.getKey(), cipher().encrypt(secret), step.getAsLong());
        session.removeAttribute(S_PENDING_TOTP);
        audit.log(AuditLogger.Action.TOTP_ENROLLED, user, Map.of());
        return true;
    }

    /** Removes the user's TOTP; other verified sessions of the user must verify again. */
    public void removeTotp(ApplicationUser user, HttpServletRequest req) {
        store.removeTotp(user.getKey());
        endVerifiedSessions(user, req);
        audit.log(AuditLogger.Action.TOTP_REMOVED, user, Map.of());
    }

    public Instant lockedUntil(ApplicationUser user) {
        return limiter().lockedUntil(user.getKey());
    }

    /** Verifies a TOTP code or, failing that, a recovery code. Counts failures. */
    public VerifyOutcome verifySecondStep(ApplicationUser user, String input, String remoteAddr) {
        String key = user.getKey();
        AttemptLimiter.Admission admission = beginAttempt(user);
        if (admission == AttemptLimiter.Admission.REFUSED) {
            return VerifyOutcome.LOCKED;
        }
        if (input != null && !input.trim().isEmpty()) {
            if (verifyTotp(user, input)) {
                limiter().recordSuccess(key);
                audit.log(AuditLogger.Action.SECOND_STEP_SUCCEEDED, user, Map.of("method", "totp", "remote address", nz(remoteAddr)));
                return VerifyOutcome.OK;
            }
            if (consumeRecoveryCode(user, input)) {
                limiter().recordSuccess(key);
                audit.log(AuditLogger.Action.RECOVERY_CODE_USED, user, Map.of("remaining", Integer.toString(remainingRecoveryCodes(key)),
                        "remote address", nz(remoteAddr)));
                return VerifyOutcome.OK;
            }
        }
        return attemptFailed(user, admission, "code", remoteAddr);
    }

    /**
     * Admits one second-step attempt for the user, counting it as a failure
     * until it succeeds. Callers check the factor only when the result is not
     * {@code REFUSED}, and finish with {@link #attemptFailed} or a success.
     */
    public AttemptLimiter.Admission beginAttempt(ApplicationUser user) {
        return limiter().tryBegin(user.getKey());
    }

    /** Logs a failed attempt that {@link #beginAttempt} already counted. */
    public VerifyOutcome attemptFailed(ApplicationUser user, AttemptLimiter.Admission admission, String method, String remoteAddr) {
        audit.log(AuditLogger.Action.SECOND_STEP_FAILED, user, Map.of("method", method, "remote address", nz(remoteAddr)));
        if (admission == AttemptLimiter.Admission.ADMITTED_LAST) {
            audit.log(AuditLogger.Action.LOCKED_OUT, user, Map.of("minutes", Integer.toString(settings.get().lockoutMinutes)));
            return VerifyOutcome.LOCKED;
        }
        return VerifyOutcome.WRONG;
    }

    public void recordPasskeySuccess(ApplicationUser user, String remoteAddr) {
        limiter().recordSuccess(user.getKey());
        audit.log(AuditLogger.Action.SECOND_STEP_SUCCEEDED, user, Map.of("method", "passkey", "remote address", nz(remoteAddr)));
    }

    private boolean verifyTotp(ApplicationUser user, String input) {
        MfaUser u = store.findUser(user.getKey()).orElse(null);
        if (u == null || u.getTotpSecret() == null) {
            return false;
        }
        byte[] secret;
        try {
            secret = cipher().decrypt(u.getTotpSecret());
        } catch (RuntimeException e) {
            // Missing or replaced key file: TOTP cannot work, but recovery codes
            // and passkeys must still let the user in.
            LOG.error("cannot decrypt the TOTP secret of {}; is {} the key file the secrets were written with?",
                    user.getUsername(), env.keyFile(), e);
            // read the key file again next time, so restoring the right file takes effect without a restart
            cipher = null;
            return false;
        }
        OptionalLong step = totp.verify(secret, input, clock.instant(), u.getTotpLastStep());
        if (!step.isPresent()) {
            return false;
        }
        store.setTotpLastStep(user.getKey(), step.getAsLong());
        return true;
    }

    private boolean consumeRecoveryCode(ApplicationUser user, String input) {
        if (RecoveryCodes.normalize(input) == null) {
            return false;
        }
        for (MfaRecoveryCode c : store.recoveryCodes(user.getKey())) {
            if (RecoveryCodes.matches(input, c.getCodeHash())) {
                return store.consumeRecoveryCode(c.getID());
            }
        }
        return false;
    }

    // ---- recovery codes ---------------------------------------------------

    /** Replaces the user's recovery codes; returns the plain codes to show once. */
    /**
     * New recovery codes on the user's request. Other verified sessions of the
     * user end, because replacing the codes is the remedy for a leaked code and
     * a session verified with it must not outlive it.
     */
    public List<String> replaceRecoveryCodes(ApplicationUser user, HttpServletRequest req) {
        List<String> codes = regenerateRecoveryCodes(user);
        endVerifiedSessions(user, req);
        return codes;
    }

    public List<String> regenerateRecoveryCodes(ApplicationUser user) {
        List<String> codes = recoveryCodes.generate();
        List<String> hashes = new ArrayList<>(codes.size());
        for (String c : codes) {
            hashes.add(recoveryCodes.hash(c));
        }
        store.replaceRecoveryCodes(user.getKey(), hashes);
        audit.log(AuditLogger.Action.RECOVERY_CODES_GENERATED, user, Map.of("count", Integer.toString(codes.size())));
        return codes;
    }

    // ---- passkeys ---------------------------------------------------------

    public PasskeyService passkeys() {
        return passkeys;
    }

    public void passkeyRegistered(ApplicationUser user, String label) {
        audit.log(AuditLogger.Action.PASSKEY_REGISTERED, user, Map.of("label", nz(label)));
    }

    /** Removes one of the user's passkeys; other verified sessions of the user must verify again. */
    public boolean removePasskey(ApplicationUser user, int id, HttpServletRequest req) {
        boolean removed = store.deletePasskey(user.getKey(), id);
        if (removed) {
            endVerifiedSessions(user, req);
            audit.log(AuditLogger.Action.PASSKEY_REMOVED, user, Map.of("id", Integer.toString(id)));
        }
        return removed;
    }

    // ---- administration ---------------------------------------------------

    public void adminReset(ApplicationUser admin, ApplicationUser target) {
        long now = clock.millis();
        store.resetUser(target.getKey(), now);
        factorsChanged.put(target.getKey(), new long[]{now, now});
        limiter().reset(target.getKey());
        audit.log(AuditLogger.Action.ADMIN_RESET, target, Map.of("administrator", admin.getUsername()));
    }

    public void basicAuthRejected(ApplicationUser user, String path, String remoteAddr) {
        audit.log(AuditLogger.Action.BASIC_AUTH_REJECTED, user, Map.of("path", nz(path), "remote address", nz(remoteAddr)));
    }

    public void saveSettings(ApplicationUser admin, MfaSettings s) {
        settings.save(s);
        audit.log(AuditLogger.Action.SETTINGS_CHANGED, admin, Map.of());
    }

    public MfaStore store() {
        return store;
    }

    public JiraEnvironment env() {
        return env;
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }
}
