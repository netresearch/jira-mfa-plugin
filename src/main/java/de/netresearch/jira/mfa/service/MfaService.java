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

/** Second-factor business logic shared by the filter and the servlets. */
@Named
public class MfaService {
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
                        cipher = SecretCipher.fromKeyFile(env.keyFile());
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
                if (limiter == null || !cfg.equals(limiterConfig)) {
                    limiter = new AttemptLimiter(s.maxFailures, Duration.ofMinutes(s.lockoutMinutes),
                            Duration.ofMinutes(s.lockoutMinutes), clock);
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

    public Instant firstSeen(String userKey) {
        MfaUser u = store.getOrCreateUser(userKey, clock.millis());
        return Instant.ofEpochMilli(u.getFirstSeen());
    }

    public Instant graceEnd(String userKey) {
        return EnforcementPolicy.graceEnd(settings.get(), firstSeen(userKey));
    }

    public Requirement requirement(ApplicationUser user) {
        if (env.isRecoveryAdmin(user)) {
            return Requirement.NONE;
        }
        MfaSettings s = settings.get();
        if (!s.enabled) {
            return Requirement.NONE;
        }
        String key = user.getKey();
        return EnforcementPolicy.evaluate(s, user.getUsername(), env.groups(user), hasFactor(key), firstSeen(key), clock.instant());
    }

    public boolean isEnforced(ApplicationUser user) {
        return !env.isRecoveryAdmin(user) && EnforcementPolicy.isEnforced(settings.get(), user.getUsername(), env.groups(user));
    }

    // ---- session ----------------------------------------------------------

    public static boolean isVerified(HttpSession session, ApplicationUser user) {
        return session != null && user != null && user.getKey().equals(session.getAttribute(S_VERIFIED));
    }

    /** Marks the session as verified and rotates the session ID (session fixation defence). */
    public static void markVerified(HttpServletRequest req, ApplicationUser user) {
        req.getSession(true).setAttribute(S_VERIFIED, user.getKey());
        req.changeSessionId();
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

    // ---- TOTP -------------------------------------------------------------

    /** Creates a pending secret for enrolment, kept encrypted in the session until confirmed. */
    public byte[] pendingTotpSecret(HttpSession session) {
        Object pending = session.getAttribute(S_PENDING_TOTP);
        if (pending instanceof String) {
            return cipher().decrypt((String) pending);
        }
        byte[] secret = totp.newSecret();
        session.setAttribute(S_PENDING_TOTP, cipher().encrypt(secret));
        return secret;
    }

    /** Confirms the pending secret with a code from the app; stores it on success. */
    public boolean confirmTotp(ApplicationUser user, HttpSession session, String code) {
        Object pending = session.getAttribute(S_PENDING_TOTP);
        if (!(pending instanceof String)) {
            return false;
        }
        byte[] secret = cipher().decrypt((String) pending);
        OptionalLong step = totp.verify(secret, code, clock.instant(), Long.MIN_VALUE);
        if (!step.isPresent()) {
            return false;
        }
        store.setTotp(user.getKey(), cipher().encrypt(secret), step.getAsLong());
        session.removeAttribute(S_PENDING_TOTP);
        audit.log(AuditLogger.Action.TOTP_ENROLLED, user, Map.of());
        return true;
    }

    public void removeTotp(ApplicationUser user) {
        store.removeTotp(user.getKey());
        audit.log(AuditLogger.Action.TOTP_REMOVED, user, Map.of());
    }

    public Instant lockedUntil(ApplicationUser user) {
        return limiter().lockedUntil(user.getKey());
    }

    /** Verifies a TOTP code or, failing that, a recovery code. Counts failures. */
    public VerifyOutcome verifySecondStep(ApplicationUser user, String input, String remoteAddr) {
        String key = user.getKey();
        if (limiter().lockedUntil(key) != null) {
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
        return recordFailure(user, "code", remoteAddr);
    }

    public VerifyOutcome recordFailure(ApplicationUser user, String method, String remoteAddr) {
        boolean locked = limiter().recordFailure(user.getKey());
        audit.log(AuditLogger.Action.SECOND_STEP_FAILED, user, Map.of("method", method, "remote address", nz(remoteAddr)));
        if (locked) {
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
        byte[] secret = cipher().decrypt(u.getTotpSecret());
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

    public boolean removePasskey(ApplicationUser user, int id) {
        boolean removed = store.deletePasskey(user.getKey(), id);
        if (removed) {
            audit.log(AuditLogger.Action.PASSKEY_REMOVED, user, Map.of("id", Integer.toString(id)));
        }
        return removed;
    }

    // ---- administration ---------------------------------------------------

    public void adminReset(ApplicationUser admin, ApplicationUser target) {
        store.resetUser(target.getKey(), clock.millis());
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
