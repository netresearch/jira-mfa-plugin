package de.netresearch.jira.mfa.service;

import com.atlassian.activeobjects.external.ActiveObjects;
import com.atlassian.plugin.spring.scanner.annotation.imports.ComponentImport;
import de.netresearch.jira.mfa.ao.MfaPasskey;
import de.netresearch.jira.mfa.ao.MfaRecoveryCode;
import de.netresearch.jira.mfa.ao.MfaUser;
import net.java.ao.DBParam;
import net.java.ao.Query;

import javax.inject.Inject;
import javax.inject.Named;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/** Active Objects persistence for MFA state. */
@Named
public class MfaStore {
    private static final String USER_KEY = "USER_KEY";
    private static final String BY_USER = USER_KEY + " = ?";
    private final ActiveObjects ao;

    @Inject
    public MfaStore(@ComponentImport ActiveObjects ao) {
        this.ao = ao;
    }

    public Optional<MfaUser> findUser(String userKey) {
        MfaUser[] found = ao.find(MfaUser.class, Query.select().where(BY_USER, userKey));
        return found.length == 0 ? Optional.empty() : Optional.of(found[0]);
    }

    /**
     * The state row inside a write transaction. The row is created beforehand by
     * {@link #getOrCreateUser} in a transaction of its own: a failed insert inside
     * an enclosing transaction would abort it on PostgreSQL.
     */
    private MfaUser existingUser(String userKey) {
        return findUser(userKey).orElseThrow(() -> new IllegalStateException("no MFA state row for " + userKey));
    }

    /**
     * Returns the state row, creating it when missing. Call it outside other
     * transactions (see {@link #existingUser}). A new row has no grace
     * period yet (first seen = 0); {@link #startGrace} starts it.
     * Parallel first requests of a user race on the unique user key; the loser
     * reads the winner's row instead of failing.
     */
    public MfaUser getOrCreateUser(String userKey) {
        Optional<MfaUser> existing = findUser(userKey);
        if (existing.isPresent()) {
            return existing.get();
        }
        try {
            return ao.executeInTransaction(() -> findUser(userKey).orElseGet(() ->
                    ao.create(MfaUser.class, new DBParam(USER_KEY, userKey), new DBParam("FIRST_SEEN", 0L))));
        } catch (RuntimeException e) {
            return findUser(userKey).orElseThrow(() -> e);
        }
    }

    /** Starts the user's grace period at {@code now} unless it has started already; returns its start. */
    public long startGrace(String userKey, long now) {
        MfaUser u = getOrCreateUser(userKey);
        if (u.getFirstSeen() > 0) {
            return u.getFirstSeen();
        }
        return ao.executeInTransaction(() -> {
            MfaUser row = findUser(userKey).orElseThrow(IllegalStateException::new);
            if (row.getFirstSeen() == 0) {
                row.setFirstSeen(now);
                row.save();
            }
            return row.getFirstSeen();
        });
    }

    public Optional<MfaUser> findUserByHandle(String handle) {
        MfaUser[] found = ao.find(MfaUser.class, Query.select().where("USER_HANDLE = ?", handle));
        return found.length == 0 ? Optional.empty() : Optional.of(found[0]);
    }

    public void setTotp(String userKey, String encryptedSecret, long lastStep) {
        getOrCreateUser(userKey);
        ao.executeInTransaction(() -> {
            MfaUser u = existingUser(userKey);
            u.setTotpSecret(encryptedSecret);
            u.setTotpLastStep(lastStep);
            u.save();
            return null;
        });
    }

    public void setTotpLastStep(String userKey, long step) {
        ao.executeInTransaction(() -> {
            findUser(userKey).ifPresent(u -> {
                u.setTotpLastStep(step);
                u.save();
            });
            return null;
        });
    }

    public void setUserHandle(String userKey, String handle) {
        getOrCreateUser(userKey);
        ao.executeInTransaction(() -> {
            MfaUser u = existingUser(userKey);
            u.setUserHandle(handle);
            u.save();
            return null;
        });
    }

    public List<MfaPasskey> passkeys(String userKey) {
        return Arrays.asList(ao.find(MfaPasskey.class, Query.select().where(BY_USER, userKey).order("ID")));
    }

    public Optional<MfaPasskey> passkeyByCredentialId(String credentialId) {
        MfaPasskey[] found = ao.find(MfaPasskey.class, Query.select().where("CREDENTIAL_ID = ?", credentialId));
        return found.length == 0 ? Optional.empty() : Optional.of(found[0]);
    }

    public List<MfaPasskey> passkeysByCredentialId(String credentialId) {
        return Arrays.asList(ao.find(MfaPasskey.class, Query.select().where("CREDENTIAL_ID = ?", credentialId)));
    }

    public void addPasskey(String userKey, String credentialId, String publicKeyCose, long signatureCount, String label, long now) {
        ao.executeInTransaction(() -> ao.create(MfaPasskey.class,
                new DBParam(USER_KEY, userKey),
                new DBParam("CREDENTIAL_ID", credentialId),
                new DBParam("PUBLIC_KEY_COSE", publicKeyCose),
                new DBParam("SIGNATURE_COUNT", signatureCount),
                new DBParam("LABEL", label),
                new DBParam("CREATED", now),
                new DBParam("LAST_USED", 0L)));
    }

    public void updatePasskeyUse(String credentialId, long signatureCount, long now) {
        ao.executeInTransaction(() -> {
            for (MfaPasskey p : passkeysByCredentialId(credentialId)) {
                p.setSignatureCount(signatureCount);
                p.setLastUsed(now);
                p.save();
            }
            return null;
        });
    }

    public boolean deletePasskey(String userKey, int id) {
        return ao.executeInTransaction(() -> {
            MfaPasskey p = ao.get(MfaPasskey.class, id);
            if (p == null || !userKey.equals(p.getUserKey())) {
                return false;
            }
            ao.delete(p);
            return true;
        });
    }

    public List<MfaRecoveryCode> recoveryCodes(String userKey) {
        return Arrays.asList(ao.find(MfaRecoveryCode.class, Query.select().where(BY_USER, userKey)));
    }

    public void replaceRecoveryCodes(String userKey, List<String> hashes) {
        ao.executeInTransaction(() -> {
            ao.deleteWithSQL(MfaRecoveryCode.class, BY_USER, userKey);
            for (String h : hashes) {
                ao.create(MfaRecoveryCode.class, new DBParam(USER_KEY, userKey), new DBParam("CODE_HASH", h));
            }
            return null;
        });
    }

    /** Deletes one recovery code; returns false if it was already consumed concurrently. */
    public boolean consumeRecoveryCode(int id) {
        return ao.executeInTransaction(() -> ao.deleteWithSQL(MfaRecoveryCode.class, "ID = ?", id) == 1);
    }

    /** Removes every factor and recovery code, clears the grace period and invalidates verified sessions. */
    public void resetUser(String userKey, long now) {
        ao.executeInTransaction(() -> {
            ao.deleteWithSQL(MfaPasskey.class, BY_USER, userKey);
            ao.deleteWithSQL(MfaRecoveryCode.class, BY_USER, userKey);
            ao.deleteWithSQL(MfaUser.class, BY_USER, userKey);
            // FIRST_SEEN 0: the grace period starts at the user's next request as an enforced user
            ao.create(MfaUser.class, new DBParam(USER_KEY, userKey), new DBParam("FIRST_SEEN", 0L),
                    new DBParam("FACTORS_CHANGED", now), new DBParam("RESET_AT", now));
            return null;
        });
    }

    /** {last factor change, last admin reset}, both 0 when unknown. */
    public long[] sessionCutoffs(String userKey) {
        return findUser(userKey).map(u -> new long[]{u.getFactorsChanged(), u.getResetAt()}).orElse(new long[]{0L, 0L});
    }

    /** Records a factor removal; {@code clearGrace} resets the grace period to "not started". */
    public void setFactorsChanged(String userKey, long now, boolean clearGrace) {
        getOrCreateUser(userKey);
        ao.executeInTransaction(() -> {
            MfaUser u = existingUser(userKey);
            u.setFactorsChanged(now);
            if (clearGrace) {
                u.setFirstSeen(0L);
            }
            u.save();
            return null;
        });
    }

    public void removeTotp(String userKey) {
        ao.executeInTransaction(() -> {
            findUser(userKey).ifPresent(u -> {
                u.setTotpSecret(null);
                u.setTotpLastStep(0);
                u.save();
            });
            return null;
        });
    }

    public int countEnrolledUsers() {
        int totp = ao.count(MfaUser.class, Query.select().where("TOTP_SECRET IS NOT NULL"));
        return totp;
    }
}
