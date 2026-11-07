package de.netresearch.jira.mfa.core;

import java.time.Instant;
import java.util.Collection;

/**
 * One user's second-factor state as the administrators' overview shows it.
 * Pure: the caller supplies the stored factors and the user's groups.
 */
public final class UserStatus {
    /** Ordered by urgency: the overview lists the first ones first. */
    public enum State {
        /** Enforced, no factor, grace period over: enrolment is mandatory at the next login. */
        ENROLMENT_REQUIRED("Must set up at next login"),
        /** Enforced, no factor, grace period running. */
        IN_GRACE_PERIOD("Grace period running"),
        /** Enforced, no factor, never seen since enforcement: the grace period starts at the next login. */
        GRACE_NOT_STARTED("Grace period not started"),
        /** At least one authenticator app or passkey. */
        SET_UP("Set up"),
        /** Listed as exempt user or member of an exempt group. */
        EXEMPT("Exempt"),
        /** Not covered by the enforced groups, or two-step verification is switched off. */
        NOT_ENFORCED("Not enforced");

        private final String label;

        State(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }
    }

    public final State state;
    public final boolean authenticatorApp;
    public final int passkeys;
    public final int recoveryCodes;
    /** End of the grace period; null when it has not started or does not apply. */
    public final Instant graceEnd;

    private UserStatus(State state, boolean authenticatorApp, int passkeys, int recoveryCodes, Instant graceEnd) {
        this.state = state;
        this.authenticatorApp = authenticatorApp;
        this.passkeys = passkeys;
        this.recoveryCodes = recoveryCodes;
        this.graceEnd = graceEnd;
    }

    /** What a user has stored. */
    public static final class Factors {
        final boolean authenticatorApp;
        final int passkeys;
        final int recoveryCodes;

        public Factors(boolean authenticatorApp, int passkeys, int recoveryCodes) {
            this.authenticatorApp = authenticatorApp;
            this.passkeys = passkeys;
            this.recoveryCodes = recoveryCodes;
        }
    }

    /**
     * @param firstSeen start of the grace period, or null when it has not started
     */
    public static UserStatus of(MfaSettings s, String username, Collection<String> groups, Factors f,
                                Instant firstSeen, Instant now) {
        boolean authenticatorApp = f.authenticatorApp;
        int passkeys = f.passkeys;
        int recoveryCodes = f.recoveryCodes;
        boolean hasFactor = authenticatorApp || passkeys > 0;
        Instant graceEnd = firstSeen == null ? null : EnforcementPolicy.graceEnd(s, firstSeen);
        State state;
        if (hasFactor) {
            state = State.SET_UP;
            graceEnd = null;
        } else if (s.enabled && EnforcementPolicy.isExempt(s, username, groups)) {
            state = State.EXEMPT;
            graceEnd = null;
        } else if (!EnforcementPolicy.isEnforced(s, username, groups)) {
            state = State.NOT_ENFORCED;
            graceEnd = null;
        } else if (graceEnd == null) {
            state = State.GRACE_NOT_STARTED;
        } else if (now.isBefore(graceEnd)) {
            state = State.IN_GRACE_PERIOD;
        } else {
            state = State.ENROLMENT_REQUIRED;
        }
        return new UserStatus(state, authenticatorApp, passkeys, recoveryCodes, graceEnd);
    }

    /** One CSV field (RFC 4180), with a leading formula character neutralised for spreadsheet programs. */
    public static String csv(String value) {
        String v = value == null ? "" : value;
        if (!v.isEmpty() && "=+-@\t\r".indexOf(v.charAt(0)) >= 0) {
            v = "'" + v;
        }
        if (v.indexOf(',') >= 0 || v.indexOf('"') >= 0 || v.indexOf('\n') >= 0 || v.indexOf('\r') >= 0) {
            v = '"' + v.replace("\"", "\"\"") + '"';
        }
        return v;
    }
}
