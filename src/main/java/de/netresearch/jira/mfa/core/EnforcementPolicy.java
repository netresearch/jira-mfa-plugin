package de.netresearch.jira.mfa.core;

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.Locale;

/** Decides what a logged-in browser session needs before pages are served. */
public final class EnforcementPolicy {
    public enum Requirement {
        /** No second factor needed. */
        NONE,
        /** The user has a factor and must present it. */
        VERIFY,
        /** Enforced, no factor yet, grace period still running: enrolment is offered. */
        ENROL_OPTIONAL,
        /** Enforced, no factor, grace period over: enrolment is mandatory. */
        ENROL_REQUIRED
    }

    private EnforcementPolicy() {
    }

    public static boolean isEnforced(MfaSettings s, String username, Collection<String> groups) {
        if (!s.enabled || isExempt(s, username, groups)) {
            return false;
        }
        if (s.enforcedGroups.isEmpty()) {
            return true;
        }
        return groups.stream().map(g -> g.toLowerCase(Locale.ROOT)).anyMatch(s.enforcedGroups::contains);
    }

    public static boolean isExempt(MfaSettings s, String username, Collection<String> groups) {
        if (username != null && s.exemptUsers.contains(username.toLowerCase(Locale.ROOT))) {
            return true;
        }
        return groups.stream().map(g -> g.toLowerCase(Locale.ROOT)).anyMatch(s.exemptGroups::contains);
    }

    public static Instant graceEnd(MfaSettings s, Instant firstSeen) {
        return firstSeen.plus(Duration.ofDays(s.graceDays));
    }

    public static Requirement evaluate(MfaSettings s, String username, Collection<String> groups,
                                       boolean hasFactor, Instant firstSeen, Instant now) {
        if (!s.enabled || isExempt(s, username, groups)) {
            return Requirement.NONE;
        }
        if (hasFactor) {
            return Requirement.VERIFY;
        }
        if (!isEnforced(s, username, groups)) {
            return Requirement.NONE;
        }
        if (firstSeen != null && now.isBefore(graceEnd(s, firstSeen))) {
            return Requirement.ENROL_OPTIONAL;
        }
        return Requirement.ENROL_REQUIRED;
    }
}
