package de.netresearch.jira.mfa.core;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Basic authentication decisions, computed the way the filter computes them:
 * the requirement from {@link EnforcementPolicy}, then {@link BasicAuthRule}.
 * Enforcement applies to all users (the default), grace period 14 days.
 */
class BasicAuthRuleTest {
    private static final Instant FIRST_SEEN = Instant.parse("2026-11-01T00:00:00Z");
    private static final Instant IN_GRACE = FIRST_SEEN.plus(Duration.ofDays(3));
    private static final Instant GRACE_OVER = FIRST_SEEN.plus(Duration.ofDays(14));
    private static final List<String> GROUPS = List.of("jira-software-users");

    private static MfaSettings settings(Set<String> basicAllowed) {
        return new MfaSettings(true, Set.of(), Set.of(), Set.of(), 14, MfaSettings.BasicAuthPolicy.BLOCK,
                basicAllowed, "", "Jira", 5, 15);
    }

    private static boolean basicAllowed(MfaSettings s, String user, boolean enrolled, Instant now) {
        return BasicAuthRule.allows(s, user, EnforcementPolicy.evaluate(s, user, GROUPS, enrolled, FIRST_SEEN, now));
    }

    @Test
    void allowedDuringGraceWhileNotEnrolled() {
        assertTrue(basicAllowed(settings(Set.of()), "alice", false, IN_GRACE));
    }

    @Test
    void refusedOnceGraceExpired() {
        assertFalse(basicAllowed(settings(Set.of()), "alice", false, GRACE_OVER));
    }

    @Test
    void refusedOnceEnrolledEvenDuringGrace() {
        assertFalse(basicAllowed(settings(Set.of()), "alice", true, IN_GRACE));
    }

    @Test
    void allowListedServiceAccountKeepsBasicEvenWhenEnrolledAndGraceOver() {
        assertTrue(basicAllowed(settings(Set.of("ci-bot")), "ci-bot", true, GRACE_OVER));
    }

    @Test
    void notEnforcedUserKeepsBasic() {
        MfaSettings s = new MfaSettings(true, Set.of("staff"), Set.of(), Set.of(), 14, MfaSettings.BasicAuthPolicy.BLOCK,
                Set.of(), "", "Jira", 5, 15);
        assertTrue(basicAllowed(s, "customer", false, GRACE_OVER));
    }
}
