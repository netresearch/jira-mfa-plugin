package de.netresearch.jira.mfa.core;

import de.netresearch.jira.mfa.core.EnforcementPolicy.Requirement;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;

class EnforcementPolicyTest {
    private static final Instant SEEN = Instant.parse("2026-11-01T00:00:00Z");
    private static final Instant IN_GRACE = SEEN.plus(Duration.ofDays(13));
    private static final Instant AFTER_GRACE = SEEN.plus(Duration.ofDays(14));

    private static MfaSettings settings(Set<String> enforced, Set<String> exemptGroups, Set<String> exemptUsers, boolean enabled) {
        return new MfaSettings(enabled, enforced, exemptGroups, exemptUsers, 14, MfaSettings.BasicAuthPolicy.BLOCK, Set.of(), "", "Jira", 5, 15);
    }

    @Test
    void everyoneEnforcedByDefaultWithGracePeriod() {
        MfaSettings s = MfaSettings.defaults();
        assertEquals(Requirement.ENROL_OPTIONAL, EnforcementPolicy.evaluate(s, "a", List.of("jira-users"), false, SEEN, IN_GRACE));
        assertEquals(Requirement.ENROL_REQUIRED, EnforcementPolicy.evaluate(s, "a", List.of("jira-users"), false, SEEN, AFTER_GRACE));
        assertEquals(Requirement.VERIFY, EnforcementPolicy.evaluate(s, "a", List.of("jira-users"), true, SEEN, IN_GRACE));
    }

    @Test
    void groupEnforcementIsCaseInsensitive() {
        MfaSettings s = settings(Set.of("Staff"), Set.of(), Set.of(), true);
        assertEquals(Requirement.ENROL_REQUIRED, EnforcementPolicy.evaluate(s, "a", List.of("staff"), false, SEEN, AFTER_GRACE));
        assertEquals(Requirement.NONE, EnforcementPolicy.evaluate(s, "c", List.of("customers"), false, SEEN, AFTER_GRACE));
    }

    @Test
    void usersWithAFactorAreAlwaysChallenged() {
        MfaSettings s = settings(Set.of("staff"), Set.of(), Set.of(), true);
        assertEquals(Requirement.VERIFY, EnforcementPolicy.evaluate(s, "c", List.of("customers"), true, SEEN, AFTER_GRACE));
    }

    @Test
    void exemptionsWinOverEverything() {
        MfaSettings s = settings(Set.of(), Set.of("service-accounts"), Set.of("Emergency"), true);
        assertEquals(Requirement.NONE, EnforcementPolicy.evaluate(s, "bot", List.of("service-accounts"), true, SEEN, AFTER_GRACE));
        assertEquals(Requirement.NONE, EnforcementPolicy.evaluate(s, "emergency", List.of(), true, SEEN, AFTER_GRACE));
        assertEquals(Requirement.ENROL_REQUIRED, EnforcementPolicy.evaluate(s, "other", List.of(), false, SEEN, AFTER_GRACE));
    }

    @Test
    void disabledMeansNothingIsRequired() {
        MfaSettings s = settings(Set.of(), Set.of(), Set.of(), false);
        assertEquals(Requirement.NONE, EnforcementPolicy.evaluate(s, "a", List.of(), true, SEEN, AFTER_GRACE));
    }

    @Test
    void zeroGraceRequiresEnrolmentImmediately() {
        MfaSettings s = new MfaSettings(true, Set.of(), Set.of(), Set.of(), 0, MfaSettings.BasicAuthPolicy.BLOCK, Set.of(), "", "Jira", 5, 15);
        assertEquals(Requirement.ENROL_REQUIRED, EnforcementPolicy.evaluate(s, "a", List.of(), false, SEEN, SEEN));
    }

    @Test
    void basicAuthAllowList() {
        MfaSettings s = new MfaSettings(true, Set.of(), Set.of(), Set.of(), 14, MfaSettings.BasicAuthPolicy.BLOCK,
                Set.of("Jenkins"), "", "Jira", 5, 15);
        assertEquals(true, s.isBasicAuthAllowedFor("jenkins"));
        assertEquals(false, s.isBasicAuthAllowedFor("alice"));
        assertEquals(false, MfaSettings.defaults().isBasicAuthAllowedFor(null));
    }
}
