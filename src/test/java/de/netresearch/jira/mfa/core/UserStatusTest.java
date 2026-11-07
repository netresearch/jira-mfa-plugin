package de.netresearch.jira.mfa.core;

import de.netresearch.jira.mfa.core.UserStatus.State;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class UserStatusTest {
    private static final Instant SEEN = Instant.parse("2026-11-01T00:00:00Z");
    private static final Instant IN_GRACE = SEEN.plus(Duration.ofDays(13));
    private static final Instant AFTER_GRACE = SEEN.plus(Duration.ofDays(14));
    private static final List<String> STAFF = List.of("staff");

    private static MfaSettings settings(Set<String> enforced, Set<String> exemptGroups, Set<String> exemptUsers, boolean enabled) {
        return new MfaSettings(enabled, enforced, exemptGroups, exemptUsers, 14, MfaSettings.BasicAuthPolicy.BLOCK, Set.of(), "", "Jira", 5, 15);
    }

    private static UserStatus noFactor(MfaSettings s, String user, List<String> groups, Instant firstSeen, Instant now) {
        return UserStatus.of(s, user, groups, new UserStatus.Factors(false, 0, 0), firstSeen, now);
    }

    @Test
    void aFactorMeansSetUpWhateverTheEnforcement() {
        MfaSettings s = settings(Set.of("staff"), Set.of(), Set.of(), true);
        assertEquals(State.SET_UP, UserStatus.of(s, "a", STAFF, new UserStatus.Factors(true, 0, 10), SEEN, AFTER_GRACE).state);
        assertEquals(State.SET_UP, UserStatus.of(s, "c", List.of("customers"), new UserStatus.Factors(false, 2, 0), null, AFTER_GRACE).state);
        UserStatus st = UserStatus.of(s, "a", STAFF, new UserStatus.Factors(false, 1, 3), SEEN, AFTER_GRACE);
        assertEquals(1, st.passkeys);
        assertEquals(3, st.recoveryCodes);
        assertNull(st.graceEnd, "a grace end is meaningless once a factor exists");
    }

    @Test
    void enforcedWithoutFactorFollowsTheGracePeriod() {
        MfaSettings s = MfaSettings.defaults();
        assertEquals(State.GRACE_NOT_STARTED, noFactor(s, "a", STAFF, null, IN_GRACE).state);
        UserStatus running = noFactor(s, "a", STAFF, SEEN, IN_GRACE);
        assertEquals(State.IN_GRACE_PERIOD, running.state);
        assertEquals(AFTER_GRACE, running.graceEnd);
        assertEquals(State.ENROLMENT_REQUIRED, noFactor(s, "a", STAFF, SEEN, AFTER_GRACE).state);
    }

    @Test
    void exemptAndNotEnforcedAreTold() {
        MfaSettings s = settings(Set.of("staff"), Set.of("service-accounts"), Set.of("emergency"), true);
        assertEquals(State.EXEMPT, noFactor(s, "Emergency", STAFF, SEEN, AFTER_GRACE).state);
        assertEquals(State.EXEMPT, noFactor(s, "bot", List.of("staff", "Service-Accounts"), SEEN, AFTER_GRACE).state);
        UserStatus customer = noFactor(s, "c", List.of("customers"), SEEN, AFTER_GRACE);
        assertEquals(State.NOT_ENFORCED, customer.state);
        assertNull(customer.graceEnd);
    }

    @Test
    void switchedOffMeansNotEnforcedEvenForExemptUsers() {
        MfaSettings s = settings(Set.of(), Set.of(), Set.of("emergency"), false);
        assertEquals(State.NOT_ENFORCED, noFactor(s, "a", STAFF, SEEN, AFTER_GRACE).state);
        assertEquals(State.NOT_ENFORCED, noFactor(s, "emergency", STAFF, SEEN, AFTER_GRACE).state);
    }

    @Test
    void statesAreOrderedByUrgency() {
        assertEquals(List.of(State.ENROLMENT_REQUIRED, State.IN_GRACE_PERIOD, State.GRACE_NOT_STARTED, State.SET_UP,
                State.EXEMPT, State.NOT_ENFORCED), List.of(State.values()));
    }

    @Test
    void csvQuotesAndNeutralisesFormulas() {
        assertEquals("alice", UserStatus.csv("alice"));
        assertEquals("", UserStatus.csv(null));
        assertEquals("\"Doe, Jane\"", UserStatus.csv("Doe, Jane"));
        assertEquals("\"say \"\"hi\"\"\"", UserStatus.csv("say \"hi\""));
        assertEquals("'=HYPERLINK(1)", UserStatus.csv("=HYPERLINK(1)"));
        assertEquals("'@cmd", UserStatus.csv("@cmd"));
        assertEquals("\"'+1,2\"", UserStatus.csv("+1,2"));
    }
}
