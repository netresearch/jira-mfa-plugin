package de.netresearch.jira.mfa.core;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VerifiedMarkTest {
    @Test
    void validForSameUserWhenNoFactorChangedSince() {
        String mark = VerifiedMark.create("JIRAUSER10000", 1_000L);
        assertTrue(VerifiedMark.isValid(mark, "JIRAUSER10000", 0L), "factors never changed");
        assertTrue(VerifiedMark.isValid(mark, "JIRAUSER10000", 1_000L), "changed in the same millisecond");
    }

    @Test
    void invalidAfterFactorRemovalOrReset() {
        String mark = VerifiedMark.create("JIRAUSER10000", 1_000L);
        assertFalse(VerifiedMark.isValid(mark, "JIRAUSER10000", 1_001L));
    }

    @Test
    void invalidForAnotherUserOrMalformedValue() {
        String mark = VerifiedMark.create("alice|x", 1_000L);
        assertTrue(VerifiedMark.isValid(mark, "alice|x", 0L), "a key containing the separator still works");
        assertFalse(VerifiedMark.isValid(mark, "alice", 0L));
        assertFalse(VerifiedMark.isValid("JIRAUSER10000", "JIRAUSER10000", 0L), "the format before this change");
        assertFalse(VerifiedMark.isValid("JIRAUSER10000|soon", "JIRAUSER10000", 0L));
        assertFalse(VerifiedMark.isValid(null, "JIRAUSER10000", 0L));
        assertFalse(VerifiedMark.isValid(Boolean.TRUE, "JIRAUSER10000", 0L));
    }
}
