package de.netresearch.jira.mfa.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PendingRequestsTest {
    @Test
    void aLaterRequestKeepsTheEarlierOne() {
        String stored = PendingRequests.add(PendingRequests.add(null, "a"), "b");
        assertArrayEquals(new String[]{"a", "b"}, PendingRequests.take(stored, "a"::equals));
        assertArrayEquals(new String[]{"b", "a"}, PendingRequests.take(stored, "b"::equals));
    }

    @Test
    void theLastRequestLeavesNothingStored() {
        assertArrayEquals(new String[]{"a", null}, PendingRequests.take("a", "a"::equals));
    }

    @Test
    void noMatchKeepsEverything() {
        assertArrayEquals(new String[]{null, "a\nb"}, PendingRequests.take("a\nb", "c"::equals));
        assertArrayEquals(new String[]{null, null}, PendingRequests.take(null, "c"::equals));
    }

    @Test
    void theOldestAreDroppedBeyondTheLimit() {
        String stored = null;
        for (int i = 0; i < PendingRequests.MAX + 2; i++) {
            stored = PendingRequests.add(stored, "r" + i);
        }
        assertEquals("r2\nr3\nr4\nr5", stored);
    }

    @Test
    void aMultiLineRequestIsRefused() {
        assertThrows(IllegalArgumentException.class, () -> PendingRequests.add(null, "a\nb"));
    }
}
