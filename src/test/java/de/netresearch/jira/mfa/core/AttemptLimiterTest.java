package de.netresearch.jira.mfa.core;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AttemptLimiterTest {
    static final class MutableClock extends Clock {
        Instant now = Instant.parse("2026-11-07T10:00:00Z");

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    private final MutableClock clock = new MutableClock();
    private final AttemptLimiter limiter = new AttemptLimiter(3, Duration.ofMinutes(15), Duration.ofMinutes(10), clock);

    @Test
    void locksAfterMaxFailuresAndUnlocksAfterLockout() {
        assertFalse(limiter.recordFailure("u"));
        assertFalse(limiter.recordFailure("u"));
        assertNull(limiter.lockedUntil("u"));
        assertTrue(limiter.recordFailure("u"), "third failure locks");
        assertEquals(clock.now.plus(Duration.ofMinutes(10)), limiter.lockedUntil("u"));
        clock.now = clock.now.plus(Duration.ofMinutes(9));
        assertTrue(limiter.lockedUntil("u") != null, "still locked");
        clock.now = clock.now.plus(Duration.ofMinutes(1));
        assertNull(limiter.lockedUntil("u"), "unlocked when the lockout has passed");
    }

    @Test
    void failuresOutsideWindowDoNotCount() {
        limiter.recordFailure("u");
        limiter.recordFailure("u");
        clock.now = clock.now.plus(Duration.ofMinutes(16));
        assertFalse(limiter.recordFailure("u"), "old failures expired");
        assertNull(limiter.lockedUntil("u"));
    }

    @Test
    void successClearsFailuresAndKeysAreIndependent() {
        limiter.recordFailure("u");
        limiter.recordFailure("u");
        limiter.recordSuccess("u");
        assertFalse(limiter.recordFailure("u"));
        limiter.recordFailure("v");
        limiter.recordFailure("v");
        assertTrue(limiter.recordFailure("v"));
        assertNull(limiter.lockedUntil("u"), "u is not affected by v");
    }

    @Test
    void resetUnlocks() {
        for (int i = 0; i < 3; i++) {
            limiter.recordFailure("u");
        }
        limiter.reset("u");
        assertNull(limiter.lockedUntil("u"));
    }

    @Test
    void rejectsNonsenseConfiguration() {
        assertThrows(IllegalArgumentException.class, () -> new AttemptLimiter(0, Duration.ofMinutes(1), Duration.ofMinutes(1), clock));
    }
}
