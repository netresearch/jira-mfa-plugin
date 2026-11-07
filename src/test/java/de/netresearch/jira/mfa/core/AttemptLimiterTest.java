package de.netresearch.jira.mfa.core;

import de.netresearch.jira.mfa.core.AttemptLimiter.Admission;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AttemptLimiterTest {
    static final class MutableClock extends Clock {
        volatile Instant now = Instant.parse("2026-11-07T10:00:00Z");

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
    void locksAfterMaxAttemptsAndUnlocksAfterLockout() {
        assertEquals(Admission.ADMITTED, limiter.tryBegin("u"));
        assertEquals(Admission.ADMITTED, limiter.tryBegin("u"));
        assertNull(limiter.lockedUntil("u"));
        assertEquals(Admission.ADMITTED_LAST, limiter.tryBegin("u"), "third attempt is checked and locks");
        assertEquals(clock.now.plus(Duration.ofMinutes(10)), limiter.lockedUntil("u"));
        assertEquals(Admission.REFUSED, limiter.tryBegin("u"));
        clock.now = clock.now.plus(Duration.ofMinutes(9));
        assertEquals(Admission.REFUSED, limiter.tryBegin("u"), "still locked");
        clock.now = clock.now.plus(Duration.ofMinutes(1));
        assertNull(limiter.lockedUntil("u"), "unlocked when the lockout has passed");
        assertEquals(Admission.ADMITTED, limiter.tryBegin("u"), "a fresh allowance after the lockout");
    }

    @Test
    void attemptsOutsideWindowDoNotCount() {
        limiter.tryBegin("u");
        limiter.tryBegin("u");
        clock.now = clock.now.plus(Duration.ofMinutes(16));
        assertEquals(Admission.ADMITTED, limiter.tryBegin("u"), "old attempts expired");
        assertNull(limiter.lockedUntil("u"));
    }

    @Test
    void successClearsAttemptsAndLockoutAndKeysAreIndependent() {
        limiter.tryBegin("u");
        limiter.tryBegin("u");
        assertEquals(Admission.ADMITTED_LAST, limiter.tryBegin("u"));
        limiter.recordSuccess("u");
        assertNull(limiter.lockedUntil("u"), "a correct last attempt lifts its own lockout");
        assertEquals(Admission.ADMITTED, limiter.tryBegin("u"));
        limiter.tryBegin("v");
        limiter.tryBegin("v");
        assertEquals(Admission.ADMITTED_LAST, limiter.tryBegin("v"));
        assertNull(limiter.lockedUntil("u"), "u is not affected by v");
    }

    @Test
    void resetUnlocks() {
        for (int i = 0; i < 3; i++) {
            limiter.tryBegin("u");
        }
        assertNotNull(limiter.lockedUntil("u"));
        limiter.reset("u");
        assertNull(limiter.lockedUntil("u"));
    }

    @Test
    void parallelAttemptsGetNoMoreThanTheAllowance() throws Exception {
        int threads = 64;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<Admission>> results = new ArrayList<>();
        try {
            for (int i = 0; i < threads; i++) {
                results.add(pool.submit(() -> {
                    start.await();
                    return limiter.tryBegin("u");
                }));
            }
            start.countDown();
            int admitted = 0;
            for (Future<Admission> f : results) {
                if (f.get(10, TimeUnit.SECONDS) != Admission.REFUSED) {
                    admitted++;
                }
            }
            assertEquals(3, admitted, "only maxFailures attempts may be checked");
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void rejectsNonsenseConfiguration() {
        assertThrows(IllegalArgumentException.class, () -> new AttemptLimiter(0, Duration.ofMinutes(1), Duration.ofMinutes(1), clock));
    }
}
