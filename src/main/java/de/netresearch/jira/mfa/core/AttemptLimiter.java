package de.netresearch.jira.mfa.core;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Limits failed second-step attempts per user: after {@code maxFailures}
 * failures within {@code window} the user is locked for {@code lockout}.
 * State is held in memory, so it is per node and resets on restart.
 */
public final class AttemptLimiter {
    private final int maxFailures;
    private final Duration window;
    private final Duration lockout;
    private final Clock clock;
    private final Map<String, State> states = new ConcurrentHashMap<>();

    public AttemptLimiter(int maxFailures, Duration window, Duration lockout, Clock clock) {
        if (maxFailures < 1) {
            throw new IllegalArgumentException("maxFailures must be >= 1");
        }
        this.maxFailures = maxFailures;
        this.window = window;
        this.lockout = lockout;
        this.clock = clock;
    }

    private static final class State {
        final Deque<Instant> failures = new ArrayDeque<>();
        Instant lockedUntil;
    }

    /** Returns the instant until which the key is locked, or null when attempts are allowed. */
    public Instant lockedUntil(String key) {
        State s = states.get(key);
        if (s == null) {
            return null;
        }
        synchronized (s) {
            Instant now = clock.instant();
            if (s.lockedUntil != null && now.isBefore(s.lockedUntil)) {
                return s.lockedUntil;
            }
            return null;
        }
    }

    /** Outcome of {@link #tryBegin}. */
    public enum Admission {
        /** The key is locked; do not check the attempt. */
        REFUSED,
        /** The attempt may be checked; it already counts as a failure until {@link #recordSuccess}. */
        ADMITTED,
        /** As {@link #ADMITTED}, but this attempt used up the allowance and locked the key. */
        ADMITTED_LAST
    }

    /**
     * Admits one attempt and counts it as a failure up front, in one step under
     * the key's lock. Counting before the check is what keeps parallel requests
     * from all passing a "not locked" test before any of their failures is
     * recorded. A correct attempt clears the count with {@link #recordSuccess}.
     */
    public Admission tryBegin(String key) {
        State s = states.computeIfAbsent(key, k -> new State());
        synchronized (s) {
            Instant now = clock.instant();
            if (s.lockedUntil != null && now.isBefore(s.lockedUntil)) {
                return Admission.REFUSED;
            }
            Instant cutoff = now.minus(window);
            while (!s.failures.isEmpty() && !s.failures.peekFirst().isAfter(cutoff)) {
                s.failures.pollFirst();
            }
            s.failures.addLast(now);
            if (s.failures.size() >= maxFailures) {
                s.failures.clear();
                s.lockedUntil = now.plus(lockout);
                return Admission.ADMITTED_LAST;
            }
            return Admission.ADMITTED;
        }
    }

    /** Clears failures and any lockout. The state object is kept, so a parallel {@link #tryBegin} cannot count into a detached one. */
    public void recordSuccess(String key) {
        State s = states.get(key);
        if (s != null) {
            synchronized (s) {
                s.failures.clear();
                s.lockedUntil = null;
            }
        }
    }

    public void reset(String key) {
        recordSuccess(key);
    }
}
