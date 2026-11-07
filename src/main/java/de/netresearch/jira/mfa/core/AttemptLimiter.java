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

    /** Records a failure; returns true when this failure triggered a lockout. */
    public boolean recordFailure(String key) {
        State s = states.computeIfAbsent(key, k -> new State());
        synchronized (s) {
            Instant now = clock.instant();
            Instant cutoff = now.minus(window);
            while (!s.failures.isEmpty() && !s.failures.peekFirst().isAfter(cutoff)) {
                s.failures.pollFirst();
            }
            s.failures.addLast(now);
            if (s.failures.size() >= maxFailures) {
                s.failures.clear();
                s.lockedUntil = now.plus(lockout);
                return true;
            }
            return false;
        }
    }

    public void recordSuccess(String key) {
        states.remove(key);
    }

    public void reset(String key) {
        states.remove(key);
    }
}
