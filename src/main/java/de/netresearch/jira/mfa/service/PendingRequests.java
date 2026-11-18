package de.netresearch.jira.mfa.service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Predicate;

/**
 * The outstanding passkey requests of one session, oldest first, as one
 * newline-separated string. Each open verify page starts its own request; a
 * later one must not replace an earlier one, or the earlier page's valid
 * assertion would be checked against the wrong challenge and counted as a
 * failed attempt.
 */
public final class PendingRequests {
    static final int MAX = 4;

    private PendingRequests() {
    }

    /** Appends a request; the oldest are dropped beyond {@link #MAX}. */
    public static String add(String stored, String request) {
        if (request.indexOf('\n') >= 0) {
            throw new IllegalArgumentException("a request must be a single line");
        }
        List<String> all = split(stored);
        all.add(request);
        while (all.size() > MAX) {
            all.remove(0);
        }
        return String.join("\n", all);
    }

    /**
     * Removes the first request that {@code matches} accepts. Returns
     * {@code {request, rest}}: the request or null, and what stays stored
     * (null when nothing stays).
     */
    public static String[] take(String stored, Predicate<String> matches) {
        List<String> all = split(stored);
        for (int i = 0; i < all.size(); i++) {
            if (matches.test(all.get(i))) {
                String hit = all.remove(i);
                return new String[]{hit, all.isEmpty() ? null : String.join("\n", all)};
            }
        }
        return new String[]{null, all.isEmpty() ? null : String.join("\n", all)};
    }

    private static List<String> split(String stored) {
        List<String> all = new ArrayList<>();
        if (stored != null && !stored.isEmpty()) {
            all.addAll(Arrays.asList(stored.split("\n")));
        }
        return all;
    }
}
