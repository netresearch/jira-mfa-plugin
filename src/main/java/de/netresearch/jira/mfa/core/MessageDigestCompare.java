package de.netresearch.jira.mfa.core;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/** Constant-time comparison helpers. */
final class MessageDigestCompare {
    private MessageDigestCompare() {
    }

    static boolean equal(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }
}
