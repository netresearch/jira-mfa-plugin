package de.netresearch.jira.mfa.core;

/**
 * The session value that records a completed second step: the user key and
 * the time of verification. A mark counts only for the same user and only if
 * no factor was removed (and the user not reset) after it was set, so a
 * session an attacker verified with a stolen factor ends when that factor is
 * removed.
 */
public final class VerifiedMark {
    private VerifiedMark() {
    }

    public static String create(String userKey, long verifiedAtMillis) {
        return userKey + "|" + verifiedAtMillis;
    }

    public static boolean isValid(Object mark, String userKey, long factorsChangedMillis) {
        if (!(mark instanceof String) || userKey == null) {
            return false;
        }
        String s = (String) mark;
        int bar = s.lastIndexOf('|');
        if (bar < 0 || !s.substring(0, bar).equals(userKey)) {
            return false;
        }
        try {
            return Long.parseLong(s.substring(bar + 1)) >= factorsChangedMillis;
        } catch (NumberFormatException e) {
            return false;
        }
    }
}
