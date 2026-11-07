package de.netresearch.jira.mfa.core;

/**
 * Makes request-derived text safe for a log line: control characters
 * (line breaks above all) are replaced, so a crafted path or label cannot
 * start a forged log entry.
 */
public final class LogText {
    private LogText() {
    }

    public static String clean(Object value) {
        if (value == null) {
            return "null";
        }
        String s = value.toString();
        StringBuilder b = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            b.append(c < 0x20 || c == 0x7f || c == 0x2028 || c == 0x2029 ? '_' : c);
        }
        return b.toString();
    }
}
