package de.netresearch.jira.mfa.core;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/** Immutable plugin configuration. Persisted by {@code SettingsStore}. */
public final class MfaSettings {
    public enum BasicAuthPolicy { BLOCK, ALLOW }

    public final boolean enabled;
    /** Groups whose members must use a second factor; empty means every user. */
    public final Set<String> enforcedGroups;
    public final Set<String> exemptGroups;
    public final Set<String> exemptUsers;
    public final int graceDays;
    public final BasicAuthPolicy basicAuthPolicy;
    /** Users that may still use HTTP Basic authentication (service accounts). */
    public final Set<String> basicAuthAllowedUsers;
    /** WebAuthn relying party ID; empty means the host of the Jira base URL. */
    public final String rpId;
    public final String issuer;
    public final int maxFailures;
    public final int lockoutMinutes;

    public MfaSettings(boolean enabled, Set<String> enforcedGroups, Set<String> exemptGroups, Set<String> exemptUsers,
                       int graceDays, BasicAuthPolicy basicAuthPolicy, Set<String> basicAuthAllowedUsers,
                       String rpId, String issuer, int maxFailures, int lockoutMinutes) {
        this.enabled = enabled;
        this.enforcedGroups = lower(enforcedGroups);
        this.exemptGroups = lower(exemptGroups);
        this.exemptUsers = lower(exemptUsers);
        this.graceDays = Math.max(0, graceDays);
        this.basicAuthPolicy = basicAuthPolicy;
        this.basicAuthAllowedUsers = lower(basicAuthAllowedUsers);
        this.rpId = rpId == null ? "" : rpId.trim();
        this.issuer = issuer == null || issuer.trim().isEmpty() ? "Jira" : issuer.trim();
        this.maxFailures = Math.max(1, maxFailures);
        this.lockoutMinutes = Math.max(1, lockoutMinutes);
    }

    public static MfaSettings defaults() {
        return new MfaSettings(true, Set.of(), Set.of(), Set.of(), 14, BasicAuthPolicy.BLOCK, Set.of(), "", "Jira", 5, 15);
    }

    /** Parses a comma- or newline-separated list. */
    public static Set<String> parseList(String raw) {
        if (raw == null) {
            return Set.of();
        }
        return Arrays.stream(raw.split("[,\\n\\r]+"))
                .map(String::trim).filter(s -> !s.isEmpty())
                .collect(Collectors.toCollection(LinkedHashSet::new));
    }

    public static String formatList(Set<String> values) {
        return String.join("\n", values);
    }

    private static Set<String> lower(Set<String> in) {
        if (in == null) {
            return Set.of();
        }
        Set<String> out = in.stream().map(s -> s.trim().toLowerCase(Locale.ROOT))
                .filter(s -> !s.isEmpty()).collect(Collectors.toCollection(LinkedHashSet::new));
        return Collections.unmodifiableSet(out);
    }

    public boolean isBasicAuthAllowedFor(String username) {
        return basicAuthPolicy == BasicAuthPolicy.ALLOW
                || basicAuthAllowedUsers.contains("*")
                || (username != null && basicAuthAllowedUsers.contains(username.toLowerCase(Locale.ROOT)));
    }
}
