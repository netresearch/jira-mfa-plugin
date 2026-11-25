package de.netresearch.jira.mfa.core;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

/** Rules for passkeys across several host names: origins, relying party IDs and the choice between them. */
public final class RelyingParties {
    /** The path browsers read for WebAuthn related origin requests. */
    public static final String WELL_KNOWN_PATH = "/.well-known/webauthn";

    private static final int MAX_HOST = 253;
    private static final Pattern LABEL = Pattern.compile("[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?");

    private RelyingParties() {
    }

    /** A setting the administrator has to correct; the message is shown on the admin page. */
    public static final class InvalidSettingException extends Exception {
        private static final long serialVersionUID = 1L;

        InvalidSettingException(String message) {
            super(message);
        }
    }

    /** The browser's origin for a URL: default ports are omitted, as browsers do. */
    public static String origin(String url) {
        return origin(URI.create(url));
    }

    private static String origin(URI u) {
        String scheme = u.getScheme().toLowerCase(Locale.ROOT);
        int port = u.getPort();
        boolean defaultPort = port < 0 || ("https".equals(scheme) && port == 443) || ("http".equals(scheme) && port == 80);
        return scheme + "://" + u.getHost().toLowerCase(Locale.ROOT) + (defaultPort ? "" : ":" + port);
    }

    /**
     * Parses one related origin: https (http only for localhost), a host name
     * and an optional port, nothing else. Returns the normalised origin.
     */
    public static String relatedOrigin(String raw) throws InvalidSettingException {
        URI u;
        try {
            u = new URI(raw);
        } catch (URISyntaxException e) {
            throw invalidOrigin(raw);
        }
        if (u.getScheme() == null || u.getHost() == null) {
            throw invalidOrigin(raw);
        }
        String scheme = u.getScheme().toLowerCase(Locale.ROOT);
        String host = u.getHost().toLowerCase(Locale.ROOT);
        boolean schemeOk = "https".equals(scheme) || ("http".equals(scheme) && "localhost".equals(host));
        String authority = u.getPort() < 0 ? host : host + ":" + u.getPort();
        // the comparison refuses user info, a path, a query, a fragment and an empty or zero-padded port
        boolean nothingElse = (scheme + "://" + authority).equals(raw.toLowerCase(Locale.ROOT));
        boolean portOk = u.getPort() < 0 || (u.getPort() > 0 && u.getPort() <= 65535);
        if (!schemeOk || !nothingElse || !portOk || !isHostName(host)) {
            throw invalidOrigin(raw);
        }
        return origin(u);
    }

    /** Labels are matched one by one: a single pattern with a repeated group recurses once per label. */
    private static boolean isHostName(String host) {
        return host.length() <= MAX_HOST && Arrays.stream(host.split("\\.", -1)).allMatch(l -> LABEL.matcher(l).matches());
    }

    private static InvalidSettingException invalidOrigin(String raw) {
        return new InvalidSettingException("\"" + raw + "\" is not a valid related origin. Enter https://host or https://host:port"
                + " (http only for localhost), without path, query, user name or wildcard.");
    }

    public static Set<String> relatedOrigins(Collection<String> raw) throws InvalidSettingException {
        Set<String> out = new LinkedHashSet<>();
        for (String r : raw) {
            out.add(relatedOrigin(r));
        }
        return out;
    }

    /** A relying party ID as entered: a host name, or empty. */
    public static String relyingPartyId(String raw) throws InvalidSettingException {
        String id = raw == null ? "" : raw.trim().toLowerCase(Locale.ROOT);
        if (!id.isEmpty() && !isHostName(id)) {
            throw new InvalidSettingException("\"" + raw + "\" is not a valid relying party ID. Enter a host name without scheme and port.");
        }
        return id;
    }

    /** Every origin a ceremony may come from: the base URL's, then the configured ones. */
    public static Set<String> allowedOrigins(String baseUrl, Collection<String> relatedOrigins) {
        Set<String> out = new LinkedHashSet<>();
        out.add(origin(baseUrl));
        out.addAll(relatedOrigins);
        return out;
    }

    /** The relying party ID of a stored passkey; rows from before the column existed have none. */
    public static String effectiveRpId(String stored, String legacyRpId, String currentRpId) {
        if (stored != null && !stored.isEmpty()) {
            return stored;
        }
        return legacyRpId.isEmpty() ? currentRpId : legacyRpId;
    }

    /** The host of an Origin header, lower case, or null. */
    public static String originHost(String originHeader) {
        if (originHeader == null) {
            return null;
        }
        try {
            String host = new URI(originHeader.trim()).getHost();
            return host == null ? null : host.toLowerCase(Locale.ROOT);
        } catch (URISyntaxException e) {
            return null;
        }
    }

    /**
     * The one relying party ID an assertion asks for, among those of the user's
     * passkeys: the one the request host belongs to (the longest, if several),
     * else the configured one, else the alphabetically first. The request host
     * only selects among the user's own IDs; it is never added to anything.
     * Without passkeys this is the configured ID.
     */
    public static String chooseRpId(Collection<String> userRpIds, String requestHost, String configuredRpId) {
        Set<String> ids = new TreeSet<>(userRpIds);
        if (requestHost != null) {
            String match = ids.stream().filter(id -> isSameOrParent(id, requestHost))
                    .max(Comparator.comparingInt(String::length)).orElse(null);
            if (match != null) {
                return match;
            }
        }
        if (ids.isEmpty() || ids.contains(configuredRpId)) {
            return configuredRpId;
        }
        return ids.iterator().next();
    }

    private static boolean isSameOrParent(String rpId, String host) {
        return host.equals(rpId) || host.endsWith("." + rpId);
    }

    /**
     * True only for the raw request URI {@code <context path>/.well-known/webauthn},
     * byte for byte: no path parameter, encoding, extra slash or sub-path.
     */
    public static boolean isWellKnown(String requestUri, String contextPath) {
        return ((contextPath == null ? "" : contextPath) + WELL_KNOWN_PATH).equals(requestUri);
    }

    /** The well-known document. Origins are validated host names, so they need no JSON escaping. */
    public static String wellKnownJson(Collection<String> origins) {
        return "{\"origins\":[\"" + String.join("\",\"", origins) + "\"]}";
    }
}
