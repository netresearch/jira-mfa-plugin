package de.netresearch.jira.mfa.core;

import java.util.List;
import java.util.Locale;

/** Classifies request paths (relative to the context path) for the MFA filter. */
public final class RequestClassifier {
    public static final String MFA_PREFIX = "/plugins/servlet/mfa/";

    /**
     * Reachable by a logged-in session that has not completed the second step.
     * The plugin's admin page is deliberately not listed: it must only be
     * reachable from a verified session.
     */
    private static final List<String> OPEN_PREFIXES = List.of(
            MFA_PREFIX + "verify",
            MFA_PREFIX + "setup",
            MFA_PREFIX + "webauthn/",
            "/s/",                       // cached static resources
            "/download/resources/",
            "/download/batch/",
            "/download/contextbatch/",
            "/images/",
            "/static-assets/",
            "/favicon.ico",
            "/status",
            "/logout",
            "/secure/Logout",
            "/login.jsp");

    private RequestClassifier() {
    }

    public static String relativePath(String requestUri, String contextPath) {
        String path = requestUri == null ? "/" : requestUri;
        if (contextPath != null && !contextPath.isEmpty() && path.startsWith(contextPath)) {
            path = path.substring(contextPath.length());
        }
        int semicolon = path.indexOf(';');
        if (semicolon >= 0) {
            path = path.substring(0, semicolon);
        }
        return path.isEmpty() ? "/" : path;
    }

    /**
     * The path the container dispatches to: servlet path plus path info, which
     * the container has already decoded and normalised (so {@code /a/%2e%2e/b}
     * arrives as {@code /b}).
     */
    public static String dispatchPath(String servletPath, String pathInfo) {
        String p = (servletPath == null ? "" : servletPath) + (pathInfo == null ? "" : pathInfo);
        return p.isEmpty() ? "/" : p;
    }

    /** True when the raw URI hides dots, slashes or backslashes in percent-encoding. */
    public static boolean hasEncodedSeparators(String rawUri) {
        if (rawUri == null) {
            return false;
        }
        String r = rawUri.toLowerCase(Locale.ROOT);
        return r.contains("%2e") || r.contains("%2f") || r.contains("%5c") || r.contains("%25");
    }

    public static boolean isOpen(String path) {
        if (path.contains("..") || path.contains("\\")) {
            return false;
        }
        for (String p : OPEN_PREFIXES) {
            if (path.equals(p) || path.startsWith(p)) {
                return true;
            }
        }
        return false;
    }

    /**
     * True when the client expects data rather than a page: REST paths, XHR and
     * fetch requests, or an Accept header that does not ask for HTML.
     */
    public static boolean isApiRequest(String path, String accept, String requestedWith) {
        if (path.startsWith("/rest/") || path.startsWith("/sr/") || path.startsWith("/plugins/servlet/applinks/")) {
            return true;
        }
        if ("XMLHttpRequest".equalsIgnoreCase(requestedWith)) {
            return true;
        }
        if (accept == null || accept.isEmpty()) {
            return false;
        }
        String a = accept.toLowerCase(Locale.ROOT);
        return !a.contains("text/html") && !a.contains("*/*");
    }

    public enum AuthScheme { NONE, BASIC, BEARER, OAUTH, OTHER }

    public static AuthScheme scheme(String authorization) {
        if (authorization == null || authorization.trim().isEmpty()) {
            return AuthScheme.NONE;
        }
        String a = authorization.trim().toLowerCase(Locale.ROOT);
        if (a.startsWith("basic ")) {
            return AuthScheme.BASIC;
        }
        if (a.startsWith("bearer ")) {
            return AuthScheme.BEARER;
        }
        if (a.startsWith("oauth ")) {
            return AuthScheme.OAUTH;
        }
        return AuthScheme.OTHER;
    }
}
