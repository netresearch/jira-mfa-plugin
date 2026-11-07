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
            "/favicon.ico",
            "/status",
            "/logout",
            "/secure/Logout",
            "/login.jsp");

    /** Static resources, open directly or behind Jira's cache prefix {@code /s/<keys>/_/}. */
    private static final List<String> STATIC_PREFIXES = List.of(
            "/download/resources/",
            "/download/batch/",
            "/download/contextbatch/",
            "/images/",
            "/static-assets/");

    private static final String CACHE_PREFIX = "/s/";
    private static final String CACHE_SEPARATOR = "/_/";

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
            if (path.startsWith(p)) {
                return true;
            }
        }
        if (path.startsWith(CACHE_PREFIX)) {
            // Jira's URL rewriting forwards /s/<keys>/_/<path> to <path>; open only
            // when that target is itself a static resource, so the result does not
            // depend on the filter seeing the forward.
            int sep = path.indexOf(CACHE_SEPARATOR);
            if (sep < 0 || sep != path.lastIndexOf(CACHE_SEPARATOR)) {
                // none, or several: the rewrite may split at either, so do not guess
                return false;
            }
            path = path.substring(sep + CACHE_SEPARATOR.length() - 1);
        }
        for (String p : STATIC_PREFIXES) {
            if (path.startsWith(p)) {
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
