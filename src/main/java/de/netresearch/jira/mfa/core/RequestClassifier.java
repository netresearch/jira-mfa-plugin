package de.netresearch.jira.mfa.core;

import java.util.List;
import java.util.Locale;

/** Classifies request paths (relative to the context path) for the MFA filter. */
public final class RequestClassifier {
    public static final String MFA_PREFIX = "/plugins/servlet/mfa/";

    /** Reachable by a logged-in session that has not completed the second step. */
    private static final List<String> OPEN_PREFIXES = List.of(
            MFA_PREFIX,
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

    /** Requests that only an already verified session may make while enrolment is mandatory or pending. */
    private static final List<String> ENROL_OPEN_PREFIXES = List.of(MFA_PREFIX);

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

    public static boolean isOpen(String path) {
        if (path.contains("..")) {
            return false;
        }
        for (String p : OPEN_PREFIXES) {
            if (path.equals(p) || path.startsWith(p)) {
                return true;
            }
        }
        return false;
    }

    public static boolean isEnrolmentPath(String path) {
        return !path.contains("..") && ENROL_OPEN_PREFIXES.stream().anyMatch(path::startsWith);
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
