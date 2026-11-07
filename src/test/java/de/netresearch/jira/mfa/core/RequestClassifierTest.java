package de.netresearch.jira.mfa.core;

import de.netresearch.jira.mfa.core.RequestClassifier.AuthScheme;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RequestClassifierTest {
    @Test
    void relativePathStripsContextAndPathParameters() {
        assertEquals("/secure/Dashboard.jspa", RequestClassifier.relativePath("/jira/secure/Dashboard.jspa", "/jira"));
        assertEquals("/browse/X-1", RequestClassifier.relativePath("/browse/X-1;jsessionid=abc", ""));
        assertEquals("/", RequestClassifier.relativePath("/jira", "/jira"));
    }

    @Test
    void onlyPluginPagesAndStaticResourcesAreOpen() {
        assertTrue(RequestClassifier.isOpen("/plugins/servlet/mfa/verify"));
        assertTrue(RequestClassifier.isOpen("/s/abc/_/download/resources/x.js"));
        assertTrue(RequestClassifier.isOpen("/download/resources/de.netresearch.jira.jira-mfa-plugin:mfa-assets/mfa.js"));
        assertTrue(RequestClassifier.isOpen("/logout"));
        assertFalse(RequestClassifier.isOpen("/secure/Dashboard.jspa"));
        assertFalse(RequestClassifier.isOpen("/rest/api/2/myself"));
        assertFalse(RequestClassifier.isOpen("/rest/plugins/1.0/safe-mode"));
        assertFalse(RequestClassifier.isOpen("/plugins/servlet/mfa/../../secure/admin"), "no traversal");
        assertFalse(RequestClassifier.isOpen("/plugins/servlet/mfaX"));
        assertTrue(RequestClassifier.isOpen("/plugins/servlet/mfa/setup"));
        assertTrue(RequestClassifier.isOpen("/plugins/servlet/mfa/webauthn/authenticate/options"));
        assertFalse(RequestClassifier.isOpen("/plugins/servlet/mfa/admin"), "admin page needs a verified session");
    }

    @Test
    void cachePrefixIsOpenOnlyForStaticTargets() {
        assertTrue(RequestClassifier.isOpen("/s/d41d8cd98f00b204e9800998ecf8427e-CDN/-1ka3d/9120003/_/download/batch/x/x.css"));
        assertTrue(RequestClassifier.isOpen("/s/abc/_/images/icons/x.png"));
        assertFalse(RequestClassifier.isOpen("/s/1/_/browse/TEST-1"), "a page behind the cache prefix");
        assertFalse(RequestClassifier.isOpen("/s/1/_/rest/api/2/myself"), "REST behind the cache prefix");
        assertFalse(RequestClassifier.isOpen("/s/1/_/plugins/servlet/mfa/admin"));
        assertFalse(RequestClassifier.isOpen("/s/1/_/s/2/_/secure/Dashboard.jspa"), "nested prefix");
        assertFalse(RequestClassifier.isOpen("/s/no-separator/download/resources/x.js"));
        assertFalse(RequestClassifier.isOpen("/s/x/_/download/resources/y/_/secure/Dashboard.jspa"),
                "a greedy rewrite would split at the last separator");
    }

    @Test
    void encodedTraversalIsDetected() {
        assertTrue(RequestClassifier.hasEncodedSeparators("/plugins/servlet/mfa/verify/%2e%2e/%2E%2E/secure/Dashboard.jspa"));
        assertTrue(RequestClassifier.hasEncodedSeparators("/plugins/servlet/mfa/verify%2f..%2fx"));
        assertTrue(RequestClassifier.hasEncodedSeparators("/plugins/servlet/mfa/verify/%252e%252e/x"));
        assertFalse(RequestClassifier.hasEncodedSeparators("/plugins/servlet/mfa/verify"));
        assertEquals("/plugins/servlet/mfa/verify", RequestClassifier.dispatchPath("/plugins/servlet", "/mfa/verify"));
        assertEquals("/secure/Dashboard.jspa", RequestClassifier.dispatchPath("/secure/Dashboard.jspa", null));
        assertEquals("/", RequestClassifier.dispatchPath("", null));
    }

    @Test
    void apiDetection() {
        assertTrue(RequestClassifier.isApiRequest("/rest/api/2/issue/X-1", "text/html", null));
        assertTrue(RequestClassifier.isApiRequest("/secure/QuickCreateIssue!default.jspa", null, "XMLHttpRequest"));
        assertTrue(RequestClassifier.isApiRequest("/secure/x", "application/json", null));
        assertFalse(RequestClassifier.isApiRequest("/secure/Dashboard.jspa", "text/html,application/xhtml+xml", null));
        assertFalse(RequestClassifier.isApiRequest("/browse/X-1", null, null));
        assertFalse(RequestClassifier.isApiRequest("/browse/X-1", "*/*", null));
    }

    @Test
    void authorizationSchemes() {
        assertEquals(AuthScheme.NONE, RequestClassifier.scheme(null));
        assertEquals(AuthScheme.BASIC, RequestClassifier.scheme("Basic YTpi"));
        assertEquals(AuthScheme.BEARER, RequestClassifier.scheme("bearer abc"));
        assertEquals(AuthScheme.OAUTH, RequestClassifier.scheme("OAuth oauth_consumer_key=\"x\""));
        assertEquals(AuthScheme.OTHER, RequestClassifier.scheme("Negotiate abc"));
    }
}
