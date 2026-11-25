package de.netresearch.jira.mfa.core;

import de.netresearch.jira.mfa.core.RelyingParties.InvalidSettingException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RelyingPartiesTest {
    private static final String OLD = "jira.example.com";
    private static final String NEW = "jira.example.org";

    @Test
    void relatedOriginsAreNormalisedLikeTheBrowserDoes() throws Exception {
        assertEquals("https://jira.example.org", RelyingParties.relatedOrigin("HTTPS://Jira.Example.org"));
        assertEquals("https://jira.example.org", RelyingParties.relatedOrigin("https://jira.example.org:443"));
        assertEquals("https://jira.example.org:8443", RelyingParties.relatedOrigin("https://jira.example.org:8443"));
        assertEquals("http://localhost:18080", RelyingParties.relatedOrigin("http://localhost:18080"));
        assertEquals("http://localhost", RelyingParties.relatedOrigin("http://localhost:80"));
        assertEquals(Set.of("https://jira.example.org"), RelyingParties.relatedOrigins(
                List.of("https://jira.example.org", "https://JIRA.example.org:443")));
        assertEquals(Set.of(), RelyingParties.relatedOrigins(Set.of()));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "jira.example.org", "//jira.example.org", "http://jira.example.org", "http://localhost.example.org",
            "ftp://jira.example.org", "https:jira.example.org", "https://", "https:///x", "https://jira.example.org/",
            "https://jira.example.org/jira", "https://jira.example.org?x", "https://jira.example.org?", "https://jira.example.org#x",
            "https://jira.example.org#", "https://user@jira.example.org", "https://user:pw@jira.example.org", "https://*.example.org", "https://*",
            "https://jira.example.org:", "https://jira.example.org:0", "https://jira.example.org:0443", "https://jira.example.org:65536",
            "https://jira example.org", "https://jira.example.org\\x", "https://j\u00edra.example.org", "https://[::1]", "https://-jira.example.org",
            "https://jira.example.org.", "javascript:alert(1)", "null"})
    void anythingElseIsRefused(String raw) {
        InvalidSettingException e = assertThrows(InvalidSettingException.class, () -> RelyingParties.relatedOrigin(raw));
        assertTrue(e.getMessage().contains("\"" + raw + "\""), "the message names the entry");
    }

    @Test
    void aRelyingPartyIdIsAHostName() throws Exception {
        assertEquals("", RelyingParties.relyingPartyId(null));
        assertEquals("", RelyingParties.relyingPartyId(" "));
        assertEquals(OLD, RelyingParties.relyingPartyId(" Jira.Example.com "));
        assertEquals("localhost", RelyingParties.relyingPartyId("localhost"));
        assertEquals("a".repeat(63) + ".x-y.example.com", RelyingParties.relyingPartyId("a".repeat(63) + ".x-y.example.com"));
        for (String bad : List.of("https://jira.example.com", "jira.example.com:8443", "jira.example.com/", "*.example.com", "jira..example.com",
                "jira.example.com.", ".example.com", "jira-.example.com", "a".repeat(64) + ".example.com", "a.".repeat(50_000) + "a")) {
            assertThrows(InvalidSettingException.class, () -> RelyingParties.relyingPartyId(bad), bad);
        }
    }

    @Test
    void allowedOriginsAreTheBaseUrlAndTheConfiguredOnes() {
        assertEquals(List.of("https://jira.example.com"), List.copyOf(RelyingParties.allowedOrigins("https://jira.example.com/jira", Set.of())));
        assertEquals(List.of("https://jira.example.com", "https://jira.example.org"),
                List.copyOf(RelyingParties.allowedOrigins("https://jira.example.com", List.of("https://jira.example.org", "https://jira.example.com"))));
    }

    @Test
    void aPasskeyWithoutStoredIdBelongsToTheLegacyIdOrTheCurrentOne() {
        assertEquals(OLD, RelyingParties.effectiveRpId(null, OLD, NEW));
        assertEquals(OLD, RelyingParties.effectiveRpId("", OLD, NEW), "Oracle stores an empty string as null");
        assertEquals(NEW, RelyingParties.effectiveRpId(null, "", NEW));
        assertEquals(NEW, RelyingParties.effectiveRpId(NEW, OLD, OLD), "a stored ID wins");
    }

    @Test
    void passkeysAreCountedPerEffectiveId() {
        assertEquals(Map.of(OLD, 2, NEW, 1), RelyingParties.countByEffectiveRpId(Arrays.asList(null, NEW, OLD), OLD, NEW));
        assertEquals(Map.of(NEW, 3), RelyingParties.countByEffectiveRpId(Arrays.asList(null, NEW, ""), "", NEW));
        assertEquals(List.of(OLD, NEW), List.copyOf(RelyingParties.countByEffectiveRpId(List.of(NEW, OLD), "", NEW).keySet()), "alphabetically");
        assertEquals(Map.of(), RelyingParties.countByEffectiveRpId(List.of(), OLD, NEW));
    }

    @Test
    void theGroupOfTheRequestHostIsPreferred() {
        assertEquals(OLD, RelyingParties.chooseRpId(Set.of(OLD, NEW), OLD, NEW));
        assertEquals(NEW, RelyingParties.chooseRpId(Set.of(OLD, NEW), NEW, OLD));
        assertEquals("example.com", RelyingParties.chooseRpId(Set.of("example.com", NEW), OLD, NEW), "a parent domain");
        assertEquals(OLD, RelyingParties.chooseRpId(Set.of("example.com", OLD), OLD, NEW), "the longest match");
    }

    @Test
    void aParentDomainEndsAtALabel() {
        assertEquals(NEW, RelyingParties.chooseRpId(Set.of("example.com", NEW), "evilexample.com", NEW));
        assertEquals(NEW, RelyingParties.chooseRpId(Set.of("www.jira.example.com", NEW), OLD, NEW), "a subdomain is no match");
    }

    @Test
    void otherwiseTheConfiguredGroupThenAFixedOne() {
        assertEquals(NEW, RelyingParties.chooseRpId(Set.of(OLD, NEW), "jira.example.net", NEW));
        assertEquals(NEW, RelyingParties.chooseRpId(Set.of(OLD, NEW), null, NEW));
        assertEquals("a.example.com", RelyingParties.chooseRpId(List.of("c.example.com", "a.example.com", "b.example.com"), null, NEW));
        assertEquals(NEW, RelyingParties.chooseRpId(Set.of(), "jira.example.net", NEW), "no passkeys: the configured ID");
    }

    @Test
    void theRequestHostIsNeverChosenItself() {
        assertEquals(OLD, RelyingParties.chooseRpId(Set.of(OLD), "evil.example.net", NEW));
        assertEquals(NEW, RelyingParties.chooseRpId(Set.of(), "evil.example.net", NEW));
    }

    @Test
    void theHostOfAnOriginHeader() {
        assertEquals(OLD, RelyingParties.originHost("https://Jira.Example.com:8443"));
        assertNull(RelyingParties.originHost(null));
        assertNull(RelyingParties.originHost("null"));
        assertNull(RelyingParties.originHost("https://a b"));
    }

    @Test
    void onlyTheExactWellKnownPathCounts() {
        assertTrue(RelyingParties.isWellKnown("/.well-known/webauthn", ""));
        assertTrue(RelyingParties.isWellKnown("/jira/.well-known/webauthn", "/jira"));
        for (String other : List.of("/.well-known/webauthn/", "/.well-known/webauthn/x", "/.well-known/webauthn;x=1", "/.well-known;x/webauthn",
                "/.well-known/%77ebauthn", "/%2ewell-known/webauthn", "//.well-known/webauthn", "/x/../.well-known/webauthn",
                "/x/..;/.well-known/webauthn", "/.well-known/webauthn/../../secure/Dashboard.jspa", "/.well-known/WebAuthn",
                "/x/.well-known/webauthn", "/s/1/_/.well-known/webauthn", "/.well-known/")) {
            assertFalse(RelyingParties.isWellKnown(other, ""), other);
        }
        assertFalse(RelyingParties.isWellKnown(null, ""));
        assertFalse(RelyingParties.isWellKnown("/.well-known/webauthn", "/jira"));
    }

    @Test
    void theFilterOfTheSecondStepHasNoOpenPathForIt() {
        for (String p : List.of(RelyingParties.WELL_KNOWN_PATH, RelyingParties.WELL_KNOWN_PATH + "/x", "/.well-known/")) {
            assertFalse(RequestClassifier.isOpen(p), p);
            assertFalse(RequestClassifier.isOpenExact(p, p, ""), p);
        }
    }
}
