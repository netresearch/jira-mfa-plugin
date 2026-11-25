package de.netresearch.jira.mfa.core;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class OriginTest {
    @Test
    void defaultPortsAreOmittedLikeTheBrowserDoes() {
        assertEquals("https://jira.example.com", RelyingParties.origin("https://jira.example.com:443"));
        assertEquals("https://jira.example.com", RelyingParties.origin("https://jira.example.com/jira"));
        assertEquals("http://localhost", RelyingParties.origin("http://localhost:80/"));
        assertEquals("https://jira.example.com", RelyingParties.origin("HTTPS://Jira.Example.com"));
    }

    @Test
    void otherPortsAreKept() {
        assertEquals("http://localhost:18080", RelyingParties.origin("http://localhost:18080"));
        assertEquals("https://jira.example.com:8443", RelyingParties.origin("https://jira.example.com:8443/jira"));
        assertEquals("http://jira.example.com:443", RelyingParties.origin("http://jira.example.com:443"));
    }
}
