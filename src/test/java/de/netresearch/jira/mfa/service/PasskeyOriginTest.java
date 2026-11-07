package de.netresearch.jira.mfa.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class PasskeyOriginTest {
    @Test
    void defaultPortsAreOmittedLikeTheBrowserDoes() {
        assertEquals("https://jira.example.com", PasskeyService.origin("https://jira.example.com:443"));
        assertEquals("https://jira.example.com", PasskeyService.origin("https://jira.example.com/jira"));
        assertEquals("http://localhost", PasskeyService.origin("http://localhost:80/"));
        assertEquals("https://jira.example.com", PasskeyService.origin("HTTPS://Jira.Example.com"));
    }

    @Test
    void otherPortsAreKept() {
        assertEquals("http://localhost:18080", PasskeyService.origin("http://localhost:18080"));
        assertEquals("https://jira.example.com:8443", PasskeyService.origin("https://jira.example.com:8443/jira"));
        assertEquals("http://jira.example.com:443", PasskeyService.origin("http://jira.example.com:443"));
    }
}
