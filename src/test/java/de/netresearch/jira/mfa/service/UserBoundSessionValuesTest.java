package de.netresearch.jira.mfa.service;

import org.junit.jupiter.api.Test;

import javax.servlet.http.HttpSession;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

class UserBoundSessionValuesTest {
    private final Map<String, Object> attrs = new HashMap<>();
    private final HttpSession session = (HttpSession) Proxy.newProxyInstance(getClass().getClassLoader(),
            new Class<?>[]{HttpSession.class}, (p, m, a) -> {
                switch (m.getName()) {
                    case "getAttribute":
                        return attrs.get((String) a[0]);
                    case "setAttribute":
                        attrs.put((String) a[0], a[1]);
                        return null;
                    case "removeAttribute":
                        attrs.remove((String) a[0]);
                        return null;
                    default:
                        return null;
                }
            });

    @Test
    void valueIsReturnedOnlyToTheUserItWasStoredFor() {
        MfaService.putForUser(session, MfaService.S_PENDING_TOTP, "JIRAUSER10000", "v1:secret-of-a");
        assertEquals("v1:secret-of-a", MfaService.getForUser(session, MfaService.S_PENDING_TOTP, "JIRAUSER10000"));
        assertNull(MfaService.getForUser(session, MfaService.S_PENDING_TOTP, "JIRAUSER10001"),
                "after a re-login as another user in the same browser");
        assertFalse(attrs.containsKey(MfaService.S_PENDING_TOTP), "the other user's value is discarded");
    }

    @Test
    void takeIsSingleUseAndOldUnboundValuesAreDiscarded() {
        MfaService.putForUser(session, MfaService.S_REG_REQUEST, "JIRAUSER10000", "{\"challenge\":\"x|y\"}");
        assertEquals("{\"challenge\":\"x|y\"}", MfaService.takeForUser(session, MfaService.S_REG_REQUEST, "JIRAUSER10000"));
        assertNull(MfaService.takeForUser(session, MfaService.S_REG_REQUEST, "JIRAUSER10000"));
        attrs.put(MfaService.S_AUTH_REQUEST, "a plain value from before this version");
        assertNull(MfaService.getForUser(session, MfaService.S_AUTH_REQUEST, "JIRAUSER10000"));
        assertFalse(attrs.containsKey(MfaService.S_AUTH_REQUEST));
    }
}
