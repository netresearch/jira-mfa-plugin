package de.netresearch.jira.mfa.web;

import org.junit.jupiter.api.Test;

import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RequestGuardsTest {
    @Test
    void returnTargetMustBeALocalPathWithoutControlCharacters() {
        assertTrue(MfaServletSupport.isSafeLocalPath("/browse/TEST-1?focusedId=1"));
        assertFalse(MfaServletSupport.isSafeLocalPath("/\t/evil.example"), "browsers strip the tab: //evil.example");
        assertFalse(MfaServletSupport.isSafeLocalPath("/\n/evil.example"));
        assertFalse(MfaServletSupport.isSafeLocalPath("/x\u007f"));
        assertFalse(MfaServletSupport.isSafeLocalPath("//evil.example"));
        assertFalse(MfaServletSupport.isSafeLocalPath("/\\evil.example"));
        assertFalse(MfaServletSupport.isSafeLocalPath("https://evil.example/"));
        assertFalse(MfaServletSupport.isSafeLocalPath("/plugins/servlet/mfa/verify"));
        assertFalse(MfaServletSupport.isSafeLocalPath(null));
    }

    @Test
    void basicHeaderCountsOnlyWhenSeraphAcceptedItsPassword() {
        assertTrue(MfaFilter.basicPasswordChecked(request("success")));
        assertFalse(MfaFilter.basicPasswordChecked(request("failed")),
                "wrong password: the user came from a session or remember-me cookie");
        assertFalse(MfaFilter.basicPasswordChecked(request("error")));
        assertFalse(MfaFilter.basicPasswordChecked(request(null)), "no login attempt in this request");
    }

    @Test
    void requestsJirasOAuthFilterAuthenticatedPassBeforeAnyOtherCheck() {
        // no MfaService: any check after the OAuth attribute would throw
        MfaFilter filter = new MfaFilter(null);
        assertEquals(MfaFilter.Decision.PASS, filter.decide(withAttribute(MfaFilter.OAUTH_ATTRIBUTE, "true"), null));
        assertEquals(MfaFilter.Decision.PASS, filter.decide(withAttribute(MfaFilter.PAT_ATTRIBUTE, Boolean.TRUE), null));
        assertThrows(NullPointerException.class, () -> filter.decide(withAttribute("unrelated", "true"), null),
                "without either attribute the filter goes on to the user's state");
    }

    @Test
    void anUnwritableAnswerIsLoggedButOtherFailuresStillReachJira() {
        HttpServletRequest req = request(null);
        boolean[] ran = {false};
        MfaServletSupport.handle(req, null, (rq, rs) -> {
            ran[0] = true;
            throw new java.io.IOException("Broken pipe");
        });
        assertTrue(ran[0], "the handler runs");
        org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class, () ->
                MfaServletSupport.handle(req, null, (rq, rs) -> {
                    throw new IllegalStateException("bug");
                }), "a programming error is not swallowed");
    }

    private static HttpServletRequest withAttribute(String name, Object value) {
        return (HttpServletRequest) Proxy.newProxyInstance(RequestGuardsTest.class.getClassLoader(), new Class<?>[]{HttpServletRequest.class},
                (p, m, a) -> "getAttribute".equals(m.getName()) && name.equals(a[0]) ? value : null);
    }

    private static HttpServletRequest request(String authStatus) {
        return (HttpServletRequest) Proxy.newProxyInstance(RequestGuardsTest.class.getClassLoader(), new Class<?>[]{HttpServletRequest.class},
                (p, m, a) -> "getAttribute".equals(m.getName()) && MfaFilter.SERAPH_AUTH_STATUS.equals(a[0]) ? authStatus : null);
    }
}
