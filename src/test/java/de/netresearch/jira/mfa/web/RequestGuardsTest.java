package de.netresearch.jira.mfa.web;

import com.atlassian.jira.user.ApplicationUser;
import org.junit.jupiter.api.Test;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
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
    void basicHeaderCountsOnlyWhenNoCookieCouldHaveIdentifiedTheUser() {
        ApplicationUser alice = user("JIRAUSER10000");
        assertTrue(MfaFilter.basicIdentifiesTheUser(request(null), null, alice), "plain Basic request");
        assertTrue(MfaFilter.basicIdentifiesTheUser(request(null), session(true, null), alice),
                "session created by this Basic request");
        assertTrue(MfaFilter.basicIdentifiesTheUser(request(null), session(false, "JIRAUSER10000"), alice),
                "session a Basic request created earlier (script with a cookie jar)");
        assertFalse(MfaFilter.basicIdentifiesTheUser(request(null), session(false, null), alice),
                "existing browser session: the header's password was not checked");
        assertFalse(MfaFilter.basicIdentifiesTheUser(request(null), session(false, "JIRAUSER99999"), alice),
                "Basic session of another user");
        assertFalse(MfaFilter.basicIdentifiesTheUser(request(new Cookie(MfaFilter.REMEMBER_ME_COOKIE, "x")), session(true, null), alice),
                "remember-me cookie logs the user in before the header is read");
    }

    private static ApplicationUser user(String key) {
        return (ApplicationUser) Proxy.newProxyInstance(RequestGuardsTest.class.getClassLoader(), new Class<?>[]{ApplicationUser.class},
                (p, m, a) -> "getKey".equals(m.getName()) ? key : null);
    }

    private static HttpServletRequest request(Cookie cookie) {
        return (HttpServletRequest) Proxy.newProxyInstance(RequestGuardsTest.class.getClassLoader(), new Class<?>[]{HttpServletRequest.class},
                (p, m, a) -> "getCookies".equals(m.getName()) ? (cookie == null ? null : new Cookie[]{cookie}) : null);
    }

    private static HttpSession session(boolean isNew, String basicUserKey) {
        Map<String, Object> attrs = new HashMap<>();
        if (basicUserKey != null) {
            attrs.put(MfaFilter.S_BASIC_SESSION, basicUserKey);
        }
        return (HttpSession) Proxy.newProxyInstance(RequestGuardsTest.class.getClassLoader(), new Class<?>[]{HttpSession.class},
                (p, m, a) -> {
                    switch (m.getName()) {
                        case "isNew":
                            return isNew;
                        case "getAttribute":
                            return attrs.get((String) a[0]);
                        default:
                            return null;
                    }
                });
    }
}
