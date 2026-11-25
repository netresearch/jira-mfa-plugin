package de.netresearch.jira.mfa.web;

import de.netresearch.jira.mfa.core.MfaSettings;
import de.netresearch.jira.mfa.service.JiraEnvironment;
import de.netresearch.jira.mfa.service.MfaService;
import de.netresearch.jira.mfa.service.PasskeyService;
import de.netresearch.jira.mfa.service.SettingsStore;
import org.junit.jupiter.api.Test;

import javax.servlet.ServletOutputStream;
import javax.servlet.WriteListener;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class WellKnownFilterTest {
    private static final String PATH = "/.well-known/webauthn";
    private static final String BODY = "{\"origins\":[\"https://jira.example.com\",\"https://jira.example.org\"]}";
    private final Map<String, Object> set = new HashMap<>();
    private final ByteArrayOutputStream body = new ByteArrayOutputStream();
    private boolean passed;

    private void run(String method, String uri, Set<String> relatedOrigins) throws Exception {
        MfaSettings s = new MfaSettings(true, Set.of(), Set.of(), Set.of(), 14, MfaSettings.BasicAuthPolicy.BLOCK, Set.of(), "",
                relatedOrigins, "", "Jira", 5, 15);
        SettingsStore settings = new SettingsStore(null) {
            @Override
            public MfaSettings get() {
                return s;
            }
        };
        JiraEnvironment env = new JiraEnvironment() {
            @Override
            public String baseUrl() {
                return "https://jira.example.com";
            }
        };
        MfaService mfa = new MfaService(null, settings, env, null, new PasskeyService(null, settings, env));
        ClassLoader cl = WellKnownFilterTest.class.getClassLoader();
        HttpServletRequest req = (HttpServletRequest) Proxy.newProxyInstance(cl, new Class<?>[]{HttpServletRequest.class}, (p, m, a) -> {
            switch (m.getName()) {
                case "getMethod": return method;
                case "getRequestURI": return uri;
                case "getContextPath": return "";
                default: throw new AssertionError("the answer must not depend on " + m.getName());
            }
        });
        HttpServletResponse resp = (HttpServletResponse) Proxy.newProxyInstance(cl, new Class<?>[]{HttpServletResponse.class}, (p, m, a) -> {
            if ("getOutputStream".equals(m.getName())) {
                return new Out(body);
            }
            set.put(a.length == 2 ? (String) a[0] : m.getName(), a[a.length - 1]);
            return null;
        });
        new WellKnownFilter(mfa).doFilter(req, resp, (rq, rs) -> passed = true);
    }

    private static final class Out extends ServletOutputStream {
        private final ByteArrayOutputStream out;

        Out(ByteArrayOutputStream out) {
            this.out = out;
        }

        @Override
        public boolean isReady() {
            return true;
        }

        @Override
        public void setWriteListener(WriteListener listener) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void write(int b) {
            out.write(b);
        }
    }

    @Test
    void getAnswersAllAllowedOrigins() throws Exception {
        run("GET", PATH, Set.of("https://jira.example.org"));
        assertFalse(passed, "the request ends here, before the login and the second step");
        assertEquals(200, set.get("setStatus"));
        assertEquals("application/json", set.get("setContentType"));
        assertEquals(BODY, body.toString(StandardCharsets.UTF_8));
        assertEquals(BODY.length(), set.get("setContentLength"));
    }

    @Test
    void headAnswersTheSameHeadersWithoutABody() throws Exception {
        run("HEAD", PATH, Set.of("https://jira.example.org"));
        assertFalse(passed);
        assertEquals(200, set.get("setStatus"));
        assertEquals("application/json", set.get("setContentType"));
        assertEquals(BODY.length(), set.get("setContentLength"));
        assertEquals(0, body.size());
    }

    @Test
    void otherMethodsAreRefused() throws Exception {
        for (String method : List.of("POST", "PUT", "DELETE", "OPTIONS", "PATCH", "TRACE")) {
            set.clear();
            run(method, PATH, Set.of("https://jira.example.org"));
            assertFalse(passed, method);
            assertEquals(405, set.get("setStatus"), method);
            assertEquals("GET, HEAD", set.get("Allow"), method);
            assertEquals(0, body.size(), method);
        }
    }

    @Test
    void withoutRelatedOriginsNothingChanges() throws Exception {
        for (String method : List.of("GET", "POST")) {
            passed = false;
            run(method, PATH, Set.of());
            assertTrue(passed, method);
            assertEquals(Map.of(), set, method);
        }
    }

    @Test
    void otherPathsPassThrough() throws Exception {
        for (String uri : List.of(PATH + "/", PATH + "/x", PATH + ";x", "/.well-known/%77ebauthn", "//.well-known/webauthn", "/x/..;" + PATH, "/")) {
            passed = false;
            run("GET", uri, Set.of("https://jira.example.org"));
            assertTrue(passed, uri);
            assertEquals(Map.of(), set, uri);
        }
    }
}
