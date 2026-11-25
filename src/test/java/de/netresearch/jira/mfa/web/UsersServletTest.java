package de.netresearch.jira.mfa.web;

import com.atlassian.activeobjects.external.ActiveObjects;
import com.atlassian.jira.component.ComponentAccessor;
import com.atlassian.jira.user.ApplicationUser;
import com.atlassian.sal.api.websudo.WebSudoManager;
import de.netresearch.jira.mfa.ao.MfaPasskey;
import de.netresearch.jira.mfa.core.MfaSettings;
import de.netresearch.jira.mfa.service.JiraEnvironment;
import de.netresearch.jira.mfa.service.MfaService;
import de.netresearch.jira.mfa.service.MfaStore;
import de.netresearch.jira.mfa.service.PasskeyService;
import de.netresearch.jira.mfa.service.SettingsStore;
import net.java.ao.Query;
import org.junit.jupiter.api.Test;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Array;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The passkeys in the administrators' overview, from the stored rows to the page and the CSV. */
class UsersServletTest {
    private static final String OLD = "jira.example.com";
    private static final String NEW = "jira.example.org";
    private static final String HEAD = "username,display_name,email,active,state,authenticator_app,passkeys,recovery_codes,grace_period_ends,passkey_rp_ids";

    private final List<MfaPasskey> rows = new ArrayList<>();
    private final Set<String> users = new LinkedHashSet<>();
    private final List<String> finds = new ArrayList<>();
    private String legacyRpId = "";
    private String baseUrl = "https://" + NEW;

    private static <T> T proxy(Class<T> type, InvocationHandler h) {
        return type.cast(Proxy.newProxyInstance(UsersServletTest.class.getClassLoader(), new Class<?>[]{type}, h));
    }

    /** A Jira component that answers every question with a text, "no" or another such component. */
    private static Object texts(Class<?> type) {
        if (type == boolean.class) {
            return false;
        }
        return type == String.class ? "text" : proxy(type, (p, m, a) -> texts(m.getReturnType()));
    }

    private static ApplicationUser user(String name) {
        return proxy(ApplicationUser.class, (p, m, a) -> "isActive".equals(m.getName()) ? (Object) true : name);
    }

    /** A passkey row; reading a column the query does not name would cost a query per row. */
    private void passkey(String userKey, String rpId) {
        users.add(userKey);
        rows.add(proxy(MfaPasskey.class, (p, m, a) -> {
            switch (m.getName()) {
                case "getUserKey": return userKey;
                case "getRpId":
                    assertTrue(finds.contains("MfaPasskey ID,USER_KEY,RP_ID"), "the query names RP_ID: " + finds);
                    return rpId;
                default: throw new AssertionError(m.getName());
            }
        }));
    }

    private Object find(Class<?> type, Query query) {
        finds.add(type.getSimpleName() + (query == null ? "" : " " + String.join(",", query.getFields())));
        return type == MfaPasskey.class ? rows.toArray(new MfaPasskey[0]) : Array.newInstance(type, 0);
    }

    private String get(String format) {
        finds.clear();
        ActiveObjects ao = proxy(ActiveObjects.class, (p, m, a) -> {
            assertEquals("find", m.getName());
            return find((Class<?>) a[0], a.length > 1 ? (Query) a[1] : null);
        });
        // switched off, so the administrator needs no second step here
        MfaSettings s = new MfaSettings(false, Set.of(), Set.of(), Set.of(), 14, MfaSettings.BasicAuthPolicy.BLOCK, Set.of(), "", Set.of(),
                legacyRpId, "Jira", 5, 15);
        SettingsStore settings = new SettingsStore(null) {
            @Override
            public MfaSettings get() {
                return s;
            }
        };
        JiraEnvironment env = new JiraEnvironment() {
            @Override
            public ApplicationUser currentUser() {
                return user("admin");
            }

            @Override
            public boolean isSysAdmin(ApplicationUser u) {
                return true;
            }

            @Override
            public Collection<ApplicationUser> allUsers() {
                List<ApplicationUser> all = new ArrayList<>();
                users.forEach(n -> all.add(user(n)));
                return all;
            }

            @Override
            public Collection<String> groups(ApplicationUser u) {
                return List.of();
            }

            @Override
            public String baseUrl() {
                return baseUrl;
            }
        };
        // the page header asks Jira for texts and the XSRF token of the logout link
        ComponentAccessor.initialiseWorker(proxy(ComponentAccessor.Worker.class, (p, m, a) -> texts((Class<?>) a[0])));
        MfaStore store = new MfaStore(ao);
        MfaService mfa = new MfaService(store, settings, env, null, new PasskeyService(store, settings, env));
        WebSudoManager webSudo = proxy(WebSudoManager.class, (p, m, a) -> m.getReturnType() == boolean.class ? (Object) true : null);
        HttpServletRequest req = proxy(HttpServletRequest.class, (p, m, a) -> "getContextPath".equals(m.getName()) ? ""
                : "getParameter".equals(m.getName()) && "format".equals(a[0]) ? format : null);
        StringWriter out = new StringWriter();
        PrintWriter writer = new PrintWriter(out);
        HttpServletResponse resp = proxy(HttpServletResponse.class, (p, m, a) -> "getWriter".equals(m.getName()) ? writer : null);
        new UsersServlet(mfa, webSudo).doGet(req, resp);
        assertEquals(3, finds.size(), "three queries for all users: " + finds);
        return out.toString();
    }

    private String csvRow(String user) {
        String[] lines = get("csv").split("\r\n");
        assertEquals(HEAD, lines[0], "new columns come last");
        for (String l : lines) {
            if (l.startsWith(user + ",")) {
                return l.substring(l.indexOf(",NOT_ENFORCED,") + ",NOT_ENFORCED,".length());
            }
        }
        throw new AssertionError("no row for " + user);
    }

    private String passkeysCell(String user) {
        String row = get(null).split("<tr data-user=\"" + user + "\"")[1];
        return row.split("<td[^>]*>")[4].replace("</td>", "");
    }

    @Test
    void aPasskeyOfAnotherIdIsShownWithTheNumberPerId() {
        passkey("alice", OLD);
        passkey("alice", NEW);
        passkey("alice", OLD);
        assertEquals("3<br><span class=\"muted\">jira.example.com: 2, jira.example.org: 1</span>", passkeysCell("alice"));
        assertEquals("no,3,0,,\"jira.example.com: 2, jira.example.org: 1\"", csvRow("alice"));
    }

    @Test
    void withOnlyTheCurrentIdThePageShowsTheNumberAlone() {
        passkey("bob", NEW);
        passkey("bob", null);
        users.add("carol");
        assertEquals("2", passkeysCell("bob"));
        assertEquals("no,2,0,,jira.example.org: 2", csvRow("bob"));
        assertEquals("0", passkeysCell("carol"));
        assertEquals("no,0,0,,", csvRow("carol"));
    }

    @Test
    void aPasskeyWithoutStoredIdCountsUnderTheLegacyId() {
        legacyRpId = OLD;
        passkey("alice", null);
        assertEquals("1<br><span class=\"muted\">jira.example.com: 1</span>", passkeysCell("alice"));
        assertEquals("no,1,0,,jira.example.com: 1", csvRow("alice"));
    }

    @Test
    void storedValuesAreEscaped() {
        passkey("alice", "=<b>\"");
        assertEquals("1<br><span class=\"muted\">=&lt;b&gt;&quot;: 1</span>", passkeysCell("alice"));
        assertEquals("no,1,0,,\"'=<b>\"\": 1\"", csvRow("alice"));
    }

    @Test
    void theOverviewOpensWhenTheBaseUrlHasNoUsableHost() {
        baseUrl = "http://jira_test:8080";
        passkey("alice", null);
        assertEquals("1", assertDoesNotThrow(() -> passkeysCell("alice")));
        assertEquals("no,1,0,,: 1", csvRow("alice"));
    }

    @Test
    void thePageHasNoFurtherColumn() {
        passkey("alice", OLD);
        String page = get(null);
        assertEquals(7, page.split("<th scope=\"col\">", -1).length - 1);
        assertFalse(page.contains("passkey_rp_ids"));
    }
}
