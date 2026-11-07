package de.netresearch.jira.mfa.web;

import com.atlassian.jira.user.ApplicationUser;
import com.atlassian.plugin.spring.scanner.annotation.imports.ComponentImport;
import com.atlassian.sal.api.websudo.WebSudoManager;
import de.netresearch.jira.mfa.core.UserStatus;
import de.netresearch.jira.mfa.core.UserStatus.State;
import de.netresearch.jira.mfa.service.MfaService;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Administrators' overview: every Jira user with the second-factor state,
 * most urgent first, as a table or as CSV. System administrators only, behind
 * websudo. Path: /plugins/servlet/mfa/admin/users
 */
public class UsersServlet extends MfaServletSupport {
    private static final DateTimeFormatter DATE = DateTimeFormatter.ofPattern("yyyy-MM-dd").withZone(ZoneOffset.UTC);
    private final WebSudoManager webSudo;

    @Inject
    public UsersServlet(MfaService mfa, @ComponentImport WebSudoManager webSudo) {
        super(mfa);
        this.webSudo = webSudo;
    }

    @Override
    protected void get(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        ApplicationUser admin = requireAdmin(req, resp, webSudo);
        if (admin == null) {
            return;
        }
        boolean inactive = "1".equals(req.getParameter("inactive"));
        State only = parseState(req.getParameter("state"));
        String q = req.getParameter("q") == null ? "" : req.getParameter("q").trim();
        List<MfaService.Overview> all = mfa.overview(mfa.env().allUsers()).stream()
                .filter(o -> inactive || o.user.isActive())
                .sorted(Comparator.<MfaService.Overview, State>comparing(o -> o.status.state)
                        .thenComparing(o -> o.user.getUsername(), String.CASE_INSENSITIVE_ORDER))
                .collect(Collectors.toList());
        List<MfaService.Overview> shown = all.stream()
                .filter(o -> only == null || o.status.state == only)
                .filter(o -> q.isEmpty() || matches(o.user, q))
                .collect(Collectors.toList());
        if ("csv".equals(req.getParameter("format"))) {
            csv(resp, shown);
            return;
        }
        render(req, resp, all, shown, only, q, inactive);
    }

    private static State parseState(String s) {
        if (s == null || s.isEmpty()) {
            return null;
        }
        try {
            return State.valueOf(s);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static boolean matches(ApplicationUser u, String q) {
        String needle = q.toLowerCase(Locale.ROOT);
        return contains(u.getUsername(), needle) || contains(u.getDisplayName(), needle) || contains(u.getEmailAddress(), needle);
    }

    private static boolean contains(String hay, String needle) {
        return hay != null && hay.toLowerCase(Locale.ROOT).contains(needle);
    }

    private static String graceEnd(UserStatus st) {
        return st.graceEnd == null ? "" : DATE.format(st.graceEnd);
    }

    private static void csv(HttpServletResponse resp, List<MfaService.Overview> rows) throws IOException {
        resp.setContentType("text/csv;charset=UTF-8");
        resp.setHeader("Content-Disposition", "attachment; filename=\"two-step-verification-users.csv\"");
        resp.setHeader("Cache-Control", "no-store");
        StringBuilder b = new StringBuilder("username,display_name,email,active,state,authenticator_app,passkeys,recovery_codes,grace_period_ends\r\n");
        for (MfaService.Overview o : rows) {
            UserStatus st = o.status;
            b.append(UserStatus.csv(o.user.getUsername())).append(',')
                    .append(UserStatus.csv(o.user.getDisplayName())).append(',')
                    .append(UserStatus.csv(o.user.getEmailAddress())).append(',')
                    .append(o.user.isActive() ? "yes" : "no").append(',')
                    .append(st.state.name()).append(',')
                    .append(st.authenticatorApp ? "yes" : "no").append(',')
                    .append(st.passkeys).append(',')
                    .append(st.recoveryCodes).append(',')
                    .append(graceEnd(st)).append("\r\n");
        }
        resp.getWriter().write(b.toString());
    }

    private void render(HttpServletRequest req, HttpServletResponse resp, List<MfaService.Overview> all,
                        List<MfaService.Overview> shown, State only, String q, boolean inactive) throws IOException {
        String ctx = req.getContextPath();
        String self = ctx + SERVLET + "/admin/users";
        Map<State, Long> counts = new EnumMap<>(State.class);
        for (MfaService.Overview o : all) {
            counts.merge(o.status.state, 1L, Long::sum);
        }
        StringBuilder b = new StringBuilder();
        b.append("<h1>Two-step verification: users</h1>")
                .append("<p class=\"muted\">").append(all.size()).append(inactive ? " users" : " active users")
                .append(". <a href=\"").append(Html.esc(ctx + SERVLET + "/admin")).append("\">Settings and reset</a></p>");

        b.append("<div class=\"card\"><table id=\"state-counts\"><tbody>");
        for (State s : State.values()) {
            b.append("<tr><th scope=\"row\"><a href=\"").append(Html.esc(self + "?state=" + s.name() + (inactive ? "&inactive=1" : "")))
                    .append("\">").append(Html.esc(s.label())).append("</a></th><td data-state=\"").append(s.name()).append("\">")
                    .append(counts.getOrDefault(s, 0L)).append("</td></tr>");
        }
        b.append("</tbody></table></div>");

        b.append("<div class=\"card\"><form method=\"get\" class=\"filters\"><label for=\"q\">User, name or email</label>")
                .append("<input type=\"text\" id=\"q\" name=\"q\" value=\"").append(Html.esc(q)).append("\">")
                .append("<label for=\"state\">State</label><select id=\"state\" name=\"state\"><option value=\"\">All</option>");
        for (State s : State.values()) {
            b.append("<option value=\"").append(s.name()).append('"').append(s == only ? " selected" : "").append('>')
                    .append(Html.esc(s.label())).append("</option>");
        }
        b.append("</select><label><input type=\"checkbox\" name=\"inactive\" value=\"1\"").append(inactive ? " checked" : "")
                .append("> Include inactive users</label>")
                .append("<button type=\"submit\" class=\"secondary\">Show</button> ")
                .append("<button type=\"submit\" name=\"format\" value=\"csv\" class=\"secondary\" id=\"download-csv\">Download CSV</button></form></div>");

        b.append("<div class=\"wide\"><table id=\"users\"><caption>").append(shown.size()).append(" shown</caption><thead><tr>")
                .append("<th scope=\"col\">User</th><th scope=\"col\">State</th><th scope=\"col\">Authenticator app</th>")
                .append("<th scope=\"col\">Passkeys</th><th scope=\"col\">Recovery codes</th><th scope=\"col\">Grace period ends</th>")
                .append("<th scope=\"col\"><span class=\"visually-hidden\">Actions</span></th></tr></thead><tbody>");
        for (MfaService.Overview o : shown) {
            UserStatus st = o.status;
            String name = o.user.getUsername();
            String enc = URLEncoder.encode(name, StandardCharsets.UTF_8);
            b.append("<tr data-user=\"").append(Html.esc(name)).append("\" data-state=\"").append(st.state.name()).append("\">")
                    .append("<td><a href=\"").append(Html.esc(ctx + "/secure/admin/user/ViewUser.jspa?name=" + enc)).append("\">")
                    .append(Html.esc(name)).append("</a><br><span class=\"muted\">").append(Html.esc(o.user.getDisplayName()))
                    .append(o.user.isActive() ? "" : " (inactive)").append("</span></td>")
                    .append("<td class=\"state-").append(st.state.name().toLowerCase(Locale.ROOT)).append("\">")
                    .append(Html.esc(st.state.label())).append("</td>")
                    .append("<td>").append(st.authenticatorApp ? "yes" : "no").append("</td>")
                    .append("<td>").append(st.passkeys).append("</td>")
                    .append("<td>").append(st.recoveryCodes).append("</td>")
                    .append("<td>").append(graceEnd(st)).append("</td>")
                    .append("<td><a href=\"").append(Html.esc(ctx + SERVLET + "/admin?user=" + enc)).append("\">Details</a></td></tr>");
        }
        b.append("</tbody></table></div>");
        Html.page(resp, "Two-step verification users", header(req, mfa.env().currentUser(), true), b.toString(), null);
    }
}
