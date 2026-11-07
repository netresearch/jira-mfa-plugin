package de.netresearch.jira.mfa.web;

import com.atlassian.jira.user.ApplicationUser;
import com.atlassian.plugin.spring.scanner.annotation.imports.ComponentImport;
import com.atlassian.sal.api.websudo.WebSudoManager;
import com.atlassian.sal.api.websudo.WebSudoSessionException;
import de.netresearch.jira.mfa.core.EnforcementPolicy;
import de.netresearch.jira.mfa.core.EnforcementPolicy.Requirement;
import de.netresearch.jira.mfa.core.MfaSettings;
import de.netresearch.jira.mfa.service.MfaService;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

/**
 * Administration: settings, user lookup and factor reset. System administrators
 * only, behind Jira's secure administrator session (websudo).
 * Path: /plugins/servlet/mfa/admin
 */
public class AdminServlet extends MfaServletSupport {
    private static final DateTimeFormatter DATE = DateTimeFormatter.ofPattern("yyyy-MM-dd").withZone(ZoneOffset.UTC);
    private final WebSudoManager webSudo;

    @Inject
    public AdminServlet(MfaService mfa, @ComponentImport WebSudoManager webSudo) {
        super(mfa);
        this.webSudo = webSudo;
    }

    private ApplicationUser admin(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        ApplicationUser u = requireUser(req, resp);
        if (u == null) {
            return null;
        }
        if (!mfa.env().isSysAdmin(u)) {
            resp.sendError(HttpServletResponse.SC_FORBIDDEN, "System administrators only.");
            return null;
        }
        // Defence in depth (the filter already requires this): an administrator
        // who has or must have a factor needs a verified session here.
        Requirement r = mfa.requirement(u);
        if ((r == Requirement.VERIFY || r == Requirement.ENROL_REQUIRED) && !mfa.isVerified(req.getSession(false), u)) {
            resp.sendRedirect(req.getContextPath() + SERVLET + (r == Requirement.VERIFY ? "/verify" : "/setup"));
            return null;
        }
        try {
            webSudo.willExecuteWebSudoRequest(req);
        } catch (WebSudoSessionException e) {
            webSudo.enforceWebSudoProtection(req, resp);
            return null;
        }
        if (!webSudo.canExecuteRequest(req)) {
            webSudo.enforceWebSudoProtection(req, resp);
            return null;
        }
        return u;
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        ApplicationUser admin = admin(req, resp);
        if (admin == null) {
            return;
        }
        render(req, resp, null, null, req.getParameter("user"));
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        ApplicationUser admin = admin(req, resp);
        if (admin == null || rejectBadCsrf(req, resp)) {
            return;
        }
        String action = req.getParameter("action");
        String error = null;
        String message = null;
        String lookup = req.getParameter("user");
        if ("save".equals(action)) {
            try {
                MfaSettings s = new MfaSettings(
                        req.getParameter("enabled") != null,
                        MfaSettings.parseList(req.getParameter("enforcedGroups")),
                        MfaSettings.parseList(req.getParameter("exemptGroups")),
                        MfaSettings.parseList(req.getParameter("exemptUsers")),
                        Integer.parseInt(req.getParameter("graceDays").trim()),
                        MfaSettings.BasicAuthPolicy.valueOf(req.getParameter("basicAuthPolicy")),
                        MfaSettings.parseList(req.getParameter("basicAuthAllowedUsers")),
                        req.getParameter("rpId"),
                        req.getParameter("issuer"),
                        Integer.parseInt(req.getParameter("maxFailures").trim()),
                        Integer.parseInt(req.getParameter("lockoutMinutes").trim()));
                mfa.saveSettings(admin, s);
                message = "Settings saved.";
            } catch (RuntimeException e) {
                error = "Settings not saved: check the numeric fields.";
            }
        } else if ("reset".equals(action)) {
            ApplicationUser target = lookup == null ? null : mfa.env().userByName(lookup.trim());
            if (target == null) {
                error = "No user named " + lookup + ".";
            } else {
                mfa.adminReset(admin, target);
                message = "All second factors and recovery codes of " + target.getUsername()
                        + " were removed. The grace period starts again at the user's next request.";
            }
        }
        render(req, resp, error, message, lookup);
    }

    private void render(HttpServletRequest req, HttpServletResponse resp, String error, String message, String lookup) throws IOException {
        MfaSettings s = mfa.settings();
        StringBuilder b = new StringBuilder();
        b.append("<h1>Two-step verification: administration</h1>");
        if (error != null) {
            b.append("<p class=\"error\" role=\"alert\">").append(Html.esc(error)).append("</p>");
        }
        if (message != null) {
            b.append("<p class=\"ok\" role=\"status\" id=\"admin-message\">").append(Html.esc(message)).append("</p>");
        }
        b.append("<div class=\"card\"><h2>Reset a user</h2><form method=\"get\"><label for=\"lookup\">Username</label>")
                .append("<input type=\"text\" id=\"lookup\" name=\"user\" value=\"").append(Html.esc(lookup)).append("\">")
                .append("<button type=\"submit\" class=\"secondary\">Show status</button></form>");
        if (lookup != null && !lookup.trim().isEmpty()) {
            ApplicationUser t = mfa.env().userByName(lookup.trim());
            if (t == null) {
                b.append("<p class=\"error\">No such user.</p>");
            } else {
                String key = t.getKey();
                boolean totp = mfa.hasTotp(key);
                int passkeys = mfa.store().passkeys(key).size();
                Instant locked = mfa.lockedUntil(t);
                b.append("<table id=\"user-status\"><tbody>")
                        .append(row("User", t.getUsername() + " (" + t.getDisplayName() + ")"))
                        .append(row("Second factor enforced", mfa.isEnforced(t) ? "yes" : "no"))
                        .append(row("Requirement now", mfa.requirementPreview(t).name()))
                        .append(row("Authenticator app", totp ? "yes" : "no"))
                        .append(row("Passkeys", Integer.toString(passkeys)))
                        .append(row("Unused recovery codes", Integer.toString(mfa.remainingRecoveryCodes(key))))
                        .append(row("Grace period ends", mfa.graceEndIfStarted(key).map(DATE::format).orElse("not started")))
                        .append(row("Locked until", locked == null ? "-" : locked.toString()))
                        .append("</tbody></table>")
                        .append("<form method=\"post\">").append(csrfField(req)).append(Html.hidden("action", "reset"))
                        .append(Html.hidden("user", t.getUsername()))
                        .append("<button type=\"submit\" id=\"reset-user\">Remove all second factors of ").append(Html.esc(t.getUsername()))
                        .append("</button></form>");
            }
        }
        b.append("</div>");

        b.append("<div class=\"card\"><h2>Settings</h2><form method=\"post\">").append(csrfField(req)).append(Html.hidden("action", "save"))
                .append("<label><input type=\"checkbox\" name=\"enabled\" id=\"enabled\"").append(s.enabled ? " checked" : "")
                .append("> Two-step verification is active</label>")
                .append(area("enforcedGroups", "Groups that must use a second factor (one per line; empty = all users)", MfaSettings.formatList(s.enforcedGroups)))
                .append(area("exemptGroups", "Exempt groups", MfaSettings.formatList(s.exemptGroups)))
                .append(area("exemptUsers", "Exempt users (emergency exceptions)", MfaSettings.formatList(s.exemptUsers)))
                .append(field("graceDays", "Grace period for enrolment (days)", Integer.toString(s.graceDays), "number"))
                .append("<label for=\"basicAuthPolicy\">HTTP Basic authentication (username and password on REST)</label>")
                .append("<select id=\"basicAuthPolicy\" name=\"basicAuthPolicy\">")
                .append(option("BLOCK", "Block for users who need a second factor", s.basicAuthPolicy == MfaSettings.BasicAuthPolicy.BLOCK))
                .append(option("ALLOW", "Allow (insecure: bypasses the second factor)", s.basicAuthPolicy == MfaSettings.BasicAuthPolicy.ALLOW))
                .append("</select>")
                .append(area("basicAuthAllowedUsers", "Users still allowed to use Basic authentication (service accounts)", MfaSettings.formatList(s.basicAuthAllowedUsers)))
                .append(field("rpId", "Passkey relying party ID (empty = host of the base URL; changing it invalidates registered passkeys)", s.rpId, "text"))
                .append(field("issuer", "Name shown in authenticator apps", s.issuer, "text"))
                .append(field("maxFailures", "Failed attempts before lockout", Integer.toString(s.maxFailures), "number"))
                .append(field("lockoutMinutes", "Lockout duration (minutes)", Integer.toString(s.lockoutMinutes), "number"))
                .append("<button type=\"submit\" id=\"save-settings\">Save settings</button></form></div>");
        Html.page(resp, "Two-step verification administration", b.toString(), null);
    }

    private static String row(String k, String v) {
        return "<tr><th scope=\"row\">" + Html.esc(k) + "</th><td>" + Html.esc(v) + "</td></tr>";
    }

    private static String area(String name, String label, String value) {
        return "<label for=\"" + name + "\">" + Html.esc(label) + "</label><textarea id=\"" + name + "\" name=\"" + name
                + "\" rows=\"3\">" + Html.esc(value) + "</textarea>";
    }

    private static String field(String name, String label, String value, String type) {
        return "<label for=\"" + name + "\">" + Html.esc(label) + "</label><input type=\"" + type + "\" id=\"" + name
                + "\" name=\"" + name + "\" value=\"" + Html.esc(value) + "\">";
    }

    private static String option(String value, String label, boolean selected) {
        return "<option value=\"" + value + "\"" + (selected ? " selected" : "") + ">" + Html.esc(label) + "</option>";
    }
}
