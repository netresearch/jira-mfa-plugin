package de.netresearch.jira.mfa.web;

import com.atlassian.jira.user.ApplicationUser;
import de.netresearch.jira.mfa.core.EnforcementPolicy.Requirement;
import de.netresearch.jira.mfa.service.MfaService;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;

/** The second step: TOTP code, recovery code or passkey. Path: /plugins/servlet/mfa/verify */
public class VerifyServlet extends MfaServletSupport {
    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("HH:mm 'UTC'").withZone(ZoneOffset.UTC);

    @Inject
    public VerifyServlet(MfaService mfa) {
        super(mfa);
    }

    @Override
    protected void get(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        ApplicationUser u = requireUser(req, resp);
        if (u == null) {
            return;
        }
        if (mfa.isVerified(req.getSession(false), u) || mfa.requirement(u) != Requirement.VERIFY) {
            resp.sendRedirect(takeReturnUrl(req));
            return;
        }
        render(req, resp, u, null);
    }

    @Override
    protected void post(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        ApplicationUser u = requireUser(req, resp);
        if (u == null || rejectBadCsrf(req, resp)) {
            return;
        }
        if (mfa.requirement(u) != Requirement.VERIFY) {
            resp.sendRedirect(takeReturnUrl(req));
            return;
        }
        MfaService.VerifyOutcome outcome = mfa.verifySecondStep(u, req.getParameter("code"), req.getRemoteAddr());
        if (outcome == MfaService.VerifyOutcome.OK) {
            String target = takeReturnUrl(req);
            mfa.markVerified(req, u);
            resp.sendRedirect(target);
            return;
        }
        resp.setStatus(outcome == MfaService.VerifyOutcome.LOCKED ? 429 : HttpServletResponse.SC_UNAUTHORIZED);
        render(req, resp, u, outcome == MfaService.VerifyOutcome.LOCKED ? null : "verify.badCode");
    }

    private void render(HttpServletRequest req, HttpServletResponse resp, ApplicationUser u, String errorKey) throws IOException {
        Messages m = Messages.forCurrentUser();
        Instant locked = mfa.lockedUntil(u);
        boolean hasTotp = mfa.hasTotp(u.getKey());
        boolean hasPasskey = !mfa.store().passkeys(u.getKey()).isEmpty();
        StringBuilder b = new StringBuilder();
        b.append("<div class=\"card\"><h1>").append(m.html("verify.heading")).append("</h1><p class=\"muted\">")
                .append(m.htmlWith("verify.signedInAs", "<strong>" + Html.esc(u.getDisplayName()) + "</strong>", Html.esc(u.getUsername())))
                .append("</p>");
        if (locked != null) {
            b.append("<p class=\"error\" role=\"alert\">").append(m.html("verify.locked", TIME.format(locked))).append("</p>");
        } else {
            if (errorKey != null) {
                b.append("<p class=\"error\" role=\"alert\" id=\"code-error\">").append(m.html(errorKey)).append("</p>");
            }
            String codeForm = codeForm(req, m, hasPasskey ? (hasTotp ? "verify.label.totpOrRecovery" : "verify.label.recovery")
                    : "verify.label.totp", "code", !hasPasskey || errorKey != null, errorKey != null);
            if (hasPasskey) {
                // The main path: the passkey prompt opens by itself (mfa.js), except after a failed code,
                // where the user has just chosen another way.
                Map<String, String> data = new LinkedHashMap<>();
                data.put("options", req.getContextPath() + SERVLET + "/webauthn/authenticate/options");
                data.put("finish", req.getContextPath() + SERVLET + "/webauthn/authenticate/finish");
                data.put("csrf", mfa.csrfToken(req.getSession(true)));
                data.put("autostart", errorKey == null ? "true" : "false");
                data.put("msg-unsupported", m.text("js.unsupported"));
                data.put("msg-waiting", m.text("verify.passkey.waiting"));
                data.put("msg-dismissed", m.text("verify.passkey.dismissed"));
                data.put("msg-failed", m.text("verify.passkey.failed", "{0}"));
                b.append("<div id=\"passkey-box\"").append(Html.dataAttrs(data)).append("><p>")
                        .append(m.html("verify.passkey.lead")).append("</p>")
                        .append("<button type=\"button\" id=\"passkey-login\"").append(errorKey == null ? " autofocus" : "").append(">")
                        .append(m.html("verify.passkey.button")).append("</button>")
                        .append("<p class=\"muted\" role=\"status\" id=\"passkey-status\"></p>")
                        .append("<p class=\"error\" role=\"alert\" id=\"passkey-error\" hidden></p></div>");
                b.append("<details id=\"other-ways\"").append(errorKey != null ? " open" : "").append("><summary>")
                        .append(m.html(hasTotp ? "verify.other" : "verify.lostPasskey")).append("</summary>")
                        .append(codeForm).append("</details>");
            } else {
                // TOTP only: the code field is the main path, a recovery code goes into the same field
                b.append("<p>").append(m.html("verify.totp.lead")).append("</p>").append(codeForm);
                b.append("<details id=\"other-ways\"><summary>").append(m.html("verify.lostDevice")).append("</summary>")
                        .append(codeForm(req, m, "verify.label.recovery", "recovery-code", false, false)).append("</details>");
            }
        }
        b.append("</div>");
        Html.page(resp, m.lang(), m.text("title"), header(req, u, false, m), b.toString(), scriptUrl(req));
    }

    private String codeForm(HttpServletRequest req, Messages m, String labelKey, String id, boolean autofocus, boolean invalid) {
        String submit = "code".equals(id) ? "verify-submit" : id + "-submit";
        return "<form method=\"post\" autocomplete=\"off\">" + csrfField(req)
                + "<label for=\"" + id + "\">" + m.html(labelKey) + "</label><input type=\"text\" id=\"" + id
                + "\" name=\"code\" inputmode=\"text\" autocomplete=\"one-time-code\""
                + (autofocus ? " autofocus" : "")
                + (invalid ? " aria-describedby=\"code-error\" aria-invalid=\"true\"" : "")
                + " required><button type=\"submit\" id=\"" + submit + "\">" + m.html("verify.submit") + "</button></form>";
    }
}
