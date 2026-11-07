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
        render(req, resp, u, outcome == MfaService.VerifyOutcome.LOCKED ? null : "That code is not valid. Try again.");
    }

    private void render(HttpServletRequest req, HttpServletResponse resp, ApplicationUser u, String error) throws IOException {
        Instant locked = mfa.lockedUntil(u);
        boolean hasTotp = mfa.hasTotp(u.getKey());
        boolean hasPasskey = !mfa.store().passkeys(u.getKey()).isEmpty();
        StringBuilder b = new StringBuilder();
        b.append("<div class=\"card\"><h1>Two-step verification</h1>")
                .append("<p>Signed in as <strong>").append(Html.esc(u.getDisplayName())).append("</strong> (")
                .append(Html.esc(u.getUsername())).append("). Confirm it is you to continue.</p>");
        if (locked != null) {
            b.append("<p class=\"error\" role=\"alert\">Too many failed attempts. Try again after ")
                    .append(TIME.format(locked)).append(", or ask a Jira administrator to reset your second factor.</p>");
        } else {
            if (error != null) {
                b.append("<p class=\"error\" role=\"alert\" id=\"code-error\">").append(Html.esc(error)).append("</p>");
            }
            if (hasPasskey) {
                b.append("<div id=\"passkey-box\"").append(Html.dataAttrs(Map.of(
                                "options", req.getContextPath() + SERVLET + "/webauthn/authenticate/options",
                                "finish", req.getContextPath() + SERVLET + "/webauthn/authenticate/finish",
                                "csrf", mfa.csrfToken(req.getSession(true)))))
                        .append("><button type=\"button\" id=\"passkey-login\">Use a passkey or security key</button>")
                        .append("<p class=\"error\" role=\"alert\" id=\"passkey-error\" hidden></p></div>");
            }
            b.append("<form method=\"post\" autocomplete=\"off\">").append(csrfField(req))
                    .append("<label for=\"code\">").append(hasTotp ? "Code from your authenticator app, or a recovery code" : "Recovery code")
                    .append("</label><input type=\"text\" id=\"code\" name=\"code\" inputmode=\"text\" autocomplete=\"one-time-code\" autofocus")
                    .append(error != null ? " aria-describedby=\"code-error\" aria-invalid=\"true\"" : "")
                    .append(" required><button type=\"submit\" id=\"verify-submit\">Verify</button></form>");
        }
        b.append("</div>");
        Html.page(resp, "Two-step verification", header(req, u, false), b.toString(), scriptUrl(req));
    }
}
