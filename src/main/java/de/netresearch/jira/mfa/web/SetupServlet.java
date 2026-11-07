package de.netresearch.jira.mfa.web;

import com.atlassian.jira.user.ApplicationUser;
import de.netresearch.jira.mfa.ao.MfaPasskey;
import de.netresearch.jira.mfa.core.EnforcementPolicy.Requirement;
import de.netresearch.jira.mfa.core.Totp;
import de.netresearch.jira.mfa.service.MfaService;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;

/**
 * Enrolment and self-service: TOTP, passkeys, recovery codes.
 * Path: /plugins/servlet/mfa/setup
 *
 * <p>A session that has not passed the second step may use this page only
 * while the user has no factor at all; otherwise anybody holding just the
 * password could add their own authenticator.
 */
public class SetupServlet extends MfaServletSupport {
    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(SetupServlet.class);
    private static final DateTimeFormatter DATE = DateTimeFormatter.ofPattern("yyyy-MM-dd").withZone(ZoneOffset.UTC);

    @Inject
    public SetupServlet(MfaService mfa) {
        super(mfa);
    }

    /** Returns the requirement if the session may manage factors, or null after redirecting. */
    private Requirement guard(HttpServletRequest req, HttpServletResponse resp, ApplicationUser u) throws IOException {
        Requirement r = mfa.requirement(u);
        if (r == Requirement.VERIFY && !mfa.isVerified(req.getSession(false), u)) {
            resp.sendRedirect(req.getContextPath() + SERVLET + "/verify");
            return null;
        }
        return r;
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        ApplicationUser u = requireUser(req, resp);
        if (u == null) {
            return;
        }
        Requirement r = guard(req, resp, u);
        if (r == null) {
            return;
        }
        render(req, resp, u, r, null, null, List.of());
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        ApplicationUser u = requireUser(req, resp);
        if (u == null || rejectBadCsrf(req, resp)) {
            return;
        }
        Requirement r = guard(req, resp, u);
        if (r == null) {
            return;
        }
        HttpSession session = req.getSession(true);
        String action = req.getParameter("action");
        String error = null;
        String message = null;
        List<String> newCodes = List.of();
        boolean hadFactor = mfa.hasFactor(u.getKey());
        if ("later".equals(action)) {
            if (r == Requirement.ENROL_OPTIONAL) {
                session.setAttribute(MfaService.S_GRACE_ACK, u.getKey());
                resp.sendRedirect(takeReturnUrl(req));
                return;
            }
            error = "Setting up a second factor is required now.";
        } else if ("totp-confirm".equals(action)) {
            Boolean confirmed;
            try {
                confirmed = mfa.confirmTotp(u, session, req.getParameter("code"));
            } catch (RuntimeException e) {
                LOG.error("cannot store the TOTP secret of {}", u.getUsername(), e);
                confirmed = null;
            }
            if (confirmed == null) {
                error = "Adding an authenticator app is not possible right now. Add a passkey or security key instead, "
                        + "or contact your Jira administrator.";
            } else if (confirmed) {
                message = "Authenticator app added.";
                newCodes = afterFirstFactor(req, u, hadFactor);
            } else {
                error = "That code does not match. Check the time on your phone and enter the current code.";
            }
        } else if ("totp-remove".equals(action)) {
            if (canRemove(u, true)) {
                mfa.removeTotp(u, req);
                message = "Authenticator app removed.";
            } else {
                error = "Add another factor before removing your last one.";
            }
        } else if ("passkey-remove".equals(action)) {
            if (canRemove(u, false)) {
                message = mfa.removePasskey(u, parseId(req.getParameter("id")), req) ? "Passkey removed." : null;
            } else {
                error = "Add another factor before removing your last one.";
            }
        } else if ("recovery-regenerate".equals(action)) {
            if (hadFactor) {
                newCodes = mfa.replaceRecoveryCodes(u, req);
                message = "New recovery codes created. The old ones no longer work.";
            }
        } else if ("passkey-registered".equals(action)) {
            // the WebAuthn servlet stored the credential; show codes if this was the first factor
            message = "Passkey added.";
            Object first = session.getAttribute("de.netresearch.jira.mfa.firstFactorCodes");
            session.removeAttribute("de.netresearch.jira.mfa.firstFactorCodes");
            if (first instanceof List) {
                @SuppressWarnings("unchecked")
                List<String> codes = (List<String>) first;
                newCodes = codes;
            }
        }
        render(req, resp, u, mfa.requirement(u), error, message, newCodes);
    }

    /** After the first factor: the session counts as verified and recovery codes are issued. */
    List<String> afterFirstFactor(HttpServletRequest req, ApplicationUser u, boolean hadFactor) {
        if (!hadFactor) {
            mfa.firstFactorAdded(u);
            mfa.markVerified(req, u);
        }
        if (mfa.remainingRecoveryCodes(u.getKey()) == 0) {
            return mfa.regenerateRecoveryCodes(u);
        }
        return List.of();
    }

    private boolean canRemove(ApplicationUser u, boolean totp) {
        int factors = (mfa.hasTotp(u.getKey()) ? 1 : 0) + mfa.store().passkeys(u.getKey()).size();
        return factors > 1 || !mfa.isEnforced(u);
    }

    private static int parseId(String s) {
        try {
            return Integer.parseInt(s);
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private void render(HttpServletRequest req, HttpServletResponse resp, ApplicationUser u, Requirement r,
                        String error, String message, List<String> newCodes) throws IOException {
        String ctx = req.getContextPath();
        HttpSession session = req.getSession(true);
        String key = u.getKey();
        boolean hasTotp = mfa.hasTotp(key);
        List<MfaPasskey> passkeys = mfa.store().passkeys(key);
        StringBuilder b = new StringBuilder();
        b.append("<h1>Two-step verification</h1>");
        if (error != null) {
            b.append("<p class=\"error\" role=\"alert\">").append(Html.esc(error)).append("</p>");
        }
        if (message != null) {
            b.append("<p class=\"ok\" role=\"status\">").append(Html.esc(message)).append("</p>");
        }
        if (!newCodes.isEmpty()) {
            b.append("<div class=\"card\" id=\"recovery-codes\"><h2>Your recovery codes</h2>")
                    .append("<p>Store these codes somewhere safe, for example in your password manager. Each code works once ")
                    .append("if you lose access to your authenticator app or passkey. They are shown only now.</p><ul class=\"codes\">");
            for (String c : newCodes) {
                b.append("<li><code>").append(Html.esc(c)).append("</code></li>");
            }
            b.append("</ul><p><a href=\"").append(Html.esc(ctx)).append("/secure/Dashboard.jspa\">Continue to Jira</a></p></div>");
        }
        if (r == Requirement.ENROL_REQUIRED) {
            b.append("<div class=\"notice\" role=\"alert\">Your account requires a second factor. Set up an authenticator app or a passkey to continue.</div>");
        } else if (r == Requirement.ENROL_OPTIONAL) {
            String end = mfa.graceEndIfStarted(key).map(DATE::format).orElse("the end of the grace period");
            b.append("<div class=\"notice\">Your account will require a second factor from <strong>")
                    .append(Html.esc(end)).append("</strong>. Set it up now, or continue and do it later.")
                    .append("<form method=\"post\" class=\"inline\">").append(csrfField(req)).append(Html.hidden("action", "later"))
                    .append(" <button type=\"submit\" class=\"secondary\" id=\"later\">Remind me later</button></form></div>");
        }

        // TOTP
        b.append("<div class=\"card\"><h2>Authenticator app</h2>");
        if (hasTotp) {
            b.append("<p>An authenticator app is set up.</p><form method=\"post\">").append(csrfField(req))
                    .append(Html.hidden("action", "totp-remove")).append("<button type=\"submit\" class=\"secondary\">Remove authenticator app</button></form>");
        } else {
            byte[] secret;
            try {
                secret = mfa.pendingTotpSecret(session);
            } catch (RuntimeException e) {
                // key file problem: keep passkeys and "later" usable instead of failing the whole page
                LOG.error("cannot offer TOTP enrolment to {}", u.getUsername(), e);
                secret = null;
            }
            if (secret == null) {
                b.append("<p class=\"error\" role=\"alert\" id=\"totp-unavailable\">Adding an authenticator app is not possible right now. ")
                        .append("Add a passkey or security key instead, or contact your Jira administrator.</p></div>");
                appendPasskeysAndRest(b, req, resp, u, r, session, hasTotp, passkeys);
                return;
            }
            String account = u.getUsername();
            String uri = Totp.otpauthUri(mfa.settings().issuer, account, secret);
            b.append("<p>Scan this code with an authenticator app (for example Aegis, Google Authenticator, Microsoft Authenticator or 1Password), then enter the 6-digit code it shows.</p>")
                    .append("<div class=\"qr\">").append(Html.qrSvg(uri, "QR code for your authenticator app")).append("</div>")
                    .append("<p class=\"muted\">Cannot scan? Enter this key manually: <code id=\"totp-secret\">")
                    .append(Html.esc(Totp.base32(secret))).append("</code> (time-based, 6 digits, 30 seconds)</p>")
                    .append("<form method=\"post\" autocomplete=\"off\">").append(csrfField(req)).append(Html.hidden("action", "totp-confirm"))
                    .append("<label for=\"totp-code\">6-digit code</label><input type=\"text\" id=\"totp-code\" name=\"code\" inputmode=\"numeric\" autocomplete=\"one-time-code\" pattern=\"[0-9 ]{6,7}\" required>")
                    .append("<button type=\"submit\" id=\"totp-confirm\">Add authenticator app</button></form>");
        }
        b.append("</div>");
        appendPasskeysAndRest(b, req, resp, u, r, session, hasTotp, passkeys);
    }

    private void appendPasskeysAndRest(StringBuilder b, HttpServletRequest req, HttpServletResponse resp, ApplicationUser u,
                                       Requirement r, HttpSession session, boolean hasTotp, List<MfaPasskey> passkeys) throws IOException {
        String ctx = req.getContextPath();
        String key = u.getKey();
        // Passkeys
        b.append("<div class=\"card\"><h2>Passkeys and security keys</h2>");
        if (!passkeys.isEmpty()) {
            b.append("<table><thead><tr><th scope=\"col\">Name</th><th scope=\"col\">Added</th><th scope=\"col\"><span class=\"muted\">Action</span></th></tr></thead><tbody>");
            for (MfaPasskey p : passkeys) {
                b.append("<tr><td>").append(Html.esc(p.getLabel())).append("</td><td>")
                        .append(DATE.format(Instant.ofEpochMilli(p.getCreated()))).append("</td><td>")
                        .append("<form method=\"post\" class=\"inline\">").append(csrfField(req))
                        .append(Html.hidden("action", "passkey-remove")).append(Html.hidden("id", Integer.toString(p.getID())))
                        .append("<button type=\"submit\" class=\"secondary\" aria-label=\"Remove passkey ").append(Html.esc(p.getLabel()))
                        .append("\">Remove</button></form></td></tr>");
            }
            b.append("</tbody></table>");
        }
        b.append("<div id=\"passkey-register\"").append(Html.dataAttrs(Map.of(
                        "options", ctx + SERVLET + "/webauthn/register/options",
                        "finish", ctx + SERVLET + "/webauthn/register/finish",
                        "done", ctx + SERVLET + "/setup",
                        "csrf", mfa.csrfToken(session))))
                .append("><label for=\"passkey-label\">Name for the new passkey</label>")
                .append("<input type=\"text\" id=\"passkey-label\" maxlength=\"60\" value=\"Passkey\">")
                .append("<button type=\"button\" id=\"passkey-add\">Add a passkey or security key</button>")
                .append("<p class=\"error\" role=\"alert\" id=\"passkey-error\" hidden></p></div></div>");

        // Recovery codes
        if (hasTotp || !passkeys.isEmpty()) {
            b.append("<div class=\"card\"><h2>Recovery codes</h2><p>")
                    .append(mfa.remainingRecoveryCodes(key)).append(" unused recovery codes left.</p>")
                    .append("<form method=\"post\">").append(csrfField(req)).append(Html.hidden("action", "recovery-regenerate"))
                    .append("<button type=\"submit\" class=\"secondary\" id=\"recovery-regenerate\">Create new recovery codes</button></form></div>");
        }
        if (mfa.isVerified(session, u) || r == Requirement.NONE) {
            b.append("<p><a href=\"").append(Html.esc(ctx)).append("/secure/Dashboard.jspa\">Back to Jira</a></p>");
        }
        b.append(logoutForm(req));
        Html.page(resp, "Two-step verification setup", b.toString(), scriptUrl(req));
    }
}
