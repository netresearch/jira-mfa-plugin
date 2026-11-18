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
import java.util.LinkedHashMap;
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
    protected void get(HttpServletRequest req, HttpServletResponse resp) throws IOException {
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
    protected void post(HttpServletRequest req, HttpServletResponse resp) throws IOException {
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
            error = "setup.laterRefused";
        } else if ("totp-confirm".equals(action)) {
            boolean confirmed = false;
            boolean unavailable = false;
            try {
                confirmed = mfa.confirmTotp(u, session, req.getParameter("code"));
            } catch (RuntimeException e) {
                LOG.error("cannot store the TOTP secret of {}", u.getUsername(), e);
                unavailable = true;
            }
            if (unavailable) {
                error = TOTP_UNAVAILABLE;
            } else if (confirmed) {
                message = "setup.totp.added";
                newCodes = afterFirstFactor(req, u, hadFactor);
            } else {
                error = "setup.totp.mismatch";
            }
        } else if ("totp-remove".equals(action)) {
            if (canRemove(u, true)) {
                mfa.removeTotp(u, req);
                message = "setup.totp.removed";
            } else {
                error = "setup.lastFactor";
            }
        } else if ("passkey-remove".equals(action)) {
            if (canRemove(u, false)) {
                message = mfa.removePasskey(u, parseId(req.getParameter("id")), req) ? "setup.passkey.removed" : null;
            } else {
                error = "setup.lastFactor";
            }
        } else if ("recovery-regenerate".equals(action)) {
            if (hadFactor) {
                newCodes = mfa.replaceRecoveryCodes(u, req);
                message = "setup.recovery.regenerated";
            }
        } else if ("passkey-registered".equals(action)) {
            // the WebAuthn servlet stored the credential; show codes if this was the first factor
            message = "setup.passkey.added";
            String first = MfaService.takeForUser(session, WebAuthnServlet.S_FIRST_FACTOR_CODES, u.getKey());
            if (first != null && !first.isEmpty()) {
                newCodes = List.of(first.split("\n"));
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
                        String errorKey, String messageKey, List<String> newCodes) throws IOException {
        Messages m = Messages.forCurrentUser();
        HttpSession session = req.getSession(true);
        String key = u.getKey();
        boolean hasTotp = mfa.hasTotp(key);
        List<MfaPasskey> passkeys = mfa.store().passkeys(key);
        StringBuilder b = new StringBuilder();
        b.append("<h1>").append(m.html("title")).append("</h1>");
        if (errorKey != null) {
            b.append("<p class=\"error\" role=\"alert\">").append(m.html(errorKey)).append("</p>");
        }
        if (messageKey != null) {
            b.append("<p class=\"ok\" role=\"status\">").append(m.html(messageKey)).append("</p>");
        }
        if (!newCodes.isEmpty()) {
            b.append(newCodesCard(req, m, newCodes));
        }
        b.append(notice(req, m, r, key));
        boolean firstFactor = !hasTotp && passkeys.isEmpty();
        boolean totpRetry = !hasTotp && isTotpError(errorKey);
        // one autofocus per page: the passkey button on a first visit, the code field after a failed code
        b.append(passkeyCard(req, m, passkeys, firstFactor && newCodes.isEmpty() && !totpRetry,
                mfa.remainingRecoveryCodes(key) == 0));
        b.append(hasTotp ? totpCard(req, m) : totpEnrolment(req, m, u, errorKey));
        if (hasTotp || !passkeys.isEmpty()) {
            b.append("<div class=\"card\"><h2>").append(m.html("setup.recovery.heading")).append(H2_P)
                    .append(m.html("setup.recovery.left", mfa.remainingRecoveryCodes(key))).append("</p>")
                    .append(postForm(req, "recovery-regenerate", ""))
                    .append("<button type=\"submit\" class=\"secondary\" id=\"recovery-regenerate\">")
                    .append(m.html("setup.recovery.regenerate")).append(BUTTON_FORM_DIV);
        }
        Html.page(resp, m.lang(), m.text("title"), header(req, u, mfa.isVerified(session, u) || r == Requirement.NONE, m),
                b.toString(), scriptUrl(req));
    }

    private static final String H2_P = "</h2><p>";
    private static final String BUTTON_FORM_DIV = "</button></form></div>";
    private static final String TOTP_UNAVAILABLE = "setup.totp.unavailable";

    private static boolean isTotpError(String errorKey) {
        return "setup.totp.mismatch".equals(errorKey) || TOTP_UNAVAILABLE.equals(errorKey);
    }

    private String postForm(HttpServletRequest req, String action, String cssClass) {
        return "<form method=\"post\"" + (cssClass.isEmpty() ? "" : " class=\"" + cssClass + "\"") + ">"
                + csrfField(req) + Html.hidden("action", action);
    }

    private static String newCodesCard(HttpServletRequest req, Messages m, List<String> newCodes) {
        StringBuilder b = new StringBuilder("<div class=\"card\" id=\"recovery-codes\"><h2>");
        b.append(m.html("setup.codes.heading")).append(H2_P).append(m.html("setup.codes.intro")).append("</p><ul class=\"codes\">");
        for (String c : newCodes) {
            b.append("<li><code>").append(Html.esc(c)).append("</code></li>");
        }
        return b.append("</ul><p><a href=\"").append(Html.esc(req.getContextPath())).append("/secure/Dashboard.jspa\">")
                .append(m.html("setup.codes.continue")).append("</a></p></div>").toString();
    }

    private String notice(HttpServletRequest req, Messages m, Requirement r, String key) {
        if (r == Requirement.ENROL_REQUIRED) {
            return "<div class=\"notice\" role=\"alert\">" + m.html("setup.required") + "</div>";
        }
        if (r != Requirement.ENROL_OPTIONAL) {
            return "";
        }
        String end = mfa.graceEndIfStarted(key).map(DATE::format).orElse(m.text("setup.optional.graceEnd"));
        return "<div class=\"notice\">" + m.htmlWith("setup.optional", "<strong>" + Html.esc(end) + "</strong>")
                + postForm(req, "later", "inline")
                + " <button type=\"submit\" class=\"secondary\" id=\"later\">" + m.html("setup.later") + BUTTON_FORM_DIV;
    }

    /** Passkeys first: the recommended factor. */
    private String passkeyCard(HttpServletRequest req, Messages m, List<MfaPasskey> passkeys, boolean focusAdd,
                               boolean codesFollow) {
        String ctx = req.getContextPath();
        StringBuilder b = new StringBuilder("<div class=\"card\" id=\"passkey-card\"><h2>");
        b.append(m.html("setup.passkey.heading")).append(" <span class=\"badge\">").append(m.html("setup.passkey.badge")).append("</span></h2>");
        if (passkeys.isEmpty()) {
            b.append("<p>").append(m.html("setup.passkey.intro")).append("</p><ol class=\"steps\"><li>")
                    .append(m.html("setup.passkey.step1")).append("</li><li>").append(m.html("setup.passkey.step2"))
                    .append(codesFollow ? "</li><li>" + m.html("setup.passkey.step3") : "").append("</li></ol>");
        } else {
            b.append("<table><thead><tr><th scope=\"col\">").append(m.html("setup.passkey.colName"))
                    .append("</th><th scope=\"col\">").append(m.html("setup.passkey.colAdded"))
                    .append("</th><th scope=\"col\"><span class=\"muted\">").append(m.html("setup.passkey.colAction"))
                    .append("</span></th></tr></thead><tbody>");
            for (MfaPasskey p : passkeys) {
                b.append("<tr><td>").append(Html.esc(p.getLabel())).append("</td><td>")
                        .append(DATE.format(Instant.ofEpochMilli(p.getCreated()))).append("</td><td>")
                        .append(postForm(req, "passkey-remove", "inline")).append(Html.hidden("id", Integer.toString(p.getID())))
                        .append("<button type=\"submit\" class=\"secondary\" aria-label=\"").append(m.html("setup.passkey.removeLabel", p.getLabel()))
                        .append("\">").append(m.html("setup.passkey.remove")).append("</button></form></td></tr>");
            }
            b.append("</tbody></table><p class=\"muted\">").append(m.html("setup.passkey.more")).append("</p>");
        }
        Map<String, String> data = new LinkedHashMap<>();
        data.put("options", ctx + SERVLET + "/webauthn/register/options");
        data.put("finish", ctx + SERVLET + "/webauthn/register/finish");
        data.put("done", ctx + SERVLET + "/setup");
        data.put("csrf", mfa.csrfToken(req.getSession(true)));
        data.put("msg-unsupported", m.text("js.unsupported"));
        data.put("msg-failed", m.text("setup.passkey.addFailed"));
        data.put("default-name", m.text("setup.passkey.defaultName"));
        return b.append("<div id=\"passkey-register\"").append(Html.dataAttrs(data)).append(">")
                .append("<label for=\"passkey-label\">").append(m.html("setup.passkey.label")).append("</label>")
                .append("<input type=\"text\" id=\"passkey-label\" maxlength=\"60\" value=\"")
                .append(m.html("setup.passkey.defaultName")).append("\">")
                .append("<button type=\"button\" id=\"passkey-add\"").append(focusAdd ? " autofocus" : "").append(">")
                .append(m.html("setup.passkey.add")).append("</button>")
                .append("<p class=\"error\" role=\"alert\" id=\"passkey-error\" hidden></p></div></div>").toString();
    }

    private String totpCard(HttpServletRequest req, Messages m) {
        return "<div class=\"card\" id=\"totp-card\"><h2>" + m.html("setup.totp.heading") + H2_P
                + m.html("setup.totp.present") + "</p>" + postForm(req, "totp-remove", "")
                + "<button type=\"submit\" class=\"secondary\">" + m.html("setup.totp.remove") + BUTTON_FORM_DIV;
    }

    /** The authenticator app as the alternative, folded away unless the user is working on it. */
    private String totpEnrolment(HttpServletRequest req, Messages m, ApplicationUser u, String errorKey) {
        boolean open = isTotpError(errorKey);
        StringBuilder b = new StringBuilder("<details class=\"card\" id=\"totp-section\"");
        b.append(open ? " open" : "").append("><summary>").append(m.html("setup.totp.summary"))
                .append("</summary><p class=\"muted\">").append(m.html("setup.totp.slower")).append("</p>");
        byte[] secret;
        try {
            secret = mfa.pendingTotpSecret(req.getSession(true), u.getKey());
        } catch (RuntimeException e) {
            // key file problem: keep passkeys and "later" usable instead of failing the whole page
            LOG.error("cannot offer TOTP enrolment to {}", u.getUsername(), e);
            secret = null;
        }
        if (secret == null) {
            return b.append("<p class=\"error\" role=\"alert\" id=\"totp-unavailable\">").append(m.html(TOTP_UNAVAILABLE))
                    .append("</p></details>").toString();
        }
        String uri = Totp.otpauthUri(mfa.settings().issuer, u.getUsername(), secret);
        return b.append("<p>").append(m.html("setup.totp.scan")).append("</p>")
                .append("<div class=\"qr\">").append(Html.qrSvg(uri, m.text("setup.totp.qrLabel"))).append("</div>")
                .append("<p class=\"muted\">").append(m.htmlWith("setup.totp.manual",
                        "<code id=\"totp-secret\">" + Html.esc(Totp.base32(secret)) + "</code>")).append("</p>")
                .append("<form method=\"post\" autocomplete=\"off\">").append(csrfField(req)).append(Html.hidden("action", "totp-confirm"))
                .append("<label for=\"totp-code\">").append(m.html("setup.totp.codeLabel"))
                .append("</label><input type=\"text\" id=\"totp-code\" name=\"code\" inputmode=\"numeric\" autocomplete=\"one-time-code\" pattern=\"[0-9 ]{6,7}\" required")
                .append(open ? " autofocus" : "").append(">")
                .append("<button type=\"submit\" id=\"totp-confirm\">").append(m.html("setup.totp.add")).append("</button></form></details>")
                .toString();
    }
}
