package de.netresearch.jira.mfa.web;

import com.atlassian.jira.user.ApplicationUser;
import com.yubico.webauthn.exception.RegistrationFailedException;
import de.netresearch.jira.mfa.core.EnforcementPolicy.Requirement;
import de.netresearch.jira.mfa.core.RequestClassifier;
import de.netresearch.jira.mfa.service.MfaService;
import de.netresearch.jira.mfa.service.PasskeyService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.io.Reader;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * JSON endpoints for the WebAuthn ceremonies, all POST with the X-MFA-Token header:
 * /plugins/servlet/mfa/webauthn/{register|authenticate}/{options|finish}
 */
public class WebAuthnServlet extends MfaServletSupport {
    private static final Logger LOG = LoggerFactory.getLogger(WebAuthnServlet.class);
    private static final int MAX_BODY = 64 * 1024;
    static final String S_FIRST_FACTOR_CODES = "de.netresearch.jira.mfa.firstFactorCodes";

    @Inject
    public WebAuthnServlet(MfaService mfa) {
        super(mfa);
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        ApplicationUser u = user();
        if (u == null) {
            json(resp, 401, "{\"error\":\"not logged in\"}");
            return;
        }
        if (!MfaService.csrfValid(req)) {
            json(resp, 403, "{\"error\":\"invalid token\"}");
            return;
        }
        // Plugin servlets are dispatched under /plugins/servlet, so the path info
        // still carries the module's own prefix (/mfa/webauthn/...).
        String path = RequestClassifier.dispatchPath(req.getServletPath(), req.getPathInfo());
        int at = path.indexOf("/webauthn/");
        path = at < 0 ? "" : path.substring(at);
        HttpSession session = req.getSession(true);
        Requirement r = mfa.requirement(u);
        PasskeyService pk = mfa.passkeys();
        try {
            switch (path) {
                case "/webauthn/register/options":
                    if (r == Requirement.VERIFY && !MfaService.isVerified(session, u)) {
                        json(resp, 403, "{\"error\":\"verify first\"}");
                        return;
                    }
                    String regRequest = pk.startRegistration(u.getKey(), u.getUsername(), u.getDisplayName());
                    session.setAttribute(MfaService.S_REG_REQUEST, regRequest);
                    json(resp, 200, PasskeyService.creationJson(regRequest));
                    return;
                case "/webauthn/register/finish": {
                    if (r == Requirement.VERIFY && !MfaService.isVerified(session, u)) {
                        json(resp, 403, "{\"error\":\"verify first\"}");
                        return;
                    }
                    Object stored = session.getAttribute(MfaService.S_REG_REQUEST);
                    session.removeAttribute(MfaService.S_REG_REQUEST);
                    if (!(stored instanceof String)) {
                        json(resp, 400, "{\"error\":\"no registration in progress\"}");
                        return;
                    }
                    boolean hadFactor = mfa.hasFactor(u.getKey());
                    String label = label(req);
                    pk.finishRegistration(u.getKey(), (String) stored, body(req), label);
                    mfa.passkeyRegistered(u, label);
                    if (!hadFactor) {
                        MfaService.markVerified(req, u);
                    }
                    if (mfa.remainingRecoveryCodes(u.getKey()) == 0) {
                        List<String> codes = mfa.regenerateRecoveryCodes(u);
                        req.getSession(true).setAttribute(S_FIRST_FACTOR_CODES, codes);
                    }
                    json(resp, 200, "{\"ok\":true}");
                    return;
                }
                case "/webauthn/authenticate/options":
                    if (r != Requirement.VERIFY) {
                        json(resp, 400, "{\"error\":\"no passkey verification needed\"}");
                        return;
                    }
                    if (mfa.lockedUntil(u) != null) {
                        json(resp, 429, "{\"error\":\"locked\"}");
                        return;
                    }
                    String authRequest = pk.startAssertion(u.getKey());
                    session.setAttribute(MfaService.S_AUTH_REQUEST, authRequest);
                    json(resp, 200, PasskeyService.requestJson(authRequest));
                    return;
                case "/webauthn/authenticate/finish": {
                    Object stored = session.getAttribute(MfaService.S_AUTH_REQUEST);
                    session.removeAttribute(MfaService.S_AUTH_REQUEST);
                    if (!(stored instanceof String) || r != Requirement.VERIFY) {
                        json(resp, 400, "{\"error\":\"no verification in progress\"}");
                        return;
                    }
                    if (mfa.lockedUntil(u) != null) {
                        json(resp, 429, "{\"error\":\"locked\"}");
                        return;
                    }
                    boolean ok;
                    try {
                        ok = pk.finishAssertion(u.getKey(), (String) stored, body(req));
                    } catch (IOException | RuntimeException e) {
                        LOG.info("passkey assertion rejected for {}: {}", u.getUsername(), e.toString());
                        ok = false;
                    }
                    if (!ok) {
                        MfaService.VerifyOutcome o = mfa.recordFailure(u, "passkey", req.getRemoteAddr());
                        json(resp, o == MfaService.VerifyOutcome.LOCKED ? 429 : 401, "{\"error\":\"passkey not accepted\"}");
                        return;
                    }
                    String target = takeReturnUrl(req);
                    mfa.recordPasskeySuccess(u, req.getRemoteAddr());
                    MfaService.markVerified(req, u);
                    json(resp, 200, "{\"ok\":true,\"redirect\":" + jsonString(target) + "}");
                    return;
                }
                default:
                    LOG.info("unknown WebAuthn endpoint: servletPath={} pathInfo={}", req.getServletPath(), req.getPathInfo());
                    json(resp, 404, "{\"error\":\"unknown endpoint\"}");
            }
        } catch (RegistrationFailedException e) {
            LOG.info("passkey registration rejected for {}: {}", u.getUsername(), e.getMessage());
            json(resp, 400, "{\"error\":\"registration rejected\"}");
        }
    }

    private static String label(HttpServletRequest req) {
        String raw = req.getHeader("X-MFA-Label");
        String label = raw == null ? "" : URLDecoder.decode(raw, StandardCharsets.UTF_8).trim();
        if (label.isEmpty()) {
            label = "Passkey";
        }
        return label.length() > 60 ? label.substring(0, 60) : label;
    }

    private static String body(HttpServletRequest req) throws IOException {
        StringBuilder b = new StringBuilder();
        char[] buf = new char[4096];
        try (Reader r = req.getReader()) {
            int n;
            while ((n = r.read(buf)) > 0) {
                b.append(buf, 0, n);
                if (b.length() > MAX_BODY) {
                    throw new IOException("request body too large");
                }
            }
        }
        return b.toString();
    }
}
