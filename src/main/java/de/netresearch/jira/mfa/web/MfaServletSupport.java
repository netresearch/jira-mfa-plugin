package de.netresearch.jira.mfa.web;

import com.atlassian.jira.component.ComponentAccessor;
import com.atlassian.jira.security.xsrf.XsrfTokenGenerator;
import com.atlassian.jira.user.ApplicationUser;
import com.atlassian.sal.api.websudo.WebSudoManager;
import com.atlassian.sal.api.websudo.WebSudoSessionException;
import de.netresearch.jira.mfa.core.EnforcementPolicy.Requirement;
import de.netresearch.jira.mfa.core.LogText;
import de.netresearch.jira.mfa.service.MfaService;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/** Common helpers for the plugin's servlets. */
abstract class MfaServletSupport extends HttpServlet {
    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(MfaServletSupport.class);
    static final String PLUGIN_KEY = "de.netresearch.jira.jira-mfa-plugin";
    static final String SERVLET = "/plugins/servlet/mfa";

    protected final MfaService mfa;

    MfaServletSupport(MfaService mfa) {
        this.mfa = mfa;
    }

    /** Handles a GET; answers 405 unless overridden. */
    protected void get(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
    }

    /** Handles a POST; answers 405 unless overridden. */
    protected void post(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
    }

    @Override
    protected final void doGet(HttpServletRequest req, HttpServletResponse resp) {
        handle(req, resp, this::get);
    }

    @Override
    protected final void doPost(HttpServletRequest req, HttpServletResponse resp) {
        handle(req, resp, this::post);
    }

    @FunctionalInterface
    interface Handler {
        void handle(HttpServletRequest req, HttpServletResponse resp) throws IOException;
    }

    /**
     * Runs a handler. An IOException here means the answer could not be
     * written, almost always because the client went away; nothing is left to
     * answer, so it is logged instead of reaching the container's error page.
     */
    static void handle(HttpServletRequest req, HttpServletResponse resp, Handler h) {
        try {
            h.handle(req, resp);
        } catch (IOException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("answer to {} {} not completed: {}", req.getMethod(), LogText.clean(req.getRequestURI()), e.toString());
            }
        }
    }

    ApplicationUser user() {
        return mfa.env().currentUser();
    }

    /** Sends anonymous visitors to the Jira login page; returns null in that case. */
    ApplicationUser requireUser(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        ApplicationUser u = user();
        if (u == null) {
            String here = req.getServletPath() + (req.getPathInfo() == null ? "" : req.getPathInfo());
            resp.sendRedirect(req.getContextPath() + "/login.jsp?os_destination=" + URLEncoder.encode(here, StandardCharsets.UTF_8));
        }
        return u;
    }

    /**
     * The current user if a system administrator in a verified, secure
     * administrator session (websudo); otherwise answers the request and
     * returns null.
     */
    ApplicationUser requireAdmin(HttpServletRequest req, HttpServletResponse resp, WebSudoManager webSudo) throws IOException {
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

    static String scriptUrl(HttpServletRequest req) {
        return req.getContextPath() + "/download/resources/" + PLUGIN_KEY + ":mfa-assets/mfa.js";
    }

    String csrfField(HttpServletRequest req) {
        return Html.hidden("csrf", mfa.csrfToken(req.getSession(true)));
    }

    static boolean rejectBadCsrf(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        if (!MfaService.csrfValid(req)) {
            resp.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid or missing form token. Reload the page and try again.");
            return true;
        }
        return false;
    }

    /** The page the filter interrupted, if it is a safe local path; otherwise the dashboard. */
    static String takeReturnUrl(HttpServletRequest req) {
        HttpSession s = req.getSession(false);
        String target = null;
        if (s != null) {
            Object r = s.getAttribute(MfaService.S_RETURN);
            s.removeAttribute(MfaService.S_RETURN);
            if (r instanceof String) {
                target = (String) r;
            }
        }
        if (!isSafeLocalPath(target)) {
            target = "/secure/Dashboard.jspa";
        }
        return req.getContextPath() + target;
    }

    /**
     * A path on this Jira that is not one of the plugin's own pages. Control
     * characters are refused because browsers strip tab and newline from URLs,
     * which would turn {@code /\t/evil.example} into the protocol-relative
     * {@code //evil.example}.
     */
    static boolean isSafeLocalPath(String target) {
        if (target == null || !target.startsWith("/") || target.startsWith("//") || target.contains("\\")
                || target.startsWith(SERVLET)) {
            return false;
        }
        for (int i = 0; i < target.length(); i++) {
            char c = target.charAt(i);
            if (c < 0x20 || c == 0x7f) {
                return false;
            }
        }
        return true;
    }

    /**
     * The bar at the top of every plugin page: a way back into Jira (only when
     * Jira would let the session in, otherwise the link would just bounce back
     * here), who is logged in, and Log out. Jira 9.12 answers 403 to /logout
     * without its XSRF token.
     */
    static String header(HttpServletRequest req, ApplicationUser u, boolean backToJira) {
        String ctx = req.getContextPath();
        String xsrf = ComponentAccessor.getComponent(XsrfTokenGenerator.class).generateToken(req);
        String logout = ctx + "/logout?atl_token=" + URLEncoder.encode(xsrf, StandardCharsets.UTF_8);
        StringBuilder b = new StringBuilder("<header class=\"topbar\"><nav aria-label=\"Jira\">");
        if (backToJira) {
            b.append("<a class=\"home\" id=\"back-to-jira\" href=\"").append(Html.esc(ctx)).append("/secure/Dashboard.jspa\">\u2190 Back to Jira</a>");
        } else {
            b.append("<span class=\"home\">Jira</span>");
        }
        b.append("<span class=\"who\">").append(Html.esc(u.getDisplayName())).append("</span>")
                .append("<a id=\"logout\" href=\"").append(Html.esc(logout)).append("\">Log out</a></nav></header>");
        return b.toString();
    }

    static void json(HttpServletResponse resp, int status, String body) throws IOException {
        resp.setStatus(status);
        resp.setContentType("application/json;charset=UTF-8");
        resp.setHeader("Cache-Control", "no-store");
        resp.getWriter().write(body);
    }

    static String jsonString(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') {
                b.append('\\').append(c);
            } else if (c < 0x20 || c == '<' || c == '>' || c == '&') {
                b.append(String.format("\\u%04x", (int) c));
            } else {
                b.append(c);
            }
        }
        return b.append('"').toString();
    }
}
