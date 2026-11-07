package de.netresearch.jira.mfa.web;

import com.atlassian.jira.component.ComponentAccessor;
import com.atlassian.jira.security.xsrf.XsrfTokenGenerator;
import com.atlassian.jira.user.ApplicationUser;
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
    static final String PLUGIN_KEY = "de.netresearch.jira.jira-mfa-plugin";
    static final String SERVLET = "/plugins/servlet/mfa";

    protected final MfaService mfa;

    MfaServletSupport(MfaService mfa) {
        this.mfa = mfa;
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
        if (target == null || !target.startsWith("/") || target.startsWith("//") || target.contains("\\")
                || target.startsWith(SERVLET)) {
            target = "/secure/Dashboard.jspa";
        }
        return req.getContextPath() + target;
    }

    /** Jira 9.12 answers 403 to /logout without its XSRF token. */
    static String logoutForm(HttpServletRequest req) {
        String token = ComponentAccessor.getComponent(XsrfTokenGenerator.class).generateToken(req);
        String href = req.getContextPath() + "/logout?atl_token=" + URLEncoder.encode(token, StandardCharsets.UTF_8);
        return "<p class=\"muted\"><a id=\"logout\" href=\"" + Html.esc(href) + "\">Log out</a></p>";
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
