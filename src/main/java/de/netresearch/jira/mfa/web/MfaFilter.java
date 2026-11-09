package de.netresearch.jira.mfa.web;

import com.atlassian.jira.user.ApplicationUser;
import de.netresearch.jira.mfa.core.BasicAuthRule;
import de.netresearch.jira.mfa.core.LogText;
import de.netresearch.jira.mfa.core.EnforcementPolicy.Requirement;
import de.netresearch.jira.mfa.core.RequestClassifier;
import de.netresearch.jira.mfa.core.RequestClassifier.AuthScheme;
import de.netresearch.jira.mfa.service.MfaService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Enforces the second step. Runs at {@code before-dispatch}, after Seraph and
 * the token filters have established the user, for every URL.
 *
 * <ul>
 *   <li>Requests authenticated by a personal access token pass. The signal is
 *   the request attribute the PAT plugin sets after a <em>successful</em> token
 *   check; the mere presence of an {@code Authorization: Bearer} header is not
 *   trusted, because Jira falls back to the session cookie when the token is
 *   invalid.</li>
 *   <li>Requests authenticated by OAuth 1.0a (application links, and clients
 *   such as the TimeTracker that book on behalf of a user) pass. The signal is
 *   the request attribute Jira's OAuth filter sets after it has verified the
 *   request's signature and token; like the PAT check, the
 *   {@code Authorization: OAuth} header alone is not trusted. The token was
 *   granted by the user on Jira's authorize page, which is only reachable
 *   from a verified session.</li>
 *   <li>HTTP Basic requests are decided by {@link BasicAuthRule}: refused once
 *   the user has a factor or the grace period has expired, unless the user is
 *   allow-listed (password-only REST would bypass the second factor).</li>
 *   <li>Browser sessions must complete the second step (or enrolment) before
 *   anything but the plugin's own pages and static resources is served.</li>
 * </ul>
 */
public class MfaFilter implements Filter {
    private static final Logger LOG = LoggerFactory.getLogger(MfaFilter.class);
    /** Set by Jira's bundled pats-plugin (TokenBasedAuthenticationFilter) after a valid token. */
    static final String PAT_ATTRIBUTE = "access.token.request";
    /**
     * Set by Jira's bundled OAuth service provider plugin (OAuthFilter, location
     * before-login) after a successful OAuth 1.0a authentication; the key is
     * {@code RequestAnnotations.OAUTH_REQUEST_FLAG} of atlassian-oauth-api,
     * spelled "oath" there.
     */
    static final String OAUTH_ATTRIBUTE = "com.atlassian.oath.request-flag";

    private final MfaService mfa;

    @Inject
    public MfaFilter(MfaService mfa) {
        this.mfa = mfa;
    }

    @Override
    public void init(FilterConfig filterConfig) {
    }

    @Override
    public void destroy() {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse resp = (HttpServletResponse) response;
        ApplicationUser user;
        try {
            user = mfa.env().currentUser();
        } catch (RuntimeException e) {
            // Fail closed, as below: without the user the second step cannot be checked.
            LOG.error("MFA check could not determine the user on {}", LogText.clean(req.getRequestURI()), e);
            MfaServletSupport.json(resp, 503, "{\"errorMessages\":[\"Two-step verification is temporarily unavailable.\"]}");
            return;
        }
        if (user == null) {
            chain.doFilter(request, response);
            return;
        }
        Decision d;
        try {
            d = decide(req, user);
        } catch (RuntimeException e) {
            // Fail closed: an error in the plugin must not silently disable the second factor.
            LOG.error("MFA check failed for {} on {}", LogText.clean(user.getUsername()), LogText.clean(req.getRequestURI()), e);
            d = Decision.ERROR;
        }
        switch (d) {
            case PASS:
                chain.doFilter(request, response);
                return;
            case BASIC_BLOCKED:
                mfa.basicAuthRejected(user, req.getRequestURI(), req.getRemoteAddr());
                resp.setHeader("WWW-Authenticate", "Bearer realm=\"Jira\"");
                MfaServletSupport.json(resp, 401, "{\"errorMessages\":[\"Password (Basic) authentication is disabled for accounts "
                        + "that require two-step verification. Use a personal access token (Authorization: Bearer).\"]}");
                return;
            case ERROR:
                MfaServletSupport.json(resp, 503, "{\"errorMessages\":[\"Two-step verification is temporarily unavailable.\"]}");
                return;
            case RELOGIN:
                HttpSession old = req.getSession(false);
                if (old != null) {
                    try {
                        old.invalidate();
                    } catch (IllegalStateException alreadyInvalidated) {
                        // a parallel request of the same session ended it first
                    }
                }
                String path = RequestClassifier.dispatchPath(req.getServletPath(), req.getPathInfo());
                if (isApi(req, path) || !"GET".equalsIgnoreCase(req.getMethod())) {
                    MfaServletSupport.json(resp, 401, "{\"errorMessages\":[\"Your session was ended by an administrator. Log in again.\"]}");
                } else {
                    resp.sendRedirect(req.getContextPath() + "/login.jsp");
                }
                return;
            default:
                challenge(req, resp, d);
        }
    }

    enum Decision { PASS, VERIFY, ENROL, BASIC_BLOCKED, ERROR, RELOGIN }

    Decision decide(HttpServletRequest req, ApplicationUser user) {
        if (req.getAttribute(PAT_ATTRIBUTE) != null || req.getAttribute(OAUTH_ATTRIBUTE) != null) {
            return Decision.PASS;
        }
        if (mfa.env().isRecoveryAdmin(user) || !mfa.settings().enabled) {
            return Decision.PASS;
        }
        String path = RequestClassifier.dispatchPath(req.getServletPath(), req.getPathInfo());
        AuthScheme scheme = RequestClassifier.scheme(req.getHeader("Authorization"));
        HttpSession session = req.getSession(false);
        if (scheme == AuthScheme.BASIC) {
            boolean sameUser = user.getUsername().equalsIgnoreCase(basicUser(req.getHeader("Authorization")));
            if (sameUser && basicPasswordChecked(req)) {
                return BasicAuthRule.allows(mfa.settings(), user.getUsername(), mfa.requirement(user))
                        ? Decision.PASS : Decision.BASIC_BLOCKED;
            }
            // a Basic header for someone else, or one whose password Seraph did not accept
            // (the user then comes from a session or remember-me cookie): treat as a session request
        }
        if (session != null && session.getCreationTime() < mfa.resetAt(user.getKey())) {
            // An admin reset ends every session that existed before it, verified or not:
            // otherwise a session of whoever caused the reset could enrol its own factor first.
            return Decision.RELOGIN;
        }
        if (mfa.isVerified(session, user)) {
            return Decision.PASS;
        }
        if (RequestClassifier.isOpen(path) && !RequestClassifier.hasEncodedSeparators(req.getRequestURI())) {
            return Decision.PASS;
        }
        if (session != null && noneCached(session, user)) {
            return Decision.PASS;
        }
        Requirement r = mfa.requirement(user);
        switch (r) {
            case NONE:
                if (session != null) {
                    // users who need nothing would otherwise cost database reads on every request
                    session.setAttribute(S_NONE_UNTIL, user.getKey() + "|" + (System.currentTimeMillis() + NONE_CACHE_MILLIS));
                }
                return Decision.PASS;
            case VERIFY:
                return Decision.VERIFY;
            case ENROL_OPTIONAL:
                if (session != null && user.getKey().equals(session.getAttribute(MfaService.S_GRACE_ACK))) {
                    return Decision.PASS;
                }
                // during the grace period only page views are diverted to the enrolment offer
                return isApi(req, path) ? Decision.PASS : Decision.ENROL;
            default:
                return Decision.ENROL;
        }
    }

    /** Request attribute Seraph's login filter sets to the result of its login attempt (BaseLoginFilter.OS_AUTHSTATUS_KEY). */
    static final String SERAPH_AUTH_STATUS = "os_authstatus";
    static final String SERAPH_LOGIN_SUCCESS = "success";

    /**
     * True when Seraph checked the Basic header's password in this request and
     * accepted it. Seraph 4.2 (Jira 9.12) authenticates a Basic header on every
     * request, also when a session exists, and records the outcome as
     * {@code os_authstatus}. With a wrong password the request may still carry
     * the user of a session or remember-me cookie; a forged {@code user:anything}
     * header must not turn such a session, which may never have passed the
     * second step, into a Basic request.
     */
    static boolean basicPasswordChecked(HttpServletRequest req) {
        return SERAPH_LOGIN_SUCCESS.equals(req.getAttribute(SERAPH_AUTH_STATUS));
    }

    static final String S_NONE_UNTIL = "de.netresearch.jira.mfa.noneUntil";
    /** How long a "no second factor needed" result is reused within a session. */
    static final long NONE_CACHE_MILLIS = 5 * 60 * 1000L;

    /**
     * True while the session's "no second factor needed" result is fresh and
     * no factor was added since it was cached (a password-only session of an
     * attacker must not keep passing after the user enrols).
     */
    private boolean noneCached(HttpSession session, ApplicationUser user) {
        Object v = session.getAttribute(S_NONE_UNTIL);
        if (!(v instanceof String)) {
            return false;
        }
        String s = (String) v;
        int bar = s.lastIndexOf('|');
        if (bar < 0 || !s.substring(0, bar).equals(user.getKey())) {
            return false;
        }
        try {
            long until = Long.parseLong(s.substring(bar + 1));
            return System.currentTimeMillis() < until
                    && !mfa.factorsChangedSince(user.getKey(), until - NONE_CACHE_MILLIS);
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private static boolean isApi(HttpServletRequest req, String path) {
        return RequestClassifier.isApiRequest(path, req.getHeader("Accept"), req.getHeader("X-Requested-With"));
    }

    private void challenge(HttpServletRequest req, HttpServletResponse resp, Decision d) throws IOException {
        String path = RequestClassifier.dispatchPath(req.getServletPath(), req.getPathInfo());
        if (isApi(req, path) || !"GET".equalsIgnoreCase(req.getMethod())) {
            MfaServletSupport.json(resp, 401, "{\"errorMessages\":[\"Two-step verification required. Complete it in the browser at "
                    + req.getContextPath() + MfaServletSupport.SERVLET + "/verify\"]}");
            return;
        }
        String query = req.getQueryString();
        req.getSession(true).setAttribute(MfaService.S_RETURN, path + (query == null ? "" : "?" + query));
        String target = d == Decision.VERIFY ? "/verify" : "/setup";
        resp.sendRedirect(req.getContextPath() + MfaServletSupport.SERVLET + target);
    }

    static String basicUser(String header) {
        try {
            String decoded = new String(Base64.getDecoder().decode(header.trim().substring(6).trim()), StandardCharsets.UTF_8);
            int colon = decoded.indexOf(':');
            return colon < 0 ? decoded : decoded.substring(0, colon);
        } catch (RuntimeException e) {
            return "";
        }
    }
}
