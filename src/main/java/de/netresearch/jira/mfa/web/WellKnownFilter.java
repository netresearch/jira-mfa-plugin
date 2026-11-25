package de.netresearch.jira.mfa.web;

import de.netresearch.jira.mfa.core.RelyingParties;
import de.netresearch.jira.mfa.service.MfaService;

import javax.inject.Inject;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Set;

/**
 * Answers {@code /.well-known/webauthn}, which a browser reads without cookies
 * before it lets one host use a passkey of another. Runs before the login and
 * so before {@link MfaFilter}, which keeps no open path for it. Without related
 * origins, and for every other spelling of the path, the request continues
 * as if this filter did not exist.
 */
public class WellKnownFilter implements Filter {
    private final MfaService mfa;

    @Inject
    public WellKnownFilter(MfaService mfa) {
        this.mfa = mfa;
    }

    @Override
    public void init(FilterConfig filterConfig) {
        // nothing to set up
    }

    @Override
    public void destroy() {
        // nothing to release
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        if (!RelyingParties.isWellKnown(req.getRequestURI(), req.getContextPath()) || mfa.settings().relatedOrigins.isEmpty()) {
            chain.doFilter(request, response);
            return;
        }
        answer(req.getMethod(), (HttpServletResponse) response, mfa.passkeys().allowedOrigins());
    }

    static void answer(String method, HttpServletResponse resp, Set<String> origins) throws IOException {
        boolean head = "HEAD".equals(method);
        if (!head && !"GET".equals(method)) {
            resp.setHeader("Allow", "GET, HEAD");
            resp.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
            return;
        }
        byte[] body = RelyingParties.wellKnownJson(origins).getBytes(StandardCharsets.UTF_8);
        resp.setStatus(HttpServletResponse.SC_OK);
        resp.setContentType("application/json");
        resp.setHeader("Cache-Control", "no-store");
        resp.setContentLength(body.length);
        if (!head) {
            resp.getOutputStream().write(body);
        }
    }
}
