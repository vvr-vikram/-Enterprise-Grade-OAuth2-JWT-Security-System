package com.security.system.tenant;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class TenantFilter implements Filter {

    private static final Logger log = LoggerFactory.getLogger(TenantFilter.class);
    private static final String TENANT_HEADER = "X-Tenant-ID";

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication instanceof JwtAuthenticationToken jwtAuthenticationToken) {
            String jwtTenantId = (String) jwtAuthenticationToken.getTokenAttributes().get("tenant_id");
            String headerTenantId = httpRequest.getHeader(TENANT_HEADER);

            if (jwtTenantId == null || jwtTenantId.isEmpty()) {
                log.warn("Access token missing tenant_id claim");
                httpResponse.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid token: tenant_id missing");
                return;
            }

            // Cross-Tenant Access Protection
            if (headerTenantId != null && !headerTenantId.isEmpty() && !headerTenantId.equalsIgnoreCase(jwtTenantId)) {
                log.warn("Tenant ID mismatch! Header: {}, JWT: {}", headerTenantId, jwtTenantId);
                httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied: Tenant mismatch");
                return;
            }

            TenantContext.setTenantId(jwtTenantId);
            log.debug("TenantContext populated with: {}", jwtTenantId);
        }

        try {
            chain.doFilter(request, response);
        } finally {
            TenantContext.clear();
        }
    }
}
