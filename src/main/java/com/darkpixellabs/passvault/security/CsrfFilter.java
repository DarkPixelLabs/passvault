package com.darkpixellabs.passvault.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.MessageDigest;

@Component
public class CsrfFilter extends OncePerRequestFilter {
    public static final String COOKIE_NAME = "PASSVAULT_CSRF";
    public static final String HEADER_NAME = "X-CSRF-TOKEN";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (!requiresProtection(request) || validToken(request)) {
            filterChain.doFilter(request, response);
            return;
        }
        response.sendError(HttpServletResponse.SC_FORBIDDEN, "CSRF validation failed.");
    }

    private boolean requiresProtection(HttpServletRequest request) {
        if (!"POST".equalsIgnoreCase(request.getMethod()) && !"PUT".equalsIgnoreCase(request.getMethod())
                && !"DELETE".equalsIgnoreCase(request.getMethod()) && !"PATCH".equalsIgnoreCase(request.getMethod())) {
            return false;
        }
        String path = request.getRequestURI();
        return !"/api/login".equals(path);
    }

    private boolean validToken(HttpServletRequest request) {
        String cookieToken = null;
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (COOKIE_NAME.equals(cookie.getName())) {
                    cookieToken = cookie.getValue();
                    break;
                }
            }
        }
        String headerToken = request.getHeader(HEADER_NAME);
        return cookieToken != null && headerToken != null
                && MessageDigest.isEqual(cookieToken.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                headerToken.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
}
