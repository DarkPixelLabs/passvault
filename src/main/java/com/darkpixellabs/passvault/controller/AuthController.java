package com.darkpixellabs.passvault.controller;

import com.darkpixellabs.passvault.crypto.CryptoService;
import com.darkpixellabs.passvault.model.VaultUser;
import com.darkpixellabs.passvault.model.VaultUserRepository;
import com.darkpixellabs.passvault.security.AuthRateLimiter;
import com.darkpixellabs.passvault.security.SessionManager;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.Arrays;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class AuthController {
    private static final int MIN_PASSWORD_LENGTH = 12;
    private static final String SESSION_COOKIE = "PASSVAULT_SESSION";
    private static final Duration SESSION_COOKIE_MAX_AGE = Duration.ofMinutes(15);

    private final VaultUserRepository userRepository;
    private final CryptoService cryptoService;
    private final SessionManager sessionManager;
    private final AuthRateLimiter rateLimiter;

    public AuthController(VaultUserRepository userRepository, CryptoService cryptoService,
                          SessionManager sessionManager, AuthRateLimiter rateLimiter) {
        this.userRepository = userRepository;
        this.cryptoService = cryptoService;
        this.sessionManager = sessionManager;
        this.rateLimiter = rateLimiter;
    }

    @PostMapping("/setup")
    public ResponseEntity<?> setup(@RequestBody PasswordRequest request, HttpServletRequest httpRequest) {
        String ip = clientIp(httpRequest);
        if (!rateLimiter.allow(ip)) {
            return ResponseEntity.status(429).body(Map.of("error", "Too many attempts. Try again later."));
        }
        if (userRepository.count() > 0) {
            return ResponseEntity.status(409).body(Map.of("error", "Master password is already configured."));
        }
        if (request == null || request.masterPassword() == null || request.masterPassword().length() < MIN_PASSWORD_LENGTH) {
            return ResponseEntity.badRequest().body(Map.of("error", "Master password must be at least 12 characters long."));
        }

        char[] password = request.masterPassword().toCharArray();
        try {
            VaultUser user = new VaultUser();
            user.setPasswordHash(cryptoService.hashMasterPassword(password));
            byte[] salt = cryptoService.generateSalt();
            user.setEncryptionSalt(salt);
            userRepository.save(user);
            return ResponseEntity.ok(Map.of("message", "Setup completed. Please log in."));
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody PasswordRequest request, HttpServletRequest httpRequest) {
        String ip = clientIp(httpRequest);
        if (!rateLimiter.allow(ip)) {
            return ResponseEntity.status(429).body(Map.of("error", "Too many attempts. Try again later."));
        }
        if (request == null || request.masterPassword() == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid master password."));
        }

        VaultUser user = userRepository.findAll().stream().findFirst().orElse(null);
        if (user == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid master password."));
        }

        char[] verifyPassword = request.masterPassword().toCharArray();
        boolean valid;
        try {
            valid = cryptoService.verifyMasterPassword(verifyPassword, user.getPasswordHash());
        } catch (RuntimeException e) {
            valid = false;
        }
        if (!valid) {
            return ResponseEntity.status(401).body(Map.of("error", "Invalid master password."));
        }

        char[] keyPassword = request.masterPassword().toCharArray();
        byte[] key = null;
        try {
            key = cryptoService.deriveKey(keyPassword, user.getEncryptionSalt());
            String token = sessionManager.createSession(key, user.getId());
            ResponseCookie cookie = ResponseCookie.from(SESSION_COOKIE, token)
                    .httpOnly(true)
                    .secure(false)
                    .sameSite("Strict")
                    .path("/")
                    .maxAge(SESSION_COOKIE_MAX_AGE)
                    .build();
            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, cookie.toString())
                    .body(Map.of("message", "Login successful."));
        } finally {
            if (key != null) {
                // wipe local key copy — SessionManager only owns wiping its internal copy
                Arrays.fill(key, (byte) 0);
            }
            Arrays.fill(keyPassword, '\0');
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        String token = extractSessionToken(request);
        sessionManager.invalidate(token);
        ResponseCookie cookie = ResponseCookie.from(SESSION_COOKIE, "")
                .httpOnly(true)
                .secure(false)
                .sameSite("Strict")
                .path("/")
                .maxAge(Duration.ZERO)
                .build();
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(Map.of("message", "Logged out."));
    }

    private static String extractSessionToken(HttpServletRequest request) {
        if (request.getCookies() == null) return null;
        for (var cookie : request.getCookies()) {
            if (SESSION_COOKIE.equals(cookie.getName())) return cookie.getValue();
        }
        return null;
    }

    private static String clientIp(HttpServletRequest request) {
        return request.getRemoteAddr();
    }

    public record PasswordRequest(String masterPassword) {}
}
