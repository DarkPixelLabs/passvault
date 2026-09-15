package com.darkpixellabs.passvault.controller;

import com.darkpixellabs.passvault.crypto.CryptoService;
import com.darkpixellabs.passvault.model.VaultEntry;
import com.darkpixellabs.passvault.model.VaultEntryRepository;
import com.darkpixellabs.passvault.model.VaultUser;
import com.darkpixellabs.passvault.model.VaultUserRepository;
import com.darkpixellabs.passvault.security.SessionManager;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/vault")
public class VaultController {
    private static final String SESSION_COOKIE = "PASSVAULT_SESSION";

    private final VaultEntryRepository entryRepository;
    private final VaultUserRepository userRepository;
    private final CryptoService cryptoService;
    private final SessionManager sessionManager;

    public VaultController(VaultEntryRepository entryRepository, VaultUserRepository userRepository,
                           CryptoService cryptoService, SessionManager sessionManager) {
        this.entryRepository = entryRepository;
        this.userRepository = userRepository;
        this.cryptoService = cryptoService;
        this.sessionManager = sessionManager;
    }

    @GetMapping
    public ResponseEntity<?> list(HttpServletRequest request) {
        Optional<SessionManager.SessionData> session = sessionManager.getSession(extractSessionToken(request));
        if (session.isEmpty()) return unauthorized();

        long userId = session.get().userId();
        List<EntryMetadata> entries = entryRepository.findAllByUserIdOrderBySiteNameAsc(userId)
                .stream()
                .map(entry -> new EntryMetadata(entry.getId(), entry.getSiteName(), entry.getUsername(), entry.getUrl()))
                .toList();
        return ResponseEntity.ok(entries);
    }

    @GetMapping("/{id}/reveal")
    public ResponseEntity<?> reveal(@PathVariable Long id, HttpServletRequest request) {
        Optional<SessionManager.SessionData> session = sessionManager.getSession(extractSessionToken(request));
        if (session.isEmpty()) return unauthorized();

        byte[] key = session.get().derivedKey();
        try {
            VaultEntry entry = entryRepository.findById(id).orElse(null);
            if (entry == null || entry.getUser().getId() != session.get().userId()) {
                return ResponseEntity.notFound().build();
            }
            byte[] plaintext = cryptoService.decrypt(entry.getEncryptedPassword(), key, entry.getPasswordNonce());
            try {
                return ResponseEntity.ok(Map.of("password", new String(plaintext, StandardCharsets.UTF_8)));
            } finally {
                Arrays.fill(plaintext, (byte) 0);
            }
        } finally {
            // wipe local key copy — SessionManager only owns wiping its internal copy
            Arrays.fill(key, (byte) 0);
        }
    }

    private static ResponseEntity<Map<String, String>> unauthorized() {
        return ResponseEntity.status(401).body(Map.of("error", "Authentication required."));
    }

    private static String extractSessionToken(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) return null;
        for (Cookie cookie : cookies) {
            if (SESSION_COOKIE.equals(cookie.getName())) return cookie.getValue();
        }
        return null;
    }

    public record EntryMetadata(Long id, String siteName, String username, String url) {}
}
