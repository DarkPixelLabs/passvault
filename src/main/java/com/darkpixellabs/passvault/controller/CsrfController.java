package com.darkpixellabs.passvault.controller;

import com.darkpixellabs.passvault.security.CsrfFilter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class CsrfController {
    private final SecureRandom secureRandom = new SecureRandom();

    @GetMapping("/csrf")
    public ResponseEntity<?> token() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        ResponseCookie cookie = ResponseCookie.from(CsrfFilter.COOKIE_NAME, token)
                .httpOnly(false)
                .secure(false)
                .sameSite("Strict")
                .path("/")
                .build();
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(Map.of("token", token));
    }
}
