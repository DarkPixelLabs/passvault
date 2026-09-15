package com.darkpixellabs.passvault.controller;

import com.darkpixellabs.passvault.crypto.CryptoService;
import com.darkpixellabs.passvault.model.VaultUser;
import com.darkpixellabs.passvault.model.VaultUserRepository;
import com.darkpixellabs.passvault.security.AuthRateLimiter;
import com.darkpixellabs.passvault.security.SessionManager;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class AuthControllerTest {
    private final VaultUserRepository userRepository = mock(VaultUserRepository.class);
    private final CryptoService cryptoService = mock(CryptoService.class);
    private final SessionManager sessionManager = mock(SessionManager.class);
    private final AuthRateLimiter rateLimiter = new AuthRateLimiter();
    private final AuthController controller = new AuthController(userRepository, cryptoService, sessionManager, rateLimiter);

    @Test
    void setupSucceedsOnceAndRejectsSecondAttempt() {
        when(userRepository.count()).thenReturn(0L, 1L);
        when(cryptoService.hashMasterPassword(any(char[].class))).thenReturn("argon2-hash");
        when(cryptoService.generateSalt()).thenReturn(new byte[16]);

        ResponseEntity<?> first = controller.setup(new AuthController.PasswordRequest("strong-password-12"), request());
        ResponseEntity<?> second = controller.setup(new AuthController.PasswordRequest("strong-password-12"), request());

        assertEquals(200, first.getStatusCode().value());
        assertEquals(409, second.getStatusCode().value());
        verify(userRepository, times(1)).save(any(VaultUser.class));
    }

    @Test
    void weakPasswordIsRejected() {
        when(userRepository.count()).thenReturn(0L);

        ResponseEntity<?> response = controller.setup(new AuthController.PasswordRequest("short"), request());

        assertEquals(400, response.getStatusCode().value());
        verify(userRepository, never()).save(any());
    }

    @Test
    void correctLoginSucceedsAndSetsStrictHttpOnlyCookie() {
        VaultUser user = new VaultUser();
        user.setPasswordHash("argon2-hash");
        user.setEncryptionSalt(new byte[16]);
        when(userRepository.findAll()).thenReturn(java.util.List.of(user));
        when(cryptoService.verifyMasterPassword(any(char[].class), eq("argon2-hash"))).thenReturn(true);
        when(cryptoService.deriveKey(any(char[].class), any(byte[].class))).thenReturn(new byte[32]);
        when(sessionManager.createSession(any(byte[].class), anyLong())).thenReturn("session-token");

        ResponseEntity<?> response = controller.login(new AuthController.PasswordRequest("strong-password-12"), request());

        assertEquals(200, response.getStatusCode().value());
        String setCookie = response.getHeaders().getFirst("Set-Cookie");
        assertNotNull(setCookie);
        assertTrue(setCookie.contains("PASSVAULT_SESSION=session-token"));
        assertTrue(setCookie.contains("HttpOnly"));
        assertTrue(setCookie.contains("SameSite=Strict"));
    }

    @Test
    void wrongPasswordIsRejectedGenerically() {
        VaultUser user = new VaultUser();
        user.setPasswordHash("argon2-hash");
        user.setEncryptionSalt(new byte[16]);
        when(userRepository.findAll()).thenReturn(java.util.List.of(user));
        when(cryptoService.verifyMasterPassword(any(char[].class), eq("argon2-hash"))).thenReturn(false);

        ResponseEntity<?> response = controller.login(new AuthController.PasswordRequest("wrong-password"), request());

        assertEquals(401, response.getStatusCode().value());
        assertEquals("{error=Invalid master password.}", response.getBody().toString());
        verify(sessionManager, never()).createSession(any(), anyLong());
    }

    @Test
    void rateLimitKicksInAfterTenAttempts() {
        when(userRepository.count()).thenReturn(1L);
        for (int i = 0; i < 10; i++) {
            ResponseEntity<?> response = controller.login(new AuthController.PasswordRequest("wrong-password"), request());
            assertEquals(401, response.getStatusCode().value());
        }

        ResponseEntity<?> blocked = controller.login(new AuthController.PasswordRequest("wrong-password"), request());
        assertEquals(429, blocked.getStatusCode().value());
    }

    @Test
    void logoutInvalidatesSessionAndClearsCookie() {
        MockHttpServletRequest request = request();
        request.setCookies(new Cookie("PASSVAULT_SESSION", "session-token"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        ResponseEntity<?> result = controller.logout(request, response);

        assertEquals(200, result.getStatusCode().value());
        verify(sessionManager).invalidate("session-token");
        String setCookie = result.getHeaders().getFirst("Set-Cookie");
        assertNotNull(setCookie);
        assertTrue(setCookie.contains("PASSVAULT_SESSION="));
        assertTrue(setCookie.contains("Max-Age=0"));
    }

    private static MockHttpServletRequest request() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("192.0.2.10");
        return request;
    }
}
