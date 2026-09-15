package com.darkpixellabs.passvault.controller;

import com.darkpixellabs.passvault.crypto.CryptoService;
import com.darkpixellabs.passvault.model.VaultEntry;
import com.darkpixellabs.passvault.model.VaultEntryRepository;
import com.darkpixellabs.passvault.model.VaultUser;
import com.darkpixellabs.passvault.model.VaultUserRepository;
import com.darkpixellabs.passvault.security.SessionManager;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class VaultControllerTest {
    private final VaultEntryRepository entryRepository = mock(VaultEntryRepository.class);
    private final VaultUserRepository userRepository = mock(VaultUserRepository.class);
    private final CryptoService cryptoService = mock(CryptoService.class);
    private final SessionManager sessionManager = mock(SessionManager.class);
    private final VaultController controller = new VaultController(entryRepository, userRepository, cryptoService, sessionManager);
    private final byte[] sessionKey = new byte[32];

    @Test
    void listReturnsMetadataOnly() {
        VaultEntry entry = entry(7L, 1L);
        entry.setEncryptedPassword("secret-password".getBytes(StandardCharsets.UTF_8));
        when(sessionManager.getSession("token")).thenReturn(Optional.of(new SessionManager.SessionData(sessionKey.clone(), 1L)));
        when(entryRepository.findAllByUserIdOrderBySiteNameAsc(1L)).thenReturn(List.of(entry));

        ResponseEntity<?> response = controller.list(requestWithToken());

        assertEquals(200, response.getStatusCode().value());
        String body = response.getBody().toString();
        assertTrue(body.contains("example"));
        assertFalse(body.contains("secret-password"));
    }

    @Test
    void revealDecryptsPasswordAndWipesLocalKeyCopy() {
        VaultEntry entry = entry(7L, 1L);
        byte[] returnedKey = new byte[32];
        when(sessionManager.getSession("token")).thenReturn(Optional.of(new SessionManager.SessionData(returnedKey, 1L)));
        when(entryRepository.findById(7L)).thenReturn(Optional.of(entry));
        when(cryptoService.decrypt(any(), same(returnedKey), any())).thenReturn("correct-password".getBytes(StandardCharsets.UTF_8));

        ResponseEntity<?> response = controller.reveal(7L, requestWithToken());

        assertEquals(200, response.getStatusCode().value());
        assertEquals("correct-password", ((java.util.Map<?, ?>) response.getBody()).get("password"));
        assertTrue(allZero(returnedKey));
    }

    @Test
    void unauthenticatedVaultRequestReturns401() {
        when(sessionManager.getSession(isNull())).thenReturn(Optional.empty());

        ResponseEntity<?> response = controller.list(new MockHttpServletRequest());

        assertEquals(401, response.getStatusCode().value());
    }

    @Test
    void createEncryptsPasswordAndNotes() {
        VaultUser user = mock(VaultUser.class);
        when(userRepository.getReferenceById(1L)).thenReturn(user);
        when(sessionManager.getSession("token")).thenReturn(Optional.of(new SessionManager.SessionData(sessionKey.clone(), 1L)));
        when(cryptoService.encrypt(any(), any())).thenAnswer(invocation -> {
            byte[] plaintext = invocation.getArgument(0);
            return new CryptoService.EncryptedData(new byte[12], ("cipher:" + new String(plaintext, StandardCharsets.UTF_8)).getBytes(StandardCharsets.UTF_8));
        });
        VaultEntry saved = entry(9L, 1L);
        when(entryRepository.save(any(VaultEntry.class))).thenReturn(saved);

        ResponseEntity<?> response = controller.create(new VaultController.VaultEntryRequest("example", "user", "https://example.com", "password", "notes"), requestWithToken());

        assertEquals(200, response.getStatusCode().value());
        verify(cryptoService, times(2)).encrypt(any(), any());
        verify(entryRepository).save(any(VaultEntry.class));
    }

    @Test
    void updateReencryptsPasswordAndNotes() {
        VaultEntry existing = entry(7L, 1L);
        when(sessionManager.getSession("token")).thenReturn(Optional.of(new SessionManager.SessionData(sessionKey.clone(), 1L)));
        when(entryRepository.findById(7L)).thenReturn(Optional.of(existing));
        when(cryptoService.encrypt(any(), any())).thenReturn(new CryptoService.EncryptedData(new byte[12], new byte[]{1, 2, 3}));
        when(entryRepository.save(existing)).thenReturn(existing);

        ResponseEntity<?> response = controller.update(7L, new VaultController.VaultEntryRequest("new-site", "new-user", "https://new.example", "new-password", "new-notes"), requestWithToken());

        assertEquals(200, response.getStatusCode().value());
        assertEquals("new-site", existing.getSiteName());
        verify(cryptoService, times(2)).encrypt(any(), any());
    }

    @Test
    void deleteRemovesOwnedEntry() {
        VaultEntry existing = entry(7L, 1L);
        when(sessionManager.getSession("token")).thenReturn(Optional.of(new SessionManager.SessionData(sessionKey.clone(), 1L)));
        when(entryRepository.findById(7L)).thenReturn(Optional.of(existing));

        ResponseEntity<?> response = controller.delete(7L, requestWithToken());

        assertEquals(204, response.getStatusCode().value());
        verify(entryRepository).delete(existing);
    }

    private static VaultEntry entry(Long id, Long userId) {
        VaultEntry entry = new VaultEntry();
        VaultUser user = mock(VaultUser.class);
        when(user.getId()).thenReturn(userId);
        entry.setUser(user);
        entry.setSiteName("example");
        entry.setUsername("user");
        entry.setUrl("https://example.com");
        entry.setEncryptedPassword(new byte[]{1});
        entry.setPasswordNonce(new byte[12]);
        return entry;
    }

    private static MockHttpServletRequest requestWithToken() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie("PASSVAULT_SESSION", "token"));
        return request;
    }

    private static boolean allZero(byte[] bytes) {
        for (byte value : bytes) if (value != 0) return false;
        return true;
    }
}
