package com.darkpixellabs.passvault.security;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class SessionManagerTest {
    @Test
    void expiredSessionIsRemovedAndDerivedKeyIsWiped() throws Exception {
        SessionManager manager = new SessionManager();
        byte[] originalKey = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
        String token = manager.createSession(originalKey, 42L);

        Field sessionsField = SessionManager.class.getDeclaredField("sessions");
        sessionsField.setAccessible(true);
        @SuppressWarnings("unchecked")
        Map<String, Object> sessions = (Map<String, Object>) sessionsField.get(manager);
        Object session = sessions.get(token);
        assertNotNull(session);

        Field lastAccessField = session.getClass().getDeclaredField("lastAccess");
        lastAccessField.setAccessible(true);
        lastAccessField.set(session, Instant.now().minusSeconds(16 * 60));

        Field keyField = session.getClass().getDeclaredField("key");
        keyField.setAccessible(true);
        byte[] storedKey = (byte[]) keyField.get(session);
        assertArrayEquals(originalKey, storedKey);

        assertTrue(manager.getSession(token).isEmpty());
        assertEquals(0, manager.activeSessionCount());
        assertTrue(Arrays.stream(storedKey).allMatch(value -> value == 0),
                "Expired session key must be wiped from memory");
    }

    @Test
    void explicitInvalidationAlsoWipesDerivedKey() throws Exception {
        SessionManager manager = new SessionManager();
        String token = manager.createSession(new byte[]{9, 8, 7, 6}, 7L);

        Field sessionsField = SessionManager.class.getDeclaredField("sessions");
        sessionsField.setAccessible(true);
        @SuppressWarnings("unchecked")
        Map<String, Object> sessions = (Map<String, Object>) sessionsField.get(manager);
        Object session = sessions.get(token);
        Field keyField = session.getClass().getDeclaredField("key");
        keyField.setAccessible(true);
        byte[] storedKey = (byte[]) keyField.get(session);

        manager.invalidate(token);

        assertTrue(Arrays.stream(storedKey).allMatch(value -> value == 0));
        assertTrue(manager.getSession(token).isEmpty());
    }
}
