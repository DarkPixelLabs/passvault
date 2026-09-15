package com.darkpixellabs.passvault.security;

import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class SessionManager {
    private static final Duration IDLE_TIMEOUT = Duration.ofMinutes(15);

    private final Map<String, Session> sessions = new ConcurrentHashMap<>();

    public String createSession(byte[] derivedKey, long userId) {
        String token = UUID.randomUUID().toString();
        sessions.put(token, new Session(derivedKey.clone(), userId, Instant.now()));
        return token;
    }

    public Optional<SessionData> getSession(String token) {
        if (token == null) return Optional.empty();
        Session session = sessions.get(token);
        if (session == null) return Optional.empty();
        synchronized (session) {
            if (Instant.now().isAfter(session.lastAccess.plus(IDLE_TIMEOUT))) {
                removeAndWipe(token, session);
                return Optional.empty();
            }
            session.lastAccess = Instant.now();
            return Optional.of(new SessionData(session.key.clone(), session.userId));
        }
    }

    public void invalidate(String token) {
        if (token == null) return;
        Session session = sessions.remove(token);
        if (session != null) Arrays.fill(session.key, (byte) 0);
    }

    int activeSessionCount() { return sessions.size(); }

    private void removeAndWipe(String token, Session session) {
        if (sessions.remove(token, session)) Arrays.fill(session.key, (byte) 0);
    }

    private static final class Session {
        private final byte[] key;
        private final long userId;
        private Instant lastAccess;

        private Session(byte[] key, long userId, Instant lastAccess) {
            this.key = key;
            this.userId = userId;
            this.lastAccess = lastAccess;
        }
    }

    public record SessionData(byte[] derivedKey, long userId) {}
}
