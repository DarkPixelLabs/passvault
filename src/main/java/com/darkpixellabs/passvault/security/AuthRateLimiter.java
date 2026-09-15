package com.darkpixellabs.passvault.security;

import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class AuthRateLimiter {
    private static final int MAX_ATTEMPTS = 10;
    private static final Duration WINDOW = Duration.ofMinutes(5);

    private final Map<String, Deque<Instant>> attempts = new ConcurrentHashMap<>();

    public boolean allow(String ipAddress) {
        Instant now = Instant.now();
        Deque<Instant> timestamps = attempts.computeIfAbsent(ipAddress, ignored -> new ArrayDeque<>());
        synchronized (timestamps) {
            Instant cutoff = now.minus(WINDOW);
            while (!timestamps.isEmpty() && timestamps.peekFirst().isBefore(cutoff)) {
                timestamps.removeFirst();
            }
            if (timestamps.size() >= MAX_ATTEMPTS) {
                return false;
            }
            timestamps.addLast(now);
            return true;
        }
    }

    public void clear(String ipAddress) {
        attempts.remove(ipAddress);
    }
}
