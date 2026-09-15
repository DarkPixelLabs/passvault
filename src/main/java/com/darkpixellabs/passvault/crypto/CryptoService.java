package com.darkpixellabs.passvault.crypto;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import org.springframework.stereotype.Service;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

@Service
public class CryptoService {
    private static final int SALT_LENGTH = 16;
    private static final int KEY_LENGTH = 32;
    private static final int NONCE_LENGTH = 12;
    private static final int GCM_TAG_BITS = 128;
    private static final int ARGON2_ITERATIONS = 3;
    private static final int ARGON2_MEMORY_KIB = 65536;
    private static final int ARGON2_PARALLELISM = 2;

    private final SecureRandom secureRandom = new SecureRandom();
    private final Argon2 argon2 = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);

    public byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        secureRandom.nextBytes(salt);
        return salt;
    }

    public String hashMasterPassword(char[] password) {
        try {
            return argon2.hash(ARGON2_ITERATIONS, ARGON2_MEMORY_KIB, ARGON2_PARALLELISM,
                    password, StandardCharsets.UTF_8);
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    public boolean verifyMasterPassword(char[] password, String storedHash) {
        try {
            return argon2.verify(storedHash, password, StandardCharsets.UTF_8);
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    public byte[] deriveKey(char[] password, byte[] salt) {
        try {
            return argon2.rawHash(ARGON2_ITERATIONS, ARGON2_MEMORY_KIB, ARGON2_PARALLELISM,
                    password, salt, KEY_LENGTH, StandardCharsets.UTF_8);
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    public EncryptedData encrypt(byte[] plaintext, byte[] key) {
        try {
            byte[] nonce = new byte[NONCE_LENGTH];
            secureRandom.nextBytes(nonce);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, nonce));
            return new EncryptedData(nonce, cipher.doFinal(plaintext));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Encryption failed", e);
        }
    }

    public byte[] decrypt(byte[] ciphertext, byte[] key, byte[] nonce) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, nonce));
            return cipher.doFinal(ciphertext);
        } catch (AEADBadTagException e) {
            throw new IllegalArgumentException("Ciphertext authentication failed", e);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Decryption failed", e);
        }
    }

    public record EncryptedData(byte[] nonce, byte[] ciphertext) {}
}
