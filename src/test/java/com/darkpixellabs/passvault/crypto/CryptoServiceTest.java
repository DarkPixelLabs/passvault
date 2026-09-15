package com.darkpixellabs.passvault.crypto;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class CryptoServiceTest {
    private final CryptoService crypto = new CryptoService();

    @Test
    void encryptDecryptRoundTrip() {
        byte[] key = crypto.deriveKey("correct horse battery staple".toCharArray(), crypto.generateSalt());
        byte[] plaintext = "my secret password".getBytes(StandardCharsets.UTF_8);

        CryptoService.EncryptedData encrypted = crypto.encrypt(plaintext, key);

        assertArrayEquals(plaintext, crypto.decrypt(encrypted.ciphertext(), key, encrypted.nonce()));
    }

    @Test
    void wrongKeyFailsToDecrypt() {
        byte[] salt = crypto.generateSalt();
        byte[] key = crypto.deriveKey("correct password".toCharArray(), salt);
        byte[] wrongKey = crypto.deriveKey("different password".toCharArray(), salt);
        CryptoService.EncryptedData encrypted = crypto.encrypt("secret".getBytes(StandardCharsets.UTF_8), key);

        assertThrows(IllegalArgumentException.class,
                () -> crypto.decrypt(encrypted.ciphertext(), wrongKey, encrypted.nonce()));
    }

    @Test
    void everyEncryptionUsesUniqueNonceAndCiphertext() {
        byte[] key = crypto.deriveKey("correct password".toCharArray(), crypto.generateSalt());
        byte[] plaintext = "same data".getBytes(StandardCharsets.UTF_8);

        CryptoService.EncryptedData first = crypto.encrypt(plaintext, key);
        CryptoService.EncryptedData second = crypto.encrypt(plaintext, key);

        assertFalse(Arrays.equals(first.nonce(), second.nonce()));
        assertFalse(Arrays.equals(first.ciphertext(), second.ciphertext()));
    }

    @Test
    void tamperedCiphertextFailsAuthentication() {
        byte[] key = crypto.deriveKey("correct password".toCharArray(), crypto.generateSalt());
        CryptoService.EncryptedData encrypted = crypto.encrypt("secret".getBytes(StandardCharsets.UTF_8), key);
        byte[] tampered = encrypted.ciphertext().clone();
        tampered[tampered.length - 1] ^= 0x01;

        assertThrows(IllegalArgumentException.class,
                () -> crypto.decrypt(tampered, key, encrypted.nonce()));
    }
}
