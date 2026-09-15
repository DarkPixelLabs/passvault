package com.darkpixellabs.passvault.model;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "vault_users")
public class VaultUser {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 500)
    private String passwordHash;

    @Column(nullable = false, length = 128)
    private byte[] encryptionSalt;

    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @PrePersist
    void onCreate() {
        createdAt = Instant.now();
    }

    public Long getId() { return id; }
    public String getPasswordHash() { return passwordHash; }
    public void setPasswordHash(String passwordHash) { this.passwordHash = passwordHash; }
    public byte[] getEncryptionSalt() { return encryptionSalt; }
    public void setEncryptionSalt(byte[] encryptionSalt) { this.encryptionSalt = encryptionSalt; }
    public Instant getCreatedAt() { return createdAt; }
}
