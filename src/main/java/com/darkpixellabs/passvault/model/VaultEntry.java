package com.darkpixellabs.passvault.model;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "vault_entries")
public class VaultEntry {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private VaultUser user;

    @Column(nullable = false, length = 200)
    private String siteName;

    @Column(length = 300)
    private String username;

    @Column(length = 1000)
    private String url;

    @Lob
    @Column(nullable = false)
    private byte[] encryptedPassword;

    @Column(nullable = false, length = 32)
    private byte[] passwordNonce;

    @Lob
    private byte[] encryptedNotes;

    @Column(length = 32)
    private byte[] notesNonce;

    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    @Column(nullable = false)
    private Instant updatedAt;

    @PrePersist
    void onCreate() {
        Instant now = Instant.now();
        createdAt = now;
        updatedAt = now;
    }

    @PreUpdate
    void onUpdate() { updatedAt = Instant.now(); }

    public Long getId() { return id; }
    public VaultUser getUser() { return user; }
    public void setUser(VaultUser user) { this.user = user; }
    public String getSiteName() { return siteName; }
    public void setSiteName(String siteName) { this.siteName = siteName; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }
    public byte[] getEncryptedPassword() { return encryptedPassword; }
    public void setEncryptedPassword(byte[] encryptedPassword) { this.encryptedPassword = encryptedPassword; }
    public byte[] getPasswordNonce() { return passwordNonce; }
    public void setPasswordNonce(byte[] passwordNonce) { this.passwordNonce = passwordNonce; }
    public byte[] getEncryptedNotes() { return encryptedNotes; }
    public void setEncryptedNotes(byte[] encryptedNotes) { this.encryptedNotes = encryptedNotes; }
    public byte[] getNotesNonce() { return notesNonce; }
    public void setNotesNonce(byte[] notesNonce) { this.notesNonce = notesNonce; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
}
