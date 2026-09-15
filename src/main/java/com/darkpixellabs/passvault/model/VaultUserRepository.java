package com.darkpixellabs.passvault.model;

import org.springframework.data.jpa.repository.JpaRepository;

public interface VaultUserRepository extends JpaRepository<VaultUser, Long> {
    boolean existsById(Long id);
}
