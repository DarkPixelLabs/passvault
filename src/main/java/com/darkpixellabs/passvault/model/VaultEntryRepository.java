package com.darkpixellabs.passvault.model;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface VaultEntryRepository extends JpaRepository<VaultEntry, Long> {
    List<VaultEntry> findAllByUserIdOrderBySiteNameAsc(Long userId);
}
