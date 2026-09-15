# PassVault

PassVault is a self-hosted, single-user encrypted password manager built as a learning project with Java 21 and Spring Boot 3. It stores vault metadata in an H2 file database and keeps secrets encrypted at rest.

> **Learning-project disclaimer:** PassVault is intentionally small and educational. Do not treat it as a professionally audited password manager or as a substitute for an established security product without performing your own security review.

## Security model

- **Master password:** never stored. Only an Argon2id password hash is persisted.
- **Key derivation:** Argon2id derives a 256-bit AES key from the master password using a separate random 16-byte encryption salt stored with the user record.
- **Argon2id parameters:** 3 iterations, 64 MiB memory, parallelism 2. These are explicit, reasonable application parameters and should be reviewed for the deployment hardware.
- **Encryption:** AES-256-GCM using JCA. Every encryption operation generates a fresh random 12-byte nonce; a nonce is never intentionally reused.
- **Vault data:** passwords and notes are stored as authenticated ciphertext plus their nonces. The normal vault list returns only site, username and URL metadata.
- **Reveal:** decrypted passwords are returned only by `GET /api/vault/{id}/reveal` and are never included in the list response.
- **Sessions:** successful login creates a random session token in an HTTP-only, `SameSite=Strict` cookie. The derived key is held only in server memory with a 15-minute idle timeout.
- **Key hygiene:** `SessionManager.getSession()` returns a clone of the internal key. Every caller that uses that local `byte[]` must wipe it in a `finally` block with `Arrays.fill(key, (byte) 0)`. The internal session copy remains owned by `SessionManager`, which wipes it on logout or expiry.
- **CSRF:** state-changing requests use a double-submit CSRF cookie/header check; login is excluded because it is the authentication entry point.
- **Rate limiting:** setup and login are limited to 10 attempts per IP address in a five-minute in-memory sliding window.
- **Logging:** plaintext master passwords, vault passwords and derived keys must not be logged.

## Important warning

**Lose the master password = lose the vault permanently, by design.** There is no recovery key or master-password reset path. Loss or corruption of the H2 database also means loss of the vault unless you maintain your own secure database backup.

## Running locally

Requirements: Java 21 and Maven 3.9+ (or the included Maven wrapper).

```bash
./mvnw spring-boot:run
```

Windows:

```powershell
.\mvnw.cmd spring-boot:run
```

Then open `http://localhost:8080` and initialize the vault with a master password of at least 12 characters.

## API overview

- `GET /api/health` — health check
- `GET /api/setup/status` — whether a master password is configured
- `GET /api/csrf` — issue a CSRF token cookie/token pair
- `POST /api/setup` — first-time setup; does not auto-login
- `POST /api/login` — authenticate and create a session
- `POST /api/logout` — invalidate the session and clear its cookie
- `GET /api/vault` — metadata-only list
- `GET /api/vault/{id}/reveal` — decrypt one password on demand
- `POST /api/vault` — create an encrypted entry
- `PUT /api/vault/{id}` — replace an entry and re-encrypt changed secrets
- `DELETE /api/vault/{id}` — delete an entry

## Docker

```bash
docker build -t passvault .
docker run --rm -p 8080:8080 -v passvault-data:/app/data passvault
```

The H2 database lives under `/app/data`, so use a persistent volume in real deployments.

## Out of scope

Multi-user accounts, browser extensions, sharing/folders, password generation, breach/strength checks, and backup/export/import workflows are intentionally outside this learning project.

## License

MIT — see `LICENSE`.
