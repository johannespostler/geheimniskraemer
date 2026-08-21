# Geheimniskrämer — Plan

Self-hosted, single-binary password manager. Passkey-only login, end-to-end encrypted vault, PWA.

## Architecture

```
Browser (vanilla JS + WebCrypto)          Go binary
┌─────────────────────────────┐   HTTPS   ┌──────────────────────┐
│ decrypt/encrypt vault (AES) │ ◄──────► │ WebAuthn ceremony     │
│ PRF → unwrap vault key      │  (Caddy) │ session cookies       │
│ PWA shell, copy-to-clipboard│          │ SQLite: ciphertext only│
└─────────────────────────────┘          └──────────────────────┘
```

The server never sees plaintext or keys. It stores opaque ciphertext blobs per user.

## Key design (the core problem: multiple passkeys, one vault)

Use the **WebAuthn PRF extension** (`prf`), supported by Chrome/Edge, Safari 17.4+/18, Android, iCloud Keychain, YubiKey 5:

1. On vault creation: generate random 256-bit **vault key** (VK) in the browser.
2. Per passkey: `prfOutput = PRF(credential, fixed salt)` → `KEK = HKDF(prfOutput)` → store `wrap(KEK, VK)` on the server next to the credential.
3. On login: WebAuthn assertion returns the PRF output → derive KEK → unwrap VK → decrypt entries with AES-256-GCM (random nonce per entry, per field).
4. Adding a passkey: while logged in (VK in memory), register new credential, wrap VK with its KEK.
5. **Recovery**: at vault creation, generate a one-time 256-bit recovery code (base32, shown once, stored offline by the user); it wraps VK like a passkey does. Redeeming it lets you register a fresh passkey.

**Decision**: synced passkeys are **allowed** (strict BE-flag rejection would block default iPhone/Android passkeys). PRF support is **required** — registration rejects authenticators without it; no master-password fallback.

## Stack

- **Go** std `net/http`, `embed` for static assets. Dependencies (deliberately few):
  - `github.com/go-webauthn/webauthn` (the de-facto library; writing WebAuthn by hand is a security anti-pattern)
  - `modernc.org/sqlite` (pure Go, no CGO → trivial cross-compile) — or `crawshaw.io/sqlite`
- **Frontend**: no framework, no build step. Vanilla ES modules, WebCrypto API. ~500 lines.
- **PWA**: manifest.json + minimal service worker (cache app shell only; never cache API responses).

## Data model (SQLite)

```sql
users(id, name, created_at)
credentials(id, user_id, credential_data BLOB, wrapped_vault_key BLOB, name, created_at)
entries(id, user_id, ciphertext BLOB, updated_at)   -- ciphertext = AES-GCM({website, username, password, notes, custom...})
```

Encrypting the whole entry as one JSON blob keeps the schema fixed while fields stay configurable client-side (spec 6). Trade-off: no server-side search — fine, filtering happens in the browser after decrypt.

## Security measures

- CSP: `default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'` — no inline scripts, no external resources.
- Headers: HSTS (via Caddy), `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy`.
- Sessions: HttpOnly, Secure, SameSite=Strict cookie; short TTL; server-side session store.
- CSRF: SameSite=Strict + custom header check (no token machinery needed for a JSON API).
- Registration of new users: invite-token via CLI (`gk invite <name>`, prints a single-use expiring registration URL) — no open signup. The CLI is a subcommand of the same binary, run on the server host, writing directly to the SQLite DB (WAL mode handles concurrency with the running server). No admin API: OS access to the DB file *is* the admin boundary.
- VK lives only in JS memory (non-extractable CryptoKey where possible); wiped on lock/timeout.
- Rate limiting on auth endpoints; binary runs as non-root, listens on localhost behind Caddy.

## Bitwarden import

Client-side only: file picker → parse export JSON in browser → map `items[].login.{uris[0].uri, username, password}` + `name`, `notes` → encrypt → bulk upload. Unmapped types (cards, identities, secure notes) → import as notes or skip, shown in a preview table before committing. The server never sees the plaintext export.

## Alternatives considered

- **JSON file storage**: viable, but SQLite (pure-Go driver) wins on concurrent writes + integrity for near-zero extra complexity. Backup = copy one file either way.
- **Deriving keys from passkey signatures instead of PRF**: signatures are non-deterministic (can't derive keys). PRF is the correct primitive; the fallback for non-PRF authenticators is a master password (adds UX + attack surface — recommend requiring PRF instead).
- **htmx / lit / preact**: unnecessary; vanilla JS keeps the auditable surface minimal.

## Milestones

1. Skeleton: Go server, embedded static, SQLite, Caddy dev config.
2. WebAuthn register/login with PRF, BE-flag rejection, invite flow.
3. Vault crypto in browser: create VK, wrap/unwrap, entry CRUD, clipboard copy.
4. Multi-passkey management (add/rename/revoke; revoke = delete wrapped key) + recovery code.
5. PWA (manifest, SW, icons), auto-lock timer.
6. Bitwarden import with preview.
7. Hardening pass: CSP audit, rate limits, backup docs (`sqlite3 .backup` or plain file copy).
