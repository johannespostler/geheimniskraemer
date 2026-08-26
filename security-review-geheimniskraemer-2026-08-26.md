# Security Review: Geheimniskrämer

**Date:** 2026-08-26
**Scope:** Full repository at commit `ce83e44` (branch `main`), including uncommitted working-tree changes to `web/app.js`, `web/manifest.json`, `web/sw.js`. Go server (`*.go`), PWA client (`web/`), and deployment configs (`Caddyfile.*`, `gk.service.example`). Excluded: vendored dependencies, test files, generated icons.
**Method:** Four-perspective AI code review (offensive, defensive, privacy, operational)

## Summary

Geheimniskrämer is a well-built, security-conscious self-hosted password manager. The core design is genuinely strong: the server is a zero-knowledge blob store that only ever handles wrapped keys and opaque AES-GCM ciphertext, all SQL is parameterized, the CSP is strict (`default-src 'none'`), cookies use `__Host-` + `HttpOnly` + `Secure` + `SameSite=Strict`, and authentication is passkey-only with PRF-derived key wrapping and 160-bit recovery codes. No critical or high-severity issues were found — no injection, no IDOR, no auth bypass, no XSS.

The findings that remain are about the boundaries of the threat model rather than breaks in it: end-to-end encryption protects **confidentiality** of vault contents, but a stolen session can still **destroy** them irreversibly, and a few defense-in-depth controls (rate limiting, secret handling at rest) are weaker than they appear. All are Medium or Low.

| Severity     | Count |
|--------------|-------|
| 🔴 Critical  | 0     |
| 🟠 High      | 0     |
| 🟡 Medium    | 2     |
| 🟢 Low       | 5     |

**Remediation status (updated 2026-08-26):** #1 accepted and addressed operationally (encrypted backups). #2 improved with a proxy-secret gate on `X-Forwarded-For`. #3, #4, #5, #6, #7 fixed in code. Details in each finding.

## Findings

### 🟡 #1 — Session theft irreversibly destroys the vault; E2E encryption does not cover integrity or availability

- **Severity:** Medium
- **Perspective:** Offensive, Operational
- **Location:** `entries.go:47` (`handlePutEntry`), `entries.go:82` (`handleDeleteEntry`), `credentials.go:147` (`handleDeleteCredential`), `credentials.go:183` (`handleSetRecovery`)

**What's wrong.** The encryption model guarantees an attacker who obtains a session cookie *cannot read* the vault (they lack the passkey/PRF output and thus the vault key). But every mutating endpoint accepts and applies writes with nothing more than a valid session. `handlePutEntry` overwrites an entry with any well-formed ciphertext-shaped blob (it never decrypts, so garbage is accepted), `handleDeleteEntry` deletes, and `handleSetRecovery` overwrites the recovery verifier and wrapped key with attacker-supplied bytes. There is no server-side versioning, soft-delete, or audit trail.

**Why it matters.** A stolen or forged session is a total, silent, irreversible loss of the vault: an attacker can null out every entry with junk ciphertext and clobber the recovery blob, and the legitimate user — who *can* still decrypt — has nothing left to decrypt. "Encrypted at rest" quietly reads as "safe," but confidentiality and destructibility are different properties. Exploitation is hard (strict CSP blocks XSS, `SameSite=Strict` + the CSRF header block cross-site forgery), so this is Medium, not High — but the blast radius is the entire vault.

**Recommendation.** Two independent mitigations: (1) Operationally, document and automate encrypted backups / SQLite snapshots of `gk.db` — this is the real recovery path and the systemd unit should reference it. (2) Consider soft-deletes / an entry version counter so an overwrite or delete is recoverable server-side, and rate-limit or step-up-authenticate destructive bulk operations. At minimum, note in the README that session compromise means data loss even though it does not mean disclosure.

**Status: accepted — addressed operationally.** The residual risk is covered by encrypted `gk.db` backups rather than in-app versioning. The confidentiality guarantee is unchanged; recovery from a destructive session-compromise is a restore-from-backup operation.

---

### 🟡 #2 — Rate limiter is fully bypassable via spoofed `X-Forwarded-For` from any loopback-reachable client

- **Severity:** Medium
- **Perspective:** Defensive
- **Location:** `ratelimit.go:69` (`clientIP`), `server.go:69` / `server.go:78-92`

**What's wrong.** `clientIP` trusts the `X-Forwarded-For` header whenever the direct peer is a loopback address, which is correct for the intended "Caddy on the same host" topology. But it trusts *any* loopback peer, and the rate-limit bucket key is the resulting IP string. Any process or user that can open a TCP connection to the listener (`127.0.0.1:8087` by default) can send a different, attacker-chosen `X-Forwarded-For` value on every request, landing each in a fresh token bucket and defeating the limiter entirely.

**Why it matters.** On a single-user box the loopback port is only reachable by that user, so the practical impact is low — which is why this is Medium and not higher. On a shared / multi-tenant host, any local user can reach `127.0.0.1:8087` and bypass the anti-brute-force control on `/api/login`, `/api/register`, and `/api/recover`. The saving grace is that there is nothing feasibly brute-forceable behind these endpoints (discoverable WebAuthn login, 256-bit invite tokens, 160-bit recovery codes), so this weakens a defense-in-depth layer rather than opening a direct break.

**Recommendation.** Only trust `X-Forwarded-For` from an explicitly configured trusted-proxy address, and take the *rightmost* untrusted hop rather than the leftmost client-controlled value — or drop XFF parsing entirely and add a `-trusted-proxy` flag that is off by default. Also bind to loopback only (already the default) and document that the port must not be exposed on shared hosts.

**Status: improved.** `gk serve` now takes a `-proxy-secret` (default `$GK_PROXY_SECRET`). When set, `X-Forwarded-For` is trusted only on a request that also carries a matching `X-GK-Proxy` header (constant-time compared) — so a local process reaching the listener directly can no longer forge a fresh rate-limit bucket per request. Caddy is configured to send the secret and to *overwrite* `X-Forwarded-For` with the real peer (`{remote_host}`), closing client-supplied XFF smuggling through the proxy too (`Caddyfile.example`, `gk.service.example` via `EnvironmentFile=/etc/gk.env`). With no secret set the previous loopback-trust behavior remains as a documented single-tenant fallback. Covered by `TestClientIPProxySecret` (`ratelimit.go:69`, `server.go`).

---

### 🟢 #3 — Invite token travels in the URL query string

- **Severity:** Low
- **Perspective:** Privacy, Defensive
- **Location:** `invite.go:38`, `web/app.js:105` / `web/app.js:132`

**What's wrong.** Registration invites are distributed as `https://origin/?invite=<256-bit token>`. The client clears it from the address bar with `history.replaceState` after use, and `Referrer-Policy: no-referrer` prevents referer leakage — both good. But before that, the token appears in the URL: it is written to browser history, and if any proxy or the origin server logs request paths (Caddy access logs commonly do), the token lands in logs.

**Why it matters.** Invite tokens are single-use and short-lived (24h default) and consuming them is transactional, which bounds the damage. Still, a token in an access log or shared browser history is a credential sitting in a place credentials should not be. Whoever reads the log within the validity window could register the account before the invitee does.

**Recommendation.** Prefer delivering the token in a way that keeps it out of the URL (e.g. a POST/paste flow), or shorten the default TTL and ensure the proxy is configured not to log query strings for `/`. At minimum, document that invite links are sensitive and short-lived.

**Status: fixed (deployment).** `Caddyfile.example` now includes an access-log block with a `filter` that deletes the `invite` query parameter, so the token cannot land in logs even when logging is enabled (Caddy logs nothing by default). The client already strips the token from the address bar after use and `Referrer-Policy: no-referrer` is set. Residual: browser history on the invitee's own device — inherent to any link-delivered invite; mitigated by the short TTL.

---

### 🟢 #4 — Session identifiers are stored unhashed at rest

- **Severity:** Low
- **Perspective:** Defensive, Privacy
- **Location:** `auth.go:14` (`createSession`), `auth.go:36` (`requireAuth`), `db.go:21`

**What's wrong.** Session IDs are 256-bit random tokens (good), but they are stored verbatim as the `sessions.id` primary key and compared directly. The token in the DB *is* the bearer credential.

**Why it matters.** Any read access to `gk.db` — a leaked backup, a stray copy, filesystem access — yields live, usable session cookies until they expire (12h). Hashing would make the stored value useless to a reader. This is Low because there is no code path that leaks the DB and the entries themselves stay encrypted, but session hijack enables finding #1.

**Recommendation.** Store `sha256(token)` and look sessions up by the hash; keep the raw token only in the cookie. Same treatment already applied correctly to the recovery verifier (`credentials.go:198`) — mirror it here.

**Status: fixed.** `createSession` now stores `hashToken(token)` (SHA-256, base64url) as the row key and sends the raw token in the cookie; `requireAuth` and `handleLogout` look up / delete by hash (`auth.go`). A DB read no longer yields usable session cookies.

---

### 🟢 #5 — No per-user cap on entry count or total storage (authenticated DoS)

- **Severity:** Low
- **Perspective:** Offensive, Operational
- **Location:** `entries.go:47` (`handlePutEntry`), `entries.go:15` (`maxEntrySize`)

**What's wrong.** Individual entries are capped at 64 KB, but a valid session can create an unbounded number of them (client-generated UUID ids, one row each). There is no per-user quota on row count or aggregate bytes.

**Why it matters.** A single authenticated (or compromised) account can fill the disk backing the SQLite file, taking the service down for all users. Requires a valid session, so blast radius is limited; hence Low.

**Recommendation.** Enforce a per-user entry count and/or total-bytes ceiling in `handlePutEntry`, returning `413`/`409` past the limit. A few thousand entries is a generous cap for a personal password manager.

**Status: fixed.** `handlePutEntry` now rejects a *new* entry (id not already owned by the user) once the user holds `maxEntriesPerUser = 1000`, returning `507 Insufficient Storage`. Updates to existing entries are never blocked. The check is a soft cap (concurrent creates can overshoot slightly), which is acceptable for a quota (`entries.go`).

---

### 🟢 #6 — `crypto/rand.Read` return values are ignored

- **Severity:** Low
- **Perspective:** Defensive
- **Location:** `webauthn.go:98` (`randToken`), `webauthn.go:120` (registration handle), `auth.go` via `randToken`

**What's wrong.** `rand.Read(b)` is called without checking the error in token and user-handle generation. On modern Go, `crypto/rand.Read` does not fail in practice (it panics internally on a broken RNG rather than returning a short read), so this is defensive hygiene rather than a live bug — but the code reads as if a failure would silently yield a low-entropy or zero-filled token.

**Why it matters.** If this code were ever ported to an environment or Go version where `rand.Read` can return early, an unchecked error would produce predictable session/invite tokens — a catastrophic failure that would pass silently. Today it is safe; the risk is latent.

**Recommendation.** Check the error and treat it as fatal for that request (or use a helper that panics), so a future RNG regression can never degrade to weak tokens unnoticed.

**Status: fixed.** Added `randBytes(n)`, which panics if `crypto/rand.Read` ever fails; `randToken` and the WebAuthn user-handle generation both go through it, so a CSPRNG failure can never silently yield a low-entropy token (`webauthn.go`).

---

### 🟢 #7 — Secrets copied to the clipboard may sync across devices

- **Severity:** Low
- **Perspective:** Privacy
- **Location:** `web/app.js:542` (`copyButton`), `web/app.js:556` (clipboard clear), `web/app.js:153`

**What's wrong.** Passwords, TOTP codes, and the recovery code are placed on the system clipboard. The app clears it after 30 seconds (best-effort) — a reasonable mitigation — but modern OS clipboards (Windows clipboard history, Android/ChromeOS cross-device clipboard, macOS Universal Clipboard) may capture or replicate the value before the clear fires, and to other devices the clear does not reach.

**Why it matters.** A copied password can outlive the 30s window in a synced clipboard history on another device the user did not think of as in scope. This is an inherent tradeoff of clipboard-based password managers, noted for completeness.

**Recommendation.** Keep the auto-clear. Optionally document the cross-device clipboard caveat, and where the browser supports it consider marking the write as sensitive/history-excluded (`ClipboardItem` with appropriate hints) — support is uneven but improving.

**Status: fixed (best-effort).** All secret copies (entry fields, TOTP codes, recovery code) now route through a `copySecret` helper that writes via the async `ClipboardItem` API where available — the vehicle browsers use to tag a payload as sensitive and keep it out of clipboard history/previews — falling back to `writeText`, and still backstopped by the existing 30s auto-clear (`web/app.js`). Note: no web standard yet *guarantees* OS-history exclusion, so on platforms that don't honor the hint this remains a normal copy plus the timed clear — an honest ceiling on what a web app can do here.

---

## Positive observations

These are things the review specifically checked and found done correctly — worth recording so they are not "fixed" into regressions later:

- **Zero-knowledge server.** Vault keys are PRF-derived and wrapped client-side; the server stores only `IV || AES-GCM(...)` ciphertext and wrapped keys. `unwrapVaultKey` produces a non-extractable `CryptoKey` by default (`web/crypto.js:49`).
- **Write-once vault-key slot** (`webauthn.go:270`): a hijacked session cannot swap in an attacker-controlled wrapped key, because only an empty slot can be filled.
- **CSRF is genuinely closed:** custom-header requirement (`auth.go:69`) + no CORS handler (cross-origin preflight fails) + `SameSite=Strict` + `__Host-` prefix.
- **Recovery flow is well-designed:** 160-bit codes, independent HKDF derivation of KEK vs. verifier, constant-time verifier comparison, uniform 403 + fixed delay to prevent account probing (`credentials.go:207`).
- **All DB access is parameterized;** user-scoped queries consistently include `AND user_id = ?`, including the upsert conflict clause in `handlePutEntry` — no IDOR.
- **Strong operational hardening** in `gk.service.example` (DynamicUser, full syscall/namespace/capability lockdown, `IPAddressAllow=localhost`) and TLS 1.3-only + HSTS in the Caddyfile.
- **No secrets committed:** `gk.db`, binaries, and WAL files are correctly gitignored; only `db.go` matches the tracked-file check.
