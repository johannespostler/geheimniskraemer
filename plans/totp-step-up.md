# TOTP step-up for synced passkeys

## Goal

Synced (backup-eligible) passkeys live in Apple/Google account sync fabrics we
don't fully trust. Compromise of that account yields the passkey — so a login
asserted with a synced credential must additionally prove possession of a
secret that never touched the sync fabric: an account-level TOTP (user keeps it
in Aegis, offline). Device-bound credentials (BE=0: YubiKey, TPM-backed) stay
single-step. A device that has passed TOTP once may be remembered ("trusted
device") so subsequent synced-passkey logins there skip the prompt.

**TOTP is opt-in.** One secret per user (account-level, not per-credential —
the trusted-device list is per-user too). A user who hasn't enrolled logs in
exactly as today, regardless of BE flag; once enrolled, every synced-passkey
login steps up. Enrollment is a settings action, never forced — the nag banner
(Phase 5) is the only push.

## Detection

`webauthn.Credential.Flags.BackupEligible` (the BE flag in signed authenticator
data) is `true` for synced passkeys and fixed for the credential's lifetime.
Read it from the credential returned by `FinishRegistration` /
`FinishDiscoverableLogin`. Decision rule everywhere: **BE=1 ⇒ TOTP required**
(unless a valid trusted-device token is presented at login).

Threat-model note: BE is asserted by the authenticator, not attested. Apple/
Google platform authenticators set it truthfully, which is exactly the case we
care about.

## Existing pieces this builds on

- Ceremony store (`webauthn.go`): in-memory, cookie-referenced, 5-min TTL —
  reuse the same pattern for the pending-TOTP state between login-finish and
  totp-verify.
- Session tokens are stored hashed (`auth.go` `hashToken`) — trusted-device
  tokens follow the same rule.
- IP rate limiter (`ratelimit.go`) already wraps all unauthenticated auth
  endpoints — wrap the new TOTP endpoints too, and add a per-user attempt
  limit on top (TOTP is 6 digits; IP limiting alone is not enough against a
  distributed guesser).
- Recovery codes already exist (client-derived verifier, recovery-wrapped
  vault key). The recovery code never syncs, so the recover flow is
  threat-model-consistent as-is and stays TOTP-free. The earlier idea of
  "second device-bound credential instead of recovery codes" becomes: keep
  recovery codes, and additionally **nag** users whose only vault-capable
  credentials are synced (see Phase 5).
- `web/totp.js` already implements TOTP generation client-side (WebCrypto) for
  vault entries — reuse for the enrollment "verify one code" step? No: the
  secret must not be handled by vault code paths; enrollment just displays the
  QR/secret and posts the user-typed code. No client TOTP computation needed.

## Schema (db.go, additive migrations like the recovery ones)

```sql
ALTER TABLE users ADD COLUMN totp_secret     BLOB;    -- RFC 6238 secret, NULL = not enrolled
ALTER TABLE users ADD COLUMN totp_last_step  INTEGER; -- last accepted time-step, replay guard

CREATE TABLE IF NOT EXISTS trusted_devices (
    id         TEXT PRIMARY KEY,                -- SHA-256 of the cookie token (hashToken)
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label      TEXT NOT NULL DEFAULT '',        -- derived from User-Agent at creation
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    last_seen  INTEGER NOT NULL DEFAULT (unixepoch()),
    expires_at INTEGER NOT NULL
);
```

The TOTP secret is stored plaintext server-side — the server must compute HMAC
over it, and the adversary in this design is the sync fabric, not the server.
(The DB already holds session hashes and credential public keys; vault
contents remain E2E encrypted regardless.)

## Server: TOTP implementation (new file `totp.go`)

Implement RFC 6238 in-house (HMAC-SHA1, 6 digits, 30 s step, ±1 step skew) —
~40 lines with `crypto/hmac`, matching the repo's minimal-dependency style
(deps today: go-webauthn, modernc sqlite). Table-driven tests against RFC 6238
Appendix B vectors in `totp_test.go`.

Verification rules:
- Constant-time digit comparison (`subtle.ConstantTimeCompare`).
- Accept a step only if `step > totp_last_step` (update atomically:
  `UPDATE users SET totp_last_step = ? WHERE id = ? AND (totp_last_step IS NULL
  OR totp_last_step < ?)` and check RowsAffected) — blocks replay and
  concurrent double-spend of one code.
- Per-user attempt limiter: reuse the token-bucket type keyed by
  `"totp:"+userID` (e.g. 5/min, burst 5), in addition to the IP limiter.

## Flow changes

### Login (`webauthn.go` `handleLoginFinish`)

After `FinishDiscoverableLogin` succeeds:

1. `needsTOTP := cred.Flags.BackupEligible && userHasTOTP(u.id)`
   - No TOTP enrolled ⇒ normal login, no flags, no forcing (TOTP is opt-in).
2. If `needsTOTP`, check the trusted-device cookie (`gk_trust`): valid,
   unexpired row for **this user** ⇒ skip TOTP, bump `last_seen`, extend
   `expires_at` (sliding 60 days).
3. Otherwise do **not** call `createSession` and do **not** return
   `wrappedVaultKey`. Store a pending entry in the ceremony store
   (`kind: "totp", userID, credID`) — its existing 5-minute TTL and
   single-use `take` semantics are exactly right — and respond
   `{"totpRequired": true, "username": ...}`.

New endpoint `POST /api/login/totp` (IP-rate-limited):
- `take` the ceremony (kind `"totp"`), verify the code (per-user limiter
  first). On failure: re-`put` the pending ceremony? No — simpler and safer:
  respond 401 and let the client re-submit against a fresh `put` made by the
  handler on failure (re-put with same data, fresh cookie), so one wrong digit
  doesn't force a full re-login, but the 5-min window still bounds it.
- On success: `createSession`, fetch `wrapped_vault_key` for the pending
  `credID`, return the same payload `handleLoginFinish` returns today, plus —
  if the client asked with `{"trust": true}` — mint a trusted-device token:
  random 32B, store hash + UA label + `expires_at = now+60d`, set cookie
  `gk_trust` (`HttpOnly; Secure; SameSite=Strict; Path=/api; Max-Age=60d`).
  Only a successful TOTP verification ever sets or extends... (correction:
  step 2 above extends on use; acceptable — the extension happens only after a
  fresh passkey assertion by the same user, and absolute cap below).
- Add `absolute` cap: refuse to extend past `created_at + 180d`; after that
  the row expires and the user TOTPs again.

### Enrollment (opt-in, from settings)

Registration is unchanged — no forcing, whatever the BE flag. Enrollment is a
user-initiated settings action. Endpoints (authenticated):

- `POST /api/totp/enroll/begin` — generate 20-byte secret, store in the
  ceremony store (kind `"totp-enroll"`, not yet in DB), return
  `otpauth://totp/Geheimniskr%C3%A4mer:<user>?secret=...&issuer=Geheimniskr%C3%A4mer`.
  Non-ASCII ("ä") is fine in otpauth URIs as percent-encoded UTF-8 — Aegis
  decodes and displays it correctly (build with `url.PathEscape` /
  `url.QueryEscape`, never raw bytes). Client renders QR + shows the secret
  for manual Aegis entry.
- `POST /api/totp/enroll/finish` — body `{code}`; verify against the pending
  secret, then persist to `users.totp_secret`. Refuse if a secret is already
  set (write-once via `UPDATE ... WHERE totp_secret IS NULL`).
- `POST /api/totp/disable` — body `{code}`; verify current code (per-user
  limiter applies), then NULL the secret and delete the user's trusted-device
  rows. Rotation = disable + re-enroll.

### Add / recover credential flows (`credentials.go`)

- `handleAddCredFinish`: if the **new** credential has BE=1 and the user has
  TOTP, require a fresh TOTP code in the finish request body (session hijack
  must not be enough to plant an attacker-synced passkey). No TOTP enrolled ⇒
  unchanged.
- `handleRecoverFinish`: unchanged (recovery verifier never syncs). A newly
  registered BE=1 credential on a TOTP-enrolled account is fine — future
  logins with it step up.

### Trusted-device management

- `GET /api/trusted-devices` (authenticated): list id-prefix, label,
  created_at, last_seen.
- `POST /api/trusted-devices/delete`: revoke one; `{"all": true}` revokes all.
- Opportunistic purge of expired rows on list/login (same style as the
  ceremony store cleanup).
- Logout does **not** clear device trust (it attests the device, not the
  session).

## Client (web/app.js, index.html, style.css)

1. Login path: handle `totpRequired` — show a 6-digit input (numeric,
   autocomplete="one-time-code") with a "trust this device for 60 days"
   checkbox, POST `/api/login/totp`, then continue into the existing
   PRF-unwrap flow exactly as if `login/finish` had returned the key. The PRF
   output can be obtained before or after TOTP; keep the current order (PRF at
   assertion time) — it's the *server's* release of `wrappedVaultKey` that is
   gated, which is the whole point.
2. Enrollment screen (reached from settings, opt-in): QR (small inline QR
   generator — a ~150-line no-dep encoder, or render the otpauth URI as text
   + secret for manual entry as v1), verify one code, done. Disable button
   prompts for a current code.
3. Settings: TOTP enroll/disable, trusted-devices list with revoke buttons;
   show per-credential "synced / device-bound" badge (server includes
   `backupEligible` in `handleListCredentials` by reading the stored
   credential JSON).
4. Nag banner (see Phase 5), dismissible: shown when no BE=0 credential with
   a wrapped vault key exists — suggests adding a device-bound passkey and/or
   enabling TOTP; links to settings.

## Migration / rollout

Trivial now that TOTP is opt-in: additive schema migration (same style as the
recovery ones), existing accounts behave exactly as today until they enroll.
No flag day, no lockouts, no legacy-account special case.
`handleDeleteCredential`'s last-way-in guard is unaffected. (A clean-slate DB
reset was offered but isn't needed.)

## Phases

1. **`totp.go` + tests; schema migrations.** No behavior change yet.
2. **Login step-up**: pending-ceremony state, `/api/login/totp`,
   `handleLoginFinish` gating, per-user attempt limiter. Server tests:
   BE=1-without-trust ⇒ no session cookie, no wrapped key in response.
3. **Enrollment/disable endpoints + add-credential gating.**
4. **Client**: TOTP prompt, enrollment screen, trusted-device checkbox,
   settings list; Playwright coverage (existing e2e harness; virtual
   authenticator can set BE flags via CDP `WebAuthn.addVirtualAuthenticator`
   `isUserVerified`/`backupEligibility` options — verify Playwright exposes
   this; fall back to unit-testing the server gate if not).
5. **Trusted devices + nag banner** for accounts with no device-bound
   vault-capable credential.

## Explicit non-goals (v1)

- Dedicated rotation UI (disable + re-enroll covers it).
- Forcing TOTP enrollment for synced-passkey accounts — nag only.
- Enforcing (hard-blocking) a second device-bound credential — nag only;
  recovery codes remain the lockout escape hatch.
- Attestation-based verification of the BE flag.

## Test checklist

- RFC 6238 vectors; skew ±1; replay of same step rejected; concurrent
  double-spend rejected (RowsAffected guard).
- Login with BE=0 credential: unchanged single-step.
- Login with BE=1: no session/key before TOTP; wrong code 401 and retryable;
  ceremony expiry after 5 min; per-user limiter kicks in at 6th try.
- Trusted device: skip works only for the same user; expired/revoked token ⇒
  TOTP again; absolute 180 d cap; hash-only storage (DB row never contains the
  cookie value).
- Add-credential with BE=1 requires code (only when enrolled); BE=0 does not.
- BE=1 account without TOTP enrolled: login unchanged, single-step.
- Disable requires a valid current code and wipes trusted-device rows;
  re-enroll works afterwards (write-once guard resets with the NULL).
- otpauth URI: issuer/label percent-encoded ("ä" ⇒ `%C3%A4`), scannable QR.
