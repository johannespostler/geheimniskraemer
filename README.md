# Geheimniskrämer

Very opinionated, self-hosted, single-binary password manager. 
Login only via Passkey (WebAuthn + PRF), end-to-end encrypted vault, PWA. 
There is currently no browser extensions, because I like the security boundary between different browsers and I'm fine with copy-pasting.

While it does support multiple users, it likely doesn't scale well due to SQLite in the backend. A couple of users should be fine thought.

Let me know, if you spot any bugs or flaws.

See `plans/PLAN.md` for the design.

## Run (dev)

```sh
go run . serve                       # app on 127.0.0.1:8087
caddy run --config Caddyfile.dev     # https://localhost → app
```

Create a user and open the printed invite URL:

```sh
go run . invite alice
```

## Build & test

```sh
make build   # → ./gk
make test    # Go + JS tests
```

## Production

```sh
./gk serve -db /var/lib/gk/gk.db -origin https://vault.example.com
```

Caddy: see `Caddyfile.example` (TLS 1.3 only, HSTS, compression for static
assets only). `-origin` must match the public URL exactly — WebAuthn
credentials are bound to it, so pick the final domain before registering
passkeys.

### systemd, not a container

I deploy via the hardened systemd unit in `gk.service.example`, not a
container. For a single static binary, the unit confines tighter than a
default container and adds no daemon or image supply chain:

- throwaway dynamic UID; filesystem read-only except `/var/lib/gk` (0700)
- no capabilities, `NoNewPrivileges`, kernel surfaces masked, syscall filter
- network restricted to localhost with deny-all — even a fully compromised
  process cannot make outbound connections to exfiltrate anything

Caveat: the data dir belongs to the dynamic user, so run `gk invite` via
`systemd-run` (see comments in the unit) or briefly stop the service and run
it as root.

## Backup

Everything lives in one SQLite file (WAL mode — copy it only via SQLite):

```sh
sqlite3 gk.db "VACUUM INTO 'backup-$(date +%F).db'"
```

The backup contains only ciphertext. It is useless without a passkey or
recovery code — which also means: **no passkey and no recovery code, no
vault.** Store recovery codes offline. Restore = stop server, replace
`gk.db` (delete stale `gk.db-wal`/`gk.db-shm`), start server.
