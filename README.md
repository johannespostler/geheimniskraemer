# Geheimniskrämer

Self-hosted, single-binary password manager. Passkey-only login (WebAuthn + PRF),
end-to-end encrypted vault, PWA. See `plans/PLAN.md` for the design.

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
