package main

import (
	"database/sql"
	"embed"
	"encoding/json"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

//go:embed web
var webFS embed.FS

type server struct {
	db         *sql.DB
	origin     string // external origin, e.g. https://vault.example.com
	wa         *webauthn.WebAuthn
	ceremonies *ceremonyStore
}

func cmdServe(args []string) error {
	fl := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := fl.String("listen", "127.0.0.1:8087", "listen address (keep local; put Caddy in front)")
	dbPath := fl.String("db", "gk.db", "path to SQLite database")
	origin := fl.String("origin", "https://localhost", "external origin as seen by browsers (WebAuthn RP origin)")
	fl.Parse(args)

	db, err := openDB(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	_, handler, err := newServer(db, *origin)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              *listen,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	log.Printf("gk: listening on http://%s (origin %s, db %s)", *listen, *origin, *dbPath)
	return srv.ListenAndServe()
}

func newServer(db *sql.DB, origin string) (*server, http.Handler, error) {
	wa, err := newWebAuthn(origin)
	if err != nil {
		return nil, nil, err
	}
	s := &server{db: db, origin: origin, wa: wa, ceremonies: newCeremonyStore()}

	static, err := fs.Sub(webFS, "web")
	if err != nil {
		return nil, nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServerFS(static))
	mux.HandleFunc("GET /api/health", s.handleHealth)
	mux.HandleFunc("POST /api/register/begin", s.handleRegisterBegin)
	mux.HandleFunc("POST /api/register/finish", s.handleRegisterFinish)
	mux.HandleFunc("POST /api/login/begin", s.handleLoginBegin)
	mux.HandleFunc("POST /api/login/finish", s.handleLoginFinish)
	mux.HandleFunc("POST /api/logout", s.handleLogout)
	mux.HandleFunc("GET /api/me", s.requireAuth(s.handleMe))
	mux.HandleFunc("POST /api/credentials/vault-key", s.requireAuth(s.handleSetVaultKey))
	mux.HandleFunc("GET /api/credentials", s.requireAuth(s.handleListCredentials))
	mux.HandleFunc("POST /api/credentials/add/begin", s.requireAuth(s.handleAddCredBegin))
	mux.HandleFunc("POST /api/credentials/add/finish", s.requireAuth(s.handleAddCredFinish))
	mux.HandleFunc("POST /api/credentials/rename", s.requireAuth(s.handleRenameCredential))
	mux.HandleFunc("POST /api/credentials/delete", s.requireAuth(s.handleDeleteCredential))
	mux.HandleFunc("POST /api/recovery", s.requireAuth(s.handleSetRecovery))
	mux.HandleFunc("POST /api/recover/begin", s.handleRecoverBegin)
	mux.HandleFunc("POST /api/recover/finish", s.handleRecoverFinish)
	mux.HandleFunc("GET /api/entries", s.requireAuth(s.handleListEntries))
	mux.HandleFunc("PUT /api/entries/{id}", s.requireAuth(s.handlePutEntry))
	mux.HandleFunc("DELETE /api/entries/{id}", s.requireAuth(s.handleDeleteEntry))

	return s, securityHeaders(csrfGuard(mux)), nil
}

// securityHeaders applies the strict defaults from the plan. TLS/HSTS is
// Caddy's job; everything content-related is set here so the app is safe
// even behind a differently-configured proxy.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy",
			"default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "+
				"connect-src 'self'; manifest-src 'self'; worker-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if err := s.db.Ping(); err != nil {
		http.Error(w, "db unavailable", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("gk: write response: %v", err)
	}
}
