package main

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"time"
)

const sessionTTL = 12 * time.Hour

// hashToken is what we persist for bearer tokens (session ids): the cookie
// carries the raw token, the DB stores only its SHA-256. A read of the DB
// (leaked backup, stray copy) then yields no usable session cookies.
func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// __Host- prefix: the browser only accepts the cookie over TLS, without a
// Domain attribute, with Path=/ — pinning it to exactly our origin.
const sessionCookie = "__Host-gk_session"

func (s *server) createSession(w http.ResponseWriter, userID int64) {
	token := randToken(32)
	expires := time.Now().Add(sessionTTL)
	if _, err := s.db.Exec(`INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)`,
		hashToken(token), userID, expires.Unix()); err != nil {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/", Expires: expires,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
}

// requireAuth wraps API handlers that need a logged-in user.
func (s *server) requireAuth(next func(http.ResponseWriter, *http.Request, int64)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ck, err := r.Cookie(sessionCookie)
		if err != nil {
			http.Error(w, "not authenticated", http.StatusUnauthorized)
			return
		}
		var userID int64
		err = s.db.QueryRow(`SELECT user_id FROM sessions WHERE id = ? AND expires_at > unixepoch()`,
			hashToken(ck.Value)).Scan(&userID)
		if err != nil {
			http.Error(w, "not authenticated", http.StatusUnauthorized)
			return
		}
		next(w, r, userID)
	}
}

func (s *server) handleMe(w http.ResponseWriter, r *http.Request, userID int64) {
	var name string
	if err := s.db.QueryRow(`SELECT name FROM users WHERE id = ?`, userID).Scan(&name); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"username": name})
}

func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if ck, err := r.Cookie(sessionCookie); err == nil {
		s.db.Exec(`DELETE FROM sessions WHERE id = ?`, hashToken(ck.Value))
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	w.WriteHeader(http.StatusNoContent)
}

// csrfGuard rejects mutating /api requests without the custom header.
// SameSite=Strict already blocks cross-site cookie sends; the header check
// covers older browsers and non-cookie-bearing forged requests.
func csrfGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Header.Get("X-GK-CSRF") == "" {
			http.Error(w, "missing CSRF header", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
