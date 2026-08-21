package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// waUser satisfies webauthn.User. The user handle is a random per-user blob,
// never the DB id, so nothing about the account leaks into authenticators.
type waUser struct {
	id     int64
	handle []byte
	name   string
	creds  []webauthn.Credential
}

func (u *waUser) WebAuthnID() []byte                         { return u.handle }
func (u *waUser) WebAuthnName() string                       { return u.name }
func (u *waUser) WebAuthnDisplayName() string                { return u.name }
func (u *waUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func newWebAuthn(origin string) (*webauthn.WebAuthn, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("invalid origin %q", origin)
	}
	return webauthn.New(&webauthn.Config{
		RPDisplayName: "Geheimniskrämer",
		RPID:          u.Hostname(),
		RPOrigins:     []string{origin},
	})
}

// ceremonyStore holds in-flight WebAuthn ceremony state server-side,
// referenced by an HttpOnly cookie. In-memory is fine: ceremonies are
// short-lived and a restart only aborts logins in progress.
type ceremonyStore struct {
	mu sync.Mutex
	m  map[string]ceremony
}

type ceremony struct {
	data    *webauthn.SessionData
	kind    string // "register", "login", "add", "recover"
	invite  string // invite token, registration only
	name    string // username, registration only
	handle  []byte // user handle, registration only
	userID  int64  // add/recover only
	expires time.Time
}

func newCeremonyStore() *ceremonyStore { return &ceremonyStore{m: make(map[string]ceremony)} }

func (c *ceremonyStore) put(w http.ResponseWriter, cer ceremony) {
	id := randToken(24)
	cer.expires = time.Now().Add(5 * time.Minute)
	c.mu.Lock()
	for k, v := range c.m { // opportunistic cleanup
		if time.Now().After(v.expires) {
			delete(c.m, k)
		}
	}
	c.m[id] = cer
	c.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: "gk_wa", Value: id, Path: "/api", MaxAge: 300,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
}

func (c *ceremonyStore) take(r *http.Request) (ceremony, bool) {
	ck, err := r.Cookie("gk_wa")
	if err != nil {
		return ceremony{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	cer, ok := c.m[ck.Value]
	delete(c.m, ck.Value)
	if !ok || time.Now().After(cer.expires) {
		return ceremony{}, false
	}
	return cer, true
}

func randToken(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// --- registration ---

func (s *server) handleRegisterBegin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var username string
	err := s.db.QueryRow(`SELECT username FROM invites WHERE token = ? AND expires_at > unixepoch()`,
		req.Token).Scan(&username)
	if err != nil {
		http.Error(w, "invalid or expired invite", http.StatusForbidden)
		return
	}
	handle := make([]byte, 32)
	rand.Read(handle)
	user := &waUser{handle: handle, name: username}
	options, session, err := s.wa.BeginRegistration(user,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		}),
	)
	if err != nil {
		http.Error(w, "registration setup failed", http.StatusInternalServerError)
		return
	}
	s.ceremonies.put(w, ceremony{data: session, kind: "register", invite: req.Token, name: username, handle: handle})
	writeJSON(w, http.StatusOK, options)
}

func (s *server) handleRegisterFinish(w http.ResponseWriter, r *http.Request) {
	cer, ok := s.ceremonies.take(r)
	if !ok || cer.kind != "register" {
		http.Error(w, "no registration in progress", http.StatusBadRequest)
		return
	}
	user := &waUser{handle: cer.handle, name: cer.name}
	cred, err := s.wa.FinishRegistration(user, *cer.data, r)
	if err != nil {
		http.Error(w, "registration failed", http.StatusBadRequest)
		return
	}
	credJSON, err := json.Marshal(cred)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	credID := base64.RawURLEncoding.EncodeToString(cred.ID)

	tx, err := s.db.Begin()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()
	// Consume the invite exactly once; a lost race means it was already used.
	res, err := tx.Exec(`DELETE FROM invites WHERE token = ? AND expires_at > unixepoch()`, cer.invite)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		http.Error(w, "invalid or expired invite", http.StatusForbidden)
		return
	}
	dbRes, err := tx.Exec(`INSERT INTO users (name, user_handle) VALUES (?, ?)`, cer.name, cer.handle)
	if err != nil {
		http.Error(w, "username already exists", http.StatusConflict)
		return
	}
	userID, _ := dbRes.LastInsertId()
	if _, err := tx.Exec(`INSERT INTO credentials (id, user_id, credential_data, wrapped_vault_key) VALUES (?, ?, ?, X'')`,
		credID, userID, credJSON); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := tx.Commit(); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.createSession(w, userID)
	writeJSON(w, http.StatusOK, map[string]string{"credentialId": credID, "username": cer.name})
}

// --- login ---

func (s *server) handleLoginBegin(w http.ResponseWriter, r *http.Request) {
	options, session, err := s.wa.BeginDiscoverableLogin(
		webauthn.WithUserVerification(protocol.VerificationRequired),
	)
	if err != nil {
		http.Error(w, "login setup failed", http.StatusInternalServerError)
		return
	}
	s.ceremonies.put(w, ceremony{data: session, kind: "login"})
	writeJSON(w, http.StatusOK, options)
}

func (s *server) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	cer, ok := s.ceremonies.take(r)
	if !ok || cer.kind != "login" {
		http.Error(w, "no login in progress", http.StatusBadRequest)
		return
	}
	var u *waUser
	lookup := func(rawID, userHandle []byte) (webauthn.User, error) {
		var err error
		u, err = s.userByHandle(userHandle)
		return u, err
	}
	cred, err := s.wa.FinishDiscoverableLogin(lookup, *cer.data, r)
	if err != nil {
		http.Error(w, "login failed", http.StatusUnauthorized)
		return
	}
	credID := base64.RawURLEncoding.EncodeToString(cred.ID)
	// Persist updated authenticator state (sign counter, clone warnings).
	if credJSON, err := json.Marshal(cred); err == nil {
		s.db.Exec(`UPDATE credentials SET credential_data = ? WHERE id = ? AND user_id = ?`, credJSON, credID, u.id)
	}
	var wrapped []byte
	if err := s.db.QueryRow(`SELECT wrapped_vault_key FROM credentials WHERE id = ? AND user_id = ?`,
		credID, u.id).Scan(&wrapped); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var hasEntries bool
	s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM entries WHERE user_id = ?)`, u.id).Scan(&hasEntries)
	s.createSession(w, u.id)
	resp := map[string]any{"username": u.name, "credentialId": credID, "wrappedVaultKey": nil, "hasEntries": hasEntries}
	if len(wrapped) > 0 {
		resp["wrappedVaultKey"] = base64.RawURLEncoding.EncodeToString(wrapped)
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *server) userByHandle(handle []byte) (*waUser, error) {
	u := &waUser{handle: handle}
	err := s.db.QueryRow(`SELECT id, name FROM users WHERE user_handle = ?`, handle).Scan(&u.id, &u.name)
	if err != nil {
		return nil, errors.New("unknown user")
	}
	rows, err := s.db.Query(`SELECT credential_data FROM credentials WHERE user_id = ?`, u.id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var c webauthn.Credential
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, err
		}
		u.creds = append(u.creds, c)
	}
	return u, rows.Err()
}

// handleSetVaultKey stores the client-wrapped vault key for a credential.
// Write-once: only an empty slot can be filled, so a hijacked session can
// never swap an existing wrapped key for one the attacker controls.
func (s *server) handleSetVaultKey(w http.ResponseWriter, r *http.Request, userID int64) {
	var req struct {
		CredentialID string `json:"credentialId"`
		Wrapped      string `json:"wrapped"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	wrapped, err := base64.RawURLEncoding.DecodeString(req.Wrapped)
	if err != nil || len(wrapped) < 28 { // 12B IV + 16B GCM tag minimum
		http.Error(w, "bad wrapped key", http.StatusBadRequest)
		return
	}
	res, err := s.db.Exec(`UPDATE credentials SET wrapped_vault_key = ?
		WHERE id = ? AND user_id = ? AND length(wrapped_vault_key) = 0`,
		wrapped, req.CredentialID, userID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		http.Error(w, "credential not found or key already set", http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
