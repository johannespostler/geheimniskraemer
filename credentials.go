package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

func (s *server) userByID(id int64) (*waUser, error) {
	u := &waUser{id: id}
	if err := s.db.QueryRow(`SELECT name, user_handle FROM users WHERE id = ?`, id).Scan(&u.name, &u.handle); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(`SELECT credential_data FROM credentials WHERE user_id = ?`, id)
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

func exclusions(creds []webauthn.Credential) []protocol.CredentialDescriptor {
	out := make([]protocol.CredentialDescriptor, len(creds))
	for i, c := range creds {
		out[i] = protocol.CredentialDescriptor{Type: protocol.PublicKeyCredentialType, CredentialID: c.ID}
	}
	return out
}

// --- passkey management (authenticated) ---

func (s *server) handleListCredentials(w http.ResponseWriter, r *http.Request, userID int64) {
	rows, err := s.db.Query(`SELECT id, name, created_at, length(wrapped_vault_key) > 0, credential_data
		FROM credentials WHERE user_id = ? ORDER BY created_at`, userID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type cred struct {
		ID             string `json:"id"`
		Name           string `json:"name"`
		CreatedAt      int64  `json:"createdAt"`
		HasVaultKey    bool   `json:"hasVaultKey"`
		BackupEligible bool   `json:"backupEligible"` // synced passkey (BE flag)
	}
	list := []cred{}
	for rows.Next() {
		var c cred
		var raw []byte
		if err := rows.Scan(&c.ID, &c.Name, &c.CreatedAt, &c.HasVaultKey, &raw); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		var wc webauthn.Credential
		if json.Unmarshal(raw, &wc) == nil {
			c.BackupEligible = wc.Flags.BackupEligible
		}
		list = append(list, c)
	}
	var hasRecovery bool
	s.db.QueryRow(`SELECT recovery_wrapped_key IS NOT NULL FROM users WHERE id = ?`, userID).Scan(&hasRecovery)
	_, totpEnabled := s.userTOTP(userID)
	writeJSON(w, http.StatusOK, map[string]any{"credentials": list, "hasRecovery": hasRecovery, "totpEnabled": totpEnabled})
}

func (s *server) handleAddCredBegin(w http.ResponseWriter, r *http.Request, userID int64) {
	u, err := s.userByID(userID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	options, session, err := s.wa.BeginRegistration(u,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		}),
		webauthn.WithExclusions(exclusions(u.creds)),
	)
	if err != nil {
		http.Error(w, "registration setup failed", http.StatusInternalServerError)
		return
	}
	s.ceremonies.put(w, ceremony{data: session, kind: "add", userID: userID})
	writeJSON(w, http.StatusOK, options)
}

func (s *server) handleAddCredFinish(w http.ResponseWriter, r *http.Request, userID int64) {
	cer, ok := s.ceremonies.take(r)
	if !ok || cer.kind != "add" || cer.userID != userID {
		http.Error(w, "no passkey registration in progress", http.StatusBadRequest)
		return
	}
	u, err := s.userByID(userID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	cred, err := s.wa.FinishRegistration(u, *cer.data, r)
	if err != nil {
		http.Error(w, "registration failed", http.StatusBadRequest)
		return
	}
	// Planting a synced passkey grants vault access from a cloud account — a
	// hijacked session must not be enough for that on a TOTP-enrolled
	// account. The code rides in a header because the body is the WebAuthn
	// attestation, parsed by the library.
	if cred.Flags.BackupEligible {
		if _, enrolled := s.userTOTP(userID); enrolled {
			ok, limited := s.checkTOTP(userID, r.Header.Get("X-GK-TOTP"))
			if limited {
				w.Header().Set("Retry-After", "60")
				http.Error(w, "too many attempts — wait a minute", http.StatusTooManyRequests)
				return
			}
			if !ok {
				http.Error(w, "adding a synced passkey requires a valid TOTP code", http.StatusForbidden)
				return
			}
		}
	}
	credJSON, _ := json.Marshal(cred)
	credID := base64.RawURLEncoding.EncodeToString(cred.ID)
	if _, err := s.db.Exec(`INSERT INTO credentials (id, user_id, credential_data, wrapped_vault_key) VALUES (?, ?, ?, X'')`,
		credID, userID, credJSON); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"credentialId": credID})
}

func (s *server) handleRenameCredential(w http.ResponseWriter, r *http.Request, userID int64) {
	var req struct {
		CredentialID string `json:"credentialId"`
		Name         string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || len(req.Name) > 64 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	res, err := s.db.Exec(`UPDATE credentials SET name = ? WHERE id = ? AND user_id = ?`,
		req.Name, req.CredentialID, userID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleDeleteCredential(w http.ResponseWriter, r *http.Request, userID int64) {
	var req struct {
		CredentialID string `json:"credentialId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// Refuse to delete the last credential that can still unwrap the vault,
	// unless a recovery code exists — otherwise the vault is lost forever.
	var targetHasKey bool
	if err := s.db.QueryRow(`SELECT length(wrapped_vault_key) > 0 FROM credentials WHERE id = ? AND user_id = ?`,
		req.CredentialID, userID).Scan(&targetHasKey); err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if targetHasKey {
		var others int
		var hasRecovery bool
		s.db.QueryRow(`SELECT COUNT(*) FROM credentials WHERE user_id = ? AND id != ? AND length(wrapped_vault_key) > 0`,
			userID, req.CredentialID).Scan(&others)
		s.db.QueryRow(`SELECT recovery_wrapped_key IS NOT NULL FROM users WHERE id = ?`, userID).Scan(&hasRecovery)
		if others == 0 && !hasRecovery {
			http.Error(w, "this is the only way into your vault; add another passkey or a recovery code first", http.StatusConflict)
			return
		}
	}
	s.db.Exec(`DELETE FROM credentials WHERE id = ? AND user_id = ?`, req.CredentialID, userID)
	w.WriteHeader(http.StatusNoContent)
}

// --- recovery code ---

// handleSetRecovery stores (or replaces) the recovery data. The server keeps
// only a hash of the client-derived verifier and the wrapped vault key; the
// recovery code itself never leaves the browser.
func (s *server) handleSetRecovery(w http.ResponseWriter, r *http.Request, userID int64) {
	var req struct {
		Verifier string `json:"verifier"`
		Wrapped  string `json:"wrapped"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	verifier, err1 := base64.RawURLEncoding.DecodeString(req.Verifier)
	wrapped, err2 := base64.RawURLEncoding.DecodeString(req.Wrapped)
	if err1 != nil || err2 != nil || len(verifier) != 32 || len(wrapped) < 28 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	hash := sha256.Sum256(verifier)
	if _, err := s.db.Exec(`UPDATE users SET recovery_verifier = ?, recovery_wrapped_key = ? WHERE id = ?`,
		hash[:], wrapped, userID); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleRecoverBegin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Verifier string `json:"verifier"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	verifier, err := base64.RawURLEncoding.DecodeString(req.Verifier)
	// The reason is logged server-side only; the client always gets the same
	// generic 403 so recovery can't be used to probe for accounts.
	deny := func(reason string) {
		log.Printf("gk: recovery denied for %q: %s", req.Username, reason)
		time.Sleep(500 * time.Millisecond) // blunt brute-force damper
		http.Error(w, "recovery failed — check the username and make sure you use the most recent recovery code", http.StatusForbidden)
	}
	if err != nil {
		deny("malformed verifier")
		return
	}
	var userID int64
	var stored []byte
	if err := s.db.QueryRow(`SELECT id, recovery_verifier FROM users WHERE name = ? COLLATE NOCASE AND recovery_verifier IS NOT NULL`,
		req.Username).Scan(&userID, &stored); err != nil {
		deny("no such user or no recovery code set")
		return
	}
	hash := sha256.Sum256(verifier)
	if subtle.ConstantTimeCompare(hash[:], stored) != 1 {
		deny("verifier mismatch (wrong or outdated code)")
		return
	}
	u, err := s.userByID(userID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	options, session, err := s.wa.BeginRegistration(u,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		}),
		webauthn.WithExclusions(exclusions(u.creds)),
	)
	if err != nil {
		http.Error(w, "registration setup failed", http.StatusInternalServerError)
		return
	}
	s.ceremonies.put(w, ceremony{data: session, kind: "recover", userID: userID})
	writeJSON(w, http.StatusOK, options)
}

func (s *server) handleRecoverFinish(w http.ResponseWriter, r *http.Request) {
	cer, ok := s.ceremonies.take(r)
	if !ok || cer.kind != "recover" {
		http.Error(w, "no recovery in progress", http.StatusBadRequest)
		return
	}
	u, err := s.userByID(cer.userID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	cred, err := s.wa.FinishRegistration(u, *cer.data, r)
	if err != nil {
		http.Error(w, "registration failed", http.StatusBadRequest)
		return
	}
	credJSON, _ := json.Marshal(cred)
	credID := base64.RawURLEncoding.EncodeToString(cred.ID)
	if _, err := s.db.Exec(`INSERT INTO credentials (id, user_id, credential_data, wrapped_vault_key) VALUES (?, ?, ?, X'')`,
		credID, cer.userID, credJSON); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var recoveryWrapped []byte
	s.db.QueryRow(`SELECT recovery_wrapped_key FROM users WHERE id = ?`, cer.userID).Scan(&recoveryWrapped)
	s.createSession(w, cer.userID)
	writeJSON(w, http.StatusOK, map[string]string{
		"credentialId":       credID,
		"username":           u.name,
		"recoveryWrappedKey": base64.RawURLEncoding.EncodeToString(recoveryWrapped),
	})
}
