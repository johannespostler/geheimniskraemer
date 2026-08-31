package main

import (
	"encoding/base32"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// TOTP step-up for synced passkeys: a backup-eligible (BE=1) credential lives
// in a cloud sync fabric, so once the user has opted into TOTP, logins with
// such a credential must additionally present a code — unless the device has
// been remembered after a previous successful step-up. TOTP is opt-in and
// account-level: one secret per user, enrolled from settings.

const (
	trustCookie      = "gk_trust"
	trustSlidingTTL  = 60 * 24 * time.Hour  // extended on each use
	trustAbsoluteTTL = 180 * 24 * time.Hour // hard cap from created_at
)

// userTOTP returns the user's TOTP secret, or ok=false if not enrolled.
func (s *server) userTOTP(userID int64) (secret []byte, ok bool) {
	if err := s.db.QueryRow(`SELECT totp_secret FROM users WHERE id = ? AND totp_secret IS NOT NULL`,
		userID).Scan(&secret); err != nil {
		return nil, false
	}
	return secret, true
}

// checkTOTP runs the full verification for one submitted code: per-user
// attempt limit, ±1-step window, and the replay guard (a step is accepted at
// most once, atomically, so one code cannot be double-spent concurrently).
func (s *server) checkTOTP(userID int64, code string) (ok, limited bool) {
	if !s.totpRL.allow(fmt.Sprintf("totp:%d", userID)) {
		return false, true
	}
	secret, enrolled := s.userTOTP(userID)
	if !enrolled {
		return false, false
	}
	step, ok := verifyTOTP(secret, code, time.Now())
	if !ok {
		return false, false
	}
	res, err := s.db.Exec(`UPDATE users SET totp_last_step = ? WHERE id = ?
		AND (totp_last_step IS NULL OR totp_last_step < ?)`, step, userID, step)
	if err != nil {
		return false, false
	}
	n, _ := res.RowsAffected()
	return n == 1, false
}

// --- trusted devices ---

// isTrustedDevice reports whether the request carries a valid trust cookie
// for this user, and slides its expiry (bounded by the absolute cap). The
// extension only ever happens right after a fresh passkey assertion by the
// same user.
func (s *server) isTrustedDevice(r *http.Request, userID int64) bool {
	ck, err := r.Cookie(trustCookie)
	if err != nil {
		return false
	}
	id := hashToken(ck.Value)
	var createdAt int64
	if err := s.db.QueryRow(`SELECT created_at FROM trusted_devices
		WHERE id = ? AND user_id = ? AND expires_at > unixepoch()`, id, userID).Scan(&createdAt); err != nil {
		return false
	}
	expires := min(time.Now().Add(trustSlidingTTL).Unix(), createdAt+int64(trustAbsoluteTTL.Seconds()))
	s.db.Exec(`UPDATE trusted_devices SET last_seen = unixepoch(), expires_at = ? WHERE id = ?`, expires, id)
	return true
}

// mintTrustedDevice remembers this device after a successful TOTP: random
// token in the cookie, only its hash in the DB (same rule as sessions).
func (s *server) mintTrustedDevice(w http.ResponseWriter, r *http.Request, userID int64) {
	token := randToken(32)
	label := r.UserAgent()
	if len(label) > 120 {
		label = label[:120]
	}
	expires := time.Now().Add(trustSlidingTTL)
	if _, err := s.db.Exec(`INSERT INTO trusted_devices (id, user_id, label, expires_at) VALUES (?, ?, ?, ?)`,
		hashToken(token), userID, label, expires.Unix()); err != nil {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: trustCookie, Value: token, Path: "/api", MaxAge: int(trustAbsoluteTTL.Seconds()),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
}

func (s *server) handleListTrustedDevices(w http.ResponseWriter, r *http.Request, userID int64) {
	s.db.Exec(`DELETE FROM trusted_devices WHERE expires_at < unixepoch()`)
	rows, err := s.db.Query(`SELECT id, label, created_at, last_seen FROM trusted_devices
		WHERE user_id = ? ORDER BY last_seen DESC`, userID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type dev struct {
		ID        string `json:"id"` // token hash; safe to expose, useless to replay
		Label     string `json:"label"`
		CreatedAt int64  `json:"createdAt"`
		LastSeen  int64  `json:"lastSeen"`
	}
	list := []dev{}
	for rows.Next() {
		var d dev
		if err := rows.Scan(&d.ID, &d.Label, &d.CreatedAt, &d.LastSeen); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		list = append(list, d)
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *server) handleDeleteTrustedDevice(w http.ResponseWriter, r *http.Request, userID int64) {
	var req struct {
		ID  string `json:"id"`
		All bool   `json:"all"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || (!req.All && req.ID == "") {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.All {
		s.db.Exec(`DELETE FROM trusted_devices WHERE user_id = ?`, userID)
	} else {
		s.db.Exec(`DELETE FROM trusted_devices WHERE id = ? AND user_id = ?`, req.ID, userID)
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- login step-up ---

// handleLoginTOTP completes a login that was paused for TOTP. The pending
// state lives in the ceremony store (single-use, 5-min TTL); on a wrong code
// it is re-put with a fresh cookie so one typo doesn't force a full
// re-authentication.
func (s *server) handleLoginTOTP(w http.ResponseWriter, r *http.Request) {
	cer, ok := s.ceremonies.take(r)
	if !ok || cer.kind != "totp" {
		http.Error(w, "no login in progress", http.StatusBadRequest)
		return
	}
	var req struct {
		Code  string `json:"code"`
		Trust bool   `json:"trust"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ok, limited := s.checkTOTP(cer.userID, req.Code)
	if !ok {
		s.ceremonies.put(w, ceremony{kind: "totp", userID: cer.userID, credID: cer.credID, name: cer.name})
		if limited {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "too many attempts — wait a minute", http.StatusTooManyRequests)
			return
		}
		http.Error(w, "wrong code", http.StatusUnauthorized)
		return
	}
	if req.Trust {
		s.mintTrustedDevice(w, r, cer.userID)
	}
	s.finishLogin(w, cer.userID, cer.credID, cer.name)
}

// --- enrollment (opt-in, authenticated, from settings) ---

func (s *server) handleTOTPEnrollBegin(w http.ResponseWriter, r *http.Request, userID int64) {
	if _, enrolled := s.userTOTP(userID); enrolled {
		http.Error(w, "TOTP already enabled", http.StatusConflict)
		return
	}
	var name string
	if err := s.db.QueryRow(`SELECT name FROM users WHERE id = ?`, userID).Scan(&name); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	secret := randBytes(20)
	s.ceremonies.put(w, ceremony{kind: "totp-enroll", userID: userID, secret: secret})
	writeJSON(w, http.StatusOK, map[string]string{
		"secret":  base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret),
		"otpauth": otpauthURL("Geheimniskrämer", name, secret),
	})
}

func (s *server) handleTOTPEnrollFinish(w http.ResponseWriter, r *http.Request, userID int64) {
	cer, ok := s.ceremonies.take(r)
	if !ok || cer.kind != "totp-enroll" || cer.userID != userID {
		http.Error(w, "no enrollment in progress", http.StatusBadRequest)
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !s.totpRL.allow(fmt.Sprintf("totp:%d", userID)) {
		http.Error(w, "too many attempts — wait a minute", http.StatusTooManyRequests)
		return
	}
	step, ok := verifyTOTP(cer.secret, req.Code, time.Now())
	if !ok {
		// Same secret, fresh cookie: the user can retype without rescanning.
		s.ceremonies.put(w, ceremony{kind: "totp-enroll", userID: userID, secret: cer.secret})
		http.Error(w, "wrong code — try again", http.StatusForbidden)
		return
	}
	// Write-once: enabling is only possible when no secret is set; rotation
	// is disable (code-gated) + re-enroll.
	res, err := s.db.Exec(`UPDATE users SET totp_secret = ?, totp_last_step = ? WHERE id = ? AND totp_secret IS NULL`,
		cer.secret, step, userID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		http.Error(w, "TOTP already enabled", http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleTOTPDisable turns TOTP off again. Gated on a current code — a
// hijacked session alone must not be able to strip the step-up — and drops
// all device trust, which only exists as a TOTP shortcut.
func (s *server) handleTOTPDisable(w http.ResponseWriter, r *http.Request, userID int64) {
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ok, limited := s.checkTOTP(userID, req.Code)
	if limited {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many attempts — wait a minute", http.StatusTooManyRequests)
		return
	}
	if !ok {
		http.Error(w, "wrong code", http.StatusForbidden)
		return
	}
	s.db.Exec(`UPDATE users SET totp_secret = NULL, totp_last_step = NULL WHERE id = ?`, userID)
	s.db.Exec(`DELETE FROM trusted_devices WHERE user_id = ?`, userID)
	http.SetCookie(w, &http.Cookie{
		Name: trustCookie, Value: "", Path: "/api", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	w.WriteHeader(http.StatusNoContent)
}
