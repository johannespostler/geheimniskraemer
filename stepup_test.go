package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// pendingTOTP plants a paused login in the ceremony store and returns the
// ceremony cookie, as handleLoginFinish would after a BE=1 assertion.
func pendingTOTP(t *testing.T, s *server, userID int64, credID, name string) *http.Cookie {
	t.Helper()
	w := httptest.NewRecorder()
	s.ceremonies.put(w, ceremony{kind: "totp", userID: userID, credID: credID, name: name})
	for _, ck := range w.Result().Cookies() {
		if ck.Name == "gk_wa" {
			return ck
		}
	}
	t.Fatal("no ceremony cookie")
	return nil
}

func callWithCookies(h http.Handler, method, path string, body any, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path, bytes.NewReader(b))
	req.Header.Set("X-GK-CSRF", "1")
	req.Header.Set("Content-Type", "application/json")
	for _, ck := range cookies {
		if ck != nil {
			req.AddCookie(ck)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func cookieNamed(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, ck := range w.Result().Cookies() {
		if ck.Name == name && ck.Value != "" {
			return ck
		}
	}
	return nil
}

func enrollTOTP(t *testing.T, s *server, userID int64, secret []byte) {
	t.Helper()
	if _, err := s.db.Exec(`UPDATE users SET totp_secret = ? WHERE id = ?`, secret, userID); err != nil {
		t.Fatal(err)
	}
}

func currentCode(secret []byte) string {
	return hotp(secret, uint64(time.Now().Unix()/totpStep))
}

func TestLoginTOTPFlow(t *testing.T) {
	s, h := newTestServer(t)
	uid := seedUser(t, s.db, "alice")
	seedCredential(t, s.db, uid, "credA", fakeWrapped(1))
	secret := []byte("12345678901234567890")
	enrollTOTP(t, s, uid, secret)

	// no pending ceremony
	wantStatus(t, callWithCookies(h, "POST", "/api/login/totp", map[string]any{"code": currentCode(secret)}), 400)

	// wrong code: 401, no session cookie, retryable via the re-put ceremony
	ck := pendingTOTP(t, s, uid, "credA", "alice")
	w := callWithCookies(h, "POST", "/api/login/totp", map[string]any{"code": "000000"}, ck)
	wantStatus(t, w, 401)
	if cookieNamed(w, sessionCookie) != nil {
		t.Fatal("wrong code must not create a session")
	}
	retry := cookieNamed(w, "gk_wa")
	if retry == nil {
		t.Fatal("wrong code must re-put the pending ceremony")
	}

	// right code on the retry ceremony: full login payload + session
	code := currentCode(secret)
	w = callWithCookies(h, "POST", "/api/login/totp", map[string]any{"code": code}, retry)
	wantStatus(t, w, 200)
	if cookieNamed(w, sessionCookie) == nil {
		t.Fatal("no session cookie after valid TOTP")
	}
	var resp struct {
		Username        string
		WrappedVaultKey string
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Username != "alice" || resp.WrappedVaultKey == "" {
		t.Fatalf("resp: %s", w.Body.String())
	}

	// the accepted step must not be spendable twice (replay guard)
	ck2 := pendingTOTP(t, s, uid, "credA", "alice")
	wantStatus(t, callWithCookies(h, "POST", "/api/login/totp", map[string]any{"code": code}, ck2), 401)
}

func TestLoginTOTPPerUserLimiter(t *testing.T) {
	s, h := newTestServer(t)
	uid := seedUser(t, s.db, "alice")
	seedCredential(t, s.db, uid, "credA", fakeWrapped(1))
	enrollTOTP(t, s, uid, []byte("12345678901234567890"))

	var last int
	for i := 0; i < 6; i++ {
		ck := pendingTOTP(t, s, uid, "credA", "alice")
		last = callWithCookies(h, "POST", "/api/login/totp", map[string]any{"code": "000000"}, ck).Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("6th attempt = %d, want 429", last)
	}
}

func TestTrustedDevice(t *testing.T) {
	s, h := newTestServer(t)
	uid := seedUser(t, s.db, "alice")
	seedCredential(t, s.db, uid, "credA", fakeWrapped(1))
	secret := []byte("12345678901234567890")
	enrollTOTP(t, s, uid, secret)

	// trust=true on a successful TOTP mints the cookie, stored hash-only
	ck := pendingTOTP(t, s, uid, "credA", "alice")
	w := callWithCookies(h, "POST", "/api/login/totp", map[string]any{"code": currentCode(secret), "trust": true}, ck)
	wantStatus(t, w, 200)
	trust := cookieNamed(w, trustCookie)
	if trust == nil {
		t.Fatal("no trust cookie minted")
	}
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM trusted_devices WHERE id = ?`, trust.Value).Scan(&n)
	if n != 0 {
		t.Fatal("raw trust token must never be stored")
	}
	s.db.QueryRow(`SELECT COUNT(*) FROM trusted_devices WHERE id = ? AND user_id = ?`, hashToken(trust.Value), uid).Scan(&n)
	if n != 1 {
		t.Fatal("trusted device row missing")
	}

	req := httptest.NewRequest("POST", "/api/login/finish", nil)
	req.AddCookie(trust)
	if !s.isTrustedDevice(req, uid) {
		t.Fatal("valid trust cookie not accepted")
	}
	if bob := seedUser(t, s.db, "bob"); s.isTrustedDevice(req, bob) {
		t.Fatal("trust must be bound to the user")
	}

	// expired row ⇒ TOTP again
	s.db.Exec(`UPDATE trusted_devices SET expires_at = unixepoch() - 1 WHERE user_id = ?`, uid)
	if s.isTrustedDevice(req, uid) {
		t.Fatal("expired trust accepted")
	}

	// sliding extension never passes created_at + absolute cap
	created := time.Now().Add(-179 * 24 * time.Hour).Unix()
	s.db.Exec(`UPDATE trusted_devices SET created_at = ?, expires_at = unixepoch() + 60 WHERE user_id = ?`, created, uid)
	if !s.isTrustedDevice(req, uid) {
		t.Fatal("valid old trust rejected")
	}
	var exp int64
	s.db.QueryRow(`SELECT expires_at FROM trusted_devices WHERE user_id = ?`, uid).Scan(&exp)
	if cap := created + int64(trustAbsoluteTTL.Seconds()); exp != cap {
		t.Fatalf("expires_at = %d, want absolute cap %d", exp, cap)
	}
}

func TestTrustedDeviceManagement(t *testing.T) {
	s, h := newTestServer(t)
	uid := seedUser(t, s.db, "alice")
	sess := seedSession(t, s.db, uid)
	s.db.Exec(`INSERT INTO trusted_devices (id, user_id, label, expires_at) VALUES ('d1', ?, 'laptop', unixepoch()+100)`, uid)
	s.db.Exec(`INSERT INTO trusted_devices (id, user_id, label, expires_at) VALUES ('gone', ?, 'old', unixepoch()-1)`, uid)
	mallory := seedSession(t, s.db, seedUser(t, s.db, "mallory"))

	w := call(h, "GET", "/api/trusted-devices", sess, nil)
	wantStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), "laptop") || strings.Contains(w.Body.String(), "old") {
		t.Fatalf("list = %s", w.Body.String())
	}

	// cross-user delete is a silent no-op on someone else's row
	wantStatus(t, call(h, "POST", "/api/trusted-devices/delete", mallory, map[string]any{"id": "d1"}), 204)
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM trusted_devices WHERE id = 'd1'`).Scan(&n)
	if n != 1 {
		t.Fatal("cross-user delete removed the row")
	}
	wantStatus(t, call(h, "POST", "/api/trusted-devices/delete", sess, map[string]any{"all": true}), 204)
	s.db.QueryRow(`SELECT COUNT(*) FROM trusted_devices WHERE user_id = ?`, uid).Scan(&n)
	if n != 0 {
		t.Fatal("revoke all left rows behind")
	}
}

func TestTOTPEnrollment(t *testing.T) {
	s, h := newTestServer(t)
	uid := seedUser(t, s.db, "alice")
	sess := seedSession(t, s.db, uid)

	w := call(h, "POST", "/api/totp/enroll/begin", sess, map[string]any{})
	wantStatus(t, w, 200)
	var begin struct{ Secret, Otpauth string }
	json.Unmarshal(w.Body.Bytes(), &begin)
	if begin.Secret == "" || !strings.HasPrefix(begin.Otpauth, "otpauth://totp/Geheimniskr%C3%A4mer:alice?") {
		t.Fatalf("begin = %s", w.Body.String())
	}
	ck := cookieNamed(w, "gk_wa")

	// wrong code: rejected, secret not persisted, retry cookie issued
	sessCk := &http.Cookie{Name: sessionCookie, Value: sess}
	// 403, not 401 — the client treats a 401 while unlocked as session expiry
	w = callWithCookies(h, "POST", "/api/totp/enroll/finish", map[string]any{"code": "000000"}, ck, sessCk)
	wantStatus(t, w, 403)
	if _, enrolled := s.userTOTP(uid); enrolled {
		t.Fatal("wrong code must not enroll")
	}
	ck = cookieNamed(w, "gk_wa")

	// the client cannot know the raw secret bytes; recover them from the DB-
	// free path: decode the returned base32
	secret := mustB32(t, begin.Secret)
	w = callWithCookies(h, "POST", "/api/totp/enroll/finish", map[string]any{"code": currentCode(secret)}, ck, sessCk)
	wantStatus(t, w, 204)
	if _, enrolled := s.userTOTP(uid); !enrolled {
		t.Fatal("not enrolled after valid code")
	}

	// enrolled ⇒ begin refuses (write-once; rotation = disable + re-enroll)
	wantStatus(t, call(h, "POST", "/api/totp/enroll/begin", sess, map[string]any{}), 409)

	// disable: wrong code refused, right code wipes secret and device trust
	s.db.Exec(`INSERT INTO trusted_devices (id, user_id, expires_at) VALUES ('d1', ?, unixepoch()+100)`, uid)
	wantStatus(t, call(h, "POST", "/api/totp/disable", sess, map[string]any{"code": "000000"}), 403)
	// use the next step's code: the enroll/verify above already spent this one
	next := hotp(secret, uint64(time.Now().Unix()/totpStep)+1)
	wantStatus(t, call(h, "POST", "/api/totp/disable", sess, map[string]any{"code": next}), 204)
	if _, enrolled := s.userTOTP(uid); enrolled {
		t.Fatal("still enrolled after disable")
	}
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM trusted_devices WHERE user_id = ?`, uid).Scan(&n)
	if n != 0 {
		t.Fatal("disable must revoke trusted devices")
	}
}

func mustB32(t *testing.T, s string) []byte {
	t.Helper()
	secret, err := decodeB32(s)
	if err != nil {
		t.Fatal(err)
	}
	return secret
}

func TestListCredentialsTOTPFields(t *testing.T) {
	s, h := newTestServer(t)
	uid := seedUser(t, s.db, "alice")
	sess := seedSession(t, s.db, uid)
	s.db.Exec(`INSERT INTO credentials (id, user_id, credential_data, wrapped_vault_key)
		VALUES ('synced', ?, '{"flags":{"backupEligible":true}}', X'01')`, uid)
	seedCredential(t, s.db, uid, "bound", fakeWrapped(1))

	w := call(h, "GET", "/api/credentials", sess, nil)
	wantStatus(t, w, 200)
	var resp struct {
		Credentials []struct {
			ID             string
			BackupEligible bool
		}
		TOTPEnabled bool `json:"totpEnabled"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.TOTPEnabled {
		t.Fatal("totpEnabled should be false before enrollment")
	}
	for _, c := range resp.Credentials {
		if want := c.ID == "synced"; c.BackupEligible != want {
			t.Errorf("cred %s backupEligible = %v", c.ID, c.BackupEligible)
		}
	}
	enrollTOTP(t, s, uid, []byte("12345678901234567890"))
	w = call(h, "GET", "/api/credentials", sess, nil)
	json.Unmarshal(w.Body.Bytes(), &resp)
	if !resp.TOTPEnabled {
		t.Fatal("totpEnabled should be true after enrollment")
	}
}
