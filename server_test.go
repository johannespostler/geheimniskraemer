package main

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestServer(t *testing.T) (*server, http.Handler) {
	t.Helper()
	db, err := openDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s, h, err := newServer(db, "https://localhost")
	if err != nil {
		t.Fatal(err)
	}
	return s, h
}

func seedUser(t *testing.T, db *sql.DB, name string) int64 {
	t.Helper()
	res, err := db.Exec(`INSERT INTO users (name, user_handle) VALUES (?, ?)`, name, []byte(name+"-handle"))
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	return id
}

func seedSession(t *testing.T, db *sql.DB, userID int64) string {
	t.Helper()
	id := randToken(32)
	if _, err := db.Exec(`INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)`,
		id, userID, time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	return id
}

func seedCredential(t *testing.T, db *sql.DB, userID int64, credID string, wrapped []byte) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO credentials (id, user_id, credential_data, wrapped_vault_key) VALUES (?, ?, '{}', ?)`,
		credID, userID, wrapped); err != nil {
		t.Fatal(err)
	}
}

// call sends a request with CSRF header (and session cookie if given) and
// returns the recorder.
func call(h http.Handler, method, path, session string, body any) *httptest.ResponseRecorder {
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("X-GK-CSRF", "1")
	req.Header.Set("Content-Type", "application/json")
	if session != "" {
		req.AddCookie(&http.Cookie{Name: "gk_session", Value: session})
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func wantStatus(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("status = %d, want %d; body: %s", w.Code, want, w.Body.String())
	}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// wrapped-key stand-in: 12B IV + 16B tag + 32B key = 60 bytes
func fakeWrapped(fill byte) []byte { return bytes.Repeat([]byte{fill}, 60) }

func TestMigrationsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.db")
	for i := 0; i < 2; i++ {
		db, err := openDB(path)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		db.Close()
	}
}

func TestSecurityHeaders(t *testing.T) {
	_, h := newTestServer(t)
	w := call(h, "GET", "/", "", nil)
	wantStatus(t, w, 200)
	for header, needle := range map[string]string{
		"Content-Security-Policy": "default-src 'none'",
		"X-Frame-Options":         "DENY",
		"Referrer-Policy":         "no-referrer",
		"X-Content-Type-Options":  "nosniff",
	} {
		if got := w.Header().Get(header); !strings.Contains(got, needle) {
			t.Errorf("%s = %q, want it to contain %q", header, got, needle)
		}
	}
}

func TestCSRFGuard(t *testing.T) {
	_, h := newTestServer(t)
	req := httptest.NewRequest("POST", "/api/login/begin", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	wantStatus(t, w, 403)
}

func TestSessionAuth(t *testing.T) {
	s, h := newTestServer(t)
	uid := seedUser(t, s.db, "alice")

	wantStatus(t, call(h, "GET", "/api/me", "", nil), 401)
	wantStatus(t, call(h, "GET", "/api/me", "bogus", nil), 401)

	expired := randToken(32)
	s.db.Exec(`INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)`,
		expired, uid, time.Now().Add(-time.Minute).Unix())
	wantStatus(t, call(h, "GET", "/api/me", expired, nil), 401)

	sess := seedSession(t, s.db, uid)
	w := call(h, "GET", "/api/me", sess, nil)
	wantStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), "alice") {
		t.Errorf("me = %s", w.Body.String())
	}
}

func TestLogoutDeletesSession(t *testing.T) {
	s, h := newTestServer(t)
	sess := seedSession(t, s.db, seedUser(t, s.db, "alice"))
	wantStatus(t, call(h, "POST", "/api/logout", sess, map[string]any{}), 204)
	wantStatus(t, call(h, "GET", "/api/me", sess, nil), 401)
}

func TestRegisterBeginInviteValidation(t *testing.T) {
	s, h := newTestServer(t)
	wantStatus(t, call(h, "POST", "/api/register/begin", "", map[string]string{"token": "nope"}), 403)

	s.db.Exec(`INSERT INTO invites (token, username, expires_at) VALUES ('expired', 'bob', ?)`,
		time.Now().Add(-time.Minute).Unix())
	wantStatus(t, call(h, "POST", "/api/register/begin", "", map[string]string{"token": "expired"}), 403)

	s.db.Exec(`INSERT INTO invites (token, username, expires_at) VALUES ('good', 'bob', ?)`,
		time.Now().Add(time.Hour).Unix())
	w := call(h, "POST", "/api/register/begin", "", map[string]string{"token": "good"})
	wantStatus(t, w, 200)
	var opts struct {
		PublicKey struct {
			RP   struct{ ID string }
			User struct{ Name string }
			AuthenticatorSelection struct {
				ResidentKey      string
				UserVerification string
			}
		}
	}
	if err := json.Unmarshal(w.Body.Bytes(), &opts); err != nil {
		t.Fatal(err)
	}
	if opts.PublicKey.RP.ID != "localhost" || opts.PublicKey.User.Name != "bob" {
		t.Errorf("options: %+v", opts.PublicKey)
	}
	if opts.PublicKey.AuthenticatorSelection.ResidentKey != "required" ||
		opts.PublicKey.AuthenticatorSelection.UserVerification != "required" {
		t.Errorf("authenticatorSelection: %+v", opts.PublicKey.AuthenticatorSelection)
	}
}

func TestFinishWithoutCeremony(t *testing.T) {
	_, h := newTestServer(t)
	wantStatus(t, call(h, "POST", "/api/register/finish", "", map[string]any{}), 400)
	wantStatus(t, call(h, "POST", "/api/login/finish", "", map[string]any{}), 400)
	wantStatus(t, call(h, "POST", "/api/recover/finish", "", map[string]any{}), 400)
}

func TestEntriesCRUDAndIsolation(t *testing.T) {
	s, h := newTestServer(t)
	alice := seedSession(t, s.db, seedUser(t, s.db, "alice"))
	bob := seedSession(t, s.db, seedUser(t, s.db, "bob"))
	id := "11111111-2222-3333-4444-555555555555"
	ct := b64(fakeWrapped(1))

	wantStatus(t, call(h, "PUT", "/api/entries/"+id, alice, map[string]string{"ciphertext": ct}), 204)

	w := call(h, "GET", "/api/entries", alice, nil)
	wantStatus(t, w, 200)
	var list []map[string]any
	json.Unmarshal(w.Body.Bytes(), &list)
	if len(list) != 1 || list[0]["id"] != id {
		t.Fatalf("list = %s", w.Body.String())
	}

	// isolation
	w = call(h, "GET", "/api/entries", bob, nil)
	if w.Body.String() != "[]\n" {
		t.Errorf("bob sees: %s", w.Body.String())
	}
	wantStatus(t, call(h, "PUT", "/api/entries/"+id, bob, map[string]string{"ciphertext": ct}), 409)
	wantStatus(t, call(h, "DELETE", "/api/entries/"+id, bob, nil), 404)

	// validation
	wantStatus(t, call(h, "PUT", "/api/entries/not-a-uuid", alice, map[string]string{"ciphertext": ct}), 400)
	wantStatus(t, call(h, "PUT", "/api/entries/"+id, alice, map[string]string{"ciphertext": "AAAA"}), 400)
	huge := b64(bytes.Repeat([]byte{1}, maxEntrySize+1))
	wantStatus(t, call(h, "PUT", "/api/entries/"+id, alice, map[string]string{"ciphertext": huge}), 400)

	// update + delete
	wantStatus(t, call(h, "PUT", "/api/entries/"+id, alice, map[string]string{"ciphertext": b64(fakeWrapped(2))}), 204)
	wantStatus(t, call(h, "DELETE", "/api/entries/"+id, alice, nil), 204)
	wantStatus(t, call(h, "DELETE", "/api/entries/"+id, alice, nil), 404)
}

func TestVaultKeyWriteOnce(t *testing.T) {
	s, h := newTestServer(t)
	uid := seedUser(t, s.db, "alice")
	sess := seedSession(t, s.db, uid)
	seedCredential(t, s.db, uid, "credA", []byte{})

	set := func(fill byte) *httptest.ResponseRecorder {
		return call(h, "POST", "/api/credentials/vault-key", sess,
			map[string]string{"credentialId": "credA", "wrapped": b64(fakeWrapped(fill))})
	}
	wantStatus(t, set(1), 204)
	wantStatus(t, set(2), 409) // already set — must never be replaceable

	var stored []byte
	s.db.QueryRow(`SELECT wrapped_vault_key FROM credentials WHERE id = 'credA'`).Scan(&stored)
	if !bytes.Equal(stored, fakeWrapped(1)) {
		t.Error("stored key was altered by second write")
	}

	// another user cannot fill someone else's empty slot either
	seedCredential(t, s.db, uid, "credB", []byte{})
	mallory := seedSession(t, s.db, seedUser(t, s.db, "mallory"))
	wantStatus(t, call(h, "POST", "/api/credentials/vault-key", mallory,
		map[string]string{"credentialId": "credB", "wrapped": b64(fakeWrapped(3))}), 409)
}

func TestCredentialDeleteLockoutGuard(t *testing.T) {
	s, h := newTestServer(t)
	uid := seedUser(t, s.db, "alice")
	sess := seedSession(t, s.db, uid)
	seedCredential(t, s.db, uid, "keyed", fakeWrapped(1))
	seedCredential(t, s.db, uid, "keyless", []byte{})

	del := func(id string) *httptest.ResponseRecorder {
		return call(h, "POST", "/api/credentials/delete", sess, map[string]string{"credentialId": id})
	}
	// deleting the keyless one is always fine
	wantStatus(t, del("keyless"), 204)
	// last keyed credential, no recovery → refused
	wantStatus(t, del("keyed"), 409)
	// with recovery set → allowed
	s.db.Exec(`UPDATE users SET recovery_verifier = X'01', recovery_wrapped_key = X'02' WHERE id = ?`, uid)
	wantStatus(t, del("keyed"), 204)
}

func TestCredentialRename(t *testing.T) {
	s, h := newTestServer(t)
	uid := seedUser(t, s.db, "alice")
	sess := seedSession(t, s.db, uid)
	seedCredential(t, s.db, uid, "credA", fakeWrapped(1))

	wantStatus(t, call(h, "POST", "/api/credentials/rename", sess,
		map[string]string{"credentialId": "credA", "name": "macbook"}), 204)
	wantStatus(t, call(h, "POST", "/api/credentials/rename", sess,
		map[string]string{"credentialId": "nope", "name": "x"}), 404)
	wantStatus(t, call(h, "POST", "/api/credentials/rename", sess,
		map[string]string{"credentialId": "credA", "name": strings.Repeat("x", 65)}), 400)

	// cross-user rename must not work
	mallory := seedSession(t, s.db, seedUser(t, s.db, "mallory"))
	wantStatus(t, call(h, "POST", "/api/credentials/rename", mallory,
		map[string]string{"credentialId": "credA", "name": "pwned"}), 404)
}

func TestRecoverBeginVerifier(t *testing.T) {
	s, h := newTestServer(t)
	uid := seedUser(t, s.db, "alice")
	verifier := bytes.Repeat([]byte{7}, 32)
	hash := sha256.Sum256(verifier)
	s.db.Exec(`UPDATE users SET recovery_verifier = ?, recovery_wrapped_key = ? WHERE id = ?`,
		hash[:], fakeWrapped(1), uid)

	begin := func(user, v string) *httptest.ResponseRecorder {
		return call(h, "POST", "/api/recover/begin", "", map[string]string{"username": user, "verifier": v})
	}
	wantStatus(t, begin("alice", b64(bytes.Repeat([]byte{8}, 32))), 403) // wrong code
	wantStatus(t, begin("mallory", b64(verifier)), 403)                  // unknown user
	w := begin("alice", b64(verifier))
	wantStatus(t, w, 200)
	if !strings.Contains(w.Body.String(), `"alice"`) {
		t.Errorf("options: %s", w.Body.String())
	}
}

func TestSetRecoveryValidation(t *testing.T) {
	s, h := newTestServer(t)
	sess := seedSession(t, s.db, seedUser(t, s.db, "alice"))
	set := func(vLen, wLen int) *httptest.ResponseRecorder {
		return call(h, "POST", "/api/recovery", sess, map[string]string{
			"verifier": b64(bytes.Repeat([]byte{1}, vLen)),
			"wrapped":  b64(bytes.Repeat([]byte{2}, wLen)),
		})
	}
	wantStatus(t, set(31, 60), 400) // verifier must be exactly 32 bytes
	wantStatus(t, set(32, 10), 400) // wrapped too short to be IV+tag
	wantStatus(t, set(32, 60), 204)
}

func TestCeremonyStoreSingleUse(t *testing.T) {
	cs := newCeremonyStore()
	w := httptest.NewRecorder()
	cs.put(w, ceremony{kind: "login"})
	cookie := w.Result().Cookies()[0]

	req := httptest.NewRequest("POST", "/api/login/finish", nil)
	req.AddCookie(cookie)
	if _, ok := cs.take(req); !ok {
		t.Fatal("first take failed")
	}
	if _, ok := cs.take(req); ok {
		t.Fatal("ceremony must be single-use")
	}
}

func TestListCredentials(t *testing.T) {
	s, h := newTestServer(t)
	uid := seedUser(t, s.db, "alice")
	sess := seedSession(t, s.db, uid)
	seedCredential(t, s.db, uid, "keyed", fakeWrapped(1))
	seedCredential(t, s.db, uid, "keyless", []byte{})

	w := call(h, "GET", "/api/credentials", sess, nil)
	wantStatus(t, w, 200)
	var resp struct {
		Credentials []struct {
			ID          string
			HasVaultKey bool
		}
		HasRecovery bool
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Credentials) != 2 || resp.HasRecovery {
		t.Fatalf("resp: %s", w.Body.String())
	}
	for _, c := range resp.Credentials {
		if want := c.ID == "keyed"; c.HasVaultKey != want {
			t.Errorf("cred %s hasVaultKey = %v", c.ID, c.HasVaultKey)
		}
	}
}

func TestInviteCommandRejectsExistingUser(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "gk.db")
	db, err := openDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	seedUser(t, db, "alice")
	db.Close()

	if err := cmdInvite([]string{"-db", dbPath, "alice"}); err == nil {
		t.Fatal("invite for existing user should fail")
	}
	if err := cmdInvite([]string{"-db", dbPath, "bob"}); err != nil {
		t.Fatalf("invite bob: %v", err)
	}
	db, _ = openDB(dbPath)
	defer db.Close()
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM invites WHERE username = 'bob'`).Scan(&n)
	if n != 1 {
		t.Fatalf("invites for bob = %d", n)
	}
}
