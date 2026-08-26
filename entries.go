package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"regexp"
)

// Entry ciphertext is opaque to the server: IV || AES-GCM(entry JSON).
// IDs are client-generated UUIDs so encryption never blocks on the server.

var entryIDRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

const maxEntrySize = 64 * 1024

// Per-user quota: bounds an authenticated (or compromised) account's ability
// to exhaust the disk backing the SQLite file. Generous for a personal vault.
const maxEntriesPerUser = 1000

func (s *server) handleListEntries(w http.ResponseWriter, r *http.Request, userID int64) {
	rows, err := s.db.Query(`SELECT id, ciphertext, updated_at FROM entries WHERE user_id = ?`, userID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type entry struct {
		ID         string `json:"id"`
		Ciphertext string `json:"ciphertext"`
		UpdatedAt  int64  `json:"updatedAt"`
	}
	list := []entry{}
	for rows.Next() {
		var e entry
		var ct []byte
		if err := rows.Scan(&e.ID, &ct, &e.UpdatedAt); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		e.Ciphertext = base64.RawURLEncoding.EncodeToString(ct)
		list = append(list, e)
	}
	if rows.Err() != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *server) handlePutEntry(w http.ResponseWriter, r *http.Request, userID int64) {
	id := r.PathValue("id")
	if !entryIDRe.MatchString(id) {
		http.Error(w, "bad entry id", http.StatusBadRequest)
		return
	}
	var req struct {
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxEntrySize*2)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ct, err := base64.RawURLEncoding.DecodeString(req.Ciphertext)
	if err != nil || len(ct) < 28 || len(ct) > maxEntrySize { // 12B IV + 16B GCM tag minimum
		http.Error(w, "bad ciphertext", http.StatusBadRequest)
		return
	}
	// Enforce the per-user quota, but only for genuinely new entries so that
	// updating an existing one never trips the limit. Concurrent creates can
	// overshoot slightly; that's an acceptable soft cap, not a hard bound.
	var exists bool
	s.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM entries WHERE id = ? AND user_id = ?)`, id, userID).Scan(&exists)
	if !exists {
		var count int
		s.db.QueryRow(`SELECT COUNT(*) FROM entries WHERE user_id = ?`, userID).Scan(&count)
		if count >= maxEntriesPerUser {
			http.Error(w, "entry limit reached", http.StatusInsufficientStorage)
			return
		}
	}
	// Upsert scoped to the user: an id owned by someone else must not be
	// touched, so the conflict-update re-checks user_id.
	res, err := s.db.Exec(`INSERT INTO entries (id, user_id, ciphertext, updated_at)
		VALUES (?, ?, ?, unixepoch())
		ON CONFLICT(id) DO UPDATE SET ciphertext = excluded.ciphertext, updated_at = unixepoch()
		WHERE entries.user_id = excluded.user_id`, id, userID, ct)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		http.Error(w, "conflict", http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleDeleteEntry(w http.ResponseWriter, r *http.Request, userID int64) {
	res, err := s.db.Exec(`DELETE FROM entries WHERE id = ? AND user_id = ?`, r.PathValue("id"), userID)
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
