package main

import (
	"database/sql"
	"fmt"
	"strings"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS users (
	id                   INTEGER PRIMARY KEY,
	name                 TEXT NOT NULL UNIQUE,
	user_handle          BLOB NOT NULL UNIQUE, -- random WebAuthn user handle, returned by discoverable credentials
	recovery_verifier    BLOB,                 -- SHA-256 of the client-derived recovery verifier
	recovery_wrapped_key BLOB,                 -- vault key wrapped by the recovery-code KEK
	created_at           INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS sessions (
	id         TEXT PRIMARY KEY,
	user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
	id                TEXT PRIMARY KEY, -- base64url credential ID
	user_id           INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	credential_data   BLOB NOT NULL,    -- serialized webauthn.Credential
	wrapped_vault_key BLOB NOT NULL,    -- vault key wrapped by this passkey's PRF-derived KEK
	name              TEXT NOT NULL DEFAULT '',
	created_at        INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS entries (
	id         TEXT PRIMARY KEY, -- client-generated UUID
	user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	ciphertext BLOB NOT NULL,    -- AES-GCM encrypted entry JSON; opaque to the server
	updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);
CREATE INDEX IF NOT EXISTS entries_user ON entries(user_id);

CREATE TABLE IF NOT EXISTS invites (
	token      TEXT PRIMARY KEY,
	username   TEXT NOT NULL,
	expires_at INTEGER NOT NULL
);
`

func openDB(path string) (*sql.DB, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	// Additive migrations for databases created before these columns existed.
	for _, alter := range []string{
		`ALTER TABLE users ADD COLUMN recovery_verifier BLOB`,
		`ALTER TABLE users ADD COLUMN recovery_wrapped_key BLOB`,
	} {
		if _, err := db.Exec(alter); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
			db.Close()
			return nil, fmt.Errorf("migrate: %w", err)
		}
	}
	return db, nil
}
