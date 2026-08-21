package main

import (
	"flag"
	"fmt"
	"time"
)

func cmdInvite(args []string) error {
	fl := flag.NewFlagSet("invite", flag.ExitOnError)
	dbPath := fl.String("db", "gk.db", "path to SQLite database")
	origin := fl.String("origin", "https://localhost", "external origin, used to print the invite URL")
	ttl := fl.Duration("ttl", 24*time.Hour, "invite validity")
	fl.Parse(args)
	if fl.NArg() != 1 {
		return fmt.Errorf("usage: gk invite [-db path] [-origin url] [-ttl dur] <username>")
	}
	username := fl.Arg(0)

	db, err := openDB(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	var exists int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users WHERE name = ?`, username).Scan(&exists); err != nil {
		return err
	}
	if exists > 0 {
		return fmt.Errorf("user %q already exists", username)
	}
	token := randToken(32)
	if _, err := db.Exec(`INSERT INTO invites (token, username, expires_at) VALUES (?, ?, ?)`,
		token, username, time.Now().Add(*ttl).Unix()); err != nil {
		return err
	}
	fmt.Printf("invite for %q (valid %s):\n%s/?invite=%s\n", username, ttl, *origin, token)
	return nil
}
