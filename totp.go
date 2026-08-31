package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"time"
)

// RFC 6238 TOTP: HMAC-SHA1, 6 digits, 30-second steps. Implemented in-house
// to keep the dependency set minimal; verified against the RFC's Appendix B
// vectors in totp_test.go.

const totpStep = 30 // seconds
const totpDigits = 6

// hotp computes the RFC 4226 code for one counter value.
func hotp(secret []byte, counter uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", totpDigits, bin%1_000_000)
}

// verifyTOTP checks code against the ±1-step skew window around now and
// returns the matching step. Constant-time digit comparison; replay
// protection (step must exceed the last accepted one) is the caller's job —
// it needs the DB.
func verifyTOTP(secret []byte, code string, now time.Time) (step int64, ok bool) {
	if len(code) != totpDigits {
		return 0, false
	}
	cur := now.Unix() / totpStep
	for _, s := range []int64{cur, cur - 1, cur + 1} {
		if s < 0 {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(hotp(secret, uint64(s))), []byte(code)) == 1 {
			return s, true
		}
	}
	return 0, false
}

// decodeB32 decodes an unpadded base32 TOTP secret (the wire form).
func decodeB32(s string) ([]byte, error) {
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
}

// otpauthURL builds the enrollment URI. Non-ASCII in issuer/label ("ä") is
// legal as percent-encoded UTF-8 — Aegis and friends decode it correctly.
func otpauthURL(issuer, account string, secret []byte) string {
	b32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
	q := url.Values{"secret": {b32}, "issuer": {issuer}}
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?" + q.Encode()
}
