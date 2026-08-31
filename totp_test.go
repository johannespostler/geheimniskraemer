package main

import (
	"testing"
	"time"
)

// RFC 6238 Appendix B vectors (SHA-1, secret "12345678901234567890"). The
// appendix lists 8-digit codes; the 6-digit code is the same value mod 10^6,
// i.e. the last six digits.
func TestTOTPVectors(t *testing.T) {
	secret := []byte("12345678901234567890")
	for _, tc := range []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	} {
		if got := hotp(secret, uint64(tc.unix/totpStep)); got != tc.want {
			t.Errorf("t=%d: code = %s, want %s", tc.unix, got, tc.want)
		}
	}
}

func TestVerifyTOTPSkew(t *testing.T) {
	secret := []byte("12345678901234567890")
	now := time.Unix(1111111111, 0) // step 37037037
	cur := hotp(secret, 37037037)
	prev := hotp(secret, 37037036)
	next := hotp(secret, 37037038)
	far := hotp(secret, 37037039)

	for code, want := range map[string]bool{cur: true, prev: true, next: true, far: false, "000000": false, "12345": false} {
		if _, ok := verifyTOTP(secret, code, now); ok != want {
			t.Errorf("verify(%s) = %v, want %v", code, ok, want)
		}
	}
	if step, ok := verifyTOTP(secret, prev, now); !ok || step != 37037036 {
		t.Errorf("prev step = %d, %v", step, ok)
	}
}

func TestOtpauthURL(t *testing.T) {
	u := otpauthURL("Geheimniskrämer", "alice", []byte("12345678901234567890"))
	want := "otpauth://totp/Geheimniskr%C3%A4mer:alice?issuer=Geheimniskr%C3%A4mer&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	if u != want {
		t.Errorf("url = %s\nwant %s", u, want)
	}
}
