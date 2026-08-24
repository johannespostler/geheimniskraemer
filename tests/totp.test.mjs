// Unit tests for web/totp.js — run with: node --test tests/*.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";

const { parseTotp, totpCode, totpRemaining } = await import("../web/totp.js");

// RFC 6238 test key "12345678901234567890" in base32.
const RFC_KEY = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

test("RFC 6238 SHA-1 vectors (6-digit truncation)", async () => {
  // Appendix B values are 8-digit; the last 6 digits are the 6-digit code.
  assert.equal(await totpCode(RFC_KEY, 59_000), "287082");
  assert.equal(await totpCode(RFC_KEY, 1111111109_000), "081804");
  assert.equal(await totpCode(RFC_KEY, 20000000000_000), "353130");
});

test("otpauth URI parameters are honored", async () => {
  const uri = `otpauth://totp/Example:me?secret=${RFC_KEY}&digits=8&period=30`;
  assert.equal(await totpCode(uri, 59_000), "94287082");
  const { digits, period, hash } = parseTotp(uri);
  assert.deepEqual({ digits, period, hash }, { digits: 8, period: 30, hash: "SHA-1" });
});

test("bare base32 defaults to 6 digits / 30s / SHA-1", () => {
  const { digits, period, hash } = parseTotp(RFC_KEY);
  assert.deepEqual({ digits, period, hash }, { digits: 6, period: 30, hash: "SHA-1" });
});

test("tolerates spaces, dashes, padding, lowercase", async () => {
  const messy = "gezd gnbv-gy3t qojq=GEZDGNBVGY3TQOJQ==";
  assert.equal(await totpCode(messy, 59_000), "287082");
});

test("remaining seconds until rollover", () => {
  assert.equal(totpRemaining(RFC_KEY, 59_000), 1);
  assert.equal(totpRemaining(RFC_KEY, 60_000), 30);
});

test("rejects garbage secrets", () => {
  assert.throws(() => parseTotp("not!base32"), /base32/);
  assert.throws(() => parseTotp(""), /Empty/);
  assert.throws(() => parseTotp("otpauth://totp/x"), /Empty/);
});
