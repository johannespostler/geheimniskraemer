// Unit tests for web/import.js — run with: node --test tests/*.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";

const { mapBitwarden } = await import("../web/import.js");

test("rejects encrypted exports", () => {
  assert.throws(() => mapBitwarden({ encrypted: true, items: [] }), /unencrypted/);
});

test("rejects non-bitwarden JSON", () => {
  assert.throws(() => mapBitwarden({ foo: 1 }), /items/);
  assert.throws(() => mapBitwarden(null), /items/);
});

test("maps a login item", () => {
  const { entries, skipped } = mapBitwarden({
    items: [{
      type: 1, name: "GitHub", notes: "work account",
      login: { uris: [{ uri: "https://github.com" }], username: "hans", password: "s3cret" },
    }],
  });
  assert.deepEqual(skipped, {});
  assert.deepEqual(entries, [{
    name: "GitHub", website: "https://github.com",
    username: "hans", password: "s3cret", totp: "", notes: "work account",
  }]);
});

test("extra URIs land in notes, TOTP in its own field", () => {
  const { entries } = mapBitwarden({
    items: [{
      type: 1, name: "X",
      login: {
        uris: [{ uri: "https://a.example" }, { uri: "https://b.example" }],
        username: "u", password: "p", totp: "otpauth://totp/x?secret=ABC",
      },
    }],
  });
  assert.equal(entries[0].website, "https://a.example");
  assert.match(entries[0].notes, /https:\/\/b\.example/);
  assert.equal(entries[0].totp, "otpauth://totp/x?secret=ABC");
});

test("lifts a legacy 'TOTP: …' notes line into the totp field", () => {
  const { entries } = mapBitwarden({
    items: [
      { type: 1, name: "A", notes: "keep this\n\nTOTP: otpauth://totp/a?secret=ABC\n\nand this", login: {} },
      // login.totp wins; the notes line is left alone in that case
      { type: 1, name: "B", notes: "TOTP: JBSWY3DP", login: { totp: "OTHER234" } },
    ],
  });
  assert.equal(entries[0].totp, "otpauth://totp/a?secret=ABC");
  assert.equal(entries[0].notes, "keep this\n\nand this");
  assert.equal(entries[1].totp, "OTHER234");
  assert.equal(entries[1].notes, "TOTP: JBSWY3DP");
});

test("maps secure notes, counts unsupported types", () => {
  const { entries, skipped } = mapBitwarden({
    items: [
      { type: 2, name: "wifi", notes: "pw: 1234", secureNote: {} },
      { type: 3, name: "visa" },
      { type: 3, name: "amex" },
      { type: 4, name: "me" },
    ],
  });
  assert.deepEqual(entries, [{ name: "wifi", website: "", username: "", password: "", totp: "", notes: "pw: 1234" }]);
  assert.deepEqual(skipped, { card: 2, identity: 1 });
});

test("tolerates missing login fields", () => {
  const { entries } = mapBitwarden({ items: [{ type: 1, name: "bare" }] });
  assert.deepEqual(entries, [{ name: "bare", website: "", username: "", password: "", totp: "", notes: "" }]);
});
