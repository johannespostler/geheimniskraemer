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
    username: "hans", password: "s3cret", notes: "work account",
  }]);
});

test("extra URIs and TOTP land in notes, nothing lost", () => {
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
  assert.match(entries[0].notes, /TOTP: otpauth/);
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
  assert.deepEqual(entries, [{ name: "wifi", website: "", username: "", password: "", notes: "pw: 1234" }]);
  assert.deepEqual(skipped, { card: 2, identity: 1 });
});

test("tolerates missing login fields", () => {
  const { entries } = mapBitwarden({ items: [{ type: 1, name: "bare" }] });
  assert.deepEqual(entries, [{ name: "bare", website: "", username: "", password: "", notes: "" }]);
});
