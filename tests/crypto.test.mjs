// Unit tests for web/crypto.js — run with: node --test tests/
import { test } from "node:test";
import assert from "node:assert/strict";

const m = await import("../web/crypto.js");

test("base64url roundtrip", () => {
  const bytes = crypto.getRandomValues(new Uint8Array(33));
  assert.deepEqual(m.b64uDecode(m.b64u(bytes)), bytes);
  assert.ok(!/[+/=]/.test(m.b64u(bytes)), "must be URL-safe without padding");
});

test("recovery code format and roundtrip", () => {
  const code = m.generateRecoveryCode();
  assert.match(code, /^([a-z2-7]{4}-){7}[a-z2-7]{4}$/);
  const bytes = m.parseRecoveryCode(code);
  assert.equal(bytes.length, 20);
  // parsing is forgiving about case, separators, whitespace
  const mangled = " " + code.toUpperCase().replaceAll("-", " / ") + " ";
  assert.deepEqual(m.parseRecoveryCode(mangled), bytes);
});

test("recovery code parse rejects wrong length", () => {
  assert.throws(() => m.parseRecoveryCode("abcd-efgh"));
  assert.throws(() => m.parseRecoveryCode(""));
});

test("recovery codes are unique", () => {
  assert.notEqual(m.generateRecoveryCode(), m.generateRecoveryCode());
});

test("verifier is deterministic and 32 bytes", async () => {
  const bytes = m.parseRecoveryCode(m.generateRecoveryCode());
  const v1 = await m.deriveRecoveryVerifier(bytes);
  const v2 = await m.deriveRecoveryVerifier(bytes);
  assert.equal(v1.length, 32);
  assert.deepEqual(v1, v2);
});

test("different codes yield different verifiers", async () => {
  const v1 = await m.deriveRecoveryVerifier(m.parseRecoveryCode(m.generateRecoveryCode()));
  const v2 = await m.deriveRecoveryVerifier(m.parseRecoveryCode(m.generateRecoveryCode()));
  assert.notDeepEqual(v1, v2);
});

test("PRF-derived KEK wraps and unwraps the vault key", async () => {
  const prfOutput = crypto.getRandomValues(new Uint8Array(32));
  const raw = m.generateRawVaultKey();
  const wrapped = await m.wrapRawVaultKey(await m.deriveKEK(prfOutput), raw);
  // a second KEK derivation from the same PRF output must unwrap it
  const vk = await m.unwrapVaultKey(await m.deriveKEK(prfOutput), wrapped);
  const back = await m.decryptEntry(vk, await m.encryptEntry(vk, { ok: true }));
  assert.equal(back.ok, true);
});

test("wrong KEK cannot unwrap", async () => {
  const raw = m.generateRawVaultKey();
  const kek = await m.deriveKEK(crypto.getRandomValues(new Uint8Array(32)));
  const wrongKek = await m.deriveKEK(crypto.getRandomValues(new Uint8Array(32)));
  const wrapped = await m.wrapRawVaultKey(kek, raw);
  await assert.rejects(m.unwrapVaultKey(wrongKek, wrapped));
});

test("recovery KEK differs from verifier derivation", async () => {
  // Same code, independent HKDF infos: knowing the verifier must not equal
  // or reveal KEK material. We can't extract the KEK, but we can check the
  // verifier doesn't decrypt what the KEK wrapped.
  const bytes = m.parseRecoveryCode(m.generateRecoveryCode());
  const kek = await m.deriveRecoveryKEK(bytes);
  const wrapped = await m.wrapRawVaultKey(kek, m.generateRawVaultKey());
  const verifier = await m.deriveRecoveryVerifier(bytes);
  const verifierAsKek = await m.deriveKEK(verifier);
  await assert.rejects(m.unwrapVaultKey(verifierAsKek, wrapped));
});

test("extractable unwrap allows rewrapping for a second KEK", async () => {
  // the add-passkey / recovery path
  const kekA = await m.deriveKEK(crypto.getRandomValues(new Uint8Array(32)));
  const kekB = await m.deriveKEK(crypto.getRandomValues(new Uint8Array(32)));
  const raw = m.generateRawVaultKey();
  const wrappedA = await m.wrapRawVaultKey(kekA, raw);

  const vkExtractable = await m.unwrapVaultKey(kekA, wrappedA, true);
  const wrappedB = await m.wrapVaultKey(kekB, vkExtractable);
  const vkB = await m.unwrapVaultKey(kekB, wrappedB);

  const ct = await m.encryptEntry(vkB, { password: "hunter2" });
  const vkA = await m.unwrapVaultKey(kekA, wrappedA);
  assert.equal((await m.decryptEntry(vkA, ct)).password, "hunter2");
});

test("entry encryption roundtrip with unicode", async () => {
  const kek = await m.deriveKEK(crypto.getRandomValues(new Uint8Array(32)));
  const vk = await m.unwrapVaultKey(kek, await m.wrapRawVaultKey(kek, m.generateRawVaultKey()));
  const data = { name: "Geheimniskrämer 🤫", password: "päßwörd", notes: "a\nb" };
  assert.deepEqual(await m.decryptEntry(vk, await m.encryptEntry(vk, data)), data);
});

test("entry IVs are unique per encryption", async () => {
  const kek = await m.deriveKEK(crypto.getRandomValues(new Uint8Array(32)));
  const vk = await m.unwrapVaultKey(kek, await m.wrapRawVaultKey(kek, m.generateRawVaultKey()));
  const a = await m.encryptEntry(vk, { x: 1 });
  const b = await m.encryptEntry(vk, { x: 1 });
  assert.notDeepEqual(a.slice(0, 12), b.slice(0, 12));
});

test("tampered ciphertext fails to decrypt", async () => {
  const kek = await m.deriveKEK(crypto.getRandomValues(new Uint8Array(32)));
  const vk = await m.unwrapVaultKey(kek, await m.wrapRawVaultKey(kek, m.generateRawVaultKey()));
  const ct = await m.encryptEntry(vk, { x: 1 });
  ct[ct.length - 1] ^= 1;
  await assert.rejects(m.decryptEntry(vk, ct));
});
