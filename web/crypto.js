// @ts-check
// All vault cryptography. The server only ever sees the outputs of wrap().

const enc = new TextEncoder();

// Fixed PRF salt: the PRF output must be identical on every login, so the
// same KEK can always unwrap this credential's copy of the vault key.
export const PRF_SALT = enc.encode("geheimniskraemer/prf/v1");
const HKDF_INFO = enc.encode("geheimniskraemer/kek/v1");

export function b64u(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

export function b64uDecode(s) {
  const bin = atob(s.replaceAll("-", "+").replaceAll("_", "/"));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

// PRF output → non-extractable AES key-encryption-key.
export async function deriveKEK(prfOutput) {
  const ikm = await crypto.subtle.importKey("raw", prfOutput, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: HKDF_INFO },
    ikm, { name: "AES-GCM", length: 256 }, false, ["wrapKey", "unwrapKey"]);
}

// Wrap an extractable vault CryptoKey under a KEK. Returns IV || ciphertext+tag.
export async function wrapVaultKey(kek, vk) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrapped = new Uint8Array(await crypto.subtle.wrapKey("raw", vk, kek, { name: "AES-GCM", iv }));
  const out = new Uint8Array(12 + wrapped.length);
  out.set(iv);
  out.set(wrapped, 12);
  return out;
}

// Wrap raw vault-key bytes. Only used at vault creation; the raw bytes are
// zeroed by the caller immediately after.
export async function wrapRawVaultKey(kek, rawVK) {
  const tmp = await crypto.subtle.importKey("raw", rawVK, "AES-GCM", true, ["encrypt", "decrypt"]);
  return wrapVaultKey(kek, tmp);
}

// Unwrap to a CryptoKey. Non-extractable by default: the session's vault key
// can encrypt/decrypt entries but its bytes are unreadable even to our own
// JS. extractable=true is used transiently only when wrapping for a new passkey.
export async function unwrapVaultKey(kek, blob, extractable = false) {
  const iv = blob.slice(0, 12);
  const data = blob.slice(12);
  return crypto.subtle.unwrapKey("raw", data, kek, { name: "AES-GCM", iv },
    { name: "AES-GCM", length: 256 }, extractable, ["encrypt", "decrypt"]);
}

export function generateRawVaultKey() {
  return crypto.getRandomValues(new Uint8Array(32));
}

// --- recovery code: 160 random bits, base32, shown to the user exactly once.
// KEK and verifier are derived independently (different HKDF infos), so the
// verifier sent to the server reveals nothing about the KEK.

const B32 = "abcdefghijklmnopqrstuvwxyz234567";

export function generateRecoveryCode() {
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  let bits = 0, acc = 0, out = "";
  for (const b of bytes) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += B32[(acc >> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  return out.replace(/(.{4})(?=.)/g, "$1-"); // xxxx-xxxx-… for readability
}

export function parseRecoveryCode(str) {
  const clean = str.toLowerCase().replace(/[^a-z2-7]/g, "");
  if (clean.length !== 32) throw new Error("A recovery code has 32 letters/digits.");
  const bytes = new Uint8Array(20);
  let bits = 0, acc = 0, i = 0;
  for (const c of clean) {
    acc = (acc << 5) | B32.indexOf(c);
    bits += 5;
    if (bits >= 8) {
      bytes[i++] = (acc >> (bits - 8)) & 0xff;
      bits -= 8;
    }
  }
  return bytes;
}

async function hkdfFromCode(codeBytes) {
  return crypto.subtle.importKey("raw", codeBytes, "HKDF", false, ["deriveKey", "deriveBits"]);
}

export async function deriveRecoveryKEK(codeBytes) {
  const ikm = await hkdfFromCode(codeBytes);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: enc.encode("geheimniskraemer/recovery-kek/v1") },
    ikm, { name: "AES-GCM", length: 256 }, false, ["wrapKey", "unwrapKey"]);
}

export async function deriveRecoveryVerifier(codeBytes) {
  const ikm = await hkdfFromCode(codeBytes);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: enc.encode("geheimniskraemer/recovery-verifier/v1") },
    ikm, 256);
  return new Uint8Array(bits);
}

// Entry payloads: AES-GCM with a fresh IV each write, IV || ciphertext.
export async function encryptEntry(vaultKey, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv }, vaultKey, enc.encode(JSON.stringify(obj))));
  const out = new Uint8Array(12 + ct.length);
  out.set(iv);
  out.set(ct, 12);
  return out;
}

export async function decryptEntry(vaultKey, blob) {
  const iv = blob.slice(0, 12);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, vaultKey, blob.slice(12));
  return JSON.parse(new TextDecoder().decode(pt));
}
