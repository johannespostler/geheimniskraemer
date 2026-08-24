// @ts-check
// TOTP (RFC 6238) from an otpauth:// URI or a bare base32 secret.
// Pure WebCrypto, no I/O — works in the browser and under node --test.

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Decode(s) {
  s = s.toUpperCase().replace(/[\s=-]/g, "");
  if (!s) throw new Error("Empty TOTP secret.");
  let bits = 0, value = 0;
  const out = [];
  for (const ch of s) {
    const idx = B32.indexOf(ch);
    if (idx === -1) throw new Error("Not a valid base32 TOTP secret.");
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return new Uint8Array(out);
}

const HASHES = { SHA1: "SHA-1", SHA256: "SHA-256", SHA512: "SHA-512" };

// Accepts an otpauth://totp/… URI or a bare base32 secret.
export function parseTotp(input) {
  let secret = (input || "").trim(), digits = 6, period = 30, hash = "SHA-1";
  if (/^otpauth:/i.test(secret)) {
    const p = new URL(secret).searchParams;
    secret = p.get("secret") || "";
    digits = Math.min(10, +(p.get("digits") || 0)) || 6;
    period = +(p.get("period") || 0) || 30;
    hash = HASHES[(p.get("algorithm") || "SHA1").toUpperCase()] || "SHA-1";
  }
  return { key: base32Decode(secret), digits, period, hash };
}

export async function totpCode(input, nowMs = Date.now()) {
  const { key, digits, period, hash } = parseTotp(input);
  const msg = new Uint8Array(8);
  new DataView(msg.buffer).setBigUint64(0, BigInt(Math.floor(nowMs / 1000 / period)));
  const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", k, msg));
  const off = mac[mac.length - 1] & 0x0f;
  const bin = ((mac[off] & 0x7f) << 24) | (mac[off + 1] << 16) | (mac[off + 2] << 8) | mac[off + 3];
  return String(bin % 10 ** digits).padStart(digits, "0");
}

// Seconds until the current code rolls over.
export function totpRemaining(input, nowMs = Date.now()) {
  const { period } = parseTotp(input);
  return period - (Math.floor(nowMs / 1000) % period);
}
