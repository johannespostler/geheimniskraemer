// Round-trip: encode with our minimal encoder, decode with a real QR decoder
// (jsqr, dev-only). Covers small and large payloads (several QR versions,
// including v7+ which needs the version-info block) and non-ASCII.
import { test } from "node:test";
import assert from "node:assert/strict";
import jsQR from "jsqr";
import { qrMatrix } from "../web/qr.js";

function decode(matrix) {
  const scale = 4, quiet = 4;
  const px = (matrix.length + 2 * quiet) * scale;
  const rgba = new Uint8ClampedArray(px * px * 4).fill(255);
  for (let r = 0; r < matrix.length; r++) {
    for (let c = 0; c < matrix.length; c++) {
      if (!matrix[r][c]) continue;
      for (let dy = 0; dy < scale; dy++) {
        for (let dx = 0; dx < scale; dx++) {
          const i = (((quiet + r) * scale + dy) * px + (quiet + c) * scale + dx) * 4;
          rgba[i] = rgba[i + 1] = rgba[i + 2] = 0;
        }
      }
    }
  }
  return jsQR(rgba, px, px)?.data;
}

test("qr round-trips an otpauth URI with non-ASCII issuer", () => {
  const uri = "otpauth://totp/Geheimniskr%C3%A4mer:alice?issuer=Geheimniskr%C3%A4mer"
    + "&secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  assert.equal(decode(qrMatrix(uri)), uri);
});

test("qr round-trips across versions", () => {
  for (const len of [1, 17, 18, 60, 100, 150, 200, 250, 271]) {
    const text = "x".repeat(len);
    const m = qrMatrix(text);
    assert.equal(decode(m), text, `len ${len} (size ${m.length})`);
  }
});

test("qr rejects oversized input", () => {
  assert.throws(() => qrMatrix("x".repeat(272)));
});
