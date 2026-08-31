// @ts-check
// Minimal QR encoder for the TOTP enrollment screen: byte mode, error
// correction level L, versions 1-10 (plenty for an otpauth:// URI). No
// dependencies; returns a boolean matrix. Verified against a real decoder
// in tests/qr.test.mjs.

// GF(256) tables for Reed-Solomon, polynomial 0x11d.
const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);
{
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) GF_EXP[i] = GF_EXP[i - 255];
}
const gmul = (a, b) => (a && b ? GF_EXP[GF_LOG[a] + GF_LOG[b]] : 0);

function rsRemainder(data, ecLen) {
  let gen = [1];
  for (let i = 0; i < ecLen; i++) {
    const next = new Array(gen.length + 1).fill(0);
    for (let j = 0; j < gen.length; j++) {
      next[j] ^= gen[j];
      next[j + 1] ^= gmul(gen[j], GF_EXP[i]);
    }
    gen = next;
  }
  const res = [...data, ...new Array(ecLen).fill(0)];
  for (let i = 0; i < data.length; i++) {
    const f = res[i];
    if (f === 0) continue;
    for (let j = 0; j < gen.length; j++) res[i + j] ^= gmul(gen[j], f);
  }
  return res.slice(data.length);
}

// Per version (level L): EC codewords per block, data codewords per block.
const VERSIONS = [
  [7, [19]], [10, [34]], [15, [55]], [20, [80]], [26, [108]],
  [18, [68, 68]], [20, [78, 78]], [24, [97, 97]], [30, [116, 116]],
  [18, [68, 68, 69, 69]],
];
const ALIGN = [
  [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34],
  [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50],
];

// BCH remainder of value (already shifted) modulo poly, for format/version info.
function bchRemainder(value, poly) {
  const deg = 31 - Math.clz32(poly);
  let v = value;
  while (31 - Math.clz32(v) >= deg && v !== 0) v ^= poly << (31 - Math.clz32(v) - deg);
  return v;
}

const MASKS = [
  (i, j) => (i + j) % 2 === 0,
  (i, _j) => i % 2 === 0,
  (_i, j) => j % 3 === 0,
  (i, j) => (i + j) % 3 === 0,
  (i, j) => (Math.floor(i / 2) + Math.floor(j / 3)) % 2 === 0,
  (i, j) => ((i * j) % 2) + ((i * j) % 3) === 0,
  (i, j) => (((i * j) % 2) + ((i * j) % 3)) % 2 === 0,
  (i, j) => (((i + j) % 2) + ((i * j) % 3)) % 2 === 0,
];

// Standard penalty score (ISO 18004 §8.8.2) used to pick the mask.
function penalty(t) {
  const size = t.length;
  let p = 0;
  for (let i = 0; i < size; i++) {
    let runR = 1, runC = 1;
    for (let j = 1; j < size; j++) {
      if (t[i][j] === t[i][j - 1]) runR++;
      else { if (runR >= 5) p += runR - 2; runR = 1; }
      if (t[j][i] === t[j - 1][i]) runC++;
      else { if (runC >= 5) p += runC - 2; runC = 1; }
    }
    if (runR >= 5) p += runR - 2;
    if (runC >= 5) p += runC - 2;
  }
  for (let i = 0; i < size - 1; i++) {
    for (let j = 0; j < size - 1; j++) {
      const v = t[i][j];
      if (v === t[i][j + 1] && v === t[i + 1][j] && v === t[i + 1][j + 1]) p += 3;
    }
  }
  const bad = [[1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0], [0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1]];
  for (let i = 0; i < size; i++) {
    for (let j = 0; j + 11 <= size; j++) {
      for (const pat of bad) {
        if (pat.every((v, k) => t[i][j + k] === v)) p += 40;
        if (pat.every((v, k) => t[j + k][i] === v)) p += 40;
      }
    }
  }
  let dark = 0;
  for (const row of t) for (const v of row) dark += v;
  p += Math.floor(Math.abs((dark * 100) / (size * size) - 50) / 5) * 10;
  return p;
}

// Encodes text; returns a size×size matrix of 0/1 (1 = dark module).
export function qrMatrix(text) {
  const bytes = new TextEncoder().encode(text);
  let ver = 0, dataLen = 0;
  for (let v = 1; v <= VERSIONS.length; v++) {
    dataLen = VERSIONS[v - 1][1].reduce((a, b) => a + b, 0);
    if (4 + (v <= 9 ? 8 : 16) + bytes.length * 8 <= dataLen * 8) { ver = v; break; }
  }
  if (!ver) throw new Error("Text too long for a QR code.");

  // --- data codewords: mode + count + bytes, terminator, byte padding
  const bits = [];
  const push = (val, len) => { for (let i = len - 1; i >= 0; i--) bits.push((val >> i) & 1); };
  push(4, 4); // byte mode
  push(bytes.length, ver <= 9 ? 8 : 16);
  for (const b of bytes) push(b, 8);
  push(0, Math.min(4, dataLen * 8 - bits.length));
  while (bits.length % 8) bits.push(0);
  const cw = [];
  for (let i = 0; i < bits.length; i += 8) {
    let b = 0;
    for (let j = 0; j < 8; j++) b = (b << 1) | bits[i + j];
    cw.push(b);
  }
  for (let pad = 0xec; cw.length < dataLen; pad ^= 0xfd) cw.push(pad);

  // --- split into blocks, compute EC, interleave
  const [ecLen, blockLens] = VERSIONS[ver - 1];
  const blocks = [], ecs = [];
  let off = 0;
  for (const len of blockLens) {
    const d = cw.slice(off, off + len);
    off += len;
    blocks.push(d);
    ecs.push(rsRemainder(d, ecLen));
  }
  const out = [];
  for (let i = 0; i < Math.max(...blockLens); i++) for (const b of blocks) if (i < b.length) out.push(b[i]);
  for (let i = 0; i < ecLen; i++) for (const e of ecs) out.push(e[i]);

  // --- function patterns
  const size = 17 + 4 * ver;
  const m = Array.from({ length: size }, () => new Int8Array(size).fill(-1));
  const func = Array.from({ length: size }, () => new Uint8Array(size));
  const set = (r, c, v) => { m[r][c] = v ? 1 : 0; func[r][c] = 1; };

  const finder = (r0, c0) => {
    for (let dr = -1; dr <= 7; dr++) {
      for (let dc = -1; dc <= 7; dc++) {
        const r = r0 + dr, c = c0 + dc;
        if (r < 0 || r >= size || c < 0 || c >= size) continue;
        const inRing = dr >= 0 && dr <= 6 && dc >= 0 && dc <= 6
          && (dr === 0 || dr === 6 || dc === 0 || dc === 6 || (dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4));
        set(r, c, inRing);
      }
    }
  };
  finder(0, 0);
  finder(0, size - 7);
  finder(size - 7, 0);

  const centers = ALIGN[ver - 1];
  for (const r of centers) {
    for (const c of centers) {
      if ((r < 9 && c < 9) || (r < 9 && c >= size - 9) || (r >= size - 9 && c < 9)) continue;
      for (let dr = -2; dr <= 2; dr++) {
        for (let dc = -2; dc <= 2; dc++) set(r + dr, c + dc, Math.max(Math.abs(dr), Math.abs(dc)) !== 1);
      }
    }
  }
  for (let i = 8; i < size - 8; i++) {
    if (m[6][i] === -1) set(6, i, i % 2 === 0);
    if (m[i][6] === -1) set(i, 6, i % 2 === 0);
  }
  // reserve format areas (filled per mask below) + dark module
  for (let i = 0; i < 8; i++) {
    func[8][i] = func[i][8] = func[8][size - 1 - i] = func[size - 1 - i][8] = 1;
  }
  func[8][8] = 1;
  set(size - 8, 8, 1);
  if (ver >= 7) {
    const vi = (ver << 12) | bchRemainder(ver << 12, 0x1f25);
    for (let i = 0; i < 18; i++) {
      const b = (vi >> i) & 1;
      const r = Math.floor(i / 3), c = size - 11 + (i % 3);
      set(r, c, b);
      set(c, r, b);
    }
  }

  // --- data placement: zigzag from bottom-right, skipping column 6
  const totalBits = out.length * 8;
  const bitAt = (i) => (out[i >> 3] >> (7 - (i & 7))) & 1;
  let bi = 0, up = true;
  for (let col = size - 1; col > 0; col -= 2) {
    if (col === 6) col--;
    for (let k = 0; k < size; k++) {
      const row = up ? size - 1 - k : k;
      for (const c of [col, col - 1]) {
        if (func[row][c]) continue;
        m[row][c] = bi < totalBits ? bitAt(bi) : 0; // remainder bits are zero
        bi++;
      }
    }
    up = !up;
  }

  // --- try all masks, keep the lowest-penalty one
  const drawFormat = (t, mask) => {
    const fmt5 = (0b01 << 3) | mask; // EC level L = 01
    const f = ((fmt5 << 10) | bchRemainder(fmt5 << 10, 0x537)) ^ 0x5412;
    for (let i = 0; i < 15; i++) {
      const b = (f >> i) & 1;
      t[i < 6 ? i : i < 8 ? i + 1 : size - 15 + i][8] = b;
      t[8][i < 8 ? size - 1 - i : i < 9 ? 15 - i : 14 - i] = b;
    }
  };
  let best = null, bestScore = Infinity;
  for (let mask = 0; mask < 8; mask++) {
    const t = m.map((row) => Int8Array.from(row));
    for (let r = 0; r < size; r++) {
      for (let c = 0; c < size; c++) {
        if (!func[r][c] && MASKS[mask](r, c)) t[r][c] ^= 1;
      }
    }
    drawFormat(t, mask);
    const score = penalty(t);
    if (score < bestScore) { best = t; bestScore = score; }
  }
  return best.map((row) => Array.from(row));
}
