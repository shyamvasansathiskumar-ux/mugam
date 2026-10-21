// Mugam · cancelable face templates.
//
// A face descriptor (128 numbers from the recognition model) is never stored as it is.
// It is multiplied by a secret random rotation Q (an orthonormal 128×128 matrix made from a
// per-enrolment 32-byte seed). Rotations keep distances exactly, so matching works the same,
// but the stored numbers are useless without the seed. Re-enrolling makes a new seed, so an
// old, leaked template can never be matched against the new one ("cancelable" biometrics,
// the renewability goal of ISO/IEC 24745). The seed itself is stored only encrypted, under a
// key the browser won't let anyone export (see vault.js).

export const DIM = 128;
export const MATCH_THRESHOLD = 0.5;     // face-api's usual cut-off is 0.6; Mugam is stricter

const subtle = globalThis.crypto.subtle;

/** Expands a 32-byte seed into n pseudo-random bytes: SHA-256(seed || counter), counter = 0, 1, 2... */
export async function expand(seed, n) {
  const out = new Uint8Array(n);
  let off = 0;
  for (let ctr = 0; off < n; ctr++) {
    const block = new Uint8Array(seed.length + 4);
    block.set(seed);
    new DataView(block.buffer).setUint32(seed.length, ctr);
    const h = new Uint8Array(await subtle.digest("SHA-256", block));
    out.set(h.subarray(0, Math.min(32, n - off)), off);
    off += 32;
  }
  return out;
}

/** Turns random bytes into standard-normal numbers (Box–Muller), two per 8 bytes. */
function gaussians(bytes, count) {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const g = new Float64Array(count);
  for (let i = 0, j = 0; i < count; i += 2, j += 8) {
    const u1 = (dv.getUint32(j) + 1) / 4294967297;      // never 0, so log() is safe
    const u2 = dv.getUint32(j + 4) / 4294967296;
    const r = Math.sqrt(-2 * Math.log(u1));
    g[i] = r * Math.cos(2 * Math.PI * u2);
    if (i + 1 < count) g[i + 1] = r * Math.sin(2 * Math.PI * u2);
  }
  return g;
}

/** A random orthonormal matrix (rows), from a seed: Gaussian matrix, then Gram–Schmidt (twice, for accuracy). */
export async function rotation(seed, dim = DIM) {
  const g = gaussians(await expand(seed, dim * dim * 4), dim * dim);
  const rows = [];
  for (let r = 0; r < dim; r++) {
    const v = g.slice(r * dim, (r + 1) * dim);
    for (let pass = 0; pass < 2; pass++) {
      for (const q of rows) {
        let d = 0;
        for (let k = 0; k < dim; k++) d += v[k] * q[k];
        for (let k = 0; k < dim; k++) v[k] -= d * q[k];
      }
    }
    let n = 0;
    for (let k = 0; k < dim; k++) n += v[k] * v[k];
    n = Math.sqrt(n);
    for (let k = 0; k < dim; k++) v[k] /= n;
    rows.push(v);
  }
  return rows;
}

export function project(Q, v) {
  const out = new Float32Array(Q.length);
  for (let r = 0; r < Q.length; r++) {
    let s = 0;
    const q = Q[r];
    for (let k = 0; k < q.length; k++) s += q[k] * v[k];
    out[r] = s;
  }
  return out;
}

export function distance(a, b) {
  let s = 0;
  for (let k = 0; k < a.length; k++) { const d = a[k] - b[k]; s += d * d; }
  return Math.sqrt(s);
}

/** The template is the average of several good, front-facing descriptors. */
export function mean(descriptors) {
  const m = new Float32Array(descriptors[0].length);
  for (const d of descriptors) for (let k = 0; k < m.length; k++) m[k] += d[k] / descriptors.length;
  return m;
}

/**
 * Enrolment refuses an inconsistent set: if two "front-facing" captures are not even the
 * same person by a wide margin, someone swapped faces or the light changed too much.
 */
export function consistent(descriptors, limit = 0.45) {
  for (let i = 0; i < descriptors.length; i++)
    for (let j = i + 1; j < descriptors.length; j++)
      if (distance(descriptors[i], descriptors[j]) > limit) return false;
  return true;
}

export function newSeed() { return globalThis.crypto.getRandomValues(new Uint8Array(32)); }
