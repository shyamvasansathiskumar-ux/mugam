// Mugam · the vault on this device (IndexedDB).
//
// For each account on this device it keeps:
//   - an ECDSA P-256 key pair whose PRIVATE key is non-extractable: the browser will use it
//     to sign, but will never hand its bytes to any script, including Mugam's own;
//   - an AES-GCM key, also non-extractable, that encrypts the face template and its seed.
// Nothing here is ever sent to the server except the public key and signatures.

import { newSeed } from "./template.js";

const DB = "mugam", STORE = "accounts", VERSION = 1;
const subtle = crypto.subtle;

function open() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, VERSION);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE, { keyPath: "username" });
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function tx(mode, fn) {
  const db = await open();
  return new Promise((resolve, reject) => {
    const t = db.transaction(STORE, mode);
    const out = fn(t.objectStore(STORE));
    t.oncomplete = () => { db.close(); resolve(out && "result" in out ? out.result : undefined); };
    t.onerror = () => { db.close(); reject(t.error); };
  });
}

export const get = (username) => tx("readonly", (s) => s.get(username));
export const remove = (username) => tx("readwrite", (s) => s.delete(username));
export const list = () => tx("readonly", (s) => s.getAll());
const put = (record) => tx("readwrite", (s) => s.put(record));

/** A fresh device key pair and template key. Nothing is saved until the server accepts the key. */
export async function newKeys() {
  const keyPair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  const wrapKey = await subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const jwk = await subtle.exportKey("jwk", keyPair.publicKey);     // only the public half can be exported
  return { keyPair, wrapKey, publicJwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y } };
}

async function seal(key, bytes, aad) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad }, key, bytes);
  return { iv, ct: new Uint8Array(ct) };
}
async function unseal(key, box, aad) {
  return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: box.iv, additionalData: aad }, key, box.ct));
}

/** Saves the account with its encrypted template. aad binds the ciphertext to this username. */
export async function save({ username, displayName, deviceId, keys, template, seed }) {
  const aad = new TextEncoder().encode("mugam|" + username);
  await put({
    username, displayName, deviceId,
    keyPair: keys.keyPair, wrapKey: keys.wrapKey,
    template: await seal(keys.wrapKey, new Uint8Array(template.buffer.slice(0)), aad),
    seed: await seal(keys.wrapKey, seed, aad),
    created: Date.now(),
  });
}

/** Replaces only the template (re-enrolment): a new seed makes the old template useless. */
export async function replaceTemplate(username, template, seed) {
  const r = await get(username);
  const aad = new TextEncoder().encode("mugam|" + username);
  r.template = await seal(r.wrapKey, new Uint8Array(template.buffer.slice(0)), aad);
  r.seed = await seal(r.wrapKey, seed, aad);
  await put(r);
}

export async function openTemplate(record) {
  const aad = new TextEncoder().encode("mugam|" + record.username);
  const t = await unseal(record.wrapKey, record.template, aad);
  const seed = await unseal(record.wrapKey, record.seed, aad);
  return { template: new Float32Array(t.buffer), seed };
}

export async function sign(record, text) {
  const sig = await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, record.keyPair.privateKey, new TextEncoder().encode(text));
  return b64(new Uint8Array(sig));
}

export function b64(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export { newSeed };
