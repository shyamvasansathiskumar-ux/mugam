// Mugam · demo server. On GitHub Pages there is no Java server, so this file plays its part
// inside the browser, following the protocol in server/src/mugam/Auth.java: one-use
// challenges that expire in 2 minutes, origin checks, ECDSA signature checks, a 5-strike
// lockout on recovery codes, recovery codes stored only as PBKDF2 hashes, a 24-hour hold on
// devices added by recovery, and a hash-chained security log.
//
// It is a demo, not a security boundary: everything lives in this browser's storage, the
// lockout counter resets when the page reloads, and the log uses a plain hash, not the Java
// server's keyed one. It protects nothing from someone at this keyboard.

const KEY = "mugam-demo-v1";
const TTL = 120000, IDLE = 15 * 60000, MAX_AGE = 12 * 3600000, STEP_UP = 5 * 60000, MAX_FAIL = 5, WINDOW = 15 * 60000;
const HOLD = 24 * 3600000;
const GENERIC = "Sign-in didn't work. Try again.";
const subtle = crypto.subtle;
const enc = new TextEncoder();

const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
const sha = async (s) => hex(await subtle.digest("SHA-256", enc.encode(s)));
const rnd = (n) => { const b = crypto.getRandomValues(new Uint8Array(n)); let s = ""; for (const x of b) s += String.fromCharCode(x); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); };
const unb64 = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));

class Err extends Error { constructor(status, m) { super(m); this.status = status; } }

export class DemoServer {
  constructor(origin = location.origin) {
    this.origin = origin;
    this.challenges = new Map();
    this.failures = new Map();
    this.db = this.load();
  }

  load() {
    try { const d = JSON.parse(localStorage.getItem(KEY)); if (d && d.users) return d; } catch { /* empty or blocked */ }
    return { users: {}, log: [], pepper: rnd(24) };
  }
  save() { try { localStorage.setItem(KEY, JSON.stringify(this.db)); } catch { /* private mode: the demo still works for this tab */ } }

  username(raw) {
    const u = String(raw ?? "").trim().toLowerCase();
    if (!/^[a-z0-9][a-z0-9._-]{2,31}$/.test(u)) throw new Err(400, "Usernames are 3–32 characters: letters, numbers, dot, dash or underscore.");
    return u;
  }
  label(raw, what, max) {
    const t = String(raw ?? "").replace(/[\p{Cc}\p{Cf}]/gu, "").trim();
    if (!t || t.length > max) throw new Err(400, `The ${what} must be 1–${max} characters.`);
    return t;
  }

  key(u) { const user = this.db.users[u]; return user ? `${user.username}#${user.created}` : null; }
  async log(username, type, detail) {
    const k = this.key(username);
    const subject = k ? (await sha(this.db.pepper + "|" + k)).slice(0, 32) : "-";
    const prev = this.db.log.length ? this.db.log[this.db.log.length - 1].hash : "0".repeat(64);
    const seq = this.db.log.length + 1, at = Date.now();
    const d = String(detail).replace(/[\p{Cc}]/gu, " ").slice(0, 200);
    this.db.log.push({ seq, at, subject, type, detail: d, prev, hash: await sha([prev, seq, at, subject, type, d].join("|")) });
    this.save();
  }
  async firstBroken() {
    let prev = "0".repeat(64);
    for (const e of this.db.log) {
      if (e.prev !== prev || e.hash !== await sha([e.prev, e.seq, e.at, e.subject, e.type, e.detail].join("|"))) return e.seq;
      prev = e.hash;
    }
    return 0;
  }

  issue(type, username) {
    const now = Date.now();
    for (const [k, c] of this.challenges) if (c.expires < now) this.challenges.delete(k);
    const c = { id: rnd(16), type, username, value: rnd(32), expires: now + TTL };
    this.challenges.set(c.id, c);
    return { challengeId: c.id, challenge: c.value, origin: this.origin, username, expiresInMs: TTL };
  }

  consume(body, type) {
    const c = this.challenges.get(body.challengeId);
    this.challenges.delete(body.challengeId);                       // one use, even on failure
    if (!c || c.expires < Date.now() || c.type !== type) throw new Err(401, GENERIC);
    let cd;
    try { cd = JSON.parse(body.clientData); } catch { throw new Err(400, GENERIC); }
    if (cd.type !== type || cd.challenge !== c.value || cd.origin !== this.origin || cd.username !== c.username) throw new Err(401, GENERIC);
    return { c, cd };
  }

  async verify(jwk, text, sig) {
    try {
      const key = await subtle.importKey("jwk", { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y }, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
      return await subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, unb64(sig), enc.encode(text));
    } catch { return false; }
  }

  locked(u) {
    const list = (this.failures.get(u) || []).filter((t) => t > Date.now() - WINDOW);
    this.failures.set(u, list);
    return list.length >= MAX_FAIL;
  }
  async fail(u, why) {   // wrong recovery codes only: a device signature can't be guessed
    this.failures.set(u, [...(this.failures.get(u) || []), Date.now()]);
    if (this.db.users[u]) await this.log(u, "RECOVERY_FAILED", why);
  }

  async codes(user) {
    const salt = rnd(16), list = [], hashes = [];
    const A = "23456789ABCDEFGHJKMNPQRSTUVWXYZ";
    for (let i = 0; i < 10; i++) {
      const r = crypto.getRandomValues(new Uint32Array(12));
      const raw = [...r].map((x) => A[x % A.length]).join("");
      list.push(raw.match(/.{4}/g).join("-"));
      hashes.push(await this.pbkdf2(raw, salt));
    }
    user.codeSalt = salt; user.codeHashes = hashes;
    return list;
  }
  async pbkdf2(code, salt) {
    const k = await subtle.importKey("raw", enc.encode(code), "PBKDF2", false, ["deriveBits"]);
    return hex(await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: unb64(salt), iterations: 210000 }, k, 256));
  }

  session(user, device) {
    const token = rnd(32);
    const s = { token, username: user.username, deviceId: device.id, created: Date.now(), signedInAt: Date.now(), lastSeen: Date.now() };
    sessionStorage.setItem("mugam-demo-session", JSON.stringify(s));
    return { username: user.username, displayName: user.displayName, deviceId: device.id };
  }
  current() {
    let s;
    try { s = JSON.parse(sessionStorage.getItem("mugam-demo-session")); } catch { s = null; }
    const u = s && this.db.users[s.username];
    const d = u && u.devices.find((x) => x.id === s.deviceId && !x.revokedAt);
    if (!d || Date.now() - s.lastSeen > IDLE || Date.now() - s.created > MAX_AGE) { sessionStorage.removeItem("mugam-demo-session"); throw new Err(401, "Please sign in."); }
    s.lastSeen = Date.now();
    sessionStorage.setItem("mugam-demo-session", JSON.stringify(s));
    return s;
  }
  stepUp(s) { if (Date.now() - s.signedInAt > STEP_UP) throw new Err(403, "For this, sign in with your face again first."); }
  owner(s) {
    this.stepUp(s);
    const u = this.db.users[s.username], d = u && u.devices.find((x) => x.id === s.deviceId);
    if (d && d.recoveredAt && Date.now() - d.recoveredAt < HOLD && u.devices.filter((x) => !x.revokedAt).length > 1)
      throw new Err(403, "This device was added with a recovery code less than 24 hours ago. Use one of your other devices, or wait until the 24 hours have passed.");
  }

  // ---- the API (same names and shapes as the Java server)

  async registerBegin({ username }) {
    const u = this.username(username);
    if (this.db.users[u]) throw new Err(409, "That username is taken.");
    return this.issue("mugam.register", u);
  }
  async registerFinish(b) {
    const { c, cd } = this.consume(b, "mugam.register");
    const displayName = this.label(b.displayName, "name", 60), deviceName = this.label(b.deviceName, "device name", 40);
    if (!(await this.verify(b.publicKey, b.clientData, b.signature))) throw new Err(401, GENERIC);
    if (this.db.users[c.username]) throw new Err(409, "That username is taken.");
    const user = { username: c.username, displayName, created: Date.now(), devices: [], codeSalt: "", codeHashes: [] };
    const device = { id: rnd(12), name: deviceName, jwk: { kty: "EC", crv: "P-256", x: b.publicKey.x, y: b.publicKey.y }, created: Date.now(), lastUsed: 0, revokedAt: 0 };
    user.devices.push(device);
    const recoveryCodes = await this.codes(user);
    this.db.users[user.username] = user;
    this.save();
    await this.log(user.username, "ACCOUNT_CREATED", `device ${device.id} (${device.name})`);
    void cd;
    return { ...this.session(user, device), recoveryCodes };
  }

  async loginBegin({ username }) {
    const u = this.username(username);
    return this.issue("mugam.login", u);
  }
  async loginFinish(b) {
    const { c, cd } = this.consume(b, "mugam.login");
    const user = this.db.users[c.username];
    const d = user && user.devices.find((x) => x.id === cd.deviceId && !x.revokedAt);
    if (!d) { if (user) await this.log(c.username, "SIGN_IN_FAILED", "unknown or removed device"); throw new Err(401, GENERIC); }
    if (!(await this.verify(d.jwk, b.clientData, b.signature))) { await this.log(c.username, "SIGN_IN_FAILED", "bad signature from device " + d.id); throw new Err(401, GENERIC); }
    d.lastUsed = Date.now();
    this.save();
    await this.log(c.username, "SIGNED_IN", `device ${d.id} (${d.name})` + (cd.face && cd.face.steps ? "; liveness " + cd.face.steps : ""));
    return this.session(user, d);
  }

  async recoverBegin({ username }) {
    const u = this.username(username);
    if (this.locked(u)) throw new Err(429, "Too many attempts. Wait 15 minutes and try again.");
    return this.issue("mugam.recover", u);
  }
  async recoverFinish(b) {
    const { c } = this.consume(b, "mugam.recover");
    if (this.locked(c.username)) throw new Err(429, "Too many attempts. Wait 15 minutes and try again.");
    const user = this.db.users[c.username];
    const code = String(b.recoveryCode || "").toUpperCase().replace(/[\s-]/g, "");
    if (!user || code.length !== 12) { await this.fail(c.username, "bad recovery code"); throw new Err(401, "That recovery code didn't work."); }
    const h = await this.pbkdf2(code, user.codeSalt);
    const hit = user.codeHashes.findIndex((x) => x && x === h);
    if (hit < 0) { await this.fail(c.username, "bad recovery code"); throw new Err(401, "That recovery code didn't work."); }
    if (!(await this.verify(b.publicKey, b.clientData, b.signature))) { await this.fail(c.username, "bad signature during recovery"); throw new Err(401, GENERIC); }
    if (user.devices.filter((d) => !d.revokedAt).length >= 10) throw new Err(409, "This account already has 10 devices. Remove one first.");
    user.codeHashes[hit] = "";
    const device = { id: rnd(12), name: this.label(b.deviceName, "device name", 40), jwk: { kty: "EC", crv: "P-256", x: b.publicKey.x, y: b.publicKey.y }, created: Date.now(), lastUsed: 0, revokedAt: 0, recoveredAt: Date.now() };
    user.devices.push(device);
    this.failures.delete(c.username);
    this.save();
    await this.log(user.username, "RECOVERY_CODE_USED", `new device ${device.id} (${device.name}); ${user.codeHashes.filter(Boolean).length} codes left`);
    return this.session(user, device);
  }

  async me() {
    const s = this.current(), u = this.db.users[s.username];
    const subject = (await sha(this.db.pepper + "|" + this.key(u.username))).slice(0, 32);
    return {
      username: u.username, displayName: u.displayName, currentDevice: s.deviceId,
      recoveryCodesLeft: u.codeHashes.filter(Boolean).length,
      devices: u.devices.filter((d) => !d.revokedAt).map(({ id, name, created, lastUsed }) => ({ id, name, created, lastUsed })),
      log: this.db.log.filter((e) => e.subject === subject).slice(-30).reverse(),
      logIntact: (await this.firstBroken()) === 0,
      logHead: this.db.log.length ? this.db.log[this.db.log.length - 1].hash : "0".repeat(64),
    };
  }
  async removeDevice({ deviceId }) {
    const s = this.current(); this.owner(s);
    const u = this.db.users[s.username], d = u.devices.find((x) => x.id === deviceId && !x.revokedAt);
    if (!d) throw new Err(404, "No such device.");
    if (u.devices.filter((x) => !x.revokedAt).length === 1 && !u.codeHashes.some(Boolean)) throw new Err(409, "This is your last device and you have no recovery codes left. Make new codes first.");
    d.revokedAt = Date.now();
    this.save();
    await this.log(u.username, "DEVICE_REMOVED", `device ${d.id} (${d.name}) removed from device ${s.deviceId}`);
    return { ok: true };
  }
  async newCodes() {
    const s = this.current(); this.owner(s);
    const u = this.db.users[s.username];
    const recoveryCodes = await this.codes(u);
    this.save();
    await this.log(u.username, "RECOVERY_CODES_REPLACED", "old codes no longer work");
    return { recoveryCodes };
  }
  async logout() {
    try { const s = this.current(); await this.log(s.username, "SIGNED_OUT", "device " + s.deviceId); } catch { /* already out */ }
    sessionStorage.removeItem("mugam-demo-session");
    return { ok: true };
  }
  async faceRenewed() {
    const s = this.current(); this.stepUp(s);
    await this.log(s.username, "FACE_SET_UP_AGAIN", "device " + s.deviceId);
    return { ok: true };
  }
  async deleteAccount() {
    const s = this.current(); this.owner(s);
    await this.log(s.username, "ACCOUNT_DELETED", "all devices and recovery codes erased");
    delete this.db.users[s.username];
    this.save();
    sessionStorage.removeItem("mugam-demo-session");
    return { ok: true };
  }
}
