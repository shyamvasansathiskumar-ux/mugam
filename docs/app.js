// Mugam · the app: screens and flows. The security work lives in vault.js (keys),
// template.js (cancelable templates), liveness.js (live person) and the server.

import { connect } from "./api.js";
import * as vault from "./vault.js";
import * as face from "./face.js";
import { rotation, project, distance, mean, consistent, MATCH_THRESHOLD } from "./template.js";
import { Challenge, randomChallenge } from "./liveness.js";

const $ = (id) => document.getElementById(id);
let api = null;
let pendingCodes = null;
let afterCodes = null;

// ------------------------------------------------------------------ screens

function show(name) {
  for (const s of document.querySelectorAll("[data-screen]")) s.hidden = s.dataset.screen !== name;
  const first = document.querySelector(`[data-screen="${name}"] input:not([type=checkbox]), [data-screen="${name}"] h1`);
  if (first && first.tagName === "INPUT" && !matchMedia("(pointer: coarse)").matches) first.focus();
}

function say(id, text, ok = false) {
  const el = $(id);
  el.textContent = text || "";
  el.hidden = !text;
  el.classList.toggle("ok", ok);
}

function guessDevice() {
  const ua = navigator.userAgent;
  const os = /iPhone/.test(ua) ? "iPhone" : /iPad/.test(ua) ? "iPad" : /Android/.test(ua) ? "Android phone"
    : /Mac/.test(ua) ? "Mac" : /Windows/.test(ua) ? "Windows PC" : /Linux/.test(ua) ? "Linux PC" : "This device";
  const br = /Edg\//.test(ua) ? "Edge" : /Chrome\//.test(ua) ? "Chrome" : /Firefox\//.test(ua) ? "Firefox" : /Safari\//.test(ua) ? "Safari" : "";
  return br ? `${os} · ${br}` : os;
}

const busy = (form, on) => { for (const b of form.querySelectorAll("button, input")) b.disabled = on; };

// ------------------------------------------------------------------ the camera ring

const TICKS = 72;
function drawRing() {
  const svg = $("ring");
  const ns = "http://www.w3.org/2000/svg";
  svg.replaceChildren();
  for (let i = 0; i < TICKS; i++) {
    const a = (i / TICKS) * Math.PI * 2 - Math.PI / 2;
    const l = document.createElementNS(ns, "line");
    l.setAttribute("x1", 150 + Math.cos(a) * 136); l.setAttribute("y1", 150 + Math.sin(a) * 136);
    l.setAttribute("x2", 150 + Math.cos(a) * 146); l.setAttribute("y2", 150 + Math.sin(a) * 146);
    svg.append(l);
  }
}
function ring(p, failed = false) {
  const lines = $("ring").children;
  const on = Math.round(Math.max(0, Math.min(1, p)) * TICKS);
  for (let i = 0; i < lines.length; i++) lines[i].classList.toggle("on", i < on);
  $("ring").classList.toggle("fail", failed);
}

// ------------------------------------------------------------------ face scan

let cancelled = false;
const SCAN_LIMIT_MS = 35000;      // a whole attempt, start to finish
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Runs the camera until the liveness challenge passes or fails.
 * Enrolment: a fixed, guided set (left, right). Sign-in: two random movements.
 * Returns descriptors captured facing the camera at the start and at the end.
 */
async function scan(mode) {
  cancelled = false;
  show("scan");
  $("scan-title").textContent = mode === "enrol" ? "Set up face sign-in" : "Face sign-in";
  $("veil").hidden = false;
  ring(0);
  $("status").textContent = "Getting ready…";
  $("hint").textContent = "Hold your device at arm's length, in good light.";
  const video = $("video"), probe = $("probe");
  try {
    await face.load();
    try { await face.start(video); }
    catch { throw new Error("Mugam needs your camera. Allow camera access in your browser's site settings, then try again."); }
    $("veil").hidden = true;

    const steps = mode === "enrol" ? ["turnLeft", "turnRight"] : randomChallenge();
    const ch = new Challenge(steps, performance.now());
    const start = [], end = [];
    let n = 0;

    const deadline = performance.now() + SCAN_LIMIT_MS;
    while (!ch.result) {
      if (cancelled) throw new Error("cancelled");
      if (performance.now() > deadline) { ring(1, true); throw new Error("That took too long. Try again in good light, facing the camera."); }
      const r = await face.look(video);
      const now = performance.now();
      if (ch.i < 0) {
        const q = r.faces === 1 ? face.quality(video, r.box, probe) : (r.faces > 1 ? "Only one face, please" : "Looking for your face…");
        if (q) { $("status").textContent = q; ch.stepStart = now; ch.calib = []; ch.lastBox = null; await wait(60); continue; }
        if (++n % 2 === 0 && start.length < (mode === "enrol" ? 4 : 2)) {
          const d = await face.describe(video);
          if (d) start.push(d);
        }
      }
      ch.frame(r.faces, r.box, r.lm, now);
      if (ch.i >= 0 && start.length < (mode === "enrol" ? 3 : 1)) {        // baseline done too fast: collect what's missing
        const d = await face.describe(video);
        if (d) start.push(d);
      }
      $("status").textContent = ch.instruction();
      $("hint").textContent = mode === "enrol" ? "Move slowly. The circle fills as you go." : "This shows a real person is here.";
      ring(ch.i < 0 ? Math.min(0.15, ch.calib.length * 0.03) : 0.15 + 0.85 * ch.progress());
    }

    if (ch.result !== "pass") { ring(1, true); throw new Error(`That didn't work (${ch.result.slice(5)}). Try again.`); }
    $("status").textContent = "Hold still…";
    for (let k = 0; k < 6 && end.length < 2; k++) { const d = await face.describe(video); if (d) end.push(d); }
    if (!start.length || !end.length) throw new Error("Couldn't see your face clearly. Try again in better light.");
    ring(1);
    $("status").textContent = mode === "enrol" ? "Face set up." : "Recognised.";
    return { start, end, steps };
  } finally {
    face.stop(video);
  }
}

/** Builds a template from an enrolment scan: consistent captures only, rotated by a new secret seed. */
async function makeTemplate(s) {
  const all = [...s.start, ...s.end];
  if (all.length < 3 || !consistent(all)) throw new Error("The captures didn't agree with each other. Try again with steady light.");
  const seed = vault.newSeed();
  const Q = await rotation(seed);
  return { template: project(Q, mean(all)), seed };
}

/** Checks a sign-in scan against this device's template. Every capture has to match. */
async function matches(record, s) {
  const { template, seed } = await vault.openTemplate(record);
  const Q = await rotation(seed);
  const ds = [...s.start, ...s.end].map((d) => distance(project(Q, d), template));
  return { ok: ds.every((d) => d < MATCH_THRESHOLD), worst: Math.max(...ds) };
}

function clientData(type, ch, username, extra = {}) {
  // origin is OUR location, never what the server says: that is what stops a look-alike
  // site from relaying a challenge and getting a valid signature for the real one
  return JSON.stringify({ type, challenge: ch.challenge, origin: location.origin, username, ...extra });
}

// ------------------------------------------------------------------ flows

async function signIn(username, { quiet = false } = {}) {
  const record = await vault.get(username);
  if (!record) {
    show("home");
    say("home-msg", `Face sign-in isn't set up for "${username}" on this device. Use a recovery code to add this device, or create an account.`);
    return false;
  }
  try {
    const s = await scan("signin");
    const m = await matches(record, s);
    if (!m.ok) throw new Error("Your face didn't match. Try again, facing the light.");
    const ch = await api.loginBegin({ username });
    const cd = clientData("mugam.login", ch, ch.username, { deviceId: record.deviceId, face: { steps: s.steps.join(","), distance: Math.round(m.worst * 1000) / 1000 } });
    await api.loginFinish({ challengeId: ch.challengeId, clientData: cd, signature: await vault.sign(record, cd) });
    if (!quiet) await account();
    return true;
  } catch (e) {
    if (e.message === "cancelled") { show(quiet ? "account" : "home"); return false; }
    show(quiet ? "account" : "home");
    say(quiet ? "account-msg" : "home-msg", e.message);
    return false;
  }
}

async function enrolNew({ displayName, username, deviceName, ch: early }) {
  const s = await scan("enrol");
  const { template, seed } = await makeTemplate(s);
  const keys = await vault.newKeys();
  // Reuse the challenge from the "is this name free?" step while it is still fresh, so a
  // sign-up costs one request against the per-address limit, not two.
  const fresh = early && early.at + early.expiresInMs - 10000 > Date.now();
  const ch = fresh ? early : await api.registerBegin({ username });
  const cd = clientData("mugam.register", ch, ch.username);
  const signature = await vault.sign({ keyPair: keys.keyPair }, cd);
  const r = await api.registerFinish({ challengeId: ch.challengeId, clientData: cd, signature, publicKey: keys.publicJwk, displayName, deviceName });
  await vault.save({ username: r.username, displayName: r.displayName, deviceId: r.deviceId, keys, template, seed });
  return r;
}

async function enrolRecovered({ username, code, deviceName }) {
  const s = await scan("enrol");
  const { template, seed } = await makeTemplate(s);
  const keys = await vault.newKeys();
  const ch = await api.recoverBegin({ username });
  const cd = clientData("mugam.recover", ch, ch.username);
  const signature = await vault.sign({ keyPair: keys.keyPair }, cd);
  const r = await api.recoverFinish({ challengeId: ch.challengeId, clientData: cd, signature, publicKey: keys.publicJwk, recoveryCode: code, deviceName });
  await vault.save({ username: r.username, displayName: r.displayName, deviceId: r.deviceId, keys, template, seed });
  return r;
}

function showCodes(codes, then) {
  pendingCodes = codes;
  afterCodes = then;
  const ol = $("codes");
  ol.replaceChildren(...codes.map((c) => { const li = document.createElement("li"); li.textContent = c; return li; }));
  $("saved").checked = false;
  $("btn-codes-done").disabled = true;
  show("codes");
}

// ------------------------------------------------------------------ account

const when = (t) => t ? new Date(t).toLocaleString(undefined, { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }) : "never";
const LABELS = {
  ACCOUNT_CREATED: "Account created", SIGNED_IN: "Signed in", SIGNED_OUT: "Signed out", SIGN_IN_FAILED: "Sign-in failed",
  DEVICE_REMOVED: "Device removed", RECOVERY_CODE_USED: "Recovery code used",
  RECOVERY_CODES_REPLACED: "New recovery codes", ACCOUNT_DELETED: "Account deleted",
  RECOVERY_FAILED: "Wrong recovery code", FACE_SET_UP_AGAIN: "Face set up again",
};

async function account() {
  let me;
  try { me = await api.me(); } catch { show("home"); return; }
  const first = me.displayName.split(" ")[0];
  $("hello").textContent = `Hello, ${first}.`;
  $("whoami").textContent = `Signed in as ${me.username}.`;

  const devs = $("devices");
  devs.replaceChildren(...me.devices.map((d) => {
    const li = document.createElement("li");
    const left = document.createElement("span");
    left.textContent = d.name;
    const sub = document.createElement("span");
    sub.className = "sub";
    sub.textContent = `Added ${when(d.created)} · last sign-in ${when(d.lastUsed)}`;
    left.append(sub);
    li.append(left);
    if (d.id === me.currentDevice) {
      const b = document.createElement("span"); b.className = "badge"; b.textContent = "This device"; li.append(b);
    } else {
      const btn = document.createElement("button");
      btn.className = "btn small"; btn.type = "button"; btn.textContent = "Remove";
      btn.addEventListener("click", async () => {
        if ((await sensitive(() => api.removeDevice({ deviceId: d.id }))).ok) { await account(); say("account-msg", `${d.name} removed.`, true); }
      });
      li.append(btn);
    }
    return li;
  }));

  $("codes-left").textContent = `${me.recoveryCodesLeft} of 10 left`;
  const chain = $("chain");
  chain.replaceChildren();
  const b = document.createElement("b");
  b.textContent = me.logIntact ? "Chain intact" : "Chain broken";
  b.classList.toggle("broken", !me.logIntact);
  const head = document.createElement("span");
  head.className = "mono";
  head.textContent = ` · head ${me.logHead.slice(0, 16)}…`;
  chain.append(b, head);
  $("log").replaceChildren(...me.log.map((e) => {
    const li = document.createElement("li");
    const what = document.createElement("span");
    what.textContent = LABELS[e.type] || e.type;
    const sub = document.createElement("span"); sub.className = "sub"; sub.textContent = e.detail;
    what.append(sub);
    const t = document.createElement("span"); t.className = "t"; t.textContent = when(e.at);
    li.append(what, t);
    return li;
  }));
  say("account-msg", "");
  show("account");
}

/**
 * Runs an action that needs a recent face sign-in. If the server asks for one (403), Mugam
 * signs in with the face again and retries once. Returns {ok, value}.
 */
async function sensitive(action) {
  try { return { ok: true, value: await action() }; }
  catch (e) {
    if (e.status !== 403) { say("account-msg", e.message); return { ok: false }; }
    const me = await api.me().catch(() => null);
    if (!me || !(await signIn(me.username, { quiet: true }))) return { ok: false };
    try { return { ok: true, value: await action() }; }
    catch (e2) { await account(); say("account-msg", e2.message); return { ok: false }; }
  }
}

function confirmAsk(title, text, yes) {
  return new Promise((resolve) => {
    const d = $("confirm");
    $("confirm-title").textContent = title;
    $("confirm-text").textContent = text;
    $("confirm-yes").textContent = yes;
    d.returnValue = "";
    d.addEventListener("close", () => resolve(d.returnValue === "yes"), { once: true });
    d.showModal();
  });
}

// ------------------------------------------------------------------ wiring

async function boot() {
  drawRing();
  api = await connect();
  if (api.mode === "demo") {
    const m = $("mode");
    m.textContent = "Demo · server runs in your browser";
    m.hidden = false;
  }
  for (const id of ["c-device", "r-device"]) $(id).value = guessDevice();

  for (const b of document.querySelectorAll("[data-go]")) b.addEventListener("click", () => {
    say("home-msg", ""); say("create-msg", ""); say("recover-msg", "");
    show(b.dataset.go);
  });

  $("f-signin").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    say("home-msg", "");
    const u = $("in-user").value.trim().toLowerCase();
    if (!u) { say("home-msg", "Enter your username."); return; }
    await signIn(u);
  });

  let draft = null;
  $("f-create").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    say("create-msg", "");
    draft = { displayName: $("c-name").value.trim(), username: $("c-user").value.trim().toLowerCase(), deviceName: $("c-device").value.trim() };
    if (!draft.displayName || !draft.username || !draft.deviceName) { say("create-msg", "Fill in all three."); return; }
    busy(ev.target, true);
    try { draft.ch = { ...(await api.registerBegin({ username: draft.username })), at: Date.now() }; show("notice"); }   // checks the name is free before the camera
    catch (e) { say("create-msg", e.message); }
    finally { busy(ev.target, false); }
  });

  $("consent").addEventListener("change", () => { $("btn-consent").disabled = !$("consent").checked; });
  $("btn-consent").addEventListener("click", async () => {
    try {
      const r = await enrolNew(draft);
      showCodes(r.recoveryCodes, account);
    } catch (e) {
      show("create");
      if (e.message !== "cancelled") say("create-msg", e.message);
    }
  });

  $("f-recover").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    say("recover-msg", "");
    const args = { username: $("r-user").value.trim().toLowerCase(), code: $("r-code").value.trim(), deviceName: $("r-device").value.trim() };
    if (!args.username || !args.code || !args.deviceName) { say("recover-msg", "Fill in all three."); return; }
    try { await enrolRecovered(args); $("r-code").value = ""; await account(); say("account-msg", "This device is added. If you lost your old one, remove it below.", true); }
    catch (e) { show("recover"); if (e.message !== "cancelled") say("recover-msg", e.message); }
  });

  $("btn-cancel").addEventListener("click", () => { cancelled = true; });

  $("saved").addEventListener("change", () => { $("btn-codes-done").disabled = !$("saved").checked; });
  $("btn-copy").addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(pendingCodes.join("\n")); $("btn-copy").textContent = "Copied"; } catch { $("btn-copy").textContent = "Copy failed"; }
  });
  $("btn-download").addEventListener("click", () => {
    const text = "Mugam recovery codes\nEach code works once. Keep them somewhere safe and private.\n\n" + pendingCodes.join("\n") + "\n";
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
    a.download = "mugam-recovery-codes.txt";
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  });
  $("btn-codes-done").addEventListener("click", async () => {
    pendingCodes = null;                    // gone from memory once the person has saved them
    $("codes").replaceChildren();
    $("btn-copy").textContent = "Copy";
    if (afterCodes) await afterCodes();
  });

  $("btn-newcodes").addEventListener("click", async () => {
    const r = await sensitive(() => api.newCodes());
    if (r.ok) showCodes(r.value.recoveryCodes, async () => { await account(); say("account-msg", "New codes saved. The old ones no longer work.", true); });
  });

  $("btn-reenrol").addEventListener("click", async () => {
    const me = await api.me().catch(() => null);
    if (!me) return;
    try {
      // The face that is set up now must first pass a full sign-in against the CURRENT
      // template. Otherwise anyone at an unlocked, signed-in browser could swap in their own face.
      say("account-msg", "First, sign in with the face that's set up now.");
      if (!(await signIn(me.username, { quiet: true }))) { await account(); return; }
      const s = await scan("enrol");
      const { template, seed } = await makeTemplate(s);
      await vault.replaceTemplate(me.username, template, seed);
      await api.faceRenewed().catch(() => {});
      await account();
      say("account-msg", "Face set up again. The old template can no longer be matched.", true);
    } catch (e) { await account(); if (e.message !== "cancelled") say("account-msg", e.message); }
  });

  $("btn-forget").addEventListener("click", async () => {
    const me = await api.me().catch(() => null);
    if (!me) return;
    if (!(await confirmAsk("Remove face data from this device?", "Your face template and this device's key are erased. You'll need a recovery code to use this device again.", "Remove"))) return;
    if (!(await sensitive(() => api.removeDevice({ deviceId: me.currentDevice }))).ok) return;
    await vault.remove(me.username);
    await api.logout().catch(() => {});
    show("home");
    say("home-msg", "Face data removed from this device.", true);
  });

  $("btn-signout").addEventListener("click", async () => { await api.logout().catch(() => {}); show("home"); });

  $("btn-delete").addEventListener("click", async () => {
    const me = await api.me().catch(() => null);
    if (!me) return;
    if (!(await confirmAsk("Delete your account?", "Every device, recovery code and face template is erased. This can't be undone.", "Delete"))) return;
    if (!(await sensitive(() => api.deleteAccount())).ok) return;
    await vault.remove(me.username);
    show("home");
    say("home-msg", "Your account is deleted.", true);
  });

  try { await api.me(); await account(); } catch { show("home"); }
}

boot();
