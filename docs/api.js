// Mugam · talks to the Java server, or to the in-browser demo server on GitHub Pages.

import { DemoServer } from "./demo-server.js";

class ApiError extends Error { constructor(status, message) { super(message); this.status = status; } }

async function call(path, body) {
  const res = await fetch(path, body === undefined
    ? { credentials: "same-origin", cache: "no-store" }
    : { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  let data = {};
  try { data = await res.json(); } catch { /* empty */ }
  if (!res.ok) throw new ApiError(res.status, data.error || "Something went wrong.");
  return data;
}

const http = {
  mode: "server",
  registerBegin: (b) => call("/api/register/begin", b),
  registerFinish: (b) => call("/api/register/finish", b),
  loginBegin: (b) => call("/api/login/begin", b),
  loginFinish: (b) => call("/api/login/finish", b),
  recoverBegin: (b) => call("/api/recover/begin", b),
  recoverFinish: (b) => call("/api/recover/finish", b),
  me: () => call("/api/me"),
  removeDevice: (b) => call("/api/device/remove", b),
  newCodes: () => call("/api/recovery/new", {}),
  faceRenewed: () => call("/api/face/renewed", {}),
  logout: () => call("/api/logout", {}),
  deleteAccount: () => call("/api/account/delete", {}),
};

function demo() {
  const s = new DemoServer();
  const wrap = (fn) => async (b) => {
    try { return await fn.call(s, b || {}); }
    catch (e) { throw new ApiError(e.status || 500, e.message); }
  };
  const out = { mode: "demo" };
  for (const k of Object.keys(http)) if (k !== "mode") out[k] = wrap(s[k]);
  return out;
}

/** Uses the real server when one answers on /api/health; otherwise the demo. */
export async function connect() {
  try {
    const r = await fetch("/api/health", { cache: "no-store" });
    if (r.ok && (await r.json()).ok) return http;
  } catch { /* no server */ }
  return demo();
}

export { ApiError };
