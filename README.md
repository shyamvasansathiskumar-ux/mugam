# Mugam (முகம்)

**Sign in with your face. Your face never leaves your device.**

Mugam is a face sign-in system for websites. It works with an ordinary webcam and needs no password. Its security model follows the same idea as Apple's Face ID: the face check runs on the person's own device, and all it does is unlock a key that never leaves that device.

**Site:** https://shyamvasansathiskumar-ux.github.io/mugam/ · **Try it:** https://shyamvasansathiskumar-ux.github.io/mugam/try.html
On GitHub Pages there's no server, so a demo server runs inside your browser and follows the same protocol (it protects nothing from the person at the keyboard). Run the Java server for the real thing.

## How it works

```
 this device                                                    server
 ───────────                                                    ──────
 camera ─▶ face model ─▶ liveness (2 random moves) ─┐
                                                    ├─ match? ─▶ unlock device key ─▶ sign challenge ─▶ verify signature
 encrypted, rotated template (IndexedDB) ───────────┘            (non-extractable)                      (public key only)
```

1. **Your face stays on your device.** Camera frames are analysed in memory and dropped. Nothing is uploaded, ever.
2. **What is stored is not your face.** Mugam stores a 128-number template, rotated by a secret random orthonormal matrix (distances are kept, so matching still works) and encrypted with AES-GCM under a key the browser won't let anyone export. Set up your face again and you get a new rotation, so the old template becomes useless ("cancelable" biometrics, the renewability goal of ISO/IEC 24745).
3. **A live person, not a photo.** Each sign-in asks for two of {turn left, turn right, blink}, in a random order, a few seconds each. It must stay one face that doesn't jump across the picture. A still photo fails, and the end-to-end test proves it.
4. **The server only ever sees a signature.** A passed face check unlocks a P-256 key whose private half can't be exported. That key signs a one-time challenge bound to the website's origin. The server keeps public keys only, so a stolen database signs nothing.
5. **Recovery without a back door.** Every account gets 10 one-time recovery codes, stored as PBKDF2 hashes. A code adds a new device; it never skips the face check on an existing one. For 24 hours a recovered device can't remove the others, so a stolen code can't lock the owner out.
6. **Every event is on the record.** Sign-ins, failures, new devices, removals and recovery all go into a chain keyed with HMAC. Editing or cutting the log file shows up as "Chain broken" while the server runs. The log stores a pseudonym, never the username.

See [SECURITY.md](SECURITY.md) for the threat model: what Mugam stops, and what it honestly can't.

## Run it

You need JDK 21. There are no other dependencies: the server uses only the JDK, and the face model ships in `docs/models`.

```bash
bash scripts/serve.sh 8080      # then open http://localhost:8080
```

The camera works on `localhost` and on HTTPS sites only (a browser rule). For a real deployment, put Mugam behind HTTPS and start it with `--origin https://your.domain`; it then sets a `__Host-` cookie with `Secure`. Also pass `--pepper /path/outside/the/data/pepper` (the log's key belongs away from the log) and, behind a reverse proxy, `--trusted-proxy <the proxy's address>` so rate limits apply per visitor, not to the proxy.

## Test it

```bash
bash scripts/test.sh            # Java: protocol, attacks, HTTP · Node: templates and liveness
bash scripts/e2e.sh             # real Chromium + the real server + a fake camera showing a still photo
```

`e2e.sh` needs Playwright with Chromium, plus a fake-camera clip at `tests/fixtures/photo-attack.y4m`. Make one from any photo you have the right to use:
`ffmpeg -loop 1 -i you.jpg -vf "scale=640:480,format=yuv420p" -t 20 -r 10 tests/fixtures/photo-attack.y4m`

| Suite | Tests | What it proves |
|---|---|---|
| Java (`server/test`) | 46 | JSON parser limits (including malformed `\u` escapes); off-curve and private-key JWKs refused; replay, expiry, wrong origin (phishing), type confusion, username swap, someone else's key, a changed byte; failed sign-ins can't lock the owner out; wrong recovery codes lock recovery; a recovered device can't remove the owner's devices for 24 hours; a reused username can't see the old account's log; recovery codes single-use; sessions end when a device is removed; step-up for sensitive actions; the server stores no face data; the log has no usernames; an edited or truncated log file is detected; CSRF, path traversal, oversize bodies, security headers, HttpOnly cookie, rate limit |
| Node (`tests/web.test.mjs`) | 13 | rotations are orthonormal and keep distances; cancelability; enrolment rejects swapped captures; yaw and blink maths; a still photo, a wrong turn, two faces and a jumping face all fail liveness |
| Browser (`tests/e2e.py`) | 20 | runs under the strict CSP; the real model matches the same face through the rotation; WebCrypto signatures verify in Java; the private key can't be exported; **a still photo of the enrolled face can't sign in**; the session cookie is invisible to scripts; the demo server applies the same rules; the landing page runs under the CSP and its own key signs and verifies |

## Layout

```
server/src/mugam/   Server (HTTP, headers, CSRF, rate limits) · Auth (the protocol) · Store · Audit (hash chain) · Crypto · Json
server/test/        TestRunner (no JUnit)
docs/               index.html (the project page, scene.js · landing.js) and try.html (the app: app.js · face.js · liveness.js · template.js · vault.js · api.js · demo-server.js)
tests/              web.test.mjs (Node) · e2e.py (Playwright) · pipeline.html (model sanity check)
```

## Credits

Face detection, landmarks and descriptors: [face-api](https://github.com/vladmandic/face-api) by Vladimir Mandic, based on face-api.js by Vincent Mühler (MIT). Blink detection: the eye aspect ratio of Soukupová & Čech (2016).

Shyam Kumar, CSE, Rajalakshmi Engineering College, 2026. MIT licence.
