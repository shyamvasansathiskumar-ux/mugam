# End-to-end in real Chromium against the real Java server, with a fake camera that shows
# a still photo. Proves: the page runs under the strict CSP, models load, the photo is
# recognised as a face, the protocol works browser -> Java, and the photo can't sign in.
import asyncio, sys, os
from playwright.async_api import async_playwright

BASE = os.environ.get("MUGAM_URL", "http://localhost:8790")
VIDEO = os.environ.get("MUGAM_FAKE_VIDEO", os.path.join(os.path.dirname(__file__), "fixtures", "photo-attack.y4m"))
SHOTS = os.environ.get("SHOTS", "/tmp/shots")
passed = failed = 0

def check(ok, name, extra=""):
    global passed, failed
    if ok: passed += 1; print("  PASS  " + name)
    else: failed += 1; print("  FAIL  " + name + ("\n        " + str(extra) if extra else ""))

async def main():
    async with async_playwright() as p:
        b = await p.chromium.launch(args=["--use-fake-ui-for-media-stream", "--use-fake-device-for-media-stream",
                                          f"--use-file-for-fake-video-capture={VIDEO}", "--use-gl=swiftshader", "--enable-unsafe-swiftshader"])
        ctx = await b.new_context(viewport={"width": 1280, "height": 860})
        await ctx.grant_permissions(["camera"], origin=BASE)
        pg = await ctx.new_page()
        errors, csp = [], []
        pg.on("pageerror", lambda e: errors.append(str(e)))
        pg.on("console", lambda m: (csp if "Content Security Policy" in m.text else errors).append(m.text) if m.type == "error" and "Failed to load resource" not in m.text else None)
        missing = []
        pg.on("response", lambda r: missing.append(r.url) if r.status == 404 else None)
        await pg.goto(BASE + "/", wait_until="networkidle")
        await pg.wait_for_timeout(800)
        check(await pg.is_visible("text=Sign in with your face."), "home screen shows")
        check(not await pg.is_visible("#mode"), "talks to the real server (no demo badge)")
        await pg.screenshot(path=f"{SHOTS}/mugam-home.png")

        # Set up an account the way the app does, using the camera stream (the still photo).
        r = await pg.evaluate("""async () => {
          const face = await import('./face.js'), vault = await import('./vault.js'), T = await import('./template.js'), A = await import('./api.js');
          const api = await A.connect();
          await face.load();
          const v = document.createElement('video'); v.muted = true; v.playsInline = true; document.body.append(v);
          await face.start(v);
          const ds = [];
          for (let k = 0; k < 6 && ds.length < 3; k++) { const d = await face.describe(v); if (d) ds.push(d); }
          face.stop(v); v.remove();
          if (ds.length < 3) return {error: 'no face in fake camera: ' + ds.length};
          const seed = T.newSeed(), Q = await T.rotation(seed), template = T.project(Q, T.mean(ds));
          const keys = await vault.newKeys();
          const ch = await api.registerBegin({username: 'e2e-' + Date.now().toString(36)});
          const cd = JSON.stringify({type: 'mugam.register', challenge: ch.challenge, origin: location.origin, username: ch.username});
          const sig = await vault.sign({keyPair: keys.keyPair}, cd);
          const reg = await api.registerFinish({challengeId: ch.challengeId, clientData: cd, signature: sig, publicKey: keys.publicJwk, displayName: 'Test Person', deviceName: 'Chromium'});
          await vault.save({username: reg.username, displayName: reg.displayName, deviceId: reg.deviceId, keys, template, seed});
          const v2 = document.createElement('video'); v2.muted = true; v2.playsInline = true; document.body.append(v2);
          await face.start(v2); const again = await face.describe(v2); face.stop(v2); v2.remove();
          const sameDistance = again ? T.distance(T.project(Q, again), template) : 9;
          let exported = 'refused';
          try { await crypto.subtle.exportKey('jwk', keys.keyPair.privateKey); exported = 'EXPORTED'; } catch (e) {}
          await api.logout();
          return {codes: reg.recoveryCodes.length, mode: api.mode, exported, consistent: T.consistent(ds), user: reg.username, sameDistance};
        }""")
        check(r.get("codes") == 10 and r.get("mode") == "server", "browser key registered with the Java server (WebCrypto signature verified by Java)", r)
        check(r.get("sameDistance", 9) < 0.5, "the real model matches the same face through the secret rotation", r.get("sameDistance"))
        check(r.get("exported") == "refused", "the private key can't be exported, even by Mugam's own code", r)

        # The photo attack: sign in through the real UI with a still photo in front of the camera.
        await pg.reload(wait_until="networkidle")
        USER = r.get("user")
        await pg.fill("#in-user", USER)
        await pg.click("button:has-text('Continue')")
        await pg.wait_for_selector("[data-screen=scan]:not([hidden])")
        await pg.wait_for_timeout(4500)
        await pg.screenshot(path=f"{SHOTS}/mugam-scan.png")
        await pg.wait_for_selector("#home-msg:not([hidden])", timeout=60000)
        msg = await pg.text_content("#home-msg")
        check("didn't work" in msg, "a still photo of the enrolled face can't sign in (liveness)", msg)
        await pg.screenshot(path=f"{SHOTS}/mugam-photo-refused.png")

        # The same device, signing a real challenge (as after a passed scan), reaches the account.
        ok = await pg.evaluate("""async (USER) => {
          const vault = await import('./vault.js'), A = await import('./api.js');
          const api = await A.connect(); const rec = await vault.get(USER);
          const ch = await api.loginBegin({username: USER});
          const cd = JSON.stringify({type: 'mugam.login', challenge: ch.challenge, origin: location.origin, username: ch.username, deviceId: rec.deviceId, face: {steps: 'test'}});
          await api.loginFinish({challengeId: ch.challengeId, clientData: cd, signature: await vault.sign(rec, cd)});
          const me = await api.me();
          const cookieVisible = document.cookie.includes('mugam');
          return {user: me.username, intact: me.logIntact, cookieVisible};
        }""", USER)
        check(ok.get("user") == USER and ok.get("intact"), "a device-key signature signs in; security log intact", ok)
        check(ok.get("cookieVisible") is False, "the session cookie is invisible to page scripts (HttpOnly)", ok)
        await pg.reload(wait_until="networkidle")
        await pg.wait_for_selector("[data-screen=account]:not([hidden])")
        await pg.screenshot(path=f"{SHOTS}/mugam-account.png", full_page=True)
        check(await pg.is_visible("text=Chain intact"), "account screen shows the chain status")

        # Notice screen (consent) for the record.
        await pg.click("#btn-signout")
        await pg.click("button:has-text('Create an account')")
        await pg.fill("#c-name", "New Person"); await pg.fill("#c-user", "np-" + USER[4:])
        await pg.click("#f-create button[type=submit]")
        await pg.wait_for_selector("[data-screen=notice]:not([hidden])")
        check(await pg.is_disabled("#btn-consent"), "setup can't start before consent is ticked")
        await pg.screenshot(path=f"{SHOTS}/mugam-notice.png")

        check(not csp, "no Content-Security-Policy violations", csp[:3])
        check(not errors, "no page errors", errors[:3])
        check(not missing, "no missing files (404)", missing[:5])

        # GitHub Pages: no server, so the in-browser demo server takes over, with the same rules.
        DEMO = os.environ.get("MUGAM_DEMO_URL")
        if DEMO:
            dp = await ctx.new_page()
            await dp.goto(DEMO, wait_until="networkidle")
            check(await dp.is_visible("#mode"), "without a server, the page says it's a demo")
            d = await dp.evaluate("""async () => {
              const vault = await import('./vault.js'), A = await import('./api.js');
              const api = await A.connect(); const keys = await vault.newKeys(); const out = {mode: api.mode};
              const u = 'demo-' + Date.now().toString(36);
              let ch = await api.registerBegin({username: u});
              let cd = JSON.stringify({type: 'mugam.register', challenge: ch.challenge, origin: location.origin, username: u});
              const reg = await api.registerFinish({challengeId: ch.challengeId, clientData: cd, signature: await vault.sign({keyPair: keys.keyPair}, cd), publicKey: keys.publicJwk, displayName: 'Demo', deviceName: 'Chromium'});
              ch = await api.loginBegin({username: u});
              cd = JSON.stringify({type: 'mugam.login', challenge: ch.challenge, origin: location.origin, username: u, deviceId: reg.deviceId});
              const body = {challengeId: ch.challengeId, clientData: cd, signature: await vault.sign({keyPair: keys.keyPair}, cd)};
              await api.loginFinish(body); out.login = true;
              try { await api.loginFinish(body); out.replay = 'ACCEPTED'; } catch (e) { out.replay = e.status; }
              ch = await api.loginBegin({username: u});
              cd = JSON.stringify({type: 'mugam.login', challenge: ch.challenge, origin: 'https://evil.example', username: u, deviceId: reg.deviceId});
              try { await api.loginFinish({challengeId: ch.challengeId, clientData: cd, signature: await vault.sign({keyPair: keys.keyPair}, cd)}); out.phish = 'ACCEPTED'; } catch (e) { out.phish = e.status; }
              const me = await api.me(); out.intact = me.logIntact; out.codes = reg.recoveryCodes.length;
              return out;
            }""")
            check(d.get("mode") == "demo" and d.get("login") and d.get("codes") == 10, "demo server: register and sign in", d)
            check(d.get("replay") == 401 and d.get("phish") == 401, "demo server refuses replay and wrong origin too", d)
            await dp.screenshot(path=f"{SHOTS}/mugam-demo.png")

        # Phone width
        m = await b.new_context(viewport={"width": 390, "height": 844}, device_scale_factor=2)
        mp = await m.new_page(); await mp.goto(BASE + "/", wait_until="networkidle")
        over = await mp.evaluate("document.documentElement.scrollWidth - innerWidth")
        check(over == 0, "no sideways scroll on a phone", over)
        await mp.screenshot(path=f"{SHOTS}/mugam-phone.png")
        await b.close()
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)

asyncio.run(main())
