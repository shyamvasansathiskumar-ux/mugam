// Mugam landing page: the live bits. Everything here runs in this browser and sends nothing.
(() => {
  const $ = (id) => document.getElementById(id);
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
  const b64 = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

  /* ---------- a real, non-extractable P-256 key signing fresh challenges ---------- */
  async function signer() {
    const s = window.crypto && crypto.subtle;
    if (!s) { $("heroSig").textContent = "needs HTTPS or localhost"; $("heroOk").textContent = "off"; return; }
    let keys;
    try { keys = await s.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]); }
    catch { $("heroSig").textContent = "WebCrypto unavailable"; $("heroOk").textContent = "off"; return; }
    const extractable = keys.privateKey.extractable;      // false: the browser refuses to hand it out
    async function once() {
      const challenge = crypto.getRandomValues(new Uint8Array(16));
      const data = new TextEncoder().encode(JSON.stringify({ type: "mugam.login", challenge: hex(challenge), origin: location.origin }));
      const sig = await s.sign({ name: "ECDSA", hash: "SHA-256" }, keys.privateKey, data);
      const ok = await s.verify({ name: "ECDSA", hash: "SHA-256" }, keys.publicKey, sig, data);
      const short = b64(sig);
      $("heroSig").textContent = short.slice(0, 28) + "…";
      $("heroOk").textContent = ok && !extractable ? "verified" : "check failed";
      $("heroOk").className = "pill " + (ok && !extractable ? "ok" : "bad");
      $("chal").textContent = hex(challenge).slice(0, 16) + "…";
      $("sig").textContent = short.slice(0, 18) + "…";
      $("ver").textContent = ok ? "yes" : "no";
    }
    await once();
    if (!reduce) setInterval(() => { if (!document.hidden) once(); }, 3200);
  }

  /* ---------- the moves card: two random moves, one after the other ---------- */
  function moves() {
    const box = $("moves"), all = ["Turn left", "Turn right", "Blink"];
    function round() {
      const pick = all.slice().sort(() => Math.random() - 0.5).slice(0, 2);
      box.replaceChildren(...pick.map((m) => { const s = document.createElement("span"); s.textContent = m; return s; }));
      const [a, b] = box.children;
      a.className = "on";
      setTimeout(() => { a.className = "done"; b.className = "on"; }, 1400);
      setTimeout(() => { b.className = "done"; }, 2800);
    }
    round();
    if (!reduce) setInterval(round, 4200);
  }

  /* ---------- the match card ---------- */
  function match() {
    const set = () => { const d = 0.24 + Math.random() * 0.14; $("dist").textContent = d.toFixed(2); $("distBar").style.width = (d / 0.5 * 100).toFixed(0) + "%"; };
    set();
    if (!reduce) setInterval(set, 2600);
  }

  /* ---------- the eye aspect ratio ---------- */
  function ear() {
    const eye = $("eyeShape"), val = $("earVal"), RX = 80;
    let t = 0;
    function step() {
      t += 1;
      const phase = t % 90;                                   // a blink about every three seconds
      const ry = phase < 4 ? 26 - phase * 6 : phase < 8 ? 2 + (phase - 4) * 6 : 26;
      eye.setAttribute("ry", String(Math.max(2, ry)));
      val.textContent = (Math.max(2, ry) / RX).toFixed(2);
      requestAnimationFrame(step);
    }
    if (reduce) { val.textContent = (26 / RX).toFixed(2); return; }
    requestAnimationFrame(step);
  }

  /* ---------- the cancelable template: a seeded orthonormal rotation keeps distances ---------- */
  function rng(seed) { let s = seed >>> 0 || 1; return () => ((s = (s * 1664525 + 1013904223) >>> 0) / 4294967296); }
  function gauss(r) { const u = Math.max(1e-12, r()), v = r(); return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v); }
  function rotation(n, seed) {
    const r = rng(seed), Q = [];
    for (let i = 0; i < n; i++) {
      let v = Array.from({ length: n }, () => gauss(r));
      for (let pass = 0; pass < 2; pass++) for (const q of Q) { const d = v.reduce((s, x, k) => s + x * q[k], 0); v = v.map((x, k) => x - d * q[k]); }
      const len = Math.hypot(...v); Q.push(v.map((x) => x / len));
    }
    return Q;
  }
  const apply = (Q, v) => Q.map((row) => row.reduce((s, x, k) => s + x * v[k], 0));
  const dist = (a, b) => Math.hypot(...a.map((x, i) => x - b[i]));
  function template() {
    const r = rng(2026);
    const A = Array.from({ length: 8 }, () => +(gauss(r) * 0.12).toFixed(3));
    const B = A.map((x) => +(x + gauss(r) * 0.02).toFixed(3));
    let seed = 1 + Math.floor(Math.random() * 1e9);
    function row(label, v, rot) {
      const d = document.createElement("div"); d.className = "vr" + (rot ? " rot" : "");
      const l = document.createElement("span"); l.textContent = label; d.append(l);
      v.forEach((x) => { const i = document.createElement("i"); i.textContent = (x >= 0 ? "+" : "") + x.toFixed(2); d.append(i); });
      return d;
    }
    function draw() {
      const Q = rotation(8, seed), RA = apply(Q, A), RB = apply(Q, B);
      $("vecs").replaceChildren(row("Capture A", A), row("Capture B", B), row("A stored", RA, true), row("B stored", RB, true));
      $("d0").textContent = dist(A, B).toFixed(4);
      $("d1").textContent = dist(RA, RB).toFixed(4);
    }
    draw();
    $("reroll").addEventListener("click", () => { seed = 1 + Math.floor(Math.random() * 1e9); draw(); });
  }

  /* ---------- pinned horizontal walkthrough, as on the other project sites ---------- */
  function pin() {
    const sec = $("how"), cards = $("cards");
    if (!window.gsap || !window.ScrollTrigger || (window.Site && Site.reduce) || innerWidth < 900) { sec.classList.add("no-pin"); return; }
    const far = () => Math.max(0, cards.scrollWidth - innerWidth);
    gsap.to(cards, { x: () => -far(), ease: "none",
      scrollTrigger: { trigger: "#hscroll", start: "top 12%", end: () => "+=" + far(), pin: true, scrub: 0.8, invalidateOnRefresh: true, anticipatePin: 1 } });
    gsap.utils.toArray(".step").forEach((s, i) => gsap.from(s, { rotate: 3, y: 60, opacity: 0, duration: 1, ease: "expo.out", delay: i * 0.06,
      scrollTrigger: { trigger: "#hscroll", start: "top 75%", once: true } }));
  }

  signer(); moves(); match(); ear(); template(); pin();
})();
