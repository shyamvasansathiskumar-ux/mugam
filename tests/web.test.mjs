// Node tests for the browser logic that doesn't need a camera: templates and liveness.
import { rotation, project, distance, mean, consistent, MATCH_THRESHOLD } from "../docs/template.js";
import { yaw, ear, Challenge, randomChallenge, ACTIONS, STEP_MS } from "../docs/liveness.js";

let passed = 0, failed = 0;
const test = async (name, fn) => {
  try { await fn(); passed++; console.log("  PASS  " + name); }
  catch (e) { failed++; console.log("  FAIL  " + name + "\n        " + e.message); }
};
const check = (ok, msg) => { if (!ok) throw new Error(msg); };
const seed = (b) => new Uint8Array(32).fill(b);
const vec = (f) => Float32Array.from({ length: 128 }, (_, k) => f(k));

// A synthetic face: 68 landmarks with eyes, nose and controllable turn and eye openness.
function face({ turn = 0, open = 1, cx = 320, cy = 240, size = 100 } = {}) {
  const lm = Array.from({ length: 68 }, () => ({ x: cx, y: cy }));
  const eye = (x0, start) => {
    const w = size * 0.25, h = w * 0.3 * open;
    const pts = [[0, 0], [w / 3, -h], [2 * w / 3, -h], [w, 0], [2 * w / 3, h], [w / 3, h]];
    pts.forEach(([dx, dy], i) => { lm[start + i] = { x: x0 + dx, y: cy - size * 0.1 + dy }; });
  };
  eye(cx - size * 0.4, 36);
  eye(cx + size * 0.15, 42);
  const iod = (cx + size * 0.15 + size * 0.125) - (cx - size * 0.4 + size * 0.125);
  lm[30] = { x: cx - size * 0.125 + size * 0.125 + turn * iod, y: cy + size * 0.1 };
  return lm;
}
const box = (cx = 320, w = 200) => ({ x: cx - w / 2, y: 140, width: w, height: w });

console.log("\nTemplates");
await test("the secret rotation is orthonormal (rows have length 1 and are perpendicular)", async () => {
  const Q = await rotation(seed(7));
  for (let i = 0; i < 128; i += 17) for (let j = 0; j < 128; j += 13) {
    let d = 0; for (let k = 0; k < 128; k++) d += Q[i][k] * Q[j][k];
    check(Math.abs(d - (i === j ? 1 : 0)) < 1e-9, `Q${i}·Q${j} = ${d}`);
  }
});
await test("same seed gives the same rotation; another seed gives a different one", async () => {
  const a = await rotation(seed(1)), b = await rotation(seed(1)), c = await rotation(seed(2));
  check(a[5][9] === b[5][9] && a[5][9] !== c[5][9], "determinism");
});
await test("rotation keeps distances exactly, so matching accuracy doesn't change", async () => {
  const Q = await rotation(seed(3));
  const x = vec((k) => Math.sin(k)), y = vec((k) => Math.cos(k * 1.3) * 0.4);
  check(Math.abs(distance(x, y) - distance(project(Q, x), project(Q, y))) < 1e-4, "distance changed");
});
await test("cancelable: the same face under two seeds is far apart (an old template can't be matched)", async () => {
  const x = vec((k) => Math.sin(k * 0.7) * 0.3);
  const d = distance(project(await rotation(seed(4)), x), project(await rotation(seed(5)), x));
  check(d > 3 * MATCH_THRESHOLD, `only ${d.toFixed(3)} apart`);
});
await test("enrolment refuses an inconsistent set of captures (a face swapped mid-way)", () => {
  const a = vec((k) => Math.sin(k) * 0.1), b = vec((k) => Math.sin(k) * 0.1 + 0.002), c = vec((k) => Math.cos(k) * 0.3);
  check(consistent([a, b]) && !consistent([a, b, c]), "consistency");
  check(Math.abs(mean([a, b])[3] - (a[3] + b[3]) / 2) < 1e-7, "mean");
});

console.log("\nLiveness");
await test("yaw is about 0 straight on, positive when the person turns left", () => {
  check(Math.abs(yaw(face())) < 0.01, "straight " + yaw(face()));
  check(yaw(face({ turn: 0.3 })) > 0.25 && yaw(face({ turn: -0.3 })) < -0.25, "turns");
});
await test("eye aspect ratio drops when the eyes close", () => {
  check(ear(face({ open: 0.2 })) < 0.5 * ear(face()), `${ear(face({ open: 0.2 }))} vs ${ear(face())}`);
});
await test("a random challenge is two different movements", () => {
  for (let k = 0; k < 50; k++) {
    const c = randomChallenge();
    check(c.length === 2 && c[0] !== c[1] && c.every((a) => ACTIONS.includes(a)), c.join());
  }
});
function run(steps, frames) {
  const ch = new Challenge(steps, 0);
  let t = 0, r = null;
  for (const f of frames) { t += 100; r = ch.frame(f.n ?? 1, f.box ?? box(), f.lm, t) || r; if (ch.result) break; }
  return ch.result;
}
const still = (n, opts) => Array.from({ length: n }, () => ({ lm: face(opts) }));
await test("a live person doing turn-left then blink passes", () => {
  const frames = [...still(6), ...still(3, { turn: 0.3 }), ...still(3), ...still(2, { open: 0.2 }), ...still(2), ...still(3)];
  check(run(["turnLeft", "blink"], frames) === "pass", "result " + run(["turnLeft", "blink"], frames));
});
await test("a still photo fails: it never moves, so the challenge times out", () => {
  const r = run(["turnRight", "blink"], still(Math.ceil(STEP_MS / 100) + 20));
  check(r && r.startsWith("fail"), "photo passed: " + r);
});
await test("turning the wrong way fails at once", () => {
  check(run(["turnLeft", "blink"], [...still(6), ...still(3, { turn: -0.35 })]) === "fail:turned the wrong way", "wrong way");
});
await test("a second face in the picture fails", () => {
  check(run(["turnLeft", "blink"], [...still(3), { n: 2, lm: face() }]) === "fail:more than one face", "two faces");
});
await test("a face that jumps across the picture (a swapped photo) fails", () => {
  check(run(["turnLeft", "blink"], [...still(6), { lm: face({ cx: 600 }), box: box(600) }]) === "fail:the face jumped", "jump");
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
