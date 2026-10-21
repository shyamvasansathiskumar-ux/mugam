// Mugam · liveness: is this a live person in front of the camera right now?
//
// A printed photo or a phone held up to the camera can match a face. So, at sign-in, Mugam
// asks for a short, random sequence of movements (turn left, turn right, blink), in an order
// an attacker can't predict, within a few seconds each, while checking that it stays the same
// single face throughout. These are pure functions over the 68 facial landmarks, so they
// can be tested without a camera.
//
// Honest limit: a webcam sees no depth. A good video deepfake or a 3D mask could pass. That
// is why the face only unlocks a key that lives on this device: an attacker would need your
// device too.

const avg = (pts) => ({ x: pts.reduce((s, p) => s + p.x, 0) / pts.length, y: pts.reduce((s, p) => s + p.y, 0) / pts.length });
const dist = (a, b) => Math.hypot(a.x - b.x, a.y - b.y);

/**
 * Head turn, as a number: the nose tip's sideways offset from the middle of the eyes,
 * divided by the distance between the eyes. About 0 facing the camera. Positive = the
 * person turned to THEIR left (their nose moves to the right of the raw camera image).
 */
export function yaw(lm) {
  const l = avg(lm.slice(36, 42)), r = avg(lm.slice(42, 48));
  const mid = { x: (l.x + r.x) / 2, y: (l.y + r.y) / 2 };
  return (lm[30].x - mid.x) / dist(l, r);
}

/** Eye aspect ratio: eye height over eye width (Soukupová & Čech, 2016). Drops sharply in a blink. */
export function ear(lm) {
  const one = (p) => (dist(p[1], p[5]) + dist(p[2], p[4])) / (2 * dist(p[0], p[3]));
  return (one(lm.slice(36, 42)) + one(lm.slice(42, 48))) / 2;
}

export const TURN = 0.2;          // how far counts as a turn (relative to the person's own straight-on value)
export const CENTER = 0.08;       // back to facing the camera
export const STEP_MS = 7000;      // time allowed per movement

export const ACTIONS = ["turnLeft", "turnRight", "blink"];

/** Two different movements in a random order, from a cryptographic random source. */
export function randomChallenge(rand = (n) => globalThis.crypto.getRandomValues(new Uint32Array(1))[0] % n) {
  const pool = ACTIONS.slice();
  const out = [];
  while (out.length < 2) out.push(pool.splice(rand(pool.length), 1)[0]);
  return out;
}

/**
 * Runs one challenge over a stream of frames. Feed it frame(...) for every video frame;
 * it says what to show and when it's done. A frame with no face or more than one face, or
 * a face that jumps across the picture (a swapped photo), fails the whole attempt.
 */
export class Challenge {
  constructor(steps, now) {
    this.steps = steps;
    this.i = -1;            // -1: first capture the straight-on baseline
    this.start = now;
    this.stepStart = now;
    this.baseYaw = null;
    this.baseEar = null;
    this.calib = [];
    this.hits = 0;
    this.closed = false;
    this.lastBox = null;
    this.result = null;     // "pass" | "fail:<reason>"
    this.mustCenter = false;
  }

  instruction() {
    if (this.result) return "";
    if (this.i < 0) return "Look straight at the camera";
    if (this.mustCenter) return "Now look straight ahead";
    return { turnLeft: "Turn your head slowly to the left", turnRight: "Turn your head slowly to the right", blink: "Blink once" }[this.steps[this.i]];
  }

  progress() { return this.result === "pass" ? 1 : Math.max(0, (this.i + (this.mustCenter ? 0.75 : 0)) / this.steps.length); }

  fail(why) { this.result = "fail:" + why; return this.result; }

  /** faces: how many faces; box: {x,y,width,height}; lm: 68 landmarks of the one face. */
  frame(faces, box, lm, now) {
    if (this.result) return this.result;
    if (faces > 1) return this.fail("more than one face");
    if (faces === 0) { if (now - this.stepStart > STEP_MS) return this.fail("no face"); return null; }
    if (this.lastBox) {
      const jump = Math.hypot((box.x + box.width / 2) - (this.lastBox.x + this.lastBox.width / 2),
                              (box.y + box.height / 2) - (this.lastBox.y + this.lastBox.height / 2));
      const resize = Math.abs(box.width - this.lastBox.width) / this.lastBox.width;
      if (jump > 0.5 * this.lastBox.width || resize > 0.35) return this.fail("the face jumped");
    }
    this.lastBox = box;
    const y = yaw(lm), e = ear(lm);

    if (this.i < 0) {                                   // baseline: 5 steady straight-on frames
      this.calib.push({ y, e });
      if (this.calib.length >= 5) {
        const ys = this.calib.map((c) => c.y);
        if (Math.max(...ys) - Math.min(...ys) > 0.1) { this.calib = []; return null; }
        this.baseYaw = ys.reduce((a, b) => a + b, 0) / ys.length;
        this.baseEar = this.calib.reduce((a, c) => a + c.e, 0) / this.calib.length;
        this.i = 0; this.stepStart = now; this.hits = 0;
      } else if (now - this.stepStart > STEP_MS) return this.fail("couldn't see your face clearly");
      return null;
    }

    const dy = y - this.baseYaw;
    if (this.mustCenter) {
      if (Math.abs(dy) < CENTER && e > 0.8 * this.baseEar) {
        this.mustCenter = false; this.i++; this.stepStart = now; this.hits = 0; this.closed = false;
        if (this.i >= this.steps.length) this.result = "pass";
      } else if (now - this.stepStart > STEP_MS) return this.fail("didn't come back to the centre");
      return this.result;
    }

    if (now - this.stepStart > STEP_MS) return this.fail("too slow");
    const want = this.steps[this.i];
    let ok = false;
    if (want === "turnLeft") ok = dy > TURN;
    else if (want === "turnRight") ok = dy < -TURN;
    else if (want === "blink") {
      if (e < 0.6 * this.baseEar) this.closed = true;              // eyes shut...
      else if (this.closed && e > 0.85 * this.baseEar) ok = true;  // ...and open again
    }
    if (want !== "blink" && Math.abs(dy) > TURN && Math.sign(dy) !== (want === "turnLeft" ? 1 : -1))
      return this.fail("turned the wrong way");
    this.hits = ok ? this.hits + 1 : (want === "blink" ? this.hits : 0);
    if (this.hits >= (want === "blink" ? 1 : 2)) { this.mustCenter = true; this.stepStart = now; }
    return null;
  }
}
