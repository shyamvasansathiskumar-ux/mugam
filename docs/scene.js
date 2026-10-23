// Mugam's world: a face drawn only as the 68 points a face model sees, inside a ring of 72 ticks
// (the same ring the sign-in screen fills), with the device key beside it. The points turn and
// blink for the liveness chapter, scatter for the "faces leak forever" chapter, and swap places
// for the cancelable-template chapter: same face, new numbers.
import { createWorld, THREE, smooth } from "./world.js";

const ACC = new THREE.Color("#b3266b");
const INK = new THREE.Color("#15120e");
const PAPER = new THREE.Color("#efe7d7");

// Keyframes per stage: [x, y, z, scale, scatter, yawAmp, shuffle, keyGlow, camX, camY, camZ]
const K = [
  /* 0 hero      */ [2.75, 0.35, -0.6, 0.92, 0.0, 0.25, 0, 0, 0, 0.6, 9.6],
  /* 1 problem   */ [-3.4, 0.2, -1.2, 0.7, 1.0, 0.1, 0, 0, 0, 0.7, 10.0],
  /* 2 how       */ [3.0, 1.25, -2.2, 0.62, 0.0, 0.2, 0, 0.6, 0, 0.9, 10.2],
  /* 3 liveness  */ [2.5, 0.4, -1.2, 0.95, 0.0, 1.0, 0, 0, 0, 0.7, 10.0],
  /* 4 template  */ [2.6, 0.5, -1.4, 0.9, 0.0, 0.15, 1, 0, 0, 0.9, 10.0],
  /* 5 server    */ [2.4, 0.4, -1.6, 0.8, 0.0, 0.1, 0, 1, 0, 0.9, 10.0],
  /* 6 proof     */ [2.5, 0.2, -1.8, 0.85, 0.0, 0.2, 0, 0.3, 0, 1.2, 10.4],
  /* 7 limits    */ [-3.7, 0.4, -2.2, 0.62, 0.25, 0.1, 0, 0, 0, 1.2, 10.6],
  /* 8 run       */ [3.3, 1.8, -3.4, 0.5, 0.0, 0.25, 0, 0.4, 0, 1.2, 10.8],
  /* end         */ [2.6, 0.5, -1.6, 0.95, 0.0, 0.25, 0, 0.4, 0, 0.8, 10.0],
];
const MOBILE = (k, i) => i === 0 ? [1.1, 3.4, -1.5, 0.52, k[4], k[5], k[6], k[7], 0, 0.6, 12.5] : [1.3, 3.45, -2.5, 0.44, k[4], k[5], k[6], k[7], 0, 0.6, 12.5];

function frame(stage, mobile) {
  const i = Math.max(0, Math.min(K.length - 2, Math.floor(stage)));
  const f = smooth(0.15, 0.85, stage - i);
  const a = mobile ? MOBILE(K[i], i) : K[i], b = mobile ? MOBILE(K[i + 1], i + 1) : K[i + 1];
  return a.map((v, j) => v + (b[j] - v) * f);
}

/** The 68-point layout (iBUG 300-W order), drawn as a front-facing face of height ~2.6 units. */
function landmarks() {
  const p = [];
  // 0-16 jaw: a U from ear to ear
  for (let i = 0; i <= 16; i++) { const a = Math.PI * (1.08 + (i / 16) * 0.84); p.push([Math.cos(a) * 1.0, 0.25 + Math.sin(a) * 1.18]); }
  // 17-21, 22-26 brows
  for (let i = 0; i < 5; i++) p.push([-0.78 + i * 0.16, 0.62 + Math.sin((i / 4) * Math.PI) * 0.1]);
  for (let i = 0; i < 5; i++) p.push([0.14 + i * 0.16, 0.62 + Math.sin((i / 4) * Math.PI) * 0.1]);
  // 27-30 nose bridge, 31-35 nose base
  for (let i = 0; i < 4; i++) p.push([0, 0.45 - i * 0.16]);
  for (let i = 0; i < 5; i++) p.push([-0.18 + i * 0.09, -0.12 + Math.abs(i - 2) * 0.03]);
  // 36-41 right eye, 42-47 left eye (six points each)
  const eye = (cx) => { for (let i = 0; i < 6; i++) { const a = Math.PI - (i / 6) * Math.PI * 2; p.push([cx + Math.cos(a) * 0.17, 0.36 + Math.sin(a) * 0.07]); } };
  eye(-0.45); eye(0.45);
  // 48-59 outer lip, 60-67 inner lip
  for (let i = 0; i < 12; i++) { const a = Math.PI - (i / 12) * Math.PI * 2, sn = Math.sin(a); p.push([Math.cos(a) * 0.38, -0.55 + sn * (sn > 0 ? 0.1 : 0.17)]); }
  for (let i = 0; i < 8; i++) { const a = Math.PI - (i / 8) * Math.PI * 2; p.push([Math.cos(a) * 0.22, -0.55 + Math.sin(a) * 0.035]); }
  // depth: points sit on a soft ellipsoid so the face reads as a face when it turns
  return p.map(([x, y]) => new THREE.Vector3(x, y, 0.55 * Math.sqrt(Math.max(0, 1 - (x / 1.15) ** 2 - ((y - 0.1) / 1.45) ** 2)) + (Math.abs(x) < 0.05 && y < 0.45 && y > -0.2 ? 0.18 : 0)));
}

// contours, as index runs, for the thin lines between the points
const RUNS = [[0, 16], [17, 21], [22, 26], [27, 30], [31, 35], [36, 41, true], [42, 47, true], [48, 59, true], [60, 67, true]];

createWorld(document.getElementById("world"), async ({ scene, camera, mobile }) => {
  const pts = landmarks();
  const N = pts.length;

  const face = new THREE.Group();
  scene.add(face);

  // the "mirror": a thin glass oval the points float in front of
  const glass = new THREE.Mesh(new THREE.CircleGeometry(1, 96), new THREE.MeshPhysicalMaterial({ color: "#f6f1e7", roughness: 0.18, metalness: 0, transparent: true, opacity: 0.55, clearcoat: 1, side: THREE.DoubleSide }));
  glass.scale.set(1.3, 1.62, 1); glass.position.z = -0.12; glass.receiveShadow = true;
  face.add(glass);
  const rim = new THREE.Mesh(new THREE.TorusGeometry(1, 0.012, 8, 160), new THREE.MeshStandardMaterial({ color: INK, roughness: 0.5 }));
  rim.scale.set(1.3, 1.62, 1); rim.position.z = -0.12;
  face.add(rim);

  // the 68 points
  const dot = new THREE.InstancedMesh(new THREE.SphereGeometry(0.045, 16, 12), new THREE.MeshStandardMaterial({ color: 0xffffff, roughness: 0.35 }), N);
  dot.castShadow = true;
  face.add(dot);
  // the lines
  const segCount = RUNS.reduce((s, [a, b, loop]) => s + (b - a) + (loop ? 1 : 0), 0);
  const lineGeo = new THREE.BufferGeometry();
  const linePos = new Float32Array(segCount * 6);
  lineGeo.setAttribute("position", new THREE.BufferAttribute(linePos, 3));
  const lines = new THREE.LineSegments(lineGeo, new THREE.LineBasicMaterial({ color: INK, transparent: true, opacity: 0.35 }));
  face.add(lines);

  // the ring: 72 ticks, the same count as the sign-in screen
  const ring = new THREE.Group();
  scene.add(ring);
  const TN = 72, RR = 1.95;
  const ticks = new THREE.InstancedMesh(new THREE.BoxGeometry(0.03, 0.22, 0.03), new THREE.MeshStandardMaterial({ color: 0xffffff, roughness: 0.6 }), TN);
  ticks.castShadow = true;
  ring.add(ticks);

  // the device key: bow, shaft and bits, in brass
  const brass = new THREE.MeshPhysicalMaterial({ color: "#c49a3a", roughness: 0.28, metalness: 0.9, clearcoat: 0.4 });
  const key = new THREE.Group();
  const bow = new THREE.Mesh(new THREE.TorusGeometry(0.26, 0.07, 18, 48), brass);
  const shaft = new THREE.Mesh(new THREE.CylinderGeometry(0.05, 0.05, 1.1, 20), brass);
  shaft.rotation.z = Math.PI / 2; shaft.position.x = 0.8;
  const bit1 = new THREE.Mesh(new THREE.BoxGeometry(0.08, 0.2, 0.06), brass); bit1.position.set(1.2, -0.12, 0);
  const bit2 = new THREE.Mesh(new THREE.BoxGeometry(0.08, 0.14, 0.06), brass); bit2.position.set(1.04, -0.09, 0);
  [bow, shaft, bit1, bit2].forEach((m) => { m.castShadow = true; key.add(m); });
  key.scale.setScalar(0.85);
  scene.add(key);

  // a fixed shuffle for the template chapter: each point moves to another point's place
  const rand = (() => { let s = 7; return () => ((s = (s * 16807) % 2147483647) / 2147483647); })();
  const perm = [...Array(N).keys()];
  for (let i = N - 1; i > 0; i--) { const j = Math.floor(rand() * (i + 1)); [perm[i], perm[j]] = [perm[j], perm[i]]; }
  const scatterDir = pts.map(() => new THREE.Vector3(rand() - 0.5, rand() - 0.5, rand() - 0.5).normalize().multiplyScalar(1.4 + rand() * 1.6));

  const m4 = new THREE.Matrix4(), q = new THREE.Quaternion(), s3 = new THREE.Vector3(), v3 = new THREE.Vector3(), zAxis = new THREE.Vector3(0, 0, 1);
  const col = new THREE.Color();
  const cur = pts.map((p) => p.clone());
  const look = new THREE.Vector3();

  scene.userData.logo = [face, ring];   // shown small and centred while the page loads

  return (st) => {
    const [x, y, z, sc, scatter, yawAmp, shuffle, keyGlow, cx, cy, cz] = frame(st.stage, st.mobile);
    const t = st.t;

    // liveness: turn left, turn right, blink, on a loop
    const cyc = (t % 6) / 6;
    const yaw = Math.sin(cyc * Math.PI * 2) * 0.55 * yawAmp + st.px * 0.3;
    const blink = yawAmp > 0.5 ? Math.max(0, 1 - Math.abs(((t % 3.2) - 2.9) / 0.12)) : 0;

    face.position.set(x, y + Math.sin(t * 0.8) * 0.05, z);
    face.scale.setScalar(sc);
    face.rotation.set(0.04 + st.py * 0.1, yaw, 0);

    // points: scatter outward, swap places, or blink
    const sh = smooth(0, 1, shuffle) * (0.5 - 0.5 * Math.cos(Math.min(1, (t % 5) / 2.5) * Math.PI * 2));
    for (let i = 0; i < N; i++) {
      const home = pts[i], other = pts[perm[i]];
      cur[i].lerpVectors(home, other, sh);
      cur[i].addScaledVector(scatterDir[i], scatter);
      if ((i >= 37 && i <= 38) || (i >= 43 && i <= 44)) cur[i].y -= blink * 0.06;
      if ((i >= 40 && i <= 41) || (i >= 46 && i <= 47)) cur[i].y += blink * 0.06;
      s3.setScalar(i >= 36 && i <= 47 ? 1.15 : 1);
      m4.compose(cur[i], q.identity(), s3);
      dot.setMatrixAt(i, m4);
      dot.setColorAt(i, col.copy(i >= 36 && i <= 47 ? ACC : INK));
    }
    dot.instanceMatrix.needsUpdate = true; dot.instanceColor.needsUpdate = true;
    let k = 0;
    for (const [a, b, loop] of RUNS) {
      const end = loop ? b + 1 : b;
      for (let i = a; i < end; i++) {
        const p0 = cur[i], p1 = cur[i === b ? a : i + 1];
        linePos.set([p0.x, p0.y, p0.z, p1.x, p1.y, p1.z], k); k += 6;
      }
    }
    lineGeo.attributes.position.needsUpdate = true;
    lines.material.opacity = 0.35 * (1 - Math.min(1, scatter + sh * 1.6));

    // the ring fills like the scan on the sign-in screen
    ring.position.set(x, y, z - 0.2);
    ring.scale.setScalar(sc);
    ring.rotation.set(0, yaw * 0.15, 0);
    const fill = (t * 0.22) % 1.25;
    for (let i = 0; i < TN; i++) {
      const a = Math.PI / 2 - (i / TN) * Math.PI * 2;
      v3.set(Math.cos(a) * RR, Math.sin(a) * RR * 1.08, 0);
      q.setFromAxisAngle(zAxis, a - Math.PI / 2);
      const on = i / TN < fill;
      s3.set(1, on ? 1.25 : 0.8, 1);
      m4.compose(v3, q, s3); ticks.setMatrixAt(i, m4);
      ticks.setColorAt(i, col.copy(on ? (scatter > 0.5 ? INK : ACC) : PAPER));
    }
    ticks.instanceMatrix.needsUpdate = true; ticks.instanceColor.needsUpdate = true;

    // the key turns slowly beside the face, and warms when the server chapter is on
    key.position.set(x + 0.55 * sc, y - 1.85 * sc + Math.sin(t * 1.1) * 0.05, z + 0.7);
    key.rotation.set(0.3, t * 0.4, -0.25);
    key.scale.setScalar(0.6 * sc * (1 + keyGlow * 0.25));
    brass.emissive = brass.emissive || new THREE.Color();
    brass.emissive.setRGB(0.25 * keyGlow, 0.16 * keyGlow, 0.02 * keyGlow);

    camera.position.set(cx + st.px * 0.35, cy - st.py * 0.2, cz);
    look.set(cx * 0.6, 0.2 + (cy - 0.5) * 0.15, -2);
    camera.lookAt(look);
  };
}, { bg: "#e8e1d3", fog: [10, 40] });
