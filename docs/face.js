// Mugam · camera and face model (face-api, MIT licence, models served from this site).
// Everything here runs in the browser. Frames are analysed in memory and dropped; nothing
// is drawn to a saved image and nothing is uploaded.

import * as faceapi from "./vendor/face-api.esm.js";

let ready = null;
const detector = () => new faceapi.TinyFaceDetectorOptions({ inputSize: 320, scoreThreshold: 0.5 });

export function load() {
  if (!ready) ready = (async () => {
    // WebGL is fast; without it (some locked-down or headless browsers) fall back to plain
    // JavaScript. Never the WASM backend: its files aren't shipped, so it would 404.
    let ok = false;
    try { ok = await faceapi.tf.setBackend("webgl"); } catch { ok = false; }
    if (!ok) await faceapi.tf.setBackend("cpu");
    await faceapi.tf.ready();
    await Promise.all([
      faceapi.nets.tinyFaceDetector.loadFromUri("./models"),
      faceapi.nets.faceLandmark68Net.loadFromUri("./models"),
      faceapi.nets.faceRecognitionNet.loadFromUri("./models"),
    ]);
  })();
  return ready;
}

let stream = null;

export async function start(video) {
  stream = await navigator.mediaDevices.getUserMedia({
    video: { facingMode: "user", width: { ideal: 640 }, height: { ideal: 480 } }, audio: false,
  });
  video.srcObject = stream;
  await video.play();
}

export function stop(video) {
  if (stream) for (const t of stream.getTracks()) t.stop();
  stream = null;
  if (video) video.srcObject = null;
}

/** One frame: how many faces, the main face's box and landmarks. */
export async function look(video) {
  const all = await faceapi.detectAllFaces(video, detector()).withFaceLandmarks();
  if (all.length !== 1) return { faces: all.length };
  const d = all[0];
  return { faces: 1, box: d.detection.box, lm: d.landmarks.positions, score: d.detection.score };
}

/** A 128-number descriptor of the one face in view, or null. */
export async function describe(video) {
  const all = await faceapi.detectAllFaces(video, detector()).withFaceLandmarks().withFaceDescriptors();
  return all.length === 1 ? all[0].descriptor : null;
}

/** Quality gate: the face must be big enough, inside the circle and lit. */
export function quality(video, box, canvas) {
  const w = video.videoWidth, h = video.videoHeight;
  if (!w || !box) return "Looking for your face…";
  if (box.width < w * 0.22) return "Move a little closer";
  const cx = box.x + box.width / 2, cy = box.y + box.height / 2;
  if (Math.abs(cx - w / 2) > w * 0.18 || Math.abs(cy - h / 2) > h * 0.2) return "Centre your face in the circle";
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  canvas.width = 64; canvas.height = 48;
  ctx.drawImage(video, box.x, box.y, box.width, box.height, 0, 0, 64, 48);   // light ON the face, not the room
  const px = ctx.getImageData(0, 0, 64, 48).data;
  let sum = 0;
  for (let i = 0; i < px.length; i += 4) sum += 0.299 * px[i] + 0.587 * px[i + 1] + 0.114 * px[i + 2];
  const lum = sum / (px.length / 4);
  ctx.clearRect(0, 0, 64, 48);
  if (lum < 40) return "It's too dark. Face a light";
  if (lum > 230) return "Too much light on your face";
  return null;
}
