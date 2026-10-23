// The landing page's 3D film, drawn with three.js and no model files (every sheet is a canvas texture), so it
// works offline. The scene is a function of one number, progress 0..1, driven by scroll. Eight chapters:
//   0.000  hero          the source sheet scans itself on a loop
//   0.125  targets       a running app, a folder and a GitHub repo
//   0.250  scanners      eight scanner tags orbit and sweep the code, flagging risky lines
//   0.375  evidence      the live app is linked to the code; candidate -> corroborated -> CONFIRMED
//   0.500  fix           fixed code fades in over the flagged lines (verified on a copy)
//   0.625  approve       the human-approval stamp lands
//   0.750  two modes     Offline and Gemini cards with a switch between them
//   0.875  finale        hold
import { useEffect, useRef } from "react";
import * as THREE from "three";

const C = { paper: "#f7f3ea", paper2: "#eee9dd", ink: "#15130f", mut: "#6b6557", line: "#b0a892", red: "#b3261e", green: "#1f6f5c" };
const MONO = 'Consolas, "Cascadia Mono", ui-monospace, monospace';
const SANS = 'Inter, "Segoe UI", system-ui, sans-serif';

const SW = 2.6, SH = 3.3; // sheet size in world units
const CW = 900, CH = 1140; // sheet texture size in px
const px = (n) => (n / CH) * SH; // texture px -> world units (vertical)

const clamp01 = (x) => Math.min(1, Math.max(0, x));
const seg = (p, a, b) => clamp01((p - a) / (b - a));
const ease = (t) => (t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2);

// ---- the text on the sheets --------------------------------------------------------------------------------
const CODE = [
  { t: "# app/routes.py" },
  { t: "" },
  { t: "def search(term):" },
  { t: "  q = \"SELECT * FROM items WHERE t='\"+term", fix: '  q = "SELECT * FROM items WHERE t = ?"', flag: true },
  { t: "  rows = db.execute(q).fetchall()", fix: "  rows = db.execute(q, (term,)).fetchall()", flag: true },
  { t: "  return jsonify(rows)" },
  { t: "" },
  { t: "def login(name, pw):" },
  { t: "  row = users.get(name)" },
  { t: "  if pw == row.password:", fix: "  if argon2.verify(row.hash, pw):", flag: true },
  { t: '  return jwt.encode(row, "secret123")', fix: "  return jwt.encode(row, env('JWT_SECRET'))", flag: true },
  { t: "  return None" },
];
const CODE_TOP = 214, LINE_H = 58;
const lineY = (i) => CODE_TOP + i * LINE_H + LINE_H / 2; // centre of code line i, in texture px

const ROUTES = [
  { t: "GET   /api/items" },
  { t: "GET   /api/search?term=", hit: 3 },
  { t: "POST  /login", hit: 9 },
  { t: "GET   /api/accounts/{id}" },
];
const ROUTE_TOP = 214, ROUTE_H = 64;
const routeY = (i) => ROUTE_TOP + i * ROUTE_H + ROUTE_H / 2;

// ---- canvas helpers -----------------------------------------------------------------------------------------
function sheetCanvas(title, tag) {
  const c = document.createElement("canvas");
  c.width = CW;
  c.height = CH;
  const g = c.getContext("2d");
  g.fillStyle = C.paper;
  g.fillRect(0, 0, CW, CH);
  g.strokeStyle = C.line;
  g.lineWidth = 4;
  g.strokeRect(2, 2, CW - 4, CH - 4);
  g.fillStyle = C.paper2;
  g.fillRect(2, 2, CW - 4, 120);
  g.strokeStyle = C.line;
  g.beginPath();
  g.moveTo(2, 122);
  g.lineTo(CW - 2, 122);
  g.stroke();
  g.fillStyle = C.ink;
  g.font = `600 34px ${MONO}`;
  g.textBaseline = "middle";
  g.fillText(title, 44, 62);
  if (tag) {
    g.font = `500 26px ${MONO}`;
    g.fillStyle = C.mut;
    g.textAlign = "right";
    g.fillText(tag, CW - 44, 62);
    g.textAlign = "left";
  }
  return [c, g];
}

const texOf = (canvas) => {
  const t = new THREE.CanvasTexture(canvas);
  t.colorSpace = THREE.SRGBColorSpace;
  t.anisotropy = 8;
  return t;
};

function codeTexture(fixed) {
  const [c, g] = sheetCanvas(fixed ? "app/routes.py  ✓" : "app/routes.py", fixed ? "FIXED" : "SOURCE");
  g.textBaseline = "middle";
  CODE.forEach((l, i) => {
    const y = lineY(i);
    const swap = fixed && l.fix;
    if (swap) {
      g.fillStyle = "rgba(31,111,92,0.16)";
      g.fillRect(14, y - LINE_H / 2 + 4, CW - 28, LINE_H - 8);
    }
    g.fillStyle = C.mut;
    g.font = `26px ${MONO}`;
    g.fillText(String(i + 12), 40, y);
    g.fillStyle = swap ? C.green : l.t.startsWith("#") ? C.mut : C.ink;
    g.font = `27px ${MONO}`;
    g.fillText(swap ? l.fix : l.t, 100, y);
  });
  g.font = `500 26px ${MONO}`;
  g.fillStyle = fixed ? C.green : C.mut;
  g.fillText(fixed ? "✓ re-scan on copy: 0 findings · tests pass" : "scanning…", 44, CH - 70);
  return texOf(c);
}

function appTexture() {
  const [c, g] = sheetCanvas("RUNNING APP", "127.0.0.1:5000");
  g.textBaseline = "middle";
  ROUTES.forEach((r, i) => {
    const y = routeY(i);
    g.strokeStyle = C.line;
    g.lineWidth = 2;
    g.beginPath();
    g.moveTo(40, y + ROUTE_H / 2);
    g.lineTo(CW - 40, y + ROUTE_H / 2);
    g.stroke();
    g.fillStyle = C.ink;
    g.font = `27px ${MONO}`;
    g.fillText(r.t, 44, y);
  });
  g.fillStyle = C.mut;
  g.font = `500 24px ${MONO}`;
  g.fillText("IDENTITIES", 44, 560);
  g.font = `27px ${MONO}`;
  g.fillStyle = C.ink;
  g.fillText("alice   (user)", 44, 612);
  g.fillText("bob     (user)", 44, 664);
  g.fillText("admin   (admin)", 44, 716);
  g.fillStyle = C.mut;
  g.font = `500 24px ${MONO}`;
  g.fillText("CHECKS", 44, 800);
  g.font = `27px ${MONO}`;
  g.fillStyle = C.ink;
  ["openapi fuzzing", "access control (BOLA)", "SSRF witness", "nuclei templates"].forEach((s, i) => g.fillText("· " + s, 44, 852 + i * 52));
  return texOf(c);
}

function evidenceTexture() {
  const [c, g] = sheetCanvas("EVIDENCE · F-0127", "OWASP A03");
  g.textBaseline = "middle";
  const chips = ["CANDIDATE", "CORROBORATED", "CONFIRMED"];
  let x = 44;
  chips.forEach((s, i) => {
    g.font = `600 22px ${MONO}`;
    const w = g.measureText(s).width + 36;
    if (i === 2) {
      g.fillStyle = C.ink;
      g.fillRect(x, 170, w, 56);
      g.fillStyle = C.paper;
    } else {
      g.strokeStyle = C.line;
      g.lineWidth = 2;
      g.strokeRect(x, 170, w, 56);
      g.fillStyle = C.mut;
    }
    g.fillText(s, x + 18, 199);
    x += w - 2;
  });
  g.fillStyle = C.red;
  g.font = `600 30px ${SANS}`;
  g.fillText("SQL injection", 44, 310);
  g.fillStyle = C.mut;
  g.font = `26px ${MONO}`;
  g.fillText("GET /api/search?term=", 44, 362);
  g.fillStyle = C.ink;
  g.font = `27px ${MONO}`;
  g.fillText("term = ' OR 1=1 --", 44, 440);
  g.fillText("→ 200 · 14 rows returned", 44, 494);
  g.fillStyle = C.mut;
  g.fillText("  (expected: 0)", 44, 548);
  g.strokeStyle = C.line;
  g.beginPath();
  g.moveTo(44, 610);
  g.lineTo(CW - 44, 610);
  g.stroke();
  g.fillStyle = C.ink;
  g.font = `600 27px ${MONO}`;
  g.fillText("code: app/routes.py:15", 44, 670);
  g.fillText("route: GET /api/search", 44, 724);
  g.fillText("risk: 0.91", 44, 778);
  g.fillStyle = C.mut;
  g.font = `24px ${MONO}`;
  g.fillText("evidence E-0412 · secrets redacted", 44, CH - 70);
  return texOf(c);
}

function stampTexture() {
  const c = document.createElement("canvas");
  c.width = c.height = 512;
  const g = c.getContext("2d");
  g.translate(256, 256);
  g.strokeStyle = C.red;
  g.fillStyle = C.red;
  g.lineWidth = 12;
  g.beginPath();
  g.arc(0, 0, 232, 0, Math.PI * 2);
  g.stroke();
  g.lineWidth = 5;
  g.beginPath();
  g.arc(0, 0, 138, 0, Math.PI * 2);
  g.stroke();
  const text = "VERIFIED · APPROVED · PROVEN · ";
  g.font = `700 40px ${MONO}`;
  g.textAlign = "center";
  g.textBaseline = "middle";
  const step = (Math.PI * 2) / text.length;
  for (let i = 0; i < text.length; i++) {
    g.save();
    g.rotate(i * step - Math.PI / 2);
    g.fillText(text[i], 0, -185);
    g.restore();
  }
  g.lineWidth = 26;
  g.lineCap = "square";
  g.beginPath();
  g.moveTo(-58, 6);
  g.lineTo(-14, 52);
  g.lineTo(62, -48);
  g.stroke();
  return texOf(c);
}

function bandTexture() {
  const c = document.createElement("canvas");
  c.width = 4;
  c.height = 64;
  const g = c.getContext("2d");
  const gr = g.createLinearGradient(0, 0, 0, 64);
  gr.addColorStop(0, "rgba(179,38,30,0)");
  gr.addColorStop(1, "rgba(179,38,30,0.35)");
  g.fillStyle = gr;
  g.fillRect(0, 0, 4, 64);
  return texOf(c);
}

// ---- more sheets: the other two targets, the scanner tags and the two mode cards -----------------------------
function folderTexture() {
  const [c, g] = sheetCanvas("FOLDER  ·  M2", "./my-app");
  g.textBaseline = "middle";
  const rows = ["my-app/", "├─ app/", "│  ├─ routes.py", "│  ├─ models.py", "│  └─ auth.py", "├─ requirements.txt", "├─ Dockerfile", "└─ .env"];
  rows.forEach((r, i) => {
    g.fillStyle = i === 0 ? C.ink : r.includes(".env") ? C.red : C.ink;
    g.font = `${i === 0 ? 600 : 400} 30px ${MONO}`;
    g.fillText(r, 52, 220 + i * 64);
  });
  g.fillStyle = C.mut;
  g.font = `500 24px ${MONO}`;
  g.fillText("SBOM · secrets · SAST · CBOM", 52, CH - 70);
  return texOf(c);
}

function repoTexture() {
  const [c, g] = sheetCanvas("GITHUB REPO  ·  M2", "public");
  g.textBaseline = "middle";
  g.fillStyle = C.ink;
  g.font = `600 30px ${MONO}`;
  g.fillText("github.com/owner/name", 52, 190);
  const xs = [150, 150, 150, 150, 150];
  g.strokeStyle = C.line2;
  g.lineWidth = 5;
  g.beginPath();
  g.moveTo(150, 270);
  g.lineTo(150, 900);
  g.stroke();
  g.strokeStyle = C.red;
  g.beginPath();
  g.moveTo(150, 430);
  g.bezierCurveTo(150, 500, 300, 480, 300, 560);
  g.lineTo(300, 700);
  g.bezierCurveTo(300, 770, 150, 750, 150, 800);
  g.stroke();
  [300, 430, 560, 700, 800, 900].forEach((y, i) => {
    const x = i === 2 || i === 3 ? 300 : 150;
    g.fillStyle = i === 2 || i === 3 ? C.red : C.ink;
    g.beginPath();
    g.arc(x, y, 15, 0, Math.PI * 2);
    g.fill();
  });
  g.fillStyle = C.ink;
  g.font = `26px ${MONO}`;
  g.fillText("main", 200, 300);
  g.fillText("fix: validate input", 200, 430);
  g.fillStyle = C.red;
  g.fillText("feature/login", 350, 600);
  g.fillStyle = C.mut;
  g.fillText("142 commits · 6 contributors", 52, CH - 70);
  void xs;
  return texOf(c);
}

function tagTexture(name) {
  const c = document.createElement("canvas");
  c.width = 400;
  c.height = 112;
  const g = c.getContext("2d");
  g.fillStyle = C.paper;
  g.fillRect(0, 0, 400, 112);
  g.strokeStyle = C.ink;
  g.lineWidth = 4;
  g.strokeRect(2, 2, 396, 108);
  g.fillStyle = C.red;
  g.beginPath();
  g.arc(38, 56, 11, 0, Math.PI * 2);
  g.fill();
  g.fillStyle = C.ink;
  g.font = `600 40px ${MONO}`;
  g.textBaseline = "middle";
  g.fillText(name, 66, 58);
  return texOf(c);
}

function cardTexture(kind) {
  const W = 760, H = 960;
  const c = document.createElement("canvas");
  c.width = W;
  c.height = H;
  const g = c.getContext("2d");
  const on = kind === "gemini";
  g.fillStyle = on ? C.red : C.paper;
  g.fillRect(0, 0, W, H);
  g.strokeStyle = on ? C.red : C.line;
  g.lineWidth = 6;
  g.strokeRect(3, 3, W - 6, H - 6);
  const fg = on ? C.paper : C.ink;
  g.fillStyle = fg;
  g.strokeStyle = fg;
  if (!on) {
    // padlock
    g.lineWidth = 36;
    g.beginPath();
    g.arc(W / 2, 310, 100, Math.PI, 0);
    g.lineTo(W / 2 + 100, 380);
    g.moveTo(W / 2 - 100, 310);
    g.lineTo(W / 2 - 100, 380);
    g.stroke();
    g.fillRect(W / 2 - 150, 360, 300, 240);
    g.fillStyle = C.paper;
    g.beginPath();
    g.arc(W / 2, 450, 34, 0, Math.PI * 2);
    g.fill();
    g.fillRect(W / 2 - 14, 450, 28, 90);
  } else {
    // four-point spark
    g.beginPath();
    const cx = W / 2, cy = 400, R = 190, r = 34;
    for (let i = 0; i < 8; i++) {
      const a = (i * Math.PI) / 4 - Math.PI / 2;
      const rad = i % 2 === 0 ? R : r;
      g.lineTo(cx + Math.cos(a) * rad, cy + Math.sin(a) * rad);
    }
    g.closePath();
    g.fill();
  }
  g.fillStyle = fg;
  g.textAlign = "center";
  g.font = `400 120px "Instrument Serif", Georgia, serif`;
  g.fillText(on ? "Gemini" : "Offline", W / 2, 740);
  g.font = `500 27px ${MONO}`;
  g.globalAlpha = 0.78;
  g.fillText(on ? "online · opt-in · redacted · audited" : "qwen2.5:7b · code never leaves", W / 2, 830);
  g.fillText(on ? "same scanners, same checks" : "same scanners, same checks", W / 2, 878);
  return texOf(c);
}

function pillTexture() {
  const c = document.createElement("canvas");
  c.width = 400;
  c.height = 160;
  const g = c.getContext("2d");
  g.fillStyle = C.paper;
  g.strokeStyle = C.ink;
  g.lineWidth = 10;
  g.beginPath();
  g.roundRect(8, 8, 384, 144, 72);
  g.fill();
  g.stroke();
  return texOf(c);
}

function dotTexture(color) {
  const c = document.createElement("canvas");
  c.width = c.height = 128;
  const g = c.getContext("2d");
  g.fillStyle = color;
  g.beginPath();
  g.arc(64, 64, 58, 0, Math.PI * 2);
  g.fill();
  return texOf(c);
}

// ---- the scene ----------------------------------------------------------------------------------------------
const TAGS = ["Semgrep", "Gitleaks", "TruffleHog", "OSV", "Trivy", "Syft", "Nuclei", "Katana"];

function buildScene() {
  const root = new THREE.Group();
  const disposables = [];
  const keep = (x) => (disposables.push(x), x);

  const plane = (w, h, map, opts = {}) => {
    const m = keep(new THREE.MeshBasicMaterial({ map, transparent: true, toneMapped: false, depthWrite: false, ...opts }));
    return new THREE.Mesh(keep(new THREE.PlaneGeometry(w, h)), m);
  };
  const flat = (w, h, color, opacity) => {
    const m = keep(new THREE.MeshBasicMaterial({ color, transparent: true, opacity, toneMapped: false, depthWrite: false }));
    return new THREE.Mesh(keep(new THREE.PlaneGeometry(w, h)), m);
  };
  const sheet = (map, order, w = SW, h = SH) => {
    const g = new THREE.Group();
    const shadow = flat(w + 0.1, h + 0.1, 0x15130f, 0.1);
    shadow.position.set(0.14, -0.14, -0.03);
    const body = plane(w, h, keep(map));
    shadow.renderOrder = order;
    body.renderOrder = order + 1;
    g.add(shadow, body);
    g.userData = { body, shadow };
    root.add(g);
    return g;
  };

  const code = sheet(codeTexture(false), 20);
  const fixedPlane = plane(SW, SH, keep(codeTexture(true)), { opacity: 0 });
  fixedPlane.position.z = 0.02;
  fixedPlane.renderOrder = 23;
  code.add(fixedPlane);

  const flags = CODE.map((l, i) => (l.flag ? i : -1)).filter((i) => i >= 0).map((i) => {
    const f = flat(SW - 0.14, px(LINE_H - 8), 0xb3261e, 0);
    f.position.set(0, SH / 2 - px(lineY(i)), 0.01);
    f.userData = { y: px(lineY(i)), i };
    f.renderOrder = 22;
    code.add(f);
    return f;
  });

  const beam = flat(SW + 0.2, 0.035, 0xb3261e, 0);
  const band = plane(SW, 0.55, bandTexture(), { opacity: 0 });
  band.renderOrder = 25;
  beam.renderOrder = 26;
  beam.position.z = 0.04;
  band.position.z = 0.035;
  code.add(band, beam);

  const stamp = plane(1.25, 1.25, keep(stampTexture()), { opacity: 0 });
  stamp.renderOrder = 28;
  stamp.position.set(0.45, -1.1, 0.06);
  code.add(stamp);

  const app = sheet(appTexture(), 0);
  const folder = sheet(folderTexture(), 4);
  const repo = sheet(repoTexture(), 8);
  const ev = sheet(evidenceTexture(), 12);

  const markers = ROUTES.filter((r) => r.hit).map((r) => {
    const m = flat(SW - 0.14, px(ROUTE_H - 10), 0xb3261e, 0);
    m.position.set(0, SH / 2 - px(routeY(ROUTES.indexOf(r))), 0.01);
    m.renderOrder = 2;
    app.add(m);
    return m;
  });

  // correlation links, built in app-sheet / code-sheet coordinates and added to the root
  const linkGroup = new THREE.Group();
  root.add(linkGroup);
  const links = ROUTES.filter((r) => r.hit).map((r) => {
    const a = new THREE.Vector3(-SW / 2 - 0.5, 0.28 + SH / 2 - px(routeY(ROUTES.indexOf(r))), -0.2);
    const b = new THREE.Vector3(-SW / 2, SH / 2 - px(lineY(r.hit)), 0.02);
    const mid = new THREE.Vector3((a.x + b.x) / 2, (a.y + b.y) / 2 + 0.12, 0.1);
    const geo = keep(new THREE.TubeGeometry(new THREE.QuadraticBezierCurve3(a, mid, b), 24, 0.014, 6, false));
    const mat = keep(new THREE.MeshBasicMaterial({ color: 0xb3261e, transparent: true, opacity: 0.9, toneMapped: false, depthWrite: false }));
    const mesh = new THREE.Mesh(geo, mat);
    mesh.userData.count = geo.index.count;
    mesh.renderOrder = 30;
    linkGroup.add(mesh);
    return mesh;
  });

  // scanner tags orbiting the code sheet
  const tags = TAGS.map((n, i) => {
    const m = plane(1.3, 0.364, keep(tagTexture(n)), { opacity: 0 });
    m.renderOrder = 40 + i;
    root.add(m);
    return m;
  });

  // mode cards and the switch between them
  const cardOff = sheet(cardTexture("offline"), 50, 2.4, 3.03);
  const cardOn = sheet(cardTexture("gemini"), 54, 2.4, 3.03);
  const pill = plane(1.3, 0.52, keep(pillTexture()), { opacity: 0 });
  const knob = plane(0.34, 0.34, keep(dotTexture("#b3261e")), { opacity: 0 });
  pill.renderOrder = 60;
  knob.renderOrder = 61;
  root.add(pill, knob);

  return { root, code, app, folder, repo, ev, fixedPlane, flags, beam, band, markers, links, linkGroup, tags, stamp, cardOff, cardOn, pill, knob, disposables };
}

// scale a sheet group in/out (0 = gone) and fade its paper
function show(g, a) {
  const k = Math.max(0.0001, a);
  g.scale.set(k, k, k);
  g.visible = a > 0.01;
  g.userData.body.material.opacity = Math.min(1, a * 1.6);
  g.userData.shadow.material.opacity = 0.1 * Math.min(1, a * 1.6);
}

// camera and scene-rotation keyframes, one per chapter centre
const KEYS = [
  { x: -1.6, y: 0.2, z: 9.2, ry: -0.3, rx: 0 },
  { x: 0.7, y: 0.1, z: 11.4, ry: -0.12, rx: 0 },
  { x: -1.5, y: 0.2, z: 11.4, ry: -0.3, rx: 0.8 },
  { x: -1.5, y: 0.2, z: 14.6, ry: -0.24, rx: 0.5 },
  { x: -1.5, y: 0.2, z: 14.2, ry: -0.26, rx: 0.5 },
  { x: -1.5, y: 0.1, z: 13.8, ry: -0.2, rx: 0.5 },
  { x: -1.0, y: 0.0, z: 11.4, ry: -0.04, rx: 0.6 },
  { x: -1.0, y: 0.0, z: 12.4, ry: -0.1, rx: 0.6 },
];
function keyAt(P) {
  const f = clamp01(P) * KEYS.length - 0.5;
  const i = Math.min(KEYS.length - 2, Math.max(0, Math.floor(f)));
  const t = ease(clamp01(f - i));
  const a = KEYS[i], b = KEYS[i + 1];
  const l = (u, v) => u + (v - u) * t;
  return { x: l(a.x, b.x), y: l(a.y, b.y), z: l(a.z, b.z), ry: l(a.ry, b.ry), rx: l(a.rx, b.rx) };
}

function applyStory(s, P, t) {
  // ---- chapter 0: the source sheet scans itself on a loop; later chapters drive it from P
  const hero = P < 0.125;
  const idle = ((t % 6) / 6) * 1.25; // sweeps, then holds the flagged state
  const sweep = hero ? clamp01(idle) : seg(P, 0.3, 0.37);
  const sweepEase = ease(sweep);
  const beamY = SH / 2 - 0.15 - sweepEase * (SH - 0.3);
  const beamOn = sweep > 0 && sweep < 1 ? 1 : 0;
  s.beam.position.y = beamY;
  s.band.position.y = beamY + 0.3;
  s.beam.material.opacity = beamOn * 0.95;
  s.band.material.opacity = beamOn;

  const fixed = ease(seg(P, 0.52, 0.6));
  const confirmed = ease(seg(P, 0.44, 0.5));
  const flagsIn = hero || P >= 0.26;
  for (const f of s.flags) {
    const found = beamY < SH / 2 - f.userData.y + 0.05 ? 1 : 0;
    const reveal = sweep >= 1 ? 1 : found;
    f.material.opacity = (flagsIn ? reveal : 0) * (0.16 + 0.14 * confirmed) * (1 - fixed);
  }
  s.fixedPlane.material.opacity = fixed;

  // ---- the source sheet: hero, hidden while the three targets show, back for the scan
  const codeA = P < 0.125 ? 1 : 1 - ease(seg(P, 0.125, 0.165)) + ease(seg(P, 0.255, 0.3));
  const codeA2 = P > 0.74 ? 1 - ease(seg(P, 0.74, 0.79)) : Math.min(1, codeA);
  show(s.code, codeA2);
  s.code.position.set(0, Math.sin(t * 0.8) * 0.04, 0);

  // ---- targets: running app, folder, repo
  const tIn = ease(seg(P, 0.125, 0.18));
  const mergeOut = ease(seg(P, 0.25, 0.3));
  const row = 1 - mergeOut;
  s.folder.position.set(2.4 * row, 0, 0.2 * row);
  s.repo.position.set(4.1 * row, -0.3 * row, 0.4 * row);
  s.folder.rotation.y = -0.1;
  s.repo.rotation.y = -0.1;
  show(s.folder, tIn * row);
  show(s.repo, tIn * row);

  // the app sheet: first target, then the live app that gets correlated, gone for the modes
  const settle = ease(seg(P, 0.25, 0.32));
  s.app.position.set(0.7 + (-2.2 - 0.7) * settle, 0.28 * settle + 0.3 * (1 - settle), 0.2 + (-1.4) * settle);
  s.app.rotation.y = -0.1 + 0.32 * settle;
  const appA = P < 0.125 ? 0 : P > 0.75 ? 1 - ease(seg(P, 0.75, 0.79)) : tIn;
  show(s.app, appA);
  for (const m of s.markers) m.material.opacity = ease(seg(P, 0.38, 0.44)) * 0.18 * (1 - fixed * 0.8);
  s.linkGroup.visible = P < 0.76;
  s.links.forEach((l, k) => {
    const g = ease(seg(P, 0.39 + k * 0.03, 0.46 + k * 0.03));
    l.geometry.setDrawRange(0, Math.floor((l.userData.count * g) / 3) * 3);
    l.material.opacity = 0.9 * (1 - fixed * 0.7);
  });

  // ---- scanner tags orbit the code sheet while the scan runs, then fly in
  const tagIn = ease(seg(P, 0.265, 0.3));
  const tagOut = ease(seg(P, 0.36, 0.395));
  s.tags.forEach((m, i) => {
    const a = t * 0.55 + (i / s.tags.length) * Math.PI * 2;
    const r = (1 - tagOut) * 2.35;
    m.position.set(Math.cos(a) * r * 0.98, Math.sin(a) * r * 0.78, Math.sin(a) * 0.9 + 0.5);
    const k = tagIn * (1 - tagOut);
    m.scale.set(Math.max(0.001, k), Math.max(0.001, k), 1);
    m.material.opacity = Math.min(1, k * 1.5);
    m.visible = k > 0.01;
  });

  // ---- evidence
  const evIn = ease(seg(P, 0.41, 0.47));
  s.ev.position.set(2.0 + (1 - evIn) * 0.9, -0.28, -1.2);
  s.ev.rotation.y = -0.22;
  const evA = P > 0.74 ? 1 - ease(seg(P, 0.74, 0.79)) : evIn;
  show(s.ev, evA);

  // ---- approve
  const st = ease(seg(P, 0.65, 0.72));
  s.stamp.material.opacity = st * (P > 0.74 ? 0 : 1);
  const sc = 1.9 - 0.9 * st;
  s.stamp.scale.set(sc, sc, 1);
  s.stamp.rotation.z = 0.25 - 0.45 * st;

  // ---- two modes
  const mIn = ease(seg(P, 0.78, 0.84));
  s.cardOff.position.set(-1.45, 0.05 + Math.sin(t * 0.7) * 0.04, 0);
  s.cardOn.position.set(1.45, 0.05 + Math.sin(t * 0.7 + 1.2) * 0.04, 0);
  s.cardOff.rotation.y = 0.12;
  s.cardOn.rotation.y = -0.12;
  show(s.cardOff, mIn);
  show(s.cardOn, mIn);
  const sw = ease(seg(P, 0.85, 0.9)); // 0 = offline, 1 = Gemini
  s.pill.position.set(0, -2.15, 0.1);
  s.knob.position.set(-0.4 + 0.8 * sw, -2.15, 0.12);
  s.pill.material.opacity = mIn;
  s.knob.material.opacity = mIn;
  s.cardOff.userData.body.material.opacity = Math.min(1, mIn * 1.6) * (1 - 0.35 * sw);
  s.cardOn.userData.body.material.opacity = Math.min(1, mIn * 1.6) * (0.65 + 0.35 * sw);
}

export default function Scene3D({ progressRef, still = false, onFail }) {
  const host = useRef(null);

  useEffect(() => {
    const el = host.current;
    if (!el) return undefined;
    let renderer;
    try {
      renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: "low-power" });
    } catch {
      onFail?.();
      return undefined;
    }
    renderer.setClearColor(0x000000, 0);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    renderer.domElement.style.cssText = "display:block;width:100%;height:100%";
    el.appendChild(renderer.domElement);

    const camera = new THREE.PerspectiveCamera(30, 1, 0.1, 60);
    const scene = new THREE.Scene();
    let s = null;
    let alive = true;
    let visible = true;
    let raf = 0;
    let smooth = still ? 0.7 : 0;
    let aspect = 1;
    const pointer = { x: 0, y: 0 };
    const start = performance.now();
    let last = start;

    const resize = () => {
      const w = el.clientWidth || 1;
      const h = el.clientHeight || 1;
      renderer.setSize(w, h, false);
      aspect = w / h;
      camera.aspect = aspect;
      camera.updateProjectionMatrix();
    };
    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(el);

    const io = new IntersectionObserver(([e]) => {
      visible = e.isIntersecting;
      if (visible) loop();
    });
    io.observe(el);

    const onMove = (e) => {
      pointer.x = (e.clientX / window.innerWidth - 0.5) * 2;
      pointer.y = (e.clientY / window.innerHeight - 0.5) * 2;
    };
    window.addEventListener("pointermove", onMove, { passive: true });

    const frame = () => {
      const now = performance.now();
      const t = (now - start) / 1000;
      const dt = Math.min(0.25, (now - last) / 1000);
      last = now;
      const target = still ? 0.7 : clamp01(progressRef?.current ?? 0);
      smooth += (target - smooth) * (1 - Math.exp(-dt * 7)); // frame-rate independent easing toward the scroll position
      const k = keyAt(smooth);
      const wide = aspect >= 1;
      // wide screens: scene sits right of the caption; portrait: scene sits in the upper half
      const fit = wide ? Math.max(1, 1.5 / aspect) : Math.max(1, 0.85 / aspect);
      camera.position.set(wide ? k.x : 0, k.y, k.z * fit);
      camera.lookAt(wide ? k.x : 0, wide ? k.y : k.y - 1.6, 0);
      s.root.position.x = wide ? k.rx + (still ? 0.9 : 0) : 0;
      s.root.rotation.y = k.ry + (still ? 0 : pointer.x * 0.08);
      s.root.rotation.x = 0.06 + (still ? 0 : pointer.y * 0.04);
      applyStory(s, smooth, still ? 3 : t);
      renderer.render(scene, camera);
    };

    const loop = () => {
      cancelAnimationFrame(raf);
      if (!alive || !s || !visible || document.hidden) return;
      frame();
      if (!still) raf = requestAnimationFrame(loop);
    };

    // sheets are drawn with the page fonts, so wait for them
    (document.fonts?.ready ?? Promise.resolve()).then(() => {
      if (!alive) return;
      s = buildScene();
      scene.add(s.root);
      loop();
    });
    const onVis = () => !document.hidden && loop();
    document.addEventListener("visibilitychange", onVis);

    return () => {
      alive = false;
      cancelAnimationFrame(raf);
      ro.disconnect();
      io.disconnect();
      window.removeEventListener("pointermove", onMove);
      document.removeEventListener("visibilitychange", onVis);
      s?.disposables.forEach((d) => d.dispose?.());
      renderer.dispose();
      renderer.forceContextLoss?.();
      renderer.domElement.remove();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [still]);

  return <div ref={host} className="ln-3d" role="img" aria-label="An animated film: a running app, a folder and a repo are scanned by eight scanners, findings are proven with evidence, fixed on a copy, approved by a human, and run offline or with Gemini" />;
}
