/* LassiNet dashboard — topology map + live threat feed (no build step). */
"use strict";

const ROLE_STYLE = {
  router:      { color: "#a371f7", label: "Router",        shape: "hexagon" },
  server:      { color: "#58a6ff", label: "Server",        shape: "circularImage", icon: "\u{1F5A5}\uFE0F" },
  workstation: { color: "#3fb950", label: "Workstation",   shape: "circularImage", icon: "\u{1F4BB}" },
  iot:         { color: "#d29922", label: "IoT",           shape: "circularImage", icon: "\u{1F4E1}" },
  printer:     { color: "#8b949e", label: "Printer",       shape: "circularImage", icon: "\u{1F5A8}\uFE0F" },
  attacker:    { color: "#f85149", label: "Attacker",      shape: "star" },
  external:    { color: "#58a6ff", label: "Internet",      shape: "circularImage", icon: "\u2601\uFE0F" },
};

function iconURI(ch, fill = "#161b22") {
  const svg =
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48">'
    + `<circle cx="24" cy="24" r="23" fill="${fill}"/>`
    + `<text x="24" y="31" font-size="23" text-anchor="middle"`
    + ` font-family="'Segoe UI Emoji','Apple Color Emoji',sans-serif">${ch}</text></svg>`;
  return "data:image/svg+xml," + encodeURIComponent(svg);
}

const SEV_ICONS = { critical: "\u{1F6A8}", high: "\u26A0\uFE0F", medium: "\u26D3\uFE0F", info: "\u2705" };

// ---- topology map -----------------------------------------------------------
const nodes = new vis.DataSet([]);
const edges = new vis.DataSet([]);
const network = new vis.Network(
  document.getElementById("map"),
  { nodes, edges },
  {
    autoResize: true,
    physics: { enabled: false },
    interaction: { hover: true, tooltipDelay: 120, selectable: true, multiselect: false, navigationButtons: false, keyboard: true },
    nodes: { font: { color: "#c9d1d9", size: 12, face: "Segoe UI" }, borderWidth: 2, scaling: { min: 10, max: 30 } },
    edges: { smooth: { enabled: true, type: "continuous", roundness: 0.3 } },
    layout: { randomSeed: 42 },
  }
);

// ---- deterministic tree layout ----------------------------------------------
const ROLE_ORDER = { server: 0, workstation: 1, iot: 2, printer: 3, attacker: 4 };
let layoutKey = "";

function computeTreeLayout(data) {
  const router = data.nodes.find(h => h.role === "router");
  const ext = data.nodes.find(h => h.role === "external");
  const leaves = data.nodes
    .filter(h => h.role !== "router" && h.role !== "external")
    .sort((a, b) => (ROLE_ORDER[a.role] ?? 9) - (ROLE_ORDER[b.role] ?? 9) || a.ip.localeCompare(b.ip));
  const pos = {};
  if (ext) pos[ext.ip] = { x: 0, y: -260 };
  if (router) pos[router.ip] = { x: 0, y: 0 };
  const n = leaves.length;
  // Dynamic spacing based on container width and node count
  const containerWidth = document.getElementById("map")?.clientWidth || 800;
  const spacing = Math.max(140, Math.min(240, containerWidth / Math.max(n * 0.8, 3)));
  leaves.forEach((h, i) => { pos[h.ip] = { x: (i - (n - 1) / 2) * spacing, y: 240 }; });
  return pos;
}

// ---- attack feedback: node flash + malicious "packet" dots over the wires ----
let lastAttacks = -1;
const flashUntil = {};
const attackPaths = [];
const FLASH_MS = 6000;

function markAttackPath(data, a, now) {
  const router = data.nodes.find(h => h.role === "router");
  if (!router || !a.src) return;
  const hostIps = new Set(data.nodes.map(h => h.ip));
  let victim = a.dst;
  if (!hostIps.has(victim)) victim = (data.nodes.find(h => h.role === "external") || {}).ip;
  if (!victim || victim === a.src) return;
  const links = new Set(data.edges.filter(e => e.kind === "link").map(e => e.from + "|" + e.to));
  const seg = (u, v) => (links.has(u + "|" + v) || links.has(v + "|" + u)) ? [u, v] : null;
  const s1 = seg(a.src, router.ip);
  const s2 = seg(router.ip, victim);
  if (s1 && s2) {
    const key = s1[0] + ">" + s1[1] + "|" + s2[0] + ">" + s2[1];
    if (!attackPaths.some(p => p.until > now && p.key === key)) {
      attackPaths.push({ key, born: now, until: now + FLASH_MS, segments: [s1, s2] });
    }
  }
}

function updateFlashes(data, now) {
  const total = data.stats.attacks_total;
  if (lastAttacks < 0) { lastAttacks = total; return; }
  const fresh = Math.max(0, total - lastAttacks);
  lastAttacks = total;
  while (attackPaths.length && attackPaths[0].until < now) attackPaths.shift();
  for (const a of data.alerts.slice(0, fresh)) {
    if (a.src) flashUntil[a.src] = now + FLASH_MS;
    markAttackPath(data, a, now);
  }
}

// ---- malicious packet animation (overlay canvas) -------------------------------
const fxHost = document.getElementById("map");
fxHost.style.position = "relative";
const fx = document.createElement("canvas");
fx.style.position = "absolute";
fx.style.inset = "0";
fx.style.width = "100%";
fx.style.height = "100%";
fx.style.pointerEvents = "none";
fx.style.zIndex = "5";
fxHost.appendChild(fx);
const fctx = fx.getContext("2d");

function sizeFx() {
  const rect = fxHost.getBoundingClientRect();
  fx.width = Math.max(1, Math.floor(rect.width));
  fx.height = Math.max(1, Math.floor(rect.height));
}
new ResizeObserver(sizeFx).observe(fxHost);
sizeFx();

const SPEED = 160;
const BALLS = 5;
const BALL_R = 5;
const RED = "#f85149";
const AMBIENT_MAX = 16;
const SPAWN_MS = 100;

let fxRouter = null, fxExt = null, fxLinks = new Set(), fxHostIds = new Set(), fxRoles = new Map(),
    trafficSamples = [];
const ambientDots = [];
let lastSpawn = 0;

const FLOW_COLORS = {
  router: "#a371f7", server: "#58a6ff", external: "#58a6ff",
  workstation: "#3fb950", iot: "#d29922", printer: "#8b949e", attacker: "#f85149",
};

function fxSync(data) {
  fxRouter = (data.nodes.find(h => h.role === "router") || {}).ip || null;
  fxExt = (data.nodes.find(h => h.role === "external") || {}).ip || null;
  fxHostIds = new Set(data.nodes.map(h => h.ip));
  fxRoles = new Map(data.nodes.map(h => [h.ip, h.role]));
  fxLinks = new Set(data.edges.filter(e => e.kind === "link").map(e => e.from + "|" + e.to));
  trafficSamples = Array.isArray(data.traffic) ? data.traffic : [];
}

function spawnAmbient(now) {
  if (!trafficSamples.length || ambientDots.length >= AMBIENT_MAX) return;
  if (now - lastSpawn < SPAWN_MS) return;
  lastSpawn = now;
  const s = trafficSamples[Math.floor(Math.random() * trafficSamples.length)];
  if (!s || s.attack || s.src === s.dst) return;
  if (!fxHostIds.has(s.src) || !fxRouter) return;
  const src = s.src;
  const dst = fxHostIds.has(s.dst) ? s.dst : fxExt;
  if (!dst || src === dst) return;
  const link = (u, v) => (fxLinks.has(u + "|" + v) || fxLinks.has(v + "|" + u)) ? [u, v] : null;
  const raw = src === fxRouter ? [link(src, dst)] : [link(src, fxRouter), link(fxRouter, dst)];
  const segments = raw.filter(Boolean);
  if (!segments.length) return;
  const bytes = Math.max(0, +s.bytes || 0);
  const radius = 2.2 + Math.min(1.5, Math.log10(1 + bytes / 600));
  ambientDots.push({ born: now, until: now + 900 + Math.random() * 1100, segments, kind: "ambient", radius });
}

function nodeDOMPos(ip) {
  const p = network.getPositions([ip])[ip];
  return p ? network.canvasToDOM(p) : null;
}

function drawGlowDot(x, y, r, col, a, glow) {
  if (r <= 0 || a <= 0) return;
  fctx.globalAlpha = a;
  fctx.beginPath();
  fctx.arc(x, y, r, 0, Math.PI * 2);
  fctx.fillStyle = col;
  if (glow > 0) { fctx.shadowColor = col; fctx.shadowBlur = glow; }
  fctx.fill();
  fctx.shadowBlur = 0;
  fctx.globalAlpha = 1;
}

function drawRider(p, now) {
  const idx = p.segments.map(seg => nodeDOMPos(seg[0]));
  idx.push(nodeDOMPos(p.segments[p.segments.length - 1][1]));
  if (idx.some(q => !q)) return;
  const legs = [];
  let total = 0;
  for (let i = 0; i < idx.length - 1; i++) {
    const L = Math.hypot(idx[i + 1].x - idx[i].x, idx[i + 1].y - idx[i].y);
    legs.push(L); total += L;
  }
  if (total <= 0) return;
  const xyAt = d => {
    let rest = Math.max(0, Math.min(d, total));
    for (let k = 0; k < legs.length; k++) {
      if (rest <= legs[k]) {
        const t = legs[k] > 0 ? rest / legs[k] : 0;
        return [idx[k].x + (idx[k + 1].x - idx[k].x) * t, idx[k].y + (idx[k + 1].y - idx[k].y) * t];
      }
      rest -= legs[k];
    }
    const last = idx[idx.length - 1];
    return [last.x, last.y];
  };

  const fade = Math.min(1, (now - p.born) / 300, Math.max(0, (p.until - now) / 600));

  if (p.kind === "ambient") {
    const col = FLOW_COLORS[fxRoles.get(p.segments[0][0])] || "#8b949e";
    const R = p.radius || 2.6;
    const ph = Math.min(1, (now - p.born) / (p.until - p.born));
    for (let g = 2; g >= 0; g--) {
      const [x, y] = xyAt(Math.max(0, ph - g * 0.08) * total);
      drawGlowDot(x, y, Math.max(0.6, g === 0 ? R : R * (0.55 - g * 0.1)),
                  col, fade * (g === 0 ? 0.9 : 0.25 / g), g === 0 ? 8 : 0);
    }
    return;
  }

  const d0 = (now / 1000) * SPEED;
  for (let i = 0; i < BALLS; i++) {
    const d = (d0 + (i * total) / BALLS) % total;
    for (let g = 3; g >= 0; g--) {
      const dd = ((d - g * 14) % total + total) % total;
      const [x, y] = xyAt(dd);
      drawGlowDot(x, y, g === 0 ? BALL_R : Math.max(0.8, BALL_R * (0.55 - g * 0.07)),
                  RED, fade * (g === 0 ? 1 : 0.22 / g), g === 0 ? 16 : 0);
    }
  }
}

// ---- dashed type-lanes: each family of devices gets a tinted dashed fence ------
const GROUP_ROLES = new Set(["server", "workstation", "iot", "printer", "attacker"]);

function drawGroupBoxes() {
  if (!fxRoles.size) return;
  const pos = network.getPositions();
  const groups = new Map();
  for (const [ip, role] of fxRoles) {
    if (!GROUP_ROLES.has(role) || !pos[ip]) continue;
    const d = network.canvasToDOM(pos[ip]);
    if (!groups.has(role)) groups.set(role, []);
    groups.get(role).push(d);
  }
  for (const [role, pts] of groups) {
    const xs = pts.map(p => p.x), ys = pts.map(p => p.y);
    const x0 = Math.min(...xs) - 52, x1 = Math.max(...xs) + 52;
    const y0 = Math.min(...ys) - 36, y1 = Math.max(...ys) + 48;
    const col = (ROLE_STYLE[role] || ROLE_STYLE.workstation).color;
    fctx.beginPath();
    if (fctx.roundRect) {
      fctx.roundRect(x0, y0, x1 - x0, y1 - y0, 16);
    } else {
      fctx.rect(x0, y0, x1 - x0, y1 - y0);
    }
    fctx.fillStyle = col + "0d";
    fctx.fill();
    fctx.strokeStyle = col + "35";
    fctx.lineWidth = 1.5;
    fctx.setLineDash([6, 6]);
    fctx.stroke();
    fctx.setLineDash([]);
  }
}

// ---- node selection highlight (drawn on overlay) ----
let selectedNodeIp = null;
let selectionPulse = 0;

function drawSelectionHighlight(now) {
  if (!selectedNodeIp) return;
  const pos = network.getPositions([selectedNodeIp])[selectedNodeIp];
  if (!pos) return;
  const dom = network.canvasToDOM(pos);
  if (!dom) return;
  selectionPulse = (selectionPulse + 0.08) % (Math.PI * 2);
  const pulseScale = 1 + 0.15 * Math.sin(selectionPulse);
  const baseR = 24 * pulseScale;
  fctx.beginPath();
  fctx.arc(dom.x, dom.y, baseR, 0, Math.PI * 2);
  fctx.strokeStyle = "#58a6ff";
  fctx.lineWidth = 2.5;
  fctx.setLineDash([8, 6]);
  fctx.stroke();
  fctx.setLineDash([]);
  fctx.beginPath();
  fctx.arc(dom.x, dom.y, baseR * 0.7, 0, Math.PI * 2);
  fctx.strokeStyle = "rgba(88,166,255,0.3)";
  fctx.lineWidth = 1;
  fctx.stroke();
}

function drawAttackFx(now) {
  while (attackPaths.length && attackPaths[0].until < now) attackPaths.shift();
  while (ambientDots.length && ambientDots[0].until < now) ambientDots.shift();
  spawnAmbient(now);
  fctx.clearRect(0, 0, fx.width, fx.height);
  drawGroupBoxes();
  for (const p of attackPaths) drawRider({ ...p, kind: "attack" }, now);
  for (const p of ambientDots) drawRider(p, now);
  drawSelectionHighlight(now);
}

(function tick() {
  drawAttackFx(Date.now());
  requestAnimationFrame(tick);
})();

// ---- interaction hint (topmost overlay, above the fx canvas) -------------------
const hint = document.createElement("div");
hint.id = "hint";
hint.textContent = "drag to pan · wheel to zoom · select a node + press B to block · double-click to rename";
fxHost.appendChild(hint);

// ---- network event handlers for selection tracking ----
network.on("selectNode", p => { selectedNodeIp = p.nodes[0] || null; });
network.on("deselectNode", () => { selectedNodeIp = null; });

// ---- double-click to rename ----
network.on("doubleClick", async p => {
  const ip = p.nodes[0];
  if (!ip) return;
  const label = nodes.get(ip)?.label || "";
  const current = label.split("\n")[0];
  const name = window.prompt(`Name this device (${ip})`, current);
  if (name && name.trim()) await post("/api/devices/rename", { ip, name: name.trim() });
});

// ---- keyboard shortcuts ----
window.addEventListener("keydown", ev => {
  if (ev.target.tagName === "INPUT" || ev.target.tagName === "TEXTAREA") return;
  if (ev.key.toLowerCase() === "b" && selectedNodeIp) {
    post("/api/firewall/block", { ip: selectedNodeIp, reason: "operator blocked selected node" });
  }
  if (ev.key === "Escape") {
    network.unselectAll();
  }
  if (ev.key === "r" || ev.key === "R") {
    network.fit({ animation: { duration: 500, easingFunction: "easeOutQuad" } });
  }
});

function renderTopology(data) {
  const now = Date.now();
  updateFlashes(data, now);
  fxSync(data);
  const pos = computeTreeLayout(data);
  const key = Object.keys(pos).sort().join(",");
  const layoutChanged = key !== layoutKey;

  const seen = new Set();
  for (const h of data.nodes) {
    const style = ROLE_STYLE[h.role] || ROLE_STYLE.workstation;
    const isBlocked = h.blocked;
    const flashing = !isBlocked && (flashUntil[h.ip] || 0) > now;
    const nodeColor = {
      background: style.color,
      border: isBlocked || flashing ? "#f85149" : style.color,
      highlight: { background: style.color, border: "#ffffff" },
      hover: { background: style.color, border: "#ffffff" },
    };
    const base = {
      color: nodeColor,
      opacity: isBlocked ? 0.5 : 1,
      borderWidth: isBlocked ? 3 : flashing ? 4 : 2,
      font: { color: isBlocked ? "#8b949e" : "#c9d1d9", size: 12, face: "Segoe UI" },
      shadow: {
        enabled: true,
        color: isBlocked ? "#f8514966" : flashing ? "#f8514988" : "#00000066",
        size: isBlocked ? 18 : flashing ? 14 : 10, x: 0, y: 3,
      },
      shapeProperties: {
        useBorderWithImage: true,
        borderDashes: h.role === "external" ? [4, 4] : false,
      },
    };
    if (!nodes.get(h.ip)) {
      const nodeData = {
        id: h.ip, label: `${h.hostname}\n${h.ip}`,
        title: `${isBlocked ? "\u{1F6AB} BLOCKED" : style.label}\nMAC: ${h.mac || "n/a"}\nports: ${h.open_ports.length ? h.open_ports.join(", ") : "\u2014"}\ndouble-click to rename · select + press B to block`,
        shape: style.shape,
        size: h.role === "router" ? 22 : h.role === "external" ? 20 : 16,
        ...(style.shape === "circularImage" ? { image: iconURI(style.icon) } : {}),
        x: pos[h.ip].x, y: pos[h.ip].y,
        ...base,
      };
      nodes.add(nodeData);
    } else {
      const label = `${h.hostname}\n${h.ip}`;
      const changed = nodes.get(h.ip).label !== label;
      nodes.update({ id: h.ip, ...(changed ? { label } : {}), ...base });
    }
    seen.add(h.ip);
  }
  for (const n of nodes.get()) if (!seen.has(n.id)) nodes.remove(n.id);

  if (layoutChanged) {
    layoutKey = key;
    for (const [id, p] of Object.entries(pos)) {
      if (nodes.get(id)) network.moveNode(id, p.x, p.y);
    }
    network.fit({ animation: { duration: 500, easingFunction: "easeOutQuad" } });
  }

  // edges: solid = infrastructure link to the router; dashed w/ arrow = observed traffic flow
  const seenEdges = new Set();
  for (const e of data.edges) {
    const isLink = e.kind === "link";
    const id = (isLink ? "L|" : "T|") + e.from + "|" + e.to;
    if (!edges.get(id)) {
      edges.add({
        id, from: e.from, to: e.to,
        dashes: !isLink,
        width: isLink ? 2.8 : 1.4,
        arrows: isLink ? "" : { to: { enabled: true, scaleFactor: 0.5, type: "arrow" } },
        color: { color: isLink ? "#484f58" : "#6e7681", highlight: "#58a6ff", hover: "#58a6ff" },
        smooth: isLink ? false : { enabled: true, type: "continuous", roundness: 0.3 },
        selectionWidth: 3,
      });
    }
    seenEdges.add(id);
  }
  for (const e of edges.get()) if (!seenEdges.has(e.id)) edges.remove(e.id);
}

// ---- side panel --------------------------------------------------------------
function fmtAlert(a) {
  const div = document.createElement("div");
  const icon = SEV_ICONS[a.severity] || "\u2139\uFE0F";
  const sev = (a.severity || "info").toLowerCase();
  const engineTag = a.engine === "rules" ? 'rules' : 'ml';
  div.className = "alert " + sev;
  div.innerHTML = `
    <div class="top">
      <b>${icon} ${a.attack}</b>
      <span class="sev-badge">${sev.toUpperCase()}</span>
    </div>
    <div class="meta">${a.time} \u00B7 ${a.src} \u2192 ${a.dst} \u00B7 engine: <span class="engine-tag ${engineTag}">${engineTag}</span> \u00B7 conf: ${a.confidence}</div>
    ${sev !== "info" && a.src ? `<button class="act" data-ip="${a.src}">Block ${a.src}</button>` : ""}`;
  return div;
}

function fmtRule(r) {
  const div = document.createElement("div");
  div.className = "rule";
  const allow = r.action === "ALLOW";
  div.innerHTML = `
    <div class="top"><span class="ip">${r.ip}</span><span>${allow ? "\u2713 ALLOW" : "\u26D4 BLOCK"}</span></div>
    <div class="meta">${r.time} \u00B7 ${r.reason}</div>
    ${allow ? "" : `<button class="act unblock" data-unblock="${r.ip}">Remove rule</button>`}`;
  return div;
}

// ---- system log panel: everything that happened, newest first ----------------
function fmtLogRow(row) {
  const div = document.createElement("div");
  div.className = "log-line " + row.cls;
  const t = document.createElement("span");
  t.className = "t";
  t.textContent = row.time;
  div.appendChild(t);
  div.appendChild(document.createTextNode(row.msg));
  return div;
}

function renderLog(data) {
  const rows = [];
  for (const a of data.alerts) {
    if (a.attack === "auto_block") {
      rows.push({ time: a.time, cls: "ok", msg: `AUTO-BLOCK fired ${a.src}` });
    } else {
      const conf = typeof a.confidence === "number" ? a.confidence.toFixed(2) : "?";
      const sev = a.severity || "info";
      rows.push({
        time: a.time,
        cls: sev === "critical" || sev === "high" ? sev : "warn",
        msg: `${sev.toUpperCase().padEnd(8)} ${a.attack} \u00B7 ${a.src} \u2192 ${a.dst} \u00B7 engine ${a.engine} conf ${conf}`,
      });
    }
  }
  for (const r of data.rules) {
    rows.push({
      time: r.time,
      cls: r.action === "BLOCK" ? "fw" : "ok",
      msg: `FW ${r.action.padEnd(5)} ${r.ip} \u2014 ${r.reason}`,
    });
  }
  rows.sort((x, y) => y.time.localeCompare(x.time));
  rows.length = Math.min(rows.length, 80);
  const log = document.getElementById("log");
  log.replaceChildren(
    ...rows.length ? rows.map(fmtLogRow) : [emptyState("waiting for events\u2026")]
  );
}

function emptyState(msg) {
  const div = document.createElement("div");
  div.className = "empty";
  div.textContent = msg;
  return div;
}

function renderFeeds(data) {
  const alerts = document.getElementById("alerts");
  alerts.replaceChildren(
    ...data.alerts.length ? data.alerts.map(fmtAlert) : [emptyState("no threats yet \u2014 watching\u2026")]
  );
  const rules = document.getElementById("rules");
  rules.replaceChildren(
    ...data.rules.length ? data.rules.map(fmtRule) : [emptyState("no firewall rules yet")]
  );
}

// ---- actions -------------------------------------------------------------------
document.getElementById("alerts").addEventListener("click", onAction);
document.getElementById("rules").addEventListener("click", onAction);

function onAction(ev) {
  const block = ev.target.closest("[data-ip]");
  const unblock = ev.target.closest("[data-unblock]");
  if (block) post("/api/firewall/block", { ip: block.dataset.ip, reason: "operator blocked from UI" });
  if (unblock) post("/api/firewall/unblock", { ip: unblock.dataset.unblock });
}

async function post(url, body) {
  try {
    await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    refresh();
  } catch (e) {
    console.error("API call failed:", e);
  }
}

// ---- stats / badges -------------------------------------------------------------
const statPrev = {};

function tweenStat(id, target, fmt = v => Math.round(v).toString()) {
  const el = document.getElementById(id);
  if (!el) return;
  const from = statPrev[id] ?? target;
  statPrev[id] = target;
  if (from === target) { el.textContent = fmt(target); return; }
  el.classList.add("updating");
  const t0 = performance.now(), dur = 400;
  const step = now => {
    const k = Math.min(1, (now - t0) / dur);
    const eased = 1 - Math.pow(1 - k, 3);
    el.textContent = fmt(from + (target - from) * eased);
    if (k < 1) statPrev[id + ":raf"] = requestAnimationFrame(step);
    else el.classList.remove("updating");
  };
  cancelAnimationFrame(statPrev[id + ":raf"]);
  statPrev[id + ":raf"] = requestAnimationFrame(step);
}

function renderStats(data) {
  const s = data.stats;
  tweenStat("s-devices", data.nodes.length);
  tweenStat("s-flows", s.flows_per_sec, v => v.toFixed(1));
  tweenStat("s-alerts", s.attacks_total);
  tweenStat("s-blocked", s.blocks_total);
  document.getElementById("mode-badge").textContent = "\u25CF " + (data.mode || "demo");
  const m = data.model_metrics;
  document.getElementById("model-badge").textContent =
    m ? `ML rf \u00B7 acc ${Math.round(m.accuracy * 100)}% \u00B7 ${m.dataset}` : "heuristic mode";
}

// ---- data loop: WebSocket w/ polling fallback -----------------------------------
let pollTimer = null;
function startPolling() {
  if (pollTimer) return;
  pollTimer = setInterval(refresh, 2000);
}
function stopPolling() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
}

async function refresh() {
  try {
    const res = await fetch("/api/state");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    apply(await res.json());
  } catch (e) {
    console.warn("refresh failed:", e);
  }
}

function apply(data) {
  renderTopology(data);
  renderFeeds(data);
  renderLog(data);
  renderStats(data);
}

// Initialize on load
(async () => {
  await refresh().catch(() => {});
  if (typeof WebSocket === "undefined") {
    startPolling();
  } else {
    const connect = () => {
      const proto = location.protocol === "https:" ? "wss" : "ws";
      const ws = new WebSocket(`${proto}://${location.host}/ws`);
      ws.onopen = () => { stopPolling(); console.log("[WS] connected"); };
      ws.onmessage = ev => { try { apply(JSON.parse(ev.data)); } catch(e) { console.warn("WS parse error", e); } };
      ws.onerror = e => console.warn("[WS] error", e);
      ws.onclose = () => { console.log("[WS] closed, fallback to polling"); startPolling(); setTimeout(connect, 4000); };
    };
    connect();
  }
})();