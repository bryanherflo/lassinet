/* LassiNet dashboard — topology map + live threat feed (no build step). */
"use strict";

const ROLE_STYLE = {
  router:      { color: "#a371f7", label: "Router",        shape: "hexagon" },
  server:      { color: "#58a6ff", label: "Server",        shape: "circularImage", icon: "\u{1F5A5}\uFE0F" },      // desktop computer
  workstation: { color: "#3fb950", label: "Workstation",   shape: "circularImage", icon: "\u{1F4BB}" },            // laptop
  iot:         { color: "#d29922", label: "IoT",           shape: "circularImage", icon: "\u{1F4E1}" },            // satellite dish
  printer:     { color: "#8b949e", label: "Printer",       shape: "circularImage", icon: "\u{1F5A8}\uFE0F" },      // printer
  attacker:    { color: "#f85149", label: "Attacker",      shape: "star" },
  external:    { color: "#58a6ff", label: "Internet",      shape: "circularImage", icon: "\u2601\uFE0F" },         // cloud
};

// emoji baked into an inline SVG so every node carries a proper device icon
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
    physics: { enabled: false },   // deterministic tree layout — no elastic drift
    interaction: { hover: true, tooltipDelay: 120 },
    nodes: { font: { color: "#c9d1d9", size: 12 }, borderWidth: 2 },
  }
);

// ---- deterministic tree layout ----------------------------------------------
// Internet on top, router in the middle, devices spread on one row below.
const ROLE_ORDER = { server: 0, workstation: 1, iot: 2, printer: 3, attacker: 4 };
let layoutKey = "";

function computeTreeLayout(data) {
  const router = data.nodes.find(h => h.role === "router");
  const ext = data.nodes.find(h => h.role === "external");
  const leaves = data.nodes
    .filter(h => h.role !== "router" && h.role !== "external")
    .sort((a, b) => (ROLE_ORDER[a.role] ?? 9) - (ROLE_ORDER[b.role] ?? 9) || a.ip.localeCompare(b.ip));
  const pos = {};
  if (ext) pos[ext.ip] = { x: 0, y: -250 };
  if (router) pos[router.ip] = { x: 0, y: 0 };
  const n = leaves.length;
  leaves.forEach((h, i) => { pos[h.ip] = { x: (i - (n - 1) / 2) * 180, y: 220 }; });
  return pos;
}

// ---- attack feedback: node flash + malicious "packet" dots over the wires ----
// the dots are drawn on a transparent overlay canvas, so the vis DataSet
// is never churned during an attack (that churn was breaking rendering),
// and there is nothing textual — just red packets riding the existing wires.
let lastAttacks = -1;
const flashUntil = {};
const attackPaths = [];        // { born, until, segments:[[src,router],[router,victim]] }
const FLASH_MS = 6000;

function markAttackPath(data, a, now) {
  const router = data.nodes.find(h => h.role === "router");
  if (!router || !a.src) return;
  const hostIps = new Set(data.nodes.map(h => h.ip));
  let victim = a.dst;
  if (!hostIps.has(victim)) victim = (data.nodes.find(h => h.role === "external") || {}).ip;  // exfil -> outside
  if (!victim || victim === a.src) return;
  const links = new Set(data.edges.filter(e => e.kind === "link").map(e => e.from + "|" + e.to));
  const seg = (u, v) => (links.has(u + "|" + v) || links.has(v + "|" + u)) ? [u, v] : null;
  const s1 = seg(a.src, router.ip);
  const s2 = seg(router.ip, victim);
  if (s1 && s2) {
    const key = s1[0] + ">" + s1[1] + "|" + s2[0] + ">" + s2[1];
    // repeated alerts (same story) must not stack identical dot trains
    if (!attackPaths.some(p => p.until > now && p.key === key)) {
      attackPaths.push({ key, born: now, until: now + FLASH_MS, segments: [s1, s2] });
    }
  }
}

function updateFlashes(data, now) {
  const total = data.stats.attacks_total;
  if (lastAttacks < 0) { lastAttacks = total; return; }   // first load: baseline only
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
fxHost.style.position = "relative";          // anchor the overlay canvas to the map box
const fx = document.createElement("canvas");
fx.style.position = "absolute";
fx.style.inset = "0";
fx.style.width = "100%";
fx.style.height = "100%";
fx.style.pointerEvents = "none";
fxHost.appendChild(fx);
const fctx = fx.getContext("2d");

function sizeFx() {
  fx.width = fxHost.clientWidth;
  fx.height = fxHost.clientHeight;
}
new ResizeObserver(sizeFx).observe(fxHost);
sizeFx();

const SPEED = 140;      // speed of red attack packets, px/s along the wires
const BALLS = 4;        // packets riding each attack path (staggered)
const BALL_R = 4.5;
const RED = "#f85149";
const AMBIENT_MAX = 14; // simultaneous background "normal traffic" dots
const SPAWN_MS = 120;   // one background dot every ~120 ms while traffic flows

// caches refreshed on every snapshot so the animation follows the live map
let fxRouter = null, fxExt = null, fxLinks = new Set(), fxHostIds = new Set(), fxRoles = new Map(),
    trafficSamples = [];
const ambientDots = [];          // { born, until, segments } — normal traffic riding the wires
let lastSpawn = 0;

const FLOW_COLORS = {            // traffic dots are tinted by the emitting device's role
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
  if (!fxHostIds.has(s.src) || !fxRouter) return;               // unknown source → skip
  const src = s.src;
  const dst = fxHostIds.has(s.dst) ? s.dst : fxExt;             // egress rides to the Internet node
  if (!dst || src === dst) return;
  const link = (u, v) => (fxLinks.has(u + "|" + v) || fxLinks.has(v + "|" + u)) ? [u, v] : null;
  const raw = src === fxRouter ? [link(src, dst)] : [link(src, fxRouter), link(fxRouter, dst)];
  const segments = raw.filter(Boolean);
  if (!segments.length) return;
  const bytes = Math.max(0, +s.bytes || 0);
  const radius = 2.0 + Math.min(1.3, Math.log10(1 + bytes / 800));   // big transfers = bigger dots
  ambientDots.push({ born: now, until: now + 800 + Math.random() * 900, segments,
                     kind: "ambient", radius });
}

function nodeDOMPos(ip) {
  const p = network.getPositions([ip])[ip];          // canvas coords
  return p ? network.canvasToDOM(p) : null;          // DOM coords (zoom/pan aware)
}

function drawGlowDot(x, y, r, col, a, glow) {
  fctx.globalAlpha = a;
  fctx.beginPath();
  fctx.arc(x, y, r, 0, Math.PI * 2);
  fctx.fillStyle = col;
  fctx.shadowColor = col;
  fctx.shadowBlur = glow;
  fctx.fill();
  fctx.shadowBlur = 0;
  fctx.globalAlpha = 1;
}

function drawRider(p, now) {
  const idx = p.segments.map(seg => nodeDOMPos(seg[0]));
  idx.push(nodeDOMPos(p.segments[p.segments.length - 1][1]));
  if (idx.some(q => !q)) return;                     // node vanished mid-flight
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
        return [idx[k].x + (idx[k + 1].x - idx[k].x) * t,
                idx[k].y + (idx[k + 1].y - idx[k].y) * t];
      }
      rest -= legs[k];
    }
    const last = idx[idx.length - 1];
    return [last.x, last.y];
  };

  // fade in on spawn, fade out as the packet expires
  const fade = Math.min(1, (now - p.born) / 400, Math.max(0, (p.until - now) / 800));

  if (p.kind === "ambient") {
    const col = FLOW_COLORS[fxRoles.get(p.segments[0][0])] || "#8b949e";
    const R = p.radius || 2.6;
    const ph = Math.min(1, (now - p.born) / (p.until - p.born));
    // two fading echoes behind the head = a soft motion trail
    for (let g = 2; g >= 0; g--) {
      const [x, y] = xyAt(Math.max(0, ph - g * 0.07) * total);
      drawGlowDot(x, y, Math.max(0.6, g === 0 ? R : R * (0.62 - g * 0.1)),
                  col, fade * (g === 0 ? 0.95 : 0.35 / g), g === 0 ? 6 : 0);
    }
    return;
  }

  // attacks: bigger red packets with a brighter comet-like trail
  const d0 = (now / 1000) * SPEED;
  for (let i = 0; i < BALLS; i++) {
    const d = (d0 + (i * total) / BALLS) % total;
    for (let g = 2; g >= 0; g--) {
      const dd = ((d - g * 16) % total + total) % total;
      const [x, y] = xyAt(dd);
      drawGlowDot(x, y, g === 0 ? BALL_R : Math.max(0.8, BALL_R * (0.6 - g * 0.08)),
                  RED, fade * (g === 0 ? 1 : 0.3 / g), g === 0 ? 12 : 0);
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
    const x0 = Math.min(...xs) - 48, x1 = Math.max(...xs) + 48;
    const y0 = Math.min(...ys) - 32, y1 = Math.max(...ys) + 44;   // covers the label lines
    const col = (ROLE_STYLE[role] || ROLE_STYLE.workstation).color;
    fctx.beginPath();
    fctx.roundRect(x0, y0, x1 - x0, y1 - y0, 14);
    fctx.fillStyle = col + "0d";                                  // whisper-quiet tint inside
    fctx.fill();
    fctx.strokeStyle = col + "40";
    fctx.lineWidth = 1;
    fctx.setLineDash([5, 5]);
    fctx.stroke();
    fctx.setLineDash([]);
  }
}

function drawAttackFx(now) {
  while (attackPaths.length && attackPaths[0].until < now) attackPaths.shift();
  while (ambientDots.length && ambientDots[0].until < now) ambientDots.shift();
  spawnAmbient(now);
  fctx.clearRect(0, 0, fx.width, fx.height);
  drawGroupBoxes();
  for (const p of attackPaths) drawRider({ ...p, kind: "attack" }, now);
  for (const p of ambientDots) drawRider(p, now);
}

(function tick() {
  drawAttackFx(Date.now());
  requestAnimationFrame(tick);
})();

// ---- interaction hint (topmost overlay, above the fx canvas) -------------------
const hint = document.createElement("div");
hint.id = "hint";
hint.textContent = "drag to pan · wheel to zoom · select a node + press B to block";
fxHost.appendChild(hint);

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
    };
    const base = {
      color: nodeColor,
      opacity: isBlocked ? 0.5 : 1,
      borderWidth: isBlocked ? 3 : flashing ? 4 : 2,
      font: { color: isBlocked ? "#8b949e" : "#c9d1d9", size: 12 },
      shadow: {
        enabled: true,
        color: isBlocked ? "#f8514966" : "#00000066",
        size: isBlocked ? 16 : 10, x: 0, y: 3,
      },
    };
    if (!nodes.get(h.ip)) {
      nodes.add({
        id: h.ip, label: `${h.hostname}\n${h.ip}`,
        title: `${isBlocked ? "\u{1F6AB} BLOCKED" : style.label}\nMAC: ${h.mac || "n/a"}\nports: ${h.open_ports.length ? h.open_ports.join(", ") : "—"}\ndouble-click to rename · select + press B to block`,
        shape: style.shape,
        size: h.role === "router" ? 20 : h.role === "external" ? 18 : 15,
        ...(style.shape === "circularImage" ? { image: iconURI(style.icon) } : {}),
        ...(h.role === "external" ? { shapeProperties: { borderDashes: [4, 4] } } : {}),
        x: pos[h.ip].x, y: pos[h.ip].y,
        ...base,
      });
    } else {
      const label = `${h.hostname}\n${h.ip}`;
      const changed = nodes.get(h.ip).label !== label;
      nodes.update({ id: h.ip, ...(changed ? { label } : {}), ...base });
    }
    seen.add(h.ip);
  }
  // prune disappeared hosts (demo reveals progressively, live churns)
  for (const n of nodes.get()) if (!seen.has(n.id)) nodes.remove(n.id);

  if (layoutChanged) {
    layoutKey = key;
    for (const [id, p] of Object.entries(pos)) {
      if (nodes.get(id)) network.moveNode(id, p.x, p.y);
    }
    network.fit();
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
        width: isLink ? 2.5 : 1.2,
        arrows: isLink ? "" : { to: { enabled: true, scaleFactor: 0.45 } },
        color: { color: isLink ? "#484f58" : "#6e7681" },
        smooth: isLink ? false : { enabled: true, type: "continuous", roundness: 0.3 },
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
  div.className = "alert " + (a.severity || "info");
  div.innerHTML = `
    <div class="top"><b>${icon} ${a.attack}</b><span>${(a.severity || "").toUpperCase()}</span></div>
    <div class="meta">${a.time} · ${a.src} → ${a.dst} · engine: ${a.engine} · conf: ${a.confidence}</div>
    ${a.severity !== "info" && a.src ? `<button class="act" data-ip="${a.src}">Block ${a.src}</button>` : ""}`;
  return div;
}

function fmtRule(r) {
  const div = document.createElement("div");
  div.className = "rule";
  const allow = r.action === "ALLOW";
  div.innerHTML = `
    <div class="top"><span class="ip">${r.ip}</span><span>${allow ? "\u2611 ALLOW" : "\u26D4 " + r.action}</span></div>
    <div class="meta">${r.time} · ${r.reason}</div>
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
      rows.push({
        time: a.time,
        cls: a.severity === "critical" || a.severity === "high" ? a.severity : "warn",
        msg: `${(a.severity || "info").toUpperCase().padEnd(8)} ${a.attack} · ${a.src} → ${a.dst} · engine ${a.engine} conf ${conf}`,
      });
    }
  }
  for (const r of data.rules) {
    rows.push({
      time: r.time,
      cls: r.action === "BLOCK" ? "fw" : "ok",
      msg: `FW ${r.action.padEnd(5)} ${r.ip} — ${r.reason}`,
    });
  }
  rows.sort((x, y) => y.time.localeCompare(x.time));
  rows.length = Math.min(rows.length, 80);           // keep the panel snappy
  const log = document.getElementById("log");
  log.replaceChildren(
    ...rows.length ? rows.map(fmtLogRow) : [emptyState("waiting for events…")]
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
    ...data.alerts.length ? data.alerts.map(fmtAlert) : [emptyState("no threats yet — watching…")]
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
  await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  refresh();
}

// key: B blocks the currently selected node; double-click renames it
let selected = null;
network.on("selectNode", p => { selected = p.nodes[0]; });
network.on("doubleClick", async p => {
  const ip = p.nodes[0];
  if (!ip) return;
  const label = nodes.get(ip)?.label || "";
  const current = label.split("\n")[0];
  const name = window.prompt(`Name this device (${ip})`, current);
  if (name && name.trim()) await post("/api/devices/rename", { ip, name: name.trim() });
});
window.addEventListener("keydown", ev => {
  if (ev.key.toLowerCase() === "b" && selected) {
    post("/api/firewall/block", { ip: selected, reason: "operator blocked selected node" });
  }
});

// ---- stats / badges -------------------------------------------------------------
const statPrev = {};   // id -> tween state (value + raf handle)

function tweenStat(id, target, fmt = v => Math.round(v).toString()) {
  const el = document.getElementById(id);
  if (!el) return;
  const from = statPrev[id] ?? target;
  statPrev[id] = target;
  if (from === target) { el.textContent = fmt(target); return; }
  const t0 = performance.now(), dur = 350;
  const step = now => {
    const k = Math.min(1, (now - t0) / dur);
    const eased = 1 - Math.pow(1 - k, 2);
    el.textContent = fmt(from + (target - from) * eased);
    if (k < 1) statPrev[id + ":raf"] = requestAnimationFrame(step);
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
    m ? `ML rf · acc ${Math.round(m.accuracy * 100)}% · ${m.dataset}` : "heuristic mode";
}

// ---- data loop: WebSocket w/ polling fallback -----------------------------------
// start polling only ONCE — WS reconnects must not stack intervals
let pollTimer = null;
function startPolling() {
  if (pollTimer) return;
  pollTimer = setInterval(refresh, 2000);
}
function stopPolling() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
}

async function refresh() {
  const res = await fetch("/api/state");
  apply(await res.json());
}

function apply(data) {
  renderTopology(data);
  renderFeeds(data);
  renderLog(data);
  renderStats(data);
}

(async () => {
  refresh().catch(() => {});
  if (typeof WebSocket === "undefined") {
    startPolling();
  } else {
    const connect = () => {
      const proto = location.protocol === "https:" ? "wss" : "ws";
      const ws = new WebSocket(`${proto}://${location.host}/ws`);
      // once the socket is live, the 2 s polling fallback is redundant
      ws.onopen = stopPolling;
      ws.onmessage = ev => apply(JSON.parse(ev.data));
      ws.onclose = () => { startPolling(); setTimeout(connect, 4000); };
    };
    connect();
  }
})();
