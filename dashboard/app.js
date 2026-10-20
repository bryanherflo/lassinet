/* LassiNet dashboard — topology map + live threat feed (no build step). */
"use strict";

const ROLE_STYLE = {
  router:      { color: "#a371f7", label: "Router",        shape: "hexagon" },
  server:      { color: "#58a6ff", label: "Server",        shape: "dot" },
  workstation: { color: "#3fb950", label: "Workstation",   shape: "dot" },
  iot:         { color: "#d29922", label: "IoT",           shape: "dot" },
  printer:     { color: "#8b949e", label: "Printer",       shape: "dot" },
  attacker:    { color: "#f85149", label: "Attacker",      shape: "star"  },
  external:    { color: "#58a6ff", label: "Internet",      shape: "ellipse" },
};

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
  if (s1 && s2) attackPaths.push({ born: now, until: now + FLASH_MS, segments: [s1, s2] });
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

const SPEED = 140;      // packet speed, px/s along the wires
const BALLS = 4;        // packets riding each attack path (staggered)
const BALL_R = 4.5;
const RED = "#f85149";

function nodeDOMPos(ip) {
  const p = network.getPositions([ip])[ip];          // canvas coords
  return p ? network.canvasToDOM(p) : null;          // DOM coords (zoom/pan aware)
}

function drawAttackFx(now) {
  while (attackPaths.length && attackPaths[0].until < now) attackPaths.shift();
  fctx.clearRect(0, 0, fx.width, fx.height);
  for (const p of attackPaths) {
    const pts = [
      nodeDOMPos(p.segments[0][0]),
      nodeDOMPos(p.segments[0][1]),
      nodeDOMPos(p.segments[1][1]),
    ];
    if (pts.some(q => !q)) continue;                 // node vanished mid-flight
    const legs = [
      Math.hypot(pts[1].x - pts[0].x, pts[1].y - pts[0].y),
      Math.hypot(pts[2].x - pts[1].x, pts[2].y - pts[1].y),
    ];
    const total = legs[0] + legs[1];
    if (total <= 0) continue;
    // fade in on spawn, fade out as it expires
    const alpha = Math.min(1, (now - p.born) / 400, Math.max(0, (p.until - now) / 800));
    const d0 = (now / 1000) * SPEED;
    for (let i = 0; i < BALLS; i++) {
      let d = (d0 + (i * total) / BALLS) % total;
      let a, b, legLen;
      if (d < legs[0]) { a = pts[0]; b = pts[1]; legLen = legs[0]; }
      else { d -= legs[0]; a = pts[1]; b = pts[2]; legLen = legs[1]; }
      const t = legLen > 0 ? d / legLen : 0;
      const x = a.x + (b.x - a.x) * t;
      const y = a.y + (b.y - a.y) * t;
      fctx.globalAlpha = alpha;
      fctx.beginPath();
      fctx.arc(x, y, BALL_R, 0, Math.PI * 2);
      fctx.fillStyle = RED;
      fctx.shadowColor = RED;
      fctx.shadowBlur = 12;
      fctx.fill();
      fctx.shadowBlur = 0;
      fctx.globalAlpha = 1;
    }
  }
}

(function tick() {
  drawAttackFx(Date.now());
  requestAnimationFrame(tick);
})();

function renderTopology(data) {
  const now = Date.now();
  updateFlashes(data, now);
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
      font: { color: isBlocked ? "#8b949e" : "#c9d1d9" },
    };
    if (!nodes.get(h.ip)) {
      nodes.add({
        id: h.ip, label: `${h.hostname}\n${h.ip}`,
        title: `${isBlocked ? "\u{1F6AB} BLOCKED" : style.label}\nMAC: ${h.mac || "n/a"}\nports: ${h.open_ports.length ? h.open_ports.join(", ") : "—"}\nselect + press B to block`,
        shape: style.shape,
        size: h.role === "router" ? 20 : h.role === "external" ? 16 : 13,
        ...(h.role === "external" ? { shapeProperties: { borderDashes: [4, 4] } } : {}),
        x: pos[h.ip].x, y: pos[h.ip].y,
        ...base,
      });
    } else {
      nodes.update({ id: h.ip, ...base });
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

function renderFeeds(data) {
  const alerts = document.getElementById("alerts");
  alerts.replaceChildren(...data.alerts.map(fmtAlert));
  const rules = document.getElementById("rules");
  rules.replaceChildren(...data.rules.map(fmtRule));
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

// key: B blocks the currently selected node
let selected = null;
network.on("selectNode", p => { selected = p.nodes[0]; });
window.addEventListener("keydown", ev => {
  if (ev.key.toLowerCase() === "b" && selected) {
    post("/api/firewall/block", { ip: selected, reason: "operator blocked selected node" });
  }
});

// ---- stats / badges -------------------------------------------------------------
function renderStats(data) {
  const s = data.stats;
  document.getElementById("s-devices").textContent = data.nodes.length;
  document.getElementById("s-flows").textContent = s.flows_per_sec;
  document.getElementById("s-alerts").textContent = s.attacks_total;
  document.getElementById("s-blocked").textContent = s.blocks_total;
  document.getElementById("mode-badge").textContent = "\u25CF " + (data.mode || "demo");
  const m = data.model_metrics;
  document.getElementById("model-badge").textContent =
    m ? `ML rf · acc ${Math.round(m.accuracy * 100)}% · ${m.dataset}` : "heuristic mode";
}

// ---- data loop: WebSocket w/ polling fallback -----------------------------------
// start polling only ONCE — WS reconnects must not stack intervals
let pollingStarted = false;
function startPolling() {
  if (pollingStarted) return;
  pollingStarted = true;
  setInterval(refresh, 2000);
}

async function refresh() {
  const res = await fetch("/api/state");
  apply(await res.json());
}

function apply(data) {
  renderTopology(data);
  renderFeeds(data);
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
      ws.onmessage = ev => apply(JSON.parse(ev.data));
      ws.onclose = () => { startPolling(); setTimeout(connect, 4000); };
    };
    connect();
  }
})();
