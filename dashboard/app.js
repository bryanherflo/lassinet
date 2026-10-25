/* LassiNet dashboard — topology map + live threat feed (no build step). */
"use strict";

const ROLE_STYLE = {
  router:      { color: "#b18cff", label: "Router",        glyph: "router" },
  server:      { color: "#58a6ff", label: "Server",        glyph: "server" },
  workstation: { color: "#3fb950", label: "Workstation",   glyph: "desktop" },
  iot:         { color: "#d29922", label: "IoT",           glyph: "iot" },
  printer:     { color: "#8b949e", label: "Printer",       glyph: "printer" },
  attacker:    { color: "#f85149", label: "Attacker",      glyph: "attacker" },
  unknown:     { color: "#8b949e", label: "Unknown",       glyph: "unknown" },
  external:    { color: "#58a6ff", label: "Internet",      glyph: "external" },
  trusted:     { color: "#3fb950", label: "Trusted",       glyph: "desktop" },
};

// Device kinds come from the server (`lassi/devices.py`, inferred from the
// name and the MAC vendor) and get their own glyph, so a phone no longer looks
// like a laptop. Line art instead of emoji on purpose: same drawing on
// Windows, Linux and macOS, and it matches the purpose-drawn router glyph.
const GLYPHS = {
  phone:    '<rect x="20" y="9" width="24" height="46" rx="5.5"/><path d="M28.5 14h7"/><circle cx="32" cy="48" r="2.4"/>',
  tablet:   '<rect x="13" y="12" width="38" height="40" rx="4.5"/><circle cx="32" cy="46" r="1.9"/>',
  laptop:   '<rect x="14" y="14" width="36" height="25" rx="2.5"/><path d="M9.5 43h45l-3.2 5.5H12.7z"/><path d="M27 46h10"/>',
  desktop:  '<rect x="10" y="13" width="44" height="28" rx="3"/><path d="M32 41v6M22 48h20"/>',
  server:   '<rect x="17" y="8" width="30" height="48" rx="3"/><path d="M23 16h18M23 24h18M23 32h18"/><circle cx="38" cy="45" r="2"/><path d="M23 45h8"/>',
  printer:  '<rect x="15" y="27" width="34" height="18" rx="3"/><rect x="21" y="12" width="22" height="15" rx="2"/><rect x="21" y="45" width="22" height="7" rx="1.5"/><circle cx="43" cy="33" r="1.6"/>',
  camera:   '<rect x="10" y="20" width="44" height="26" rx="5"/><path d="M20 20l5-6h14l5 6"/><circle cx="32" cy="33" r="7.5"/>',
  tv:       '<rect x="9" y="14" width="46" height="30" rx="3"/><path d="M32 44v6M22 50h20"/>',
  console:  '<path d="M14 24h36c4 0 6 4 6 8v3c0 5-4 7-8 6l-7-3H21l-7 3c-4 1-8-1-8-6v-3c0-4 2-8 8-8z"/><path d="M20 29v8M16 33h8"/><circle cx="40" cy="30" r="2"/><circle cx="45" cy="35" r="2"/>',
  speaker:  '<rect x="19" y="10" width="26" height="44" rx="10"/><circle cx="32" cy="38" r="6"/><circle cx="32" cy="20" r="2.4"/>',
  watch:    '<rect x="21" y="17" width="22" height="30" rx="7"/><path d="M26 17v-5h12v5M26 47v5h12v-5"/><circle cx="32" cy="32" r="5"/>',
  nas:      '<rect x="17" y="10" width="30" height="18" rx="2"/><rect x="17" y="30" width="30" height="18" rx="2"/><circle cx="24" cy="19" r="1.6"/><circle cx="24" cy="39" r="1.6"/><path d="M30 19h12M30 39h12"/>',
  sbc:      '<rect x="14" y="15" width="36" height="34" rx="3"/><circle cx="32" cy="32" r="6"/><path d="M14 23h-6M14 32h-6M14 41h-6M50 23h6M50 32h6M50 41h6"/>',
  iot:      '<rect x="20" y="24" width="24" height="18" rx="5"/><path d="M26 24v-9M38 24v-9M32 42v11"/>',
  external: '<path d="M20 41h24a8 8 0 0 0 0-16 11 11 0 0 0-21-2 7 7 0 0 0-3 18z"/>',
  attacker: '<path d="M20 31a12 12 0 0 1 24 0v6a5 5 0 0 1-5 5h-2v5h-4v-5h-2v5h-4v-5h-2a5 5 0 0 1-5-5z"/><circle cx="26.5" cy="31" r="2.4"/><circle cx="37.5" cy="31" r="2.4"/>',
  unknown:  '<path d="M24.5 25a7.5 7.5 0 1 1 11 6.6c-2 1-3.5 2.4-3.5 5.4"/><circle cx="32" cy="45" r="2.2"/>',
};

// Human labels for the legend and the selection bar. Order = legend order.
const KIND_LABELS = {
  phone: "Phone", tablet: "Tablet", laptop: "Laptop", desktop: "Desktop",
  server: "Server", tv: "TV", console: "Console", printer: "Printer",
  camera: "Camera", speaker: "Speaker", watch: "Watch", nas: "NAS",
  sbc: "SBC", iot: "Smart device",
};
const LEGEND_KINDS = Object.keys(KIND_LABELS);

var GLYPH_CACHE = {};
function glyphIconURI(name) {
  if (name === "router") return routerIconURI();
  var key = Object.prototype.hasOwnProperty.call(GLYPHS, name) ? name : "unknown";
  if (GLYPH_CACHE[key]) return GLYPH_CACHE[key];
  var svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">' +
    '<circle cx="32" cy="32" r="31" fill="#161b22"/>' +
    '<g fill="none" stroke="#e6edf3" stroke-width="3" stroke-linecap="round" stroke-linejoin="round">' +
    GLYPHS[key] + '</g></svg>';
  return (GLYPH_CACHE[key] = "data:image/svg+xml," + encodeURIComponent(svg));
}

// Which glyph a node shows: the confirmed-attacker skull wins, then the
// inferred device kind, then the role's own icon. An ARP-discovered host with
// no kind is drawn as "unknown" instead of pretending it is a desktop.
function nodeGlyph(host, displayRole, isAttacker) {
  if (isAttacker) return "attacker";
  if (host.kind === "router" || host.kind === "external") return host.kind;
  if (host.kind && GLYPHS[host.kind]) return host.kind;
  var style = ROLE_STYLE[displayRole] || ROLE_STYLE.workstation;
  if (style.glyph === "desktop" && displayRole === "workstation") return "unknown";
  return style.glyph;
}

// Map label: name on the first line, address on the second. A device that has
// not been named yet would print the address twice, so show it only once. Any
// whitespace inside the name collapses: the label is canvas text with a fixed
// two-line layout and a pasted newline would push the address off the node.
function nodeLabel(hostname, ip) {
  var name = String(hostname || "").replace(/\s+/g, " ").trim();
  return !name || name === ip ? String(ip) : name + "\n" + ip;
}

// "seen 4m ago" for a device the sensor has not heard from in a while: on a
// real LAN a sleeping phone looks exactly like a quiet one.
function fmtSeen(epochSeconds) {
  var ts = Number(epochSeconds);
  if (!isFinite(ts) || ts <= 0) return "";
  var seconds = Math.max(0, Math.round(Date.now() / 1000 - ts));
  if (seconds < 60) return "just now";
  if (seconds < 3600) return Math.round(seconds / 60) + "m ago";
  if (seconds < 86400) return Math.round(seconds / 3600) + "h ago";
  return Math.round(seconds / 86400) + "d ago";
}

// A purpose-drawn gateway glyph reads better than a flat hexagon and keeps the
// same circular language as every other device. Rendered as an inline SVG so
// the dashboard still ships with no build step and no external assets.
var ROUTER_ICON = null;
function routerIconURI() {
  if (ROUTER_ICON) return ROUTER_ICON;
  var svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">' +
    '<defs>' +
      '<radialGradient id="bg" cx="34%" cy="24%" r="88%">' +
        '<stop offset="0" stop-color="#44306f"/><stop offset=".55" stop-color="#21183a"/><stop offset="1" stop-color="#0e0c18"/>' +
      '</radialGradient>' +
      '<linearGradient id="rim" x1="0" y1="0" x2="1" y2="1">' +
        '<stop stop-color="#d7c7ff"/><stop offset=".5" stop-color="#9b6dff"/><stop offset="1" stop-color="#58a6ff"/>' +
      '</linearGradient>' +
    '</defs>' +
    '<circle cx="32" cy="32" r="30" fill="url(#bg)"/>' +
    '<circle cx="32" cy="32" r="29" fill="none" stroke="url(#rim)" stroke-width="1.6" opacity=".95"/>' +
    '<g fill="none" stroke="#eee8ff" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">' +
      '<rect x="19" y="38" width="26" height="10.5" rx="3.2"/>' +
      '<path d="M24.5 38v-4.2M39.5 38v-4.2"/>' +
      '<path d="M22.5 28.2c5.2-4.4 13.8-4.4 19 0"/>' +
      '<path d="M26.6 32.5c3.1-2.6 7.7-2.6 10.8 0" opacity=".82"/>' +
    '</g>' +
    '<circle cx="32" cy="34" r="1.7" fill="#d7c7ff"/>' +
    '<circle cx="24" cy="43.6" r="1.15" fill="#58a6ff"/>' +
    '<circle cx="27.5" cy="43.6" r="1.15" fill="#b18cff"/>' +
    '</svg>';
  return (ROUTER_ICON = "data:image/svg+xml," + encodeURIComponent(svg));
}

// Escape untrusted strings (hostnames, IPs coming from the capture) before
// interpolating them into innerHTML.
function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, function(c) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
  });
}

var SEV_ICONS = { critical: "\u{1F6A8}", high: "\u26A0\uFE0F", medium: "\u26D3\uFE0F", info: "\u2705" };

// Technical detector names -> labels a human can read at a glance.
var ATTACK_LABELS = {
  port_scan: "Port scan",
  brute_force: "Brute force",
  ddos: "DDoS",
  data_exfiltration: "Data exfiltration",
  auto_block: "Auto-block fired",
};
function attackLabel(name) {
  return ATTACK_LABELS[name] || String(name || "attack").replace(/_/g, " ");
}

// Infrastructure addresses (edge router, Internet placeholder) are never valid
// block targets: dropping the router would cut the whole map. Trusted devices
// are protected by the server for the same reason (a false positive on the
// DNS/DHCP server of the LAN would take the network down). Any other IP —
// including an external source that is not on the map yet — can be blocked.
function isBlockableNode(ip) {
  var node = nodes.get(ip);
  return !!node && node.hostRole !== "router" && node.hostRole !== "external";
}
function isIpLiteral(ip) {
  // Valid IPv4 (each octet <= 255) or a colon-shaped IPv6 literal. Used before
  // offering a block button, so the UI never promises a block the server will
  // refuse ("no-es-ip", "192.168.0.999", "<img src=x>" and friends).
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) {
    return ip.split(".").every(function(part) { return Number(part) <= 255; });
  }
  return ip.indexOf(":") >= 0 && /^[0-9a-f:.]+$/i.test(ip);
}
function canBlockIp(ip) {
  if (!isIpLiteral(ip)) return false;
  if (ip === "0.0.0.0" || ip === "::") return false;      // unspecified
  if (/^127\./.test(ip) || ip === "::1") return false;    // loopback
  if (trustedDevices.has(ip)) return false;
  var node = nodes.get(ip);
  return !node || (node.hostRole !== "router" && node.hostRole !== "external");
}

var nodes = new vis.DataSet([]);
var edges = new vis.DataSet([]);
var network = new vis.Network(
  document.getElementById("map"),
  { nodes: nodes, edges: edges },
  {
    autoResize: true,
    physics: { enabled: false },
    interaction: { hover: true, tooltipDelay: 120, selectable: true, multiselect: false, navigationButtons: false, keyboard: true },
    nodes: { font: { color: "#c9d1d9", size: 12, face: "Segoe UI" }, borderWidth: 2, scaling: { min: 10, max: 30 } },
    edges: { smooth: { enabled: true, type: "continuous", roundness: 0.3 } },
    layout: { randomSeed: 42 },
  }
);

var confirmedAttackers = new Set();
var trustedDevices = new Set();
var suspiciousDevices = new Set();

// The trust mark lives on the server: a trusted device is never blocked there,
// not only painted in a different colour. The snapshot is the source of truth,
// so a restart (or another browser) shows the same protected devices.
function syncTrusted(data) {
  if (!data || !Array.isArray(data.trusted)) return;
  var server = new Set(data.trusted);
  server.forEach(function(ip) { trustedDevices.add(ip); suspiciousDevices.delete(ip); });
  Array.from(trustedDevices).forEach(function(ip) {
    if (!server.has(ip)) trustedDevices.delete(ip);
  });
}

var ROLE_ORDER = { server: 0, workstation: 1, iot: 2, printer: 3, attacker: 4, unknown: 5, trusted: 6 };
var layoutKey = "";

function computeTreeLayout(data) {
  var router = data.nodes.find(function(h) { return h.role === "router"; });
  var ext = data.nodes.find(function(h) { return h.role === "external"; });
  var leaves = data.nodes.filter(function(h) { return h.role !== "router" && h.role !== "external"; })
    .sort(function(a, b) { return (ROLE_ORDER[a.role] ?? 9) - (ROLE_ORDER[b.role] ?? 9) || a.ip.localeCompare(b.ip); });
  var pos = {};
  if (ext) pos[ext.ip] = { x: 0, y: -220 };
  if (router) pos[router.ip] = { x: 0, y: 0 };
  var n = leaves.length;
  if (!n) return pos;
  var mapEl = document.getElementById("map");
  var width = mapEl ? mapEl.clientWidth : 800;
  // The legend floats over the right edge (~290 px). A single row of 12 nodes
  // made fit() zoom out until the icons were unreadable (and the last nodes
  // hid behind the legend), so wrap the leaves into balanced rows.
  var usable = Math.max(420, width - 300);
  var perRowMax = Math.max(3, Math.min(7, Math.floor(usable / 125)));
  var rows = Math.max(1, Math.ceil(n / perRowMax));
  var assigned = [];
  leaves.forEach(function(h, i) {
    var row = Math.min(rows - 1, Math.floor(i * rows / n));
    (assigned[row] = assigned[row] || []).push(h);
  });
  assigned.forEach(function(rowHosts, r) {
    var count = rowHosts.length;
    var step = Math.min(230, usable / Math.max(count, 1));
    rowHosts.forEach(function(h, c) {
      pos[h.ip] = { x: (c - (count - 1) / 2) * step, y: 190 + r * 150 };
    });
  });
  return pos;
}

// Fit the tree in the space the floating legend leaves free. `fit()` alone
// centres on the whole canvas, which puts the rightmost nodes under the legend.
function fitMapView(animate) {
  network.fit({ animation: animate ? { duration: 500, easingFunction: "easeOutQuad" } : false });
  var legend = document.getElementById("legend");
  var legendW = (legend && !legend.classList.contains("collapsed")) ? legend.offsetWidth + 16 : 0;
  if (legendW > 0) {
    var view = network.getViewPosition();
    var scale = network.getScale() || 1;
    network.moveTo({ position: { x: view.x + (legendW / 2) / scale, y: view.y }, animation: false });
  }
}

var lastAttacks = -1;
var flashUntil = {};
var attackPaths = [];
var FLASH_MS = 8000;
var lastBannerKey = null;

function alertKey(a) {
  return [a.time, a.attack, a.severity, a.src, a.dst, a.confidence].join("|");
}

// On the first snapshot, keep known attacker sources as attackers instead of
// demoting them to "unknown" until the next alert arrives.
function seedConfirmedAttackers(data) {
  data.alerts.forEach(function(a) {
    if (a.src && (a.severity === "critical" || a.severity === "high") && !trustedDevices.has(a.src)) {
      confirmedAttackers.add(a.src);
    }
  });
}

function newestSevereAlert(data) {
  for (var i = 0; i < data.alerts.length; i++) {
    var a = data.alerts[i];
    if (a.attack === "auto_block") continue;
    if (blockedHosts.has(a.src) || blockedHosts.has(a.dst)) continue;
    if (a.severity === "critical" || a.severity === "high") return a;
  }
  return null;
}

function markAttackPath(data, a, now) {
  var router = data.nodes.find(function(h) { return h.role === "router"; });
  if (!router || !a.src) return;
  if (blockedHosts.has(a.src) || blockedHosts.has(a.dst)) return;
  var hostIps = new Set(data.nodes.map(function(h) { return h.ip; }));
  var victim = a.dst;
  if (!hostIps.has(victim)) victim = (data.nodes.find(function(h) { return h.role === "external"; }) || {}).ip;
  if (!victim || victim === a.src) return;
  var links = new Set(data.edges.filter(function(e) { return e.kind === "link"; }).map(function(e) { return e.from + "|" + e.to; }));
  var seg = function(u, v) { return (links.has(u + "|" + v) || links.has(v + "|" + u)) ? [u, v] : null; };
  var s1 = seg(a.src, router.ip);
  var s2 = seg(router.ip, victim);
  if (s1 && s2) {
    var key = s1[0] + ">" + s1[1] + "|" + s2[0] + ">" + s2[1];
    var exists = attackPaths.some(function(p) { return p.until > now && p.key === key; });
    if (!exists) attackPaths.push({ key: key, born: now, until: now + FLASH_MS, segments: [s1, s2], severity: a.severity, src: a.src, dst: a.dst });
    if (!confirmedAttackers.has(a.src) && !trustedDevices.has(a.src)) {
      confirmedAttackers.add(a.src);
      upgradeToAttacker(a.src);
    }
  }
}

function upgradeToAttacker(ip) { applyNodeRole(ip, "attacker", "ATTACKER (confirmed)"); }

function updateFlashes(data, now) {
  var total = data.stats.attacks_total;
  if (lastAttacks < 0) {
    lastAttacks = total;
    seedConfirmedAttackers(data);
    var initial = newestSevereAlert(data);
    if (initial) lastBannerKey = alertKey(initial);   // never banner old history on page load
    return;
  }
  if (total < lastAttacks) {
    // Server restarted and its counters reset; do not wait forever for the
    // old total to catch up before flashing new attacks again.
    lastAttacks = total;
    lastBannerKey = null;
    attackPaths.length = 0;
  }
  var fresh = Math.max(0, total - lastAttacks);
  lastAttacks = total;
  while (attackPaths.length && attackPaths[0].until < now) attackPaths.shift();
  attackPaths = attackPaths.filter(function(p) { return !blockedHosts.has(p.src) && !blockedHosts.has(p.dst); });
  // The feed is newest-first and contains both detections and the auto-block
  // confirmation card. Count only real detections, otherwise one confirmation
  // at the front can hide the fresh attack below it.
  var seenFresh = 0;
  for (var i = 0; i < data.alerts.length && seenFresh < fresh; i++) {
    var a = data.alerts[i];
    if (!a || a.attack === "auto_block") continue;
    seenFresh++;
    if (blockedHosts.has(a.src) || blockedHosts.has(a.dst)) continue;   // dropped by the firewall
    if (a.src) flashUntil[a.src] = now + FLASH_MS;
    markAttackPath(data, a, now);
  }
  // Banner policy: only for a genuinely new high/critical detection - never for
  // history replayed by the attack-animation loop, and only one at a time.
  var severe = newestSevereAlert(data);
  if (severe) {
    var key = alertKey(severe);
    if (key !== lastBannerKey) {
      lastBannerKey = key;
      if (!attackBannerEl) showAttackBanner(severe);
    }
  }
}

var attackBannerEl = null, attackBannerTimer = null;
function hideAttackBanner() {
  if (attackBannerTimer) { clearTimeout(attackBannerTimer); attackBannerTimer = null; }
  if (attackBannerEl) { attackBannerEl.remove(); attackBannerEl = null; }
}

function showAttackBanner(alert) {
  hideAttackBanner();
  var sev = alert.severity || "high";
  var icon = SEV_ICONS[sev] || "\u26A0\uFE0F";
  var conf = typeof alert.confidence === "number" ? alert.confidence.toFixed(2) : (alert.confidence || "?");
  var el = document.createElement("div");
  el.id = "attack-banner";
  el.className = "attack-banner " + sev;
  el.dataset.src = alert.src || "";
  el.setAttribute("role", "alert");
  var blockAction = canBlockIp(alert.src)
    ? '<button class="banner-act" title="Drop traffic from ' + esc(alert.src) + ' at the firewall (reversible)">Block source ' + esc(alert.src) + '</button>'
    : "";
  el.innerHTML = '<div class="banner-content"><span class="banner-icon">' + icon + '</span>' +
    '<div class="banner-text"><strong>' + esc(attackLabel(alert.attack)) + ' detected</strong>' +
    '<span>' + esc(alert.src) + ' \u2192 ' + esc(alert.dst) + ' \u00B7 confidence ' + esc(conf) + ' \u00B7 engine ' + esc(alert.engine || "ml") + '</span></div>' +
    blockAction +
    '<button class="banner-close" aria-label="Dismiss alert" title="Dismiss">\u00D7</button></div>';
  document.body.appendChild(el);
  attackBannerEl = el;
  el.querySelector(".banner-close").onclick = hideAttackBanner;
  var act = el.querySelector(".banner-act");
  if (act) act.onclick = function() {
    post("/api/firewall/block", { ip: alert.src, reason: "operator blocked from attack banner" });
    hideAttackBanner();
  };
  attackBannerTimer = setTimeout(hideAttackBanner, 10000);
}

var fxHost = document.getElementById("map");
fxHost.style.position = "relative";
var fx = document.createElement("canvas");
fx.style.position = "absolute";
fx.style.inset = "0";
fx.style.width = "100%";
fx.style.height = "100%";
fx.style.pointerEvents = "none";
fx.style.zIndex = "5";
fxHost.appendChild(fx);
var fctx = fx.getContext("2d");

function sizeFx() {
  var rect = fxHost.getBoundingClientRect();
  fx.width = Math.max(1, Math.floor(rect.width));
  fx.height = Math.max(1, Math.floor(rect.height));
}
new ResizeObserver(sizeFx).observe(fxHost);
sizeFx();

var SPEED = 180, BALLS = 6, BALL_R = 6, AMBIENT_MAX = 8, SPAWN_MS = 180;
var fxRouter = null, fxExt = null, fxLinks = new Set(), fxHostIds = new Set(), fxRoles = new Map(), trafficSamples = [];
var ambientDots = []; var lastSpawn = 0;
var blockedHosts = new Set();
var FLOW_COLOR = "#58a6ff";
var FX_ENABLED = true;
try { FX_ENABLED = localStorage.getItem("lassi.fx") !== "off"; } catch (e) { /* storage disabled */ }

function fxSync(data) {
  fxRouter = (data.nodes.find(function(h) { return h.role === "router"; }) || {}).ip || null;
  fxExt = (data.nodes.find(function(h) { return h.role === "external"; }) || {}).ip || null;
  fxHostIds = new Set(data.nodes.map(function(h) { return h.ip; }));
  fxRoles = new Map(data.nodes.map(function(h) { return [h.ip, h.role]; }));
  fxLinks = new Set(data.edges.filter(function(e) { return e.kind === "link"; }).map(function(e) { return e.from + "|" + e.to; }));
  trafficSamples = Array.isArray(data.traffic) ? data.traffic : [];
  var blocked = Array.isArray(data.blocked_ips) ? data.blocked_ips.slice() : [];
  data.nodes.forEach(function(h) { if (h.blocked && blocked.indexOf(h.ip) < 0) blocked.push(h.ip); });
  blockedHosts = new Set(blocked);
}

function spawnAmbient(now) {
  if (!FX_ENABLED || !trafficSamples.length || ambientDots.length >= AMBIENT_MAX) return;
  if (now - lastSpawn < SPAWN_MS) return;
  lastSpawn = now;
  // Pick only live traffic between hosts that are not blocked: a blocked
  // device must not keep emitting dots after the firewall drops it.
  var candidates = trafficSamples.filter(function(s) {
    return s && !s.attack && s.src !== s.dst && fxHostIds.has(s.src) &&
      !blockedHosts.has(s.src) && !blockedHosts.has(s.dst);
  });
  if (!candidates.length) return;
  var s = candidates[Math.floor(Math.random() * candidates.length)];
  var src = s.src, dst = fxHostIds.has(s.dst) ? s.dst : fxExt;
  if (!dst || src === dst) return;
  var link = function(u, v) { return (fxLinks.has(u + "|" + v) || fxLinks.has(v + "|" + u)) ? [u, v] : null; };
  var raw = src === fxRouter ? [link(src, dst)] : [link(src, fxRouter), link(fxRouter, dst)];
  var segments = raw.filter(Boolean);
  if (!segments.length) return;
  var bytes = Math.max(0, +s.bytes || 0);
  var radius = 2 + Math.min(1.2, Math.log10(1 + bytes / 600));
  ambientDots.push({ born: now, until: now + 900 + Math.random() * 1100, segments: segments, kind: "ambient", radius: radius });
}

function nodeDOMPos(ip) { var p = network.getPositions([ip])[ip]; return p ? network.canvasToDOM(p) : null; }

function drawGlowDot(x, y, r, col, a, glow) { if (r <= 0 || a <= 0) return; fctx.globalAlpha = a; fctx.beginPath(); fctx.arc(x, y, r, 0, Math.PI * 2); fctx.fillStyle = col; if (glow > 0) { fctx.shadowColor = col; fctx.shadowBlur = glow; } fctx.fill(); fctx.shadowBlur = 0; fctx.globalAlpha = 1; }

function drawRider(p, now) {
  if (!p.segments || !p.segments.length) return;
  var from = p.segments[0][0], to = p.segments[p.segments.length - 1][1];
  if (blockedHosts.has(from) || blockedHosts.has(to)) return;
  var idx = p.segments.map(function(seg) { return nodeDOMPos(seg[0]); });
  idx.push(nodeDOMPos(p.segments[p.segments.length - 1][1]));
  if (idx.some(function(q) { return !q; })) return;
  var legs = []; var total = 0;
  for (var i = 0; i < idx.length - 1; i++) { var L = Math.hypot(idx[i+1].x - idx[i].x, idx[i+1].y - idx[i].y); legs.push(L); total += L; }
  if (total <= 0) return;
  var xyAt = function(d) { var rest = Math.max(0, Math.min(d, total)); for (var k = 0; k < legs.length; k++) { if (rest <= legs[k]) { var t = legs[k] > 0 ? rest / legs[k] : 0; return [idx[k].x + (idx[k+1].x - idx[k].x) * t, idx[k].y + (idx[k+1].y - idx[k].y) * t]; } rest -= legs[k]; } var last = idx[idx.length - 1]; return [last.x, last.y]; };
  var fade = Math.min(1, (now - p.born) / 300, Math.max(0, (p.until - now) / 600));
  if (p.kind === "ambient") {
    // Normal traffic is deliberately quiet: one soft cyan dot, no comet trail.
    // Red is reserved for attacks, so the map has an unambiguous colour code.
    var R = p.radius || 2.4;
    var ph = Math.min(1, (now - p.born) / (p.until - p.born));
    var xy = xyAt(ph * total);
    drawGlowDot(xy[0], xy[1], R, FLOW_COLOR, fade * 0.75, 5);
    return;
  }
  var severity = p.severity || "high";
  var severityColor = severity === "critical" ? "#ff0040" : severity === "high" ? "#f85149" : "#ff8c00";
  var d0 = (now / 1000) * SPEED;
  for (var i = 0; i < BALLS; i++) { var d = (d0 + (i * total) / BALLS) % total; for (var g = 4; g >= 0; g--) { var dd = ((d - g * 12) % total + total) % total; var xy2 = xyAt(dd); drawGlowDot(xy2[0], xy2[1], g === 0 ? BALL_R : Math.max(1, BALL_R * (0.5 - g * 0.07)), severityColor, fade * (g === 0 ? 1 : 0.2 / g), g === 0 ? 20 : 0); } }
}

// Role bands are drawn only for roles that carry information. "workstation"
// is the default role every discovered host gets when nothing else is known,
// so a green band around it would claim a finding nobody made (on a real LAN
// six unnamed devices ended up inside one). Their unknown glyph is the honest
// signal; a band appears when there is something to say (server, IoT, printer,
// attacker, trusted, suspicious).
var GROUP_ROLES = new Set(["server", "iot", "printer", "attacker", "trusted", "unknown"]);
function drawGroupBoxes() {
  if (!fxRoles.size) return;
  var pos = network.getPositions(); var groups = new Map();
  fxRoles.forEach(function(role, ip) {
    if (!GROUP_ROLES.has(role) || !pos[ip]) return;
    var d = network.canvasToDOM(pos[ip]);
    // One box per role *per row*: the layout wraps rows, so a role that spans
    // two rows must not become one giant box around the router.
    var key = role + "|" + Math.round(d.y / 40);
    if (!groups.has(key)) groups.set(key, { role: role, pts: [] });
    groups.get(key).pts.push(d);
  });
  groups.forEach(function(group) {
    var pts = group.pts;
    if (pts.length < 2) return;            // one node is not a group
    var xs = pts.map(function(p) { return p.x; }), ys = pts.map(function(p) { return p.y; });
    var x0 = Math.min.apply(null, xs) - 60, x1 = Math.max.apply(null, xs) + 60;
    var y0 = Math.min.apply(null, ys) - 40, y1 = Math.max.apply(null, ys) + 55;
    var col = (ROLE_STYLE[group.role] || ROLE_STYLE.workstation).color;
    fctx.beginPath();
    if (fctx.roundRect) fctx.roundRect(x0, y0, x1 - x0, y1 - y0, 18);
    else fctx.rect(x0, y0, x1 - x0, y1 - y0);
    fctx.fillStyle = col + "0d"; fctx.fill();
    fctx.strokeStyle = col + "35"; fctx.lineWidth = 1.5;
    fctx.setLineDash([6, 6]); fctx.stroke(); fctx.setLineDash([]);
  });
}

var selectedNodeIp = null, selectionPulse = 0;
function drawSelectionHighlight(now) {
  if (!selectedNodeIp) return;
  var pos = network.getPositions([selectedNodeIp])[selectedNodeIp]; if (!pos) return;
  var dom = network.canvasToDOM(pos); if (!dom) return;
  selectionPulse = (selectionPulse + 0.08) % (Math.PI * 2);
  var pulseScale = 1 + 0.18 * Math.sin(selectionPulse); var baseR = 28 * pulseScale;
  fctx.beginPath(); fctx.arc(dom.x, dom.y, baseR, 0, Math.PI * 2); fctx.strokeStyle = "#58a6ff"; fctx.lineWidth = 3; fctx.setLineDash([10, 8]); fctx.stroke(); fctx.setLineDash([]);
  fctx.beginPath(); fctx.arc(dom.x, dom.y, baseR * 0.65, 0, Math.PI * 2); fctx.strokeStyle = "rgba(88,166,255,0.25)"; fctx.lineWidth = 1.5; fctx.stroke();
}

function drawAttackFx(now) {
  while (attackPaths.length && attackPaths[0].until < now) attackPaths.shift();
  while (ambientDots.length && ambientDots[0].until < now) ambientDots.shift();
  spawnAmbient(now);
  fctx.clearRect(0, 0, fx.width, fx.height);
  drawGroupBoxes();
  if (FX_ENABLED) {
    for (var i = 0; i < attackPaths.length; i++) drawRider(Object.assign({}, attackPaths[i], { kind: "attack" }), now);
    for (var j = 0; j < ambientDots.length; j++) drawRider(ambientDots[j], now);
  }
  drawSelectionHighlight(now);
}
(function tick() { drawAttackFx(Date.now()); requestAnimationFrame(tick); })();

network.on("selectNode", function(p) {
  selectedNodeIp = p.nodes[0] || null;
  updateSelectionBar();
});
network.on("deselectNode", function() {
  selectedNodeIp = null;
  updateSelectionBar();
});

// Selected-device action bar: makes click-to-act discoverable without knowing
// the right-click menu or the B shortcut.
var lastPannedSelection = null;
function ensureSelectionVisible() {
  if (!selectedNodeIp) return;
  var bar = document.getElementById("selection-bar");
  var mapEl = document.getElementById("map");
  if (!bar || bar.hidden || !mapEl) return;
  var coords = network.getPositions([selectedNodeIp])[selectedNodeIp];
  if (!coords) return;
  var dom = network.canvasToDOM(coords);
  var mapRect = mapEl.getBoundingClientRect();
  // Use layout offset, not getBoundingClientRect: the bar has an entrance
  // animation (translateY) and measuring mid-animation would under-pan.
  var containerRect = document.getElementById("map-container").getBoundingClientRect();
  var barTop = containerRect.top + bar.offsetTop;
  // Leave room for the label under the node, not just the circle.
  var overlap = (mapRect.top + dom.y + 28) - barTop;
  if (overlap <= 0) return;
  var view = network.getViewPosition();
  var scale = network.getScale() || 1;
  network.moveTo({
    position: { x: view.x, y: view.y + overlap / scale },
    animation: { duration: 220, easingFunction: "easeOutQuad" },
  });
}
function updateSelectionBar() {
  var bar = document.getElementById("selection-bar");
  if (!bar) return;
  var node = selectedNodeIp ? nodes.get(selectedNodeIp) : null;
  if (selectedNodeIp && !node) {
    // The selected device left the map (asleep, lease expired): forget it, or
    // the "b" shortcut would keep referring to an address that is no longer a
    // device on this network.
    selectedNodeIp = null;
    lastPannedSelection = null;
    network.unselectAll();
  }
  var baseRole = node ? (node.hostRole || node.role) : null;
  if (!node || baseRole === "router" || baseRole === "external") {
    bar.hidden = true;
    lastPannedSelection = null;
    return;
  }
  var blocked = blockedHosts.has(selectedNodeIp);
  bar.hidden = false;
  bar.classList.toggle("blocked", blocked);
  var displayName = node.hostname || String(node.label || selectedNodeIp).split("\n")[0];
  var unnamed = !node.hostname || node.hostname === selectedNodeIp;
  document.getElementById("sel-name").textContent = unnamed ? selectedNodeIp : displayName;
  var ipEl = document.getElementById("sel-ip");
  ipEl.textContent = selectedNodeIp;
  ipEl.hidden = unnamed;
  var kindEl = document.getElementById("sel-kind");
  var kindLabel = node.kind ? (KIND_LABELS[node.kind] || "") : "";
  if (kindEl) { kindEl.textContent = kindLabel; kindEl.hidden = !kindLabel; }
  var seenEl = document.getElementById("sel-seen");
  if (seenEl) {
    var seen = fmtSeen(node.lastSeen);
    seenEl.textContent = seen ? "seen " + seen : "";
    seenEl.hidden = !seen;
  }
  var btn = document.getElementById("sel-block");
  btn.textContent = blocked ? "Unblock IP" : "Block IP";
  btn.className = "sel-btn " + (blocked ? "safe" : "danger");
  btn.title = blocked ? "Remove the firewall block for " + selectedNodeIp : "Drop traffic from " + selectedNodeIp + " at the firewall (reversible)";
  btn.setAttribute("aria-label", (blocked ? "Unblock " : "Block ") + selectedNodeIp);
  // Pan only when the selection changes (not on every data tick), so the
  // operator can still pan freely while a device stays selected.
  if (lastPannedSelection !== selectedNodeIp) {
    lastPannedSelection = selectedNodeIp;
    requestAnimationFrame(ensureSelectionVisible);
  }
}
document.getElementById("sel-block").onclick = function() {
  if (!selectedNodeIp) return;
  if (blockedHosts.has(selectedNodeIp)) post("/api/firewall/unblock", { ip: selectedNodeIp });
  else post("/api/firewall/block", { ip: selectedNodeIp, reason: "operator blocked selected node" });
};
document.getElementById("sel-actions").onclick = function() {
  if (!selectedNodeIp) return;
  var pos = nodeDOMPos(selectedNodeIp);
  var rect = fxHost.getBoundingClientRect();
  var cx = pos ? rect.left + pos.x : rect.left + rect.width / 2;
  var cy = pos ? rect.top + pos.y : rect.top + 90;
  showTrustMenu({ clientX: cx, clientY: cy, preventDefault: function() {} }, selectedNodeIp);
};
document.getElementById("sel-close").onclick = function() {
  selectedNodeIp = null;
  updateSelectionBar();
  closeTrustMenu();
  network.unselectAll();
};

// Help dialog: the map is dense, so one short reference beats guessing what a
// colour or an icon means. Opened from the toolbar or with H / ?.
var helpOverlay = document.getElementById("help-overlay");
var helpReturnFocus = null;
function openHelp() {
  if (!helpOverlay || !helpOverlay.hidden) return;
  helpReturnFocus = document.activeElement;
  helpOverlay.hidden = false;
  document.body.classList.add("modal-open");
  var body = helpOverlay.querySelector(".modal-body");
  if (body) body.scrollTop = 0;
  var close = document.getElementById("help-close");
  if (close) close.focus();
}
function closeHelp() {
  if (!helpOverlay || helpOverlay.hidden) return;
  helpOverlay.hidden = true;
  document.body.classList.remove("modal-open");
  if (helpReturnFocus && helpReturnFocus.focus) helpReturnFocus.focus();
  helpReturnFocus = null;
}
document.getElementById("btn-help").onclick = openHelp;
document.getElementById("help-close").onclick = closeHelp;
helpOverlay.addEventListener("click", function(ev) { if (ev.target === helpOverlay) closeHelp(); });
helpOverlay.addEventListener("keydown", function(ev) {
  if (ev.key !== "Tab") return;
  var focusable = helpOverlay.querySelectorAll("button, [href], [tabindex]:not([tabindex='-1'])");
  if (!focusable.length) return;
  var first = focusable[0], last = focusable[focusable.length - 1];
  if (ev.shiftKey && document.activeElement === first) { ev.preventDefault(); last.focus(); }
  else if (!ev.shiftKey && document.activeElement === last) { ev.preventDefault(); first.focus(); }
});

function toast(msg, kind) {
  var wrap = document.getElementById("toast-container");
  if (!wrap) return;
  var el = document.createElement("div");
  el.className = "toast" + (kind ? " " + kind : "");
  el.textContent = msg;
  wrap.appendChild(el);
  setTimeout(function() {
    el.classList.add("out");
    setTimeout(function() { el.remove(); }, 220);
  }, 3200);
}

// Right-click anywhere on the map: open the trust menu only when a node is hit.
// Listening on the container (instead of vis' oncontext) gives us a reliable
// clientX/clientY for positioning and lets us stop the native browser menu.
fxHost.addEventListener("contextmenu", function(ev) {
  ev.preventDefault();
  var rect = fxHost.getBoundingClientRect();
  var ip = network.getNodeAt({ x: ev.clientX - rect.left, y: ev.clientY - rect.top });
  if (ip) showTrustMenu(ev, ip); else closeTrustMenu();
});

function closeTrustMenu() { var m = document.getElementById("trust-menu"); if (m) m.remove(); }

function showTrustMenu(event, ip) {
  closeTrustMenu();
  var node = nodes.get(ip); if (!node) return;
  var isTrusted = trustedDevices.has(ip), isSuspicious = suspiciousDevices.has(ip), isAttacker = confirmedAttackers.has(ip);
  var currentRole = node.role || "unknown";
  var markable = currentRole !== "router" && currentRole !== "external";
  var hostname = node.hostname || String(node.label || ip).split("\n")[0];
  var roleLabel = ROLE_STYLE[currentRole] ? ROLE_STYLE[currentRole].label : currentRole;
  var rows = '';
  if (markable) {
    rows += '<button class="trust-btn' + (isTrusted ? ' active' : '') + '" data-action="trust"' + (isAttacker ? ' disabled' : '') + '>' +
      (isTrusted ? '\u2713' : '\u2610') + ' Mark as trusted</button>' +
      '<button class="trust-btn' + (isSuspicious ? ' active' : '') + '" data-action="suspicious"' + (isAttacker ? ' disabled' : '') + '>' +
      (isSuspicious ? '\u2713' : '\u2610') + ' Mark as suspicious</button>' +
      '<button class="trust-btn" data-action="clear"' + (!isTrusted && !isSuspicious ? ' disabled' : '') + '>Clear mark</button>';
  } else {
    rows += '<div class="trust-menu-note">Infrastructure node \u2014 trust marks are not available.</div>';
  }
  if (markable) {
    rows += blockedHosts.has(ip)
      ? '<button class="trust-btn safe" data-action="unblock" title="Remove the firewall block for ' + esc(ip) + '">\u2713 Unblock ' + esc(ip) + '</button>'
      : '<button class="trust-btn danger" data-action="block" title="Drop traffic from ' + esc(ip) + ' at the firewall (reversible)">\u{1F6AB} Block ' + esc(ip) + '</button>';
  }

  var menu = document.createElement("div");
  menu.id = "trust-menu"; menu.className = "trust-menu"; menu.setAttribute("role", "menu");
  menu.innerHTML = '<div class="trust-menu-header">' + esc(hostname) + ' <span class="trust-menu-ip">' + esc(ip) + '</span></div>' +
    '<div class="trust-menu-role">Current role: <strong>' + esc(roleLabel) + '</strong>' +
    (node.kind && KIND_LABELS[node.kind] ? ' \u00B7 ' + esc(KIND_LABELS[node.kind]) : '') + '</div>' + rows;
  document.body.appendChild(menu);

  // keep the menu inside the viewport (offsetWidth/Height ignore the pop animation scale)
  var left = Math.min(event.clientX, window.innerWidth - menu.offsetWidth - 12);
  var top = Math.min(event.clientY, window.innerHeight - menu.offsetHeight - 12);
  menu.style.left = Math.max(10, left) + "px";
  menu.style.top = Math.max(10, top) + "px";

  menu.querySelectorAll(".trust-btn").forEach(function(btn) { btn.setAttribute("role", "menuitem"); btn.onclick = function() { handleTrustAction(ip, btn.dataset.action); }; });
  setTimeout(function() { document.addEventListener("click", function closeMenu(e) { if (!menu.contains(e.target)) { menu.remove(); document.removeEventListener("click", closeMenu); } }); }, 0);
}

function handleTrustAction(ip, action) {
  switch (action) {
    case "trust": {
      var willTrust = !trustedDevices.has(ip);
      if (willTrust) { trustedDevices.add(ip); suspiciousDevices.delete(ip); markAsTrusted(ip); }
      else { trustedDevices.delete(ip); revertToOriginalRole(ip); }
      // The server owns the protection: it refuses to block a trusted device
      // and removes an existing firewall rule when the device is trusted.
      post("/api/devices/trust", { ip: ip, trusted: willTrust });
      break;
    }
    case "suspicious":
      if (suspiciousDevices.has(ip)) { suspiciousDevices.delete(ip); revertToOriginalRole(ip); }
      else { suspiciousDevices.add(ip); trustedDevices.delete(ip); markAsSuspicious(ip); }
      post("/api/devices/trust", { ip: ip, trusted: false });
      break;
    case "clear":
      trustedDevices.delete(ip); suspiciousDevices.delete(ip); revertToOriginalRole(ip);
      post("/api/devices/trust", { ip: ip, trusted: false });
      break;
    case "block": post("/api/firewall/block", { ip: ip, reason: "operator blocked from trust menu" }); break;
    case "unblock": post("/api/firewall/unblock", { ip: ip }); break;
  }
  closeTrustMenu();
}

function nodeInfoTitle(node, headline) {
  var ports = node.openPorts && node.openPorts.length ? node.openPorts.join(", ") : "\u2014";
  var infra = node.hostRole === "router" || node.hostRole === "external";
  var kind = node.kindLabel ? "\ntype: " + node.kindLabel : "";
  var vendor = node.macVendor ? "\nvendor: " + node.macVendor : "";
  var mac = node.mac || "n/a";
  if (node.privateMac) mac += " (private/randomized)";
  return headline + kind + vendor + "\nMAC: " + mac + "\nports: " + ports +
    (node.lastSeen ? "\nlast seen " + node.lastSeen : "") +
    (infra ? "\ndouble-click to rename" : "\nclick for actions \u00B7 right-click for trust menu \u00B7 double-click to rename");
}

function applyNodeRole(ip, role, headline) {
  var node = nodes.get(ip); if (!node) return;
  var style = ROLE_STYLE[role] || ROLE_STYLE.workstation;
  var isSuspicious = role === "unknown", isTrusted = role === "trusted", isAttacker = role === "attacker";
  var border = isSuspicious ? "#d29922" : (isAttacker ? "#f85149" : style.color);
  var accent = isSuspicious ? "#d2992288" : (isAttacker ? "#f8514988" : (isTrusted ? "#3fb95066" : "#00000066"));
  nodes.update({
    id: ip, role: role, shape: style.shape, image: iconURI(style.icon),
    color: { background: style.color, border: border, highlight: { background: style.color, border: "#ffffff" }, hover: { background: style.color, border: "#ffffff" } },
    borderWidth: isSuspicious || isAttacker ? 3 : 2,
    shadow: { enabled: true, color: accent, size: isSuspicious || isAttacker ? 14 : 10, x: 0, y: 3 },
    title: nodeInfoTitle(node, headline)
  });
}

function markAsTrusted(ip) { applyNodeRole(ip, "trusted", "TRUSTED (marked by user)"); }
function markAsSuspicious(ip) { applyNodeRole(ip, "unknown", "SUSPICIOUS (marked by user)"); }
function revertToOriginalRole(ip) {
  var node = nodes.get(ip); if (!node) return;
  if (confirmedAttackers.has(ip)) { upgradeToAttacker(ip); return; }
  var role = node.hostRole || "workstation";
  if (role === "attacker") role = "unknown";
  var label = ROLE_STYLE[role] ? ROLE_STYLE[role].label : "Workstation";
  applyNodeRole(ip, role, label + (role === "unknown" ? " (unverified traffic)" : ""));
}

network.on("doubleClick", function(p) { var ip = p.nodes[0]; if (!ip) return; var label = nodes.get(ip)?.label || ""; var current = label.split("\n")[0]; var name = window.prompt("Name this device (" + ip + ")", current); if (name && name.trim()) post("/api/devices/rename", { ip: ip, name: name.trim() }); });

window.addEventListener("keydown", function(ev) {
  if (ev.target && (ev.target.tagName === "INPUT" || ev.target.tagName === "TEXTAREA" || ev.target.isContentEditable)) return;
  if (ev.ctrlKey || ev.metaKey || ev.altKey) return;
  if (helpOverlay && !helpOverlay.hidden) {
    if (ev.key === "Escape") { ev.preventDefault(); closeHelp(); }
    return;
  }
  var key = ev.key.toLowerCase();
  if (ev.key === "?" || key === "h") { ev.preventDefault(); openHelp(); }
  else if (key === "b" && selectedNodeIp) {
    if (!isBlockableNode(selectedNodeIp)) toast("Infrastructure nodes cannot be blocked", "error");
    else if (blockedHosts.has(selectedNodeIp)) toast(selectedNodeIp + " is already blocked", "error");
    else post("/api/firewall/block", { ip: selectedNodeIp, reason: "operator blocked selected node" });
  }
  else if (ev.key === "Escape") { selectedNodeIp = null; updateSelectionBar(); network.unselectAll(); closeTrustMenu(); hideAttackBanner(); }
  else if (key === "r") fitMapView(true);
  else if (key === "/") { ev.preventDefault(); if (pickerInput) { pickerInput.focus(); pickerInput.select(); pickerRender(); } }
  else if (key === "m") toggleMapMinimize();
  else if (key === "l") toggleLegend();
  else if (key === "d") toggleFx();
});

function renderTopology(data) {
  var now = Date.now(); fxSync(data); updateFlashes(data, now);
  syncTrusted(data);
  if (attackBannerEl && attackBannerEl.dataset.src && blockedHosts.has(attackBannerEl.dataset.src)) hideAttackBanner();
  var pos = computeTreeLayout(data);
  // Role changes (e.g. a workstation becoming the gateway) change the sorted
  // leaf order, so include the role in the layout key as well as the IPs.
  var key = data.nodes.map(function(h) { return h.ip + ":" + h.role; }).sort().join(",") +
    "|" + Object.keys(pos).sort().join(",");
  var layoutChanged = key !== layoutKey;
  var seen = new Set();
  for (var i = 0; i < data.nodes.length; i++) {
    var h = data.nodes[i];
    var displayRole = h.role;
    if (confirmedAttackers.has(h.ip)) displayRole = "attacker";
    else if (trustedDevices.has(h.ip)) displayRole = "trusted";
    else if (suspiciousDevices.has(h.ip)) displayRole = "unknown";
    else if (h.role === "attacker") displayRole = "unknown";
    var style = ROLE_STYLE[displayRole] || ROLE_STYLE.workstation;
    var isBlocked = h.blocked, flashing = !isBlocked && (flashUntil[h.ip] || 0) > now;
    var isAttacker = displayRole === "attacker", isUnknown = displayRole === "unknown", isTrusted = displayRole === "trusted";
    var nodeColor = { background: style.color, border: isBlocked || flashing ? "#f85149" : (isUnknown ? "#d29922" : (isTrusted ? style.color : style.color)), highlight: { background: style.color, border: "#ffffff" }, hover: { background: style.color, border: "#ffffff" } };
    var base = { color: nodeColor, opacity: isBlocked ? 0.5 : 1, borderWidth: isBlocked ? 3 : flashing ? 4 : (h.role === "router" || isAttacker || isUnknown ? 3 : 2), font: { color: isBlocked ? "#8b949e" : "#d7dee8", size: 14, face: "Segoe UI", strokeWidth: 3, strokeColor: "#0b0f14", vadjust: 4 }, shadow: { enabled: true, color: isBlocked ? "#f8514966" : flashing ? "#f8514988" : (h.role === "router" ? "#8b5cf688" : (isAttacker ? "#f8514944" : (isUnknown ? "#d2992244" : (isTrusted ? "#3fb95044" : "#00000066")))), size: isBlocked ? 20 : flashing ? 16 : (h.role === "router" ? 18 : (isAttacker ? 14 : (isUnknown ? 12 : 10))), x: 0, y: 3 }, shapeProperties: { useBorderWithImage: true, borderDashes: h.role === "external" ? [4, 4] : false } };
    var headline = isBlocked ? "\u{1F6AB} BLOCKED" : (isAttacker ? "ATTACKER (confirmed)" : isTrusted ? "TRUSTED (marked by user)" : isUnknown ? "SUSPICIOUS / UNKNOWN" : style.label);
    var kindLabel = h.kind ? (KIND_LABELS[h.kind] || "") : "";
    var title = nodeInfoTitle({ mac: h.mac, openPorts: h.open_ports || [], hostRole: h.role, kindLabel: kindLabel, lastSeen: fmtSeen(h.last_seen), macVendor: h.mac_vendor, privateMac: h.private_mac }, headline);
    var nodeSize = h.role === "router" ? 27 : h.role === "external" ? 23 : (isAttacker ? 22 : 20);
    var img = glyphIconURI(nodeGlyph(h, displayRole, isAttacker));
    if (!nodes.get(h.ip)) {
      var nodeData = { id: h.ip, label: nodeLabel(h.hostname, h.ip), title: title, role: displayRole, hostRole: h.role, hostname: h.hostname, mac: h.mac, kind: h.kind || "", openPorts: h.open_ports || [], lastSeen: h.last_seen, macVendor: h.mac_vendor || "", privateMac: !!h.private_mac, shape: "circularImage", size: nodeSize, image: img, x: pos[h.ip].x, y: pos[h.ip].y };
      for (var k in base) nodeData[k] = base[k];
      nodes.add(nodeData);
    } else {
      var label = nodeLabel(h.hostname, h.ip);
      var existing = nodes.get(h.ip);
      var updateObj = { id: h.ip, role: displayRole, hostRole: h.role, hostname: h.hostname, mac: h.mac, kind: h.kind || "", openPorts: h.open_ports || [], lastSeen: h.last_seen, macVendor: h.mac_vendor || "", privateMac: !!h.private_mac, title: title, size: nodeSize };
      if (existing.label !== label) updateObj.label = label;
      if (existing.image !== img) updateObj.image = img;
      for (var k2 in base) updateObj[k2] = base[k2];
      nodes.update(updateObj);
    }
    seen.add(h.ip);
  } for (var ni = 0; ni < nodes.get().length; ni++) if (!seen.has(nodes.get()[ni].id)) nodes.remove(nodes.get()[ni].id);
  if (layoutChanged) { layoutKey = key; for (var id in pos) if (nodes.get(id)) network.moveNode(id, pos[id].x, pos[id].y); fitMapView(true); if (selectedNodeIp) setTimeout(ensureSelectionVisible, 560); }
  var seenEdges = new Set(); for (var ei = 0; ei < data.edges.length; ei++) { var e = data.edges[ei]; var isLink = e.kind === "link"; var id = (isLink ? "L|" : "T|") + e.from + "|" + e.to; if (!edges.get(id)) { edges.add({ id: id, from: e.from, to: e.to, dashes: !isLink, width: isLink ? 3 : 1.6, arrows: isLink ? "" : { to: { enabled: true, scaleFactor: 0.5, type: "arrow" } }, color: { color: isLink ? "#484f58" : "#6e7681", highlight: "#58a6ff", hover: "#58a6ff" }, smooth: isLink ? false : { enabled: true, type: "continuous", roundness: 0.3 }, selectionWidth: 3 }); } seenEdges.add(id); } edges.get().forEach(function(e) { if (!seenEdges.has(e.id)) edges.remove(e.id); }); }


function fmtAlert(a) {
  var div = document.createElement("div");
  var sev = (a.severity || "info").toLowerCase();
  var icon = SEV_ICONS[sev] || "\u2139\uFE0F";
  var engineName = (a.engine === "rules" || a.engine === "ml+rules") ? a.engine : "ml";
  var engineClass = engineName === "rules" ? "rules" : "ml";
  var blocked = a.src && blockedHosts.has(a.src);
  var repeats = Number(a.count) > 1
    ? '<span class="repeat-badge" title="The same detection fired ' + esc(a.count) +
      ' times \u2014 collapsed into one card">\u00d7' + esc(a.count) + "</span>"
    : "";
  var action = "";
  if (sev !== "info" && a.src) {
    if (trustedDevices.has(a.src)) action = '<span class="blocked-tag">\u2713 Trusted (protected)</span>';
    else if (!canBlockIp(a.src)) action = '<span class="blocked-tag">\u26D4 Infrastructure IP</span>';
    else if (blocked) action = '<span class="blocked-tag">\u26D4 Blocked</span>';
    else action = '<button class="act" data-ip="' + esc(a.src) + '" title="Drop traffic from ' + esc(a.src) + ' at the firewall (reversible)">Block source ' + esc(a.src) + '</button>';
  }
  div.className = "alert " + sev;
  div.innerHTML = '<div class="top"><b>' + icon + " " + esc(attackLabel(a.attack)) + '</b><span class="sev-badge">' + sev.toUpperCase() + '</span>' + repeats + '</div>' +
    '<div class="meta">' + esc(a.time) + " \u00B7 " + esc(a.src) + " \u2192 " + esc(a.dst) +
    ' \u00B7 engine: <span class="engine-tag ' + engineClass + '">' + engineName + '</span> \u00B7 conf: ' + esc(a.confidence) + '</div>' +
    action;
  return div;
}
function fmtRule(r) {
  var div = document.createElement("div");
  div.className = "rule";
  div.innerHTML = '<div class="top"><span class="ip">' + esc(r.ip) + '</span><span class="action block">\u26D4 BLOCK</span></div>' +
    '<div class="meta">' + esc(r.time) + " \u00B7 " + esc(r.reason) + '</div>' +
    '<button class="act unblock" data-unblock="' + esc(r.ip) + '" title="Remove the firewall block for ' + esc(r.ip) + '">Unblock</button>';
  return div;
}
function fmtLogRow(row) { var div = document.createElement("div"); div.className = "log-line " + (row.cls || ""); div.title = row.time + "  " + row.msg; var t = document.createElement("span"); t.className = "t"; t.textContent = row.time; div.appendChild(t); div.appendChild(document.createTextNode(row.msg)); return div; }
function renderLog(data) {
  var rows = [];
  for (var i = 0; i < data.alerts.length; i++) {
    var a = data.alerts[i];
    if (a.attack === "auto_block") rows.push({ time: a.time, cls: "ok", msg: "AUTO-BLOCK fired " + a.src });
    else {
      var conf = typeof a.confidence === "number" ? a.confidence.toFixed(2) : "?";
      var sev = a.severity || "info";
      var times = Number(a.count) > 1 ? " \u00d7" + a.count : "";
      rows.push({ time: a.time, cls: sev === "critical" || sev === "high" ? sev : "warn",
                  msg: sev.toUpperCase().padEnd(8) + ' ' + attackLabel(a.attack) + ' \u00B7 ' + a.src + ' \u2192 ' + a.dst + times + ' \u00B7 engine ' + (a.engine || "rules") + ' conf ' + conf });
    }
  }
  for (var j = 0; j < data.rules.length; j++) {
    var r = data.rules[j];
    rows.push({ time: r.time, cls: r.action === "BLOCK" ? "fw" : "ok", msg: 'FW ' + r.action.padEnd(5) + ' ' + r.ip + ' \u2014 ' + r.reason });
  }
  rows.sort(function(x, y) { return String(y.time || "").localeCompare(String(x.time || "")); });
  rows.length = Math.min(rows.length, 80);
  var log = document.getElementById("log");
  renderKeyed(log, rows, function(row) { return rowKey([row.time, row.cls, row.msg]); },
              fmtLogRow, "waiting for events\u2026");
  setCount("log-count", rows.length);
}
function emptyState(msg) { var div = document.createElement("div"); div.className = "empty"; div.textContent = msg; return div; }
function feedNote(msg) { var div = document.createElement("div"); div.className = "feed-note"; div.textContent = msg; return div; }
function setCount(id, n) { var el = document.getElementById(id); if (el) el.textContent = n; }

// Snapshot-safe list rendering: the WebSocket sends a full state every 2 s.
// Rebuilding the feeds from scratch made every card replay its entrance
// animation on every tick, which read as the page "vibrating". Reuse nodes by
// content key and only insert genuinely new rows, so the animation means
// "this item is new" again.
function rowKey(parts) { return JSON.stringify(parts); }
function reconcileChildren(container, next) {
  var keep = new Set(next);
  Array.prototype.slice.call(container.children).forEach(function(node) {
    if (!keep.has(node)) node.remove();
  });
  var cursor = container.firstChild;
  for (var i = 0; i < next.length; i++) {
    var node = next[i];
    if (node === cursor) { cursor = cursor.nextSibling; continue; }
    container.insertBefore(node, cursor);
  }
}
function renderKeyed(container, items, keyFn, makeFn, emptyMsg) {
  if (!items.length) {
    var empty = container.querySelector(".empty");
    if (!empty || empty.textContent !== emptyMsg) container.replaceChildren(emptyState(emptyMsg));
    return;
  }
  var pool = new Map();
  Array.prototype.slice.call(container.children).forEach(function(node) {
    var key = node.dataset && node.dataset.key;
    if (!key) return;
    if (!pool.has(key)) pool.set(key, []);
    pool.get(key).push(node);
  });
  var seen = new Map();
  var next = items.map(function(item) {
    var base = keyFn(item);
    var n = seen.get(base) || 0;
    seen.set(base, n + 1);
    var key = base + "#" + n;
    var reuse = pool.get(key);
    if (reuse && reuse.length) return reuse.shift();
    var node = makeFn(item);
    if (node && node.dataset) node.dataset.key = key;
    return node;
  });
  reconcileChildren(container, next);
}
function renderFeeds(data) {
  var alertsEl = document.getElementById("alerts");
  var shown = data.alerts.slice(0, 30);
  renderKeyed(alertsEl, shown, function(a) {
    return rowKey([a.time, a.attack, a.src, a.dst, a.severity, a.engine, a.confidence, a.count || 1,
                   canBlockIp(a.src) ? "blockable" : "infra",
                   a.src && blockedHosts.has(a.src) ? "blocked" : "allowed"]);
  }, fmtAlert, "no threats yet \u2014 watching\u2026");
  if (data.alerts.length > shown.length) alertsEl.appendChild(feedNote("showing latest 30 of " + data.alerts.length));
  var rulesEl = document.getElementById("rules");
  var activeRules = [];
  if (Array.isArray(data.active_rules)) {
    activeRules = data.active_rules;
  } else {
    var seenBlocked = new Set();
    data.rules.forEach(function(r) {
      if (r.action === "BLOCK" && blockedHosts.has(r.ip) && !seenBlocked.has(r.ip)) {
        seenBlocked.add(r.ip);
        activeRules.push(r);
      }
    });
  }
  renderKeyed(rulesEl, activeRules, function(r) {
    return rowKey([r.ip, r.time, r.action, r.reason]);
  }, fmtRule, "no active blocks \u2014 traffic is allowed");
  setCount("alerts-count", data.alerts.length);
  setCount("rules-count", activeRules.length);
}
document.getElementById("alerts").addEventListener("click", onAction); document.getElementById("rules").addEventListener("click", onAction);
function onAction(ev) { var block = ev.target.closest("[data-ip]"); var unblock = ev.target.closest("[data-unblock]"); if (block) post("/api/firewall/block", { ip: block.dataset.ip, reason: "operator blocked from UI" }); if (unblock) post("/api/firewall/unblock", { ip: unblock.dataset.unblock }); }
async function post(url, body) {
  try {
    var res = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    if (!res.ok) throw new Error("HTTP " + res.status);
    var data = await res.json().catch(function() { return {}; });
    if (data && data.ok === false) { toast(data.error || "That action is not allowed right now", "error"); return; }
    if (url.indexOf("/firewall/block") >= 0) {
      if (data.changed === false) toast(body.ip + " is already blocked", "error");
      else toast("Blocked " + body.ip + " \u00B7 traffic from it is dropped");
    } else if (url.indexOf("/firewall/unblock") >= 0) {
      if (data.changed === false) toast("No active block for " + body.ip, "error");
      else toast("Unblocked " + body.ip + " \u00B7 traffic is allowed again");
    } else if (url.indexOf("/devices/rename") >= 0) {
      toast("Renamed to " + body.name);
    } else if (url.indexOf("/devices/trust") >= 0) {
      toast(body.trusted ? (body.ip + " is trusted \u00B7 it can no longer be blocked")
                         : (body.ip + " is no longer trusted"));
    }
    refresh();
  } catch (e) {
    console.error("API call failed:", e);
    toast("Action failed \u2014 check the server log", "error");
  }
}
var statPrev = {};
function tweenStat(id, target, fmt) { fmt = fmt || function(v) { return Math.round(v).toString(); }; var el = document.getElementById(id); if (!el) return; var from = statPrev[id] !== undefined ? statPrev[id] : target; statPrev[id] = target; if (from === target) { el.textContent = fmt(target); return; } el.classList.add("updating"); var t0 = performance.now(), dur = 400; var step = function(now) { var k = Math.min(1, (now - t0) / dur); var eased = 1 - Math.pow(1 - k, 3); el.textContent = fmt(from + (target - from) * eased); if (k < 1) statPrev[id + ":raf"] = requestAnimationFrame(step); else el.classList.remove("updating"); }; cancelAnimationFrame(statPrev[id + ":raf"]); statPrev[id + ":raf"] = requestAnimationFrame(step); }
function renderStats(data) {
  var s = data.stats || {};
  var flowsPerSec = Number(s.flows_per_sec);
  if (!isFinite(flowsPerSec)) flowsPerSec = 0;
  tweenStat("s-devices", data.nodes.length);
  tweenStat("s-flows", flowsPerSec, function(v) { return v.toFixed(1); });
  tweenStat("s-alerts", Number(s.attacks_total) || 0);
  var blockedNow = Array.isArray(data.blocked_ips)
    ? data.blocked_ips.length
    : data.nodes.filter(function(h) { return h.blocked; }).length;
  tweenStat("s-blocked", blockedNow);
  var modeEl = document.getElementById("mode-badge");
  var mode = String(data.mode || "demo");
  modeEl.textContent = "\u25CF " + mode;
  var isLive = mode.indexOf("live") === 0;
  modeEl.title = isLive
    ? (mode.indexOf("capture error") >= 0
        ? "Live mode: the packet capture stopped \u2014 check the server log or /health for the reason"
        : "Live mode: reading real traffic from this machine")
    : "Demo mode: simulated traffic on a fictional network \u2014 no real packets";
  var m = data.model_metrics;
  var modelEl = document.getElementById("model-badge");
  var accuracy = m ? Number(m.accuracy) : NaN;
  if (m && isFinite(accuracy)) {
    var dataset = m.dataset || "training";
    modelEl.textContent = "ML model \u00B7 " + Math.round(accuracy * 100) + "% \u00B7 " + dataset;
    modelEl.title = "RandomForest intrusion-detection model \u00B7 " + Math.round(accuracy * 100) + "% accuracy on the " + dataset + " dataset";
  } else if (m) {
    modelEl.textContent = "ML model";
    modelEl.title = "Intrusion-detection model loaded (metrics unavailable)";
  } else {
    modelEl.textContent = "heuristic mode";
    modelEl.title = "No ML model loaded \u2014 rule-based detection only";
  }
}
var ICON_CHEVRON_UP = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 15l-6-6-6 6"/></svg>';
var ICON_CHEVRON_DOWN = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 9l6 6 6-6"/></svg>';
var ICON_LEGEND_CLOSED = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/></svg>';
var ICON_LEGEND_OPEN = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M9 9h6v6H9z"/></svg>';

function setMapMinimized(min) {
  var container = document.getElementById("map-container");
  var map = document.getElementById("map");
  var btn = document.getElementById("btn-toggle-map");
  container.classList.toggle("minimized", min);
  map.classList.toggle("minimized", min);
  btn.innerHTML = min ? ICON_CHEVRON_DOWN : ICON_CHEVRON_UP;
  btn.title = min ? "Expand map (M)" : "Minimize map (M)";
  btn.setAttribute("aria-label", btn.title);
  btn.setAttribute("aria-expanded", String(!min));
  // let the CSS transition finish before vis re-measures the canvas
  setTimeout(function() { sizeFx(); network.redraw(); if (!min) { fitMapView(true); if (selectedNodeIp) setTimeout(ensureSelectionVisible, 460); } }, 320);
}
function toggleMapMinimize() { setMapMinimized(!document.getElementById("map-container").classList.contains("minimized")); }

function setLegendCollapsed(collapsed) {
  var btn = document.getElementById("btn-toggle-legend");
  document.getElementById("legend").classList.toggle("collapsed", collapsed);
  btn.innerHTML = collapsed ? ICON_LEGEND_CLOSED : ICON_LEGEND_OPEN;
  btn.title = collapsed ? "Show legend (L)" : "Hide legend (L)";
  btn.setAttribute("aria-label", btn.title);
  btn.setAttribute("aria-expanded", String(!collapsed));
  // The fit depends on the legend width, so recompute it when it opens/closes.
  setTimeout(function() { fitMapView(false); }, 30);
}
function toggleLegend() { setLegendCollapsed(!document.getElementById("legend").classList.contains("collapsed")); }
function setFxEnabled(on) {
  FX_ENABLED = !!on;
  try { localStorage.setItem("lassi.fx", FX_ENABLED ? "on" : "off"); } catch (e) { /* private mode */ }
  var btn = document.getElementById("btn-toggle-fx");
  if (btn) {
    btn.classList.toggle("off", !FX_ENABLED);
    btn.setAttribute("aria-pressed", FX_ENABLED ? "true" : "false");
    btn.title = FX_ENABLED ? "Hide traffic dots (D)" : "Show traffic dots (D)";
  }
  if (!FX_ENABLED) { ambientDots.length = 0; attackPaths.length = 0; }
}
function toggleFx() { setFxEnabled(!FX_ENABLED); }
function fitMap() { fitMapView(true); if (selectedNodeIp) setTimeout(ensureSelectionVisible, 560); }
var pollTimer = null; function startPolling() { if (pollTimer) return; pollTimer = setInterval(refresh, 2000); } function stopPolling() { if (pollTimer) { clearInterval(pollTimer); pollTimer = null; } }
async function refresh() { try { var res = await fetch("/api/state"); if (!res.ok) throw new Error("HTTP " + res.status); apply(await res.json()); } catch (e) { console.warn("refresh failed:", e); } }
function setConnStatus(state) {
  var el = document.getElementById("map-status");
  if (!el) return;
  el.className = "map-status " + state;
  el.textContent = state === "live" ? "live" : state === "polling" ? "polling" : "connecting\u2026";
  el.title = state === "live" ? "Live \u2014 WebSocket stream connected" : state === "polling" ? "WebSocket unavailable \u2014 refreshing over /api/state" : "Connecting to the live stream\u2026";
}
function apply(data) { renderTopology(data); renderFeeds(data); renderLog(data); renderStats(data); updateSelectionBar(); }
// The legend lists the icon set once, built from the same glyph map the map
// uses (so the SVG is never duplicated in the HTML).
function buildLegendIcons() {
  var box = document.getElementById("legend-icons");
  if (!box) return;
  box.replaceChildren();
  LEGEND_KINDS.forEach(function(kind) {
    var row = document.createElement("span");
    row.className = "lg";
    var img = document.createElement("img");
    img.src = glyphIconURI(kind);
    img.alt = "";
    img.width = 18;
    img.height = 18;
    var label = document.createElement("span");
    label.textContent = KIND_LABELS[kind] || kind;
    row.appendChild(img);
    row.appendChild(label);
    box.appendChild(row);
  });
}

// ---- device picker (toolbar): find any device by name, IP, type or role ----
var pickerInput = document.getElementById("picker-input");
var pickerList = document.getElementById("picker-list");
var pickerRows = [];
var pickerActive = -1;

function pickerKindLabel(node) {
  if (node.kind && KIND_LABELS[node.kind]) return KIND_LABELS[node.kind];
  // "workstation" is the role every discovered host gets when nothing else is
  // known: showing it would claim a finding that was never made. Only roles
  // that carry information may label a device the sensor could not identify.
  var role = node.role || node.hostRole;
  if (role === "router" || role === "external" || role === "trusted"
      || role === "attacker" || role === "unknown") {
    var style = ROLE_STYLE[role];
    return style ? style.label : "";
  }
  return "Unknown";
}

function pickerMatches(node, query) {
  if (!query) return true;
  var hay = [
    node.hostname, node.id,
    node.kind && KIND_LABELS[node.kind] ? KIND_LABELS[node.kind] : "",
    node.hostRole || "", node.role || "",
  ].join(" ").toLowerCase();
  return query.split(/\s+/).every(function(part) { return !part || hay.indexOf(part) >= 0; });
}

function pickerRender() {
  if (!pickerList) return;
  var query = (pickerInput.value || "").trim().toLowerCase();
  var rows = nodes.get().filter(function(n) {
    return n.id !== "0.0.0.0" && pickerMatches(n, query);
  }).sort(function(a, b) {
    return String(a.hostname || a.id).localeCompare(String(b.hostname || b.id));
  }).slice(0, 40);
  pickerList.replaceChildren();
  pickerRows = [];
  pickerActive = -1;
  if (!rows.length) {
    var empty = document.createElement("div");
    empty.className = "picker-empty";
    empty.textContent = nodes.get().length ? "No device matches" : "Waiting for devices\u2026";
    pickerList.appendChild(empty);
  } else {
    rows.forEach(function(node, index) {
      var row = document.createElement("div");
      row.className = "picker-row";
      row.setAttribute("role", "option");
      row.dataset.ip = node.id;
      row.dataset.index = String(index);
      row.title = node.id
        + (node.macVendor ? " \u00b7 vendor " + node.macVendor : "")
        + (node.privateMac ? " \u00b7 private/randomized MAC" : "")
        + (node.openPorts && node.openPorts.length ? " \u00b7 ports " + node.openPorts.join(", ") : "");
      var img = document.createElement("img");
      img.src = node.image || glyphIconURI("unknown");
      img.alt = "";
      var name = document.createElement("span");
      name.className = "pr-name";
      var unnamed = !node.hostname || node.hostname === node.id;
      name.textContent = unnamed ? node.id : node.hostname;
      var ip = document.createElement("span");
      ip.className = "pr-ip";
      ip.textContent = node.id;
      var kind = document.createElement("span");
      kind.className = "pr-kind";
      kind.textContent = pickerKindLabel(node) || "";
      row.appendChild(img);
      row.appendChild(name);
      if (!unnamed) row.appendChild(ip);
      if (kind.textContent) row.appendChild(kind);
      row.addEventListener("mousedown", function(ev) { ev.preventDefault(); pickerChoose(node.id); });
      pickerList.appendChild(row);
      pickerRows.push(row);
    });
  }
  pickerList.hidden = false;
  pickerInput.setAttribute("aria-expanded", "true");
}

function pickerClose() {
  if (!pickerList || pickerList.hidden) return;
  pickerList.hidden = true;
  pickerInput.setAttribute("aria-expanded", "false");
  pickerInput.removeAttribute("aria-activedescendant");
  pickerActive = -1;
  pickerRows.forEach(function(row) { row.classList.remove("active"); });
}

function pickerChoose(ip) {
  if (!ip) return;
  if (!nodes.get(ip)) {
    // The list is a snapshot: the device may have left the map while it was
    // open (phone asleep, lease expired). Re-render instead of asking vis for
    // a node that no longer exists, which threw and left the picker stuck.
    toast("That device is no longer on the map", "error");
    if (document.activeElement === pickerInput) pickerRender(); else pickerClose();
    return;
  }
  selectedNodeIp = ip;
  network.selectNodes([ip]);
  network.focus(ip, { scale: Math.max(network.getScale() || 1, 1.15),
                      animation: { duration: 400, easingFunction: "easeOutQuad" } });
  updateSelectionBar();
  pickerClose();
  pickerInput.value = "";
  pickerInput.blur();
}

function pickerMove(delta) {
  if (!pickerRows.length) return;
  pickerActive = (pickerActive + delta + pickerRows.length) % pickerRows.length;
  pickerRows.forEach(function(row, i) { row.classList.toggle("active", i === pickerActive); });
  var active = pickerRows[pickerActive];
  if (!active) return;
  active.scrollIntoView({ block: "nearest" });
  pickerInput.setAttribute("aria-activedescendant", active.dataset.ip || "");
}

if (pickerInput && pickerList) {
  pickerInput.addEventListener("focus", pickerRender);
  pickerInput.addEventListener("input", pickerRender);
  pickerInput.addEventListener("keydown", function(ev) {
    if (ev.key === "ArrowDown") { ev.preventDefault(); pickerMove(1); }
    else if (ev.key === "ArrowUp") { ev.preventDefault(); pickerMove(-1); }
    else if (ev.key === "Enter") {
      ev.preventDefault();
      var row = pickerRows[pickerActive] || pickerRows[0];
      if (row) pickerChoose(row.dataset.ip);
    } else if (ev.key === "Escape") { ev.preventDefault(); pickerClose(); pickerInput.blur(); }
  });
  document.addEventListener("mousedown", function(ev) {
    var box = document.getElementById("device-picker");
    if (box && !pickerList.hidden && !box.contains(ev.target)) pickerClose();
  });
}

(function() {
  refresh().catch(function() {});
  buildLegendIcons();
  document.getElementById("btn-toggle-map").onclick = toggleMapMinimize;
  document.getElementById("btn-toggle-legend").onclick = toggleLegend;
  document.getElementById("btn-fit-map").onclick = fitMap;
  document.getElementById("btn-toggle-fx").onclick = toggleFx;
  document.getElementById("btn-legend-close").onclick = function() { setLegendCollapsed(true); };
  setFxEnabled(FX_ENABLED);
  // on narrow screens the legend would cover the map, so start it collapsed
  if (window.matchMedia && window.matchMedia("(max-width: 1120px)").matches) setLegendCollapsed(true);
  if (typeof WebSocket === "undefined") { setConnStatus("polling"); startPolling(); return; }
  var connect = function() {
    var proto = location.protocol === "https:" ? "wss" : "ws";
    var ws = new WebSocket(proto + "://" + location.host + "/ws");
    ws.onopen = function() { stopPolling(); setConnStatus("live"); console.log("[WS] connected"); };
    ws.onmessage = function(ev) { try { apply(JSON.parse(ev.data)); } catch(e) { console.warn("WS parse error", e); } };
    ws.onerror = function(e) { setConnStatus("polling"); startPolling(); console.warn("[WS] error", e); };
    ws.onclose = function() { setConnStatus("polling"); console.log("[WS] closed, fallback to polling"); startPolling(); setTimeout(connect, 4000); };
  };
  setConnStatus("connecting");
  connect();
})();
