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

// Ring colour per device type. The role is green "workstation" for almost
// every discovered host (it is the default), so painting the ring by role made
// the whole map look the same. The type is what the sensor actually found.
// States still win over the type: red for blocked/attacker, green for trusted,
// amber for suspicious.
const KIND_COLORS = {
  phone: "#3fb950", tablet: "#56d364", watch: "#56d364",
  laptop: "#79c0ff", desktop: "#4493f8", server: "#58a6ff", sbc: "#f0883e",
  tv: "#bc8cff", console: "#a371f7", speaker: "#f778ba",
  camera: "#39c5cf", nas: "#f0883e", iot: "#d29922",
  printer: "#8b949e", unknown: "#6e7681",
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
  sbc: "SBC", iot: "Smart device", unknown: "Unknown",
};
const LEGEND_KINDS = Object.keys(KIND_LABELS);
// Short labels for the two-column legend grid; the tooltip keeps the long one.
const LEGEND_LABELS = { iot: "IoT" };

// Order of the leaves on the map: same family together, unknown last. The
// grid used to be plain IP order, so cameras sat between two phones and the
// colours could not form a block the eye can scan.
const KIND_ORDER = [
  "camera", "tv", "console", "speaker", "iot", "phone", "tablet", "watch",
  "laptop", "desktop", "sbc", "server", "nas", "printer",
];
function kindRank(kind) {
  var i = KIND_ORDER.indexOf(kind);
  return i < 0 ? KIND_ORDER.length : i;
}

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

// Map label: name on the first line (when there is one), address on the next
// and the inferred type last, so the map answers "what is this?" without a
// hover. The type is "Unknown" when nothing was found — never the default role.
function nodeLabel(hostname, ip, typeLabel) {
  var name = String(hostname || "").replace(/\s+/g, " ").trim();
  var lines = [];
  if (name && name !== ip) lines.push(name);
  lines.push(String(ip));
  if (typeLabel) lines.push(typeLabel);
  return lines.join("\n");
}

function nodeTypeLabel(host) {
  if (host.role === "external") return "";          // "Internet" would repeat
  if (host.role === "router") return "Router";
  return host.kind ? (KIND_LABELS[host.kind] || "") : "Unknown";
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
  return !!node && !protectedIps.has(ip)
    && node.hostRole !== "router" && node.hostRole !== "external";
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
  if (protectedIps.has(ip)) return false;                   // infra / this host
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
var protectedIps = new Set();   // infra/sensor: never blockable, never an attacker
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
var layoutInitialized = false;
var positionedNodes = new Set();
var freezeLayout = true;
try { freezeLayout = localStorage.getItem("lassi.freezeLayout") !== "off"; } catch (e) { /* storage blocked */ }
var kindFilter = null;   // "camera", "unknown", ... or null (show everything)
var firewallProvider = "mock", firewallReady = false, firewallNote = "";
var serverFeatures = new Set();   // capabilities advertised by /api/state
var authBlocked = false;          // the sign-in modal is waiting
var authRole = "operator";        // "viewer" hides the write actions
var lastData = null;     // last snapshot, so a legend click re-renders immediately

function computeTreeLayout(data) {
  var router = data.nodes.find(function(h) { return h.role === "router"; });
  var ext = data.nodes.find(function(h) { return h.role === "external"; });
  var leaves = data.nodes.filter(function(h) { return h.role !== "router" && h.role !== "external"; })
    .sort(function(a, b) {
      return (ROLE_ORDER[a.role] ?? 9) - (ROLE_ORDER[b.role] ?? 9)
        || kindRank(a.kind) - kindRank(b.kind)
        || a.ip.localeCompare(b.ip);
    });
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

// Identity of one feed card, including its timestamp. Dismissal removes that
// exact card; the server remembers the key so a restart does not bring it back.
function dismissKey(a) {
  return [a.time, a.attack, a.src, a.dst, a.severity, a.engine]
    .map(function(v) { return v == null ? "" : String(v); }).join("|");
}

// On the first snapshot, keep known attacker sources as attackers instead of
// demoting them to "unknown" until the next alert arrives.
function seedConfirmedAttackers(data) {
  // Infrastructure and the sensor itself can never be blocked, so an alert
  // from one of them is a false positive far more often than a real attack
  // (our own discovery probes did exactly this). The alert still appears in
  // the feed and in the log; only the red "attacker" ring is suppressed.
  var infra = new Set(data.protected || []);
  (data.nodes || []).forEach(function(n) {
    if (n.role === "router" || n.role === "external") infra.add(n.ip);
  });
  data.alerts.forEach(function(a) {
    if (a.src && (a.severity === "critical" || a.severity === "high")
        && !trustedDevices.has(a.src) && !infra.has(a.src)) {
      confirmedAttackers.add(a.src);
    }
  });
}

function syncProtected(data) {
  if (!data || !Array.isArray(data.protected)) return;
  protectedIps = new Set(data.protected);
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

function drawGlowDot(x, y, r, col, a, glow) { if (r <= 0 || a <= 0) return; if (x < -r || y < -r || x > fx.width + r || y > fx.height + r) return; fctx.globalAlpha = a; fctx.beginPath(); fctx.arc(x, y, r, 0, Math.PI * 2); fctx.fillStyle = col; if (glow > 0) { fctx.shadowColor = col; fctx.shadowBlur = glow; } fctx.fill(); fctx.shadowBlur = 0; fctx.globalAlpha = 1; }

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
  if (!kindFilter) drawGroupBoxes();
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
  btn.title = blocked
    ? (firewallReady ? "Remove the firewall block for " : "Remove the recorded block for ") + selectedNodeIp
    : (firewallReady ? "Drop traffic from " + selectedNodeIp + " at the firewall (reversible)"
                     : "Record a block for " + selectedNodeIp + " (simulated: no traffic is dropped)");
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

// Flow history dialog: SQLite-backed metadata. Selecting a row shows the two
// endpoints and the detector verdict; it never exposes packet payloads.
var flowsOverlay = document.getElementById("flows-overlay");
var flowsList = document.getElementById("flows-list");
var flowDetail = document.getElementById("flow-detail");
var flowsMeta = document.getElementById("flows-meta");
var flowsFilter = document.getElementById("flows-filter");
var flowsScope = document.getElementById("flows-scope");
var flowsToolbar = document.getElementById("flows-toolbar");
var flowsLayout = document.getElementById("flows-layout");
var flowsTop = document.getElementById("flows-top");
var flowsTopList = document.getElementById("flows-top-list");
var flowsTopMeta = document.getElementById("flows-top-meta");
var flowsInventory = document.getElementById("flows-inventory");
var inventoryFilter = document.getElementById("inventory-filter");
var inventoryList = document.getElementById("inventory-list");
var inventoryMeta = document.getElementById("inventory-meta");
var flowsReport = document.getElementById("flows-report");
var reportBody = document.getElementById("report-body");
var reportHours = 24;
var reportData = null;
var flowsTimeline = document.getElementById("flows-timeline");
var timelineCanvas = document.getElementById("timeline-canvas");
var timelineMeta = document.getElementById("timeline-meta");
var flowsStats = document.getElementById("flows-stats");
var flowsExport = document.getElementById("flows-export");
var flowsCompact = document.getElementById("flows-compact");
var flowsClear = document.getElementById("flows-clear");
var flowsTabs = flowsOverlay ? flowsOverlay.querySelectorAll("[data-flows-view]") : [];
var flowsReturnFocus = null;
var flowsTimer = null;
var flowsFilterTimer = null;
var flowsCache = [];
var flowsSelectedId = null;
var flowsKind = "";
var flowsContext = null;
var flowsView = "flows";
var flowsTopWindow = 900;
var timelineMinutes = 60;
var timelineData = null;

function flowEl(tag, cls, text) {
  var el = document.createElement(tag);
  if (cls) el.className = cls;
  if (text !== undefined && text !== null) el.textContent = String(text);
  return el;
}
function flowBytes(value) {
  var n = Number(value) || 0;
  if (n < 1024) return Math.round(n) + " B";
  if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
  if (n < 1073741824) return (n / 1048576).toFixed(1) + " MB";
  return (n / 1073741824).toFixed(2) + " GB";
}
function flowDuration(value) {
  var n = Number(value) || 0;
  return n < 1 ? n.toFixed(2) + " s" : n.toFixed(1) + " s";
}
function flowClock(ts, full) {
  if (ts === undefined || ts === null || Number(ts) <= 0) return "—";
  var d = new Date(Number(ts) * 1000);
  if (!isFinite(d.getTime())) return "—";
  return full ? d.toLocaleString() : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}
function flowAttackName(attack) {
  var names = {
    benign: "benign", port_scan: "Port scan", brute_force: "Brute force",
    ddos: "DDoS", data_exfiltration: "Data exfiltration", auto_block: "Auto-block"
  };
  return names[attack] || attack || "unknown";
}
function flowVerdictClass(flow) {
  if (!flow.attack || flow.attack === "benign") return "benign";
  return flow.severity === "medium" ? "medium" : "attack";
}
function flowLabel(flow, side) {
  var name = flow[side + "_name"];
  var ip = flow[side];
  return name && name !== ip ? name : (ip || "—");
}
function flowPorts(value) {
  return value ? String(value) : "not recorded";
}
function flowRow(flow) {
  var row = flowEl("button", "flow-row");
  row.type = "button";
  row.dataset.id = String(flow.id);
  row.setAttribute("aria-pressed", "false");
  row.title = flow.src + " → " + flow.dst + " · " + flowAttackName(flow.attack);
  var route = flowEl("div", "flow-route");
  route.appendChild(flowEl("span", "flow-end", flowLabel(flow, "src")));
  route.appendChild(flowEl("span", "flow-arrow", "→"));
  route.appendChild(flowEl("span", "flow-end", flowLabel(flow, "dst")));
  row.appendChild(route);
  var sub = flowEl("div", "flow-sub");
  sub.appendChild(flowEl("span", "", flowClock(flow.ts)));
  sub.appendChild(flowEl("span", "", (Number(flow.pkts) || 0) + " pkts"));
  sub.appendChild(flowEl("span", "", flowBytes(flow.bytes)));
  if (flow.protocols) sub.appendChild(flowEl("span", "", flow.protocols));
  var verdict = flowEl("span", "flow-verdict " + flowVerdictClass(flow), flowAttackName(flow.attack));
  sub.appendChild(verdict);
  row.appendChild(sub);
  row.addEventListener("click", function() { selectFlow(Number(flow.id)); });
  return row;
}
function renderFlowList(flows, total, enabled) {
  flowsCache = flows || [];
  if (!flowsList) return;
  var scrollTop = flowsList.scrollTop;
  flowsList.replaceChildren();
  if (enabled === false) {
    flowsList.appendChild(flowEl("p", "flows-empty", "Flow history is disabled (LASSI_FLOW_HISTORY=0)."));
    if (flowsMeta) flowsMeta.textContent = "disabled";
    return;
  }
  if (!flows.length) {
    flowsList.appendChild(flowEl("p", "flows-empty", "No matching flows. New flows appear after the 10-second aggregation window."));
    if (flowsMeta) flowsMeta.textContent = "0 flows";
    return;
  }
  flows.forEach(function(flow) { flowsList.appendChild(flowRow(flow)); });
  flowsList.scrollTop = scrollTop;
  if (flowsMeta) {
    var shown = flows.length;
    flowsMeta.textContent = total + " flow" + (total === 1 ? "" : "s") +
      (shown < total ? " · latest " + shown : "");
  }
}
function flowEndpoint(role, name, ip) {
  var box = flowEl("div", "flow-endpoint");
  box.appendChild(flowEl("span", "flow-role", role));
  box.appendChild(flowEl("b", "", name || ip || "—"));
  if (name && ip && name !== ip) box.appendChild(flowEl("code", "", ip));
  else box.appendChild(flowEl("code", "", "IP only"));
  box.appendChild(flowEl("small", "flow-device-meta", flowDeviceMeta(ip)));
  return box;
}
function flowDeviceMeta(ip) {
  var nodes = (lastData && lastData.nodes) || [];
  for (var i = 0; i < nodes.length; i++) {
    if (nodes[i].ip !== ip) continue;
    var role = nodes[i].role || "";
    var kind = nodes[i].kind || "";
    var bits = [];
    if (role && role !== "workstation") bits.push(role);
    if (kind && kind !== "unknown" && kind !== role) bits.push(kind);
    if (!bits.length) bits.push(role === "workstation" ? "workstation (type unknown)" : (role || "unknown"));
    if (nodes[i].blocked) bits.push("blocked");
    return bits.length ? bits.join(" · ") : "current device";
  }
  return "not on current map";
}
function renderFlowDetail(flow) {
  if (!flowDetail || !flow) return;
  flowDetail.replaceChildren();
  var head = flowEl("h4", "", "Flow #" + flow.id + " · " + flowClock(flow.ts, true));
  flowDetail.appendChild(head);

  var endpoints = flowEl("div", "flow-endpoints");
  endpoints.appendChild(flowEndpoint("Source", flow.src_name, flow.src));
  endpoints.appendChild(flowEl("div", "flow-big-arrow", "→"));
  endpoints.appendChild(flowEndpoint("Destination", flow.dst_name, flow.dst));
  flowDetail.appendChild(endpoints);

  var stats = flowEl("div", "flow-stats");
  [
    ["Packets", Number(flow.pkts) || 0],
    ["Bytes", flowBytes(flow.bytes)],
    ["Duration", flowDuration(flow.duration)],
    ["Protocols", flowPorts(flow.protocols)],
    ["Direction", flow.direction || "not recorded"],
    ["Initiator", flow.initiator || "not recorded"],
    ["Source ports", flowPorts(flow.src_ports)],
    ["Destination ports", flowPorts(flow.dst_ports)],
    ["Top ports", flowPorts(flow.port_histogram)],
    ["TCP flags", flowPorts(flow.tcp_flags)],
    ["Distinct dest. ports", Number(flow.dst_port_count) || 0],
    ["SYN ratio", ((Number(flow.syn_ratio) || 0) * 100).toFixed(1) + "%"],
    ["Packet rate", (Number(flow.pkt_rate) || 0).toFixed(2) + "/s"],
  ].forEach(function(item) {
    var stat = flowEl("div", "flow-stat");
    stat.appendChild(flowEl("span", "", item[0]));
    stat.appendChild(flowEl("b", "", item[1]));
    stats.appendChild(stat);
  });
  flowDetail.appendChild(stats);

  var verdict = flowEl("div", "flow-verdict-box");
  verdict.appendChild(flowEl("span", "flow-verdict " + flowVerdictClass(flow), flowAttackName(flow.attack)));
  var conf = Number(flow.confidence) || 0;
  verdict.appendChild(flowEl("p", "", "Severity: " + (flow.severity || "low") +
    " · Engine: " + (flow.engine || "rules") + " · Confidence: " + Math.round(conf * 100) + "%"));
  if (flow.mode) verdict.appendChild(flowEl("p", "", "Recorded in: " + flow.mode));
  flowDetail.appendChild(verdict);
}
function markSelectedFlow(id) {
  if (!flowsList) return;
  var rows = flowsList.querySelectorAll(".flow-row");
  for (var i = 0; i < rows.length; i++) {
    var on = Number(rows[i].dataset.id) === Number(id);
    rows[i].classList.toggle("selected", on);
    rows[i].setAttribute("aria-pressed", on ? "true" : "false");
  }
}
function selectFlow(id) {
  flowsSelectedId = id;
  markSelectedFlow(id);
  var flow = flowsCache.find(function(item) { return Number(item.id) === Number(id); });
  if (flow) { renderFlowDetail(flow); return; }
  fetch("/api/flows/" + encodeURIComponent(id)).then(function(res) {
    if (res.status === 401) { closeFlows(false); showAuth(); return null; }
    if (!res.ok) throw new Error("HTTP " + res.status);
    return res.json();
  }).then(function(data) {
    if (data && data.flow) renderFlowDetail(data.flow);
  }).catch(function() { toast("Could not load that flow", "error"); });
}
function flowsParams() {
  var params = new URLSearchParams({ limit: "200" });
  var ctx = flowsContext || {};
  if (flowsFilter && flowsFilter.value.trim()) params.set("q", flowsFilter.value.trim());
  if (flowsKind) params.set("kind", flowsKind);
  if (ctx.src) params.set("src", ctx.src);
  if (ctx.dst) params.set("dst", ctx.dst);
  if (ctx.device) params.set("device", ctx.device);
  if (ctx.since) params.set("since", String(ctx.since));
  if (ctx.until) params.set("until", String(ctx.until));
  return params;
}
async function fetchFlows() {
  if (!flowsOverlay || flowsOverlay.hidden || flowsView !== "flows") return;
  try {
    var res = await fetch("/api/flows?" + flowsParams().toString());
    if (res.status === 401) { closeFlows(false); showAuth(); return; }
    if (!res.ok) throw new Error("HTTP " + res.status);
    var data = await res.json();
    renderFlowList(data.flows || [], data.total || 0, data.enabled !== false);
    if (flowsSelectedId !== null) markSelectedFlow(flowsSelectedId);
    if (flowsMeta && data.enabled === false) flowsMeta.textContent = "disabled";
  } catch (e) {
    if (flowsMeta) flowsMeta.textContent = "unavailable";
  }
}
function renderFlowScope() {
  if (!flowsScope) return;
  flowsScope.replaceChildren();
  if (!flowsContext || !flowsContext.label) {
    flowsScope.hidden = true;
    return;
  }
  flowsScope.hidden = false;
  flowsScope.appendChild(flowEl("span", "", "Scope: "));
  flowsScope.appendChild(flowEl("b", "", flowsContext.label));
  var clear = flowEl("button", "", "Clear");
  clear.type = "button";
  clear.addEventListener("click", function() { applyFlowsContext(null); });
  flowsScope.appendChild(clear);
}
function applyFlowsContext(ctx) {
  flowsContext = ctx || null;
  if (flowsFilter) flowsFilter.value = (ctx && ctx.q) || "";
  flowsKind = "";
  var kindButtons = flowsOverlay ? flowsOverlay.querySelectorAll("[data-flow-kind]") : [];
  for (var i = 0; i < kindButtons.length; i++) {
    kindButtons[i].classList.toggle("active", !kindButtons[i].dataset.flowKind);
  }
  renderFlowScope();
  setFlowsView("flows");
  fetchFlows();
}
function showFlowsForDevice(ip) {
  var ctx = { device: ip, label: "device " + ip };
  if (!flowsOverlay || flowsOverlay.hidden) openFlows(ctx);
  else applyFlowsContext(ctx);
}
function setFlowsView(view) {
  flowsView = view || "flows";
  for (var i = 0; i < flowsTabs.length; i++) {
    var active = flowsTabs[i].dataset.flowsView === flowsView;
    flowsTabs[i].classList.toggle("active", active);
    flowsTabs[i].setAttribute("aria-selected", active ? "true" : "false");
  }
  if (flowsToolbar) flowsToolbar.hidden = flowsView !== "flows";
  if (flowsLayout) flowsLayout.hidden = flowsView !== "flows";
  if (flowsTop) flowsTop.hidden = flowsView !== "top";
  if (flowsInventory) flowsInventory.hidden = flowsView !== "inventory";
  if (flowsReport) flowsReport.hidden = flowsView !== "report";
  if (flowsTimeline) flowsTimeline.hidden = flowsView !== "timeline";
  if (flowsScope) flowsScope.hidden = flowsView !== "flows" || !flowsContext;
  if (flowsExport) flowsExport.hidden = flowsView !== "flows";
  if (flowsView === "top") fetchTop();
  else if (flowsView === "timeline") fetchTimeline();
  else if (flowsView === "inventory") fetchInventory();
  else if (flowsView === "report") fetchReport();
  else fetchFlows();
}
async function fetchTop() {
  if (!flowsOverlay || flowsOverlay.hidden || flowsView !== "top") return;
  try {
    var res = await fetch("/api/flows/top?window=" + flowsTopWindow + "&limit=15");
    if (res.status === 401) { closeFlows(false); showAuth(); return; }
    if (!res.ok) throw new Error("HTTP " + res.status);
    var data = await res.json();
    renderTop(data.items || [], data.window_seconds || flowsTopWindow);
  } catch (e) {
    if (flowsTopMeta) flowsTopMeta.textContent = "unavailable";
  }
}
function renderTop(items, windowSeconds) {
  if (!flowsTopList) return;
  flowsTopList.replaceChildren();
  if (flowsTopMeta) {
    var label = windowSeconds >= 86400 ? "24 h" : windowSeconds >= 3600 ? "1 h" : "15 min";
    flowsTopMeta.textContent = (items.length ? items.length + " devices" : "no flows") + " · " + label;
  }
  if (!items.length) {
    flowsTopList.appendChild(flowEl("p", "flows-top-empty", "No flow history in this window."));
    return;
  }
  var maxBytes = Math.max.apply(null, items.map(function(item) { return Number(item.bytes) || 0; })) || 1;
  items.forEach(function(item, index) {
    var row = flowEl("button", "top-row");
    row.type = "button";
    row.dataset.ip = item.ip;
    row.title = "Show flows for " + item.ip;
    row.appendChild(flowEl("span", "top-rank", String(index + 1)));
    var name = flowEl("span", "top-name", item.name || item.ip);
    if (item.name && item.name !== item.ip) {
      var code = flowEl("code", "", item.ip);
      name.appendChild(code);
    }
    var roleText = [item.role, item.kind].filter(function(value, index, arr) {
      return value && value !== "unknown" && arr.indexOf(value) === index;
    }).join(" · ");
    if (roleText) name.appendChild(flowEl("small", "top-role", roleText));
    row.appendChild(name);
    var bar = flowEl("span", "top-bar");
    var fill = flowEl("i");
    fill.style.width = Math.max(2, ((Number(item.bytes) || 0) / maxBytes) * 100) + "%";
    bar.appendChild(fill);
    row.appendChild(bar);
    var stats = flowEl("span", "top-stats",
      "\u2191 " + flowBytes(item.bytes_out) + "  \u2193 " + flowBytes(item.bytes_in));
    stats.appendChild(flowEl("span", "", (Number(item.flows_out) || 0) +
      " out · " + (Number(item.flows_in) || 0) + " in"));
    row.title = (item.name || item.ip) + " · " + flowBytes(item.bytes) +
      " total · " + (Number(item.flows) || 0) + " flows";
    row.appendChild(stats);
    row.addEventListener("click", function() { showFlowsForDevice(item.ip); });
    flowsTopList.appendChild(row);
  });
}
async function fetchInventory() {
  if (!flowsOverlay || flowsOverlay.hidden || flowsView !== "inventory") return;
  var q = inventoryFilter ? inventoryFilter.value.trim() : "";
  try {
    var res = await fetch("/api/devices/inventory?limit=500" +
      (q ? "&q=" + encodeURIComponent(q) : ""));
    if (res.status === 401) { closeFlows(false); showAuth(); return; }
    if (!res.ok) throw new Error("HTTP " + res.status);
    renderInventory((await res.json()).items || []);
  } catch (e) {
    if (inventoryMeta) inventoryMeta.textContent = "unavailable";
  }
}
function renderInventory(items) {
  if (!inventoryList) return;
  inventoryList.replaceChildren();
  if (inventoryMeta) inventoryMeta.textContent = items.length + " device" + (items.length === 1 ? "" : "s");
  if (!items.length) {
    inventoryList.appendChild(flowEl("p", "inventory-empty", "No devices recorded yet."));
    return;
  }
  items.forEach(function(item) {
    var row = flowEl("button", "inventory-row");
    row.type = "button";
    var name = flowEl("span", "inventory-name", item.name || item.ip);
    if (item.name && item.name !== item.ip) name.appendChild(flowEl("code", "", item.ip));
    row.appendChild(name);
    var type = flowEl("span", "inventory-meta-cell");
    type.appendChild(flowEl("b", "", item.kind || item.role || "unknown"));
    type.appendChild(document.createTextNode([item.role, item.mac].filter(Boolean).join(" · ")));
    row.appendChild(type);
    var traffic = flowEl("span", "inventory-meta-cell",
      "\u2191 " + flowBytes(item.bytes_out) + "  \u2193 " + flowBytes(item.bytes_in));
    traffic.appendChild(flowEl("b", "", (Number(item.flows) || 0) + " flows"));
    row.appendChild(traffic);
    var seen = flowEl("span", "inventory-meta-cell", flowClock(item.last_seen));
    seen.appendChild(flowEl("b", "", "last seen"));
    row.appendChild(seen);
    var first = flowEl("span", "inventory-meta-cell", flowClock(item.first_seen));
    first.appendChild(flowEl("b", "", "first seen"));
    row.appendChild(first);
    row.title = "Open investigation for " + item.ip;
    row.addEventListener("click", function() { openInvestigation({ ip: item.ip }); });
    inventoryList.appendChild(row);
  });
}
async function fetchReport() {
  if (!flowsOverlay || flowsOverlay.hidden || flowsView !== "report") return;
  try {
    var res = await fetch("/api/report?hours=" + reportHours);
    if (res.status === 401) { closeFlows(false); showAuth(); return; }
    if (!res.ok) throw new Error("HTTP " + res.status);
    reportData = await res.json();
    renderReport(reportData);
  } catch (e) {
    if (reportBody) reportBody.replaceChildren(flowEl("p", "section-note", "Could not build the report."));
  }
}
function reportCard(label, value) {
  var card = flowEl("div", "report-card");
  card.appendChild(flowEl("span", "", label));
  card.appendChild(flowEl("b", "", value));
  return card;
}
function renderReport(data) {
  if (!reportBody) return;
  reportBody.replaceChildren();
  var summary = flowEl("div", "report-summary");
  summary.appendChild(reportCard("Flows", (data.flows || 0).toLocaleString()));
  summary.appendChild(reportCard("Bytes", flowBytes(data.bytes || 0)));
  summary.appendChild(reportCard("Packets", (data.packets || 0).toLocaleString()));
  summary.appendChild(reportCard("Alerts / blocks", (data.alerts || []).length + " / " + (data.blocks || []).length));
  summary.appendChild(reportCard("Sensitivity", data.sensitivity || "balanced"));
  summary.appendChild(reportCard("Suppression", data.suppress && data.suppress.length ? data.suppress.join(", ") : "none"));
  summary.appendChild(reportCard("Blocked now", String(data.blocked || 0)));
  summary.appendChild(reportCard("Trusted", String(data.trusted || 0)));
  reportBody.appendChild(summary);

  var top = flowEl("div", "report-section");
  top.appendChild(flowEl("h4", "", "Top devices"));
  if (data.top && data.top.length) {
    var table = flowEl("table", "report-table");
    var head = document.createElement("tr");
    ["Device", "Out", "In", "Flows"].forEach(function(label) {
      var th = document.createElement("th"); th.textContent = label; head.appendChild(th);
    });
    table.appendChild(head);
    data.top.forEach(function(item) {
      var tr = document.createElement("tr");
      [item.name || item.ip, flowBytes(item.bytes_out), flowBytes(item.bytes_in),
       String(item.flows || 0)].forEach(function(value) {
        var td = document.createElement("td"); td.textContent = value; tr.appendChild(td);
      });
      table.appendChild(tr);
    });
    top.appendChild(table);
  } else {
    top.appendChild(flowEl("p", "section-note", "No flows in this window."));
  }
  reportBody.appendChild(top);

  var events = flowEl("div", "report-section");
  events.appendChild(flowEl("h4", "", "Alerts and blocks"));
  var allEvents = (data.alerts || []).concat(data.blocks || []).sort(function(a, b) {
    return (Number(a.at) || 0) - (Number(b.at) || 0);
  });
  if (allEvents.length) {
    var et = flowEl("table", "report-table");
    var eh = document.createElement("tr");
    ["Time", "Kind", "Detail"].forEach(function(label) {
      var th = document.createElement("th"); th.textContent = label; eh.appendChild(th);
    });
    et.appendChild(eh);
    allEvents.slice(-50).forEach(function(event) {
      var tr = document.createElement("tr");
      [flowClock(event.at, true), event.kind || "",
       event.kind === "block" ? (event.ip + " · " + (event.reason || "")) :
         (event.attack + " · " + event.src + " → " + event.dst)].forEach(function(value) {
        var td = document.createElement("td"); td.textContent = value; tr.appendChild(td);
      });
      et.appendChild(tr);
    });
    events.appendChild(et);
  } else {
    events.appendChild(flowEl("p", "section-note", "No alert/block events in this window."));
  }
  reportBody.appendChild(events);

  var ports = flowEl("div", "report-section");
  ports.appendChild(flowEl("h4", "", "Top destination ports"));
  if (data.ports && data.ports.length) {
    var chips = flowEl("div", "investigation-chips");
    data.ports.forEach(function(item) {
      chips.appendChild(flowEl("span", "flows-chip", item.port + " · " + item.count));
    });
    ports.appendChild(chips);
  } else {
    ports.appendChild(flowEl("p", "section-note", "No port samples in this window."));
  }
  reportBody.appendChild(ports);
}
function downloadText(filename, text, type) {
  var blob = new Blob([text], { type: type || "text/plain;charset=utf-8" });
  var url = URL.createObjectURL(blob);
  var a = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(function() { URL.revokeObjectURL(url); }, 500);
}
function csvCell(value) {
  var text = String(value === undefined || value === null ? "" : value);
  return '"' + text.replace(/"/g, '""') + '"';
}
function reportAlertsCsv() {
  if (!reportData) return;
  var rows = [["time", "kind", "ip", "src", "dst", "attack", "severity", "reason"]];
  (reportData.alerts || []).forEach(function(event) {
    rows.push([new Date((Number(event.at) || 0) * 1000).toISOString(), "alert",
      "", event.src, event.dst, event.attack, event.severity, ""]);
  });
  (reportData.blocks || []).forEach(function(event) {
    rows.push([new Date((Number(event.at) || 0) * 1000).toISOString(), "block",
      event.ip, "", "", "", "", event.reason]);
  });
  downloadText("lassinet-alerts.csv", rows.map(function(row) {
    return row.map(csvCell).join(",");
  }).join("\n"), "text/csv;charset=utf-8");
}
function reportTimelineCsv() {
  if (!reportData) return;
  var rows = [["time", "kind", "src", "dst", "ip", "attack", "severity", "reason"]];
  (reportData.alerts || []).concat(reportData.blocks || []).sort(function(a, b) {
    return (Number(a.at) || 0) - (Number(b.at) || 0);
  }).forEach(function(event) {
    rows.push([new Date((Number(event.at) || 0) * 1000).toISOString(), event.kind,
      event.src || "", event.dst || "", event.ip || "", event.attack || "",
      event.severity || "", event.reason || ""]);
  });
  downloadText("lassinet-timeline.csv", rows.map(function(row) {
    return row.map(csvCell).join(",");
  }).join("\n"), "text/csv;charset=utf-8");
}
function reportJson() {
  if (!reportData) return;
  downloadText("lassinet-report.json", JSON.stringify(reportData, null, 2),
    "application/json;charset=utf-8");
}
async function fetchTimeline() {
  if (!flowsOverlay || flowsOverlay.hidden || flowsView !== "timeline") return;
  try {
    var res = await fetch("/api/flows/timeline?minutes=" + timelineMinutes);
    if (res.status === 401) { closeFlows(false); showAuth(); return; }
    if (!res.ok) throw new Error("HTTP " + res.status);
    var data = await res.json();
    timelineData = data;
    drawTimeline(data);
  } catch (e) {
    if (timelineMeta) timelineMeta.textContent = "unavailable";
    drawTimeline({ buckets: [], alerts: [], blocks: [] });
  }
}
function drawTimeline(data) {
  if (!timelineCanvas) return;
  var rect = timelineCanvas.getBoundingClientRect();
  if (rect.width < 20 || rect.height < 20) return;
  var dpr = window.devicePixelRatio || 1;
  timelineCanvas.width = Math.floor(rect.width * dpr);
  timelineCanvas.height = Math.floor(rect.height * dpr);
  var ctx = timelineCanvas.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  var w = rect.width, h = rect.height;
  ctx.clearRect(0, 0, w, h);
  var left = 38, right = 12, top = 14, bottom = 25;
  var plotW = Math.max(1, w - left - right), plotH = Math.max(1, h - top - bottom);
  var buckets = (data && data.buckets) || [];
  var alerts = (data && data.alerts) || [];
  var blocks = (data && data.blocks) || [];
  var until = Number(data && data.until) || (Date.now() / 1000);
  var since = Number(data && data.since) || (until - 3600);
  var maxFlows = Math.max(1, Math.max.apply(null, buckets.map(function(b) { return Number(b.flows) || 0; })));
  ctx.strokeStyle = "#30363d"; ctx.fillStyle = "#6e7681";
  ctx.font = "10px monospace"; ctx.lineWidth = 1;
  for (var i = 0; i <= 3; i++) {
    var y = top + (plotH * i / 3);
    ctx.beginPath(); ctx.moveTo(left, y); ctx.lineTo(left + plotW, y); ctx.stroke();
    ctx.fillText(String(Math.round(maxFlows * (3 - i) / 3)), 4, y + 3);
  }
  if (!buckets.length) {
    ctx.fillText("No flow buckets in this window", left + 8, top + plotH / 2);
    if (timelineMeta) timelineMeta.textContent = "no data";
    return;
  }
  var bw = plotW / buckets.length;
  buckets.forEach(function(bucket, index) {
    var value = Number(bucket.flows) || 0;
    var barH = (value / maxFlows) * plotH;
    var x = left + index * bw + Math.max(1, bw * 0.12);
    var bwPix = Math.max(1, bw * 0.76);
    ctx.fillStyle = "#58a6ff88";
    ctx.fillRect(x, top + plotH - barH, bwPix, barH);
  });
  function marker(at, color, label) {
    var ratio = (Number(at) - since) / Math.max(1, until - since);
    if (!isFinite(ratio) || ratio < 0 || ratio > 1) return;
    var x = left + ratio * plotW;
    ctx.strokeStyle = color; ctx.fillStyle = color;
    ctx.beginPath(); ctx.moveTo(x, top); ctx.lineTo(x, top + plotH); ctx.stroke();
    ctx.beginPath(); ctx.arc(x, top + 5, 2.5, 0, Math.PI * 2); ctx.fill();
  }
  alerts.forEach(function(item) { marker(item.at, "#f85149"); });
  blocks.forEach(function(item) { marker(item.at, "#d29922"); });
  ctx.fillStyle = "#6e7681"; ctx.font = "10px monospace";
  ctx.fillText(flowClock(since), left, h - 6);
  ctx.fillText(flowClock(until), left + plotW - 42, h - 6);
  if (timelineMeta) {
    timelineMeta.textContent = buckets.reduce(function(sum, b) { return sum + (Number(b.flows) || 0); }, 0) +
      " flows · " + alerts.length + " alerts · " + blocks.length + " blocks";
  }
}
async function refreshFlowStats() {
  if (!flowsStats) return;
  try {
    var res = await fetch("/api/flows/stats");
    if (res.status === 401) return;
    if (!res.ok) throw new Error("HTTP " + res.status);
    var data = await res.json();
    var retention = data.retention_hours ? data.retention_hours + " h" : "no age limit";
    var cap = data.max_rows ? data.max_rows.toLocaleString() + " rows" : "no row cap";
    flowsStats.textContent = (data.rows || 0).toLocaleString() + " rows · " +
      flowBytes(data.db_bytes || 0) + " · " + retention + " / " + cap +
      (data.compacting ? " · compacting…" : "");
    if (flowsCompact) {
      flowsCompact.disabled = !!data.compacting;
      flowsCompact.hidden = authRole !== "operator";
    }
    if (flowsClear) flowsClear.hidden = authRole !== "operator";
  } catch (e) { /* keep the last value */ }
}
function exportFlows() {
  var params = flowsParams();
  params.delete("limit");
  window.location.href = "/api/flows/export.csv?" + params.toString();
}
function compactFlowHistory() {
  if (authRole !== "operator") { toast("Read-only token: this action needs the operator token", "error"); return; }
  fetch("/api/flows/compact", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken() },
    body: "{}"
  }).then(function(res) {
    if (res.status === 401) { closeFlows(false); showAuth(); return null; }
    if (res.status === 403) { toast("Operator token required", "error"); return null; }
    if (!res.ok) throw new Error("HTTP " + res.status);
    return res.json();
  }).then(function(data) {
    if (!data) return;
    toast(data.started ? "Compacting flow database…" : "Compaction already running", "ok");
    refreshFlowStats();
  }).catch(function() { toast("Could not compact flow history", "error"); });
}
function clearFlowHistory() {
  if (authRole !== "operator") { toast("Read-only token: this action needs the operator token", "error"); return; }
  if (!window.confirm("Delete all stored flow history? This cannot be undone.")) return;
  fetch("/api/flows/clear", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken() },
    body: "{}"
  }).then(function(res) {
    if (res.status === 401) { closeFlows(false); showAuth(); return null; }
    if (res.status === 403) { toast("Operator token required", "error"); return null; }
    if (!res.ok) throw new Error("HTTP " + res.status);
    return res.json();
  }).then(function(data) {
    if (!data) return;
    toast("Flow history cleared (" + (data.deleted || 0) + " rows)", "ok");
    flowsSelectedId = null;
    if (flowDetail) flowDetail.replaceChildren(flowEl("p", "section-note", "Select a flow to see which devices are communicating and what the detector decided."));
    renderFlowList([], 0, true);
    refreshFlowStats();
    if (flowsView === "top") fetchTop();
    else if (flowsView === "timeline") fetchTimeline();
    else fetchFlows();
  }).catch(function() { toast("Could not clear flow history", "error"); });
}
function openFlows(opts) {
  if (!flowsOverlay) return;
  var wasHidden = flowsOverlay.hidden;
  if (wasHidden) flowsReturnFocus = document.activeElement;
  if (flowsOverlay.hidden) flowsOverlay.hidden = false;
  document.body.classList.add("modal-open");
  flowsContext = opts || null;
  flowsView = "flows";
  setFlowsView("flows");
  applyFlowsContext(opts || null);
  refreshFlowStats();
  if (flowsTimer) clearInterval(flowsTimer);
  flowsTimer = setInterval(function() {
    if (!flowsOverlay || flowsOverlay.hidden) return;
    if (flowsView === "flows") fetchFlows();
    else if (flowsView === "top") fetchTop();
    else if (flowsView === "timeline") fetchTimeline();
    else if (flowsView === "inventory") fetchInventory();
    else if (flowsView === "report") fetchReport();
    refreshFlowStats();
  }, 5000);
  var close = document.getElementById("flows-close");
  if (close) close.focus();
}
function closeFlows(restoreFocus) {
  if (!flowsOverlay || flowsOverlay.hidden) return;
  flowsOverlay.hidden = true;
  if (flowsTimer) { clearInterval(flowsTimer); flowsTimer = null; }
  if (flowsFilterTimer) { clearTimeout(flowsFilterTimer); flowsFilterTimer = null; }
  document.body.classList.remove("modal-open");
  if (restoreFocus !== false && flowsReturnFocus && flowsReturnFocus.focus) flowsReturnFocus.focus();
  flowsReturnFocus = null;
  flowsContext = null;
  timelineData = null;
}
document.getElementById("btn-flows").onclick = function() { openFlows(); };
document.getElementById("flows-close").onclick = function() { closeFlows(true); };
if (flowsOverlay) {
  flowsOverlay.addEventListener("click", function(ev) { if (ev.target === flowsOverlay) closeFlows(true); });
  flowsOverlay.addEventListener("keydown", function(ev) {
    if (ev.key === "Escape") { ev.preventDefault(); closeFlows(true); return; }
    if (ev.key !== "Tab") return;
    var focusable = flowsOverlay.querySelectorAll("button, [href], input, [tabindex]:not([tabindex='-1'])");
    if (!focusable.length) return;
    var first = focusable[0], last = focusable[focusable.length - 1];
    if (ev.shiftKey && document.activeElement === first) { ev.preventDefault(); last.focus(); }
    else if (!ev.shiftKey && document.activeElement === last) { ev.preventDefault(); first.focus(); }
  });
}
for (var fti = 0; fti < flowsTabs.length; fti++) {
  flowsTabs[fti].addEventListener("click", function() { setFlowsView(this.dataset.flowsView); });
}
if (flowsFilter) {
  flowsFilter.addEventListener("input", function() {
    if (flowsFilterTimer) clearTimeout(flowsFilterTimer);
    flowsFilterTimer = setTimeout(fetchFlows, 250);
  });
}
document.getElementById("flows-refresh").onclick = function() {
  if (flowsView === "flows") fetchFlows();
  else if (flowsView === "top") fetchTop();
  else if (flowsView === "inventory") fetchInventory();
  else if (flowsView === "report") fetchReport();
  else fetchTimeline();
  refreshFlowStats();
};
if (inventoryFilter) {
  inventoryFilter.addEventListener("input", function() {
    if (flowsFilterTimer) clearTimeout(flowsFilterTimer);
    flowsFilterTimer = setTimeout(fetchInventory, 250);
  });
}
if (document.getElementById("inventory-refresh")) {
  document.getElementById("inventory-refresh").onclick = fetchInventory;
}
var reportHourButtons = flowsOverlay ? flowsOverlay.querySelectorAll("[data-report-hours]") : [];
for (var rhi = 0; rhi < reportHourButtons.length; rhi++) {
  reportHourButtons[rhi].addEventListener("click", function() {
    reportHours = Number(this.dataset.reportHours) || 24;
    for (var j = 0; j < reportHourButtons.length; j++) {
      reportHourButtons[j].classList.toggle("active", reportHourButtons[j] === this);
    }
    fetchReport();
  });
}
if (document.getElementById("report-print")) {
  document.getElementById("report-print").onclick = function() { if (reportData) window.print(); };
}
if (document.getElementById("report-json")) {
  document.getElementById("report-json").onclick = reportJson;
}
if (document.getElementById("report-alerts-csv")) {
  document.getElementById("report-alerts-csv").onclick = reportAlertsCsv;
}
if (document.getElementById("report-timeline-csv")) {
  document.getElementById("report-timeline-csv").onclick = reportTimelineCsv;
}
if (flowsExport) flowsExport.onclick = exportFlows;
if (flowsCompact) flowsCompact.onclick = compactFlowHistory;
if (flowsClear) flowsClear.onclick = clearFlowHistory;
var flowKindButtons = flowsOverlay ? flowsOverlay.querySelectorAll("[data-flow-kind]") : [];
for (var fki = 0; fki < flowKindButtons.length; fki++) {
  flowKindButtons[fki].addEventListener("click", function() {
    flowsKind = this.dataset.flowKind || "";
    for (var j = 0; j < flowKindButtons.length; j++) {
      flowKindButtons[j].classList.toggle("active", flowKindButtons[j] === this);
    }
    fetchFlows();
  });
}
var topWindowButtons = flowsOverlay ? flowsOverlay.querySelectorAll("[data-top-window]") : [];
for (var twi = 0; twi < topWindowButtons.length; twi++) {
  topWindowButtons[twi].addEventListener("click", function() {
    flowsTopWindow = Number(this.dataset.topWindow) || 900;
    for (var j = 0; j < topWindowButtons.length; j++) {
      topWindowButtons[j].classList.toggle("active", topWindowButtons[j] === this);
    }
    fetchTop();
  });
}
var timelineWindowButtons = flowsOverlay ? flowsOverlay.querySelectorAll("[data-timeline-minutes]") : [];
for (var tmi = 0; tmi < timelineWindowButtons.length; tmi++) {
  timelineWindowButtons[tmi].addEventListener("click", function() {
    timelineMinutes = Number(this.dataset.timelineMinutes) || 60;
    for (var j = 0; j < timelineWindowButtons.length; j++) {
      timelineWindowButtons[j].classList.toggle("active", timelineWindowButtons[j] === this);
    }
    fetchTimeline();
  });
}
window.addEventListener("resize", function() {
  if (timelineData && flowsView === "timeline" && flowsOverlay && !flowsOverlay.hidden) drawTimeline(timelineData);
});
var selFlowsButton = document.getElementById("sel-flows");
if (selFlowsButton) selFlowsButton.onclick = function() { if (selectedNodeIp) showFlowsForDevice(selectedNodeIp); };
var freezeButton = document.getElementById("btn-freeze-layout");
if (freezeButton) freezeButton.onclick = function() { setFreezeLayout(!freezeLayout); };
setFreezeLayout(freezeLayout);

// Investigation dialog: one screen for an alert or a device.
var investigationOverlay = document.getElementById("investigation-overlay");
var investigationBody = document.getElementById("investigation-body");
var investigationReturnFocus = null;
function openInvestigation(opts) {
  if (!investigationOverlay || !investigationBody) return;
  opts = opts || {};
  investigationReturnFocus = document.activeElement;
  investigationOverlay.hidden = false;
  document.body.classList.add("modal-open");
  investigationBody.replaceChildren(flowEl("p", "section-note", "Loading investigation…"));
  var params = new URLSearchParams();
  if (opts.ip) params.set("ip", opts.ip);
  if (opts.src) params.set("src", opts.src);
  if (opts.dst) params.set("dst", opts.dst);
  if (opts.at) params.set("at", String(opts.at));
  fetch("/api/investigation?" + params.toString()).then(function(res) {
    if (res.status === 401) { closeInvestigation(false); showAuth(); return null; }
    if (!res.ok) throw new Error("HTTP " + res.status);
    return res.json();
  }).then(function(data) {
    if (data) renderInvestigation(data);
  }).catch(function() {
    if (investigationBody) investigationBody.replaceChildren(flowEl("p", "section-note", "Could not load the investigation."));
  });
  var close = document.getElementById("investigation-close");
  if (close) close.focus();
}
function closeInvestigation(restoreFocus) {
  if (!investigationOverlay || investigationOverlay.hidden) return;
  investigationOverlay.hidden = true;
  if (!flowsOverlay || flowsOverlay.hidden) document.body.classList.remove("modal-open");
  if (restoreFocus !== false && investigationReturnFocus && investigationReturnFocus.focus) investigationReturnFocus.focus();
  investigationReturnFocus = null;
}
function invCard(label, value, sub) {
  var card = flowEl("div", "investigation-card");
  card.appendChild(flowEl("span", "investigation-label", label));
  card.appendChild(flowEl("b", "", value || "—"));
  if (sub) card.appendChild(flowEl("small", "", sub));
  return card;
}
function renderInvestigation(data) {
  if (!investigationBody) return;
  investigationBody.replaceChildren();
  var device = data.device || {};
  var ip = device.ip || "";
  var head = flowEl("div", "investigation-head");
  var title = flowEl("div", "");
  title.appendChild(flowEl("h4", "", (device.name || ip || "Investigation")));
  title.appendChild(flowEl("p", "section-note", [device.role, device.kind, device.mac].filter(Boolean).join(" · ") || "No inventory metadata"));
  head.appendChild(title);
  if (ip) {
    var actions = flowEl("div", "investigation-actions");
    var flowsBtn = flowEl("button", "sel-btn", "Flows");
    flowsBtn.type = "button";
    flowsBtn.onclick = function() { closeInvestigation(false); showFlowsForDevice(ip); };
    actions.appendChild(flowsBtn);
    if (authRole === "operator") {
      var trustBtn = flowEl("button", "sel-btn", data.trusted ? "Untrust" : "Trust");
      trustBtn.type = "button";
      trustBtn.onclick = function() { post("/api/devices/trust", { ip: ip, trusted: !data.trusted }); };
      actions.appendChild(trustBtn);
      var blockBtn = flowEl("button", "sel-btn " + (data.blocked ? "safe" : "danger"), data.blocked ? "Unblock" : "Block");
      blockBtn.type = "button";
      blockBtn.onclick = function() { post(data.blocked ? "/api/firewall/unblock" : "/api/firewall/block", { ip: ip, reason: "investigation" }); };
      actions.appendChild(blockBtn);
    }
    head.appendChild(actions);
  }
  investigationBody.appendChild(head);

  var grid = flowEl("div", "investigation-grid");
  grid.appendChild(invCard("IP", ip));
  grid.appendChild(invCard("First seen", flowClock(device.first_seen, true)));
  grid.appendChild(invCard("Last seen", flowClock(device.last_seen, true)));
  grid.appendChild(invCard("State", data.blocked ? "blocked" : data.trusted ? "trusted" : data.protected ? "protected" : "normal"));
  grid.appendChild(invCard("Sensitivity", data.sensitivity || "balanced"));
  grid.appendChild(invCard("Suppression", data.suppress || "none"));
  investigationBody.appendChild(grid);

  var endpoints = Object.keys(data.geo || {});
  if (endpoints.length) {
    var geoBox = flowEl("div", "investigation-section");
    geoBox.appendChild(flowEl("h4", "", "Country / ASN (local CSV)"));
    endpoints.forEach(function(endpoint) {
      var geo = data.geo[endpoint] || {};
      geoBox.appendChild(flowEl("p", "section-note", endpoint + ": " +
        [geo.country, geo.asn, geo.org].filter(Boolean).join(" · ") +
        " (" + (geo.source || "unknown") + ")"));
    });
    investigationBody.appendChild(geoBox);
  }

  if (data.ports && data.ports.length) {
    var ports = flowEl("div", "investigation-section");
    ports.appendChild(flowEl("h4", "", "Top destination ports"));
    var chips = flowEl("div", "investigation-chips");
    data.ports.forEach(function(item) {
      chips.appendChild(flowEl("span", "flows-chip", item.port + " · " + item.count));
    });
    ports.appendChild(chips);
    investigationBody.appendChild(ports);
  }

  if (data.alerts && data.alerts.length) {
    var alerts = flowEl("div", "investigation-section");
    alerts.appendChild(flowEl("h4", "", "Related alerts"));
    data.alerts.slice(0, 5).forEach(function(alert) {
      var line = flowEl("div", "investigation-line");
      line.appendChild(flowEl("b", "", flowAttackName(alert.attack) + " · " + (alert.severity || "low")));
      line.appendChild(flowEl("span", "", alert.time + " · " + alert.src + " → " + alert.dst + " · " + (alert.engine || "")));
      if (alert.evidence) {
        line.appendChild(flowEl("small", "", Object.keys(alert.evidence).map(function(key) {
          return key + "=" + alert.evidence[key];
        }).join(" · ")));
      }
      alerts.appendChild(line);
    });
    investigationBody.appendChild(alerts);
  }

  if (data.flows && data.flows.length) {
    var flows = flowEl("div", "investigation-section");
    flows.appendChild(flowEl("h4", "", "Related flows"));
    data.flows.slice(0, 12).forEach(function(item) {
      var row = flowEl("button", "investigation-flow");
      row.type = "button";
      row.appendChild(flowEl("span", "", flowClock(item.ts) + " · " + item.src + " → " + item.dst));
      row.appendChild(flowEl("small", "", (item.protocols || "—") + " · " + flowBytes(item.bytes) + " · " +
        (item.attack || "benign")));
      row.onclick = function() { closeInvestigation(false); showFlowsForDevice(item.src); };
      flows.appendChild(row);
    });
    investigationBody.appendChild(flows);
  }

  if (data.history && data.history.length) {
    var history = flowEl("div", "investigation-section");
    history.appendChild(flowEl("h4", "", "Inventory history"));
    data.history.slice(0, 12).forEach(function(event) {
      history.appendChild(flowEl("p", "section-note",
        flowClock(event.at, true) + " · " + event.event +
        (event.detail ? " · " + event.detail : "")));
    });
    investigationBody.appendChild(history);
  }
}
document.getElementById("investigation-close").onclick = function() { closeInvestigation(true); };
if (investigationOverlay) {
  investigationOverlay.addEventListener("click", function(ev) { if (ev.target === investigationOverlay) closeInvestigation(true); });
  investigationOverlay.addEventListener("keydown", function(ev) {
    if (ev.key === "Escape") { ev.preventDefault(); closeInvestigation(true); }
  });
}

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
  if (authRole === "viewer") { toast("Read-only token: this action needs the operator token", "error"); return; }
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
  var isSuspicious = role === "unknown", isTrusted = role === "trusted", isAttacker = role === "attacker";
  // Immediate feedback while the next snapshot re-renders the node: state ring
  // first, otherwise the device type. Never touch the glyph here (it belongs
  // to the type) and never call a role icon.
  var ring = isSuspicious ? "#d29922" : (isAttacker ? "#f85149"
    : (isTrusted ? "#3fb950" : (KIND_COLORS[node.kind] || KIND_COLORS.unknown)));
  nodes.update({
    id: ip, role: role,
    color: { background: ring, border: ring, highlight: { background: ring, border: "#ffffff" }, hover: { background: ring, border: "#ffffff" } },
    borderWidth: isSuspicious || isAttacker ? 3 : 2,
    shadow: { enabled: true, color: ring + "44", size: isSuspicious || isAttacker ? 14 : 10, x: 0, y: 3 },
    title: nodeInfoTitle({ mac: node.mac, openPorts: node.openPorts || [], hostRole: node.hostRole,
                           kindLabel: KIND_LABELS[node.kind] || "", macVendor: node.macVendor,
                           privateMac: node.privateMac }, headline)
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

network.on("doubleClick", function(p) { var ip = p.nodes[0]; if (!ip) return; if (authRole === "viewer") { toast("Read-only token: this action needs the operator token", "error"); return; } var label = nodes.get(ip)?.label || ""; var current = label.split("\n")[0]; var name = window.prompt("Name this device (" + ip + ")", current); if (name && name.trim()) post("/api/devices/rename", { ip: ip, name: name.trim() }); });

window.addEventListener("keydown", function(ev) {
  if (ev.target && (ev.target.tagName === "INPUT" || ev.target.tagName === "TEXTAREA" || ev.target.isContentEditable)) return;
  if (ev.ctrlKey || ev.metaKey || ev.altKey) return;
  var authOverlay = document.getElementById("auth-overlay");
  if (authOverlay && !authOverlay.hidden) return;
  if (investigationOverlay && !investigationOverlay.hidden) {
    if (ev.key === "Escape") { ev.preventDefault(); closeInvestigation(true); }
    return;
  }
  if (flowsOverlay && !flowsOverlay.hidden) {
    if (ev.key === "Escape") { ev.preventDefault(); closeFlows(true); }
    return;
  }
  if (helpOverlay && !helpOverlay.hidden) {
    if (ev.key === "Escape") { ev.preventDefault(); closeHelp(); }
    return;
  }
  var key = ev.key.toLowerCase();
  if (ev.key === "?" || key === "h") { ev.preventDefault(); openHelp(); }
  else if (key === "f") { ev.preventDefault(); openFlows(); }
  else if (key === "b" && selectedNodeIp) {
    if (authRole === "viewer") toast("Read-only token: this action needs the operator token", "error");
    else if (!isBlockableNode(selectedNodeIp)) toast("Infrastructure nodes cannot be blocked", "error");
    else if (blockedHosts.has(selectedNodeIp)) toast(selectedNodeIp + " is already blocked", "error");
    else post("/api/firewall/block", { ip: selectedNodeIp, reason: "operator blocked selected node" });
  }
  else if (ev.key === "Escape") { selectedNodeIp = null; updateSelectionBar(); network.unselectAll(); closeTrustMenu(); hideAttackBanner(); }
  else if (key === "r") fitMapView(true);
  else if (key === "k") setFreezeLayout(!freezeLayout);
  else if (key === "/") { ev.preventDefault(); if (pickerInput) { pickerInput.focus(); pickerInput.select(); pickerRender(); } }
  else if (key === "m") toggleMapMinimize();
  else if (key === "l") toggleLegend();
  else if (key === "d") toggleFx();
});

function renderTopology(data) {
  var now = Date.now(); fxSync(data); updateFlashes(data, now);
  syncTrusted(data);
  syncProtected(data);
  if (attackBannerEl && attackBannerEl.dataset.src && blockedHosts.has(attackBannerEl.dataset.src)) hideAttackBanner();
  var pos = computeTreeLayout(data);
  // Role changes (e.g. a workstation becoming the gateway) change the sorted
  // leaf order, so include the role in the layout key as well as the IPs.
  var key = data.nodes.map(function(h) { return h.ip + ":" + h.role + ":" + (h.kind || ""); }).sort().join(",") +
    "|" + Object.keys(pos).sort().join(",");
  var layoutChanged = key !== layoutKey;
  // Type filter (click a row in the legend): infrastructure always stays
  // visible; everything else outside the chosen type is dimmed, not removed,
  // so the map keeps its shape and the context is still there.
  var kindOf = new Map();
  for (var k0 = 0; k0 < data.nodes.length; k0++) {
    var hk = data.nodes[k0];
    kindOf.set(hk.ip, hk.role === "router" ? "router"
      : hk.role === "external" ? "external" : (hk.kind || "unknown"));
  }
  function typeVisible(ip) {
    if (!kindFilter) return true;
    var kind = kindOf.get(ip);
    return kind === "router" || kind === "external" || kind === kindFilter;
  }
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
    // Ring: state first (blocked/attacker/trusted/suspicious), then the device
    // type the sensor actually found, then the role for infrastructure. The
    // default "workstation" role is never used as a colour.
    var kindColor = KIND_COLORS[h.kind] || "";
    var borderColor = isBlocked || flashing ? "#f85149"
      : isAttacker ? "#f85149"
      : isUnknown ? "#d29922"
      : isTrusted ? "#3fb950"
      : (h.role === "router" || h.role === "external") ? style.color
      : (kindColor || KIND_COLORS.unknown);
    var nodeColor = { background: borderColor, border: borderColor, highlight: { background: borderColor, border: "#ffffff" }, hover: { background: borderColor, border: "#ffffff" } };
    var base = { color: nodeColor, opacity: typeVisible(h.ip) ? (isBlocked ? 0.5 : 1) : 0.12, borderWidth: isBlocked ? 3 : flashing ? 4 : (h.role === "router" || isAttacker || isUnknown ? 3 : 2), font: { color: isBlocked ? "#8b949e" : "#d7dee8", size: 12, face: "Segoe UI", strokeWidth: 3, strokeColor: "#0b0f14", vadjust: 4 }, shadow: { enabled: true, color: borderColor + (isBlocked || flashing ? "55" : "44"), size: isBlocked ? 20 : flashing ? 16 : (h.role === "router" ? 18 : (isAttacker ? 14 : (isUnknown ? 12 : 10))), x: 0, y: 3 }, shapeProperties: { useBorderWithImage: true, borderDashes: h.role === "external" ? [4, 4] : false } };
    var headline = isBlocked ? "\u{1F6AB} BLOCKED" : (isAttacker ? "ATTACKER (confirmed)" : isTrusted ? "TRUSTED (marked by user)" : isUnknown ? "SUSPICIOUS / UNKNOWN" : style.label);
    var kindLabel = h.kind ? (KIND_LABELS[h.kind] || "") : "";
    if (displayRole === "workstation") {
      // The role is only the default (nothing was inferred): the tooltip must
      // say what the sensor actually found, not "Workstation".
      headline = kindLabel || "Unknown";
      kindLabel = "";
    }
    var title = nodeInfoTitle({ mac: h.mac, openPorts: h.open_ports || [], hostRole: h.role, kindLabel: kindLabel, lastSeen: fmtSeen(h.last_seen), macVendor: h.mac_vendor, privateMac: h.private_mac }, headline);
    var nodeSize = h.role === "router" ? 27 : h.role === "external" ? 23 : (isAttacker ? 22 : 20);
    var img = glyphIconURI(nodeGlyph(h, displayRole, isAttacker));
    if (!nodes.get(h.ip)) {
      var nodeData = { id: h.ip, label: nodeLabel(h.hostname, h.ip, nodeTypeLabel(h)), title: title, role: displayRole, hostRole: h.role, hostname: h.hostname, mac: h.mac, kind: h.kind || "", openPorts: h.open_ports || [], lastSeen: h.last_seen, macVendor: h.mac_vendor || "", privateMac: !!h.private_mac, shape: "circularImage", size: nodeSize, image: img, x: pos[h.ip].x, y: pos[h.ip].y };
      for (var k in base) nodeData[k] = base[k];
      nodes.add(nodeData);
    } else {
      var label = nodeLabel(h.hostname, h.ip, nodeTypeLabel(h));
      var existing = nodes.get(h.ip);
      var updateObj = { id: h.ip, role: displayRole, hostRole: h.role, hostname: h.hostname, mac: h.mac, kind: h.kind || "", openPorts: h.open_ports || [], lastSeen: h.last_seen, macVendor: h.mac_vendor || "", privateMac: !!h.private_mac, title: title, size: nodeSize };
      if (existing.label !== label) updateObj.label = label;
      if (existing.image !== img) updateObj.image = img;
      for (var k2 in base) updateObj[k2] = base[k2];
      nodes.update(updateObj);
    }
    seen.add(h.ip);
  } for (var ni = 0; ni < nodes.get().length; ni++) if (!seen.has(nodes.get()[ni].id)) nodes.remove(nodes.get()[ni].id);
  if (layoutChanged) {
    layoutKey = key;
    if (!layoutInitialized || !freezeLayout) {
      for (var id in pos) if (nodes.get(id)) {
        network.moveNode(id, pos[id].x, pos[id].y);
        positionedNodes.add(id);
      }
    } else {
      for (var nid in pos) if (nodes.get(nid) && !positionedNodes.has(nid)) {
        network.moveNode(nid, pos[nid].x, pos[nid].y);
        positionedNodes.add(nid);
      }
    }
    // Fit once, when the first snapshot arrives. Later snapshots add devices
    // and reflow the tree; fitting on every reflow yanked the viewport around
    // while the operator was looking at a node. R still fits on demand.
    if (!layoutInitialized) { layoutInitialized = true; fitMapView(false); }
    if (selectedNodeIp) setTimeout(ensureSelectionVisible, 560);
  }
  var seenEdges = new Set();
  for (var ei = 0; ei < data.edges.length; ei++) {
    var e = data.edges[ei];
    var isLink = e.kind === "link";
    var id = (isLink ? "L|" : "T|") + e.from + "|" + e.to;
    var active = typeVisible(e.from) && typeVisible(e.to);
    var edgeColor = active ? (isLink ? "#3d444d" : "#6e7681") : "#252a31";
    var edgeWidth = (isLink ? 2 : 1.4) * (active ? 1 : 0.7);
    if (!edges.get(id)) {
      edges.add({ id: id, from: e.from, to: e.to, dashes: !isLink, width: edgeWidth,
                  arrows: isLink ? "" : { to: { enabled: true, scaleFactor: 0.5, type: "arrow" } },
                  color: { color: edgeColor, highlight: "#58a6ff", hover: "#58a6ff" },
                  smooth: isLink ? false : { enabled: true, type: "continuous", roundness: 0.3 },
                  selectionWidth: 3 });
    } else {
      var existingEdge = edges.get(id);
      if (existingEdge.color.color !== edgeColor || existingEdge.width !== edgeWidth) {
        edges.update({ id: id, width: edgeWidth,
                       color: { color: edgeColor, highlight: "#58a6ff", hover: "#58a6ff" } });
      }
    }
    seenEdges.add(id);
  }
  edges.get().forEach(function(edge) { if (!seenEdges.has(edge.id)) edges.remove(edge.id); });
}


function fmtAlert(a) {
  var div = document.createElement("div");
  var sev = (a.severity || "info").toLowerCase();
  var icon = SEV_ICONS[sev] || "\u2139\uFE0F";
  var engineName = a.engine === "suricata" ? "suricata"
    : (a.engine === "rules" || a.engine === "ml+rules") ? a.engine : "ml";
  var engineClass = (engineName === "rules" || engineName === "suricata") ? "rules" : "ml";
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
  var dismiss = serverFeatures.has("dismiss_alerts")
    ? '<button type="button" class="alert-dismiss" data-dismiss="' + esc(dismissKey(a)) +
      '" title="Dismiss from the feed \u2014 the audit log keeps it" aria-label="Dismiss alert">\u00d7</button>'
    : '';
  var triage = a.triage || {};
  var triageKey = dismissKey(a);
  var triageBadge = "";
  if (triage.false_positive) triageBadge = '<span class="triage-badge fp">FALSE POSITIVE</span>';
  else if (triage.status === "closed") triageBadge = '<span class="triage-badge closed">CLOSED</span>';
  else if (triage.status === "ack") triageBadge = '<span class="triage-badge ack">ACK</span>';
  var triageMeta = (triageBadge || triage.assignee || triage.note)
    ? '<div class="triage-meta">' + triageBadge +
      (triage.assignee ? ' <span class="triage-assignee">' + esc(triage.assignee) + '</span>' : '') +
      (triage.note ? ' <span class="triage-note">' + esc(triage.note) + '</span>' : '') + '</div>'
    : '';
  var triageActions = "";
  if (serverFeatures.has("alert_triage") && sev !== "info") {
    triageActions = '<div class="triage-actions">' +
      '<button type="button" class="act triage" data-triage="ack" data-triage-key="' + esc(triageKey) + '">Ack</button>' +
      '<button type="button" class="act triage" data-triage="false_positive" data-triage-key="' + esc(triageKey) + '">False positive</button>' +
      (triage.status || triage.false_positive ? '<button type="button" class="act triage" data-triage="clear" data-triage-key="' + esc(triageKey) + '">Reopen</button>' : '') +
      '<button type="button" class="act triage" data-triage="note" data-triage-key="' + esc(triageKey) + '">Note</button>' +
      '</div>';
  }
  var alertAt = Number(a.at) || (Date.now() / 1000);
  var flowAction = '<button type="button" class="act triage" data-alert-flows="1" data-src="' +
    esc(a.src) + '" data-dst="' + esc(a.dst) + '" data-at="' + esc(alertAt) +
    '" title="Show flows between these endpoints around this alert">Flows</button>';
  var investigateAction = '<button type="button" class="act triage" data-alert-investigate="1" data-src="' +
    esc(a.src) + '" data-dst="' + esc(a.dst) + '" data-at="' + esc(alertAt) +
    '" title="Open the device investigation view">Investigate</button>';
  div.className = "alert " + sev;
  div.innerHTML = '<div class="top"><b>' + icon + " " + esc(attackLabel(a.attack)) + '</b><span class="sev-badge">' + sev.toUpperCase() + '</span>' + repeats + dismiss + '</div>' +
    '<div class="meta">' + esc(a.time) + " \u00B7 " + esc(a.src) + " \u2192 " + esc(a.dst) +
    ' \u00B7 engine: <span class="engine-tag ' + engineClass + '">' + engineName + '</span> \u00B7 conf: ' + esc(a.confidence) +
    (a.sensor ? ' \u00B7 <span class="sensor-tag">sensor ' + esc(a.sensor) + '</span>' : '') + '</div>' +
    action + flowAction + investigateAction + triageMeta + triageActions;
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
                   JSON.stringify(a.triage || {}),
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
function onAction(ev) {
  var dismiss = ev.target.closest("[data-dismiss]");
  if (dismiss) { dismissAlert(dismiss.dataset.dismiss); return; }
  var alertFlows = ev.target.closest("[data-alert-flows]");
  if (alertFlows) {
    var at = Number(alertFlows.dataset.at) || (Date.now() / 1000);
    openFlows({
      src: alertFlows.dataset.src, dst: alertFlows.dataset.dst,
      since: at - 300, until: at + 300,
      label: "Alert " + alertFlows.dataset.src + " \u2192 " + alertFlows.dataset.dst + " \u00B1 5 min",
    });
    return;
  }
  var investigate = ev.target.closest("[data-alert-investigate]");
  if (investigate) {
    openInvestigation({
      src: investigate.dataset.src, dst: investigate.dataset.dst,
      at: Number(investigate.dataset.at) || (Date.now() / 1000),
    });
    return;
  }
  var triage = ev.target.closest("[data-triage]");
  if (triage) {
    triageAction(triage.dataset.triage, triage.dataset.triageKey);
    return;
  }
  var block = ev.target.closest("[data-ip]");
  var unblock = ev.target.closest("[data-unblock]");
  if (block) post("/api/firewall/block", { ip: block.dataset.ip, reason: "operator blocked from UI" });
  if (unblock) post("/api/firewall/unblock", { ip: unblock.dataset.unblock });
}

function triageAction(action, key) {
  var current = null;
  if (lastData && Array.isArray(lastData.alerts)) {
    current = lastData.alerts.find(function(a) { return dismissKey(a) === key; });
  }
  var existing = (current && current.triage) || {};
  var body = {
    key: key,
    status: existing.status || "open",
    assignee: existing.assignee || "",
    note: existing.note || "",
    false_positive: !!existing.false_positive
  };
  if (action === "ack") {
    body.status = "ack";
    body.false_positive = false;
  } else if (action === "false_positive") {
    body.status = "closed";
    body.false_positive = true;
  } else if (action === "clear") {
    body.status = "open";
    body.false_positive = false;
  } else if (action === "note") {
    var note = window.prompt("Note for this alert", existing.note || "");
    if (note === null) return;
    body.note = note;
    if (!body.status || body.status === "open") body.status = "ack";
  } else {
    return;
  }
  post("/api/alerts/triage", body);
}

// Hide one card from the feed. The server also persists the key, so the log
// replay after a restart will not bring it back; the JSONL audit log keeps it.
function csrfToken() {
  var m = document.cookie.match(/(?:^|;\s*)lassi_csrf=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : "";
}

async function dismissAlert(key) {
  try {
    var res = await fetch("/api/alerts/dismiss", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken() },
      body: JSON.stringify({ key: key })
    });
    if (res.status === 401) { showAuth(); return; }
    if (res.status === 403) { toast("Read-only token: this action needs the operator token", "error"); return; }
    var data = await res.json().catch(function() { return {}; });
    if (!res.ok || (data && data.ok === false)) {
      toast((data && data.error) || "Could not dismiss that alert", "error");
      return;
    }
    if (lastData) {
      lastData.alerts = (lastData.alerts || []).filter(function(a) { return dismissKey(a) !== key; });
      confirmedAttackers = new Set();
      seedConfirmedAttackers(lastData);
      renderTopology(lastData);
      renderFeeds(lastData);
      renderLog(lastData);
      updateSelectionBar();
      updateLegend(lastData);
    }
    toast("Alert dismissed \u00b7 it stays in the audit log");
    refresh();
  } catch (e) {
    console.error("dismiss failed:", e);
    toast("Action failed \u2014 check the server log", "error");
  }
}
async function post(url, body) {
  try {
    var res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrfToken() },
      body: JSON.stringify(body)
    });
    if (res.status === 401) { showAuth(); return; }
    if (res.status === 403) { toast("Read-only token: this action needs the operator token", "error"); return; }
    if (!res.ok) throw new Error("HTTP " + res.status);
    var data = await res.json().catch(function() { return {}; });
    if (data && data.ok === false) { toast(data.error || "That action is not allowed right now", "error"); return; }
    if (url.indexOf("/firewall/block") >= 0) {
      if (data.changed === false) toast(body.ip + " is already blocked", "error");
      else if (data.simulated) toast(body.ip + " marked as blocked \u00B7 simulated (mock firewall, nothing dropped)");
      else toast("Blocked " + body.ip + " \u00B7 traffic from it is dropped");
    } else if (url.indexOf("/firewall/unblock") >= 0) {
      if (data.changed === false) toast("No active block for " + body.ip, "error");
      else if (data.simulated) toast(body.ip + " unblocked \u00B7 simulated (nothing was enforced)");
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
  var isPassive = mode.indexOf("passive") >= 0;
  var isDryRun = data.dry_run === true;
  modeEl.title = isLive
    ? (mode.indexOf("capture error") >= 0
        ? "Live mode: the packet capture stopped \u2014 check the server log or /health for the reason"
        : isPassive
          ? "Live passive mode: only reads captured flows; no ARP sweep or port probes"
          : "Live mode: reading real traffic from this machine")
    : "Demo mode: simulated traffic on a fictional network \u2014 no real packets";
  // Enforcement context: the mode badge says how traffic is captured; this
  // one says whether a Block really drops anything. A mock firewall must
  // never look like a real one.
  firewallProvider = String(data.firewall || "mock");
  firewallReady = data.firewall_ready === true;
  firewallNote = String(data.firewall_note || "");
  var fwEl = document.getElementById("fw-badge");
  if (fwEl) {
    var fwNames = { mock: "mock \u00b7 simulated", windows: "Windows Firewall",
                    nftables: "nftables", opnsense: "OPNsense",
                    pfsense: "pfSense \u00b7 placeholder" };
    var fwLabel = isDryRun ? "mock \u00b7 dry-run"
      : (fwNames[firewallProvider] || firewallProvider);
    fwEl.textContent = "FW: " + fwLabel;
    fwEl.className = "badge fw " + (firewallReady && !isDryRun ? "ok" : "warn");
    fwEl.title = isDryRun
      ? "Dry-run: blocks are recorded and shown, but no firewall rule is created"
      : firewallReady
        ? "Firewall " + firewallProvider + " \u2014 blocks are real"
        : (firewallNote || ("Firewall " + firewallProvider + " \u2014 blocks are simulated"));
  }
  var noteEl = document.getElementById("rules-note");
  if (noteEl) {
    var autoTtl = Number(data.auto_block_ttl) || 0;
    var ttlNote = autoTtl > 0
      ? " Auto-blocks expire after " + Math.round(autoTtl / 60) + " min."
      : " Auto-blocks do not expire.";
    var baseNote = isDryRun
      ? "Dry-run: blocks are recorded and shown, but no firewall rule is created."
      : firewallReady
        ? "Active blocks only. Block source drops traffic from that IP; Unblock reverses it. History stays in the System log."
        : (firewallNote || "Simulated: blocks are recorded here but no traffic is dropped.");
    noteEl.textContent = baseNote + ttlNote;
    noteEl.classList.toggle("warn-note", !firewallReady || isDryRun);
  }
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
function setFreezeLayout(on) {
  freezeLayout = !!on;
  try { localStorage.setItem("lassi.freezeLayout", freezeLayout ? "on" : "off"); } catch (e) { /* ignore */ }
  var btn = document.getElementById("btn-freeze-layout");
  if (btn) {
    btn.classList.toggle("off", !freezeLayout);
    btn.setAttribute("aria-pressed", freezeLayout ? "true" : "false");
    btn.title = freezeLayout ? "Layout frozen — new nodes appear without moving existing ones (K)"
      : "Layout follows topology changes (K)";
  }
  if (!freezeLayout && lastData) {
    layoutKey = "";
    renderTopology(lastData);
  }
}
var pollTimer = null; function startPolling() { if (pollTimer) return; pollTimer = setInterval(refresh, 2000); } function stopPolling() { if (pollTimer) { clearInterval(pollTimer); pollTimer = null; } }
function showAuth(message) {
  var overlay = document.getElementById("auth-overlay");
  if (!overlay) return;
  authBlocked = true;
  stopPolling();
  if (investigationOverlay && !investigationOverlay.hidden) closeInvestigation(false);
  if (flowsOverlay && !flowsOverlay.hidden) closeFlows(false);
  if (helpOverlay && !helpOverlay.hidden) closeHelp();
  overlay.hidden = false;
  document.body.classList.add("modal-open");
  var err = document.getElementById("auth-error");
  if (err) { err.textContent = message || ""; err.hidden = !message; }
  var input = document.getElementById("auth-token");
  if (input) setTimeout(function() { input.focus(); }, 50);
}

async function submitAuth() {
  var input = document.getElementById("auth-token");
  var err = document.getElementById("auth-error");
  var token = input ? input.value.trim() : "";
  if (!token) {
    if (err) { err.textContent = "Enter an access token"; err.hidden = false; }
    return;
  }
  try {
    var res = await fetch("/api/auth", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token: token })
    });
    if (!res.ok) {
      if (err) {
        err.textContent = res.status === 429
          ? "Too many attempts; wait a minute"
          : "Invalid token";
        err.hidden = false;
      }
      return;
    }
    location.reload();
  } catch (e) {
    if (err) { err.textContent = "Could not sign in"; err.hidden = false; }
  }
}

async function refresh() {
  if (authBlocked) return;
  try {
    var res = await fetch("/api/state");
    if (res.status === 401) { showAuth(); return; }
    if (!res.ok) throw new Error("HTTP " + res.status);
    apply(await res.json());
  } catch (e) { console.warn("refresh failed:", e); }
}
function setConnStatus(state) {
  var el = document.getElementById("map-status");
  if (!el) return;
  el.className = "map-status " + state;
  el.textContent = state === "live" ? "live" : state === "polling" ? "polling" : "connecting\u2026";
  el.title = state === "live" ? "Live \u2014 WebSocket stream connected" : state === "polling" ? "WebSocket unavailable \u2014 refreshing over /api/state" : "Connecting to the live stream\u2026";
}
function apply(data) { lastData = data; serverFeatures = new Set((data && data.features) || []);
  authRole = (data && data.role) || "operator";
  document.body.classList.toggle("read-only", authRole === "viewer");
  renderTopology(data); renderFeeds(data); renderLog(data); renderStats(data); updateSelectionBar(); updateLegend(data); }
// The legend lists the icon set once, built from the same glyph map the map
// uses (so the SVG is never duplicated in the HTML).
function buildLegendIcons() {
  var box = document.getElementById("legend-icons");
  if (!box) return;
  box.replaceChildren();
  LEGEND_KINDS.forEach(function(kind) {
    var row = document.createElement("span");
    row.className = "lg";
    row.dataset.kind = kind;
    row.setAttribute("role", "button");
    row.setAttribute("aria-pressed", "false");
    row.tabIndex = 0;
    var dot = document.createElement("span");
    dot.className = "kind-dot";
    dot.style.background = KIND_COLORS[kind] || "#6e7681";
    dot.style.color = dot.style.background;
    var img = document.createElement("img");
    img.src = glyphIconURI(kind);
    img.alt = "";
    img.width = 18;
    img.height = 18;
    var label = document.createElement("span");
    label.className = "lg-label";
    label.textContent = LEGEND_LABELS[kind] || KIND_LABELS[kind] || kind;
    var count = document.createElement("span");
    count.className = "lg-count";
    row.appendChild(dot);
    row.appendChild(img);
    row.appendChild(label);
    row.appendChild(count);
    row.addEventListener("click", function() { toggleKindFilter(kind); });
    row.addEventListener("keydown", function(ev) {
      if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); toggleKindFilter(kind); }
    });
    box.appendChild(row);
  });
}

// Click a type to isolate it: matching devices stay bright, the rest dim to
// context. Linux/POSIX style: clicking the active row again clears it.
function toggleKindFilter(kind) {
  kindFilter = kindFilter === kind ? null : kind;
  if (lastData) {
    renderTopology(lastData);
    updateLegend(lastData);
  }
}

function updateLegend(data) {
  var counts = {};
  ((data && data.nodes) || []).forEach(function(h) {
    var kind = h.role === "router" ? "router"
      : h.role === "external" ? "external" : (h.kind || "unknown");
    counts[kind] = (counts[kind] || 0) + 1;
  });
  Array.prototype.forEach.call(document.querySelectorAll("#legend-icons .lg"), function(row) {
    var kind = row.dataset.kind;
    var count = counts[kind] || 0;
    var badge = row.querySelector(".lg-count");
    if (badge) badge.textContent = count ? String(count) : "";
    var on = kindFilter === kind;
    row.classList.toggle("active", on);
    row.setAttribute("aria-pressed", on ? "true" : "false");
    row.title = (on ? "Showing only " : "Show only ")
      + (KIND_LABELS[kind] || kind) + " (" + count + ")";
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
  if (kindFilter) {                     // choosing a device always shows it
    kindFilter = null;
    if (lastData) { renderTopology(lastData); updateLegend(lastData); }
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
  // The header grows when the badges wrap (mobile / narrow windows). The
  // attack banner is fixed, so follow the real header height instead of a
  // hard-coded top that overlapped it.
  var headerEl = document.querySelector("header");
  function syncHeaderHeight() {
    if (headerEl) document.documentElement.style.setProperty("--header-h", headerEl.offsetHeight + "px");
  }
  syncHeaderHeight();
  if (headerEl && typeof ResizeObserver !== "undefined") {
    new ResizeObserver(syncHeaderHeight).observe(headerEl);
  } else {
    window.addEventListener("resize", syncHeaderHeight);
  }

  var authSubmitBtn = document.getElementById("auth-submit");
  if (authSubmitBtn) authSubmitBtn.addEventListener("click", submitAuth);
  var authTokenInput = document.getElementById("auth-token");
  if (authTokenInput) authTokenInput.addEventListener("keydown", function(ev) {
    if (ev.key === "Enter") { ev.preventDefault(); submitAuth(); }
  });

  var installBtn = document.getElementById("btn-install");
  var deferredInstall = null;
  window.addEventListener("beforeinstallprompt", function(ev) {
    ev.preventDefault();
    deferredInstall = ev;
    if (installBtn) installBtn.hidden = false;
  });
  if (installBtn) {
    installBtn.addEventListener("click", async function() {
      if (!deferredInstall) return;
      deferredInstall.prompt();
      try { await deferredInstall.userChoice; } catch (e) { /* dismissed */ }
      deferredInstall = null;
      installBtn.hidden = true;
    });
  }
  window.addEventListener("appinstalled", function() {
    if (installBtn) installBtn.hidden = true;
  });
  if ("serviceWorker" in navigator && (location.protocol === "https:" ||
      location.hostname === "localhost" || location.hostname === "127.0.0.1")) {
    window.addEventListener("load", function() {
      navigator.serviceWorker.register("sw.js").catch(function(e) {
        console.warn("service worker registration failed", e);
      });
    });
  }

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
    if (authBlocked) return;
    var proto = location.protocol === "https:" ? "wss" : "ws";
    var ws = new WebSocket(proto + "://" + location.host + "/ws");
    ws.onopen = function() { stopPolling(); setConnStatus("live"); console.log("[WS] connected"); };
    ws.onmessage = function(ev) { try { apply(JSON.parse(ev.data)); } catch(e) { console.warn("WS parse error", e); } };
    ws.onerror = function(e) { if (authBlocked) return; setConnStatus("polling"); startPolling(); console.warn("[WS] error", e); };
    ws.onclose = function() { if (authBlocked) return; setConnStatus("polling"); console.log("[WS] closed, fallback to polling"); startPolling(); setTimeout(connect, 4000); };
  };
  setConnStatus("connecting");
  connect();
})();
