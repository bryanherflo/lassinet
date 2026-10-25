"""Enrich what ARP found: a real name, open ports, a better device kind.

An ARP sweep only returns IP + MAC, which is why every node used to look like a
generic workstation. For each device, and only once per TTL, this module adds:

  * **a hostname** — reverse DNS (PTR) through the OS resolver, bounded by a
    deadline so a broken resolver cannot stall the engine;
  * **a light port fingerprint** — a TCP connect to twelve curated ports that
    identify common consumer devices (631/9100 printer, 554/8554 camera,
    62078 iPhone sync, 8009 Chromecast, 5000/5001 Synology, 445/3389 Windows…);
  * **one mDNS (Bonjour) query** — answers carry the owner's name
    ("Ana's iPhone._apple-mobdev2._tcp"), which is the only way to name a phone;
  * **one SSDP/UPnP M-SEARCH** — the SERVER header names the family of smart
    TVs, consoles, speakers, NAS boxes and Windows PCs;
  * **the kind** — `lassi.devices.classify(name, mac, role, ports, hint)`.

Everything is cached by MAC in `data/device_cache.json`, so the steady state is
just the ARP sweep: a device is asked once and remembered for 12 h (5 minutes
when the answer was empty, so a sleeping phone is retried soon).

Scope and manners matter here: this only runs in live mode, only for the subnet
the sensor just swept, and only for hosts it discovered. Two multicast packets
per sweep, no UDP sweep, no banner grabbing. `LASSI_ENRICH=0` disables all of
it, `LASSI_PROBE=0` keeps the names while skipping the TCP ports,
`LASSI_MDNS=0` and `LASSI_SSDP=0` skip the multicast questions.
"""

import ipaddress
import json
import logging
import os
import re
import select
import socket
import struct
import threading
import time
from pathlib import Path
from typing import Any

from lassi.devices import classify, is_private_mac, vendor_for

log = logging.getLogger("lassi.discovery")

# Curated: every port here maps to a device kind on its own (see PORT_HINTS).
PROBE_PORTS = (22, 80, 443, 445, 554, 631, 3389, 5000, 5001, 62078, 8009, 8554, 9100)

CACHE_PATH = Path(os.environ.get("LASSI_DEVICE_CACHE", "data/device_cache.json"))
DEFAULT_TTL = 12 * 3600.0          # 12 h: a device is re-asked twice a day
RETRY_TTL = 5 * 60.0               # an uninformative answer is retried in 5 min
_PROBE_TIMEOUT = 0.35
_NAME_TIMEOUT = 1.2

_cache_lock = threading.Lock()

_GENERIC_NAMES = {"localhost", "unknown", "none", "null", "localhost.localdomain"}


def enabled() -> bool:
    return (os.getenv("LASSI_ENRICH", "1").strip().lower()
            not in ("0", "false", "no", "off"))


def ports_enabled() -> bool:
    return (os.getenv("LASSI_PROBE", "1").strip().lower()
            not in ("0", "false", "no", "off"))


def _ttl() -> float:
    try:
        value = float(os.getenv("LASSI_ENRICH_TTL", str(DEFAULT_TTL)))
        return value if value > 0 else DEFAULT_TTL
    except ValueError:
        return DEFAULT_TTL


# ---- cache ------------------------------------------------------------------
def _load_cache() -> dict[str, dict[str, Any]]:
    try:
        if CACHE_PATH.exists():
            raw = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                return {str(k): v for k, v in raw.items() if isinstance(v, dict)}
    except Exception:
        log.warning("device cache is unreadable; starting empty", exc_info=True)
    return {}


def _save_cache(cache: dict[str, dict[str, Any]]) -> None:
    try:
        CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        CACHE_PATH.write_text(json.dumps(cache, indent=1, sort_keys=True), encoding="utf-8")
    except Exception:
        log.warning("could not write the device cache", exc_info=True)


def _cache_key(host: dict[str, Any]) -> str:
    mac = str(host.get("mac") or "").strip().lower()
    return f"mac:{mac}" if mac else f"ip:{host.get('ip', '')}"


# ---- names ------------------------------------------------------------------
def clean_name(raw: Any, ip: str = "") -> str:
    """First DNS label, stripped of anything that is not a device name."""
    text = str(raw or "").strip().rstrip(".")
    if not text:
        return ""
    try:
        ipaddress.ip_address(text)
        return ""                      # a PTR that answers with the IP itself
    except ValueError:
        pass
    name = text.split(".")[0]
    name = re.sub(r"[^A-Za-z0-9 _-]", "", name).strip()[:32]
    if not name or name.isdigit() or name.lower() in _GENERIC_NAMES:
        return ""
    if ip and name.lower() == str(ip).strip().lower():
        return ""
    return name


def _reverse_one(ip: str, out: dict[str, str]) -> None:
    try:
        out[ip] = socket.gethostbyaddr(ip)[0]
    except Exception:
        pass


def reverse_names(ips: list[str], timeout: float = _NAME_TIMEOUT) -> dict[str, str]:
    """PTR lookups in parallel with one deadline; empty dict on a dead resolver."""
    out: dict[str, str] = {}
    threads = []
    for ip in ips:
        thread = threading.Thread(target=_reverse_one, args=(ip, out), daemon=True)
        thread.start()
        threads.append(thread)
    deadline = time.time() + timeout
    for thread in threads:
        thread.join(max(0.0, deadline - time.time()))
    names = {ip: clean_name(name, ip) for ip, name in out.items()}
    return {ip: name for ip, name in names.items() if name}


# ---- ports ------------------------------------------------------------------
def _probe(ip: str, port: int, out: list[int]) -> None:
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(_PROBE_TIMEOUT)
            if sock.connect_ex((ip, port)) == 0:
                out.append(port)
    except OSError:
        pass


def scan_ports(ip: str, ports: tuple[int, ...] = PROBE_PORTS) -> list[int]:
    """Open ports from a curated list. One SYN per port, 350 ms allowance."""
    found: list[int] = []
    threads = []
    for port in ports:
        thread = threading.Thread(target=_probe, args=(ip, port, found), daemon=True)
        thread.start()
        threads.append(thread)
    deadline = time.time() + _PROBE_TIMEOUT + 0.15
    for thread in threads:
        thread.join(max(0.0, deadline - time.time()))
    return sorted(set(found))


# ---- mDNS (Bonjour / DNS-SD) -------------------------------------------------
# One packet with a few PTR questions for the service types that name their
# owner ("Ana's iPhone._apple-mobdev2._tcp"). The QU bit (unicast response) is
# set, so answers come back to our ephemeral port and we never have to bind
# 5353 (which the OS mDNS responder already owns on Windows).
MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353
MDNS_SERVICES = (
    "_apple-mobdev2._tcp.local",     # iPhone / iPad sync
    "_airplay._tcp.local",           # Apple TV, HomePod, AirPlay TVs
    "_raop._tcp.local",              # AirPlay audio (speakers)
    "_googlecast._tcp.local",        # Chromecast / Google TV
    "_ipp._tcp.local",               # printers
    "_sonos._tcp.local",             # Sonos
    "_homekit._tcp.local",           # HomeKit accessories
    "_workstation._tcp.local",       # desktops / servers
    "_companion-link._tcp.local",    # Apple devices
)

# Service -> kind. Only services whose *owner* is a single kind of device.
_MDNS_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("phone", ("_apple-mobdev2",)),
    ("speaker", ("_raop", "_sonos", "_spotify-connect")),
    ("tv", ("_googlecast", "_airplay")),
    ("printer", ("_ipp", "_ipps", "_printer")),
    ("camera", ("_rtsp", "_axis-video")),
    ("iot", ("_homekit", "_hap", "_matter", "_shelly", "_esphomelib")),
    ("desktop", ("_workstation", "_smb", "_rfb")),
)


def mdns_enabled() -> bool:
    return (os.getenv("LASSI_MDNS", "1").strip().lower()
            not in ("0", "false", "no", "off"))


def _dns_question(service: str, unicast: bool = True) -> bytes:
    out = b""
    for label in service.strip(".").split("."):
        if not label:
            continue
        out += bytes([len(label)]) + label.encode("ascii", "replace")
    qclass = 0x8001 if unicast else 1          # IN + QU bit
    return out + b"\x00" + struct.pack("!HH", 12, qclass)


def _mdns_query(services: tuple[str, ...]) -> bytes:
    header = struct.pack("!HHHHHH", 0, 0, len(services), 0, 0, 0)
    return header + b"".join(_dns_question(service) for service in services)


def _read_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decode a (possibly compressed) DNS name; returns (name, next offset)."""
    labels: list[str] = []
    jumped = False
    next_offset = offset
    seen: set[int] = set()
    while 0 <= offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            if not jumped:
                next_offset = offset
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if pointer in seen:
                break
            seen.add(pointer)
            if not jumped:
                next_offset = offset + 2
                jumped = True
            offset = pointer
            continue
        label = data[offset + 1:offset + 1 + length].decode("utf-8", "replace")
        labels.append(label)
        offset += 1 + length
        if not jumped:
            next_offset = offset
    return ".".join(labels), next_offset


def _kind_from_service(name: str) -> str:
    low = name.lower()
    for kind, needles in _MDNS_RULES:
        if any(needle in low for needle in needles):
            return kind
    return ""


def parse_mdns(answers: list[tuple[bytes, str]]) -> dict[str, dict[str, str]]:
    """Extract {ip: {"name": ..., "kind": ...}} from mDNS response packets."""
    found: dict[str, dict[str, str]] = {}
    for data, ip in answers:
        if len(data) < 12:
            continue
        try:
            _id, flags, qdcount, ancount = struct.unpack("!HHHH", data[:8])
        except struct.error:
            continue
        if not flags & 0x8000:            # queries are noise, answers matter
            continue
        offset = 12
        for _ in range(qdcount):
            _name, offset = _read_name(data, offset)
            offset += 4
        for _ in range(ancount):
            name, offset = _read_name(data, offset)
            if offset + 10 > len(data):
                break
            try:
                rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[offset:offset + 10])
            except struct.error:
                break
            rd_start = offset + 10
            offset = rd_start + rdlen
            if offset > len(data):
                break
            target = ""
            if rtype == 12:               # PTR: service -> instance
                target, _ = _read_name(data, rd_start)
            elif rtype == 33 and rdlen >= 7:   # SRV: priority/weight/port + host
                target, _ = _read_name(data, rd_start + 6)
            elif rtype == 1 and rdlen == 4:    # A: owner name is the host name
                if ".".join(str(b) for b in data[rd_start:rd_start + 4]) == ip:
                    target = name
            if not target:
                continue
            kind = _kind_from_service(name) or _kind_from_service(target)
            instance = ""
            if target.startswith("_") or "._" not in target:
                instance = ""
            else:
                instance = target.split("._", 1)[0]
            entry = found.setdefault(str(ip), {})
            if instance:
                clean = clean_name(instance, ip)
                if clean and not entry.get("name"):
                    entry["name"] = clean
            if kind and not entry.get("kind"):
                entry["kind"] = kind
    return found


def mdns_scan(timeout: float = 2.0, local_ip: str | None = None) -> dict[str, dict[str, str]]:
    """Ask mDNS who is there; {ip: {"name", "kind"}} for the devices that answer."""
    sock = _udp_socket(local_ip)
    try:
        answers = _collect(sock, _mdns_query(MDNS_SERVICES), (MDNS_ADDR, MDNS_PORT), timeout)
    finally:
        sock.close()
    return parse_mdns(answers)


def _udp_socket(local_ip: str | None) -> socket.socket:
    """Multicast socket pinned to the LAN interface.

    Without the bind/IP_MULTICAST_IF, Windows routes 224.0.0.0/4 through
    whichever adapter has the best metric — on this laptop that was the
    VirtualBox host-only NIC, and every query went nowhere (measured).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((local_ip or "", 0))
    except OSError:
        pass
    if local_ip:
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                            socket.inet_aton(local_ip))
        except OSError:
            pass
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    except OSError:
        pass
    sock.settimeout(0.25)
    return sock


def _collect(sock: socket.socket, payload: bytes, target: tuple[str, int],
             timeout: float) -> list[tuple[bytes, str]]:
    answers: list[tuple[bytes, str]] = []
    sock.sendto(payload, target)
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            data, addr = sock.recvfrom(65507)
        except socket.timeout:
            continue
        except OSError:
            break
        answers.append((data, str(addr[0])))
    return answers


# ---- SSDP / UPnP ------------------------------------------------------------
# One M-SEARCH for the whole sweep. Smart TVs, consoles, speakers, NAS boxes
# and Windows PCs answer with a SERVER header that names their family — much
# better than guessing from a MAC. Responses are unicast back to our port.
SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900
_SSDP_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 1\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
).encode("ascii")

_SSDP_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("camera", ("doorbell", "ipcam", "ip camera", "hikvision", "dahua", "reolink")),
    ("printer", ("printer", "laserjet", "officejet", "epson")),
    ("nas", ("synology", "diskstation", "qnap", "truenas", "readynas", "twonky")),
    ("console", ("playstation", "xbox")),
    ("speaker", ("sonos", "homepod", "bose", "denon", "heos", "soundbar", "speaker")),
    ("tv", ("roku", "chromecast", "google cast", "bravia", "webos", "tizen",
            "samsung", "hisense", "vizio", "smarttv", "smart tv")),
    ("desktop", ("microsoft-windows", "windows nt")),
    ("iot", ("sonoff", "shelly", "tasmota", "tuya")),
)


def ssdp_enabled() -> bool:
    return (os.getenv("LASSI_SSDP", "1").strip().lower()
            not in ("0", "false", "no", "off"))


def kind_from_ssdp(text: str) -> str:
    low = str(text or "").lower()
    for kind, needles in _SSDP_RULES:
        if any(needle in low for needle in needles):
            return kind
    return ""


def parse_ssdp(answers: list[tuple[bytes, str]]) -> dict[str, str]:
    """{ip: kind} from SSDP answers (first recognised answer per device wins)."""
    hints: dict[str, str] = {}
    for payload, ip in answers:
        ip = str(ip)
        if ip in hints:
            continue
        kind = kind_from_ssdp(payload.decode("utf-8", "replace"))
        if kind:
            hints[ip] = kind
    return hints


def ssdp_scan(timeout: float = 2.0, local_ip: str | None = None) -> dict[str, str]:
    """One M-SEARCH; return {ip: kind} for the devices that answered."""
    sock = _udp_socket(local_ip)
    try:
        answers = _collect(sock, _SSDP_MSEARCH, (SSDP_ADDR, SSDP_PORT), timeout)
    finally:
        sock.close()
    return parse_ssdp(answers)


def multicast_hints(local_ip: str | None = None, timeout: float = 2.0) -> dict[str, dict[str, str]]:
    """Run mDNS and SSDP together (one select loop) and merge what they learn."""
    want_mdns = mdns_enabled()
    want_ssdp = ssdp_enabled()
    if not (want_mdns or want_ssdp):
        return {}
    sockets: dict[socket.socket, str] = {}
    answers: dict[str, list[tuple[bytes, str]]] = {"mdns": [], "ssdp": []}
    try:
        if want_mdns:
            sock = _udp_socket(local_ip)
            sock.sendto(_mdns_query(MDNS_SERVICES), (MDNS_ADDR, MDNS_PORT))
            sockets[sock] = "mdns"
        if want_ssdp:
            sock = _udp_socket(local_ip)
            sock.sendto(_SSDP_MSEARCH, (SSDP_ADDR, SSDP_PORT))
            sockets[sock] = "ssdp"
        deadline = time.time() + timeout
        while sockets and time.time() < deadline:
            ready, _, _ = select.select(list(sockets), [], [], 0.25)
            for sock in ready:
                try:
                    data, addr = sock.recvfrom(65507)
                except OSError:
                    sockets.pop(sock, None)
                    continue
                answers[sockets[sock]].append((data, str(addr[0])))
    finally:
        for sock in sockets:
            sock.close()
    hints = parse_mdns(answers["mdns"])
    for ip, kind in parse_ssdp(answers["ssdp"]).items():
        hints.setdefault(ip, {}).setdefault("kind", kind)
    return hints


# ---- public API -------------------------------------------------------------
def enrich(hosts: list[dict[str, Any]], *, skip_ports: Any = (),
           ttl: float | None = None, now: float | None = None,
           local_ip: str | None = None) -> list[dict[str, Any]]:
    """Return the same hosts with `hostname`, `open_ports` and `kind` filled in.

    Devices seen before are answered from the cache (no packets at all); only
    new or stale ones are asked for a name, probed and matched against one mDNS
    query and one SSDP sweep. `skip_ports` lists addresses that must not be
    port-probed (typically the LAN gateway); `local_ip` pins the multicast
    sockets to the right interface.
    """
    if not hosts:
        return []
    if not enabled():
        return [_with_kind(host) for host in hosts]
    ttl = _ttl() if ttl is None else ttl
    now = time.time() if now is None else now
    skip = {str(ip) for ip in skip_ports}

    with _cache_lock:
        cache = _load_cache()
    stale = []
    for host in hosts:
        entry = cache.get(_cache_key(host))
        age = now - float(entry.get("at", 0)) if entry else None
        # A device that answered with nothing (asleep, or blocked by the AP)
        # is asked again soon instead of being "unknown" for twelve hours.
        useful = bool(entry and (entry.get("name") or entry.get("ports") or entry.get("hint")))
        limit = ttl if useful else min(ttl, RETRY_TTL)
        if age is None or age > limit:
            stale.append(host)

    names: dict[str, str] = {}
    hints: dict[str, dict[str, str]] = {}
    if stale:
        names = reverse_names([host["ip"] for host in stale if host.get("ip")])
        try:
            hints = multicast_hints(local_ip)
        except Exception:
            log.debug("mDNS/SSDP discovery failed", exc_info=True)

    enriched: list[dict[str, Any]] = []
    for host in hosts:
        key = _cache_key(host)
        entry = cache.get(key) or {}
        age = (now - float(entry["at"])) if entry.get("at") else None
        useful = bool(entry.get("name") or entry.get("ports") or entry.get("hint"))
        limit = ttl if useful else min(ttl, RETRY_TTL)
        fresh = age is not None and age <= limit
        ip = host.get("ip", "")
        if fresh:
            name = str(entry.get("name") or "")
            ports = list(entry.get("ports") or [])
            hint = str(entry.get("hint") or "")
        else:
            local = hints.get(ip, {})
            # A failed re-check must not erase what we knew: keep the previous
            # name/fingerprint when this round found nothing (sleeping device,
            # transient DNS). New evidence still wins.
            name = (names.get(ip, "") or local.get("name", "")
                    or str(entry.get("name") or ""))
            scanned = (scan_ports(ip) if ip and ip not in skip
                       and ports_enabled() else [])
            ports = scanned or list(entry.get("ports") or [])
            hint = (local.get("kind", "") or str(entry.get("hint") or ""))
            cache[key] = {"name": name, "ports": ports, "hint": hint, "at": now}
        item = dict(host)
        if name:
            item["hostname"] = name
        item["open_ports"] = ports
        enriched.append(_with_kind(item, hint))

    if stale:
        with _cache_lock:
            _save_cache(cache)
    return enriched


def _with_kind(host: dict[str, Any], hint: str = "") -> dict[str, Any]:
    """Classify from everything we now know (name, ports, MAC vendor, UPnP)."""
    kind = classify(hostname=str(host.get("hostname") or ""),
                    mac=host.get("mac"),
                    role=host.get("role"),
                    ports=host.get("open_ports"),
                    hint=hint)
    if kind:
        host["kind"] = kind
    # Context for the tooltip: who made the box (when the OUI says so) and
    # whether the MAC is software-assigned (phones' private address), which is
    # exactly why "?" devices cannot always be identified.
    host["mac_vendor"] = vendor_for(host.get("mac"))
    host["private_mac"] = is_private_mac(host.get("mac"))
    return host


def is_private_ip(value: Any) -> bool:
    try:
        return ipaddress.ip_address(str(value)).is_private
    except ValueError:
        return False
