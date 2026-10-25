"""Best-effort device-type classification, for the map icon only.

Two offline signals are used: the device name (operator rename or the name
discovery found) and, in live mode, the open ports the light fingerprint found
— plus the mDNS/SSDP hint when a device announces itself. The MAC vendor is
**not** used to pick a type (D-Link builds routers, cameras and switches; a
phone's random MAC has no vendor); it is only shown as context. This is a
*display* hint — never a security decision: blocking, trust and protection are
decided by `lassi.state` from roles and explicit marks.

When the evidence is ambiguous the answer is `""` (unknown) on purpose: a wrong
icon is worse than no icon.
"""

import re
from typing import Any

KINDS = (
    "phone", "tablet", "laptop", "desktop", "server",
    "tv", "console", "printer", "camera", "speaker",
    "watch", "nas", "sbc", "iot",
)

# Name patterns, checked in order: the first match wins. Specific names come
# first so "galaxy-tab" is a tablet and not a phone, and "smart-tv" is a TV.
_NAME_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("tablet", ("ipad", "galaxy-tab", "galaxytab", "mediapad", "tablet", "tab-", "-tab")),
    ("phone", ("iphone", "android", "galaxy", "pixel", "redmi", "xiaomi", "oneplus",
               "huawei", "honor", "oppo", "realme", "smartphone", "movil", "celular")),
    ("laptop", ("macbook", "laptop", "notebook", "thinkpad", "ideapad", "ultrabook",
                "chromebook", "surface", "xps", "latitude", "elitebook")),
    ("desktop", ("desktop", "imac", "mac-pro", "optiplex", "precision", "workstation",
                 "-pc", "pc-")),
    ("tv", ("smart-tv", "smarttv", "roku", "firetv", "fire-tv", "chromecast",
            "appletv", "apple-tv", "bravia", "shield", "-tv", "tv-")),
    ("console", ("playstation", "ps4", "ps5", "xbox", "nintendo", "switch")),
    ("printer", ("printer", "laserjet", "officejet", "deskjet", "mfp", "epson",
                 "brother", "canon", "xerox", "print-", "-print")),
    ("camera", ("camera", "ipcam", "webcam", "hikvision", "dahua", "reolink",
                "wyze", "cam-", "-cam")),
    ("speaker", ("homepod", "sonos", "speaker", "echo", "alexa", "nest-audio", "jbl")),
    ("watch", ("watch", "garmin")),
    ("nas", ("synology", "diskstation", "qnap", "truenas", "freenas",
             "openmediavault", "nas")),
    ("sbc", ("raspberrypi", "raspberry", "orangepi", "bananapi", "rockpi", "rpi")),
    ("iot", ("esp32", "esp8266", "esp-", "tasmota", "shelly", "sonoff", "tuya",
             "smart-plug", "bulb", "thermostat", "hue", "plug")),
    ("router", ("router", "fritz", "openwrt", "unifi", "deco", "eero", "orbi", "gateway")),
)


# Vendor names for OUIs we are sure about. This is *context* for the tooltip,
# never a device kind: D-Link builds routers, cameras and switches, so knowing
# the vendor must not change classify().
_VENDORS: dict[str, str] = {
    "00:ad:24": "D-Link", "48:29:52": "Sagemcom",
    # Tuya Smart (smart-home OEM)
    "fc:3c:d7": "Tuya Smart", "4c:a9:19": "Tuya Smart", "a8:80:55": "Tuya Smart",
    "a8:dd:bc": "Tuya Smart", "fc:67:1f": "Tuya Smart", "50:8a:06": "Tuya Smart",
    "50:8b:b9": "Tuya Smart", "68:57:2d": "Tuya Smart", "70:89:76": "Tuya Smart",
    # Raspberry Pi, Sonos, Roku, Synology, QNAP, Nintendo, Philips Hue, Espressif
    "b8:27:eb": "Raspberry Pi", "dc:a6:32": "Raspberry Pi", "e4:5f:01": "Raspberry Pi",
    "2c:cf:67": "Raspberry Pi",
    "78:28:ca": "Sonos", "5c:aa:fd": "Sonos", "b8:e9:37": "Sonos",
    "b0:a7:37": "Roku",
    "00:11:32": "Synology", "00:08:9b": "QNAP",
    "98:b6:e9": "Nintendo", "58:bd:a3": "Nintendo",
    "00:17:88": "Philips Hue",
    "24:0a:c4": "Espressif", "24:6f:28": "Espressif", "30:ae:a4": "Espressif",
    "84:f3:eb": "Espressif", "a4:cf:12": "Espressif", "ac:67:b2": "Espressif",
    "dc:4f:22": "Espressif", "ec:fa:bc": "Espressif", "8c:aa:b5": "Espressif",
    "c4:4f:33": "Espressif", "48:3f:da": "Espressif", "60:01:94": "Espressif",
    "84:0d:8e": "Espressif", "a0:20:a6": "Espressif",
    # Cameras where the OUI is unambiguous
    "44:19:b6": "Hikvision", "3c:ef:8c": "Dahua",
}


def is_private_mac(mac: str | None) -> bool:
    """True for a locally administered MAC (a phone's private Wi-Fi address).

    The second-least-significant bit of the first octet marks an address that
    software assigned, not the vendor: the OUI then says nothing, so the device
    cannot be identified from its MAC at all.
    """
    text = str(mac or "").strip().lower().replace("-", ":")
    if not re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", text):
        return False
    try:
        first = int(text.split(":", 1)[0], 16)
    except ValueError:
        return False
    return bool(first & 0x02) and not bool(first & 0x01)


def vendor_for(mac: str | None) -> str:
    """Company that registered the OUI, when known. Context, never a guess."""
    text = str(mac or "").strip().lower().replace("-", ":")
    if not re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", text):
        return ""
    if is_private_mac(text):
        return ""                      # a randomized MAC has no vendor
    return _VENDORS.get(text[:8], "")

# Open ports that identify the *role* of a device on the network. A printer
# that answers on 9100 (raw print) or 631 (IPP) is a printer whatever the MAC
# vendor says; HP and Epson build laptops too, so vendor prefixes are not used
# for printers.
_PORT_HINTS: tuple[tuple[str, frozenset[int]], ...] = (
    ("printer", frozenset({631, 9100})),
    ("camera", frozenset({554, 8554})),
    ("phone", frozenset({62078})),          # iPhone/iPad sync (lockdownd)
    ("tv", frozenset({8009})),              # Chromecast / Google Cast
    ("nas", frozenset({5000, 5001})),       # Synology DSM
)

_ROLE_FALLBACK = {"printer": "printer", "iot": "iot", "server": "server"}

_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _normalise(name: str) -> str:
    """Lowercase and separators to '-', so token patterns match reliably."""
    return re.sub(r"[\s_.]+", "-", str(name or "").strip().lower())


def _from_name(name: str) -> str:
    for kind, patterns in _NAME_RULES:
        if any(pattern in name for pattern in patterns):
            return kind
    return ""


def _from_ports(ports: Any) -> str:
    try:
        open_ports = {int(port) for port in (ports or ())}
    except (TypeError, ValueError):
        return ""
    for kind, needles in _PORT_HINTS:
        if open_ports & needles:
            return kind
    return ""


def classify(hostname: str = "", mac: str | None = None, role: str | None = None,
             ports: Any = None, hint: str = "") -> str:
    """Return one of KINDS (plus "router"/"external"), or "" when unsure.

    `role` is the network role already known (`router`, `server`, `printer`…),
    `ports` the result of the light fingerprint and `hint` what mDNS/SSDP said
    about the device. The name wins (it is the operator's word), then the ports
    (what the device *does*), then the multicast hint, and the role is the last
    resort.

    The MAC vendor is accepted for call-site compatibility but deliberately
    **not** used: D-Link makes routers, cameras and switches, and a phone's
    randomized MAC has no vendor at all, so an OUI cannot pick a type without
    guessing. `vendor_for()` exposes the company for the tooltip as context.
    """
    role = (role or "").strip().lower()
    if role == "router":
        return "router"
    if role == "external":
        return "external"
    name = _normalise(hostname)
    if name and not _IPV4.match(name):
        kind = _from_name(name)
        if kind:
            return kind
    kind = _from_ports(ports)
    if kind:
        return kind
    hint = (hint or "").strip().lower()
    if hint in KINDS:
        return hint
    return _ROLE_FALLBACK.get(role, "")
