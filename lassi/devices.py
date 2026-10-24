"""Best-effort device-type classification, for the map icon only.

Three offline signals are used: the device name (operator rename or the name
discovery found), the MAC vendor prefix (OUI) and, in live mode, the open ports
the light fingerprint found. This is a *display* hint — never a security
decision: blocking, trust and protection are decided by `lassi.state` from
roles and explicit marks.

When the evidence is ambiguous the answer is `""` (unknown) on purpose: a wrong
icon is worse than no icon. Apple OUIs, for instance, cannot tell an iPhone
from a MacBook, and a randomized MAC carries no vendor at all.
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

# MAC vendor prefixes that identify the *kind* of device unambiguously. Vendors
# that make several kinds (Apple, Samsung, Sony, TP-Link…) are deliberately not
# here: guessing "phone" from an Apple OUI would be wrong half the time.
_OUI: dict[str, str] = {
    # Raspberry Pi -> single-board computer
    "b8:27:eb": "sbc", "dc:a6:32": "sbc", "e4:5f:01": "sbc", "2c:cf:67": "sbc",
    # Espressif (ESP32/ESP8266) -> IoT
    "24:0a:c4": "iot", "24:6f:28": "iot", "30:ae:a4": "iot", "84:f3:eb": "iot",
    "a4:cf:12": "iot", "ac:67:b2": "iot", "dc:4f:22": "iot", "ec:fa:bc": "iot",
    # Sonos -> speaker
    "78:28:ca": "speaker", "5c:aa:fd": "speaker", "b8:e9:37": "speaker",
    # Roku -> TV/media player
    "b0:a7:37": "tv", "cc:6d:a0": "tv", "d8:31:34": "tv", "ac:3a:7a": "tv",
    # Hikvision / Dahua -> IP camera
    "44:19:b6": "camera", "bc:ad:28": "camera", "c0:56:e3": "camera",
    "3c:ef:8c": "camera", "4c:11:bf": "camera", "90:02:a9": "camera",
    # Synology / QNAP -> NAS
    "00:11:32": "nas", "00:08:9b": "nas",
    # Nintendo -> console
    "98:b6:e9": "console", "58:bd:a3": "console",
    # Philips Hue -> IoT
    "00:17:88": "iot",
    # More Espressif chips -> IoT
    "8c:aa:b5": "iot", "c4:4f:33": "iot", "48:3f:da": "iot",
    "60:01:94": "iot", "84:0d:8e": "iot", "a0:20:a6": "iot",
    # Ring doorbells and Wyze cameras -> camera
    "0c:47:c9": "camera", "54:e0:19": "camera",
    "2c:aa:8e": "camera", "7c:78:b2": "camera",
    # Nest thermostats, LIFX bulbs -> IoT
    "18:b4:30": "iot", "64:16:66": "iot", "d0:73:d5": "iot",
}

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


def _from_mac(mac: str | None) -> str:
    """Vendor -> kind, unless the MAC is locally administered (randomized)."""
    text = str(mac or "").strip().lower().replace("-", ":")
    if not re.match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", text):
        return ""
    try:
        first = int(text.split(":", 1)[0], 16)
    except ValueError:
        return ""
    if first & 0x02:                  # locally administered: no vendor at all
        return ""
    return _OUI.get(text[:8], "")


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
    `ports` the result of the light fingerprint and `hint` what SSDP/UPnP said
    about the device. The name wins (it is the operator's word), then the ports
    (what the device *does*), then the MAC vendor (what it is), then the UPnP
    hint, and the role is the last resort.
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
    kind = _from_mac(mac)
    if kind:
        return kind
    hint = (hint or "").strip().lower()
    if hint in KINDS:
        return hint
    return _ROLE_FALLBACK.get(role, "")
