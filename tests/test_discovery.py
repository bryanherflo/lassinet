"""Device enrichment (names, ports, cache). No network traffic in these tests."""

import struct

import pytest

import lassi.discovery as discovery


@pytest.fixture(autouse=True)
def _isolated_cache(tmp_path, monkeypatch):
    """Own cache file per test and enrichment explicitly enabled.

    The suite as a whole runs with LASSI_ENRICH=0 (see conftest) so no test can
    poke the real LAN; here every probe is stubbed anyway.
    """
    monkeypatch.setattr(discovery, "CACHE_PATH", tmp_path / "device_cache.json")
    monkeypatch.setenv("LASSI_ENRICH", "1")
    monkeypatch.setenv("LASSI_SSDP", "0")          # opt-in per test, no multicast
    monkeypatch.setenv("LASSI_MDNS", "0")
    monkeypatch.delenv("LASSI_PROBE", raising=False)
    return tmp_path / "device_cache.json"


def test_clean_name_keeps_the_first_label_only() -> None:
    assert discovery.clean_name("iPhone-de-Ana.lan", "192.168.0.5") == "iPhone-de-Ana"
    assert discovery.clean_name("desktop-01.", "192.168.0.9") == "desktop-01"
    assert discovery.clean_name("bad$name!", "192.168.0.9") == "badname"
    assert discovery.clean_name("192.168.0.9", "192.168.0.9") == ""
    assert discovery.clean_name("localhost", "192.168.0.9") == ""
    assert discovery.clean_name("", "192.168.0.9") == ""


def test_enrich_fills_name_ports_and_kind(monkeypatch) -> None:
    monkeypatch.setattr(discovery, "reverse_names",
                        lambda ips, timeout=1.2: {"10.0.0.5": "iPhone-Ana"})
    monkeypatch.setattr(discovery, "scan_ports",
                        lambda ip, ports=discovery.PROBE_PORTS: [62078] if ip == "10.0.0.5" else [])
    hosts = [{"ip": "10.0.0.5", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "10.0.0.5",
              "role": "workstation", "open_ports": []}]
    out = discovery.enrich(hosts)
    assert out[0]["hostname"] == "iPhone-Ana"
    assert out[0]["open_ports"] == [62078]
    assert out[0]["kind"] == "phone"


def test_second_call_comes_from_the_cache(monkeypatch, _isolated_cache) -> None:
    calls = []

    def fake_dns(ips, timeout=1.2):
        calls.append("dns")
        return {"10.0.0.6": "sonos-salon"}

    def fake_scan(ip, ports=discovery.PROBE_PORTS):
        calls.append("scan")
        return []

    monkeypatch.setattr(discovery, "reverse_names", fake_dns)
    monkeypatch.setattr(discovery, "scan_ports", fake_scan)
    hosts = [{"ip": "10.0.0.6", "mac": "78:28:ca:aa:bb:cc", "hostname": "10.0.0.6",
              "role": "workstation", "open_ports": []}]
    discovery.enrich(hosts)
    assert sorted(calls) == ["dns", "scan"]
    assert _isolated_cache.exists()

    out = discovery.enrich(hosts)                 # same MAC, fresh cache
    assert out[0]["hostname"] == "sonos-salon"
    assert out[0]["kind"] == "speaker"
    assert sorted(calls) == ["dns", "scan"]       # nothing new was sent


def test_a_failed_recheck_keeps_the_previous_name_and_ports(monkeypatch) -> None:
    monkeypatch.setattr(discovery, "reverse_names", lambda ips, timeout=1.2: {"10.0.0.7": "cam-hall"})
    monkeypatch.setattr(discovery, "scan_ports", lambda ip, ports=discovery.PROBE_PORTS: [554])
    hosts = [{"ip": "10.0.0.7", "mac": "44:19:b6:aa:bb:cc", "hostname": "10.0.0.7",
              "role": "workstation", "open_ports": []}]
    discovery.enrich(hosts, now=1_000_000, ttl=10)
    # The device went to sleep: DNS fails and no port answers.
    monkeypatch.setattr(discovery, "reverse_names", lambda ips, timeout=1.2: {})
    monkeypatch.setattr(discovery, "scan_ports", lambda ip, ports=discovery.PROBE_PORTS: [])
    out = discovery.enrich(hosts, now=1_000_100, ttl=10)
    assert out[0]["hostname"] == "cam-hall"
    assert out[0]["open_ports"] == [554]
    assert out[0]["kind"] == "camera"


def test_the_gateway_is_named_but_never_probed(monkeypatch) -> None:
    probed = []
    monkeypatch.setattr(discovery, "reverse_names", lambda ips, timeout=1.2: {})
    monkeypatch.setattr(discovery, "scan_ports",
                        lambda ip, ports=discovery.PROBE_PORTS: probed.append(ip) or [])
    hosts = [{"ip": "10.0.0.1", "mac": "aa:aa:aa:aa:aa:aa", "hostname": "10.0.0.1",
              "role": "router", "open_ports": []}]
    out = discovery.enrich(hosts, skip_ports={"10.0.0.1"})
    assert probed == []
    assert out[0]["open_ports"] == []
    assert out[0]["kind"] == "router"


def test_enrichment_disabled_sends_nothing(monkeypatch) -> None:
    monkeypatch.setenv("LASSI_ENRICH", "0")

    def boom(*args, **kwargs):
        raise AssertionError("no network when enrichment is disabled")

    monkeypatch.setattr(discovery, "reverse_names", boom)
    monkeypatch.setattr(discovery, "scan_ports", boom)
    hosts = [{"ip": "10.0.0.8", "mac": "78:28:ca:aa:bb:cc", "hostname": "10.0.0.8",
              "role": "workstation", "open_ports": []}]
    out = discovery.enrich(hosts)
    assert out[0]["hostname"] == "10.0.0.8"
    assert out[0].get("kind", "") == ""           # no MAC-vendor guessing
    assert out[0]["mac_vendor"] == "Sonos"        # vendor stays as context only


def test_probe_can_be_disabled_while_names_are_kept(monkeypatch) -> None:
    monkeypatch.setenv("LASSI_PROBE", "0")
    monkeypatch.setattr(discovery, "reverse_names",
                        lambda ips, timeout=1.2: {"10.0.0.9": "printer-hall"})

    def boom(*args, **kwargs):
        raise AssertionError("no port probe expected")

    monkeypatch.setattr(discovery, "scan_ports", boom)
    hosts = [{"ip": "10.0.0.9", "mac": None, "hostname": "10.0.0.9",
              "role": "workstation", "open_ports": []}]
    out = discovery.enrich(hosts)
    assert out[0]["hostname"] == "printer-hall"
    assert out[0]["kind"] == "printer"


@pytest.mark.parametrize("header,expected", [
    ("SERVER: Roku/9.4 UPnP/1.1", "tv"),
    ("SERVER: Sonos/70.0 UPnP/1.1", "speaker"),
    ("SERVER: Microsoft-Windows/10.0 UPnP/1.1", "desktop"),
    ("ST: urn:schemas-upnp-org:device:Printer:1", "printer"),
    ("SERVER: Synology/DSM UPnP/1.0", "nas"),
    ("SERVER: PlayStation 5", "console"),
    ("SERVER: Linux/4.9 UPnP/1.0", ""),
])
def test_ssdp_server_header_names_the_family(header: str, expected: str) -> None:
    assert discovery.kind_from_ssdp(header) == expected


class _FakeSocket:
    def __init__(self, replies):
        self.replies = list(replies)
        self.sent = []
        self.bound = None

    def setsockopt(self, *args):
        pass

    def bind(self, addr):
        self.bound = addr

    def settimeout(self, *args):
        pass

    def sendto(self, data, addr):
        self.sent.append((data, addr))

    def recvfrom(self, size):
        if not self.replies:
            raise OSError("no more answers")
        return self.replies.pop(0)

    def close(self):
        pass


def test_ssdp_scan_sends_one_search_and_dedupes_answers(monkeypatch) -> None:
    roku = b"HTTP/1.1 200 OK\r\nSERVER: Roku/9.4 UPnP/1.1\r\n\r\n"
    linux = b"HTTP/1.1 200 OK\r\nSERVER: Linux/4.9 UPnP/1.0\r\n\r\n"
    fake = _FakeSocket([
        (roku, ("192.168.0.22", 1900)),
        (roku, ("192.168.0.22", 1900)),          # same device, second service
        (linux, ("192.168.0.1", 1900)),          # generic: no hint
    ])
    monkeypatch.setattr(discovery.socket, "socket", lambda *args, **kwargs: fake)
    hints = discovery.ssdp_scan(timeout=1.0)
    assert hints == {"192.168.0.22": "tv"}
    assert fake.sent and fake.sent[0][1] == (discovery.SSDP_ADDR, discovery.SSDP_PORT)


def test_upnp_hint_sets_the_kind_and_is_cached(monkeypatch) -> None:
    monkeypatch.setattr(discovery, "reverse_names", lambda ips, timeout=1.2: {})
    monkeypatch.setattr(discovery, "scan_ports", lambda ip, ports=discovery.PROBE_PORTS: [])
    monkeypatch.setattr(discovery, "multicast_hints",
                        lambda local_ip=None, timeout=2.0: {"10.0.0.22": {"kind": "tv"}})
    hosts = [{"ip": "10.0.0.22", "mac": "aa:bb:cc:dd:ee:01", "hostname": "10.0.0.22",
              "role": "workstation", "open_ports": []}]
    out = discovery.enrich(hosts)
    assert out[0]["kind"] == "tv"

    def no_multicast(*args, **kwargs):
        raise AssertionError("the cache must answer without a new multicast sweep")

    monkeypatch.setattr(discovery, "multicast_hints", no_multicast)
    assert discovery.enrich(hosts)[0]["kind"] == "tv"


# ---- mDNS -------------------------------------------------------------------
def _enc(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def _mdns_packet(service: str, instance: str, addr: str = "192.168.0.60") -> bytes:
    """A minimal mDNS answer: PTR service -> instance, plus the A record."""
    rr = _enc(service) + struct.pack("!HHIH", 12, 1, 120, len(_enc(instance))) + _enc(instance)
    rr += _enc(instance) + struct.pack("!HHIH", 1, 1, 120, 4) + bytes(int(part) for part in addr.split("."))
    return struct.pack("!HHHHHH", 0, 0x8400, 0, 2, 0, 0) + rr


def test_parse_mdns_names_the_owner_and_the_family() -> None:
    cases = (
        ("_apple-mobdev2._tcp.local", "Ana-iPhone._apple-mobdev2._tcp.local", "Ana-iPhone", "phone"),
        ("_ipp._tcp.local", "HP-OfficeJet._ipp._tcp.local", "HP-OfficeJet", "printer"),
        ("_googlecast._tcp.local", "Salon-TV._googlecast._tcp.local", "Salon-TV", "tv"),
        ("_raop._tcp.local", "Salon._raop._tcp.local", "Salon", "speaker"),
    )
    for service, instance, name, kind in cases:
        out = discovery.parse_mdns([(_mdns_packet(service, instance), "192.168.0.60")])
        assert out["192.168.0.60"] == {"name": name, "kind": kind}, service


def test_parse_mdns_follows_compression_pointers() -> None:
    question = _enc("_raop._tcp.local") + struct.pack("!HH", 12, 1)
    target = _enc("Salon._raop._tcp.local")
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 12, 1, 120, len(target)) + target
    packet = struct.pack("!HHHHHH", 0, 0x8400, 1, 1, 0, 0) + question + answer
    assert discovery.parse_mdns([(packet, "192.168.0.61")]) == {
        "192.168.0.61": {"name": "Salon", "kind": "speaker"}}


def test_mdns_scan_asks_the_services_and_parses_answers(monkeypatch) -> None:
    packet = _mdns_packet("_apple-mobdev2._tcp.local", "Ana-iPhone._apple-mobdev2._tcp.local")
    fake = _FakeSocket([(packet, ("192.168.0.60", 5353))])
    monkeypatch.setattr(discovery.socket, "socket", lambda *args, **kwargs: fake)
    out = discovery.mdns_scan(timeout=1.0)
    assert out["192.168.0.60"]["name"] == "Ana-iPhone"
    sent, addr = fake.sent[0]
    assert addr == (discovery.MDNS_ADDR, discovery.MDNS_PORT)
    assert b"_apple-mobdev2" in sent and b"_ipp" in sent and b"_googlecast" in sent


def test_an_empty_answer_is_retried_soon(monkeypatch) -> None:
    """A sleeping device must not stay "unknown" for the full 12 h TTL."""
    calls = []
    monkeypatch.setattr(discovery, "reverse_names", lambda ips, timeout=1.2: {})
    monkeypatch.setattr(discovery, "scan_ports",
                        lambda ip, ports=discovery.PROBE_PORTS: calls.append(ip) or [])
    hosts = [{"ip": "10.0.0.30", "mac": "aa:bb:cc:dd:ee:30", "hostname": "10.0.0.30",
              "role": "workstation", "open_ports": []}]
    discovery.enrich(hosts, now=1_000_000)
    assert calls == ["10.0.0.30"]
    # 4 minutes later it is not re-asked yet…
    discovery.enrich(hosts, now=1_000_000 + 240)
    assert calls == ["10.0.0.30"]
    # …but after five it is.
    discovery.enrich(hosts, now=1_000_000 + 400)
    assert calls == ["10.0.0.30", "10.0.0.30"]


def test_mdns_gives_the_name_and_kind_to_enrichment(monkeypatch) -> None:
    monkeypatch.setattr(discovery, "reverse_names", lambda ips, timeout=1.2: {})
    monkeypatch.setattr(discovery, "scan_ports", lambda ip, ports=discovery.PROBE_PORTS: [])
    monkeypatch.setattr(discovery, "multicast_hints",
                        lambda local_ip=None, timeout=2.0: {
                            "10.0.0.60": {"name": "Ana-iPhone", "kind": "phone"}})
    hosts = [{"ip": "10.0.0.60", "mac": "aa:bb:cc:dd:ee:60", "hostname": "10.0.0.60",
              "role": "workstation", "open_ports": []}]
    out = discovery.enrich(hosts)
    assert out[0]["hostname"] == "Ana-iPhone"
    assert out[0]["kind"] == "phone"


def test_enrichment_records_vendor_and_private_mac() -> None:
    """Context for '?' devices: who made the box, and whether the MAC is real."""
    dlink = discovery._with_kind({"ip": "10.0.0.5", "hostname": "10.0.0.5",
                                  "mac": "00:ad:24:17:f5:85"})
    assert dlink["mac_vendor"] == "D-Link"
    assert dlink["private_mac"] is False
    phone = discovery._with_kind({"ip": "10.0.0.6", "hostname": "10.0.0.6",
                                  "mac": "7a:b6:16:db:2d:0e"})
    assert phone["mac_vendor"] == ""
    assert phone["private_mac"] is True
