"""Device-type classification (the map icon hint, never a security decision)."""

from lassi.devices import KINDS, classify


def test_names_classify_to_kinds() -> None:
    cases = {
        "iphone-ana": "phone",
        "Galaxy S23": "phone",
        "ipad-lounge": "tablet",
        "galaxy-tab-s7": "tablet",
        "macbook-sam": "laptop",
        "pc-finance": "desktop",
        "smart-tv": "tv",
        "ps5-lounge": "console",
        "hp-print": "printer",
        "cam-lobby": "camera",
        "echo-kitchen": "speaker",
        "apple-watch": "watch",
        "nas-salon": "nas",
        "raspberrypi": "sbc",
        "shelly-plug": "iot",
        "fritz-box": "router",
    }
    for name, expected in cases.items():
        assert classify(hostname=name) == expected, name


def test_ambiguous_evidence_stays_unknown() -> None:
    # An Apple OUI cannot tell an iPhone from a MacBook…
    assert classify(mac="a4:83:e7:11:22:33") == ""
    # …and a randomized MAC carries no vendor at all.
    assert classify(mac="da:a1:19:11:22:33") == ""
    # A bare IP is not a name.
    assert classify(hostname="192.168.0.42") == ""
    assert classify(hostname="pi-hole") == ""
    assert classify(mac="not-a-mac") == ""


def test_the_vendor_alone_never_picks_a_kind() -> None:
    """Operator preference (0.8.1): a known company is context, not a type.

    D-Link builds routers, cameras and switches; Tuya builds many smart-home
    boxes; a phone's random MAC has no vendor. Showing "Unknown" is preferred
    over a specific guess from the OUI.
    """
    from lassi.devices import vendor_for

    assert classify(mac="b8:27:eb:aa:bb:cc") == ""            # Raspberry Pi
    assert classify(mac="78:28:ca:aa:bb:cc") == ""            # Sonos
    assert classify(mac="44:19:b6:aa:bb:cc") == ""            # Hikvision
    assert classify(mac="fc:3c:d7:aa:bb:cc") == ""            # Tuya (smart home)
    assert classify(mac="B8-27-EB-AA-BB-CC") == ""            # dash form
    assert vendor_for("b8:27:eb:aa:bb:cc") == "Raspberry Pi"  # still shown as text
    assert vendor_for("B8-27-EB-AA-BB-CC") == "Raspberry Pi"


def test_role_is_the_last_resort_and_never_guesses() -> None:
    assert classify(role="server") == "server"
    assert classify(role="printer") == "printer"
    assert classify(role="iot") == "iot"
    assert classify(role="router") == "router"
    assert classify(role="external") == "external"
    assert classify(role="workstation") == ""                # no invented icon


def test_a_name_wins_over_the_vendor() -> None:
    assert classify(hostname="iphone-ana", mac="b8:27:eb:aa:bb:cc") == "phone"


def test_vendor_and_private_mac_are_context_not_a_kind() -> None:
    """The tooltip may say 'D-Link'; that must never become 'camera'."""
    from lassi.devices import is_private_mac, vendor_for

    assert vendor_for("00:ad:24:17:f5:85") == "D-Link"
    assert vendor_for("fc:3c:d7:aa:bb:cc") == "Tuya Smart"
    assert vendor_for("48:29:52:43:99:dc") == "Sagemcom"
    assert vendor_for("aa:bb:cc:dd:ee:ff") == ""
    assert vendor_for(None) == ""
    assert is_private_mac("7a:b6:16:db:2d:0e") is True       # phone, private Wi-Fi
    assert is_private_mac("46:a3:68:72:ba:dc") is True
    assert is_private_mac("00:ad:24:17:f5:85") is False
    assert is_private_mac("not-a-mac") is False
    # A known OUI with the private bit set is not that vendor at all.
    assert is_private_mac("02:ad:24:17:f5:85") is True
    assert vendor_for("02:ad:24:17:f5:85") == ""
    # D-Link makes routers, cameras and switches: the vendor is not a kind.
    assert classify(mac="00:ad:24:17:f5:85") == ""


def test_every_answer_is_a_known_kind() -> None:
    for name in ("iphone", "ipad", "macbook", "pc-x", "raspberrypi", "sonos", "ps5"):
        assert classify(hostname=name) in KINDS


def test_ports_classify_when_the_name_says_nothing() -> None:
    assert classify(ports=[9100]) == "printer"
    assert classify(ports=[631]) == "printer"
    assert classify(ports=[554]) == "camera"
    assert classify(ports=[62078]) == "phone"
    assert classify(ports=[8009]) == "tv"
    assert classify(ports=[5000]) == "nas"
    assert classify(ports=[22, 80, 443, 445]) == ""      # generic, no guess


def test_the_name_wins_over_the_ports() -> None:
    assert classify(hostname="iphone-ana", ports=[9100]) == "phone"


def test_upnp_hint_is_used_when_nothing_else_knows() -> None:
    assert classify(hint="speaker") == "speaker"
    assert classify(hint="tv") == "tv"
    assert classify(hint="not-a-kind") == ""
    assert classify(hostname="pc-x", hint="tv") == "desktop"   # the name wins
