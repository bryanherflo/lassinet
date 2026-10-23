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


def test_vendor_oui_classifies_when_the_name_says_nothing() -> None:
    assert classify(mac="b8:27:eb:aa:bb:cc") == "sbc"        # Raspberry Pi
    assert classify(mac="78:28:ca:aa:bb:cc") == "speaker"    # Sonos
    assert classify(mac="44:19:b6:aa:bb:cc") == "camera"     # Hikvision
    assert classify(mac="B8-27-EB-AA-BB-CC") == "sbc"        # dash form


def test_role_is_the_last_resort_and_never_guesses() -> None:
    assert classify(role="server") == "server"
    assert classify(role="printer") == "printer"
    assert classify(role="iot") == "iot"
    assert classify(role="router") == "router"
    assert classify(role="external") == "external"
    assert classify(role="workstation") == ""                # no invented icon


def test_a_name_wins_over_the_vendor() -> None:
    assert classify(hostname="iphone-ana", mac="b8:27:eb:aa:bb:cc") == "phone"


def test_every_answer_is_a_known_kind() -> None:
    for name in ("iphone", "ipad", "macbook", "pc-x", "raspberrypi", "sonos", "ps5"):
        assert classify(hostname=name) in KINDS
