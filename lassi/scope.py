"""Live-mode authorization scope.

`LASSI_LIVE_ALLOW` is a comma-separated CIDR allowlist. When it is set, live
mode refuses to start on any other network and the ARP discovery skips
candidates outside it. This is the guard that stops a laptop at school (or on
a customer Wi-Fi) from sweeping a network the operator does not own.

An empty/absent value keeps the historical behaviour (any LAN), but logs a
warning: a professional deployment should always set it.
"""

from __future__ import annotations

import ipaddress
import logging
import os

log = logging.getLogger("lassi.scope")


def allowlist_from_env(value: str | None = None) -> list[ipaddress.IPv4Network]:
    """Parse `LASSI_LIVE_ALLOW` into IPv4 networks; invalid entries are logged."""
    raw = value if value is not None else (os.getenv("LASSI_LIVE_ALLOW") or "")
    found: list[ipaddress.IPv4Network] = []
    for item in raw.replace(";", ",").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            net = ipaddress.ip_network(item, strict=False)
        except ValueError:
            log.warning("ignoring invalid LASSI_LIVE_ALLOW entry %r", item)
            continue
        if net.version != 4:
            log.warning("ignoring IPv6 LASSI_LIVE_ALLOW entry %r (live scope is IPv4)",
                        item)
            continue
        found.append(net)
    return found


def allowlist_is_configured(value: str | None = None) -> bool:
    raw = value if value is not None else (os.getenv("LASSI_LIVE_ALLOW") or "")
    return bool(raw.strip())


def network_allowed(net: ipaddress.IPv4Network,
                    networks: list[ipaddress.IPv4Network]) -> bool:
    """True when `net` is equal to or contained in one allowed network."""
    return any(net.version == allowed.version and net.subnet_of(allowed)
               for allowed in networks)


def check_live_scope(local_ip: str | None,
                     subnet_override: str | None,
                     networks: list[ipaddress.IPv4Network]) -> tuple[bool, str]:
    """Decide whether live mode may run here.

    `networks` empty is the existing "no allowlist" behaviour. If an allowlist
    is configured but local_ip cannot be determined, or the host/subnet is not
    inside it, live mode must not start.
    """
    if not networks:
        return True, "no LASSI_LIVE_ALLOW set"
    if not local_ip:
        return False, "cannot determine this host's LAN address"
    try:
        local = ipaddress.ip_address(local_ip)
    except ValueError:
        return False, f"invalid local address {local_ip!r}"
    if not any(local.version == net.version and local in net for net in networks):
        allowed = ", ".join(str(net) for net in networks)
        return False, f"this host {local} is outside LASSI_LIVE_ALLOW ({allowed})"
    if subnet_override:
        try:
            target = ipaddress.ip_network(subnet_override, strict=False)
        except ValueError:
            return False, f"invalid LASSI_SUBNET {subnet_override!r}"
        if target.version != 4:
            return False, "LASSI_SUBNET must be IPv4 for live ARP discovery"
        if not network_allowed(target, networks):
            allowed = ", ".join(str(net) for net in networks)
            return False, f"LASSI_SUBNET {target} is outside LASSI_LIVE_ALLOW ({allowed})"
    return True, f"{local} is inside LASSI_LIVE_ALLOW"
