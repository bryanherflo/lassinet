"""Firewall providers.

LassiNet keeps a single source of truth for the rule table — `lassi.state` —
and this module *issues* the corresponding commands to a firewall provider.
`block()` / `unblock()` return True only when the provider actually accepted
the operation, so the API and the auto-block path never mark an IP as blocked
when `nft` failed or when a provider is still a placeholder.

Providers (LASSI_FW env var):
  * mock     — no external calls; logs actions (default, zero config, safe anywhere)
  * nftables — issues real `nft` commands (Linux, needs root)
  * pfsense  — OPNsense/pfSense integration point (placeholder; does not enforce yet)
"""

import ipaddress
import logging
import os
import subprocess

log = logging.getLogger("lassi.firewall")

def _family(ip: str) -> str:
    try:
        return "ip6" if ipaddress.ip_address(ip).version == 6 else "ip"
    except ValueError:
        return "ip"


class Firewall:
    def __init__(self, provider: str | None = None) -> None:
        self.provider = os.getenv("LASSI_FW", provider or "mock").lower()
        self.opnsense_url = os.getenv("OPNSENSE_URL", "")
        self.opnsense_key = os.getenv("OPNSENSE_KEY", "")
        if self.provider not in ("mock", "nftables", "pfsense"):
            log.error("Unknown firewall provider %r — no rules will be applied", self.provider)
        log.info("Firewall provider: %s", self.provider)

    def block(self, ip: str, reason: str = "manual") -> bool:
        """Apply a BLOCK rule for traffic **from** `ip` on the provider.

        The dashboard always blocks the source of a detection (the attacker),
        so nftables matches `saddr`. Returns True only when the provider
        accepted the rule. The rule is reversible with `unblock`.
        """
        if self.provider == "nftables":
            return self._nft(["add", "rule", "inet", "lassinet", "drop", _family(ip), "saddr", ip])
        if self.provider == "pfsense":
            return self._opnsense_rule(ip, block=True)
        if self.provider == "mock":
            log.info("[mock] BLOCK %s (%s)", ip, reason)
            return True
        log.error("Firewall provider %r cannot apply blocks", self.provider)
        return False

    def unblock(self, ip: str) -> bool:
        """Remove the BLOCK rule for `ip`. Returns True only when it was removed."""
        if self.provider == "nftables":
            listing = self._nft_list()
            if listing is None:
                log.warning("cannot list nftables rules; block for %s was not removed", ip)
                return False
            for line in listing.splitlines():
                tokens = line.split()
                if "drop" in tokens and ip in tokens and "handle" in tokens:
                    handle = line.rsplit("handle", 1)[-1].strip()
                    if handle.isdigit():
                        return self._nft(["delete", "rule", "inet", "lassinet", "handle", handle])
            log.warning("no nftables block rule found for %s", ip)
            return False
        if self.provider == "pfsense":
            return self._opnsense_rule(ip, block=False)
        if self.provider == "mock":
            log.info("[mock] ALLOW %s", ip)
            return True
        log.error("Firewall provider %r cannot remove blocks", self.provider)
        return False

    @staticmethod
    def _nft(args: list[str]) -> bool:
        try:
            result = subprocess.run(["nft", *args], check=False, capture_output=True, text=True)
            if result.returncode != 0:
                log.warning("nft command failed: %s", (result.stderr or "").strip())
                return False
            return True
        except FileNotFoundError:
            log.error("nft binary not found \u2014 rule not applied (check that nftables is installed).")
            return False

    @staticmethod
    def _nft_list() -> str | None:
        try:
            result = subprocess.run(["nft", "-a", "list", "table", "inet", "lassinet"],
                                    check=False, capture_output=True, text=True)
            if result.returncode != 0:
                log.warning("nft list failed: %s", (result.stderr or "").strip())
                return None
            return result.stdout
        except FileNotFoundError:
            log.error("nft binary not found \u2014 cannot list rules.")
            return None

    def _opnsense_rule(self, ip: str, block: bool) -> bool:
        """OPNsense/pfSense integration point — not implemented yet.

        Returning False is deliberate: the dashboard must not claim a real
        block when this provider only logs. Implement the REST call here and
        return True/False based on the HTTP result.
        """
        log.warning("[opnsense] %s rule for %s requested, but this provider is a "
                    "placeholder; no rule was applied",
                    "BLOCK" if block else "ALLOW", ip)
        return False
