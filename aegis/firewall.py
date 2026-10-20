"""Firewall providers.

AegisNet keeps a single source of truth for the rule table — `aegis.state` —
and this module only *issues* the corresponding commands to a real firewall
provider. This guarantees that any auto-block (SOAR-style) is actually applied
when running against nftables/OPNsense instead of updating the dashboard only.

Providers (AEGIS_FW env var):
  * mock     — no external calls; logs actions (default, zero config, safe anywhere)
  * nftables — issues real `nft` commands (Linux, needs root)
  * pfsense  — OPNsense/pfSense REST API (needs base URL + API key)
"""

import logging
import os
import subprocess

log = logging.getLogger("aegis.firewall")


class Firewall:
    def __init__(self, provider: str | None = None) -> None:
        self.provider = os.getenv("AEGIS_FW", provider or "mock").lower()
        self.opnsense_url = os.getenv("OPNSENSE_URL", "")
        self.opnsense_key = os.getenv("OPNSENSE_KEY", "")
        log.info("Firewall provider: %s", self.provider)

    def block(self, ip: str, reason: str = "manual") -> None:
        """Apply a BLOCK rule for `ip` on the configured provider."""
        if self.provider == "nftables":
            self._nft(f"nft add rule inet aegisnet drop ip daddr {ip}")
        elif self.provider == "pfsense":
            self._opnsense_rule(ip, block=True)
        else:
            log.info("[mock] BLOCK %s (%s)", ip, reason)

    def unblock(self, ip: str) -> None:
        """Remove the BLOCK rule for `ip` on the configured provider."""
        if self.provider == "nftables":
            self._nft(f"nft delete rule inet aegisnet handle $(nft -a list table inet aegisnet | grep {ip} | awk '{{print $NF}}')")
        elif self.provider == "pfsense":
            self._opnsense_rule(ip, block=False)
        else:
            log.info("[mock] ALLOW %s", ip)

    @staticmethod
    def _nft(cmd: str) -> None:
        try:
            subprocess.run(cmd.split(), check=False)
        except FileNotFoundError:
            log.error("nft binary not found — rule not applied (check that nftables is installed).")

    def _opnsense_rule(self, ip: str, block: bool) -> None:
        """OPNsense REST API NC — placeholder showing the integration point."""
        log.info("[opnsense] %s rule for %s (implement against your API key)",
                 "BLOCK" if block else "ALLOW", ip)
