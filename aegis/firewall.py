"""Firewall management.

Providers (AEGIS_FW env var):
  * mock     — in-memory rule table (default, zero config, safe anywhere)
  * nftables — issues real `nft` commands (Linux, needs root)
  * pfsense  — OPNsense/pfSense REST API (needs base URL + API key)
"""

import logging
import os
import subprocess
import time
from typing import Any

log = logging.getLogger("aegis.firewall")


class Firewall:
    def __init__(self, provider: str | None = None) -> None:
        self.provider = os.getenv("AEGIS_FW", provider or "mock").lower()
        self.rules: list[dict[str, Any]] = []
        self.opnsense_url = os.getenv("OPNSENSE_URL", "")
        self.opnsense_key = os.getenv("OPNSENSE_KEY", "")
        log.info("Firewall provider: %s", self.provider)

    def block(self, ip: str, reason: str = "manual") -> dict[str, Any]:
        rule = {"ip": ip, "action": "BLOCK", "reason": reason,
                "time": time.strftime("%H:%M:%S")}
        if self.provider == "nftables":
            self._nft(f"nft add rule inet aegisnet drop ip daddr {ip}")
        elif self.provider == "pfsense":
            self._opnsense_rule(ip, block=True)
        else:
            log.info("[mock] BLOCK %s (%s)", ip, reason)
        self.rules.append(rule)
        return rule

    def unblock(self, ip: str) -> dict[str, Any] | None:
        rule = None
        if self.provider == "nftables":
            self._nft(f"nft delete rule inet aegisnet handle $(nft -a list table inet aegisnet | grep {ip} | awk '{{print $NF}}')")
        elif self.provider == "pfsense":
            self._opnsense_rule(ip, block=False)
        else:
            log.info("[mock] ALLOW %s", ip)
            rule = {"ip": ip, "action": "ALLOW", "reason": "unblock",
                    "time": time.strftime("%H:%M:%S")}
            self.rules.append(rule)
        return rule

    @staticmethod
    def _nft(cmd: str) -> None:
        try:
            subprocess.run(["nft", "list", "table", "inet", "aegisnet"],
                           capture_output=True, check=False)
            subprocess.run(cmd.split(), check=False)
        except FileNotFoundError:
            log.error("nft binary not found; falling back to mock behaviour.")

    def _opnsense_rule(self, ip: str, block: bool) -> None:
        """OPNsense REST API NC — placeholder showing the integration point."""
        log.info("[opnsense] %s rule for %s (implement against your API key)",
                 "BLOCK" if block else "ALLOW", ip)

    def list_rules(self) -> list[dict[str, Any]]:
        return self.rules[-100:][::-1]
