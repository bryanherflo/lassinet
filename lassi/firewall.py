"""Firewall providers.

LassiNet keeps a single source of truth for the rule table — `lassi.state` —
and this module *issues* the corresponding commands to a firewall provider.
`block()` / `unblock()` return True only when the provider actually accepted
the operation, so the API and the auto-block path never mark an IP as blocked
when `nft` failed or when a provider is still a placeholder.

Providers (LASSI_FW env var):
  * mock     — no external calls; logs actions (default, zero config, safe anywhere)
  * nftables — issues real `nft` commands (Linux, needs root)
  * opnsense — adds/removes the source IP in an existing OPNsense alias
  * pfsense  — placeholder; pfSense uses a different REST API and is not wired yet
"""

import base64
import ipaddress
import json
import logging
import os
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request

log = logging.getLogger("lassi.firewall")


def _family(ip: str) -> str:
    try:
        return "ip6" if ipaddress.ip_address(ip).version == 6 else "ip"
    except ValueError:
        return "ip"


class Firewall:
    def __init__(self, provider: str | None = None) -> None:
        self.provider = os.getenv("LASSI_FW", provider or "mock").lower()
        self.opnsense_url = os.getenv("OPNSENSE_URL", "").strip()
        self.opnsense_key = os.getenv("OPNSENSE_KEY", "").strip()
        self.opnsense_secret = os.getenv("OPNSENSE_SECRET", "").strip()
        self.opnsense_alias = os.getenv("OPNSENSE_ALIAS", "lassinet_blocked").strip()
        self.opnsense_verify_tls = os.getenv("OPNSENSE_VERIFY_TLS", "1").lower() not in (
            "0", "false", "no", "off",
        )
        try:
            self.opnsense_timeout = max(float(os.getenv("OPNSENSE_TIMEOUT", "5")), 1.0)
        except ValueError:
            self.opnsense_timeout = 5.0
        if self.provider not in ("mock", "nftables", "opnsense", "pfsense"):
            log.error("Unknown firewall provider %r — no rules will be applied", self.provider)
        log.info("Firewall provider: %s", self.provider)

    def block(self, ip: str, reason: str = "manual") -> bool:
        """Apply a BLOCK rule for traffic **from** `ip` on the provider.

        The dashboard always blocks the source of a detection (the attacker),
        so nftables matches `saddr` and OPNsense adds the IP to the block
        alias. Returns True only when the provider accepted the rule.
        """
        if self.provider == "nftables":
            return self._nft(["add", "rule", "inet", "lassinet", "drop", _family(ip), "saddr", ip])
        if self.provider == "opnsense":
            return self._opnsense_alias(ip, add=True)
        if self.provider == "pfsense":
            return self._pfsense_placeholder(ip, block=True)
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
        if self.provider == "opnsense":
            return self._opnsense_alias(ip, add=False)
        if self.provider == "pfsense":
            return self._pfsense_placeholder(ip, block=False)
        if self.provider == "mock":
            log.info("[mock] ALLOW %s", ip)
            return True
        log.error("Firewall provider %r cannot remove blocks", self.provider)
        return False

    def active_blocks(self) -> set[str] | None:
        """Read the current block sources from the provider, when supported.

        This lets a restarted live sensor rebuild its dashboard state from the
        rules that are actually still in the kernel instead of starting empty
        and later adding duplicates. OPNsense/pfSense return None for now.
        """
        if self.provider != "nftables":
            return None
        listing = self._nft_list()
        if listing is None:
            return None
        return self._parse_nft_blocks(listing)

    @staticmethod
    def _parse_nft_blocks(listing: str) -> set[str]:
        blocked: set[str] = set()
        for line in listing.splitlines():
            tokens = line.split()
            if "drop" not in tokens or "saddr" not in tokens:
                continue
            try:
                ip = tokens[tokens.index("saddr") + 1]
                ipaddress.ip_address(ip)
            except (ValueError, IndexError):
                continue
            blocked.add(ip)
        return blocked

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

    def _opnsense_alias(self, ip: str, add: bool) -> bool:
        """Add/remove an address in the configured OPNsense alias.

        The alias must already exist (Host, Network or External type) and be
        referenced by a firewall rule; this method only manages its contents.
        OPNsense's alias_util API returns {"status": "done"} on success.
        """
        action = "add" if add else "delete"
        key, secret = self.opnsense_key, self.opnsense_secret
        if not secret and ":" in key:          # accept KEY="key:secret" too
            key, secret = key.split(":", 1)
        if not (self.opnsense_url and key and secret and self.opnsense_alias):
            log.error("[opnsense] cannot %s %s: set OPNSENSE_URL, OPNSENSE_KEY, "
                      "OPNSENSE_SECRET and OPNSENSE_ALIAS", action, ip)
            return False

        alias = urllib.parse.quote(self.opnsense_alias, safe="")
        url = f"{self.opnsense_url.rstrip('/')}/api/firewall/alias_util/{action}/{alias}"
        body = json.dumps({"address": ip}).encode("utf-8")
        auth = base64.b64encode(f"{key}:{secret}".encode("utf-8")).decode("ascii")
        request = urllib.request.Request(
            url, data=body, method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Basic {auth}"},
        )
        context = None
        if not self.opnsense_verify_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        try:
            with urllib.request.urlopen(
                request, timeout=self.opnsense_timeout, context=context
            ) as response:
                status = getattr(response, "status", 200)
                raw = response.read(4096).decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            detail = exc.read(512).decode("utf-8", "replace")
            log.warning("[opnsense] %s %s failed: HTTP %s %s", action, ip, exc.code, detail)
            return False
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            log.warning("[opnsense] %s %s failed: %s", action, ip, exc)
            return False

        if not 200 <= status < 300:
            log.warning("[opnsense] %s %s failed: HTTP %s %s", action, ip, status, raw[:200])
            return False
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            log.warning("[opnsense] %s %s returned non-JSON: %s", action, ip, raw[:200])
            return False
        result = str(payload.get("status", "")).lower() if isinstance(payload, dict) else ""
        if result in ("done", "ok", "success"):
            log.info("[opnsense] %s %s in alias %s", action.upper(), ip, self.opnsense_alias)
            return True
        log.warning("[opnsense] %s %s rejected: %s", action, ip, raw[:200])
        return False

    def _pfsense_placeholder(self, ip: str, block: bool) -> bool:
        """pfSense's REST API differs from OPNsense's alias_util API."""
        log.warning("[pfsense] %s rule for %s requested, but this provider is a "
                    "placeholder; no rule was applied",
                    "BLOCK" if block else "ALLOW", ip)
        return False
