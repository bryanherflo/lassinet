#!/usr/bin/env python3
"""Generate a small SPDX-style JSON SBOM from the installed environment."""

from __future__ import annotations

import json
from importlib.metadata import distributions
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    packages = []
    for dist in distributions():
        name = dist.metadata.get("Name")
        if not name:
            continue
        packages.append({
            "name": name,
            "version": dist.version or "unknown",
            "license": dist.metadata.get("License") or "unknown",
        })
    packages.sort(key=lambda item: item["name"].lower())
    output = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "name": "LassiNet",
        "documentNamespace": "https://github.com/bryanherflo/lassinet/sbom",
        "packages": packages,
    }
    target = ROOT / "dist" / "lassinet-sbom.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    print(f"{target} ({len(packages)} packages)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
