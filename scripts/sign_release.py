#!/usr/bin/env python3
"""Create or verify detached GPG signatures for release artifacts.

The private key must stay outside the repository. By default the script signs
the source ZIP and checksum in `dist/`; pass explicit files to choose another
artifact.

    set LASSINET_GPG_KEY=<key-id>       # PowerShell: $env:LASSINET_GPG_KEY=...
    python scripts/sign_release.py
    python scripts/sign_release.py --verify

No key is stored, generated or copied by this script.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"


def _default_files() -> list[Path]:
    files = sorted(DIST.glob("lassinet-*.zip")) + sorted(DIST.glob("lassinet-*.zip.sha256"))
    return [path for path in files if path.is_file()]


def _run_gpg(gpg: str, args: list[str]) -> int:
    print("+", gpg, " ".join(args))
    return subprocess.run([gpg, *args], check=False).returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="*", help="artifacts (default: dist/lassinet-*)")
    parser.add_argument("--key", default=os.getenv("LASSINET_GPG_KEY", ""),
                        help="GPG key id/email (or set LASSINET_GPG_KEY)")
    parser.add_argument("--gpg", default="gpg", help="GPG executable")
    parser.add_argument("--verify", action="store_true", help="verify .asc signatures")
    args = parser.parse_args()

    gpg = args.gpg or "gpg"
    if shutil.which(gpg) is None and not Path(gpg).exists():
        print(f"error: {gpg!r} not found; install GnuPG or pass --gpg", file=sys.stderr)
        return 2
    files = [Path(item) for item in args.files] if args.files else _default_files()
    files = [path if path.is_absolute() else ROOT / path for path in files]
    if not files:
        print("error: no artifacts found; run scripts/release_zip.py first", file=sys.stderr)
        return 2
    missing = [str(path) for path in files if not path.is_file()]
    if missing:
        print(f"error: missing files: {', '.join(missing)}", file=sys.stderr)
        return 2

    if args.verify:
        status = 0
        for path in files:
            signature = Path(str(path) + ".asc")
            if not signature.is_file():
                print(f"error: missing signature {signature}", file=sys.stderr)
                status = 1
                continue
            status = _run_gpg(gpg, ["--verify", str(signature), str(path)]) or status
        return status

    key = (args.key or "").strip()
    if not key:
        print("error: choose a GPG key with --key or LASSINET_GPG_KEY", file=sys.stderr)
        print("       keep the private key outside the repository", file=sys.stderr)
        return 2
    for path in files:
        signature = Path(str(path) + ".asc")
        result = _run_gpg(gpg, [
            "--batch", "--yes", "--armor", "--detach-sign",
            "--local-user", key, "--output", str(signature), str(path),
        ])
        if result != 0:
            return result
        print(f"wrote {signature}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
