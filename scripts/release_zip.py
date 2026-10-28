#!/usr/bin/env python3
"""Build a reproducible source ZIP and SHA-256 checksum.

This is intentionally dependency-free. It does not create a signed artifact:
signing needs a key that must stay outside the repository. Pass the printed
checksum/signature to your release workflow.
"""

from __future__ import annotations

import argparse
import hashlib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INCLUDE = [
    "app.py", "run.py", "requirements.txt", "requirements-dev.txt",
    "README.md", "LICENSE", "GUIA_DE_USO.md", "SUPPORT.md", "SECURITY.md",
    "CONTRIBUTING.md", ".env.example",
    "dashboard", "docs", "deploy", "install.ps1", "install.bat", "install.sh",
    "lassi", "ml-training", "scripts", "tests", ".github",
]
SKIP_PARTS = {".git", ".venv", "__pycache__", "data", "logs", "backups",
              "dist", ".pytest_cache"}


def _files() -> list[Path]:
    result: list[Path] = []
    for name in INCLUDE:
        path = ROOT / name
        if not path.exists():
            continue
        if path.is_file():
            result.append(path)
            continue
        for child in path.rglob("*"):
            if child.is_file() and not any(part in SKIP_PARTS for part in child.parts):
                result.append(child)
    result.extend(ROOT.glob("RELEASE_NOTES_*.md"))
    return sorted(set(result))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="dist")
    args = parser.parse_args()
    from lassi import __version__

    out_dir = ROOT / args.out
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / f"lassinet-{__version__}.zip"
    files = _files()
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            archive.write(path, path.relative_to(ROOT).as_posix())
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    checksum = target.with_suffix(".zip.sha256")
    checksum.write_text(f"{digest}  {target.name}\n", encoding="ascii")
    print(target)
    print(checksum)
    print(f"files={len(files)} sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
