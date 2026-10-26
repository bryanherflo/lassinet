"""Verified local backup/restore for the runtime data and audit log.

The backup contains `data/` and `logs/` by default, plus a manifest with a
SHA-256 per file. `.env` (secrets) is opt-in and should be handled with the
same care as the tokens themselves. Restore is explicit: it writes into a
target directory, never silently over the live installation.

    python -m lassi.backup create
    python -m lassi.backup verify backups/lassinet-....zip
    python -m lassi.backup restore backups/....zip --target restore-here

No network, no cloud, no external dependency.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_ROOTS = ("data", "logs")
MANIFEST = "manifest.json"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _iter_files(root: Path, bases: Iterable[str], include_env: bool) -> list[tuple[Path, str]]:
    found: list[tuple[Path, str]] = []
    for base in bases:
        directory = root / base
        if not directory.exists():
            continue
        for path in sorted(directory.rglob("*")):
            if path.is_file():
                found.append((path, path.relative_to(root).as_posix()))
    if include_env:
        env = root / ".env"
        if env.is_file():
            found.append((env, ".env"))
    return found


def create_backup(output: Path, root: Path = ROOT,
                  bases: Iterable[str] = DEFAULT_ROOTS,
                  include_env: bool = False) -> Path:
    output = Path(output)
    if not output.is_absolute():
        output = Path.cwd() / output
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise FileExistsError(output)
    root = Path(root)
    files = [(path, name) for path, name in _iter_files(root, bases, include_env)
             if path.resolve() != output.resolve()]
    manifest: dict = {
        "format": "lassinet-backup-1",
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "files": {},
    }
    try:
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as zf:
            for path, name in files:
                zf.write(path, name)
                manifest["files"][name] = _sha256(path)
            zf.writestr(MANIFEST, json.dumps(manifest, indent=2, sort_keys=True))
    except Exception:
        output.unlink(missing_ok=True)
        raise
    return output


def verify_backup(path: Path) -> dict:
    path = Path(path)
    result: dict = {"ok": False, "files": 0, "error": ""}
    try:
        with zipfile.ZipFile(path) as zf:
            try:
                manifest = json.loads(zf.read(MANIFEST).decode("utf-8"))
            except KeyError:
                result["error"] = "manifest.json is missing"
                return result
            if not isinstance(manifest, dict) or manifest.get("format") != "lassinet-backup-1":
                result["error"] = "unsupported backup format"
                return result
            files = manifest.get("files")
            if not isinstance(files, dict):
                result["error"] = "invalid file list"
                return result
            for name, expected in files.items():
                if (not isinstance(name, str) or not name
                        or name.startswith(("/", "\\")) or "\\" in name
                        or ":" in name or ".." in Path(name).parts
                        or Path(name).is_absolute() or not isinstance(expected, str)):
                    result["error"] = f"unsafe manifest entry {name!r}"
                    return result
                try:
                    actual = hashlib.sha256(zf.read(name)).hexdigest()
                except KeyError:
                    result["error"] = f"missing file {name}"
                    return result
                if actual != expected:
                    result["error"] = f"checksum mismatch for {name}"
                    return result
            result.update(ok=True, files=len(files))
    except (OSError, zipfile.BadZipFile) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def restore_backup(path: Path, target: Path, force: bool = False) -> list[str]:
    check = verify_backup(path)
    if not check["ok"]:
        raise ValueError(check["error"] or "backup is not valid")
    target = Path(target).resolve()
    target.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    with zipfile.ZipFile(path) as zf:
        manifest = json.loads(zf.read(MANIFEST).decode("utf-8"))
        for name in sorted(manifest["files"]):
            destination = (target / name).resolve()
            if not destination.is_relative_to(target):
                raise ValueError(f"unsafe path in backup: {name}")
            if destination.exists() and not force:
                raise FileExistsError(destination)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(zf.read(name))
            written.append(name)
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="LassiNet verified backup/restore")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create", help="create a new verified backup")
    create.add_argument("--out", default="")
    create.add_argument("--include-env", action="store_true",
                        help="include .env (contains secrets)")
    verify = sub.add_parser("verify", help="verify a backup")
    verify.add_argument("archive")
    restore = sub.add_parser("restore", help="restore into a target directory")
    restore.add_argument("archive")
    restore.add_argument("--target", required=True)
    restore.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)

    if args.command == "create":
        out = Path(args.out) if args.out else (
            ROOT / "backups" /
            f"lassinet-{datetime.now().strftime('%Y%m%d-%H%M%S')}.zip")
        try:
            archive = create_backup(out, include_env=args.include_env)
        except Exception as exc:
            print(f"backup failed: {exc}", file=sys.stderr)
            return 1
        print(archive)
        return 0
    if args.command == "verify":
        result = verify_backup(Path(args.archive))
        print(json.dumps(result, indent=2))
        return 0 if result["ok"] else 1
    try:
        written = restore_backup(Path(args.archive), Path(args.target),
                                 force=args.force)
    except Exception as exc:
        print(f"restore failed: {exc}", file=sys.stderr)
        return 1
    print(f"restored {len(written)} file(s) into {args.target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
