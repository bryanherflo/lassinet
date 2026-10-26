"""Verified backup/restore tests; no network."""

import json
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import lassi.backup as backup  # noqa: E402


def test_backup_round_trip_and_manifest(tmp_path) -> None:
    source = tmp_path / "source"
    (source / "data").mkdir(parents=True)
    (source / "logs").mkdir()
    (source / "data" / "triage.db").write_bytes(b"sqlite-ish")
    (source / "logs" / "events.jsonl").write_text('{"event":"x"}\n',
                                                  encoding="utf-8")
    archive = tmp_path / "snapshot.zip"
    backup.create_backup(archive, root=source)
    check = backup.verify_backup(archive)
    assert check["ok"] is True and check["files"] == 2

    target = tmp_path / "restored"
    written = backup.restore_backup(archive, target)
    assert sorted(written) == ["data/triage.db", "logs/events.jsonl"]
    assert (target / "logs" / "events.jsonl").read_text(encoding="utf-8") == \
        '{"event":"x"}\n'


def test_backup_detects_a_tampered_file(tmp_path) -> None:
    archive = tmp_path / "bad.zip"
    manifest = {"format": "lassinet-backup-1",
                "files": {"data/x.txt": "0" * 64}}
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("data/x.txt", "tampered")
        zf.writestr("manifest.json", json.dumps(manifest))
    result = backup.verify_backup(archive)
    assert result["ok"] is False
    assert "checksum mismatch" in result["error"]


def test_env_is_opt_in(tmp_path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / ".env").write_text("LASSI_TOKEN_OPERATOR=secret\n", encoding="utf-8")
    normal = tmp_path / "normal.zip"
    backup.create_backup(normal, root=source)
    with zipfile.ZipFile(normal) as zf:
        assert ".env" not in zf.namelist()
    with_env = tmp_path / "with-env.zip"
    backup.create_backup(with_env, root=source, include_env=True)
    with zipfile.ZipFile(with_env) as zf:
        assert ".env" in zf.namelist()
