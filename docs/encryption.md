# Encryption at rest and the flow database

LassiNet stores **network metadata**, not packet payloads. The local SQLite
database still contains sensitive information: IP addresses, device names,
MAC addresses, ports, alert history and timing. Assume it is private data.

## What is protected today

- `data/flows.db` is created with owner-only permissions on POSIX and lives
  under the ignored `data/` directory.
- The dashboard binds to loopback by default and should sit behind a TLS reverse
  proxy/VPN if accessed remotely.
- No cloud lookup, telemetry or account is used; GeoIP is an offline CSV.

## What is not protected today

The application does **not** encrypt `flows.db`, the triage database, audit
JSONL or reports. Anyone who can read the disk/backup (or an administrator on
the host) can read the metadata. SQLite WAL/SHM files and backups must be
protected too; encrypting only the main `.db` file is insufficient.

## Recommended baseline

1. Enable OS full-disk encryption: BitLocker on Windows, LUKS on Linux, or
   FileVault on macOS.
2. Keep `data/`, `logs/` and `backups/` owner-only. Do not sync them to a
   consumer cloud folder.
3. Encrypt backups at the archive level and test restore on a separate host.
4. Use a dedicated low-privilege service account; do not run the dashboard as
   root.
5. Protect hibernation/swap and crash dumps, which can contain SQLite pages.
6. If the host is shared or physically exposed, use an encrypted volume or
   container (for example VeraCrypt) for the whole runtime directory.

Full-disk encryption protects a powered-off disk. It does **not** protect data
from a process or administrator while the system is running.

## SQLCipher: not supported out of the box

SQLCipher is an encrypted SQLite build with a different Python driver. It is not
a drop-in change:

- a compatible driver/build must be installed on every OS and CI runner;
- the database key must be supplied and rotated without leaking it into logs,
  shell history or the dashboard;
- migrations, backups, compact/`VACUUM` and the triage/audit stores need an
  explicit encryption policy;
- losing the key means losing the history; there is no recovery path.

Until that work is done, do not claim LassiNet data is encrypted at rest. Treat
OS/volume encryption as the supported option and keep the SQLCipher dependency
out of the runtime requirements.

## Encrypted backups

`scripts/backup.py`/the backup UI create verified local backups, not encrypted
ones. Encrypt the resulting archive with your OS tooling or GPG, store the key
separately, and remember that restore also needs the key. See
[runbook.md](runbook.md) and [SECURITY.md](../SECURITY.md).

## Residual risk

A fully compromised sensor host can read live capture metadata, the model,
tokens and the unencrypted database. No application-level control replaces host
hardening, least privilege and an independent security review.
