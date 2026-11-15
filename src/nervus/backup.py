"""Making a backup of nervus (ADR-0027 question 1a, 2, 3 and 4): everything
nervus cannot make again without touching machines or clients, taken at one
moment, as one file only the recovery key opens.

What it holds to:
- A backup holds every piece `Pieces` names, and nothing else: no export,
  upload or transfer file, no code. Each piece is stored by its role, not its
  path, so a restore puts it where that installation's unit says.
- A required piece missing or unreadable refuses the backup, naming it: a
  backup that cannot bring nervus back is not one.
- The database is taken by SQLite's own backup command, so it is whole and
  consistent while nervus writes; the audit log is read last, up to its last
  whole record, so it holds the record of every change in that database and
  the backup's own `backup` record.
- Nothing is written in clear. The archive is put together in memory and
  streamed into `age`, the standard program, which locks it to the recovery
  key's public half (question 2). nervus never holds what opens it.
- Nothing is a backup until it is whole: it is written as `.partial`, and
  given its name only once `age` has finished cleanly. A failure leaves no
  `.partial` and removes nothing.
- Making a backup is audited before anything is read (ADR-0001 s10): no
  record, no backup. A missing audit log refuses before that record, which
  would otherwise start a new log and hide that the old one is gone. Its outcome, and every backup the keeping removed, are
  recorded after.
- The folder is 0700, each backup 0600.
- Kept: the newest backup of each of the last 7 days, of each of the last 5
  weeks within 31 days, and of each of the last 12 months within 365 days;
  nothing older (question 4, as the operator decided). Only after a backup is
  made, never after one failed; a file whose name is not a backup's is never
  touched.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import subprocess
import tarfile
from dataclasses import dataclass, field, fields
from datetime import datetime, timedelta, timezone
from pathlib import Path

import nervus
from nervus import plainfile
from nervus.audit import AuditError, AuditLog
from nervus.config import ConfigError

# Where the recovery key's public half is kept, beside the other secrets and,
# like them, read-only to nervus under its unit. Relative to nervus's
# working directory, as the other secrets' defaults are.
RECOVERY_KEY = "secrets/recovery.pub"
# An age X25519 recipient: "age1" and bech32 characters.
RECIPIENT = re.compile(r"age1[02-9ac-hj-np-z]{58}")

FORMAT = 1
NAME = re.compile(r"nervus-backup-(\d{8}T\d{6}Z)\.tar\.gz\.age")
STAMP = "%Y%m%dT%H%M%SZ"
CHUNK = 1 << 20

# Question 4, as the operator decided: (how many, within how many days).
DAILY = (7, 7)
WEEKLY = (5, 31)
MONTHLY = (12, 365)


class BackupFailed(ConfigError):
    """No backup was made, and why, in words for the operator."""


@dataclass(frozen=True)
class Pieces:
    """What a backup holds, by role, with each piece's path on this
    installation. `None` is a piece this installation does not have."""

    ssh_key: Path
    ssh_ca_key: Path
    tokens: Path
    hosts: Path
    switches: Path
    database: Path
    audit_log: Path
    ssh_key_pub: Path | None = None
    ssh_ca_key_pub: Path | None = None
    known_hosts: Path | None = None
    tls_cert: Path | None = None
    tls_key: Path | None = None
    tls_issuer_cert: Path | None = None
    tls_issuer_key: Path | None = None
    tls_root_cert: Path | None = None
    tls_renewed: Path | None = None
    proxmox: Path | None = None
    proxmox_ca: Path | None = None
    recovery_key: Path | None = None  # its public half: a restored nervus locks its backups to the same key
    drop_ins: tuple[Path, ...] = field(default=())

    def files(self) -> list[tuple[str, Path]]:
        """(role, path) of every piece read as a file: all but the database and
        the audit log, which have their own way of being read."""
        out = []
        for f in fields(self):
            value = getattr(self, f.name)
            if f.name in ("database", "audit_log", "drop_ins") or value is None:
                continue
            out.append((f.name, value))
        out += [(f"drop_ins/{p.name}", p) for p in self.drop_ins]
        return out


@dataclass(frozen=True)
class Made:
    path: Path
    size: int
    sha256: str
    removed: list[str]


def recipient(path: Path) -> str:
    """The recovery key's public half, from its file: one `age1…` line."""
    try:
        text = plainfile.read_text(path).strip()
    except OSError as exc:
        raise BackupFailed(f"no recovery key at {path}: {exc}. Make one with `nervus-ctl recovery-key`") from exc
    if not RECIPIENT.fullmatch(text):
        raise BackupFailed(f"{path} is not an age public key (one line, age1…)")
    return text


def backup_name(made: datetime) -> str:
    return f"nervus-backup-{made.astimezone(timezone.utc).strftime(STAMP)}.tar.gz.age"


def made_at(name: str) -> datetime | None:
    """When a backup was made, from its name; None for a name that is not a
    backup's. Read from the name, not the file's date, which a copy changes."""
    found = NAME.fullmatch(name)
    if found is None:
        return None
    try:
        return datetime.strptime(found.group(1), STAMP).replace(tzinfo=timezone.utc)
    except ValueError:
        return None  # the shape matches but the date is impossible: not a backup's name


def to_keep(made: list[datetime], now: datetime) -> set[datetime]:
    """Which of the backups made at `made` to keep at `now` (question 4)."""
    kept: set[datetime] = set()

    def newest_of_each(period, rule: tuple[int, int]) -> None:
        count, days = rule
        newest: dict = {}
        for t in made:
            if now - t < timedelta(days=days):
                key = period(t)
                newest[key] = max(newest.get(key, t), t)
        kept.update(newest[key] for key in sorted(newest, reverse=True)[:count])

    newest_of_each(lambda t: t.date(), DAILY)
    newest_of_each(lambda t: t.isocalendar()[:2], WEEKLY)
    newest_of_each(lambda t: (t.year, t.month), MONTHLY)
    return kept


def prune(folder: Path, now: datetime, keep: Path) -> list[str]:
    """Remove the backups in `folder` that to_keep does not keep, never
    `keep`, the backup just made, and never a file whose name is not a
    backup's. Returns the names removed."""
    backups = {p: t for p in folder.iterdir() if (t := made_at(p.name)) is not None and p.is_file()}
    kept = to_keep(list(backups.values()), now)
    removed = []
    for path, t in sorted(backups.items()):
        if t not in kept and path != keep:
            path.unlink()
            removed.append(path.name)
    return removed


def _read(role: str, path: Path) -> tuple[bytes, int]:
    try:
        with plainfile.open_file(path) as f:  # its mode read from what was opened, not from the name again
            return f.read(), os.fstat(f.fileno()).st_mode & 0o777
    except OSError as exc:
        raise BackupFailed(f"cannot read {role} ({path}): {exc}") from exc


def _database(path: Path) -> tuple[bytes, int, int]:
    """The database as one consistent copy, in memory: its bytes, mode and
    schema version. SQLite's backup command copies it whole while nervus
    writes; a copy of the file could miss what sits in its write-ahead log."""
    if not path.is_file():
        raise BackupFailed(f"cannot read database ({path}): no such file")
    try:
        # mode=rw, as Database does: never make the file.
        with contextlib.closing(sqlite3.connect(f"{path.absolute().as_uri()}?mode=rw", uri=True)) as source, \
                contextlib.closing(sqlite3.connect(":memory:")) as copy:
            source.backup(copy)
            version = copy.execute("PRAGMA user_version").fetchone()[0]
            data = copy.serialize()
        return data, path.stat().st_mode & 0o777, version
    except (sqlite3.Error, OSError) as exc:
        raise BackupFailed(f"cannot read database ({path}): {exc}") from exc


def _whole_records(log) -> int:
    """How many bytes of the open audit log, from its start, end at its last
    whole record. The log only grows, so those bytes do not change after."""
    size = os.fstat(log.fileno()).st_size
    at = size
    while at > 0:
        step = min(CHUNK, at)
        log.seek(at - step)
        block = log.read(step)
        newline = block.rfind(b"\n")
        if newline >= 0:
            return at - step + newline + 1
        at -= step
    return 0


def _hash_first(log, length: int) -> str:
    digest = hashlib.sha256()
    log.seek(0)
    left = length
    while left:
        block = log.read(min(CHUNK, left))
        if not block:
            raise BackupFailed("the audit log grew shorter while it was read")
        digest.update(block)
        left -= len(block)
    return digest.hexdigest()


def _member(name: str, size: int, mtime: float) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size, info.mode, info.mtime = size, 0o600, int(mtime)
    return info


def make_backup(pieces: Pieces, recipient: str, folder: Path, audit: AuditLog,
                now: datetime | None = None, tool: str = "nervus-ctl") -> Made:
    """Make one backup of `pieces` in `folder`, locked to `recipient`, then
    remove the backups the keeping no longer keeps. Raises BackupFailed, and
    then nothing was made or removed."""
    now = now or datetime.now(timezone.utc)
    name = backup_name(now)
    # Before the record below, which would otherwise start a new log, and a
    # backup of that would carry one line where the whole record was.
    if not pieces.audit_log.is_file():
        raise BackupFailed(f"cannot read audit_log ({pieces.audit_log}): no such file; no backup made")
    try:
        record = audit.record_operator("backup", {"file": name}, tool=tool)
    except AuditError as exc:
        raise BackupFailed(f"no backup made: its record could not be written: {exc}") from exc
    try:
        made = _make(pieces, recipient, folder, name, now)
    except Exception as exc:
        failed = exc if isinstance(exc, BackupFailed) else BackupFailed(f"no backup made: {exc}")
        with contextlib.suppress(AuditError):
            audit.record_operator("backup_failed", {"file": name, "backup_record": record, "reason": str(failed)},
                                  tool=tool)
        if failed is exc:
            raise
        raise failed from exc
    audit.record_operator("backup_made", {"file": name, "backup_record": record, "size": made.size,
                                          "sha256": made.sha256, "removed": made.removed}, tool=tool)
    return made


def _make(pieces: Pieces, recipient: str, folder: Path, name: str, now: datetime) -> Made:
    age = shutil.which("age")
    if age is None:
        raise BackupFailed("age is not installed, so no backup can be locked to the recovery key")
    if not RECIPIENT.fullmatch(recipient):
        raise BackupFailed("the recovery key is not an age public key (age1…)")

    # In this order: the database, the other files, the audit log last.
    database, database_mode, schema_version = _database(pieces.database)
    files = [(role, path, *_read(role, path)) for role, path in pieces.files()]
    try:
        log = plainfile.open_file(pieces.audit_log)
    except OSError as exc:
        raise BackupFailed(f"cannot read audit_log ({pieces.audit_log}): {exc}") from exc
    with log:
        log_size = _whole_records(log)
        log_sha = _hash_first(log, log_size)
        log_mode = os.fstat(log.fileno()).st_mode & 0o777

        listed = [{"role": "database", "path": str(pieces.database), "mode": database_mode,
                   "size": len(database), "sha256": hashlib.sha256(database).hexdigest()}]
        listed += [{"role": role, "path": str(path), "mode": mode, "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest()} for role, path, data, mode in files]
        listed.append({"role": "audit_log", "path": str(pieces.audit_log), "mode": log_mode,
                       "size": log_size, "sha256": log_sha})
        manifest = json.dumps({"format": FORMAT, "made_at": now.timestamp(), "nervus": nervus.__version__,
                               "schema_version": schema_version, "pieces": listed},
                              indent=1, sort_keys=True).encode()

        folder.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(folder, 0o700)
        final = folder / name
        partial = folder / (name + ".partial")
        if final.exists():
            # A backup's name is its second, so two in one second share one.
            raise BackupFailed(f"a backup was made this same second ({final.name}); make another in a moment")
        try:
            fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except OSError as exc:
            raise BackupFailed(f"cannot write {partial}: {exc}") from exc
        try:
            os.fchmod(fd, 0o600)
            process = subprocess.Popen([age, "--encrypt", "--recipient", recipient],
                                       stdin=subprocess.PIPE, stdout=fd, stderr=subprocess.PIPE)
            try:
                with tarfile.open(fileobj=process.stdin, mode="w|gz") as archive:
                    archive.addfile(_member("manifest.json", len(manifest), now.timestamp()), io.BytesIO(manifest))
                    archive.addfile(_member("pieces/database", len(database), now.timestamp()), io.BytesIO(database))
                    for role, _, data, _ in files:
                        archive.addfile(_member(f"pieces/{role}", len(data), now.timestamp()), io.BytesIO(data))
                    log.seek(0)
                    archive.addfile(_member("pieces/audit_log", log_size, now.timestamp()), log)
                process.stdin.close()
            except (OSError, tarfile.TarError) as exc:
                process.kill()
                process.wait()
                raise BackupFailed(f"age stopped before the backup was written: "
                                   f"{process.stderr.read().decode().strip() or exc}") from exc
            error = process.stderr.read().decode().strip()
            if process.wait() != 0:
                raise BackupFailed(f"age failed: {error or 'exit ' + str(process.returncode)}")
            os.fsync(fd)
        except BaseException:
            os.close(fd)
            partial.unlink(missing_ok=True)
            raise
        os.close(fd)

    os.rename(partial, final)
    with contextlib.suppress(OSError):  # the rename lasting a crash; not every platform can
        dir_fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    digest = hashlib.sha256()
    with plainfile.open_file(final) as written:
        while block := written.read(CHUNK):
            digest.update(block)
    removed = prune(folder, now, keep=final)
    return Made(path=final, size=final.stat().st_size, sha256=digest.hexdigest(), removed=removed)
