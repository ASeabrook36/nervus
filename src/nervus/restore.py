"""Opening, checking and restoring a backup (ADR-0027 questions 5 and 7), for
`nervus-ctl backup --check` and `nervus-ctl restore`.

What it holds to:
- A backup is opened only with the recovery key's private half, given to the
  standard `age` program through a pipe, never a file; nothing opened is
  written in clear, except the audit log a restore puts in place.
- A backup is checked whole before anything relies on it: every piece its
  manifest names, and nothing else, each with its SHA-256; the database
  passing SQLite's own integrity check, at the schema version this nervus
  knows; each private key matching its public half.
- A restore refuses a damaged backup, a wrong key or a database from another
  release before anything on the machine changes, and nervus is not stopped.
- What a restore replaces is moved into a dated folder beside the database,
  never deleted. The installation's own drop-ins are kept: the backup's are
  saved beside what was replaced, for the person to compare.
- Each piece goes where this installation's unit puts its role, owned by
  nervus's account, with the mode the backup recorded.
- An audit log that already begins with the backup's is kept, since it holds
  everything the backup's does and more; otherwise the backup's is put in
  place and the other kept with what was replaced.
- A restored nervus acts for no one until the person has looked: the off
  switch is set to lockdown, keeping the clients the backup had switched off.
"""

from __future__ import annotations

import contextlib
import errno
import hashlib
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import tarfile
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import asyncssh
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from nervus import plainfile
from nervus.backup import CHUNK, FORMAT, Pieces
from nervus.config import ConfigError
from nervus.database import SCHEMA_VERSION
from nervus.tls import issuer_cert_path, issuer_key_path, root_cert_path

if TYPE_CHECKING:
    from nervus.ctl import Service


class BackupRefused(ConfigError):
    """A backup that cannot be opened, or is not whole, and why. Nothing was
    changed."""


# --- where each piece lives ----------------------------------------------------------


def locations(service: Service) -> dict[str, Path | None]:
    """Each role's path on this installation, as its unit names it. None for a
    role this installation does not have (no Proxmox settings)."""
    proxmox_ca = None
    if service.proxmox is not None:
        try:
            from nervus.proxmox import load_config
            proxmox_ca = Path(load_config(service.proxmox).ca_file)
        except (ConfigError, OSError):
            proxmox_ca = None
    return {
        "ssh_key": service.ssh_key,
        "ssh_ca_key": service.ssh_ca,
        "tokens": service.tokens,
        "hosts": service.hosts,
        "switches": service.switches,
        "database": service.database,
        "audit_log": service.audit_log,
        "ssh_key_pub": service.ssh_key.with_name(service.ssh_key.name + ".pub"),
        "ssh_ca_key_pub": service.ssh_ca.with_name(service.ssh_ca.name + ".pub"),
        "known_hosts": service.known_hosts,
        "tls_cert": service.tls_cert,
        "tls_key": service.tls_key,
        "tls_issuer_cert": issuer_cert_path(service.tls_cert),
        "tls_issuer_key": issuer_key_path(service.tls_key),
        "tls_root_cert": root_cert_path(service.tls_cert),
        "tls_renewed": service.tls_renewed,
        "proxmox": service.proxmox,
        "proxmox_ca": proxmox_ca,
        "recovery_key": service.recovery_key,
    }


REQUIRED = ("ssh_key", "ssh_ca_key", "tokens", "hosts", "switches", "database", "audit_log")


# Every role a backup may carry a piece for: the keys of locations(). A backup is
# authenticated only by decrypting, and the recovery key's public half is not secret,
# so a forged backup can be made whole. Restore and the whole-backup check therefore
# take where and how each piece is written from this installation, never from the
# backup: an unknown role or unsafe drop-in name is refused, an over-broad mode is
# clamped (procedure 056, finding 1). VALID_ROLES is kept in step with locations()
# by a test.
VALID_ROLES = frozenset({
    "ssh_key", "ssh_ca_key", "tokens", "hosts", "switches", "database", "audit_log",
    "ssh_key_pub", "ssh_ca_key_pub", "known_hosts", "tls_cert", "tls_key",
    "tls_issuer_cert", "tls_issuer_key", "tls_root_cert", "tls_renewed",
    "proxmox", "proxmox_ca", "recovery_key",
})

# Pieces whose file holds a secret, honestly 0600: restored owner-only. Every other
# piece keeps the backup's read bits, but no piece is ever setuid/setgid/sticky or
# writable by group or other.
SECRET_ROLES = frozenset({
    "ssh_key", "ssh_ca_key", "tokens", "known_hosts",
    "tls_key", "tls_issuer_key", "proxmox", "recovery_key",
})


def _safe_mode(role: str, mode: int) -> int:
    """The manifest's mode, de-fanged: never setuid/setgid/sticky, never writable by
    group or other, and owner-only for a secret."""
    mode &= 0o777
    mode &= ~0o022
    if role in SECRET_ROLES or role.startswith("drop_ins/"):
        mode &= ~0o077
    return mode


def _safe_drop_in_name(name: str) -> bool:
    """A drop-in name that stays one path component inside the kept folder."""
    return bool(name) and "/" not in name and name not in (".", "..")


def destinations(opened: "Opened", service: Service) -> dict[str, Path]:
    """Where each piece of `opened` is written on this installation, by role, taken
    only from locations(). Raises BackupRefused if the backup names a role this
    installation has no place for, or an unsafe drop-in name. Used to refuse before
    anything changes, and to show the plan before the confirmation."""
    where = locations(service)
    plan: dict[str, Path] = {}
    for role in opened.files:
        if role.startswith("drop_ins/"):
            if not _safe_drop_in_name(role[len("drop_ins/"):]):
                raise BackupRefused(f"the backup has an unsafe drop-in name: {role!r}")
            continue
        path = where.get(role)
        if path is None:
            raise BackupRefused(f"the backup names a piece this installation has no place for: {role!r}")
        if role == "proxmox_ca" and not _beside(path, service.proxmox):
            raise BackupRefused(f"the Proxmox settings name their CA outside nervus's secrets folder ({path}); "
                                "restore writes it only beside them: name it there, then restore again")
        plan[role] = path
    return plan


def _beside(path: Path, settings: Path | None) -> bool:
    """Whether `path` is a file directly beside `settings`, judged by name alone.
    The Proxmox settings are nervus's account's to edit, so the CA place they name
    is honoured only in nervus's own secrets folder, never anywhere root reads
    (ADR-0027, amendment 2026-11-13). By name, not resolved: a symlink there is
    replaced by the rename that puts the file in place, never written through."""
    if settings is None:
        return False
    return Path(os.path.normpath(path)).parent == Path(os.path.normpath(settings)).parent


def pieces(service: Service) -> Pieces:
    """What a backup of this installation holds: every required piece, and
    each other piece the installation has."""
    where = locations(service)
    present = {role: path for role, path in where.items()
               if role in REQUIRED or (path is not None and path.is_file())}
    return Pieces(**present, drop_ins=tuple(service.drop_ins))


def backups_folder(service: Service) -> Path:
    return service.database.parent / "backups"


# --- what the UI and `status` show (questions 4 and 7a) ---------------------------------

# Newer than this, a backup is "a day" old: the timer runs daily, up to an hour
# late at random (RandomizedDelaySec), so a little slack.
STALE_HOURS = 26


@dataclass(frozen=True)
class BackupFile:
    name: str
    size: int
    made_at: float
    # For the backup made before an upgrade and kept until the next (ADR-0029 step 7): the release
    # it was made before the upgrade to. None for a backup the daily keeping holds.
    kept_before: str | None = None


def listing(folder: Path) -> list[BackupFile]:
    """The backups in `folder`, newest first, a kept one after the daily one
    of the same moment; none if it cannot be read."""
    from nervus.backup import kept, made_at
    found = []
    try:
        for path in folder.iterdir():
            made, release = made_at(path.name), None
            if made is None and (named := kept(path.name)) is not None:
                made, release = named
            if made is not None and path.is_file():
                found.append(BackupFile(name=path.name, size=path.stat().st_size, made_at=made.timestamp(),
                                        kept_before=release))
    except OSError:
        return []
    return sorted(found, key=lambda b: (-b.made_at, b.kept_before is not None))


def stale(backups: list[BackupFile], now: float | None = None) -> str:
    """The warning a day without a new backup gives, or "" (question 4)."""
    now = time.time() if now is None else now
    if not backups:
        return "No backup of nervus has been made yet."
    if now - backups[0].made_at > STALE_HOURS * 3600:
        return f"No backup of nervus for more than a day: the newest was made {_when(backups[0].made_at)}."
    return ""


def _when(timestamp: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(timestamp))


def events(database) -> list[tuple]:
    """(kind, file, made_at, at) of every backup made, checked, downloaded or
    restored, oldest first."""
    with database.transaction(write=False) as db:
        return db.execute("SELECT kind, file, made_at, at FROM backup_event ORDER BY at").fetchall()


def restored_note(rows: list[tuple]) -> str:
    """After a restore, until a backup is made after it (question 6)."""
    restored = [e for e in rows if e[0] == "restored"]
    if not restored or [e for e in rows if e[0] == "made" and e[3] > restored[-1][3]]:
        return ""
    return (f"Restored from a backup made {_when(restored[-1][2])}: machines enrolled and tokens issued after it "
            "are not here.")


def backup_now(service: Service, database, audit, tool: str = "ui"):
    """One backup and the keeping, as `nervus-ctl backup` makes it, from inside
    nervus, which runs as its own account: the UI's button."""
    from nervus.backup import make_backup, made_at, recipient
    made = make_backup(pieces(service), recipient(service.recovery_key), backups_folder(service), audit, tool=tool)
    with database.transaction() as db:
        db.execute("INSERT INTO backup_event (kind, file, made_at, at) VALUES ('made', ?, ?, ?)",
                   (made.path.name, made_at(made.path.name).timestamp(), time.time()))
    return made


# --- opening and checking a backup -----------------------------------------------------


@dataclass
class Opened:
    """A backup opened in memory: its manifest, each piece but the audit log by
    role, and the audit log's size and SHA-256 (and its staged copy, if one
    was asked for)."""

    path: Path
    manifest: dict
    files: dict[str, bytes] = field(default_factory=dict)
    log_size: int = 0
    log_sha256: str = ""
    staged_log: Path | None = None
    # (device, inode) of the staged copy as restore made it: its name alone is not proof,
    # in a folder nervus's account can change (procedure 058).
    staged_id: tuple[int, int] | None = None

    @property
    def made_at(self) -> float:
        return float(self.manifest["made_at"])


def open_backup(path: Path, identity: str, stage_log: Path | None = None) -> Opened:
    """Open the backup at `path` with the recovery key's private half
    `identity`, and check that each piece is the one its manifest names.
    With `stage_log`, the audit log is written there (0600) as it is read;
    otherwise it is only hashed. Raises BackupRefused."""
    age = shutil.which("age")
    if age is None:
        raise BackupRefused("age is not installed, so no backup can be opened")
    try:
        backup = plainfile.open_file(path)
    except FileNotFoundError:
        raise BackupRefused(f"no backup at {path}") from None
    except OSError as exc:
        raise BackupRefused(f"cannot open {path}: {exc}") from exc
    with backup:
        read_end, write_end = os.pipe()
        try:
            os.write(write_end, identity.strip().encode() + b"\n")
        finally:
            os.close(write_end)
        try:
            # age is given the backup already open, as its standard input, and never its name:
            # a name is whatever is at it when age opens it, a pipe to wait on included.
            process = subprocess.Popen([age, "--decrypt", "--identity", f"/dev/fd/{read_end}"], stdin=backup,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=(read_end,))
        finally:
            os.close(read_end)
    opened = Opened(path=path, manifest={}, staged_log=stage_log)
    try:
        _read_archive(process.stdout, opened, stage_log)
    except (tarfile.TarError, OSError, EOFError, ValueError) as exc:
        process.kill()
        process.wait()
        error = process.stderr.read().decode().strip()
        _unstage(stage_log)
        raise BackupRefused(f"cannot open {path}: {_age_words(error) or exc}") from exc
    except BackupRefused:
        process.kill()
        process.wait()
        _unstage(stage_log)
        raise
    process.stdout.close()
    error = process.stderr.read().decode().strip()
    if process.wait() != 0:
        _unstage(stage_log)
        raise BackupRefused(f"cannot open {path}: {_age_words(error)}")
    try:
        _matches_manifest(opened)
    except BackupRefused:
        _unstage(stage_log)
        raise
    return opened


def _age_words(error: str) -> str:
    if "no identity matched" in error:
        return "the recovery key given is not the one this backup was locked to"
    return error


def _unstage(stage_log: Path | None) -> None:
    if stage_log is not None:
        stage_log.unlink(missing_ok=True)


def _read_archive(stream, opened: Opened, stage_log: Path | None) -> None:
    with tarfile.open(fileobj=stream, mode="r|gz") as archive:
        for member in archive:
            if not member.isfile():
                raise BackupRefused(f"{member.name} in it is not a file")
            data = archive.extractfile(member)
            if member.name == "pieces/audit_log":
                opened.log_size, opened.log_sha256, opened.staged_id = _copy_log(data, stage_log)
            elif member.name == "manifest.json":
                opened.manifest = json.loads(data.read())
            elif member.name.startswith("pieces/"):
                opened.files[member.name[len("pieces/"):]] = data.read()
            else:
                raise BackupRefused(f"{member.name} in it is not a piece of a backup")


def _copy_log(data, stage_log: Path | None) -> tuple[int, str, tuple[int, int] | None]:
    """The log's size and SHA-256, and, staged, which file that is: (device, inode)."""
    digest, size = hashlib.sha256(), 0
    out, made = None, None
    if stage_log is not None:
        fd = os.open(stage_log, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        status = os.fstat(fd)
        made = (status.st_dev, status.st_ino)
        out = os.fdopen(fd, "wb")
    with out if out is not None else contextlib.nullcontext():
        while block := data.read(CHUNK):
            digest.update(block)
            size += len(block)
            if out is not None:
                out.write(block)
        if out is not None:
            out.flush()
            os.fsync(out.fileno())
    return size, digest.hexdigest(), made


def _matches_manifest(opened: Opened) -> None:
    manifest = opened.manifest
    if manifest.get("format") != FORMAT:
        raise BackupRefused(f"{opened.path} is not a backup this nervus can read (format {manifest.get('format')})")
    listed = {piece["role"]: piece for piece in manifest.get("pieces", [])}
    bad = sorted(r for r in listed if r not in VALID_ROLES and not r.startswith("drop_ins/"))
    if bad:
        raise BackupRefused(f"{opened.path} names pieces nervus does not know: {bad}")
    unsafe = sorted(r for r in listed if r.startswith("drop_ins/") and not _safe_drop_in_name(r[len("drop_ins/"):]))
    if unsafe:
        raise BackupRefused(f"{opened.path} has unsafe drop-in names: {unsafe}")
    found = set(opened.files) | ({"audit_log"} if opened.log_sha256 else set())
    if found != set(listed):
        missing, extra = sorted(set(listed) - found), sorted(found - set(listed))
        raise BackupRefused(f"{opened.path} is not whole: missing {missing}, unlisted {extra}")
    for role, data in opened.files.items():
        if hashlib.sha256(data).hexdigest() != listed[role]["sha256"]:
            raise BackupRefused(f"{opened.path} is damaged: {role} is not what its manifest says")
    if (opened.log_size, opened.log_sha256) != (listed["audit_log"]["size"], listed["audit_log"]["sha256"]):
        raise BackupRefused(f"{opened.path} is damaged: audit_log is not what its manifest says")
    for role in REQUIRED:
        if role not in listed:
            raise BackupRefused(f"{opened.path} has no {role}")


def check_contents(opened: Opened) -> None:
    """Question 5's checks: the database whole and of this release, and each
    private key matching its public half. Raises BackupRefused."""
    data = bytearray(opened.files["database"])
    if len(data) >= 20 and data[18:20] == b"\x02\x02":
        # Write-ahead logging is marked in the header (bytes 18 and 19), and an
        # in-memory copy cannot have one. Checked as an ordinary file; the file
        # a restore writes keeps its mark.
        data[18:20] = b"\x01\x01"
    with contextlib.closing(sqlite3.connect(":memory:")) as db:
        try:
            db.deserialize(bytes(data))
            result = db.execute("PRAGMA integrity_check").fetchone()[0]
            version = db.execute("PRAGMA user_version").fetchone()[0]
        except sqlite3.Error as exc:
            raise BackupRefused(f"its database is damaged: {exc}") from exc
    if result != "ok":
        raise BackupRefused(f"its database fails SQLite's integrity check: {result}")
    if version > SCHEMA_VERSION:
        raise BackupRefused(f"its database is version {version}, made by a newer release of nervus; this one "
                            f"knows version {SCHEMA_VERSION}. Restore it with that release or a later one")
    if version != SCHEMA_VERSION:
        raise BackupRefused(f"its database is version {version}; this nervus knows version {SCHEMA_VERSION}")
    for private, public in (("ssh_key", "ssh_key_pub"), ("ssh_ca_key", "ssh_ca_key_pub")):
        if public in opened.files and _ssh_public(opened.files, private) != opened.files[public].split()[:2]:
            raise BackupRefused(f"its {private} does not match its public half")
        _ssh_public(opened.files, private)
    for key, cert in (("tls_key", "tls_cert"), ("tls_issuer_key", "tls_issuer_cert")):
        if key in opened.files and cert in opened.files and _tls_public(opened.files, key) != _cert_public(opened.files, cert):
            raise BackupRefused(f"its {key} does not match its certificate {cert}")


def _ssh_public(files: dict[str, bytes], role: str) -> list[bytes]:
    try:
        return asyncssh.import_private_key(files[role]).export_public_key("openssh").split()[:2]
    except (asyncssh.KeyImportError, ValueError) as exc:
        raise BackupRefused(f"its {role} is not a key nervus can read: {exc}") from exc


def _der(public) -> bytes:
    return public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _tls_public(files: dict[str, bytes], role: str) -> bytes:
    try:
        return _der(serialization.load_pem_private_key(files[role], password=None).public_key())
    except (ValueError, TypeError) as exc:
        raise BackupRefused(f"its {role} is not a key nervus can read: {exc}") from exc


def _cert_public(files: dict[str, bytes], role: str) -> bytes:
    try:
        return _der(x509.load_pem_x509_certificates(files[role])[0].public_key())
    except ValueError as exc:
        raise BackupRefused(f"its {role} is not a certificate nervus can read: {exc}") from exc


def log_begins_with(log: Path, size: int, sha256: str, dir_fd: int | None = None) -> bool:
    """Whether the audit log at `log` begins with `size` bytes whose SHA-256 is
    `sha256`: the backup's log, with whatever was written since after it. With
    `dir_fd`, the log is looked up by its name in the folder open there. A link, a
    pipe or anything else that is not a plain file does not begin with it: it is
    never followed and never waited on."""
    try:
        fd = os.open(log.name if dir_fd is not None else log, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=dir_fd)
    except FileNotFoundError:
        return False
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK, errno.ENXIO):
            return False
        raise
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return False
        digest, left = hashlib.sha256(), size
        while left:
            block = f.read(min(CHUNK, left))
            if not block:
                return False
            digest.update(block)
            left -= len(block)
    return digest.hexdigest() == sha256


# --- putting a backup in place --------------------------------------------------------


@dataclass
class Placed:
    replaced: Path
    kept_log: bool
    drop_ins_differ: list[str]


def place(opened: Opened, service: Service, owner: tuple[int, int] | None, now: float | None = None) -> Placed:
    """Question 5's steps 3 and 4, and the switch of step 5: move what each
    piece replaces aside, then put each piece where this installation's unit
    puts its role. nervus must be stopped first; `opened` must have its audit
    log staged. `owner` is (uid, gid) of nervus's account, or None to leave
    files as the caller's.

    Everything that can be refused is refused first, before anything is moved
    (BackupRefused: nothing was replaced). From then on each folder is used
    through the handle opened here, never again by its path: nervus's account
    owns those folders, and a name in them proves nothing (ADR-0027, amendment
    2026-11-13)."""
    now = time.time() if now is None else now
    where = locations(service)
    destinations(opened, service)  # an unknown role, an unsafe drop-in name, a CA outside the secrets folder
    check_places(opened, service)  # a link where a folder belongs, or something that is not a file where one goes
    listed = {piece["role"]: piece for piece in opened.manifest["pieces"]}
    roles = [role for role in opened.files if not role.startswith("drop_ins/")]
    log, switch = where["audit_log"], where["switches"]
    folders: dict[Path, int] = {}
    handles: list[int] = []

    def folder(path: Path) -> int:
        """The handle on `path`'s folder: opened once, and made if it is missing."""
        parent = Path(os.path.normpath(path.parent))
        if parent not in folders:
            folders[parent] = _open_folder(parent, owner, make=True)
        return folders[parent]

    try:
        for path in (*(where[role] for role in roles), switch, log, service.database):
            folder(path)
        if opened.staged_log is None:
            raise BackupRefused("the backup's audit log was not staged for this restore")
        staged_name, staged_folder = opened.staged_log.name, folder(opened.staged_log)
        staged = _open_staged(opened, staged_folder)
        handles.append(staged)
        replaced, kept, aside = _kept_folder(service.database.parent, now)
        handles += [kept, aside]
        # Nothing is refused from here on.

        # The database's write-ahead files go with it: a log left beside a new
        # database would be read into it.
        for suffix in ("-wal", "-shm"):
            _move_into(folder(service.database), service.database.name + suffix, "database" + suffix, aside)
        for role in roles:
            path = where[role]
            _move_into(folder(path), path.name, role, aside)
            _write_in(folder(path), path.name, opened.files[role], _safe_mode(role, listed[role]["mode"]), owner)

        switches = yaml.safe_load(opened.files["switches"]) or {}
        lockdown = yaml.safe_dump({"lockdown": True, "disabled": sorted(switches.get("disabled") or [])})
        _write_in(folder(switch), switch.name, lockdown.encode(), _safe_mode("switches", listed["switches"]["mode"]),
                  owner)

        kept_log = log_begins_with(log, opened.log_size, opened.log_sha256, dir_fd=folder(log))
        if kept_log:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(staged_name, dir_fd=staged_folder)
        else:
            _move_into(folder(log), log.name, "audit_log", aside)
            # Through the handle on the file restore staged, never its name.
            os.fchmod(staged, _safe_mode("audit_log", listed["audit_log"]["mode"]))
            if owner is not None:
                os.fchown(staged, *owner)
            os.rename(staged_name, log.name, src_dir_fd=staged_folder, dst_dir_fd=folder(log))

        differ = []
        current = {path.name: path for path in service.drop_ins}
        saved = None
        for role, data in opened.files.items():
            if role.startswith("drop_ins/"):
                name = role[len("drop_ins/"):]
                if name not in current or current[name].read_bytes() != data:
                    differ.append(name)
                    if saved is None:
                        saved = _open_subfolder(kept, "backup-drop-ins", replaced)
                        handles.append(saved)
                    _keep_bytes(saved, name, data)
    finally:
        for fd in (*handles, *folders.values()):
            os.close(fd)
    return Placed(replaced=replaced, kept_log=kept_log, drop_ins_differ=differ)


# --- folders another account can change --------------------------------------------------------
#
# restore runs as root and writes into folders nervus's own account owns: its secrets, its
# state, its log's folder. Inside such a folder that account can make any name a link, and
# can swap one name for another while restore waits or runs. So restore reaches each folder
# without following a link that an account other than root could have put there, and then
# acts through the folder's handle (procedure 058; ADR-0027, amendment 2026-11-13).


def _changeable(status: os.stat_result) -> bool:
    """Whether an account other than root, or the one running this, can change what
    the folder with this status holds: it is another account's, or others may write it."""
    return status.st_uid not in (0, os.geteuid()) or bool(status.st_mode & 0o022)


def _open_folder(path: Path, owner: tuple[int, int] | None = None, make: bool = False) -> int:
    """A handle on the folder `path`, reached without following any link that sits
    in a folder another account can change. With `make`, a missing folder is made,
    0700, and given to `owner`. Raises BackupRefused for such a link or for
    anything there that is not a folder, and FileNotFoundError for a folder that
    is missing and not made."""
    parts = Path(os.path.normpath(path)).parts
    walked = Path(parts[0])
    fd = os.open(parts[0], os.O_RDONLY | os.O_DIRECTORY)
    try:
        distrusted = False
        for part in parts[1:]:
            distrusted = distrusted or _changeable(os.fstat(fd))
            walked = walked / part
            flags = os.O_RDONLY | os.O_DIRECTORY | (os.O_NOFOLLOW if distrusted else 0)
            try:
                inner = os.open(part, flags, dir_fd=fd)
            except FileNotFoundError:
                if not make:
                    raise
                os.mkdir(part, 0o700, dir_fd=fd)
                inner = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                if owner is not None:
                    try:
                        os.fchown(inner, *owner)
                    except BaseException:
                        os.close(inner)
                        raise
            except OSError as exc:
                if exc.errno not in (errno.ELOOP, errno.ENOTDIR, errno.EMLINK):
                    raise
                if _kind(fd, part) == "link":
                    raise BackupRefused(
                        f"{walked} is a symbolic link where a folder belongs, in a folder another account can "
                        "change, and restore follows no link there; remove it, then restore again") from None
                raise BackupRefused(f"{walked} is not a folder; remove it, then restore again") from None
            os.close(fd)
            fd = inner
        return fd
    except BaseException:
        os.close(fd)
        raise


def _kind(dir_fd: int, name: str) -> str | None:
    """What is at `name` in the folder open as `dir_fd`, itself and not what it may
    name: None for nothing, else "file", "link", "folder", "pipe", "socket" or "device"."""
    try:
        mode = os.stat(name, dir_fd=dir_fd, follow_symlinks=False).st_mode
    except FileNotFoundError:
        return None
    for test, kind in ((stat.S_ISREG, "file"), (stat.S_ISLNK, "link"), (stat.S_ISDIR, "folder"),
                       (stat.S_ISFIFO, "pipe"), (stat.S_ISSOCK, "socket")):
        if test(mode):
            return kind
    return "device"


def places(opened: Opened, service: Service) -> list[Path]:
    """Every path restore writes, or moves aside, for `opened`."""
    where = locations(service)
    paths = [where[role] for role in opened.files if not role.startswith("drop_ins/") and where.get(role)]
    paths += [where["switches"], where["audit_log"]]
    return paths + [service.database.with_name(service.database.name + suffix) for suffix in ("-wal", "-shm")]


def check_places(opened: Opened, service: Service) -> None:
    """Refuse, before anything changes, a place restore could not write safely: one
    reached through a link in a folder another account can change, or one that
    holds something other than a file (or a link, which is moved aside as a link).
    A folder there once made restore fail half-way, and a pipe made it wait for
    ever, both after nervus was stopped. Raises BackupRefused."""
    for path in places(opened, service):
        try:
            fd = _open_folder(path.parent)
        except FileNotFoundError:
            continue  # made, through a handle, when the piece is put there
        try:
            kind = _kind(fd, path.name)
        finally:
            os.close(fd)
        if kind not in (None, "file", "link"):
            raise BackupRefused(f"{path} is a {kind}, not a file, and restore replaces only files; "
                                "remove it, then restore again")


def _open_staged(opened: Opened, dir_fd: int) -> int:
    """A handle on the audit log staged for this restore, if the file at its name is
    still the one restore made. It was staged in the log's folder, which nervus's
    account can change, before the operator confirmed and while nervus still ran:
    a link swapped in there would carry root's chmod and chown to whatever it
    names. Raises BackupRefused."""
    gone = (f"the audit log staged for this restore, {opened.staged_log}, was removed or swapped for something "
            "else while restore waited")
    try:
        fd = os.open(opened.staged_log.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    except OSError:
        raise BackupRefused(gone) from None
    status = os.fstat(fd)
    if (status.st_dev, status.st_ino) != opened.staged_id or not stat.S_ISREG(status.st_mode):
        os.close(fd)
        raise BackupRefused(gone)
    return fd


# The folder that keeps what a restore replaces is named for this, then the time, then random
# characters (docs/install.md leaves `replaced-*` out of a container backup).
KEPT_PREFIX = "replaced-"


def _kept_folder(parent: Path, now: float) -> tuple[Path, int, int]:
    """The dated folder that keeps what a restore replaces, beside the database, and
    its `pieces` folder: (its path, a handle on it, a handle on `pieces`).

    nervus's account owns the folder it is made in, so it could plant a link at any
    name it can guess, or swap the new folder for one while the restore runs. The
    name ends in random characters and is made exclusively; the folder is opened at
    once without following a link and must be root's own, 0700, as made; and
    everything inside it is done through these handles, never by path again
    (ADR-0027, amendment 2026-11-13)."""
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now))
    path = Path(tempfile.mkdtemp(dir=parent, prefix=f"{KEPT_PREFIX}{stamp}-"))
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise BackupRefused(f"the folder made to keep what is replaced, {path}, was swapped for something else "
                            f"before it could be opened ({exc.strerror})") from None
    made = os.fstat(fd)
    if made.st_uid != os.geteuid() or stat.S_IMODE(made.st_mode) != 0o700:
        os.close(fd)
        raise BackupRefused(f"the folder made to keep what is replaced, {path}, was swapped for another")
    try:
        return path, fd, _open_subfolder(fd, "pieces", path)
    except BaseException:
        os.close(fd)
        raise


def _open_subfolder(dir_fd: int, name: str, where: Path) -> int:
    """Make folder `name` inside the folder open as `dir_fd`, and open it, never
    following a link."""
    try:
        os.mkdir(name, 0o700, dir_fd=dir_fd)
        return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)
    except OSError as exc:
        raise BackupRefused(f"could not make {where / name} to keep what is replaced ({exc.strerror})") from None


def _move_into(dir_fd: int, name: str, kept: str, aside: int) -> None:
    """Move what is at `name` in the folder open as `dir_fd` -- a file, or a link,
    itself and never what it names -- into the folder open as `aside`, as `kept`.
    Across filesystems it is copied, then removed."""
    try:
        mode = os.stat(name, dir_fd=dir_fd, follow_symlinks=False).st_mode
    except FileNotFoundError:
        return
    try:
        os.rename(name, kept, src_dir_fd=dir_fd, dst_dir_fd=aside)
        return
    except OSError as exc:
        if exc.errno != errno.EXDEV:
            raise
    if stat.S_ISLNK(mode):
        os.symlink(os.readlink(name, dir_fd=dir_fd), kept, dir_fd=aside)
    elif stat.S_ISREG(mode):
        src = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
        try:
            dst = os.open(kept, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                          stat.S_IMODE(os.fstat(src).st_mode), dir_fd=aside)
            try:
                while chunk := os.read(src, CHUNK):
                    _write_all(dst, chunk)
            finally:
                os.close(dst)
        finally:
            os.close(src)
    os.unlink(name, dir_fd=dir_fd)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


def _keep_bytes(dir_fd: int, name: str, data: bytes) -> None:
    """Write `data` as a new file `name`, owner-only, in the folder open as `dir_fd`."""
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dir_fd)
    try:
        _write_all(fd, data)
    finally:
        os.close(fd)


def _write_in(dir_fd: int, name: str, data: bytes, mode: int, owner: tuple[int, int] | None) -> None:
    """Write `data` as `name` in the folder open as `dir_fd`: beside, then renamed
    over, so a reader sees the old file or the new, never half of one. The staging
    file has an unpredictable name and is made exclusively; its mode and owner are
    set through its handle; and it is renamed within the folder's handle. So no
    link at any name, and none swapped in for the folder, is followed or written
    through (procedure 056, finding 1; procedure 058)."""
    staging = f".{name}.{os.urandom(8).hex()}.restore-new"
    fd = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dir_fd)
    try:
        try:
            _write_all(fd, data)
            os.fchmod(fd, mode)
            if owner is not None:
                os.fchown(fd, *owner)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(staging, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(staging, dir_fd=dir_fd)
        raise


# Run as nervus's account once the database is in place (question 5 step 5).
CLEAR_SHORT_LIVED = """
DELETE FROM session;
DELETE FROM signin_link;
DELETE FROM enrollment_login WHERE code_id IN (SELECT id FROM enrollment_code WHERE used_at IS NULL);
DELETE FROM enrollment_code WHERE used_at IS NULL;
"""
