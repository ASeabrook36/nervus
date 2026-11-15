"""The export store (ADR-0016): copies of files a client asked nervus to fetch,
kept until the client downloads them, and the record of each in the database.

What it holds to:

- **Only the token that made an export ever reaches it** (decision B). Every
  lookup is by token and id together; another token's id is simply not found.
- **Space is reserved before anything is copied** (decision D), inside one
  database transaction, which SQLite lets only one writer hold at a time. So
  two exports made at once cannot both pass the check. The total counts copies
  still being made, and the free-space floor counts what they have yet to
  write, so the audit log, on the same filesystem, always has room.
- **A copy can never outgrow its reservation.** The writer counts every byte
  and refuses the one that would pass the size the source declared.
- **A finished export never changes, and its id is never reused** (decision F).
  The copy is written under a name ending `.part`, then renamed to its id and
  made read-only. Ids are 128 random bits.
- **The client never names a path here** (decision G). Files are named by
  nervus, created exclusively and never through a link, and opened for
  download only by a recorded id, as a regular file, not through a link.
- **Exports last 24 hours** (decision E), then are deleted. A restart fails
  any copy that was being made and deletes what it left.

How a file is fetched from a host or a VM is the sources' business (step 2);
the tool and the download route (steps 3 and 4) use this module.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from nervus.config import ConfigError
from nervus.database import Database

MiB = 1024 * 1024
GiB = 1024 * MiB

# ADR-0016 decision D.
MAX_EXPORT_BYTES = 256 * MiB
MAX_TOTAL_BYTES = 1 * GiB
FREE_FLOOR_BYTES = 2 * GiB
# ADR-0016 decision E: 24 hours from when it is made.
LIFETIME_SECONDS = 24 * 3600
# A spent export's record is kept this long after it expired, so asking again
# with the same request key says what became of it rather than starting over.
KEEP_SPENT_SECONDS = 24 * 3600

ID = re.compile(r"[0-9a-f]{32}")
ID_BYTES = 16
REQUEST_KEY = re.compile(r"[A-Za-z0-9._:-]{1,128}")
FILENAME_CHARACTERS = 255
PART = ".part"

# What an export can be. `staging`: being copied. `ready`: whole, checked, and
# downloadable. `failed`: it will never be ready; `failure_code` says why.
# `expired` and `deleted`: it was ready, and its file is gone.
STAGING, READY, FAILED, EXPIRED, DELETED = "staging", "ready", "failed", "expired", "deleted"
HOLDS_SPACE = (STAGING, READY)


# Uploads (ADR-0020 decision F) share these ceilings: the space either holds
# counts against both. An upload holds space while it is `receiving` or
# `delivering`; only a `receiving` one has bytes still to write. uploads.py
# names the same states.
UPLOAD_HOLDS_SPACE = ("receiving", "delivering")
UPLOAD_RECEIVING = "receiving"


def held_bytes(db) -> int:
    """What exports and uploads together hold or have reserved."""
    return db.execute(
        f"SELECT (SELECT COALESCE(SUM(reserved_bytes), 0) FROM export WHERE state IN {HOLDS_SPACE}) + "
        f"(SELECT COALESCE(SUM(reserved_bytes), 0) FROM upload WHERE state IN {UPLOAD_HOLDS_SPACE})"
    ).fetchone()[0]


def unwritten_bytes(db) -> int:
    """What copies still being made, of either kind, have yet to write."""
    return db.execute(
        "SELECT (SELECT COALESCE(SUM(reserved_bytes - bytes_written), 0) FROM export WHERE state = ?) + "
        "(SELECT COALESCE(SUM(reserved_bytes - bytes_received), 0) FROM upload WHERE state = ?)",
        (STAGING, UPLOAD_RECEIVING),
    ).fetchone()[0]


class ExportRefused(Exception):
    """An export that cannot be made, continued or read. `code` is for the
    client and the audit log; the message says what to do in words."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Limits:
    max_export_bytes: int = MAX_EXPORT_BYTES
    max_total_bytes: int = MAX_TOTAL_BYTES
    free_floor_bytes: int = FREE_FLOOR_BYTES
    lifetime_seconds: float = LIFETIME_SECONDS


@dataclass(frozen=True)
class Export:
    id: str
    token_id: str
    request_key: str
    source: dict
    filename: str
    state: str
    reserved_bytes: int
    bytes_written: int
    size: int | None
    sha256: str | None
    failure_code: str | None
    failure_message: str | None
    made_at: float
    expires_at: float
    finished_at: float | None


_COLUMNS = ("id, token_id, request_key, source, filename, state, reserved_bytes, bytes_written, size, "
            "sha256, failure_code, failure_message, made_at, expires_at, finished_at")


def _export(row: tuple, now: float) -> Export:
    values = list(row)
    values[3] = json.loads(values[3])
    export = Export(*values)
    # A ready export past its time is expired, whether or not a sweep has yet
    # deleted its file.
    if export.state == READY and export.expires_at <= now:
        return dataclasses.replace(export, state=EXPIRED)
    return export


def _now(now: float | None) -> float:
    return time.time() if now is None else now


def safe_filename(name: str) -> str:
    """The name a client is told to save the file as: the source's last path
    part, without control characters, never empty, never a path."""
    name = name.replace("\\", "/").rsplit("/", 1)[-1]
    name = "".join(c for c in name if c.isprintable())
    name = name.strip().lstrip(".") or "export"
    return name[:FILENAME_CHARACTERS]


class StagingWriter:
    """Writes one export's copy, hashing and counting as it goes, and refuses
    any byte past what was reserved. Made only by ExportStore.writer()."""

    def __init__(self, path: Path, limit: int):
        self.path = path
        self.limit = limit
        self.written = 0
        self._hash = hashlib.sha256()
        # O_EXCL: never an existing file, and with O_CREAT not through a link
        # either. O_NOFOLLOW for platforms that check it first.
        try:
            self._fd: int | None = os.open(
                path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
            )
        except FileExistsError as exc:
            raise ExportRefused("staging_exists", f"a staging file for this export already exists: {path.name}") from exc

    def write(self, data: bytes) -> None:
        if self._fd is None:
            raise ExportRefused("closed", "this export's copy is already closed")
        if self.written + len(data) > self.limit:
            raise ExportRefused(
                "grew",
                f"the source grew past the {self.limit} bytes it declared while it was being copied; "
                f"export it again once it has stopped changing",
            )
        view = memoryview(data)
        while view:
            done = os.write(self._fd, view)
            view = view[done:]
        self._hash.update(data)
        self.written += len(data)

    @property
    def sha256(self) -> str:
        return self._hash.hexdigest()

    def _seal(self) -> None:
        """Flush to disk and make the copy read-only."""
        assert self._fd is not None
        os.fsync(self._fd)
        os.fchmod(self._fd, 0o400)
        self.close()

    def close(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None


class ExportStore:
    def __init__(self, database: Database, directory: Path, *, limits: Limits = Limits(),
                 free_bytes: Callable[[], int] | None = None):
        self.database = database
        self.directory = Path(directory)
        self.limits = limits
        self._free_bytes = free_bytes or (lambda: shutil.disk_usage(self.directory).free)

    # --- start ------------------------------------------------------------------

    def open(self, now: float | None = None) -> None:
        """Make the directory if it is missing, check it, and recover from a
        stop: run once when nervus starts, after the database is open."""
        try:
            self.directory.mkdir(mode=0o700)
        except FileExistsError:
            pass
        except OSError as exc:
            raise ConfigError(f"cannot create the exports directory {self.directory}: {exc}") from exc
        info = self.directory.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ConfigError(f"the exports directory {self.directory} must be a directory, not a link")
        if info.st_mode & 0o077:
            raise ConfigError(
                f"the exports directory {self.directory} is mode {oct(stat.S_IMODE(info.st_mode))}; "
                f"it must be readable by nervus alone (0700)"
            )
        self.recover(now)

    def recover(self, now: float | None = None) -> None:
        """After a stop: a copy that was being made will never finish, so fail
        it; delete every file that is not a ready export's; and fail a ready
        export whose file has gone."""
        now = _now(now)
        with self.database.transaction() as db:
            db.execute(
                "UPDATE export SET state = ?, reserved_bytes = 0, failure_code = 'interrupted', "
                "failure_message = 'nervus stopped while the copy was being made; ask again with a new request key', "
                "finished_at = ? WHERE state = ?",
                (FAILED, now, STAGING),
            )
            ready = {row[0] for row in db.execute("SELECT id FROM export WHERE state = ?", (READY,))}
            present = set()
            for entry in self.directory.iterdir():
                if entry.name in ready and not entry.is_symlink() and entry.is_file():
                    present.add(entry.name)
                else:
                    entry.unlink(missing_ok=True)
            for lost in ready - present:
                db.execute(
                    "UPDATE export SET state = ?, reserved_bytes = 0, failure_code = 'lost', "
                    "failure_message = 'its file is missing; export it again', finished_at = ? WHERE id = ?",
                    (FAILED, now, lost),
                )
        self.sweep(now)

    # --- making an export ---------------------------------------------------------

    def begin(self, token_id: str, request_key: str, source: dict, filename: str, size: int,
              now: float | None = None) -> tuple[Export, bool]:
        """Reserve space for a copy of `size` bytes, and record the export. If
        this token already made one with this request key, return that one
        instead, and False: a retry never starts a second copy (decision I).
        Raises ExportRefused if the copy would pass a limit."""
        now = _now(now)
        if not isinstance(request_key, str) or not REQUEST_KEY.fullmatch(request_key):
            raise ExportRefused("bad_request_key",
                                "a request key is 1 to 128 letters, digits, '.', '_', ':' or '-'")
        if not isinstance(size, int) or size < 0:
            raise ExportRefused("bad_size", f"the source reported no usable size: {size!r}")
        with self.database.transaction() as db:
            existing = self._by_key(db, token_id, request_key, now)
            if existing is not None:
                return existing, False
            if size > self.limits.max_export_bytes:
                raise ExportRefused(
                    "too_large",
                    f"the file is {size} bytes; one export is at most {self.limits.max_export_bytes}. "
                    f"Split it at the source into parts under that size",
                )
            held = held_bytes(db)
            if held + size > self.limits.max_total_bytes:
                raise ExportRefused(
                    "quota",
                    f"exports and uploads already hold {held} of {self.limits.max_total_bytes} bytes; "
                    f"delete finished exports, or wait for them to expire",
                )
            if self._free_bytes() - unwritten_bytes(db) - size < self.limits.free_floor_bytes:
                raise ExportRefused(
                    "disk_floor",
                    f"copying it would leave nervus's disk under {self.limits.free_floor_bytes} bytes free, "
                    f"which the audit log needs; try later or with a smaller file",
                )
            export_id = secrets.token_hex(ID_BYTES)
            db.execute(
                f"INSERT INTO export ({_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL, NULL, NULL, NULL, ?, ?, NULL)",
                (export_id, token_id, request_key, json.dumps(source, sort_keys=True), safe_filename(filename),
                 STAGING, size, now, now + self.limits.lifetime_seconds),
            )
            return self._by_id(db, export_id, now), True

    def refuse(self, token_id: str, request_key: str, source: dict, filename: str, code: str, message: str,
               now: float | None = None) -> Export:
        """Record an export that failed before any space was reserved: the
        source was not a file, could not hash, or the limits refused it. The
        request key then keeps that answer, as it would any other (decision
        I); asking again means a new key. If the key already has an export,
        that one is returned instead."""
        now = _now(now)
        with self.database.transaction() as db:
            existing = self._by_key(db, token_id, request_key, now)
            if existing is not None:
                return existing
            export_id = secrets.token_hex(ID_BYTES)
            db.execute(
                f"INSERT INTO export ({_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, 0, 0, NULL, NULL, ?, ?, ?, ?, ?)",
                (export_id, token_id, request_key, json.dumps(source, sort_keys=True), safe_filename(filename),
                 FAILED, code, message, now, now + self.limits.lifetime_seconds, now),
            )
            return self._by_id(db, export_id, now)

    def writer(self, export: Export) -> StagingWriter:
        """Start writing a staging export's copy."""
        if export.state != STAGING:
            raise ExportRefused("not_staging", f"export {export.id} is {export.state}, not being copied")
        return StagingWriter(self._part(export.id), export.reserved_bytes)

    def progress(self, export_id: str, bytes_written: int) -> None:
        """Record how far a copy has got, for a client asking (decision I)."""
        with self.database.transaction() as db:
            db.execute("UPDATE export SET bytes_written = ? WHERE id = ? AND state = ?",
                       (bytes_written, export_id, STAGING))

    def finish(self, export: Export, writer: StagingWriter, now: float | None = None) -> Export:
        """Seal the copy: flushed, read-only, renamed to its id. Its size and
        SHA-256 are the writer's. The reservation shrinks to the real size."""
        now = _now(now)
        writer._seal()
        final = self._final(export.id)
        os.rename(writer.path, final)
        self._sync_directory()
        with self.database.transaction() as db:
            done = db.execute(
                "UPDATE export SET state = ?, size = ?, sha256 = ?, reserved_bytes = ?, bytes_written = ?, "
                "finished_at = ? WHERE id = ? AND state = ?",
                (READY, writer.written, writer.sha256, writer.written, writer.written, now, export.id, STAGING),
            ).rowcount
            if done:
                return self._by_id(db, export.id, now)
        # Deleted, or failed by a restart, while it was being copied.
        final.unlink(missing_ok=True)
        raise ExportRefused("not_staging", f"export {export.id} was ended while it was being copied")

    def fail(self, export: Export, code: str, message: str, writer: StagingWriter | None = None,
             now: float | None = None) -> Export:
        """End a copy that will not finish: delete what it wrote, release its
        space, and record why."""
        now = _now(now)
        if writer is not None:
            writer.close()
        self._part(export.id).unlink(missing_ok=True)
        with self.database.transaction() as db:
            db.execute(
                "UPDATE export SET state = ?, reserved_bytes = 0, failure_code = ?, failure_message = ?, "
                "finished_at = ? WHERE id = ? AND state = ?",
                (FAILED, code, message, now, export.id, STAGING),
            )
            return self._by_id(db, export.id, now)

    # --- a client's exports -------------------------------------------------------

    def get(self, token_id: str, export_id: str, now: float | None = None) -> Export | None:
        """This token's export with this id, in whatever state, or None."""
        if not isinstance(export_id, str) or not ID.fullmatch(export_id):
            return None
        now = _now(now)
        with self.database.transaction(write=False) as db:
            export = self._by_id(db, export_id, now)
        return export if export is not None and export.token_id == token_id else None

    def by_key(self, token_id: str, request_key: str, now: float | None = None) -> Export | None:
        now = _now(now)
        with self.database.transaction(write=False) as db:
            return self._by_key(db, token_id, request_key, now)

    def open_ready(self, token_id: str, export_id: str, now: float | None = None) -> tuple[Export, BinaryIO] | None:
        """Open this token's ready export for download. None if the token has
        no such export, or it is not ready. Raises ExportRefused if the file
        is not the regular file of the recorded size that finish() left."""
        export = self.get(token_id, export_id, now)
        if export is None or export.state != READY:
            return None
        try:
            fd = os.open(self._final(export.id), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)  # a pipe is not waited on
        except OSError as exc:
            raise ExportRefused("lost", f"export {export.id}'s file cannot be opened: {exc.strerror}") from exc
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size != export.size:
            os.close(fd)
            raise ExportRefused("lost", f"export {export.id}'s file is not the one nervus made")
        return export, os.fdopen(fd, "rb")

    def delete(self, token_id: str, export_id: str, now: float | None = None) -> bool:
        """Delete this token's export early: its file goes, and its space is
        released. False if the token has no such export to delete."""
        export = self.get(token_id, export_id, now)
        if export is None or export.state not in HOLDS_SPACE:
            return False
        now = _now(now)
        with self.database.transaction() as db:
            gone = db.execute(
                f"UPDATE export SET state = ?, reserved_bytes = 0, finished_at = COALESCE(finished_at, ?) "
                f"WHERE id = ? AND token_id = ? AND state IN {HOLDS_SPACE}",
                (DELETED, now, export.id, token_id),
            ).rowcount
        self._final(export.id).unlink(missing_ok=True)
        # A copy still being made is ended by finish(), which finds it deleted.
        return gone > 0

    # --- the route ----------------------------------------------------------------

    def set_route(self, export_id: str, route: str) -> None:
        """How the export's copy is read: "sftp", or "guest-agent" (ADR-0022
        7a). A table of its own, so the export table and its version stay as
        a rollback expects (ADR-0014 decision F)."""
        with self.database.transaction() as db:
            db.execute("INSERT OR REPLACE INTO export_route (export_id, route) VALUES (?, ?)", (export_id, route))

    def route(self, export_id: str) -> str | None:
        with self.database.transaction(write=False) as db:
            row = db.execute("SELECT route FROM export_route WHERE export_id = ?", (export_id,)).fetchone()
            return row[0] if row else None

    # --- expiry -------------------------------------------------------------------

    def sweep(self, now: float | None = None) -> int:
        """Expire ready exports past their time, deleting their files, and
        forget spent ones kept long enough. Returns how many expired."""
        now = _now(now)
        with self.database.transaction() as db:
            expired = [row[0] for row in db.execute(
                "SELECT id FROM export WHERE state = ? AND expires_at <= ?", (READY, now))]
            db.executemany("UPDATE export SET state = ?, reserved_bytes = 0 WHERE id = ?",
                           [(EXPIRED, i) for i in expired])
            db.execute(
                f"DELETE FROM export WHERE state NOT IN {HOLDS_SPACE} AND expires_at + ? <= ?",
                (KEEP_SPENT_SECONDS, now),
            )
            db.execute("DELETE FROM export_route WHERE export_id NOT IN (SELECT id FROM export)")
        for export_id in expired:
            self._final(export_id).unlink(missing_ok=True)
        return len(expired)

    # --- inside -------------------------------------------------------------------

    def _by_id(self, db, export_id: str, now: float) -> Export | None:
        row = db.execute(f"SELECT {_COLUMNS} FROM export WHERE id = ?", (export_id,)).fetchone()
        return None if row is None else _export(row, now)

    def _by_key(self, db, token_id: str, request_key: str, now: float) -> Export | None:
        row = db.execute(f"SELECT {_COLUMNS} FROM export WHERE token_id = ? AND request_key = ?",
                         (token_id, request_key)).fetchone()
        return None if row is None else _export(row, now)

    def _final(self, export_id: str) -> Path:
        assert ID.fullmatch(export_id)
        return self.directory / export_id

    def _part(self, export_id: str) -> Path:
        assert ID.fullmatch(export_id)
        return self.directory / (export_id + PART)

    def _sync_directory(self) -> None:
        """Make a rename survive a power cut."""
        fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
