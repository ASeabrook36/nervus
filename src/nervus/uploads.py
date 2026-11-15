"""The upload store (ADR-0020): files a client sent nervus to put in place on a
host or in a VM, held only until they are delivered, and the record of each in
the database.

What it holds to:

- **Only the token that sent an upload ever reaches it** (decision H). Every
  lookup is by token and id, or token and request key, together.
- **One request key, one upload** (decision G). The same key with the same
  SHA-256 returns the upload already made, whatever became of it; with
  another SHA-256 it is refused, so a retry can never deliver a different file.
- **Space is reserved before the body is read** (decision F), from the size
  the client declared, inside one database transaction, against the same
  ceilings as exports, counting what both hold.
- **Nothing is delivered unless it is what the client declared** (decision B):
  the body is hashed and counted as it arrives, refused past its declared size,
  and failed if it ends short or hashes differently. A delivery is recorded
  only with the destination's own hash, and failed if that differs.
- **The staged copy goes as soon as it is delivered or has failed** (decision
  F); the record stays a day, so asking again with the key says what happened.
- **A VM's pull uses a one-time secret** (decision E): made here, given only to
  the VM, valid for one fetch of one upload being delivered, for a few
  minutes. Only its hash is stored.
- **A restart fails every upload in progress** and deletes every staged file.
  recover() returns those that were being delivered, so the caller can remove
  the temporary file each may have left at its destination.

How a body arrives is the route's business (step 2); how a file is delivered
is the deliverers' (steps 3 and 4).
"""

from __future__ import annotations

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
from nervus.exports import REQUEST_KEY, UPLOAD_HOLDS_SPACE, UPLOAD_RECEIVING, Limits, held_bytes, unwritten_bytes

# What an upload can be. `receiving`: its body is arriving. `delivering`: it is
# whole and checked, and being put in place. `delivered`: in place, with the
# destination's hash. `failed`: it never will be; `failure_code` says why.
RECEIVING, DELIVERING, DELIVERED, FAILED = UPLOAD_RECEIVING, "delivering", "delivered", "failed"
HOLDS_SPACE = UPLOAD_HOLDS_SPACE
assert RECEIVING in HOLDS_SPACE and DELIVERING in HOLDS_SPACE

# A spent upload's record is kept this long after it finished.
KEEP_SPENT_SECONDS = 24 * 3600
# Decision E: a few minutes.
PULL_SECRET_SECONDS = 300

ID = re.compile(r"[0-9a-f]{32}")
ID_BYTES = 16
SHA256 = re.compile(r"[0-9a-f]{64}")
PULL_SECRET_BYTES = 32
PART = ".part"


class UploadRefused(Exception):
    """An upload that cannot be made, received or delivered. `code` is for the
    client and the audit log; the message says what to do in words."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Upload:
    id: str
    token_id: str
    request_key: str
    destination: dict
    size: int
    sha256: str
    state: str
    reserved_bytes: int
    bytes_received: int
    bytes_delivered: int
    route: str | None
    failure_code: str | None
    failure_message: str | None
    made_at: float
    finished_at: float | None


_COLUMNS = ("id, token_id, request_key, destination, size, sha256, state, reserved_bytes, bytes_received, "
            "bytes_delivered, route, failure_code, failure_message, made_at, finished_at")


def _upload(row: tuple) -> Upload:
    values = list(row)
    values[3] = json.loads(values[3])
    return Upload(*values)


def _now(now: float | None) -> float:
    return time.time() if now is None else now


def _secret_hash(secret: str) -> str:
    """The secret is random, so no salt is needed: there is nothing to guess
    it from."""
    return hashlib.sha256(secret.encode()).hexdigest()


class Receiver:
    """Writes one upload's body, hashing and counting as it goes, and refuses
    any byte past the declared size. Made only by UploadStore.receiver()."""

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
            raise UploadRefused("staging_exists", f"a staging file for this upload already exists: {path.name}") from exc

    def write(self, data: bytes) -> None:
        if self._fd is None:
            raise UploadRefused("closed", "this upload's body is already closed")
        if self.written + len(data) > self.limit:
            raise UploadRefused(
                "too_long",
                f"the body is longer than the {self.limit} bytes declared; send it again with its real size",
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


class UploadStore:
    def __init__(self, database: Database, directory: Path, *, limits: Limits = Limits(),
                 free_bytes: Callable[[], int] | None = None):
        self.database = database
        self.directory = Path(directory)
        self.limits = limits
        self._free_bytes = free_bytes or (lambda: shutil.disk_usage(self.directory).free)

    # --- start ------------------------------------------------------------------

    def open(self, now: float | None = None) -> list[Upload]:
        """Make the directory if it is missing, check it, and recover from a
        stop: run once when nervus starts, after the database is open. Returns
        what recover() returns."""
        try:
            self.directory.mkdir(mode=0o700)
        except FileExistsError:
            pass
        except OSError as exc:
            raise ConfigError(f"cannot create the uploads directory {self.directory}: {exc}") from exc
        info = self.directory.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise ConfigError(f"the uploads directory {self.directory} must be a directory, not a link")
        if info.st_mode & 0o077:
            raise ConfigError(
                f"the uploads directory {self.directory} is mode {oct(stat.S_IMODE(info.st_mode))}; "
                f"it must be readable by nervus alone (0700)"
            )
        return self.recover(now)

    def recover(self, now: float | None = None) -> list[Upload]:
        """After a stop: no upload in progress will finish, so fail each one
        and delete every staged file. Returns the uploads that were being
        delivered, now failed, whose destinations may hold a temporary file."""
        now = _now(now)
        with self.database.transaction() as db:
            delivering = [row[0] for row in db.execute("SELECT id FROM upload WHERE state = ?", (DELIVERING,))]
            db.execute(
                f"UPDATE upload SET state = ?, reserved_bytes = 0, failure_code = 'interrupted', "
                f"failure_message = 'nervus stopped before it was delivered; send it again with a new request key', "
                f"pull_secret_hash = NULL, pull_secret_expires_at = NULL, finished_at = ? "
                f"WHERE state IN {HOLDS_SPACE}",
                (FAILED, now),
            )
            was_delivering = [self._by_id(db, upload_id) for upload_id in delivering]
        for entry in self.directory.iterdir():
            entry.unlink(missing_ok=True)
        self.sweep(now)
        return was_delivering

    # --- receiving ----------------------------------------------------------------

    def begin(self, token_id: str, request_key: str, destination: dict, size: int, sha256: str,
              now: float | None = None) -> tuple[Upload, bool]:
        """Reserve space for a body of `size` bytes, and record the upload. If
        this token already sent one with this request key and this SHA-256,
        return that one instead, and False: a retry never delivers twice
        (decision G). Raises UploadRefused if the key was used for another
        file, or the body would pass a limit."""
        now = _now(now)
        if not isinstance(request_key, str) or not REQUEST_KEY.fullmatch(request_key):
            raise UploadRefused("bad_request_key",
                                "a request key is 1 to 128 letters, digits, '.', '_', ':' or '-'")
        if not isinstance(sha256, str) or not SHA256.fullmatch(sha256.lower()):
            raise UploadRefused("bad_sha256", "declare the file's SHA-256 as 64 hexadecimal digits")
        sha256 = sha256.lower()
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise UploadRefused("bad_size", f"declare the file's size in bytes: {size!r}")
        with self.database.transaction() as db:
            existing = self._by_key(db, token_id, request_key)
            if existing is not None:
                if existing.sha256 != sha256:
                    raise UploadRefused(
                        "key_reused",
                        f"request key {request_key} was used for a different file; use a new key for a new file",
                    )
                return existing, False
            if size > self.limits.max_export_bytes:
                raise UploadRefused(
                    "too_large",
                    f"the file is {size} bytes; one upload is at most {self.limits.max_export_bytes}. "
                    f"Split it into parts under that size",
                )
            held = held_bytes(db)
            if held + size > self.limits.max_total_bytes:
                raise UploadRefused(
                    "quota",
                    f"exports and uploads already hold {held} of {self.limits.max_total_bytes} bytes; "
                    f"try again once they finish",
                )
            if self._free_bytes() - unwritten_bytes(db) - size < self.limits.free_floor_bytes:
                raise UploadRefused(
                    "disk_floor",
                    f"receiving it would leave nervus's disk under {self.limits.free_floor_bytes} bytes free, "
                    f"which the audit log needs; try later or with a smaller file",
                )
            upload_id = secrets.token_hex(ID_BYTES)
            db.execute(
                f"INSERT INTO upload ({_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 0, NULL, NULL, NULL, ?, NULL)",
                (upload_id, token_id, request_key, json.dumps(destination, sort_keys=True), size, sha256,
                 RECEIVING, size, now),
            )
            return self._by_id(db, upload_id), True

    def receiver(self, upload: Upload) -> Receiver:
        """Start writing a receiving upload's body."""
        if upload.state != RECEIVING:
            raise UploadRefused("not_receiving", f"upload {upload.id} is {upload.state}, not receiving")
        return Receiver(self._part(upload.id), upload.reserved_bytes)

    def progress(self, upload_id: str, bytes_received: int) -> None:
        """Record how much of the body has arrived, for a client asking."""
        with self.database.transaction() as db:
            db.execute("UPDATE upload SET bytes_received = ? WHERE id = ? AND state = ?",
                       (bytes_received, upload_id, RECEIVING))

    def received(self, upload: Upload, receiver: Receiver, now: float | None = None) -> Upload:
        """The body has ended. If it is the size and SHA-256 declared, seal it:
        flushed, read-only, renamed to its id, and the upload `delivering`.
        Otherwise fail it (decision B). Returns the upload either way."""
        if receiver.written != upload.size:
            return self.fail(upload, "short",
                             f"the body ended after {receiver.written} of the {upload.size} bytes declared; "
                             f"send it again", receiver, now)
        if receiver.sha256 != upload.sha256:
            return self.fail(upload, "hash_mismatch",
                             "the body's SHA-256 is not the one declared; check the file and send it again",
                             receiver, now)
        receiver._seal()
        final = self._final(upload.id)
        os.rename(receiver.path, final)
        self._sync_directory()
        with self.database.transaction() as db:
            done = db.execute(
                "UPDATE upload SET state = ?, bytes_received = ? WHERE id = ? AND state = ?",
                (DELIVERING, receiver.written, upload.id, RECEIVING),
            ).rowcount
            if done:
                return self._by_id(db, upload.id)
        # Failed, by a restart or the route, while its body was arriving.
        final.unlink(missing_ok=True)
        raise UploadRefused("not_receiving", f"upload {upload.id} was ended while its body was arriving")

    # --- delivering ---------------------------------------------------------------

    def open_staged(self, upload: Upload) -> BinaryIO:
        """Open a delivering upload's sealed copy, to deliver it. Raises
        UploadRefused if it is not the regular file of the declared size that
        received() left."""
        if upload.state != DELIVERING:
            raise UploadRefused("not_delivering", f"upload {upload.id} is {upload.state}, not being delivered")
        try:
            fd = os.open(self._final(upload.id), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)  # a pipe is not waited on
        except OSError as exc:
            raise UploadRefused("lost", f"upload {upload.id}'s staged copy cannot be opened: {exc.strerror}") from exc
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size != upload.size:
            os.close(fd)
            raise UploadRefused("lost", f"upload {upload.id}'s staged copy is not the one nervus received")
        return os.fdopen(fd, "rb")

    def delivery_progress(self, upload_id: str, bytes_delivered: int) -> None:
        """Record how much has reached the destination, for a client asking."""
        with self.database.transaction() as db:
            db.execute("UPDATE upload SET bytes_delivered = ? WHERE id = ? AND state = ?",
                       (bytes_delivered, upload_id, DELIVERING))

    def delivered(self, upload: Upload, route: str, sha256: str, now: float | None = None) -> Upload:
        """The file is in place, and the destination hashed it as `sha256`. If
        that is the declared hash, record the upload delivered by `route`;
        otherwise fail it. Either way the staged copy goes and the space comes
        back."""
        now = _now(now)
        with self.database.transaction(write=False) as db:
            current = self._by_id(db, upload.id)
        if current is None or current.state != DELIVERING:
            state = "gone" if current is None else current.state
            raise UploadRefused("not_delivering", f"upload {upload.id} is {state}, not being delivered")
        if not isinstance(sha256, str) or sha256.lower() != current.sha256:
            return self.fail(current, "destination_hash",
                             "the destination's SHA-256 of what it wrote is not the one declared; "
                             "nothing was left in place", now=now)
        with self.database.transaction() as db:
            db.execute(
                "UPDATE upload SET state = ?, route = ?, reserved_bytes = 0, bytes_delivered = size, "
                "pull_secret_hash = NULL, pull_secret_expires_at = NULL, finished_at = ? WHERE id = ? AND state = ?",
                (DELIVERED, route, now, upload.id, DELIVERING),
            )
            done = self._by_id(db, upload.id)
        self._final(upload.id).unlink(missing_ok=True)
        return done

    def fail(self, upload: Upload, code: str, message: str, receiver: Receiver | None = None,
             now: float | None = None) -> Upload:
        """End an upload that will not be delivered: delete what was staged,
        release its space, and record why."""
        now = _now(now)
        if receiver is not None:
            receiver.close()
        self._part(upload.id).unlink(missing_ok=True)
        self._final(upload.id).unlink(missing_ok=True)
        with self.database.transaction() as db:
            db.execute(
                f"UPDATE upload SET state = ?, reserved_bytes = 0, failure_code = ?, failure_message = ?, "
                f"pull_secret_hash = NULL, pull_secret_expires_at = NULL, finished_at = ? "
                f"WHERE id = ? AND state IN {HOLDS_SPACE}",
                (FAILED, code, message, now, upload.id),
            )
            return self._by_id(db, upload.id)

    # --- the one-time secret for a VM's pull (decision E) -------------------------

    def issue_pull_secret(self, upload: Upload, now: float | None = None) -> str:
        """A secret that lets one fetch of this delivering upload's copy, for
        PULL_SECRET_SECONDS. A new one replaces any before it."""
        now = _now(now)
        secret = secrets.token_urlsafe(PULL_SECRET_BYTES)
        with self.database.transaction() as db:
            done = db.execute(
                "UPDATE upload SET pull_secret_hash = ?, pull_secret_expires_at = ? WHERE id = ? AND state = ?",
                (_secret_hash(secret), now + PULL_SECRET_SECONDS, upload.id, DELIVERING),
            ).rowcount
        if not done:
            raise UploadRefused("not_delivering", f"upload {upload.id} is not being delivered")
        return secret

    def claim_pull_secret(self, secret: str, now: float | None = None) -> Upload | None:
        """The delivering upload this secret was issued for, if it is unused
        and unexpired; using it spends it. None otherwise."""
        if not isinstance(secret, str) or not secret:
            return None
        now = _now(now)
        with self.database.transaction() as db:
            row = db.execute(
                f"SELECT {_COLUMNS} FROM upload WHERE pull_secret_hash = ? AND pull_secret_expires_at > ? "
                f"AND state = ?",
                (_secret_hash(secret), now, DELIVERING),
            ).fetchone()
            if row is None:
                return None
            upload = _upload(row)
            db.execute("UPDATE upload SET pull_secret_hash = NULL, pull_secret_expires_at = NULL WHERE id = ?",
                       (upload.id,))
            return upload

    # --- a client's uploads -------------------------------------------------------

    def get(self, token_id: str, upload_id: str, now: float | None = None) -> Upload | None:
        """This token's upload with this id, in whatever state, or None."""
        if not isinstance(upload_id, str) or not ID.fullmatch(upload_id):
            return None
        with self.database.transaction(write=False) as db:
            upload = self._by_id(db, upload_id)
        return upload if upload is not None and upload.token_id == token_id else None

    def by_key(self, token_id: str, request_key: str, now: float | None = None) -> Upload | None:
        with self.database.transaction(write=False) as db:
            return self._by_key(db, token_id, request_key)

    # --- forgetting ---------------------------------------------------------------

    def sweep(self, now: float | None = None) -> int:
        """Forget spent uploads kept long enough. Returns how many."""
        now = _now(now)
        with self.database.transaction() as db:
            return db.execute(
                f"DELETE FROM upload WHERE state NOT IN {HOLDS_SPACE} AND finished_at + ? <= ?",
                (KEEP_SPENT_SECONDS, now),
            ).rowcount

    # --- inside -------------------------------------------------------------------

    def _by_id(self, db, upload_id: str) -> Upload | None:
        row = db.execute(f"SELECT {_COLUMNS} FROM upload WHERE id = ?", (upload_id,)).fetchone()
        return None if row is None else _upload(row)

    def _by_key(self, db, token_id: str, request_key: str) -> Upload | None:
        row = db.execute(f"SELECT {_COLUMNS} FROM upload WHERE token_id = ? AND request_key = ?",
                         (token_id, request_key)).fetchone()
        return None if row is None else _upload(row)

    def _final(self, upload_id: str) -> Path:
        assert ID.fullmatch(upload_id)
        return self.directory / upload_id

    def _part(self, upload_id: str) -> Path:
        assert ID.fullmatch(upload_id)
        return self.directory / (upload_id + PART)

    def _sync_directory(self) -> None:
        """Make a rename survive a power cut."""
        fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
