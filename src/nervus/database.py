"""What nervus writes while it runs, kept in one SQLite file (ADR-0011 decision
1): the operator's sign-in links and browser sessions (ADR-0012 decisions 3 to
5), the tokens issued in the UI (ADR-0014 decisions C and D), and the record of
each export a client makes (ADR-0016 decision E; exports.py uses it), of
each upload (ADR-0020 decision G; uploads.py uses it), and the VMs nervus has
enrolled (ADR-0022 decision 5a; enrollments.py uses it), the machines enrolled from the
UI (ADR-0024 decision 3; enrolled_hosts.py uses it), first-run setup's tier and
ranges declared internal (ADR-0015; first_run.py uses it), the fingerprints of
nervus's own keys (ADR-0027 question 6; identity.py uses it), when backups
were made, checked, downloaded and restored (ADR-0027 questions 4 and 7), and the
one-time codes that hand a token to the computer its client runs on (ADR-0032
question 5; token_codes.py uses it).

- One file: /var/lib/nervus/nervus.db in the systemd unit, made 0600 by open().
- Every change is one transaction. It lands whole or not at all, a second
  writer waits its turn, and a crash part-way leaves the state before it: the
  three hazards ADR-0005 consequence 5 named for state the service writes.
- nervus and nervus-ctl are separate processes using the same file. Each
  change opens its own connection, so neither holds the file between changes.
- Only a hash of each link, session and token is stored, never the value, so
  a copy of the file signs no one in and lets no client in.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import secrets
import sqlite3
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

from nervus.auth import Token
from nervus.config import ConfigError

# ADR-0012 decision 4: a link works once, within 5 minutes.
LINK_SECONDS = 5 * 60
# ADR-0011 question A and ADR-0012 decision 5: 12 hours from sign-in, not
# extended by use.
SESSION_SECONDS = 12 * 3600
# 128 random bits in a link (ADR-0012, "Settled already"); a session, which
# lives longer, carries 256.
LINK_BYTES = 16
SESSION_BYTES = 32
# A token issued in the UI: 256 random bits, 43 url-safe characters, the shape
# of the token file's.
TOKEN_BYTES = 32
TOKEN_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,63}")
LABEL_CHARACTERS = 64
# A used or expired link is remembered this long after it expired, so a second
# attempt is refused as "used" or "expired", which the audit log records,
# rather than as "unknown". Cleared when a link is made.
KEEP_SPENT_SECONDS = 24 * 3600
# How long a change waits for another process's change to finish before
# failing. Every change here takes milliseconds.
BUSY_SECONDS = 5.0

# The version changes only for a change a release before could not live with
# (ADR-0014 decision F). A new table is not one: the release before checks
# only the version, and ignores a table it does not know. So tables added
# since version 1 go in ADDED, which open() makes when missing, and the
# version stays, so a deploy that rolls back still starts. A change that an
# older release would misread, such as a column it relies on changing
# meaning, must raise the version.
SCHEMA_VERSION = 1
SCHEMA = """
CREATE TABLE signin_link (
    hash TEXT PRIMARY KEY,
    made_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    used_at REAL
);
CREATE TABLE session (
    hash TEXT PRIMARY KEY,
    signed_in_at REAL NOT NULL,
    expires_at REAL NOT NULL
);
"""
ADDED = """
CREATE TABLE IF NOT EXISTS issued_token (
    id TEXT PRIMARY KEY,
    hash TEXT NOT NULL UNIQUE,
    client TEXT NOT NULL,
    project TEXT NOT NULL,
    hosts TEXT NOT NULL,
    issued_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS export (
    id TEXT PRIMARY KEY,
    token_id TEXT NOT NULL,
    request_key TEXT NOT NULL,
    source TEXT NOT NULL,
    filename TEXT NOT NULL,
    state TEXT NOT NULL,
    reserved_bytes INTEGER NOT NULL,
    bytes_written INTEGER NOT NULL,
    size INTEGER,
    sha256 TEXT,
    failure_code TEXT,
    failure_message TEXT,
    made_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    finished_at REAL,
    UNIQUE (token_id, request_key)
);
CREATE TABLE IF NOT EXISTS upload (
    id TEXT PRIMARY KEY,
    token_id TEXT NOT NULL,
    request_key TEXT NOT NULL,
    destination TEXT NOT NULL,
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    state TEXT NOT NULL,
    reserved_bytes INTEGER NOT NULL,
    bytes_received INTEGER NOT NULL,
    bytes_delivered INTEGER NOT NULL,
    route TEXT,
    failure_code TEXT,
    failure_message TEXT,
    pull_secret_hash TEXT UNIQUE,
    pull_secret_expires_at REAL,
    made_at REAL NOT NULL,
    finished_at REAL,
    UNIQUE (token_id, request_key)
);
CREATE TABLE IF NOT EXISTS enrollment_code (
    id TEXT PRIMARY KEY,
    hash TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    address TEXT NOT NULL,
    level TEXT NOT NULL,
    made_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    made_by TEXT NOT NULL,
    used_at REAL,
    outcome TEXT
);
CREATE TABLE IF NOT EXISTS enrollment_login (
    code_id TEXT PRIMARY KEY,
    login TEXT NOT NULL,
    host_key TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS enrolled_host (
    name TEXT PRIMARY KEY,
    address TEXT NOT NULL,
    level TEXT NOT NULL,
    host_keys TEXT NOT NULL,
    machine_id TEXT NOT NULL,
    enrolled_at REAL NOT NULL,
    enrolled_by TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS export_route (
    export_id TEXT PRIMARY KEY,
    route TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS enrolled_vm (
    vmid INTEGER PRIMARY KEY,
    address TEXT NOT NULL,
    host_keys TEXT NOT NULL,
    enrolled_at REAL NOT NULL,
    enrolled_by TEXT NOT NULL,
    moved_at REAL
);
CREATE TABLE IF NOT EXISTS setup_tier (
    only INTEGER PRIMARY KEY CHECK (only = 1),
    tier INTEGER NOT NULL CHECK (tier IN (1, 2, 3)),
    chosen_at REAL NOT NULL,
    chosen_by TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS declared_range (
    network TEXT PRIMARY KEY,
    declared_at REAL NOT NULL,
    declared_by TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS identity (
    only INTEGER PRIMARY KEY CHECK (only = 1),
    ssh_key TEXT NOT NULL,
    ssh_ca_key TEXT NOT NULL,
    tls_issuer TEXT,
    recorded_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS backup_event (
    kind TEXT NOT NULL,
    file TEXT NOT NULL,
    made_at REAL,
    at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS enrollment_accounts (
    code_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    readwrite TEXT,
    readonly TEXT NOT NULL,
    off TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS machine_account (
    name TEXT PRIMARY KEY,
    enrolled_at REAL,
    readwrite TEXT,
    readonly TEXT,
    readonly_groups TEXT NOT NULL,
    why_none TEXT,
    checked_at REAL NOT NULL,
    made TEXT NOT NULL DEFAULT '[]',
    machine_id TEXT
);
CREATE TABLE IF NOT EXISTS assigned_token (
    id TEXT PRIMARY KEY,
    hash TEXT NOT NULL UNIQUE,
    client TEXT NOT NULL,
    project TEXT NOT NULL,
    levels TEXT NOT NULL,
    issued_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS token_code (
    id TEXT PRIMARY KEY,
    hash TEXT NOT NULL UNIQUE,
    token_id TEXT NOT NULL,
    client TEXT NOT NULL,
    made_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    used_at REAL,
    used_from TEXT
);
"""
# ADR-0031: what a token may be on one of its machines. Read-write is the
# machine's own level, as for every token before; read-only is the machine's
# read-only account.
ASSIGNMENTS = ("read-only", "read-write")


class DatabaseUnusable(ConfigError):
    """The database cannot be opened, is not one this nervus made, or a change
    to it failed."""


class LinkRefused(Exception):
    """A sign-in link that cannot be used. `reason` is "unknown", "used" or
    "expired", for the audit log (ADR-0012 decision 6); the browser is told
    none of it."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class TokenRefused(ValueError):
    """A token that cannot be issued, and why, in words for the operator."""


@dataclass(frozen=True)
class IssuedToken:
    token: Token
    issued_at: float


@dataclass(frozen=True)
class Session:
    signed_in_at: float
    expires_at: float


def _hash(value: str) -> str:
    """SHA-256 of a link or session value. Both are random, so no salt is
    needed: there is nothing to guess them from."""
    return hashlib.sha256(value.encode()).hexdigest()


def audit_id(value: str) -> str:
    """What the audit log calls a link or a session: the first 16 hex digits of
    its hash. It ties a link's making to its use, and a sign-in to its
    sign-out (ADR-0012 decision 6), without being usable to sign in."""
    return _hash(value)[:16]


def _now(now: float | None) -> float:
    return time.time() if now is None else now


@dataclass(frozen=True)
class Database:
    path: Path

    def open(self) -> None:
        """Make the database if it does not exist, then check it is one this
        nervus understands. The only call that makes the file.

        The file is made 0600 before SQLite sees it, and SQLite gives its
        write-ahead files the database's own mode.
        """
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        except OSError as exc:
            raise DatabaseUnusable(f"cannot create the database {self.path}: {exc}") from exc
        else:
            os.fchmod(fd, 0o600)  # the umask can take bits away, never add them
            os.close(fd)
        try:
            with contextlib.closing(self._connect()) as db:
                # Write-ahead logging: a reader never waits for a writer. It is a
                # property of the file, kept once set, and cannot be set inside
                # a transaction.
                db.execute("PRAGMA journal_mode = WAL")
        except sqlite3.Error as exc:
            raise DatabaseUnusable(f"cannot use the database {self.path}: {exc}") from exc
        with self._transaction() as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version == SCHEMA_VERSION:
                self._add_tables(db)
                return
            if version != 0:
                raise DatabaseUnusable(
                    f"the database {self.path} is version {version}; this nervus knows "
                    f"version {SCHEMA_VERSION}. It was made by another release of nervus"
                )
            if db.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()[0]:
                raise DatabaseUnusable(f"the database {self.path} holds tables nervus did not make")
            for statement in SCHEMA.split(";"):
                if statement.strip():
                    db.execute(statement)
            self._add_tables(db)
            db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")

    @staticmethod
    def _add_tables(db: sqlite3.Connection) -> None:
        for statement in ADDED.split(";"):
            if statement.strip():
                db.execute(statement)

    def _connect(self) -> sqlite3.Connection:
        # mode=rw: never make the file. A missing database is open()'s to make;
        # anywhere else it means something is wrong, and a quiet new one would
        # sign everyone out without saying why.
        return sqlite3.connect(
            f"{self.path.absolute().as_uri()}?mode=rw",
            uri=True,
            isolation_level=None,  # nervus says where each transaction begins and ends
            timeout=BUSY_SECONDS,
        )

    def transaction(self, write: bool = True) -> contextlib.AbstractContextManager[sqlite3.Connection]:
        """One transaction, for a module that keeps a table of its own here
        (exports.py)."""
        return self._transaction(write)

    @contextlib.contextmanager
    def _transaction(self, write: bool = True) -> Iterator[sqlite3.Connection]:
        """One connection, one transaction: committed if the block finishes,
        rolled back otherwise. A writing one takes the write lock at its start
        (BEGIN IMMEDIATE), so two writers queue rather than both reading first
        and one then failing."""
        try:
            db = self._connect()
        except sqlite3.Error as exc:
            raise DatabaseUnusable(f"cannot open the database {self.path}: {exc}") from exc
        try:
            db.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield db
            db.execute("COMMIT")
        except sqlite3.Error as exc:
            raise DatabaseUnusable(f"the database {self.path}: {exc}") from exc
        finally:
            if db.in_transaction:
                db.execute("ROLLBACK")
            db.close()

    # --- sign-in links (ADR-0012 decision 4) ---------------------------------------

    def make_link(self, now: float | None = None) -> tuple[str, float]:
        """A new sign-in link's value, and when it expires. Only its hash is
        kept; the value exists only in what the caller prints."""
        now = _now(now)
        value = secrets.token_urlsafe(LINK_BYTES)
        with self._transaction() as db:
            db.execute("DELETE FROM signin_link WHERE expires_at <= ?", (now - KEEP_SPENT_SECONDS,))
            db.execute(
                "INSERT INTO signin_link (hash, made_at, expires_at) VALUES (?, ?, ?)",
                (_hash(value), now, now + LINK_SECONDS),
            )
        return value, now + LINK_SECONDS

    def use_link(self, value: str, now: float | None = None) -> tuple[str, Session]:
        """Spend a link and start a session: the new session's value, which goes
        only to the browser, and the session. Raises LinkRefused.

        Spending and starting are one transaction, and the link is spent only
        if it is unused and in time. Of two presses at once, one signs in and
        the other is refused as used.
        """
        now = _now(now)
        session_value = secrets.token_urlsafe(SESSION_BYTES)
        session = Session(signed_in_at=now, expires_at=now + SESSION_SECONDS)
        with self._transaction() as db:
            spent = db.execute(
                "UPDATE signin_link SET used_at = ? WHERE hash = ? AND used_at IS NULL AND expires_at > ?",
                (now, _hash(value), now),
            ).rowcount
            if spent:
                db.execute("DELETE FROM session WHERE expires_at <= ?", (now,))
                db.execute(
                    "INSERT INTO session (hash, signed_in_at, expires_at) VALUES (?, ?, ?)",
                    (_hash(session_value), session.signed_in_at, session.expires_at),
                )
                reason = None
            else:
                row = db.execute("SELECT used_at FROM signin_link WHERE hash = ?", (_hash(value),)).fetchone()
                reason = "unknown" if row is None else "used" if row[0] is not None else "expired"
        if reason is not None:
            raise LinkRefused(reason)
        return session_value, session

    # --- sessions (ADR-0012 decision 5) ------------------------------------------------

    def session(self, value: str, now: float | None = None) -> Session | None:
        """The session a browser's value belongs to, or None if it has none, or
        its 12 hours are up. Asking does not extend it."""
        now = _now(now)
        with self._transaction(write=False) as db:
            row = db.execute(
                "SELECT signed_in_at, expires_at FROM session WHERE hash = ? AND expires_at > ?",
                (_hash(value), now),
            ).fetchone()
        return None if row is None else Session(signed_in_at=row[0], expires_at=row[1])

    def sign_out(self, value: str) -> bool:
        """End one browser's session. False if it had none."""
        with self._transaction() as db:
            return db.execute("DELETE FROM session WHERE hash = ?", (_hash(value),)).rowcount > 0

    def sign_out_all(self, now: float | None = None) -> int:
        """End every session: `nervus-ctl signout --all`. Returns how many were
        still running."""
        now = _now(now)
        with self._transaction() as db:
            running = db.execute("SELECT COUNT(*) FROM session WHERE expires_at > ?", (now,)).fetchone()[0]
            db.execute("DELETE FROM session")
        return running

    # --- tokens issued in the UI (ADR-0014 decisions C and D) ----------------------

    def issue_token(self, id: str, client: str, project: str, hosts: list[str],
                    taken: object = (), never_issued: object = (), now: float | None = None,
                    readonly: object = (), waiting: Callable[[sqlite3.Connection], None] | None = None) -> str | None:
        """Issue a token and return its value, which exists only in what the
        caller shows, once. Raises TokenRefused.

        With `waiting` (ADR-0032 question 5 a), the token has no value yet: it
        is kept under the hash of one made and thrown away here, which nothing
        can present, and None is returned. `waiting` is called in the same
        transaction, to make the one-time code that will hand its value over
        (nervus.token_codes): a token never waits without one.

        `taken` holds the ids already in the token file, so an id names one
        token wherever it lives. A token's hosts are fixed now: to change them,
        issue another and revoke this one (decision D). `never_issued` holds the
        inventory's entries marked `issue: never`, which only the token file's
        tokens hold (ADR-0009 decision 3, ADR-0019 decision D).

        `readonly` names the hosts on which the token is read-only (ADR-0031),
        each one of `hosts`. A token with any is kept whole in `assigned_token`,
        which a release before this one does not know, so it refuses the token
        as unknown rather than read it as read-write everywhere ("Settled
        already"). One with none is kept in `issued_token`, as before.
        """
        now = _now(now)
        if not isinstance(id, str) or not TOKEN_ID.fullmatch(id):
            raise TokenRefused("an id is lower-case letters, digits and -, starting with a letter or "
                               "digit, at most 64 characters")
        labels = {"client": client, "project": project}
        for name, label in labels.items():
            if not isinstance(label, str) or not label.strip() or len(label) > LABEL_CHARACTERS:
                raise TokenRefused(f"a {name} is needed, at most {LABEL_CHARACTERS} characters")
        if not isinstance(hosts, list) or not hosts or not all(isinstance(h, str) and h for h in hosts):
            raise TokenRefused("a token needs at least one host")
        kept = sorted(set(hosts) & set(never_issued))
        if kept:
            raise TokenRefused(f"{', '.join(kept)} is never issued here: the inventory marks it "
                               "`issue: never` (ADR-0009)")
        if not isinstance(readonly, (list, tuple, set, frozenset)) or not all(isinstance(h, str) for h in readonly):
            raise TokenRefused("the machines a token is read-only on are a list of its hosts")
        outside = sorted(set(readonly) - set(hosts))
        if outside:
            raise TokenRefused(f"{', '.join(outside)} is read-only on this token but is not one of its hosts")
        if id in taken:
            raise TokenRefused(f"the id {id} is already a token's, in the token file")
        value = secrets.token_urlsafe(TOKEN_BYTES)
        kept_as = _hash(value) if waiting is None else unknown_value_hash()
        with self._transaction() as db:
            if db.execute("SELECT 1 FROM issued_token WHERE id = ? UNION SELECT 1 FROM assigned_token WHERE id = ?",
                          (id, id)).fetchone():
                raise TokenRefused(f"the id {id} is already a token's")
            if readonly:
                levels = {h: ("read-only" if h in set(readonly) else "read-write") for h in sorted(set(hosts))}
                db.execute(
                    "INSERT INTO assigned_token (id, hash, client, project, levels, issued_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (id, kept_as, client.strip(), project.strip(), json.dumps(levels), now),
                )
            else:
                db.execute(
                    "INSERT INTO issued_token (id, hash, client, project, hosts, issued_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (id, kept_as, client.strip(), project.strip(), json.dumps(sorted(set(hosts))), now),
                )
            if waiting is not None:
                waiting(db)
                return None
        return value

    def token(self, value: str) -> Token | None:
        """The issued token a client's value belongs to, or None. Read on every
        request, so an issued token works at once and a revoked one stops."""
        with self._transaction(write=False) as db:
            row = db.execute("SELECT id, client, project, hosts FROM issued_token WHERE hash = ?",
                             (_hash(value),)).fetchone()
            if row is not None:
                return _token(row)
            row = db.execute("SELECT id, client, project, levels FROM assigned_token WHERE hash = ?",
                             (_hash(value),)).fetchone()
        return None if row is None else _assigned(row)

    def issued_tokens(self) -> list[IssuedToken]:
        """Every token issued in the UI, from both tables, by id."""
        with self._transaction(write=False) as db:
            plain = db.execute("SELECT id, client, project, hosts, issued_at FROM issued_token").fetchall()
            assigned = db.execute("SELECT id, client, project, levels, issued_at FROM assigned_token").fetchall()
        issued = ([IssuedToken(token=_token(row[:4]), issued_at=row[4]) for row in plain]
                  + [IssuedToken(token=_assigned(row[:4]), issued_at=row[4]) for row in assigned])
        return sorted(issued, key=lambda i: i.token.id)

    def revoke_token(self, id: str) -> bool:
        """Delete an issued token, from whichever table holds it: its next call
        is refused as an unknown token's (ADR-0006 decision 8). False if there
        was none. Its one-time codes go in the same transaction (ADR-0032): a
        code left behind could hand over a later token issued under the same
        id, and take its client's value away."""
        with self._transaction() as db:
            gone = db.execute("DELETE FROM issued_token WHERE id = ?", (id,)).rowcount
            gone += db.execute("DELETE FROM assigned_token WHERE id = ?", (id,)).rowcount
            db.execute("DELETE FROM token_code WHERE token_id = ?", (id,))
            return gone > 0


def unknown_value_hash() -> str:
    """The hash a token waiting for its code is kept under (ADR-0032 question 5 a): of a value
    made and thrown away here, which nothing can present, so the token lets no one in."""
    return _hash(secrets.token_urlsafe(TOKEN_BYTES))


def _token(row: tuple) -> Token:
    id, client, project, hosts = row
    return Token(id=id, client=client, project=project, hosts=frozenset(json.loads(hosts)))


def _assigned(row: tuple) -> Token:
    """A token from `assigned_token`: its hosts, and those it is read-only on.
    A level this release does not know reads as read-only, never as more."""
    id, client, project, levels = row
    levels = json.loads(levels)
    return Token(id=id, client=client, project=project, hosts=frozenset(levels),
                 readonly=frozenset(h for h, level in levels.items() if level != "read-write"))
