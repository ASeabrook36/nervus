"""Who nervus is (ADR-0027 question 6): nervus records the keys it was made
with, and refuses to start as someone else, or as no one, without being told.

What it holds to:
- The first start records the fingerprints of nervus's SSH key, its SSH
  certificate authority key and its TLS issuer key in the database, and says
  so in the audit log first. An installation from before this records them at
  its first start with it, the same way.
- Every later start compares them. A key that is missing, or not the one the
  database names, refuses the start, naming the piece: this is ADR-0005
  consequence 6's refusal, and ADR-0015 question G's case of a database put
  beside keys it was not made with.
- A TLS issuer appearing where none was recorded (`nervus tls-init
  --upgrade`) is recorded, not refused: nothing that trusted nervus before
  stops trusting it.
- No database beside an audit log holding records refuses the start: nervus
  has run here before and its database is gone, and an empty one would forget
  every machine without a word. A database that has recorded who nervus is,
  beside a missing or empty audit log, refuses likewise, since nervus never
  removes its log. Neither is skipped by any flag of nervus's own; starting
  empty on purpose is `nervus-ctl start-empty`'s, and audited.
- Reading and comparing change nothing; the only write is the first record.
- A key replaced on purpose is accepted only by the person, with
  `nervus-ctl accept-keys`, audited (question 6, as the operator added it).
"""

from __future__ import annotations

import contextlib
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

import asyncssh

from nervus import plainfile
from nervus.audit import AuditError, AuditLog
from nervus.config import ConfigError
from nervus.database import Database
from nervus.tls import key_file_fingerprint

WORDS = {
    "ssh_key": "nervus's SSH key",
    "ssh_ca_key": "nervus's SSH certificate authority key",
    "tls_issuer": "nervus's TLS issuer key",
}
ROLES = ("ssh_key", "ssh_ca_key", "tls_issuer")
# What replacing each costs, for `nervus-ctl accept-keys` (question 6, as the
# operator added it on 2026-10-28).
COST = {
    "ssh_key": "costs nothing: machines trust nervus's certificate authority, which vouches for whatever key "
               "nervus presents",
    "ssh_ca_key": "every machine refuses nervus until it is enrolled again from the Machines page",
    "tls_issuer": "every client must trust nervus again (tools/nervus-trust)",
}
RESTORE = ("restore that key, or the whole backup (`nervus-ctl restore`); if it was replaced on purpose, "
           "accept it with `nervus-ctl accept-keys`")
START_EMPTY = ("Restore a backup (`nervus-ctl restore`), or, to start {what} on purpose, run "
               "`nervus-ctl start-empty`, which is audited")


class IdentityRefused(ConfigError):
    """nervus will not start: a piece of it is missing or not its own."""


@dataclass(frozen=True)
class Keys:
    """nervus's keys, by role. `tls_issuer` is None where nervus has no issuer
    of its own: it serves a certificate it was given, or plain HTTP."""

    ssh_key: Path
    ssh_ca_key: Path
    tls_issuer: Path | None


def _ssh_fingerprint(path: Path) -> str:
    try:
        return asyncssh.import_private_key(plainfile.read_bytes(path)).get_fingerprint("sha256")
    except (OSError, asyncssh.KeyImportError) as exc:
        raise IdentityRefused(f"cannot read {path}: {exc}") from exc


def fingerprints(keys: Keys) -> dict[str, str | None]:
    """The SHA-256 fingerprint of each key's public half."""
    return {
        "ssh_key": _ssh_fingerprint(keys.ssh_key),
        "ssh_ca_key": _ssh_fingerprint(keys.ssh_ca_key),
        "tls_issuer": key_file_fingerprint(keys.tls_issuer) if keys.tls_issuer is not None else None,
    }


def has_records(audit_log: Path) -> bool:
    try:
        return audit_log.stat().st_size > 0
    except FileNotFoundError:
        return False


def recorded(database: Path) -> bool:
    """Whether the database has recorded who nervus is. A database it cannot
    read says no here; Database.open() then says why."""
    try:
        # mode=rw, as Database does: never make the file.
        with contextlib.closing(sqlite3.connect(f"{database.absolute().as_uri()}?mode=rw", uri=True)) as db:
            return db.execute("SELECT 1 FROM identity").fetchone() is not None
    except sqlite3.Error:
        return False


def check_history(database: Path, audit_log: Path) -> None:
    """Before the database is opened, which would make an empty one: refuse a
    start where the database or the audit log is gone and the other shows
    nervus has run here."""
    if not database.exists():
        if has_records(audit_log):
            raise IdentityRefused(
                f"there is no database at {database}, but the audit log {audit_log} holds records: nervus has "
                "run here before and its database is gone, and an empty one would forget every machine and "
                "every token issued in the UI. " + START_EMPTY.format(what="with an empty database"))
        return
    if not has_records(audit_log) and recorded(database):
        raise IdentityRefused(
            f"the audit log {audit_log} is missing or empty, but the database {database} shows nervus has run "
            "here, and nervus never removes its log. " + START_EMPTY.format(what="a new log"))


def check(database: Database, keys: Keys, audit: AuditLog, now: float | None = None) -> None:
    """Record who nervus is at its first start; at every other, refuse a key
    that is missing or not the one recorded."""
    found = fingerprints(keys)
    with database.transaction(write=False) as db:
        row = db.execute("SELECT ssh_key, ssh_ca_key, tls_issuer FROM identity").fetchone()
    if row is None:
        _record(database, audit, found, now, "identity_recorded")
        return
    recorded = dict(zip(("ssh_key", "ssh_ca_key", "tls_issuer"), row))
    for role in ("ssh_key", "ssh_ca_key"):
        if found[role] != recorded[role]:
            raise IdentityRefused(
                f"{WORDS[role]} ({getattr(keys, role)}) is not the one nervus's database was made with "
                f"({recorded[role]}, found {found[role]}): {RESTORE}")
    if recorded["tls_issuer"] is not None and found["tls_issuer"] is None:
        raise IdentityRefused(
            f"{WORDS['tls_issuer']} is missing, but nervus's database was made with one "
            f"({recorded['tls_issuer']}), which every client trusts: {RESTORE}")
    if recorded["tls_issuer"] is not None and found["tls_issuer"] != recorded["tls_issuer"]:
        raise IdentityRefused(
            f"{WORDS['tls_issuer']} ({keys.tls_issuer}) is not the one nervus's database was made with "
            f"({recorded['tls_issuer']}, found {found['tls_issuer']}): {RESTORE}")
    if recorded["tls_issuer"] is None and found["tls_issuer"] is not None:
        _record(database, audit, found, now, "identity_issuer_recorded")


def _record(database: Database, audit: AuditLog, found: dict, now: float | None, action: str) -> None:
    """Audited first: a start that cannot say who nervus is does not record
    it (ADR-0001 s10)."""
    try:
        audit.record_operator(action, found, tool="nervus")
    except AuditError as exc:
        raise IdentityRefused(f"cannot record who nervus is: {exc}") from exc
    with database.transaction() as db:
        db.execute("INSERT OR REPLACE INTO identity (only, ssh_key, ssh_ca_key, tls_issuer, recorded_at) "
                   "VALUES (1, ?, ?, ?, ?)",
                   (found["ssh_key"], found["ssh_ca_key"], found["tls_issuer"], time.time() if now is None else now))
