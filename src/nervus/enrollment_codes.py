"""One-time enrollment codes (ADR-0024 decision 2).

The UI makes a code for a machine's name, the address nervus will use, and
the level its owner chose, and puts it in the two lines the owner runs as
root on the machine. The first line fetches the enrollment script with the
code; the script sends the machine's host keys back with it.

What it holds to:
- **Only a hash of the code is kept** (ADR-0012), so a copy of the database
  enrolls nothing. The UI and the audit log name a code by its id.
- **A code is good for 15 minutes.** The script may be fetched with it any
  number of times in that time; the report back is accepted once (spend),
  and then the code fetches nothing.
- **A code is made only for what can be enrolled**: the same checks as the
  enrolled-host store, a hosts.yaml name refused.
- **What became of it is kept** (finish), for the UI to show the owner, and
  a code a day past its expiry is dropped.
- **The address may be left blank**: the machine is then reached at the
  address its report came from (ADR-0024 decision 4a).
- **A code made from nervus's page keeps the account it logs in as and the
  host key that answered, never a password** (ADR-0026 question 4). Both or
  neither, the account a name and the key exactly one key; they go when the
  code does.
- **A code keeps the accounts its script makes** (ADR-0031 question 8), in a
  table of its own, `enrollment_accounts`: the read-write one, at standard or
  full; the read-only one, always; and those nervus used on the machine before
  and takes its line off. A code for a machine described by hand gives it the
  read-only account alone (question 4), at a level of its own that a release
  before this one does not know, so it serves no script for it.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import time
from collections.abc import Iterable
from dataclasses import dataclass

from nervus import accounts
from nervus.database import Database
from nervus.enrolled_hosts import HostRefused, check
from nervus.enrollments import EnrollmentRefused, host_keys

CODE_SECONDS = 15 * 60
CODE_BYTES = 24  # 192 random bits, in a URL
ID_BYTES = 8
KEEP_SECONDS = 24 * 3600  # how long a code is kept past its expiry, for the UI
# An account name as a login names it: what `useradd` allows on the machines nervus enrolls.
LOGIN = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}")

_COLUMNS = "id, name, address, level, made_at, expires_at, made_by, used_at, outcome"


@dataclass(frozen=True)
class EnrollmentCode:
    id: str
    name: str
    address: str
    level: str
    made_at: float
    expires_at: float
    made_by: str
    used_at: float | None
    outcome: str | None


# ADR-0031 question 4: the level of a code that gives a machine described by
# hand its read-only account, and nothing else.
READONLY_ACCOUNT = "readonly-account"


@dataclass(frozen=True)
class CodeAccounts:
    """The accounts a code's script makes (ADR-0031): `kind` "machine", or
    READONLY_ACCOUNT for a machine described by hand."""
    kind: str
    readwrite: str | None
    readonly: str
    off: tuple[str, ...]


def _accounts(level: str, readwrite: str | None, readonly: str | None, off) -> CodeAccounts:
    """The accounts as a code keeps them, or HostRefused saying what is wrong."""
    kind = accounts.READONLY_ACCOUNT_KIND if level == READONLY_ACCOUNT else "machine"
    if level in ("read-only", READONLY_ACCOUNT):
        readwrite = None
    elif readwrite is None:
        readwrite = accounts.READWRITE
    readonly = accounts.READONLY if readonly is None else readonly
    off = tuple(sorted(set(off)))
    for name in (readwrite, readonly, *off):
        if name is not None and (not isinstance(name, str) or not accounts.NAME.fullmatch(name) or name == "root"):
            raise HostRefused("bad_account", f"{name!r} is not an account nervus uses: lowercase letters, digits, "
                                             f"_ and -, starting with a letter or _, at most 32, and never root")
    if readwrite is not None and readwrite == readonly:
        raise HostRefused("bad_account", "the read-write and the read-only accounts must be two accounts")
    return CodeAccounts(kind, readwrite, readonly, tuple(a for a in off if a not in (readwrite, readonly)))


@dataclass(frozen=True)
class CodeLogin:
    """What a code made from nervus's page logs in with: the account, and the
    one host key, as `host_keys` keeps it, the login is pinned to. Not the
    password, which nervus holds for one enrollment and writes nowhere."""
    login: str
    host_key: str


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _login_and_key(login: str | None, host_key: str | None) -> CodeLogin | None:
    """The login a code is made with, checked, or None for a code made without
    one. Raises HostRefused."""
    if login is None and host_key is None:
        return None
    if login is None or host_key is None:
        raise HostRefused("bad_login", "a login is the account and the host key it is pinned to, both or neither")
    if not isinstance(login, str) or not LOGIN.fullmatch(login):
        raise HostRefused("bad_login", f"{str(login)[:40]!r} is not an account name")
    try:
        keys = host_keys([host_key])
    except EnrollmentRefused as exc:
        raise HostRefused("bad_host_keys", exc.message) from None
    # host_keys reads the first key of a longer text and drops the rest, so the
    # lines are counted here: the login is pinned to exactly the key it was shown.
    if len(keys) != 1 or len(host_key.strip().splitlines()) != 1:
        raise HostRefused("bad_host_keys", "give exactly one host key, the one the machine answered with")
    return CodeLogin(login, keys[0])


def _now(now: float | None) -> float:
    return time.time() if now is None else now


class EnrollmentCodes:
    def __init__(self, database: Database):
        self.database = database

    def make(self, *, name: str, address: str, level: str, made_by: str, reserved: Iterable[str] = (),
             now: float | None = None, login: str | None = None,
             host_key: str | None = None, readwrite: str | None = None, readonly: str | None = None,
             off: Iterable[str] = ()) -> tuple[str, EnrollmentCode]:
        """A new code for this machine: its value, which exists only in what
        the caller shows, and its record. A code made from nervus's page also
        takes the account it logs in as and the host key that answered
        (ADR-0026), both or neither; and every code, the accounts its script
        makes (ADR-0031), nervus's names unless others are given. Raises
        HostRefused."""
        name, address, level = check(name, address, level, reserved)
        made_with = _login_and_key(login, host_key)
        return self._make(name, address, level, made_by, now, made_with, _accounts(level, readwrite, readonly, off))

    def make_readonly_account(self, *, name: str, made_by: str, described: Iterable[str],
                              readonly: str | None = None, now: float | None = None) -> tuple[str, EnrollmentCode]:
        """A code that gives machine `name`, one described by hand in hosts.yaml
        and named in `described`, the read-only account alone (ADR-0031
        question 4). Raises HostRefused."""
        if name not in set(described):
            raise HostRefused("not_described", f"{name} is not a machine described by hand that a token may be "
                                               f"issued for")
        return self._make(name, "", READONLY_ACCOUNT, made_by, now, None,
                          _accounts(READONLY_ACCOUNT, None, readonly, ()))

    def _make(self, name, address, level, made_by, now, made_with, made_accounts) -> tuple[str, EnrollmentCode]:
        now = _now(now)
        value, code_id = secrets.token_urlsafe(CODE_BYTES), secrets.token_hex(ID_BYTES)
        with self.database.transaction() as db:
            db.execute("DELETE FROM enrollment_code WHERE expires_at <= ?", (now - KEEP_SECONDS,))
            db.execute("DELETE FROM enrollment_login WHERE code_id NOT IN (SELECT id FROM enrollment_code)")
            db.execute("DELETE FROM enrollment_accounts WHERE code_id NOT IN (SELECT id FROM enrollment_code)")
            db.execute(
                "INSERT INTO enrollment_code (id, hash, name, address, level, made_at, expires_at, made_by) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (code_id, _hash(value), name, address, level, now, now + CODE_SECONDS, made_by),
            )
            if made_with is not None:
                db.execute("INSERT INTO enrollment_login (code_id, login, host_key) VALUES (?, ?, ?)",
                           (code_id, made_with.login, made_with.host_key))
            db.execute("INSERT INTO enrollment_accounts (code_id, kind, readwrite, readonly, off) VALUES (?, ?, ?, ?, ?)",
                       (code_id, made_accounts.kind, made_accounts.readwrite, made_accounts.readonly,
                        json.dumps(list(made_accounts.off))))
            return value, self._get(db, "id", code_id)

    def accounts_of(self, code_id: str) -> CodeAccounts | None:
        """The accounts a code's script makes, or None for a code made by a
        release before this one, which kept none."""
        with self.database.transaction(write=False) as db:
            row = db.execute("SELECT kind, readwrite, readonly, off FROM enrollment_accounts WHERE code_id = ?",
                             (code_id,)).fetchone()
        return CodeAccounts(row[0], row[1], row[2], tuple(json.loads(row[3]))) if row else None

    def login_of(self, code_id: str) -> CodeLogin | None:
        """The account and host key a code was made with, or None for a code
        made without a login."""
        with self.database.transaction(write=False) as db:
            row = db.execute("SELECT login, host_key FROM enrollment_login WHERE code_id = ?", (code_id,)).fetchone()
        return CodeLogin(*row) if row else None

    @staticmethod
    def _get(db, column: str, value: str) -> EnrollmentCode | None:
        row = db.execute(f"SELECT {_COLUMNS} FROM enrollment_code WHERE {column} = ?", (value,)).fetchone()
        return EnrollmentCode(*row) if row else None

    def get(self, code_id: str) -> EnrollmentCode | None:
        with self.database.transaction(write=False) as db:
            return self._get(db, "id", code_id)

    def find(self, value: str, now: float | None = None) -> EnrollmentCode | None:
        """The code, if it is unspent and in time; otherwise None."""
        now = _now(now)
        with self.database.transaction(write=False) as db:
            code = self._get(db, "hash", _hash(value))
        return code if code and code.used_at is None and code.expires_at > now else None

    def spend(self, value: str, now: float | None = None) -> EnrollmentCode | None:
        """Spend the code, if it is unspent and in time: of two reports at
        once, one is accepted. Returns it spent, or None."""
        now = _now(now)
        with self.database.transaction() as db:
            done = db.execute("UPDATE enrollment_code SET used_at = ? WHERE hash = ? AND used_at IS NULL "
                              "AND expires_at > ?", (now, _hash(value), now)).rowcount
            return self._get(db, "hash", _hash(value)) if done else None

    def recent(self, now: float | None = None) -> list[EnrollmentCode]:
        """Every code kept, the latest first: those not yet a day past expiry."""
        with self.database.transaction(write=False) as db:
            rows = db.execute(f"SELECT {_COLUMNS} FROM enrollment_code WHERE expires_at > ? "
                              "ORDER BY made_at DESC, id", (_now(now) - KEEP_SECONDS,)).fetchall()
        return [EnrollmentCode(*row) for row in rows]

    def cancel(self, code_id: str, now: float | None = None) -> None:
        """The code expires now, unspent: what the UI does when the record of
        its making cannot be written."""
        with self.database.transaction() as db:
            db.execute("UPDATE enrollment_code SET expires_at = MIN(expires_at, ?) WHERE id = ?",
                       (_now(now), code_id))

    def finish(self, code_id: str, outcome: str) -> None:
        """What became of the code's enrollment, in words for the owner."""
        with self.database.transaction() as db:
            db.execute("UPDATE enrollment_code SET outcome = ? WHERE id = ?", (outcome, code_id))
