"""The enrolled-host store (ADR-0024 decision 3): machines enrolled from the web
UI, one database row each, keyed by the name a token's allowlist uses.

A row holds the address nervus uses, the level the machine's owner chose
(read-only, standard or full, enforced by the machine itself), its host
public keys as the machine reported them during enrollment, its machine id,
and when and by whom it was enrolled. nervus reads these at every call,
beside the machines hosts.yaml describes by hand, so enrolling needs no
restart.

What it holds to:
- **A name in hosts.yaml is never taken**: the caller passes those names,
  and they are refused, so a token's allowlist names one machine.
- **Only a plain name, an IP address or DNS name, a known level, host public
  keys, and a machine id in /etc/machine-id's form are kept.**
- **Enrolling again replaces the row whole**, and returns the row it
  replaced: the owner ran a new command, so the level and keys are theirs.

Every change is one transaction (database.py).
"""

from __future__ import annotations

import dataclasses
import json
import re
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from nervus.config import ConfigError, Host
from nervus.database import Database
from nervus.enrollments import EnrollmentRefused, host_keys as pinned_keys
from nervus.tls import certificate_name

# ADR-0024 decision 1, in the order of what each lets nervus do.
LEVELS = ("read-only", "standard", "full")
# A token's allowlist names it, and the UI shows it: a DNS label's shape.
NAME = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
MACHINE_ID = re.compile(r"[0-9a-f]{32}")
# ADR-0001 s4: the account nervus authenticates as, on every target.
AGENT_USER = "agent"

_COLUMNS = "name, address, level, host_keys, machine_id, enrolled_at, enrolled_by"


class HostRefused(ValueError):
    """A machine that cannot be kept, and why. `code` is for the UI and the
    audit log; the message says what was wrong in words."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class EnrolledHost:
    name: str
    address: str
    level: str
    host_keys: tuple[str, ...]  # "type base64", sorted
    machine_id: str
    enrolled_at: float
    enrolled_by: str

    def as_host(self, accounts=None) -> Host:
        """The machine as nervus's tools use a host: at its address, pinned to
        its own keys, with the accounts its enrollment made (ADR-0031).

        `accounts` is its `machine_account` row, believed only if it was made
        for this enrollment. Without one, the machine was added before this
        release, or added again since by a release before it: `agent`, which
        at read-only is the read-only account."""
        if accounts is not None and accounts.enrolled_at == self.enrolled_at:
            readwrite, readonly = accounts.readwrite, accounts.readonly
        elif self.level == "read-only":
            readwrite, readonly = None, AGENT_USER
        else:
            readwrite, readonly = AGENT_USER, None
        return Host(name=self.name, address=self.address, os="", role=f"enrolled, {self.level}",
                    agent_user=readwrite or readonly or AGENT_USER, status="onboarded", host_keys=self.host_keys,
                    level=self.level, readonly_user=readonly)


def _now(now: float | None) -> float:
    return time.time() if now is None else now


def _name(name) -> str:
    if not isinstance(name, str) or not NAME.fullmatch(name):
        raise HostRefused("bad_name", f"{name!r} is not a name for a machine: lowercase letters, digits and "
                                      f"hyphens, at most 63, not starting or ending with a hyphen")
    return name


def _address(address) -> str:
    try:
        if not isinstance(address, str):
            raise ConfigError("not text")
        return certificate_name(address)
    except ConfigError:
        raise HostRefused("bad_address", f"{address!r} is not an IP address or a DNS name") from None


def check(name, address, level, reserved: Iterable[str] = ()) -> tuple[str, str, str]:
    """`name`, `address` and `level` as a machine is kept, or HostRefused: what
    an enrollment code may be made for (ADR-0024 step 3). An empty address,
    on a code only, means the one its report comes from (decision 4a)."""
    name = _name(name)
    address = "" if address == "" else _address(address)
    if name in set(reserved):
        raise HostRefused("name_taken", f"{name} is already a machine in hosts.yaml; choose another name")
    if level not in LEVELS:
        raise HostRefused("bad_level", f"{level!r} is not a level; the levels are {', '.join(LEVELS)}")
    return name, address, level


def _row(row: tuple) -> EnrolledHost:
    name, address, level, keys, machine_id, enrolled_at, enrolled_by = row
    return EnrolledHost(name, address, level, tuple(json.loads(keys)), machine_id, enrolled_at, enrolled_by)


class EnrolledHostStore:
    def __init__(self, database: Database):
        self.database = database

    @staticmethod
    def _get(db, name: str) -> EnrolledHost | None:
        row = db.execute(f"SELECT {_COLUMNS} FROM enrolled_host WHERE name = ?", (name,)).fetchone()
        return _row(row) if row else None

    def get(self, name: str) -> EnrolledHost | None:
        with self.database.transaction(write=False) as db:
            return self._get(db, name)

    def all(self) -> list[EnrolledHost]:
        with self.database.transaction(write=False) as db:
            return [_row(r) for r in db.execute(f"SELECT {_COLUMNS} FROM enrolled_host ORDER BY name")]

    def add(self, name: str, *, address: str, level: str, host_keys: Iterable[str], machine_id: str,
            enrolled_by: str, reserved: Iterable[str] = (), now: float | None = None,
            also: Callable[[object, EnrolledHost], None] | None = None,
            ) -> tuple[EnrolledHost, EnrolledHost | None]:
        """Keep machine `name`, replacing any row it had. `reserved` is the
        names hosts.yaml has, which are refused. Returns the new row and the
        one it replaced, or None.

        `also(db, row)` writes, in the same transaction, what goes with the new
        row: its accounts (ADR-0031). If it fails, the machine is not kept and
        the row it had stays as it was (procedure 068, section 12)."""
        name, address, level = check(name, _address(address), level, reserved)
        try:
            keys = pinned_keys(host_keys)
        except EnrollmentRefused as exc:
            raise HostRefused("bad_host_keys", exc.message) from None
        if not isinstance(machine_id, str) or not MACHINE_ID.fullmatch(machine_id):
            raise HostRefused("bad_machine_id", f"{machine_id!r} is not a machine id: 32 lowercase hex digits")
        with self.database.transaction() as db:
            replaced = self._get(db, name)
            db.execute(f"INSERT OR REPLACE INTO enrolled_host ({_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?)",
                       (name, address, level, json.dumps(keys), machine_id, _now(now), enrolled_by))
            row = self._get(db, name)
            if also is not None:
                also(db, row)
            return row, replaced

    def move(self, name: str, address: str) -> bool:
        """Machine `name` is now at `address`; its keys and level stay
        (decision 4a). False if there was no such row."""
        address = _address(address)
        with self.database.transaction() as db:
            return bool(db.execute("UPDATE enrolled_host SET address = ? WHERE name = ?", (address, name)).rowcount)

    def remove(self, name: str) -> bool:
        """Forget machine `name`. False if there was no such row."""
        with self.database.transaction() as db:
            return bool(db.execute("DELETE FROM enrolled_host WHERE name = ?", (name,)).rowcount)


def merged(file_hosts: dict[str, Host], store: EnrolledHostStore | None, machine_accounts=None) -> dict[str, Host]:
    """hosts.yaml's machines, then the enrolled ones, read now. A hand-written
    entry keeps its name if one was enrolled under it before hosts.yaml
    gained it: the operator's file is the last word.

    Each with its accounts (ADR-0031), from `machine_accounts`
    (nervus.accounts.MachineAccounts): a hand-written entry, the account it
    names and the read-only account its owner added; an enrolled one, what its
    enrollment made."""
    rows = {a.name: a for a in machine_accounts.all()} if machine_accounts is not None else {}
    hosts = {}
    for name, host in file_hosts.items():
        row = rows.get(name)
        if row is not None and row.enrolled_at is None and row.readonly is not None:
            host = dataclasses.replace(host, readonly_user=row.readonly)
        hosts[name] = host
    if store is not None:
        for row in store.all():
            if row.name not in hosts:
                hosts[row.name] = row.as_host(rows.get(row.name))
    return hosts
