"""Which account on a machine a connection logs in to (ADR-0031): chosen here,
in one place, and nowhere else.

A machine that clients may change has two accounts of nervus's: the read-write
one, at the level its owner chose, and the read-only one, which the machine
keeps read-only by the sandbox its kernel enforces. nervus chooses between them
from the client's assignment on that machine; the client has no say, and the
machine refuses what the account may not do.

- **Read-only** where the token is read-only on the machine, or the machine is
  itself read-only: the machine's read-only account. A machine with none
  refuses, here, before anything is sent, saying how its owner adds one.
- **Otherwise** the machine's read-write account, at the machine's own level;
  for a machine described by hand, whose level nervus does not know,
  "read-write".
- **A VM used by its id** is `agent`, at full, as nervus enrolled it.

The choice is put on the call (certs.take), and every connection the call makes
carries it; nervus.ssh.connect refuses one made for a client's call without it.

What nervus knows of each machine's accounts is kept in `machine_account`, one
row a machine, written when nervus has checked the read-only account itself
(enrollment, ADR-0031 step 5). A row for a machine added from the UI is tied to
the enrollment it was made for, by that enrollment's time: one an older release
left behind when it added the machine again is not believed, and the machine is
read as one added before this release. A table of its own, not a column, so an
older release never misreads it (ADR-0014 decision F).
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Iterable
from dataclasses import dataclass

from nervus.auth import Token
from nervus.certs import Route
from nervus.config import Host
from nervus.database import Database

# The names nervus gives the accounts it makes (ADR-0031 question 8), which the
# form that adds a machine fills in; and the one every machine added before
# this release, and every VM, has.
READWRITE = "nervusagent"
READONLY = "nervusagent-readonly"
LEGACY = "agent"
# The kind of enrollment that gives a machine described by hand its read-only
# account alone (question 4).
READONLY_ACCOUNT_KIND = "readonly-account"
# An account name nervus accepts: a portable login name, as useradd takes it.
NAME = re.compile(r"[a-z_][a-z0-9_-]{0,31}")


class NoReadOnlyAccount(ValueError):
    """A read-only call to a machine with no read-only account: nothing runs."""

    def __init__(self, host: str, why: str | None = None):
        because = f" ({why})" if why else ""
        super().__init__(
            f"{host} has no read-only account{because}, and this token is read-only there, so nothing ran. "
            f"Its owner adds one from nervus's Machines page: by adding the machine again, or, for a machine "
            f"described by hand, with the line shown beside it.")
        self.host = host


# ADR-0031 question 2a: what a client may not do where it is read-only, refused
# by nervus before anything is sent, each with a record and these words.
def read_only_put(host: str) -> str:
    return (f"this token is read-only on {host}, so nervus sends no file there: put and uploads are refused "
            f"where a client is read-only (ADR-0031), and nothing was sent")


def read_only_vms(host: str) -> str:
    return (f"this token is read-only on {host}, the Proxmox host, so it may not use the Proxmox API or a VM by "
            f"its id: the API has one credential of nervus's for every client, with no look-only half, and a "
            f"VM nervus enrolls has one account, with sudo (ADR-0031); nothing was sent")

def choose(token: Token | None, host: Host) -> Route:
    """The account a call by `token` (None for the operator's own work) logs in
    to on `host`, and the level it runs at there."""
    if (token is not None and host.name in token.readonly) or host.level == "read-only":
        if host.readonly_user is None:
            raise NoReadOnlyAccount(host.name)
        return Route(host.name, host.readonly_user, True, "read-only")
    return Route(host.name, host.agent_user, False, host.level or "read-write")


def described(hosts: dict[str, Host]) -> dict[str, Host]:
    """The machines described by hand that a token may be issued for, and so
    may be given a read-only account from the Machines page (question 4)."""
    return {name: h for name, h in hosts.items() if h.level is None and not h.never_issued}


def accounts_at(hosts: dict[str, Host], name: str) -> frozenset[str]:
    """The accounts machine `name`, described by hand, is reached as under every
    entry of `hosts` (hosts.yaml's) at its address: one machine may be two
    entries, behind two accounts (ADR-0009), and none of them may be made its
    read-only account (procedure 068, section 12)."""
    address = hosts[name].address
    return frozenset(h.agent_user for h in hosts.values() if h.address == address)


def has_both(host: Host) -> bool:
    """A machine on which a client may be either read-only or read-write: it has
    a read-only account, and is not itself read-only."""
    return host.readonly_user is not None and host.level != "read-only"


def vm_name(vmid: int) -> str:
    """A VM used by its id, as a route and its connection name it."""
    return f"vmid {vmid}"


def vm_route(vmid: int) -> Route:
    """A VM used by its id: `agent`, with sudo, as nervus's enrollment made it."""
    return Route(vm_name(vmid), LEGACY, False, "full")


def level(token: Token, host: Host) -> str:
    """What `hosts` says of this token on `host`: read-only where it would run
    read-only, whether or not the machine has the account yet."""
    if host.name in token.readonly or host.level == "read-only":
        return "read-only"
    return host.level or "read-write"


@dataclass(frozen=True)
class MachineAccount:
    name: str
    enrolled_at: float | None  # the enrollment it was made for; None for a machine described by hand
    readwrite: str | None      # None at read-only alone, and for a machine described by hand
    readonly: str | None       # None where no read-only account could be made
    groups: tuple[str, ...]    # the read-only account's groups, as nervus saw them
    why_none: str | None       # why there is no read-only account, in words
    checked_at: float
    # ADR-0031 questions 9 and 13: the accounts nervus's script made on this machine, as it said, those of
    # names the machine had before included, and the machine id it said them on. Removing the machine
    # deletes those alone; every other account keeps itself and its home.
    made: tuple[str, ...] = ()
    machine_id: str | None = None


_COLUMNS = "name, enrolled_at, readwrite, readonly, readonly_groups, why_none, checked_at, made, machine_id"


def made_names(listed: Iterable) -> tuple[str, ...]:
    """Of `listed`, the names an account nervus made can have: never root, nor
    what is no account name."""
    return tuple(sorted({a for a in listed if isinstance(a, str) and NAME.fullmatch(a) and a != "root"}))


def _made(text) -> tuple[str, ...]:
    """The accounts a row says nervus made. Since question 13 they may be of
    names the machine had before, so any account name counts. Fail closed:
    anything that cannot be read as such names none, so nothing an owner made
    is deleted."""
    try:
        listed = json.loads(text) if text else []
    except (TypeError, ValueError):
        return ()
    return made_names(listed) if isinstance(listed, list) else ()


def _row(row: tuple) -> MachineAccount:
    name, enrolled_at, readwrite, readonly, groups, why_none, checked_at, made, machine_id = row
    return MachineAccount(name, enrolled_at, readwrite, readonly, tuple(json.loads(groups)), why_none, checked_at,
                          _made(made), machine_id)


def _name(value: str | None) -> str | None:
    if value is not None and (not isinstance(value, str) or not NAME.fullmatch(value)):
        raise ValueError(f"{value!r} is not an account name nervus keeps")
    return value


# The read-only account's groups, as the machine named them, are only shown (the
# Machines page, the script's answer): kept as words, whatever their names, so a
# group id with no name, which `id -Gn` prints as a number, or a directory's
# group, is never a reason to refuse after the machine was stored (procedure
# 068, section 12). A character that is not printable shows as "?".
_GROUPS, _GROUP_CHARS = 64, 64


def groups_shown(groups: Iterable[str]) -> tuple[str, ...]:
    words = ("".join(c if c.isprintable() and not c.isspace() else "?" for c in str(g))[:_GROUP_CHARS]
             for g in groups)
    return tuple(w for w in words if w)[:_GROUPS]


class MachineAccounts:
    """The `machine_account` table: one row a machine, replaced whole."""

    def __init__(self, database: Database):
        self.database = database

    def get(self, name: str) -> MachineAccount | None:
        with self.database.transaction(write=False) as db:
            row = db.execute(f"SELECT {_COLUMNS} FROM machine_account WHERE name = ?", (name,)).fetchone()
        return _row(row) if row else None

    def all(self) -> list[MachineAccount]:
        with self.database.transaction(write=False) as db:
            return [_row(r) for r in db.execute(f"SELECT {_COLUMNS} FROM machine_account ORDER BY name")]

    @staticmethod
    def write(db, name: str, *, enrolled_at: float | None, readwrite: str | None, readonly: str | None,
              groups: Iterable[str], why_none: str | None, now: float | None = None,
              made: Iterable[str] = (), machine_id: str | None = None) -> None:
        """Machine `name`'s row, inside the transaction `db`: the one that stores
        the machine itself, where there is one (enrolled_hosts.add).

        `made` is the accounts the script said it made this time, and
        `machine_id` the machine it said so on. What an earlier row said nervus
        made is kept where it was said on the same machine, whatever names the
        machine has now, so that removing it deletes them too; on another
        machine by the same name, it is not (ADR-0031 questions 9 and 13)."""
        for value in (readwrite, readonly):
            _name(value)
        if readwrite is not None and readwrite == readonly:
            raise ValueError("one account cannot be both the read-write and the read-only one")
        made = set(made)
        if machine_id is not None:
            before = db.execute("SELECT made, machine_id FROM machine_account WHERE name = ?", (name,)).fetchone()
            if before is not None and before[1] == machine_id:
                made |= set(_made(before[0]))
        db.execute(f"INSERT OR REPLACE INTO machine_account ({_COLUMNS}) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                   (name, enrolled_at, readwrite, readonly, json.dumps(list(groups_shown(groups))), why_none,
                    time.time() if now is None else now, json.dumps(list(made_names(made))), machine_id))

    def record(self, name: str, *, enrolled_at: float | None, readwrite: str | None, readonly: str | None,
               groups: Iterable[str], why_none: str | None, now: float | None = None,
               made: Iterable[str] = (), machine_id: str | None = None) -> MachineAccount:
        with self.database.transaction() as db:
            self.write(db, name, enrolled_at=enrolled_at, readwrite=readwrite, readonly=readonly, groups=groups,
                       why_none=why_none, now=now, made=made, machine_id=machine_id)
        return self.get(name)

    def remove(self, name: str) -> bool:
        with self.database.transaction() as db:
            return bool(db.execute("DELETE FROM machine_account WHERE name = ?", (name,)).rowcount)
