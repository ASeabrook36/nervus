"""The enrollment store (ADR-0022 decision 5a): the VMs nervus has enrolled,
one database row each, keyed by VM id. The first inventory nervus writes
itself (ADR-0005 consequence 5); `hosts.yaml` and `known_hosts` stay for
machines described by hand.

A row holds the address nervus reaches the VM at, the host public keys its
guest agent reported, and when and by which token it was enrolled. Nothing in
it is trusted without being checked against the VM at each use (step 2 and
3's work); this module keeps the rows, and holds to:

- **Only an address nervus can reach a VM at is kept**, never a name: nervus
  never asks DNS for a VM (ADR-0022 question 9). Loopback is refused, since a
  VM's own 127.0.0.1 is, from nervus, nervus's machine; so are unspecified,
  link-local and multicast addresses.
- **Only host public keys are pinned**, each as its type and base64, without
  the comment, once each. Host public keys are not secret, so they live here
  rather than in `secrets/`, which stays read-only to nervus (ADR-0014 A).
- **Enrolling afresh replaces the row whole**, and returns the row it
  replaced, so the caller can say the host key changed.
- **A repair or a drop names the keys it was meant for**, and does nothing if
  the row holds others: a call still holding a row that a newer enrollment
  replaced cannot move or drop the new one.

Every change is one transaction (database.py).
"""

from __future__ import annotations

import ipaddress
import json
import time
from collections.abc import Iterable
from dataclasses import dataclass

import asyncssh

from nervus.database import Database

# Proxmox's VM ids: 100 to 999,999,999.
MIN_VMID, MAX_VMID = 100, 999_999_999

_COLUMNS = "vmid, address, host_keys, enrolled_at, enrolled_by, moved_at"


class EnrollmentRefused(ValueError):
    """A row that cannot be kept. `code` is for the client and the audit log;
    the message says what was wrong in words."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class EnrolledVM:
    vmid: int
    address: str
    host_keys: tuple[str, ...]  # "type base64", sorted
    enrolled_at: float
    enrolled_by: str  # the token id that enrolled it
    moved_at: float | None  # when its address was last repaired


def _now(now: float | None) -> float:
    return time.time() if now is None else now


def _vmid(vmid) -> int:
    if not isinstance(vmid, int) or isinstance(vmid, bool) or not MIN_VMID <= vmid <= MAX_VMID:
        raise EnrollmentRefused("bad_vmid", f"{vmid!r} is not a Proxmox VM id ({MIN_VMID} to {MAX_VMID})")
    return vmid


def _address(address) -> str:
    """The address in one form, or refused. Never a name, never loopback."""
    try:
        if not isinstance(address, str):
            raise ValueError
        ip = ipaddress.ip_address(address)
    except ValueError:
        raise EnrollmentRefused("bad_address", f"{address!r} is not an IP address; a VM is reached by address, "
                                               f"never by name") from None
    if ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip.is_multicast:
        raise EnrollmentRefused("bad_address", f"{address} is not an address nervus can reach a VM at "
                                               f"(loopback, unspecified, link-local or multicast)")
    return str(ip)


def valid_vmid(vmid) -> int:
    """`vmid` if it is a Proxmox VM id, or EnrollmentRefused (a ValueError)."""
    return _vmid(vmid)


def reachable(address) -> bool:
    """Whether the store would keep `address`: what the enroller tries."""
    try:
        _address(address)
    except EnrollmentRefused:
        return False
    return True


def host_keys(keys) -> tuple[str, ...]:
    """Host keys as the store keeps them, or EnrollmentRefused."""
    return _host_keys(keys)


def _host_keys(keys) -> tuple[str, ...]:
    """Each key as its type and base64, sorted, once each; at least one."""
    if isinstance(keys, (str, bytes)) or not isinstance(keys, Iterable):
        raise EnrollmentRefused("bad_host_keys", "give the host keys as a list of public key lines")
    kept = set()
    for line in keys:
        try:
            if not isinstance(line, str) or "PRIVATE KEY" in line:
                raise ValueError
            key = asyncssh.import_public_key(line)
        except (ValueError, asyncssh.KeyImportError):
            raise EnrollmentRefused("bad_host_keys", f"{str(line)[:80]!r} is not an SSH host public key") from None
        kept.add(" ".join(key.export_public_key("openssh").decode().split()[:2]))  # no comment
    if not kept:
        raise EnrollmentRefused("bad_host_keys", "no host key was given; a VM is pinned by at least one")
    return tuple(sorted(kept))


def _row(row: tuple) -> EnrolledVM:
    vmid, address, keys, enrolled_at, enrolled_by, moved_at = row
    return EnrolledVM(vmid, address, tuple(json.loads(keys)), enrolled_at, enrolled_by, moved_at)


def _key_clash(db, vmid: int, keys: set[str]) -> str | None:
    """A machine nervus already knows, under another identity, that shares a host
    key with `keys` -- so enrolling `vmid` with them would alias it to that machine.

    ADR-0022 takes the guest agent as the trust anchor, but a root-compromised VM
    controls its own guest agent and can make it report another machine's real host
    keys and address. That machine, trusting nervus's CA, answers the enrollment
    check, so without this nervus would store the VM pointing at it and a client
    could reach it outside its allowlist (procedure 056, finding 2). Host public
    keys are a machine's identity here, so a shared one betrays the aliasing."""
    for other, keys_json in db.execute("SELECT vmid, host_keys FROM enrolled_vm WHERE vmid != ?", (vmid,)):
        if keys & set(json.loads(keys_json)):
            return f"enrolled VM {other}"
    for name, keys_json in db.execute("SELECT name, host_keys FROM enrolled_host"):
        if keys & set(json.loads(keys_json)):
            return f"the enrolled host {name!r}"
    return None


class EnrollmentStore:
    def __init__(self, database: Database):
        self.database = database

    @staticmethod
    def _get(db, vmid: int) -> EnrolledVM | None:
        row = db.execute(f"SELECT {_COLUMNS} FROM enrolled_vm WHERE vmid = ?", (vmid,)).fetchone()
        return _row(row) if row else None

    def get(self, vmid: int) -> EnrolledVM | None:
        vmid = _vmid(vmid)
        with self.database.transaction(write=False) as db:
            return self._get(db, vmid)

    def all(self) -> list[EnrolledVM]:
        with self.database.transaction(write=False) as db:
            return [_row(r) for r in db.execute(f"SELECT {_COLUMNS} FROM enrolled_vm ORDER BY vmid")]

    def enroll(self, vmid: int, address: str, host_keys: Iterable[str], token_id: str,
               now: float | None = None) -> tuple[EnrolledVM, EnrolledVM | None]:
        """Keep VM `vmid` as enrolled at `address`, pinned to `host_keys`, by
        `token_id`, replacing any row it had. Returns the new row, and the
        one it replaced or None."""
        vmid, address, keys = _vmid(vmid), _address(address), _host_keys(host_keys)
        if not isinstance(token_id, str) or not token_id:
            raise EnrollmentRefused("bad_token", "an enrollment names the token that made it")
        with self.database.transaction() as db:
            clash = _key_clash(db, vmid, set(keys))
            if clash is not None:
                raise EnrollmentRefused("host_key_in_use",
                                        f"a host key reported for VM {vmid} already belongs to {clash}; if the VM "
                                        "was cloned, regenerate its SSH host keys, otherwise its guest agent may "
                                        "be reporting another machine")
            replaced = self._get(db, vmid)
            db.execute(f"INSERT OR REPLACE INTO enrolled_vm ({_COLUMNS}) VALUES (?, ?, ?, ?, ?, NULL)",
                       (vmid, address, json.dumps(keys), _now(now), token_id))
            return self._get(db, vmid), replaced

    def moved(self, vmid: int, host_keys: tuple[str, ...], address: str,
              now: float | None = None) -> EnrolledVM | None:
        """The VM's address moved and its keys did not: keep the new address,
        if the row still holds `host_keys`. Returns the repaired row, or None
        if there is no such row now."""
        vmid, address = _vmid(vmid), _address(address)
        with self.database.transaction() as db:
            done = db.execute("UPDATE enrolled_vm SET address = ?, moved_at = ? WHERE vmid = ? AND host_keys = ?",
                              (address, _now(now), vmid, json.dumps(tuple(host_keys)))).rowcount
            return self._get(db, vmid) if done else None

    def drop(self, vmid: int, host_keys: tuple[str, ...]) -> bool:
        """The VM is gone: forget it, if the row still holds `host_keys`."""
        vmid = _vmid(vmid)
        with self.database.transaction() as db:
            return bool(db.execute("DELETE FROM enrolled_vm WHERE vmid = ? AND host_keys = ?",
                                   (vmid, json.dumps(tuple(host_keys)))).rowcount)

    def keep_only(self, present: Iterable[int]) -> list[int]:
        """Forget every VM not in `present`, the VM ids the hypervisor has now
        (one /cluster/resources call). Returns the ids dropped."""
        present = set(present)
        with self.database.transaction() as db:
            gone = [vmid for (vmid,) in db.execute("SELECT vmid FROM enrolled_vm ORDER BY vmid")
                    if vmid not in present]
            db.executemany("DELETE FROM enrolled_vm WHERE vmid = ?", [(vmid,) for vmid in gone])
            return gone
