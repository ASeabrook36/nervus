"""A VM as a target of nervus's tools, named by its id (ADR-0022 step 3).

- **Enrolled on first use** (decision 2a): the first call that names a VM
  not yet enrolled enrolls it through its guest agent (enroller.py), then
  carries on. Nothing is remembered when that fails; the next call tries again.
- **Checked at every use, and repaired** (decision 5a), never trusting the
  network for a key:
  - the VM is gone (Proxmox has no such id): its row is dropped, and the call
    fails saying so;
  - its address moved (SSH does not answer there): the addresses its guest
    agent reports now are tried with the same pinned keys; one call, no person;
  - its key differs, nervus's key is refused, or no address answers with the
    pinned keys: it is enrolled afresh through its guest agent, and the call
    says what changed.
- **One enrollment at a time per VM**: two first calls at once do not both
  enroll it.
- **What a call changed is in that call's audit result**: `connect` returns a
  note saying so, and keeps it for the call's result record (certs.note), so
  an export or an upload, whose answers have no place for it, records it too.
- **`listing`** names every enrolled VM Proxmox still has, and forgets the
  rest, but only from a listing Proxmox gave: a failed call forgets nothing.

Which tokens may name a VM is server.py's business (decision 6a).
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import asyncssh

from nervus import accounts, certs
from nervus.enroller import Enroller, EnrollmentFailed
from nervus.enrollments import EnrolledVM, EnrollmentStore
from nervus.guest import FIRST_POLL, Guest, GuestError

_NO_SSH = (OSError, asyncio.TimeoutError, asyncssh.Error)
_NOT_THIS_VM = (asyncssh.HostKeyNotVerifiable, asyncssh.PermissionDenied)


def _utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).isoformat(timespec="seconds")


class VMTargets:
    def __init__(self, store: EnrollmentStore, enroller: Enroller, api, *, poll: float = FIRST_POLL):
        self.store = store
        self.enroller = enroller
        self.api = api
        self.poll = poll
        self._locks: dict[int, asyncio.Lock] = {}

    def _guest(self, vmid: int) -> Guest:
        return Guest(self.api, vmid, poll=self.poll)

    async def connect(self, vmid: int, token_id: str) -> tuple[asyncssh.SSHClientConnection, str | None]:
        """SSH to VM `vmid` as agent, enrolling or repairing it first if it
        needs it. Returns the connection, and a note saying what changed, or
        None; the note is also kept for the audit result of the call this is
        made for (certs.note). Raises EnrollmentFailed, saying why, if it
        cannot be reached."""
        async with self._locks.setdefault(vmid, asyncio.Lock()):
            row = self.store.get(vmid)
            guest = self._guest(vmid)
            if row is None:
                row, _ = await self._enroll(guest, token_id)
                note = f"VM {vmid} enrolled, at {row.address}"
            else:
                try:
                    return await self.enroller.connect(row.address, row.host_keys, machine=accounts.vm_name(vmid)), None
                except _NOT_THIS_VM:
                    await self._still_there(guest, row)
                    row, note = await self._afresh(guest, token_id, row)
                except _NO_SSH:
                    await self._still_there(guest, row)
                    row, note = await self._moved(guest, token_id, row)
            # The VM and its row are changed by now. The note goes with the call as well as to
            # the caller, so the call's audit result has it whatever becomes of the connection
            # below or of the call after it (ADR-0001 section 10).
            certs.note(note)
            return await self.enroller.connect(row.address, row.host_keys, machine=accounts.vm_name(vmid)), note

    async def _enroll(self, guest: Guest, token_id: str):
        return await self.enroller.enroll(guest, token_id)

    async def _still_there(self, guest: Guest, row: EnrolledVM) -> None:
        """Fail, forgetting the VM, if Proxmox no longer has it."""
        try:
            await guest.agent()
        except GuestError as exc:
            if exc.code != "no_such_vm":
                raise EnrollmentFailed(exc.code, exc.message) from None
            self.store.drop(row.vmid, row.host_keys)
            raise EnrollmentFailed("vm_gone", f"VM {row.vmid} is gone: Proxmox has no such VM, "
                                              f"so nervus has forgotten it") from None

    async def _moved(self, guest: Guest, token_id: str, row: EnrolledVM):
        """SSH did not answer at the row's address: try where the VM is now,
        with the same keys, then afresh."""
        try:
            address = await self.enroller.reach(guest, row.host_keys)
        except EnrollmentFailed:
            return await self._afresh(guest, token_id, row)
        moved = self.store.moved(row.vmid, row.host_keys, address)
        if moved is None:  # forgotten or replaced meanwhile
            return await self._afresh(guest, token_id, row)
        return moved, f"VM {row.vmid} moved from {row.address} to {address}"

    async def _afresh(self, guest: Guest, token_id: str, row: EnrolledVM):
        new, _ = await self._enroll(guest, token_id)
        if new.host_keys != row.host_keys:
            note = f"VM {row.vmid}'s host key changed, as its guest agent reports; enrolled again"
        elif new.address != row.address:
            note = f"VM {row.vmid} moved from {row.address} to {new.address}; enrolled again"
        else:
            note = f"VM {row.vmid} enrolled again: nervus's access to it was repaired"
        return new, note

    async def listing(self) -> list[dict]:
        """Every enrolled VM Proxmox still has: id, Proxmox's name, address,
        when it was enrolled. Rows for VMs Proxmox no longer has are dropped.
        Raises GuestError if Proxmox cannot be asked, dropping nothing."""
        resp = await self.api.request("GET", "/cluster/resources", {"type": "vm"})
        if resp.status != 200 or not isinstance(resp.data, list):
            raise GuestError("guest_agent_error", f"cannot list VMs: Proxmox answered {resp.status} {resp.reason}")
        qemu = {g["vmid"]: g for g in resp.data
                if isinstance(g, dict) and g.get("type") == "qemu" and isinstance(g.get("vmid"), int)}
        self.store.keep_only(qemu)
        return [{"vmid": row.vmid, "name": qemu[row.vmid].get("name"), "address": row.address,
                 "enrolled_at": _utc(row.enrolled_at)}
                for row in self.store.all() if row.vmid in qemu]
