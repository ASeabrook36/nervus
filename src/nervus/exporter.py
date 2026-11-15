"""Runs exports inside nervus, apart from the call that asked for them
(ADR-0016 decision I).

A copy may take minutes: the guest agent moves about 1.3 MB/s (step 0), and a
client's call is cut off at 60 seconds. So `export` starts the work as a task
of nervus's own and waits for it only up to `wait` seconds. A client timeout or
disconnect ends the wait, not the copy. Calling again with the same token and
request key returns the same export, to check progress or to retry, and never
starts a second copy, even while the source is still being measured and no
export is recorded yet.

What becomes of the work is the export store's record: ready, or failed with a
reason, including a source refused before any space was reserved. The audit
log gets the creating call's result when the export ends; if a VM was enrolled
or repaired on the way, or could not be, that result says so (`vm_note`).

A stop cancels every copy in progress; the store fails each one, and its
start-up recovery deletes anything left (exports.py).
"""

from __future__ import annotations

import asyncio
import contextlib
import sys
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass

import asyncssh

from nervus import certs
from nervus.audit import AuditError, AuditLog
from nervus.config import Host
from nervus.export_sources import HostSource, Source, VMSource, stage
from nervus.exports import REQUEST_KEY, Export, ExportRefused, ExportStore
from nervus.enroller import EnrollmentFailed
from nervus.proxmox import ProxmoxError

# ADR-0016 decision I: the call waits this long by default, and never longer
# than a client's own limit allows (Codex's is 60 seconds).
DEFAULT_WAIT_SECONDS = 30.0
MAX_WAIT_SECONDS = 55.0
# Decision E: expired exports are swept at every call and once an hour.
SWEEP_SECONDS = 3600.0
# What `state` says before an export is recorded: the source is being measured.
MEASURING = "measuring"


@dataclass(frozen=True)
class HostRequest:
    host: Host
    remote_path: str

    def describe(self) -> dict:
        return {"kind": "host", "host": self.host.name, "remote_path": self.remote_path}

    @property
    def filename(self) -> str:
        return self.remote_path


@dataclass(frozen=True)
class VMRequest:
    vmid: int
    path: str

    def describe(self) -> dict:
        return {"kind": "vm", "vmid": self.vmid, "path": self.path}

    @property
    def filename(self) -> str:
        return self.path


Request = HostRequest | VMRequest
# SSH to a VM by id for a token, enrolling it first if it needs it.
VMConnect = Callable[[int, str], Awaitable[tuple[asyncssh.SSHClientConnection, str | None]]]


@dataclass(frozen=True)
class Status:
    """What a call learns: the export, or None while the source is still being
    measured; and whether this call started the work."""

    export: Export | None
    created: bool

    @property
    def state(self) -> str:
        return MEASURING if self.export is None else self.export.state


def _console(line: str) -> None:
    print(f"nervus: {line}", file=sys.stderr, flush=True)


def export_fields(export: Export) -> dict:
    """An export as the audit log records it: no token, no path on nervus."""
    fields = {"export_id": export.id, "state": export.state, "bytes_written": export.bytes_written}
    if export.size is not None:
        fields.update(size=export.size, sha256=export.sha256, expires_at=export.expires_at)
    if export.failure_code is not None:
        fields.update(failure_code=export.failure_code, failure_message=export.failure_message)
    return fields


class Exporter:
    def __init__(self, store: ExportStore, audit: AuditLog, *,
                 connect: Callable[[Host], Awaitable[asyncssh.SSHClientConnection]],
                 vm_api=None, vm_connect: VMConnect | None = None):
        """`vm_connect` reaches a VM by SSH, enrolling it if it needs it
        (vm_targets.VMTargets.connect); without it, VMs are read through the
        guest agent only."""
        self.store = store
        self.audit = audit
        self.connect = connect
        self.vm_api = vm_api
        self.vm_connect = vm_connect
        # (token id, request key) -> (the work, what it is copying)
        self._running: dict[tuple[str, str], tuple[asyncio.Task, dict]] = {}

    @property
    def vms(self) -> bool:
        """Whether VM exports can work: they need nervus's Proxmox settings."""
        return self.vm_api is not None

    def check(self, token_id: str, request_key: str, request: Request) -> None:
        """Refuse, before anything is recorded as intended, a request key that
        is malformed or already names a different source, or a source path
        holding a NUL byte: nervus sends none to a machine, where it would be
        dropped or cut the path short and the audit log would not say what was
        read (procedure 056)."""
        if not isinstance(request_key, str) or not REQUEST_KEY.fullmatch(request_key):
            raise ExportRefused("bad_request_key",
                                "a request key is 1 to 128 letters, digits, '.', '_', ':' or '-'")
        if "\x00" in request.filename:
            raise ExportRefused("bad_path", "the source's path holds a NUL byte, which nervus sends to no machine: "
                                "it would be dropped or cut the path short there")
        existing = self.store.by_key(token_id, request_key)
        running = self._running.get((token_id, request_key))
        known = existing.source if existing is not None else running[1] if running else None
        if known is not None and known != request.describe():
            raise ExportRefused(
                "key_reused",
                f"request key {request_key!r} already names an export of {known}; use a new key for "
                f"another file",
            )

    async def export(self, token_id: str, request_key: str, request: Request, run_id: str,
                     wait: float = DEFAULT_WAIT_SECONDS) -> Status:
        """Start this export, or find the one this token's key already names,
        and wait up to `wait` seconds for it to end. Raises ExportRefused if
        the key already names a different source. `run_id` is this call's
        audit intent, whose result is written when work this call starts ends."""
        self.store.sweep()
        self.check(token_id, request_key, request)
        wanted = request.describe()
        key = (token_id, request_key)
        existing = self.store.by_key(token_id, request_key)
        running = self._running.get(key)
        created = existing is None and running is None
        if created:
            task = asyncio.get_running_loop().create_task(self._work(token_id, request_key, request, run_id))
            self._running[key] = (task, wanted)
            task.add_done_callback(lambda _: self._running.pop(key, None))
            running = self._running[key]
        if running is not None:
            # asyncio.wait never cancels what it waits for: a call that is cut
            # off leaves the copy running.
            await asyncio.wait({running[0]}, timeout=max(0.0, min(wait, MAX_WAIT_SECONDS)))
        return Status(export=self.store.by_key(token_id, request_key), created=created)

    def delete(self, token_id: str, export_id: str) -> bool:
        """Delete this token's export, stopping its copy if one is running."""
        export = self.store.get(token_id, export_id)
        if export is None:
            return False
        running = self._running.get((token_id, export.request_key))
        if running is not None:
            running[0].cancel()
        return self.store.delete(token_id, export_id)

    async def sweep_forever(self, every: float = SWEEP_SECONDS) -> None:
        """Decision E's hourly sweep, for as long as nervus runs."""
        while True:
            await asyncio.sleep(every)
            try:
                self.store.sweep()
            except Exception as exc:  # the next call, or the next hour, tries again
                _console(f"WARNING: sweeping expired exports failed: {exc}")

    # --- the work ---------------------------------------------------------------

    @contextlib.asynccontextmanager
    async def _source(self, request: Request, token_id: str) -> AsyncIterator[Source]:
        if isinstance(request, HostRequest):
            conn = await self.connect(request.host)
            try:
                yield HostSource(conn, request.host.name, request.remote_path)
            finally:
                conn.close()
            return
        if self.vm_api is None:
            raise ExportRefused("no_proxmox", "VM exports need nervus's Proxmox settings (--proxmox)")
        # The fastest route nervus has (ADR-0022 7a): SFTP from the VM,
        # enrolled first if it needs it, and the guest agent only if it
        # cannot be enrolled.
        conn = None
        if self.vm_connect is not None:
            try:
                conn, _ = await self.vm_connect(request.vmid, token_id)
            except EnrollmentFailed as exc:
                if exc.code == "vm_gone":
                    raise ExportRefused("vm_gone", exc.message) from None
                # The attempt may have run the enrollment script in the VM, as root: it goes in
                # this call's audit result, as an enrollment does (vm_targets.connect).
                certs.note(f"VM {request.vmid} could not be enrolled or reached over SSH: {exc.message}")
                _console(f"export from VM {request.vmid}: through the guest agent: {exc.message}")
        if conn is None:
            yield VMSource(self.vm_api, request.vmid, request.path)
            return
        try:
            yield HostSource(conn, f"VM {request.vmid}", request.path)
        finally:
            conn.close()

    async def _work(self, token_id: str, request_key: str, request: Request, run_id: str) -> None:
        wanted, filename = request.describe(), request.filename
        try:
            try:
                async with self._source(request, token_id) as source:
                    before = await source.fingerprint()
                    export, _ = self.store.begin(token_id, request_key, wanted, filename, before.size)
                    if export.state == "staging":
                        self.store.set_route(export.id, source.route)
                        export = await stage(self.store, export, source, before)
            except ExportRefused as exc:
                export = self.store.refuse(token_id, request_key, wanted, filename, exc.code, exc.message)
            except (OSError, asyncssh.Error, ProxmoxError) as exc:
                export = self.store.refuse(token_id, request_key, wanted, filename, "source_error",
                                           f"{type(exc).__name__}: {exc}")
            except asyncio.CancelledError:
                export = self.store.by_key(token_id, request_key) or self.store.refuse(
                    token_id, request_key, wanted, filename, "interrupted",
                    "the export was stopped before the source was measured")
                self._result(run_id, export)
                raise
            except Exception as exc:  # a fault in nervus: say so, rather than leave the key hanging
                _console(f"WARNING: export {request_key!r} for {token_id} failed inside nervus: {exc!r}")
                export = self.store.refuse(token_id, request_key, wanted, filename, "internal",
                                           f"nervus failed while exporting: {type(exc).__name__}")
            self._result(run_id, export)
        except Exception as exc:
            _console(f"WARNING: could not record the end of export {request_key!r} for {token_id}: {exc!r}")

    def _result(self, run_id: str, export: Export) -> None:
        try:
            # What enrolling or repairing a VM on the way did (ADR-0022 5a), and the port of
            # each SSH connection the copy made (ADR-0025 decision 3).
            self.audit.record_result(run_id, "export", {**export_fields(export), **certs.vm_note(),
                                                        **certs.ssh_ports()})
        except AuditError as exc:
            _console(f"WARNING: {exc}")
