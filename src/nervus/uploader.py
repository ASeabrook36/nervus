"""Runs uploads' deliveries inside nervus, apart from the request that sent the
file (ADR-0020 decision G).

A delivery may take minutes: through a VM's guest agent, files move at about
0.17 MB/s (procedure 026). So the route starts it as a task of nervus's own and
waits for it only up to `wait` seconds. A client timeout or disconnect ends the
wait, not the delivery. Asking again, by request key, finds the same upload.

Where a file goes is the deliverer's business (steps 3 and 4): one coroutine
that takes an upload being delivered, puts its staged copy in place, and
returns the route it used and the SHA-256 the destination computed of what it
wrote. It raises UploadRefused for a refusal it can explain, such as a file
already there. The store decides whether the hash makes it delivered.

The audit log gets the sending request's result when the delivery ends; if a
VM was enrolled or repaired on the way, or could not be, that result says so
(`vm_note`). A stop cancels every delivery in progress; the store fails each one, and its
start-up recovery deletes what was staged (uploads.py).
"""

from __future__ import annotations

import asyncio
import sys

import anyio
from collections.abc import Awaitable, Callable

import asyncssh

from nervus import certs
from nervus.audit import AuditError, AuditLog
from nervus.exporter import DEFAULT_WAIT_SECONDS, MAX_WAIT_SECONDS, SWEEP_SECONDS
from nervus.proxmox import ProxmoxError
from nervus.uploads import Upload, UploadRefused, UploadStore

TOOL = "upload"

Deliver = Callable[[Upload], Awaitable[tuple[str, str]]]


def _console(line: str) -> None:
    print(f"nervus: {line}", file=sys.stderr, flush=True)


def upload_fields(upload: Upload) -> dict:
    """An upload as the audit log records it: no token, no path on nervus."""
    fields = {"upload_id": upload.id, "request_key": upload.request_key, "state": upload.state,
              "destination": upload.destination, "size": upload.size, "sha256": upload.sha256,
              "bytes_received": upload.bytes_received, "bytes_delivered": upload.bytes_delivered}
    if upload.route is not None:
        fields["route"] = upload.route
    if upload.failure_code is not None:
        fields.update(failure_code=upload.failure_code, failure_message=upload.failure_message)
    return fields


def clamp_wait(wait: float) -> float:
    return max(0.0, min(wait, MAX_WAIT_SECONDS))


class Uploader:
    def __init__(self, store: UploadStore, audit: AuditLog, *, deliver: Deliver):
        self.store = store
        self.audit = audit
        self.deliver = deliver
        # upload id -> its delivery
        self._running: dict[str, asyncio.Task] = {}

    def start(self, upload: Upload, run_id: str) -> None:
        """Deliver this upload as nervus's own work. `run_id` is the sending
        request's audit intent, whose result is written when it ends."""
        task = asyncio.get_running_loop().create_task(self._work(upload, run_id))
        self._running[upload.id] = task
        task.add_done_callback(lambda _: self._running.pop(upload.id, None))

    async def wait(self, upload_id: str, wait: float = DEFAULT_WAIT_SECONDS) -> None:
        """Wait up to `wait` seconds for this upload's delivery, if one is
        running. asyncio.wait never cancels what it waits for: a request that
        is cut off leaves the delivery running."""
        task = self._running.get(upload_id)
        if task is not None:
            await asyncio.wait({task}, timeout=clamp_wait(wait))

    async def tidy(self, interrupted: list[Upload]) -> None:
        """After a stop: ask each interrupted delivery's target to remove the
        temporary file it may have left (decision G). Best effort: its name
        says it is nervus's, so one left behind is recognisable.

        No client asks for this, so each clean-up has its own audit record,
        `actor: operator`, and its login is signed `operator run=<record>`
        (ADR-0025, the operator's choice at step 3). A machine enrolled with
        nervus's CA admits nothing else. Without the record, nothing connects."""
        cleanup = getattr(self.deliver, "cleanup", None)
        for upload in interrupted if cleanup else ():
            try:
                run_id = self.audit.record_intent(TOOL, {"actor": "operator", "action": "cleanup",
                                                         "upload_id": upload.id, "destination": upload.destination})
            except AuditError as exc:
                _console(f"WARNING: upload {upload.id}'s leftovers were not removed: the audit log refused: {exc}")
                continue
            certs.acting_for(None, run_id)
            try:
                with anyio.move_on_after(60):
                    await cleanup(upload)
            except Exception as exc:
                _console(f"WARNING: could not remove what upload {upload.id} left at {upload.destination}: {exc}")
            try:
                self.audit.record_result(run_id, TOOL, {"upload_id": upload.id, **certs.ssh_ports()})
            except AuditError as exc:
                _console(f"WARNING: the audit result of upload {upload.id}'s clean-up was not written: {exc}")

    async def sweep_forever(self, every: float = SWEEP_SECONDS) -> None:
        """Forget spent uploads once a day old, hourly, for as long as nervus runs."""
        while True:
            await asyncio.sleep(every)
            try:
                self.store.sweep()
            except Exception as exc:  # the next hour tries again
                _console(f"WARNING: sweeping spent uploads failed: {exc}")

    async def _work(self, upload: Upload, run_id: str) -> None:
        try:
            try:
                route, sha256 = await self.deliver(upload)
                done = self.store.delivered(upload, route, sha256)
            except UploadRefused as exc:
                done = self.store.fail(upload, exc.code, exc.message)
            except (OSError, asyncssh.Error, ProxmoxError) as exc:
                done = self.store.fail(upload, "destination_error", f"{type(exc).__name__}: {exc}")
            except asyncio.CancelledError:
                done = self.store.fail(upload, "interrupted",
                                       "nervus stopped before it was delivered; send it again with a new request key")
                self._result(run_id, done)
                raise
            except Exception as exc:  # a fault in nervus: the client learns the kind, the console the rest
                _console(f"WARNING: delivering upload {upload.id} failed: {type(exc).__name__}: {exc}")
                done = self.store.fail(upload, "internal_error", f"nervus failed delivering it ({type(exc).__name__})")
            self._result(run_id, done)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # the store itself failed; nothing more to record
            _console(f"WARNING: recording upload {upload.id} failed: {type(exc).__name__}: {exc}")

    def _result(self, run_id: str, upload: Upload) -> None:
        try:
            # What enrolling or repairing a VM on the way did (ADR-0022 5a), and the port of
            # each SSH connection the delivery made (ADR-0025 decision 3).
            self.audit.record_result(run_id, TOOL, {**upload_fields(upload), **certs.vm_note(),
                                                    **certs.ssh_ports()})
        except AuditError as exc:
            _console(f"WARNING: the audit result of upload {upload.id} was not written: {exc}")
