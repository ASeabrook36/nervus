"""Where an export's bytes come from (ADR-0016 decision C), and the check that
what nervus copied is what the source holds (decision F).

Two sources:

- **a host**, over SFTP with nervus's own SSH connection, as `get` reads one;
- **a VM**, through Proxmox's guest agent: nervus reads the file with the
  API's `file-read`, at most 1 MiB per call. Above 1 MiB, Proxmox 9.2.3 joins
  base64 pieces that each carry their own padding, and returns corrupt data
  as a success (ADR-0016 Context, "Step 0"). At 1 MiB each answer is one piece,
  and every decoded length is checked against the answer's `bytes-read`.

Either way the source is asked for its size and SHA-256 before the copy and
again after it, by one small shell script run there (over SSH, or by the guest
agent's `exec`). The copy is kept only if all three agree: the source before,
the source after, and nervus's own hash of what it wrote. A file that changed
while it was read, or a source that cannot hash, is refused, so a hash nervus
reports always means the source agreed.

The remote path is the source's business: nervus does not filter it, and a
link there is followed there (decision G). The script refuses anything but a
regular file.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import re
import shlex
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Protocol

import asyncssh

from nervus.exports import Export, ExportRefused, ExportStore

MiB = 1024 * 1024
# One guest-agent read: the most Proxmox returns intact (see above).
VM_READ_BYTES = 1 * MiB
# What one such answer can weigh: base64 is 4/3 of 1 MiB, plus the JSON around
# it. The Proxmox client nervus uses for exports must accept this much; the
# `proxmox` tool's own 256 KiB limit is unchanged.
VM_RESPONSE_BYTES = 2 * MiB
HOST_READ_BYTES = 1 * MiB
# How often a copy's progress is written down for a client asking (decision I).
PROGRESS_EVERY = 8 * MiB
# How long the source may take to hash the file: 256 MiB is seconds.
HASH_TIMEOUT = 300.0
POLL_SECONDS = 0.5

# Size and SHA-256 of one regular file, in any POSIX shell, with GNU, BSD or
# uutils tools alike: `wc -c` and `sha256sum` reading standard input, so no
# file name is ever printed back or needs unescaping. Exit 3: not a regular
# file. Anything else that fails: this source cannot hash.
FINGERPRINT_SCRIPT = (
    'f=$1\n'
    '[ -f "$f" ] || { echo "not a regular file: $f" >&2; exit 3; }\n'
    'size=$(wc -c < "$f") || exit 4\n'
    'hash=$(sha256sum < "$f") || exit 5\n'
    'echo $size $hash\n'
)
NOT_A_FILE = 3
_FINGERPRINT = re.compile(r"\s*(\d+)\s+([0-9a-f]{64})\b")


@dataclass(frozen=True)
class Fingerprint:
    size: int
    sha256: str


def parse_fingerprint(exit_code: int | None, out: str, err: str, where: str) -> Fingerprint:
    if exit_code == NOT_A_FILE:
        raise ExportRefused("not_a_file", f"{where}: {err.strip() or 'not a regular file'}; export one file, "
                                          f"an archive for a directory")
    match = _FINGERPRINT.match(out or "")
    if exit_code != 0 or match is None:
        detail = (err or out or "").strip()[:500]
        raise ExportRefused(
            "cannot_hash",
            f"{where} could not report the file's size and SHA-256 (exit {exit_code}): {detail}. nervus "
            f"exports only what it can check against the source; it needs `wc` and `sha256sum` there",
        )
    return Fingerprint(size=int(match.group(1)), sha256=match.group(2))


class Source(Protocol):
    where: str

    async def fingerprint(self) -> Fingerprint: ...

    def chunks(self) -> AsyncIterator[bytes]: ...


# --- a host, over SSH -----------------------------------------------------------


class HostSource:
    """A file read over SFTP: on a host, or in an enrolled VM (ADR-0022 7a),
    `host` then naming the VM."""

    route = "sftp"

    def __init__(self, conn: asyncssh.SSHClientConnection, host: str, remote_path: str):
        self.conn = conn
        self.remote_path = remote_path
        self.where = f"{host}:{remote_path}"

    async def fingerprint(self) -> Fingerprint:
        command = f"sh -c {shlex.quote(FINGERPRINT_SCRIPT)} sh {shlex.quote(self.remote_path)}"
        try:
            done = await self.conn.run(command, timeout=HASH_TIMEOUT)
        except asyncssh.TimeoutError as exc:
            raise ExportRefused("cannot_hash", f"{self.where}: hashing took over {HASH_TIMEOUT:.0f} s") from exc
        return parse_fingerprint(done.exit_status, str(done.stdout or ""), str(done.stderr or ""), self.where)

    async def chunks(self) -> AsyncIterator[bytes]:
        async with self.conn.start_sftp_client() as sftp:
            async with sftp.open(self.remote_path, "rb") as remote:
                while chunk := await remote.read(HOST_READ_BYTES):
                    yield chunk


# --- a VM, through Proxmox's guest agent -----------------------------------------


class VMSource:
    """`api` is a ProxmoxClient, or anything with its `request`, that accepts
    answers of VM_RESPONSE_BYTES."""

    route = "guest-agent"

    def __init__(self, api, vmid: int, path: str, *, poll_seconds: float = POLL_SECONDS,
                 hash_timeout: float = HASH_TIMEOUT):
        self.api = api
        self.vmid = vmid
        self.path = path
        self.where = f"VM {vmid}:{path}"
        self.poll_seconds = poll_seconds
        self.hash_timeout = hash_timeout
        self._node: str | None = None

    async def _call(self, method: str, path: str, params: dict) -> object:
        resp = await self.api.request(method, path, params)
        if resp.status != 200:
            reason = resp.reason
            if resp.errors:
                reason = f"{reason} {resp.errors}"
            raise ExportRefused("source_error", f"{self.where}: Proxmox answered {resp.status} {reason}")
        return resp.data

    async def node(self) -> str:
        """The node the VM runs on. A guest the token cannot see, or that is not
        a QEMU VM (a container has no guest agent), is refused."""
        if self._node is None:
            guests = await self._call("GET", "/cluster/resources", {"type": "vm"}) or []
            match = [g for g in guests if isinstance(g, dict) and g.get("vmid") == self.vmid]
            if not match or match[0].get("type") != "qemu":
                raise ExportRefused("no_such_vm", f"no QEMU VM {self.vmid} that nervus's Proxmox token can see")
            self._node = str(match[0]["node"])
        return self._node

    async def fingerprint(self) -> Fingerprint:
        base = f"/nodes/{await self.node()}/qemu/{self.vmid}/agent"
        started = await self._call("POST", f"{base}/exec",
                                   {"command": ["sh", "-c", FINGERPRINT_SCRIPT, "sh", self.path]})
        pid = started["pid"] if isinstance(started, dict) else None
        if not isinstance(pid, int):
            raise ExportRefused("source_error", f"{self.where}: the guest agent started no command: {started!r}")
        waited = 0.0
        while True:
            status = await self._call("GET", f"{base}/exec-status", {"pid": pid})
            if isinstance(status, dict) and status.get("exited"):
                return parse_fingerprint(status.get("exitcode"), str(status.get("out-data", "")),
                                         str(status.get("err-data", "")), self.where)
            if waited >= self.hash_timeout:
                raise ExportRefused("cannot_hash", f"{self.where}: hashing took over {self.hash_timeout:.0f} s")
            await asyncio.sleep(self.poll_seconds)
            waited += self.poll_seconds

    async def chunks(self) -> AsyncIterator[bytes]:
        path = f"/nodes/{await self.node()}/qemu/{self.vmid}/agent/file-read"
        offset = 0
        while True:
            data = await self._call("GET", path, {"file": self.path, "offset": offset,
                                                  "count": VM_READ_BYTES, "decode": False})
            if not isinstance(data, dict) or not isinstance(data.get("bytes-read"), int):
                raise ExportRefused("source_error", f"{self.where}: file-read answered without bytes-read")
            try:
                chunk = base64.b64decode(data.get("content", ""), validate=True)
            except (binascii.Error, ValueError) as exc:
                raise ExportRefused("source_error", f"{self.where}: file-read at offset {offset} was not "
                                                    f"valid base64: {exc}") from exc
            if len(chunk) != data["bytes-read"]:
                raise ExportRefused("source_error", f"{self.where}: file-read at offset {offset} decoded to "
                                                    f"{len(chunk)} bytes, not the {data['bytes-read']} it reported")
            if chunk:
                yield chunk
                offset += len(chunk)
            if not chunk or not data.get("truncated"):
                return


# --- making the copy -------------------------------------------------------------


async def stage(store: ExportStore, export: Export, source: Source, before: Fingerprint) -> Export:
    """Copy `source` into a staging export begun with `before.size`, then keep
    it only if the source before, the source after, and the copy all agree.
    Returns the export, ready or failed; never leaves a partial file."""
    writer = store.writer(export)
    reported = 0
    try:
        async for chunk in source.chunks():
            writer.write(chunk)
            if writer.written - reported >= PROGRESS_EVERY:
                store.progress(export.id, writer.written)
                reported = writer.written
        after = await source.fingerprint()
    except ExportRefused as exc:
        return store.fail(export, exc.code, exc.message, writer)
    except (OSError, asyncssh.Error) as exc:
        return store.fail(export, "source_error", f"{source.where}: {exc}", writer)
    except BaseException:
        # Cancelled, or a fault in nervus: no partial file is left either way.
        store.fail(export, "interrupted", "the copy was stopped before it finished", writer)
        raise
    copied = Fingerprint(size=writer.written, sha256=writer.sha256)
    if not before == after == copied:
        return store.fail(
            export,
            "changed",
            f"{source.where} changed while it was copied, or the copy differs from it: before "
            f"{before.size} bytes {before.sha256}, after {after.size} bytes {after.sha256}, copied "
            f"{copied.size} bytes {copied.sha256}. Export it again once it has stopped changing",
            writer,
        )
    return store.finish(export, writer)
