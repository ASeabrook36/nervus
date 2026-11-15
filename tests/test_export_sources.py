"""Where an export's bytes come from (ADR-0016 decisions C, F and G): a host
over SFTP, a VM through Proxmox's guest agent, and the check that the source
before, the source after, and the copy all agree.

The VM tests run against a fake Proxmox whose `file-read` does what
PVE/API2/Qemu/Agent.pm does on hv (read 2026-10-14): it reads the guest in
1 MiB pieces and, with decode=0, joins their base64 text, each piece padded on
its own; `truncated` is set unless the guest agent reported end of file. Its
`exec` runs the command for real, on this machine, so the fingerprint script
is tested in a real shell."""

import asyncio
import base64
import hashlib
import itertools
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from nervus.database import Database
from nervus.export_sources import (
    FINGERPRINT_SCRIPT,
    VM_READ_BYTES,
    Fingerprint,
    HostSource,
    VMSource,
    parse_fingerprint,
    stage,
)
from nervus.exports import FAILED, READY, ExportRefused, ExportStore
from nervus.proxmox import ProxmoxResponse
from nervus.ssh import connect

MiB = 1024 * 1024
TOKEN = "codex-anywhere"
_keys = itertools.count()


@pytest.fixture
def store(tmp_path):
    db = Database(tmp_path / "nervus.db")
    db.open()
    s = ExportStore(db, tmp_path / "exports", free_bytes=lambda: 100 * 1024**3)
    s.open()
    return s


def _staged_files(tmp_path):
    return sorted(p.name for p in (tmp_path / "exports").iterdir())


async def _export(store, source):
    """What the tool will do (step 3): fingerprint, reserve, copy, check."""
    before = await source.fingerprint()
    export, _ = store.begin(TOKEN, f"k{next(_keys)}", {"where": source.where}, source.where, before.size)
    return await stage(store, export, source, before)


# --- the fingerprint script --------------------------------------------------------


def _run_script(path):
    done = subprocess.run(["sh", "-c", FINGERPRINT_SCRIPT, "sh", str(path)], capture_output=True, text=True)
    return parse_fingerprint(done.returncode, done.stdout, done.stderr, str(path))


def test_the_script_reports_size_and_sha256(tmp_path):
    f = tmp_path / "a.bin"
    data = os.urandom(70_001)
    f.write_bytes(data)
    assert _run_script(f) == Fingerprint(len(data), hashlib.sha256(data).hexdigest())


def test_the_script_handles_an_empty_file(tmp_path):
    (tmp_path / "empty").write_bytes(b"")
    assert _run_script(tmp_path / "empty") == Fingerprint(0, hashlib.sha256(b"").hexdigest())


def test_a_hostile_file_name_is_only_ever_a_name(tmp_path):
    name = tmp_path / "a 'b' $(touch pwned) `touch pwned2`; *.txt"
    name.write_bytes(b"x")
    assert _run_script(name).size == 1
    assert not list(tmp_path.glob("pwned*"))
    assert not (Path.cwd() / "pwned").exists()


@pytest.mark.parametrize("make", ["directory", "missing"])
def test_anything_but_a_regular_file_is_refused(tmp_path, make):
    target = tmp_path / "t"
    if make == "directory":
        target.mkdir()
    with pytest.raises(ExportRefused) as refused:
        _run_script(target)
    assert refused.value.code == "not_a_file"


def test_a_source_without_sha256sum_cannot_hash(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for tool in ("sh", "wc"):
        (bin_dir / tool).symlink_to(shutil.which(tool))
    (tmp_path / "f").write_bytes(b"x")
    done = subprocess.run([str(bin_dir / "sh"), "-c", FINGERPRINT_SCRIPT, "sh", str(tmp_path / "f")],
                          capture_output=True, text=True, env={"PATH": str(bin_dir)})
    with pytest.raises(ExportRefused) as refused:
        parse_fingerprint(done.returncode, done.stdout, done.stderr, "f")
    assert refused.value.code == "cannot_hash"


@pytest.mark.parametrize("out", ["", "12", "12 nothex", "x 0dbe9a46929a1a257943df27ea42b265271ddad33c6f06bd41c7965c7df7a496"])
def test_output_that_is_not_a_size_and_a_hash_cannot_hash(out):
    with pytest.raises(ExportRefused) as refused:
        parse_fingerprint(0, out, "", "f")
    assert refused.value.code == "cannot_hash"


# --- a host, over SSH --------------------------------------------------------------


async def _conn(ssh_server):
    return await connect(address=ssh_server.host, port=ssh_server.port, username=ssh_server.username,
                         client_keys=[ssh_server.client_key_path], known_hosts=ssh_server.known_hosts_path)


async def test_a_host_file_is_exported_whole(ssh_server, store, tmp_path):
    remote = tmp_path / "remote" / "build output.tar"
    remote.parent.mkdir()
    data = os.urandom(3 * MiB + 12345)
    remote.write_bytes(data)
    conn = await _conn(ssh_server)
    try:
        export = await _export(store, HostSource(conn, "node-a", str(remote)))
    finally:
        conn.close()
    assert export.state == READY
    assert export.size == len(data)
    assert export.sha256 == hashlib.sha256(data).hexdigest()
    assert (tmp_path / "exports" / export.id).read_bytes() == data


async def test_a_host_directory_is_refused(ssh_server, store, tmp_path):
    conn = await _conn(ssh_server)
    try:
        with pytest.raises(ExportRefused) as refused:
            await HostSource(conn, "node-a", str(tmp_path)).fingerprint()
    finally:
        conn.close()
    assert refused.value.code == "not_a_file"


async def test_a_host_file_that_changes_after_it_is_measured_is_refused(ssh_server, store, tmp_path):
    remote = tmp_path / "growing.log"
    remote.write_bytes(b"a" * 1000)
    conn = await _conn(ssh_server)
    try:
        source = HostSource(conn, "node-a", str(remote))
        before = await source.fingerprint()
        export, _ = store.begin(TOKEN, "k", {}, "growing.log", before.size)
        remote.write_bytes(b"b" * 1000)  # same size, other bytes
        result = await stage(store, export, source, before)
    finally:
        conn.close()
    assert result.state == FAILED and result.failure_code == "changed"
    assert _staged_files(tmp_path) == []


async def test_a_host_file_that_grows_past_its_reservation_is_stopped(ssh_server, store, tmp_path):
    remote = tmp_path / "growing.log"
    remote.write_bytes(b"a" * 1000)
    conn = await _conn(ssh_server)
    try:
        source = HostSource(conn, "node-a", str(remote))
        before = await source.fingerprint()
        export, _ = store.begin(TOKEN, "k", {}, "growing.log", before.size)
        remote.write_bytes(b"a" * 5000)
        result = await stage(store, export, source, before)
    finally:
        conn.close()
    assert result.failure_code == "grew"
    assert _staged_files(tmp_path) == []


# --- a VM, through a Proxmox that behaves as the Proxmox host's does ---------------------------


class FakeProxmox:
    """The four calls a VM export makes, as Proxmox 9.2.3 answers them. Files
    are read from this machine's disk, standing in for the guest's."""

    def __init__(self, *, guests=None, block=1 * MiB, refuse=None, exec_polls=1):
        self.guests = guests if guests is not None else [{"vmid": 100, "type": "qemu", "node": "hv"},
                                                         {"vmid": 123, "type": "lxc", "node": "hv"}]
        self.block = block  # Proxmox's own read size inside one file-read
        self.refuse = refuse or {}  # path suffix -> (status, reason)
        self.exec_polls = exec_polls
        self.reads = []  # the count of every file-read
        self._runs = {}
        self._pids = itertools.count(1000)

    async def request(self, method, path, params=None, *, timeout=60.0):
        await asyncio.sleep(0)  # the real client waits on a thread, so the loop can run
        params = params or {}
        for suffix, (status, reason) in self.refuse.items():
            if path.endswith(suffix):
                return ProxmoxResponse(status=status, reason=reason, data=None, errors=None, body_bytes=0)
        if path == "/cluster/resources":
            return self._ok(self.guests)
        if path == "/nodes/hv/qemu/100/agent/exec":
            done = subprocess.run(params["command"], capture_output=True, text=True)
            pid = next(self._pids)
            self._runs[pid] = [done, self.exec_polls]
            return self._ok({"pid": pid})
        if path == "/nodes/hv/qemu/100/agent/exec-status":
            run = self._runs[params["pid"]]
            run[1] -= 1
            if run[1] > 0:
                return self._ok({"exited": 0})
            done = run[0]
            return self._ok({"exited": 1, "exitcode": done.returncode,
                             "out-data": done.stdout, "err-data": done.stderr})
        if path == "/nodes/hv/qemu/100/agent/file-read":
            return self._file_read(params)
        return ProxmoxResponse(status=501, reason="not in the fake", data=None, errors=None, body_bytes=0)

    def _file_read(self, params):
        count, offset = params["count"], params.get("offset", 0)
        assert params["decode"] is False
        self.reads.append(count)
        try:
            f = open(params["file"], "rb")
        except OSError as exc:
            return ProxmoxResponse(status=500, reason=f"can't open file - {exc.strerror}", data=None,
                                   errors=None, body_bytes=0)
        with f:
            f.seek(offset)
            content, read, eof = "", 0, False
            while read < count and not eof:
                n = min(count - read, self.block)
                piece = f.read(n)
                content += base64.b64encode(piece).decode()  # padded on its own, as Proxmox does
                read += len(piece)
                eof = len(piece) < n  # fread came up short: feof
        data = {"content": content, "bytes-read": read}
        if not eof:
            data["truncated"] = 1
        return self._ok(data)

    @staticmethod
    def _ok(data):
        return ProxmoxResponse(status=200, reason="OK", data=data, errors=None, body_bytes=0)


def _vm(api, path, **kw):
    return VMSource(api, 100, str(path), poll_seconds=0, **kw)


@pytest.mark.parametrize("size", [0, 1, 3 * MiB + 7, 1 * MiB, 2 * MiB])
async def test_a_vm_file_is_exported_whole(store, tmp_path, size):
    """1 MiB and 2 MiB end exactly on a read: Proxmox then says `truncated`,
    and one more read returns nothing."""
    f = tmp_path / "guest.tar.gz"
    data = os.urandom(size)
    f.write_bytes(data)
    api = FakeProxmox()
    export = await _export(store, _vm(api, f))
    assert export.state == READY
    assert export.sha256 == hashlib.sha256(data).hexdigest()
    assert (tmp_path / "exports" / export.id).read_bytes() == data
    assert api.reads and max(api.reads) <= VM_READ_BYTES


async def test_the_fingerprint_waits_for_the_guest_command(store, tmp_path):
    f = tmp_path / "f"
    f.write_bytes(b"abc")
    assert (await _vm(FakeProxmox(exec_polls=4), f).fingerprint()).size == 3


async def test_a_guest_that_never_finishes_hashing_is_refused(tmp_path):
    f = tmp_path / "f"
    f.write_bytes(b"abc")
    with pytest.raises(ExportRefused) as refused:
        await _vm(FakeProxmox(exec_polls=10**9), f, hash_timeout=0).fingerprint()
    assert refused.value.code == "cannot_hash"


async def test_a_read_that_joins_padded_pieces_is_caught_not_kept(store, tmp_path):
    """What Proxmox does above 1 MiB, made to happen inside 1 MiB: if its own
    read size ever shrank, the joined text would decode to the wrong bytes, or
    not at all. The length check against bytes-read refuses it."""
    f = tmp_path / "f"
    f.write_bytes(os.urandom(3 * MiB))
    export = await _export(store, _vm(FakeProxmox(block=300_001), f))
    assert export.state == FAILED and export.failure_code == "source_error"
    assert _staged_files(tmp_path) == []


@pytest.mark.parametrize("guests", [[], [{"vmid": 100, "type": "lxc", "node": "hv"}]])
async def test_a_guest_the_token_cannot_see_or_that_is_not_a_vm_is_refused(tmp_path, guests):
    with pytest.raises(ExportRefused) as refused:
        await _vm(FakeProxmox(guests=guests), tmp_path / "f").fingerprint()
    assert refused.value.code == "no_such_vm"


async def test_a_container_such_as_nervuss_own_is_refused(tmp_path):
    with pytest.raises(ExportRefused) as refused:
        await VMSource(FakeProxmox(), 123, "/opt/nervus/secrets/tokens.yaml", poll_seconds=0).fingerprint()
    assert refused.value.code == "no_such_vm"


async def test_a_proxmox_refusal_is_reported_with_its_reason(tmp_path):
    api = FakeProxmox(refuse={"/agent/exec": (403, "Permission check failed (/vms/100, VM.GuestAgent.Unrestricted)")})
    with pytest.raises(ExportRefused) as refused:
        await _vm(api, tmp_path / "f").fingerprint()
    assert refused.value.code == "source_error"
    assert "Permission check failed" in refused.value.message


async def test_a_vm_file_that_changes_while_it_is_copied_is_refused(store, tmp_path):
    f = tmp_path / "f"
    f.write_bytes(b"a" * (2 * MiB))
    source = _vm(FakeProxmox(), f)
    before = await source.fingerprint()
    export, _ = store.begin(TOKEN, "k", {}, "f", before.size)
    chunks = source.chunks

    async def changing():
        async for chunk in chunks():
            yield chunk
            f.write_bytes(b"b" * (2 * MiB))  # after the first MiB

    source.chunks = changing
    result = await stage(store, export, source, before)
    assert result.state == FAILED and result.failure_code == "changed"
    assert _staged_files(tmp_path) == []


async def test_a_copy_cancelled_part_way_leaves_nothing(store, tmp_path):
    f = tmp_path / "f"
    f.write_bytes(os.urandom(4 * MiB))
    source = _vm(FakeProxmox(), f)
    before = await source.fingerprint()
    export, _ = store.begin(TOKEN, "k", {}, "f", before.size)
    chunks = source.chunks

    async def slow():
        async for chunk in chunks():
            yield chunk
            await asyncio.sleep(10)

    source.chunks = slow
    task = asyncio.create_task(stage(store, export, source, before))
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    after = store.get(TOKEN, export.id)
    assert after.state == FAILED and after.failure_code == "interrupted"
    assert _staged_files(tmp_path) == []


async def test_progress_is_written_down_as_the_copy_goes(store, tmp_path, monkeypatch):
    monkeypatch.setattr("nervus.export_sources.PROGRESS_EVERY", 1 * MiB)
    f = tmp_path / "f"
    f.write_bytes(os.urandom(3 * MiB))
    source = _vm(FakeProxmox(), f)
    before = await source.fingerprint()
    export, _ = store.begin(TOKEN, "k", {}, "f", before.size)
    seen = []
    chunks = source.chunks

    async def watched():
        async for chunk in chunks():
            seen.append(store.get(TOKEN, export.id).bytes_written)
            yield chunk

    source.chunks = watched
    await stage(store, export, source, before)
    assert seen == [0, 1 * MiB, 2 * MiB]


async def test_a_file_that_changes_after_the_copy_is_still_refused(store, tmp_path):
    """Decision F: the source is asked again after the copy, and all three
    must agree, so a file being rewritten as it was read is never kept on
    the strength of a copy that happens to match the first answer."""
    f = tmp_path / "f"
    f.write_bytes(b"a" * 100)
    source = _vm(FakeProxmox(), f)
    before = await source.fingerprint()
    export, _ = store.begin(TOKEN, "k", {}, "f", before.size)
    chunks = source.chunks

    async def then_changed():
        async for chunk in chunks():
            yield chunk
        f.write_bytes(b"b" * 100)

    source.chunks = then_changed
    result = await stage(store, export, source, before)
    assert result.failure_code == "changed"
    assert _staged_files(tmp_path) == []


async def test_a_read_that_says_truncated_but_returns_nothing_ends_the_copy(store, tmp_path):
    """Proxmox never does this, but if it did, nervus must stop rather than ask
    for the same empty offset forever."""

    class AlwaysTruncated(FakeProxmox):
        def _file_read(self, params):
            resp = super()._file_read(params)
            if resp.data:
                resp.data["truncated"] = 1
            return resp

    f = tmp_path / "f"
    f.write_bytes(b"abc")
    export = await asyncio.wait_for(_export(store, _vm(AlwaysTruncated(), f)), timeout=5)
    assert export.state == READY and export.size == 3
