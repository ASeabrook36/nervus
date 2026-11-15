"""The `export` tool (ADR-0016 decisions B, C, H and I), through a real MCP
session: who may export what, one export per request key whatever the
retries, work that outlives the call, and what the audit log records."""

import asyncio
import hashlib
import json
import os

import pytest
from test_export_sources import FakeProxmox
from test_server import _call_tool, _content, _list_tools

from nervus.audit import AuditLog
from nervus.auth import Token
from nervus.config import Host, Settings
from nervus.database import Database
from nervus.exporter import Exporter, VMRequest
from nervus.exports import ExportStore
from nervus.server import build_server, connect_host

MiB = 1024 * 1024
WIDE = "sekret-wide"  # testhost and hv, the Proxmox host
HOST_ONLY = "sekret-host-only"  # testhost
OTHER = "sekret-other"  # testhost and hv, another client


class SlowProxmox(FakeProxmox):
    """A guest whose reads take `delay` seconds each, as a large one would."""

    def __init__(self, delay, **kw):
        super().__init__(**kw)
        self.delay = delay

    async def request(self, method, path, params=None, *, timeout=60.0):
        if path.endswith("/file-read"):
            await asyncio.sleep(self.delay)
        return await super().request(method, path, params, timeout=timeout)


@pytest.fixture
def world(tmp_path, ssh_server):
    host = Host(name="testhost", address=ssh_server.host, os="test", role="test",
                agent_user=ssh_server.username, status="onboarded")
    # The Proxmox host is the entry marked `hypervisor: proxmox`, whatever its
    # name (ADR-0019 decision D).
    hv = Host(name="hv", address="localhost", os="test", role="test", agent_user="observer",
              status="onboarded", hypervisor="proxmox")
    settings = Settings(hosts={"testhost": host, "hv": hv}, tokens_path=tmp_path / "tokens.yaml",
                        known_hosts_path=ssh_server.known_hosts_path, ssh_key_path=ssh_server.client_key_path,
                        audit_log_path=tmp_path / "audit.jsonl", transfer_dir=tmp_path,
                        bind_host="127.0.0.1", bind_port=0, ssh_port=ssh_server.port)
    tokens = {
        WIDE: Token(id="t-wide", client="codex", project="project-b", hosts=frozenset({"testhost", "hv"})),
        HOST_ONLY: Token(id="t-host", client="codex", project="p", hosts=frozenset({"testhost"})),
        OTHER: Token(id="t-other", client="claude-code", project="q", hosts=frozenset({"testhost", "hv"})),
    }
    audit = AuditLog(path=settings.audit_log_path)
    db = Database(tmp_path / "nervus.db")
    db.open()
    store = ExportStore(db, tmp_path / "exports", free_bytes=lambda: 100 * 1024**3)
    store.open()

    class World:
        pass

    w = World()
    w.tmp, w.settings, w.tokens, w.audit, w.store = tmp_path, settings, tokens, audit, store
    w.api = FakeProxmox()

    def build(vm_api="default"):
        w.exporter = Exporter(store, audit, connect=lambda h: connect_host(settings, h),
                              vm_api=w.api if vm_api == "default" else vm_api)
        w.server = build_server(settings=settings, tokens=tokens, audit=audit, exporter=w.exporter)
        return w.server

    w.build = build
    build()
    return w


async def _export(w, token=WIDE, **args):
    return await _call_tool(w.server, token, "export", args)


def _records(w):
    return [json.loads(line) for line in w.settings.audit_log_path.read_text().splitlines()]


def _file(w, name, data):
    f = w.tmp / name
    f.write_bytes(data)
    return str(f)


# --- a whole export ---------------------------------------------------------------


async def test_a_host_file_is_exported_and_described(world):
    data = os.urandom(2 * MiB + 3)
    result = _content(await _export(world, request_key="a1", host="testhost",
                                    remote_path=_file(world, "out.tar.gz", data)))
    assert result["state"] == "ready"
    assert result["size"] == len(data)
    assert result["sha256"] == hashlib.sha256(data).hexdigest()
    assert result["download_path"] == f"/exports/{result['export_id']}"
    assert result["filename"] == "out.tar.gz"
    assert result["source"] == {"kind": "host", "host": "testhost", "remote_path": str(world.tmp / "out.tar.gz")}
    assert result["expires_at"].endswith("+00:00")
    assert (world.tmp / "exports" / result["export_id"]).read_bytes() == data


async def test_a_vm_file_is_exported(world):
    data = os.urandom(3 * MiB)
    result = _content(await _export(world, request_key="v1", vmid=100, path=_file(world, "g.bin", data)))
    assert result["state"] == "ready"
    assert result["sha256"] == hashlib.sha256(data).hexdigest()
    assert max(world.api.reads) <= MiB


async def test_the_audit_log_has_the_source_and_the_outcome_and_no_token(world):
    data = b"payload"
    result = _content(await _export(world, request_key="a1", host="testhost",
                                    remote_path=_file(world, "f", data)))
    records = [r for r in _records(world) if r["tool"] == "export"]
    intent = next(r for r in records if r["phase"] == "intent")
    outcome = [r for r in records if r["phase"] == "result" and r["id"] == intent["id"]]
    assert intent["token_id"] == "t-wide" and intent["request_key"] == "a1"
    assert intent["source"]["remote_path"] == str(world.tmp / "f")
    assert len(outcome) == 1
    assert outcome[0]["sha256"] == hashlib.sha256(data).hexdigest()
    assert outcome[0]["export_id"] == result["export_id"]
    text = world.settings.audit_log_path.read_text()
    assert all(secret not in text for secret in (WIDE, HOST_ONLY, OTHER))
    assert WIDE not in json.dumps(result)


# --- one key, one export (decision I) ----------------------------------------------


async def test_the_same_key_returns_the_same_export_and_copies_once(world):
    path = _file(world, "g.bin", os.urandom(MiB + 1))
    first = _content(await _export(world, request_key="k", vmid=100, path=path))
    reads = len(world.api.reads)
    again = _content(await _export(world, request_key="k", vmid=100, path=path))
    assert again["export_id"] == first["export_id"] and again["state"] == "ready"
    assert len(world.api.reads) == reads
    # The retry's own call is recorded, with what it found.
    second = [r for r in _records(world) if r["tool"] == "export"][-2:]
    assert [r["phase"] for r in second] == ["intent", "result"]
    assert second[1]["export_id"] == first["export_id"]


async def test_the_same_key_for_another_file_is_refused_and_audited(world):
    await _export(world, request_key="k", vmid=100, path=_file(world, "a", b"a"))
    result = await _export(world, request_key="k", vmid=100, path=_file(world, "b", b"b"))
    assert result.is_error and "already names" in result.content[0].text
    assert _records(world)[-1]["phase"] == "refused"


async def test_the_same_key_from_another_client_is_its_own_export(world):
    path = _file(world, "a", b"a")
    mine = _content(await _export(world, request_key="k", vmid=100, path=path))
    theirs = _content(await _export(world, token=OTHER, request_key="k", vmid=100, path=path))
    assert mine["export_id"] != theirs["export_id"]


async def test_a_failure_stays_with_its_key(world):
    first = _content(await _export(world, request_key="k", host="testhost", remote_path=str(world.tmp)))
    assert first["state"] == "failed" and first["failure"]["code"] == "not_a_file"
    again = _content(await _export(world, request_key="k", host="testhost", remote_path=str(world.tmp)))
    assert again["export_id"] == first["export_id"] and again["state"] == "failed"


# --- work that outlives the call ---------------------------------------------------


async def test_a_long_copy_answers_at_once_and_is_waited_for_by_asking_again(world):
    world.api = SlowProxmox(0.2)
    world.build()
    path = _file(world, "big", os.urandom(3 * MiB))
    first = _content(await _export(world, request_key="k", vmid=100, path=path, wait=0))
    assert first["state"] in ("measuring", "staging")
    assert "same request_key" in first["next"]
    for _ in range(50):
        later = _content(await _export(world, request_key="k", vmid=100, path=path, wait=1))
        if later["state"] == "ready":
            break
    assert later["state"] == "ready"
    # The first call's result was written when the export ended, once.
    intent = next(r for r in _records(world) if r["phase"] == "intent" and r["tool"] == "export")
    results = [r for r in _records(world) if r["phase"] == "result" and r["id"] == intent["id"]]
    assert len(results) == 1 and results[0]["state"] == "ready"


async def test_a_call_cut_off_while_waiting_leaves_the_copy_running(world):
    world.api = SlowProxmox(0.1)
    world.build()
    vm_path = _file(world, "big", os.urandom(2 * MiB))
    waiting = asyncio.create_task(world.exporter.export("t-wide", "k", VMRequest(100, vm_path), "run", wait=30))
    await asyncio.sleep(0.05)
    waiting.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiting
    status = await world.exporter.export("t-wide", "k", VMRequest(100, vm_path), "run2", wait=30)
    assert status.state == "ready"


# --- who may export what (decisions B and C) ----------------------------------------


async def test_a_host_outside_the_allowlist_is_refused_and_audited(world):
    world.tokens[HOST_ONLY] = Token(id="t-host", client="codex", project="p", hosts=frozenset({"elsewhere"}))
    result = await _export(world, token=HOST_ONLY, request_key="k", host="testhost",
                           remote_path=_file(world, "f", b"x"))
    assert result.is_error
    assert "not allowed to reach host 'testhost'" in result.content[0].text
    assert _records(world)[-1]["phase"] == "refused"
    assert not list((world.tmp / "exports").iterdir())


async def test_a_vm_needs_the_proxmox_host_in_the_allowlist(world):
    result = await _export(world, token=HOST_ONLY, request_key="k", vmid=100, path=_file(world, "f", b"x"))
    assert result.is_error
    refusal = _records(world)[-1]
    assert refusal["phase"] == "refused" and refusal["host"] == "hv"
    assert world.api.reads == []


async def test_a_vm_export_without_proxmox_settings_is_refused(world):
    world.build(vm_api=None)
    result = await _export(world, request_key="k", vmid=100, path=_file(world, "f", b"x"))
    assert result.is_error and "Proxmox settings" in result.content[0].text


@pytest.mark.parametrize("args", [
    {},
    {"host": "testhost"},
    {"vmid": 100},
    {"host": "testhost", "remote_path": "/x", "vmid": 100, "path": "/y"},
    {"host": "testhost", "path": "/y"},
])
async def test_a_request_that_is_not_one_source_is_refused(world, args):
    result = await _export(world, request_key="k", **args)
    assert result.is_error
    assert _records(world)[-1]["phase"] == "refused"


async def test_a_container_is_refused_by_proxmox_not_by_a_list(world):
    result = _content(await _export(world, request_key="k", vmid=123, path="/opt/nervus/secrets/tokens.yaml"))
    assert result["state"] == "failed" and result["failure"]["code"] == "no_such_vm"


async def test_a_bad_request_key_is_refused_before_anything_is_recorded(world):
    result = await _export(world, request_key="../k", vmid=100, path="/x")
    assert result.is_error
    assert [r["phase"] for r in _records(world)] == ["refused"]


@pytest.mark.parametrize("args", [
    {"host": "testhost", "remote_path": "/tmp/out\x00.tar.gz"},
    {"vmid": 100, "path": "/tmp/g\x00.bin"},
])
async def test_a_source_path_holding_a_nul_byte_is_refused_before_anything_is_recorded(world, args):
    """Procedure 056: nervus sends no NUL byte to a machine, where it would be dropped or cut the path short
    and the audit log would not say what was read; an upload's destination was refused one already."""
    result = await _export(world, request_key="k", **args)
    assert result.is_error and "holds a NUL byte" in result.content[0].text
    assert [r["phase"] for r in _records(world)] == ["refused"]


# --- deleting (decision E) ---------------------------------------------------------


async def test_a_client_deletes_its_own_export_and_no_other(world):
    made = _content(await _export(world, request_key="k", vmid=100, path=_file(world, "f", b"x")))
    theirs = _content(await _export(world, token=OTHER, action="delete", request_key="-",
                                    export_id=made["export_id"]))
    assert theirs["deleted"] is False
    mine = _content(await _export(world, action="delete", request_key="-", export_id=made["export_id"]))
    assert mine["deleted"] is True
    assert not list((world.tmp / "exports").iterdir())


async def test_deleting_a_copy_in_progress_stops_it(world):
    world.api = SlowProxmox(0.1)
    world.build()
    path = _file(world, "big", os.urandom(4 * MiB))
    first = None
    for _ in range(50):
        first = _content(await _export(world, request_key="k", vmid=100, path=path, wait=0.05))
        if first["state"] == "staging":
            break
    assert first["state"] == "staging"
    reads = len(world.api.reads)
    gone = _content(await _export(world, action="delete", request_key="-", export_id=first["export_id"]))
    assert gone["deleted"] is True
    await asyncio.sleep(0.5)
    assert len(world.api.reads) <= reads + 1
    assert not list((world.tmp / "exports").iterdir())
    assert world.store.get("t-wide", first["export_id"]).state == "deleted"


# --- the hourly sweep --------------------------------------------------------------


async def test_the_sweep_runs_by_itself(world, monkeypatch):
    made = _content(await _export(world, request_key="k", vmid=100, path=_file(world, "f", b"x")))
    assert made["state"] == "ready"
    real = world.store.sweep
    after_expiry = world.store.get("t-wide", made["export_id"]).expires_at
    monkeypatch.setattr(world.store, "sweep", lambda now=None: real(now=after_expiry))
    sweeper = asyncio.create_task(world.exporter.sweep_forever(every=0.01))
    await asyncio.sleep(0.1)
    sweeper.cancel()
    assert not list((world.tmp / "exports").iterdir())


# --- offered only when nervus has a store ------------------------------------------


async def test_the_tool_is_offered_with_a_store_and_absent_without(world):
    assert "export" in await _list_tools(world.server, WIDE)
    bare = build_server(settings=world.settings, tokens=world.tokens, audit=world.audit)
    assert "export" not in await _list_tools(bare, WIDE)


async def test_the_copys_ssh_port_is_in_the_exports_result_record(world):
    """ADR-0025 decision 3: the copy runs as a task of its own, and its
    connection's local port reaches the call's result record."""
    result = _content(await _export(world, request_key="p1", host="testhost",
                                    remote_path=_file(world, "p.bin", b"port")))
    assert result["state"] == "ready"
    records = [r for r in _records(world) if r["id"] == result["run_id"] and r["phase"] == "result"]
    assert records and all(isinstance(p, int) for r in records for p in r["ssh_ports"])
    assert len(records[-1]["ssh_ports"]) == 1
