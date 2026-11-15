import dataclasses
import json
import os
import shutil

import httpx
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from nervus.audit import AuditLog
from nervus.auth import Token
from nervus.config import Host, Settings
from nervus.server import build_server

GOOD_TOKEN = "sekret-good"
NARROW_TOKEN = "sekret-narrow"  # allowed only for a host that doesn't exist in this test


def _transfer_dir(tmp_path):
    """put/get are confined to this; anything outside it is refused."""
    d = tmp_path / "transfer"
    d.mkdir(exist_ok=True)
    return d


def _settings(tmp_path, ssh_server) -> Settings:
    host = Host(
        name="testhost",
        address=ssh_server.host,
        os="test",
        role="test",
        agent_user=ssh_server.username,
        status="not-onboarded",
    )
    return Settings(
        hosts={"testhost": host},
        tokens_path=tmp_path / "tokens.yaml",
        known_hosts_path=ssh_server.known_hosts_path,
        ssh_key_path=ssh_server.client_key_path,
        audit_log_path=tmp_path / "audit.jsonl",
        transfer_dir=_transfer_dir(tmp_path),
        bind_host="127.0.0.1",
        bind_port=0,
        ssh_port=ssh_server.port,
    )


def _tokens() -> dict[str, Token]:
    return {
        GOOD_TOKEN: Token(id="t-good", client="claude-code", project="p", hosts=frozenset({"testhost"})),
        NARROW_TOKEN: Token(id="t-narrow", client="codex", project="p", hosts=frozenset({"some-other-host"})),
    }


def _build(tmp_path, ssh_server):
    settings = _settings(tmp_path, ssh_server)
    tokens = _tokens()
    audit = AuditLog(path=settings.audit_log_path)
    return build_server(settings=settings, tokens=tokens, audit=audit), settings, audit


async def _call_tool(mcp_server, token: str | None, name: str, arguments: dict):
    app = mcp_server.streamable_http_app()
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    http_client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000", headers=headers
    )
    # streamable_http_app()'s Starlette lifespan runs the session manager,
    # but httpx.ASGITransport never sends ASGI lifespan events -- drive it
    # directly instead.
    async with mcp_server.session_manager.run():
        async with http_client:
            async with streamable_http_client(
                "http://127.0.0.1:8000/mcp", http_client=http_client
            ) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    return await session.call_tool(name, arguments)


def _content(result) -> dict:
    """Tool results carry their payload as JSON text content, not
    structured_content, in this SDK version -- parse it directly."""
    return json.loads(result.content[0].text)


async def test_hosts_lists_only_allowed_hosts(tmp_path, ssh_server):
    mcp_server, _, _ = _build(tmp_path, ssh_server)

    result = await _call_tool(mcp_server, GOOD_TOKEN, "hosts", {})

    assert not result.is_error
    assert _content(result)["hosts"][0]["name"] == "testhost"


async def test_bad_token_is_rejected_before_any_tool_runs(tmp_path, ssh_server):
    mcp_server, _, _ = _build(tmp_path, ssh_server)

    with pytest.raises(Exception):
        await _call_tool(mcp_server, "not-a-real-token", "hosts", {})


async def test_missing_token_is_rejected(tmp_path, ssh_server):
    mcp_server, _, _ = _build(tmp_path, ssh_server)

    with pytest.raises(Exception):
        await _call_tool(mcp_server, None, "hosts", {})


async def test_exec_on_allowed_host_succeeds(tmp_path, ssh_server):
    mcp_server, _, audit = _build(tmp_path, ssh_server)

    result = await _call_tool(
        mcp_server, GOOD_TOKEN, "exec", {"host": "testhost", "command": "echo hi", "cwd": "/tmp"}
    )

    assert not result.is_error
    assert _content(result)["exit_code"] == 0
    assert "hi" in _content(result)["output"]

    lines = audit.path.read_text().splitlines()
    assert any('"phase": "intent"' in line for line in lines)
    assert any('"phase": "result"' in line for line in lines)


async def test_exec_on_disallowed_host_is_refused_before_any_ssh(tmp_path, ssh_server):
    mcp_server, _, audit = _build(tmp_path, ssh_server)

    result = await _call_tool(
        mcp_server, NARROW_TOKEN, "exec", {"host": "testhost", "command": "echo hi"}
    )

    assert result.is_error
    # This previously asserted `not audit.path.exists()` -- that a refused call
    # writes nothing. That encoded defect B as intended behaviour, which is why
    # the suite stayed green while denied access attempts were invisible.
    # ADR-0001 s10 says every tool call appends a record, and a refusal is the
    # case the log most needs to show.
    records = [json.loads(line) for line in audit.path.read_text().splitlines() if line.strip()]
    assert [r["phase"] for r in records] == ["refused"]
    assert records[0]["token_id"] == "t-narrow"
    # Still refused before any SSH: no intent record means nothing was attempted.
    assert not [r for r in records if r["phase"] == "intent"]


@pytest.mark.skipif(
    shutil.which("tmux") is None,
    reason="tmux not available here; exec_bg starts a detached tmux session (same guard as tests/test_jobs.py)",
)
async def test_exec_bg_then_job_status_round_trips(tmp_path, ssh_server):
    mcp_server, _, _ = _build(tmp_path, ssh_server)

    started = await _call_tool(
        mcp_server, GOOD_TOKEN, "exec_bg", {"host": "testhost", "command": "echo bg-output", "cwd": "/tmp"}
    )
    assert not started.is_error
    job_id = _content(started)["job_id"]

    import asyncio

    for _ in range(50):
        status = await _call_tool(
            mcp_server, GOOD_TOKEN, "job", {"host": "testhost", "job_id": job_id, "action": "status"}
        )
        if not _content(status)["running"]:
            break
        await asyncio.sleep(0.1)
    else:
        raise AssertionError("job did not finish in time")

    assert _content(status)["exit_code"] == 0

    logs = await _call_tool(
        mcp_server, GOOD_TOKEN, "job", {"host": "testhost", "job_id": job_id, "action": "logs"}
    )
    assert "bg-output" in _content(logs)["logs"]


# --- ADR-0001 s10: "every tool call appends one JSON record" ----------------
# Two cases did not. The hosts tool audited nothing at all, so a client could
# enumerate the fleet without trace; and a call refused by the allowlist
# audited nothing either, because authorization ran before record_intent and
# the exception escaped first. Both were found by reading the live log rather
# than the code -- see procedures/004-acceptance-verification.md.


def _audit_records(settings) -> list[dict]:
    path = settings.audit_log_path
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


async def test_hosts_writes_intent_and_result_records(tmp_path, ssh_server):
    mcp_server, settings, _ = _build(tmp_path, ssh_server)

    result = await _call_tool(mcp_server, GOOD_TOKEN, "hosts", {})
    assert not result.is_error

    records = [r for r in _audit_records(settings) if r["tool"] == "hosts"]
    phases = [r["phase"] for r in records]
    assert phases == ["intent", "result"]

    intent = records[0]
    assert intent["token_id"] == "t-good"
    assert intent["client"] == "claude-code"
    assert intent["project"] == "p"

    assert records[1]["id"] == intent["id"]
    assert records[1]["count"] == 1
    assert records[1]["hosts"] == ["testhost"]


async def test_a_host_outside_the_allowlist_is_audited_as_refused(tmp_path, ssh_server):
    mcp_server, settings, _ = _build(tmp_path, ssh_server)

    # NARROW_TOKEN may only reach "some-other-host", so testhost is denied.
    result = await _call_tool(
        mcp_server, NARROW_TOKEN, "exec", {"host": "testhost", "command": "echo nope"}
    )
    assert result.is_error

    refusals = [r for r in _audit_records(settings) if r["phase"] == "refused"]
    assert len(refusals) == 1
    refusal = refusals[0]
    assert refusal["tool"] == "exec"
    assert refusal["token_id"] == "t-narrow"
    assert refusal["client"] == "codex"
    assert refusal["host"] == "testhost"
    assert "not allowed" in refusal["reason"]

    # A refusal is its own phase, not an intent left dangling -- a dangling
    # intent means a call that started and never finished.
    assert not [r for r in _audit_records(settings) if r["phase"] == "intent"]


async def test_a_host_absent_from_the_inventory_is_audited_as_refused(tmp_path, ssh_server):
    mcp_server, settings, _ = _build(tmp_path, ssh_server)

    # NARROW_TOKEN *is* allowed "some-other-host"; it just isn't in hosts.yaml,
    # so this exercises the second refusal path rather than the allowlist one.
    result = await _call_tool(
        mcp_server, NARROW_TOKEN, "exec", {"host": "some-other-host", "command": "echo nope"}
    )
    assert result.is_error

    refusals = [r for r in _audit_records(settings) if r["phase"] == "refused"]
    assert len(refusals) == 1
    assert refusals[0]["host"] == "some-other-host"
    assert "unknown host" in refusals[0]["reason"]


async def test_a_refusal_records_the_token_id_never_the_token(tmp_path, ssh_server):
    mcp_server, settings, _ = _build(tmp_path, ssh_server)

    await _call_tool(mcp_server, NARROW_TOKEN, "exec", {"host": "testhost", "command": "x"})

    raw = settings.audit_log_path.read_text()
    assert "t-narrow" in raw
    assert NARROW_TOKEN not in raw


async def test_every_host_taking_tool_audits_a_refusal(tmp_path, ssh_server):
    """All five, not just exec -- the bug was identical in each."""
    calls = {
        "exec": {"host": "testhost", "command": "x"},
        "exec_bg": {"host": "testhost", "command": "x"},
        "job": {"host": "testhost", "job_id": "j", "action": "status"},
        "put": {"host": "testhost", "local_path": "/tmp/a", "remote_path": "/tmp/b"},
        "get": {"host": "testhost", "remote_path": "/tmp/b", "local_path": "/tmp/a"},
    }
    for tool, args in calls.items():
        sandbox = tmp_path / tool
        sandbox.mkdir()
        mcp_server, settings, _ = _build(sandbox, ssh_server)
        result = await _call_tool(mcp_server, NARROW_TOKEN, tool, args)
        assert result.is_error, f"{tool} should have been refused"
        refusals = [r for r in _audit_records(settings) if r["phase"] == "refused"]
        assert [r["tool"] for r in refusals] == [tool], f"{tool} did not audit its refusal"


async def test_put_outside_the_transfer_dir_is_refused_and_audited(tmp_path, ssh_server):
    """The exfiltration case: put() reads from nervus's own filesystem.

    Unconfined, an authenticated client could name the fleet private key and
    have nervus send it to a host it can reach, then read it back with exec --
    against ADR-0001 s2's "No agent ever holds an SSH key".
    """
    mcp_server, settings, _ = _build(tmp_path, ssh_server)
    secret = tmp_path / "pretend_private_key"
    secret.write_text("PRETEND KEY MATERIAL")

    result = await _call_tool(
        mcp_server, GOOD_TOKEN, "put",
        {"host": "testhost", "local_path": str(secret), "remote_path": "/tmp/stolen"},
    )
    assert result.is_error

    refusals = [r for r in _audit_records(settings) if r["phase"] == "refused"]
    assert len(refusals) == 1
    assert refusals[0]["tool"] == "put"
    assert refusals[0]["local_path"] == str(secret)
    assert "transfer directory" in refusals[0]["reason"]
    # Refused before anything ran: no intent means no SFTP session was opened.
    assert not [r for r in _audit_records(settings) if r["phase"] == "intent"]


async def test_get_outside_the_transfer_dir_is_refused_and_audited(tmp_path, ssh_server):
    """The mirror case: get() writes to nervus's own filesystem.

    The audit log is the one path the hardened unit leaves writable, so an
    unconfined get() could overwrite the very record used to investigate it.
    """
    mcp_server, settings, _ = _build(tmp_path, ssh_server)

    result = await _call_tool(
        mcp_server, GOOD_TOKEN, "get",
        {"host": "testhost", "remote_path": "/etc/hostname",
         "local_path": str(settings.audit_log_path)},
    )
    assert result.is_error
    refusals = [r for r in _audit_records(settings) if r["phase"] == "refused"]
    assert [r["tool"] for r in refusals] == ["get"]


async def test_put_inside_the_transfer_dir_still_works(tmp_path, ssh_server):
    """The guard must not break legitimate transfers."""
    mcp_server, settings, _ = _build(tmp_path, ssh_server)
    payload = settings.transfer_dir / "payload.txt"
    payload.write_text("hello from nervus")
    dest = tmp_path / "delivered.txt"

    result = await _call_tool(
        mcp_server, GOOD_TOKEN, "put",
        {"host": "testhost", "local_path": "payload.txt", "remote_path": str(dest)},
    )
    assert not result.is_error, "a relative path inside the transfer dir must be allowed"
    assert dest.read_text() == "hello from nervus"


# --- a symlink swapped in after the check is not followed (procedure 056, C4) -------------
# resolve_transfer_path checks where a path lands, and the file is opened later. A process running as
# nervus that swapped in a symbolic link between the two, at the file's own name or at a folder above
# it, could have had put read, or get write, a file outside the transfer directory. Such a process
# holds nervus's keys already (ADR-0007 decisions 2 and 9), so this is defence in depth: every step
# below the transfer directory is now opened without following a symbolic link.

import asyncio  # noqa: E402

from nervus import sftp  # noqa: E402


def _swapped_after_the_check(monkeypatch, swap):
    """resolve_transfer_path as nervus calls it, then `swap`: the racing process, between the check
    and the open."""
    checked = sftp.resolve_transfer_path

    def then_swapped(transfer_dir, local_path):
        resolved = checked(transfer_dir, local_path)
        swap()
        return resolved

    monkeypatch.setattr(sftp, "resolve_transfer_path", then_swapped)


def _replace_with_link(path, target):
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink()
    path.symlink_to(target)


async def test_put_reads_no_file_swapped_for_a_symlink_after_the_check(tmp_path, ssh_server, monkeypatch):
    mcp_server, settings, _ = _build(tmp_path, ssh_server)
    secret = tmp_path / "pretend_private_key"
    secret.write_text("PRETEND KEY MATERIAL")
    payload = settings.transfer_dir / "payload.txt"
    payload.write_text("an ordinary file")
    _swapped_after_the_check(monkeypatch, lambda: _replace_with_link(payload, secret))
    dest = tmp_path / "delivered.txt"
    result = await _call_tool(mcp_server, GOOD_TOKEN, "put",
                              {"host": "testhost", "local_path": "payload.txt", "remote_path": str(dest)})
    assert "symbolic link" in _text(result)
    assert not dest.exists() and not dest.is_symlink() and not list(tmp_path.glob(".nervus-put-*"))
    intent, done = _calls(settings, "put")
    assert done["id"] == intent["id"] and "symbolic link" in done["error"]


async def test_put_reads_nothing_through_a_folder_swapped_for_a_symlink_after_the_check(tmp_path, ssh_server,
                                                                                        monkeypatch):
    mcp_server, settings, _ = _build(tmp_path, ssh_server)
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    (secrets / "key").write_text("PRETEND KEY MATERIAL")
    sub = settings.transfer_dir / "sub"
    sub.mkdir()
    (sub / "key").write_text("an ordinary file")
    _swapped_after_the_check(monkeypatch, lambda: _replace_with_link(sub, secrets))
    dest = tmp_path / "delivered.txt"
    result = await _call_tool(mcp_server, GOOD_TOKEN, "put",
                              {"host": "testhost", "local_path": "sub/key", "remote_path": str(dest)})
    assert "symbolic link" in _text(result)
    assert not dest.exists()


async def test_get_writes_through_no_symlink_swapped_in_after_the_check(tmp_path, ssh_server, monkeypatch):
    mcp_server, settings, _ = _build(tmp_path, ssh_server)
    precious = tmp_path / "precious.txt"
    precious.write_text("the operator's own file")
    source = tmp_path / "on-the-machine.txt"
    source.write_text("from the machine")
    landing = settings.transfer_dir / "landing.txt"
    _swapped_after_the_check(monkeypatch, lambda: landing.symlink_to(precious))
    result = await _call_tool(mcp_server, GOOD_TOKEN, "get",
                              {"host": "testhost", "remote_path": str(source), "local_path": "landing.txt"})
    assert "symbolic link" in _text(result)
    assert precious.read_text() == "the operator's own file"


async def test_get_writes_nothing_through_a_folder_swapped_for_a_symlink_after_the_check(tmp_path, ssh_server,
                                                                                         monkeypatch):
    mcp_server, settings, _ = _build(tmp_path, ssh_server)
    outside = tmp_path / "outside"
    outside.mkdir()
    source = tmp_path / "on-the-machine.txt"
    source.write_text("from the machine")
    sub = settings.transfer_dir / "sub"
    sub.mkdir()
    _swapped_after_the_check(monkeypatch, lambda: _replace_with_link(sub, outside))
    result = await _call_tool(mcp_server, GOOD_TOKEN, "get",
                              {"host": "testhost", "remote_path": str(source), "local_path": "sub/landing.txt"})
    assert "symbolic link" in _text(result)
    assert list(outside.iterdir()) == []


async def test_a_symlink_the_check_resolves_inside_the_transfer_dir_still_works(tmp_path, ssh_server):
    """The check resolves a symbolic link that stays inside the transfer directory to the file it
    names, and that file is what is opened: nothing that worked before is refused."""
    mcp_server, settings, _ = _build(tmp_path, ssh_server)
    (settings.transfer_dir / "real.txt").write_text("hello")
    (settings.transfer_dir / "link.txt").symlink_to("real.txt")
    dest = tmp_path / "delivered.txt"
    result = await _call_tool(mcp_server, GOOD_TOKEN, "put",
                              {"host": "testhost", "local_path": "link.txt", "remote_path": str(dest)})
    assert not result.is_error, result.content[0].text
    assert dest.read_text() == "hello"


async def test_a_transfer_dir_that_is_itself_a_symlink_still_works(tmp_path, ssh_server):
    real = tmp_path / "real-transfer"
    real.mkdir()
    (tmp_path / "transfer").symlink_to(real)
    mcp_server, settings, _ = _build(tmp_path, ssh_server)
    (real / "payload.txt").write_text("hello")
    dest = tmp_path / "delivered.txt"
    sent = await _call_tool(mcp_server, GOOD_TOKEN, "put",
                            {"host": "testhost", "local_path": "payload.txt", "remote_path": str(dest)})
    assert not sent.is_error, sent.content[0].text
    got = await _call_tool(mcp_server, GOOD_TOKEN, "get",
                           {"host": "testhost", "remote_path": str(dest), "local_path": "back.txt"})
    assert not got.is_error, got.content[0].text
    assert (real / "back.txt").read_text() == "hello"


@pytest.mark.parametrize("tool, args, named", [
    ("exec", {"command": "echo cu\x00rl", "cwd": "/"}, "command"),
    ("exec", {"command": "pwd", "cwd": "/tm\x00p"}, "cwd"),
    ("exec_bg", {"command": "echo cu\x00rl"}, "command"),
    ("put", {"local_path": "pay\x00load.txt", "remote_path": "/tmp/x"}, "local_path"),
    ("put", {"local_path": "payload.txt", "remote_path": "/tmp/x\x00y"}, "remote_path"),
    ("get", {"remote_path": "/etc/host\x00name", "local_path": "x"}, "remote_path"),
    ("get", {"remote_path": "/etc/hostname", "local_path": "x\x00y"}, "local_path"),
])
async def test_a_nul_byte_bound_for_a_machine_is_refused_with_a_record(tmp_path, ssh_server, tool, args, named):
    """Procedure 056. bash drops a NUL byte from the script nervus sends it, so `echo cu<NUL>rl` ran as
    `echo curl` while the audit log held the NUL, and a search of the log for what ran missed it; a NUL in
    a local path was refused with no record at all. One in anything bound for a machine is refused before
    anything is sent, with a record saying why, as an upload's destination already was."""
    mcp_server, settings, _ = _build(tmp_path, ssh_server)
    (settings.transfer_dir / "payload.txt").write_text("hello")
    result = await _call_tool(mcp_server, GOOD_TOKEN, tool, {"host": "testhost", **args})
    assert f"`{named}` holds a NUL byte" in _text(result)
    records = [r for r in _audit_records(settings) if r["tool"] == tool]
    assert [r["phase"] for r in records] == ["refused"]
    assert f"`{named}` holds a NUL byte" in records[0]["reason"]


async def test_put_of_something_other_than_a_regular_file_is_refused_at_once(tmp_path, ssh_server):
    """A named pipe at the name held put's open until something wrote to it; it is refused now."""
    mcp_server, settings, _ = _build(tmp_path, ssh_server)
    os.mkfifo(settings.transfer_dir / "pipe")
    result = await asyncio.wait_for(_call_tool(mcp_server, GOOD_TOKEN, "put",
                                               {"host": "testhost", "local_path": "pipe",
                                                "remote_path": str(tmp_path / "delivered")}), timeout=30)
    assert "not a regular file" in _text(result)


# --- the proxmox tool (ADR-0009 decision 2) ---------------------------------

from nervus.proxmox import ProxmoxClient, ProxmoxConfig  # noqa: E402

PVE_TOKEN = "sekret-hv"
PVE_SECRET = "00000000-server-test-secret"
PVE_TOKEN_ID = "nervus@pve!nervus"


# The Proxmox host is whichever entry is marked `hypervisor: proxmox`; its name
# is nothing to nervus (ADR-0019 decision D), so these tests use another.
HV = "hv"


def _hypervisor_entry(name: str = HV, hypervisor: str | None = "proxmox") -> Host:
    return Host(name=name, address="localhost", os="test", role="test", agent_user="observer",
                status="onboarded", hypervisor=hypervisor)


def _build_with_proxmox(tmp_path, ssh_server, pki, port, entry: Host | None = None):
    settings = _settings(tmp_path, ssh_server)
    entry = _hypervisor_entry() if entry is None else entry
    settings = dataclasses.replace(settings, hosts={**settings.hosts, entry.name: entry})
    tokens = {
        **_tokens(),
        PVE_TOKEN: Token(id="t-hv", client="claude-code", project="p", hosts=frozenset({entry.name})),
    }
    audit = AuditLog(path=settings.audit_log_path)
    client = ProxmoxClient(
        ProxmoxConfig(host="localhost", port=port, token_id=PVE_TOKEN_ID,
                      ca_file=pki["ca"], secret=PVE_SECRET)
    )
    return build_server(settings=settings, tokens=tokens, audit=audit, proxmox=client), audit


async def _list_tools(mcp_server, token: str) -> list[str]:
    app = mcp_server.streamable_http_app()
    http_client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:8000",
        headers={"Authorization": f"Bearer {token}"},
    )
    async with mcp_server.session_manager.run():
        async with http_client:
            async with streamable_http_client(
                "http://127.0.0.1:8000/mcp", http_client=http_client
            ) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    return sorted(t.name for t in (await session.list_tools()).tools)


def _records(audit) -> list[dict]:
    return [json.loads(line) for line in audit.path.read_text().splitlines() if line.strip()]


async def test_the_proxmox_tool_is_absent_when_unconfigured(tmp_path, ssh_server):
    mcp_server, _, _ = _build(tmp_path, ssh_server)
    assert "proxmox" not in await _list_tools(mcp_server, GOOD_TOKEN)


async def test_the_proxmox_tool_is_offered_when_configured(tmp_path, ssh_server, pki, fake_api):
    mcp_server, _ = _build_with_proxmox(tmp_path, ssh_server, pki, fake_api.port)
    assert "proxmox" in await _list_tools(mcp_server, PVE_TOKEN)


async def test_proxmox_call_is_sent_and_audited(tmp_path, ssh_server, pki, fake_api):
    mcp_server, audit = _build_with_proxmox(tmp_path, ssh_server, pki, fake_api.port)

    result = await _call_tool(
        mcp_server, PVE_TOKEN, "proxmox",
        {"method": "GET", "path": "/nodes/pve1/qemu", "params": {"full": True}},
    )

    assert not result.is_error
    body = _content(result)
    assert (body["status"], body["data"]) == (200, {"echo": "/api2/json/nodes/pve1/qemu"})
    [req] = fake_api.requests
    assert req["path"] == "/api2/json/nodes/pve1/qemu?full=1"

    intent, res = _records(audit)
    assert (intent["phase"], intent["tool"], intent["token_id"]) == ("intent", "proxmox", "t-hv")
    assert (intent["host"], intent["user"]) == (HV, PVE_TOKEN_ID)
    assert (intent["method"], intent["path"], intent["params"]) == (
        "GET", "/nodes/pve1/qemu", {"full": True})
    assert (res["phase"], res["id"], res["status"]) == ("result", intent["id"], 200)
    assert res["body_bytes"] > 0
    assert "data" not in res  # sizes, not the body (ADR-0009 decision 2)
    assert PVE_SECRET not in audit.path.read_text()


async def test_passwords_are_sent_but_not_recorded(tmp_path, ssh_server, pki, fake_api):
    mcp_server, audit = _build_with_proxmox(tmp_path, ssh_server, pki, fake_api.port)

    await _call_tool(
        mcp_server, PVE_TOKEN, "proxmox",
        {"method": "PUT", "path": "/nodes/pve1/qemu/105/config",
         "params": {"cipassword": "hunter2-cloud", "ciuser": "operator"}},
    )

    [req] = fake_api.requests
    assert "cipassword=hunter2-cloud" in req["body"]  # Proxmox still gets it
    intent = _records(audit)[0]
    assert intent["params"] == {"cipassword": "<redacted>", "ciuser": "operator"}
    assert "hunter2-cloud" not in audit.path.read_text()


async def test_a_token_without_the_proxmox_host_is_refused_and_nothing_is_sent(tmp_path, ssh_server, pki, fake_api):
    mcp_server, audit = _build_with_proxmox(tmp_path, ssh_server, pki, fake_api.port)

    result = await _call_tool(
        mcp_server, GOOD_TOKEN, "proxmox",
        {"method": "POST", "path": "/nodes/pve1/qemu/100/status/stop",
         "params": {"password": "x-should-not-log"}},
    )

    assert result.is_error
    assert fake_api.requests == []
    [refusal] = _records(audit)
    assert (refusal["phase"], refusal["token_id"], refusal["host"]) == ("refused", "t-good", HV)
    assert refusal["params"] == {"password": "<redacted>"}
    assert "x-should-not-log" not in audit.path.read_text()


async def test_a_path_leaving_the_api_is_refused_and_nothing_is_sent(tmp_path, ssh_server, pki, fake_api):
    mcp_server, audit = _build_with_proxmox(tmp_path, ssh_server, pki, fake_api.port)

    result = await _call_tool(
        mcp_server, PVE_TOKEN, "proxmox", {"method": "GET", "path": "/../../pve2/js/x.js"},
    )

    assert result.is_error
    assert fake_api.requests == []
    [refusal] = _records(audit)
    assert refusal["phase"] == "refused"
    assert "segments" in refusal["reason"]


async def test_a_proxmox_permission_refusal_is_a_result_not_an_error(tmp_path, ssh_server, pki, fake_api):
    mcp_server, audit = _build_with_proxmox(tmp_path, ssh_server, pki, fake_api.port)

    result = await _call_tool(mcp_server, PVE_TOKEN, "proxmox", {"method": "GET", "path": "/denied"})

    assert not result.is_error
    body = _content(result)
    assert (body["status"], body["reason"]) == (403, "Permission check failed (/vms/123, VM.Audit)")
    intent, res = _records(audit)
    assert (res["status"], res["reason"]) == (403, "Permission check failed (/vms/123, VM.Audit)")


async def test_an_untrusted_api_is_an_error_with_a_result_record(tmp_path, ssh_server, pki, impostor):
    mcp_server, audit = _build_with_proxmox(tmp_path, ssh_server, pki, impostor.port)

    result = await _call_tool(mcp_server, PVE_TOKEN, "proxmox", {"method": "GET", "path": "/version"})

    assert result.is_error
    assert impostor.requests == []
    intent, res = _records(audit)
    assert (intent["phase"], res["phase"], res["id"]) == ("intent", "result", intent["id"])
    assert "not trusted by the pinned CA" in res["error"]
    assert PVE_SECRET not in audit.path.read_text()


async def test_every_record_made_with_a_static_token_says_unconfined(tmp_path, ssh_server):
    """ADR-0006 decision 7 and ADR-0014 decision G: a static token is a fallback
    token, and every record of its calls says so: intents, refusals, and the
    hosts tool's too."""
    mcp_server, settings, _ = _build(tmp_path, ssh_server)
    await _call_tool(mcp_server, GOOD_TOKEN, "hosts", {})
    await _call_tool(mcp_server, GOOD_TOKEN, "exec", {"host": "testhost", "command": "true"})
    await _call_tool(mcp_server, NARROW_TOKEN, "exec", {"host": "testhost", "command": "true"})
    records = [json.loads(line) for line in settings.audit_log_path.read_text().splitlines()]
    with_token = [r for r in records if "token_id" in r]
    assert {(r["phase"], r["tool"]) for r in with_token} == {
        ("intent", "hosts"), ("intent", "exec"), ("refused", "exec")}
    assert all(r["unconfined"] is True for r in with_token)


# --- refusals reach the client with their reason (defect, 2026-10-14) ---------------
# Every tool's refusals used to reach the client as "Error executing tool <name>":
# they raised plain exceptions, whose text the MCP library hides. Only a
# switched-off client is meant to learn nothing (ADR-0003 question B), and that
# is the middleware's refusal, before any tool runs.


def _text(result) -> str:
    assert result.is_error
    return result.content[0].text


async def test_a_host_outside_the_allowlist_says_so(tmp_path, ssh_server):
    mcp_server, _, _ = _build(tmp_path, ssh_server)
    result = await _call_tool(mcp_server, NARROW_TOKEN, "exec", {"host": "testhost", "command": "true"})
    assert "token 't-narrow' is not allowed to reach host 'testhost'" in _text(result)


async def test_a_host_not_in_the_inventory_says_so(tmp_path, ssh_server):
    mcp_server, _, _ = _build(tmp_path, ssh_server)
    result = await _call_tool(mcp_server, NARROW_TOKEN, "exec", {"host": "some-other-host", "command": "true"})
    assert "unknown host 'some-other-host' (not in nervus's inventory)" in _text(result)


async def test_a_path_outside_the_transfer_dir_says_so(tmp_path, ssh_server):
    mcp_server, _, _ = _build(tmp_path, ssh_server)
    result = await _call_tool(mcp_server, GOOD_TOKEN, "get",
                              {"host": "testhost", "remote_path": "/etc/hostname", "local_path": "../escape"})
    assert "outside the transfer directory" in _text(result)


async def test_a_missing_remote_file_says_so(tmp_path, ssh_server):
    mcp_server, _, _ = _build(tmp_path, ssh_server)
    result = await _call_tool(mcp_server, GOOD_TOKEN, "get",
                              {"host": "testhost", "remote_path": str(tmp_path / "absent"), "local_path": "x"})
    assert "No such file" in _text(result)


async def test_a_proxmox_request_nervus_will_not_send_says_why(tmp_path, ssh_server, pki, fake_api):
    mcp_server, _ = _build_with_proxmox(tmp_path, ssh_server, pki, fake_api.port)
    result = await _call_tool(mcp_server, PVE_TOKEN, "proxmox", {"method": "GET", "path": "/nodes/../access"})
    assert "may not contain" in _text(result)


async def test_a_fault_inside_nervus_stays_hidden(tmp_path, ssh_server, monkeypatch):
    """A bug's text may carry internals; the library's generic answer stays."""
    import nervus.server as server_module

    def broken(settings, host):
        raise RuntimeError("internal detail: /opt/nervus/secrets/nervus_ed25519")

    monkeypatch.setattr(server_module, "connect_host", broken)
    mcp_server, _, _ = _build(tmp_path, ssh_server)
    result = await _call_tool(mcp_server, GOOD_TOKEN, "exec", {"host": "testhost", "command": "true"})
    assert _text(result) == "Error executing tool exec"


async def test_a_host_called_hv_is_not_the_proxmox_host_by_its_name(tmp_path, ssh_server, pki, fake_api):
    """ADR-0019 decision D: only `hypervisor: proxmox` makes an entry the
    Proxmox host. One called `hv` without it gates nothing."""
    mcp_server, audit = _build_with_proxmox(tmp_path, ssh_server, pki, fake_api.port,
                                            entry=_hypervisor_entry("hv", hypervisor=None))
    result = await _call_tool(mcp_server, PVE_TOKEN, "proxmox", {"method": "GET", "path": "/version"})
    assert result.is_error
    assert "no inventory entry is marked `hypervisor: proxmox`" in result.content[0].text
    assert fake_api.requests == []
    [refusal] = [r for r in _records(audit) if r["phase"] == "refused"]
    assert (refusal["tool"], refusal["host"]) == ("proxmox", None)


# --- a call that fails after its intent gets a result naming its error (procedure 054, finding 3) ----
# A newcomer's `put` into /etc, refused by the machine, left an intent and nothing else, and the
# viewer showed it as "no result recorded", as it shows a call still running. The proxmox tool's
# result always said its error; now every tool that reaches a machine does too.


def _calls(settings, tool) -> list[dict]:
    return [r for r in _audit_records(settings) if r["tool"] == tool and r["phase"] in ("intent", "result")]


@pytest.mark.skipif(os.geteuid() == 0, reason="root writes into a folder whose mode refuses it")
async def test_a_put_the_machine_refuses_has_a_result_naming_its_error(tmp_path, ssh_server):
    mcp_server, settings, _ = _build(tmp_path, ssh_server)
    (settings.transfer_dir / "payload.txt").write_text("hello")
    shut = tmp_path / "shut"
    shut.mkdir(mode=0o500)
    try:
        result = await _call_tool(mcp_server, GOOD_TOKEN, "put",
                                  {"host": "testhost", "local_path": "payload.txt", "remote_path": str(shut / "x")})
    finally:
        shut.chmod(0o700)
    assert "Permission denied" in _text(result)
    intent, res = _calls(settings, "put")
    assert (intent["phase"], res["phase"], res["id"]) == ("intent", "result", intent["id"])
    assert _text(result).endswith(f": {res['error']}")  # after the library's "Error executing tool put"
    assert res["ssh_ports"] and res["duration_s"] >= 0 and "ok" not in res


@pytest.mark.parametrize("tool, arguments", [
    ("exec", {"command": "true"}),
    ("exec_bg", {"command": "true"}),
    ("job", {"job_id": "a1b2c3d4", "action": "status"}),
    ("put", {"local_path": "payload.txt", "remote_path": "/tmp/nervus-test-never-written"}),
    ("get", {"remote_path": "/etc/hostname", "local_path": "x"}),
])
async def test_a_call_whose_connection_fails_has_a_result_naming_its_error(tmp_path, ssh_server, monkeypatch,
                                                                           tool, arguments):
    import nervus.server as server_module

    def refused(settings, host):
        raise ConnectionRefusedError("Connection refused (the test's)")

    monkeypatch.setattr(server_module, "connect_host", refused)
    mcp_server, settings, _ = _build(tmp_path, ssh_server)
    (settings.transfer_dir / "payload.txt").write_text("hello")
    result = await _call_tool(mcp_server, GOOD_TOKEN, tool, {"host": "testhost", **arguments})
    assert _text(result).endswith(": ConnectionRefusedError: Connection refused (the test's)")
    intent, res = _calls(settings, tool)
    assert (intent["phase"], res["phase"], res["id"]) == ("intent", "result", intent["id"])
    assert res["error"] == "ConnectionRefusedError: Connection refused (the test's)"


async def test_a_fault_inside_nervus_is_recorded_by_its_type_alone(tmp_path, ssh_server, monkeypatch):
    """Its text may carry internals: the client is told only that the tool failed, and the
    log, which is copied where agents can read it, only what kind of fault it was."""
    import nervus.server as server_module

    def broken(settings, host):
        raise RuntimeError("internal detail: /opt/nervus/secrets/nervus_ed25519")

    monkeypatch.setattr(server_module, "connect_host", broken)
    mcp_server, settings, _ = _build(tmp_path, ssh_server)
    result = await _call_tool(mcp_server, GOOD_TOKEN, "exec", {"host": "testhost", "command": "true"})
    assert _text(result) == "Error executing tool exec"
    intent, res = _calls(settings, "exec")
    assert (res["phase"], res["id"], res["error"]) == ("result", intent["id"], "RuntimeError")
    assert "internal detail" not in settings.audit_log_path.read_text()


async def test_a_call_that_works_still_has_one_result_and_no_error(tmp_path, ssh_server):
    mcp_server, settings, _ = _build(tmp_path, ssh_server)
    await _call_tool(mcp_server, GOOD_TOKEN, "exec", {"host": "testhost", "command": "true", "cwd": "/tmp"})
    intent, res = _calls(settings, "exec")
    assert (res["id"], res["exit_code"]) == (intent["id"], 0) and "error" not in res
