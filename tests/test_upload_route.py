"""The upload route (ADR-0020 step 2; decisions A, F, G and H): PUT /uploads
and GET /uploads/<request key> beside /mcp, with the client's own token, a
destination its allowlist reaches, the body checked against its declared
SHA-256, delivery left to a deliverer (steps 3 and 4; a stand-in here), and an
audit intent and result for every request."""

import asyncio
import hashlib
import json
import os
import shutil
import socket
import subprocess
import threading
import time

import httpx
import pytest
import uvicorn

from nervus.audit import AuditLog
from nervus.auth import Token
from nervus.config import Host, Settings
from nervus.database import Database
from nervus.exports import Limits
from nervus.server import build_server
from nervus.uploader import Uploader
from nervus.uploads import UploadRefused, UploadStore

MINE = "sekret-mine"
THEIRS = "sekret-theirs"
OFF = "sekret-off"
DATA = b"#!/bin/sh\necho hello\n" * 100
SHA = hashlib.sha256(DATA).hexdigest()
BIG = os.urandom(3 * 1024 * 1024 + 17)


class StandIn:
    """A deliverer that records what it was asked, and answers as told."""

    def __init__(self):
        self.calls = []
        self.gate: asyncio.Event | None = None
        self.answer = None  # None: the declared hash, by route "sftp"
        self.raises: Exception | None = None

    async def __call__(self, upload):
        self.calls.append(upload)
        if self.gate is not None:
            await self.gate.wait()
        if self.raises is not None:
            raise self.raises
        return self.answer or ("sftp", upload.sha256)


class World:
    pass


def _host(name, **extra):
    return Host(name=name, address=f"{name}.example", os="debian", role="test", agent_user="agent",
                status="active", **extra)


@pytest.fixture
def world(tmp_path):
    w = World()
    w.switches = tmp_path / "switches.yaml"
    w.switches.write_text("lockdown: false\ndisabled: [t-off]\n")
    w.settings = Settings(hosts={"web": _host("web"), "db": _host("db"), "hv": _host("hv", hypervisor="proxmox")},
                          tokens_path=tmp_path / "t", known_hosts_path=tmp_path / "k", ssh_key_path=tmp_path / "s",
                          audit_log_path=tmp_path / "audit.jsonl", transfer_dir=tmp_path, bind_host="127.0.0.1",
                          bind_port=0, switches_path=w.switches)
    w.tokens = {MINE: Token(id="t-mine", client="codex", project="a", hosts=frozenset({"web", "hv"})),
                THEIRS: Token(id="t-theirs", client="codex", project="b", hosts=frozenset({"web"})),
                OFF: Token(id="t-off", client="codex", project="c", hosts=frozenset({"web"}))}
    w.audit = AuditLog(path=w.settings.audit_log_path)
    db = Database(tmp_path / "nervus.db")
    db.open()
    w.store = UploadStore(db, tmp_path / "uploads", limits=Limits(max_export_bytes=4 * 1024 * 1024),
                          free_bytes=lambda: 100 * 1024**3)
    w.store.open()
    w.deliver = StandIn()
    w.uploader = Uploader(w.store, w.audit, deliver=w.deliver)
    w.app = build_server(settings=w.settings, tokens=w.tokens, audit=w.audit,
                         uploader=w.uploader).streamable_http_app()
    return w


def _query(**params):
    base = {"host": "web", "path": "/srv/run.sh", "sha256": SHA, "key": "k1"}
    base.update(params)
    return {k: v for k, v in base.items() if v is not None}


async def _put(w, data=DATA, token=MINE, headers=None, **params):
    headers = dict(headers or {})
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=w.app), base_url="http://nervus") as c:
        return await c.put("/uploads", params=_query(**params), content=data, headers=headers)


async def _status(w, key="k1", token=MINE, **params):
    headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=w.app), base_url="http://nervus") as c:
        return await c.get(f"/uploads/{key}", params=params, headers=headers)


def _records(w):
    if not w.settings.audit_log_path.exists():
        return []
    return [json.loads(line) for line in w.settings.audit_log_path.read_text().splitlines()]


def _staged(w):
    return list(w.store.directory.iterdir())


# --- a whole upload ---------------------------------------------------------------


async def test_an_upload_to_a_host_is_received_checked_and_delivered(world):
    r = await _put(world)
    assert r.status_code == 200
    body = r.json()
    assert body["state"] == "delivered"
    assert body["sha256"] == SHA and body["size"] == len(DATA)
    assert body["route"] == "sftp"
    assert body["destination"] == {"kind": "host", "host": "web", "path": "/srv/run.sh",
                                   "replace": False, "root": False, "mode": None}
    assert len(world.deliver.calls) == 1
    assert _staged(world) == []


async def test_the_options_reach_the_deliverer(world):
    r = await _put(world, replace="1", root="1", mode="0755")
    assert r.status_code == 200
    assert world.deliver.calls[0].destination == {"kind": "host", "host": "web", "path": "/srv/run.sh",
                                                  "replace": True, "root": True, "mode": "0755"}


async def test_an_upload_to_a_vm_needs_the_proxmox_host_in_the_allowlist(world):
    r = await _put(world, host=None, vmid="123")
    assert r.status_code == 200
    assert world.deliver.calls[0].destination == {"kind": "vm", "vmid": 123, "path": "/srv/run.sh",
                                                  "replace": False, "root": False, "mode": None}
    r = await _put(world, token=THEIRS, host=None, vmid="123")
    assert r.status_code == 403
    assert r.json()["failure"]["code"] == "not_allowed"


async def test_a_body_that_is_not_the_declared_file_is_never_delivered(world):
    r = await _put(world, sha256="0" * 64)
    assert r.status_code == 422
    assert r.json()["state"] == "failed"
    assert r.json()["failure"]["code"] == "hash_mismatch"
    assert world.deliver.calls == []
    assert _staged(world) == []


# --- refused before anything is read --------------------------------------------------


async def test_no_token_is_refused(world):
    r = await _put(world, token=None)
    assert r.status_code == 401
    assert world.store.by_key("t-mine", "k1") is None


async def test_a_switched_off_client_is_refused_and_audited(world):
    r = await _put(world, token=OFF)
    assert r.status_code == 401
    assert world.store.by_key("t-off", "k1") is None
    assert any(rec.get("token_id") == "t-off" and rec.get("phase") == "refused" for rec in _records(world))


@pytest.mark.parametrize("host", ["db", "nowhere"])
async def test_a_host_outside_the_allowlist_is_refused_and_audited(world, host):
    r = await _put(world, host=host)
    assert r.status_code == 403
    assert r.json()["failure"]["code"] == "not_allowed"
    assert world.store.by_key("t-mine", "k1") is None
    assert any(rec.get("host") == host and rec.get("phase") == "refused" for rec in _records(world))


async def test_a_vm_upload_without_a_proxmox_host_in_the_inventory_is_refused(world):
    del world.settings.hosts["hv"]
    r = await _put(world, host=None, vmid="123")
    assert r.status_code == 403
    assert r.json()["failure"]["code"] == "no_proxmox"


@pytest.mark.parametrize("params", [
    {"host": None},                              # no destination
    {"vmid": "123"},                             # two destinations
    {"host": None, "vmid": "x"},
    {"path": None},
    {"path": "srv/run.sh"},                      # not absolute
    {"path": "/srv/"},                           # not a file
    {"path": "/srv/a\x00b"},
    {"host": None, "vmid": "123", "root": "1"},  # a VM's guest agent is root already
    {"mode": "755x"},
    {"mode": "17777"},
    {"replace": "maybe"},
])
async def test_a_malformed_destination_is_refused(world, params):
    r = await _put(world, **params)
    assert r.status_code == 400
    assert r.json()["failure"]["code"] == "bad_destination"
    assert world.store.by_key("t-mine", "k1") is None


@pytest.mark.parametrize("params, code", [
    ({"wait": "soon"}, "bad_wait"),
    ({"sha256": None}, "bad_sha256"),
    ({"sha256": "abc"}, "bad_sha256"),
    ({"key": None}, "bad_request_key"),
    ({"key": "a b"}, "bad_request_key"),
])
async def test_a_malformed_declaration_is_refused(world, params, code):
    r = await _put(world, **params)
    assert r.status_code == 400
    assert r.json()["failure"]["code"] == code


async def test_a_body_without_a_declared_length_is_refused(world):
    async def chunks():
        yield DATA

    r = await _put(world, data=chunks())
    assert r.status_code == 411
    assert r.json()["failure"]["code"] == "length_required"


async def test_a_file_over_the_ceiling_is_refused_before_it_is_read(world):
    big = b"x" * (4 * 1024 * 1024 + 1)
    r = await _put(world, data=big, sha256=hashlib.sha256(big).hexdigest())
    assert r.status_code == 413
    assert r.json()["failure"]["code"] == "too_large"
    assert _staged(world) == []


# --- retries, waiting and status (decision G) -----------------------------------------


async def test_the_same_key_and_file_again_returns_the_same_upload_and_delivers_once(world):
    first = (await _put(world)).json()
    again = await _put(world)
    assert again.status_code == 200
    assert again.json()["upload_id"] == first["upload_id"]
    assert len(world.deliver.calls) == 1


async def test_the_same_key_with_another_file_is_refused(world):
    await _put(world)
    other = b"something else"
    r = await _put(world, data=other, sha256=hashlib.sha256(other).hexdigest())
    assert r.status_code == 409
    assert r.json()["failure"]["code"] == "key_reused"


async def test_a_slow_delivery_answers_delivering_and_can_be_asked_about_later(world):
    world.deliver.gate = asyncio.Event()
    r = await _put(world, wait="0.05")
    assert r.status_code == 202
    assert r.json()["state"] == "delivering"
    r = await _status(world, wait="0")
    assert r.status_code == 202 and r.json()["state"] == "delivering"
    world.deliver.gate.set()
    r = await _status(world, wait="5")
    assert r.status_code == 200
    assert r.json()["state"] == "delivered"


async def test_another_tokens_upload_is_not_found(world):
    await _put(world)
    assert (await _status(world, token=THEIRS)).status_code == 404
    assert (await _status(world, key="nope")).status_code == 404
    assert (await _status(world, token=None)).status_code == 401


# --- a delivery that fails ---------------------------------------------------------------


async def test_a_refused_delivery_fails_with_the_deliverers_reason(world):
    world.deliver.raises = UploadRefused("exists", "/srv/run.sh exists; send replace=1 to replace it")
    r = await _put(world)
    assert r.status_code == 422
    assert r.json()["failure"] == {"code": "exists", "message": "/srv/run.sh exists; send replace=1 to replace it"}
    assert _staged(world) == []


async def test_a_destination_that_cannot_be_reached_fails(world):
    world.deliver.raises = OSError("connection refused")
    r = await _put(world)
    assert r.status_code == 422
    assert r.json()["failure"]["code"] == "destination_error"
    assert "connection refused" in r.json()["failure"]["message"]
    assert _staged(world) == []


async def test_a_destination_that_hashed_differently_fails(world):
    world.deliver.answer = ("sftp", "0" * 64)
    r = await _put(world)
    assert r.status_code == 422
    assert r.json()["failure"]["code"] == "destination_hash"


# --- the audit log (decision H) ----------------------------------------------------------


async def test_an_upload_has_one_intent_and_one_result_and_no_token(world):
    body = (await _put(world)).json()
    mine = [rec for rec in _records(world) if rec.get("id") == body["run_id"]]
    assert [rec["phase"] for rec in mine] == ["intent", "result"]
    intent, result = mine
    assert intent["tool"] == "upload"
    assert intent["token_id"] == "t-mine"
    assert intent["destination"]["host"] == "web"
    assert intent["size"] == len(DATA) and intent["sha256"] == SHA
    assert result["state"] == "delivered" and result["route"] == "sftp"
    text = world.settings.audit_log_path.read_text()
    for secret in (MINE, THEIRS, OFF):
        assert secret not in text


async def test_a_slow_deliverys_result_is_written_when_it_ends(world):
    world.deliver.gate = asyncio.Event()
    body = (await _put(world, wait="0")).json()
    assert [rec["phase"] for rec in _records(world) if rec.get("id") == body["run_id"]] == ["intent"]
    world.deliver.gate.set()
    await _status(world, wait="5")
    results = [rec for rec in _records(world) if rec.get("id") == body["run_id"] and rec["phase"] == "result"]
    assert len(results) == 1 and results[0]["state"] == "delivered"


async def test_a_refusal_after_the_intent_still_has_a_result(world):
    big = b"x" * (4 * 1024 * 1024 + 1)
    r = await _put(world, data=big, sha256=hashlib.sha256(big).hexdigest())
    body = r.json()
    mine = [rec for rec in _records(world) if rec.get("id") == body["run_id"]]
    assert [rec["phase"] for rec in mine] == ["intent", "result"]
    assert mine[1]["failure_code"] == "too_large"


@pytest.mark.parametrize("headers, expected", [
    ([(b"content-length", b"21")], 21),
    ([(b"content-length", b"0")], 0),
    ([], "length_required"),
    ([(b"content-length", b"-1")], "length_required"),
    ([(b"content-length", b"1e3")], "length_required"),
    # HTTP says a length beside chunks is ignored, so it declares nothing.
    ([(b"content-length", b"21"), (b"transfer-encoding", b"chunked")], "length_required"),
])
def test_the_declared_size_is_the_content_length_alone(headers, expected):
    from starlette.requests import Request

    from nervus.upload_route import declared_length

    request = Request({"type": "http", "method": "PUT", "path": "/uploads", "headers": headers})
    if isinstance(expected, int):
        assert declared_length(request) == expected
    else:
        with pytest.raises(UploadRefused) as refused:
            declared_length(request)
        assert refused.value.code == expected


# --- with real curl, against a real server ------------------------------------------

curl = pytest.mark.skipif(shutil.which("curl") is None, reason="curl is not installed")


@pytest.fixture
def served(world):
    """nervus's MCP app under uvicorn on a loopback port, in a thread."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(world.app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(200):
        if server.started:
            break
        time.sleep(0.01)
    world.base = f"http://127.0.0.1:{port}"
    yield world
    server.should_exit = True
    thread.join(timeout=10)


def _curl_upload(w, file, sha, path, token=MINE):
    """One command, as decision A has it: the header through standard input,
    the parameters encoded by curl, the body by -T with its length."""
    args = ["curl", "-sS", "--fail-with-body", "-H", "@-", "-T", str(file),
            "--url-query", "host=web", "--url-query", f"path={path}", "--url-query", f"sha256={sha}",
            "--url-query", "key=real-1", w.base + "/uploads"]
    proc = subprocess.run(args, input=f"Authorization: Bearer {token}\n".encode(), capture_output=True,
                          timeout=60)
    return proc.returncode, proc.stdout.decode(), proc.stderr.decode()


@curl
def test_curl_sends_a_file_in_one_command(served, tmp_path):
    file = tmp_path / "big.bin"
    file.write_bytes(BIG)
    code, out, err = _curl_upload(served, file, hashlib.sha256(BIG).hexdigest(), "/srv/a file.bin")
    assert code == 0, err
    body = json.loads(out)
    assert body["state"] == "delivered"
    assert body["size"] == len(BIG)
    assert served.deliver.calls[0].destination["path"] == "/srv/a file.bin"


@curl
def test_curl_shows_the_client_why_an_upload_failed(served, tmp_path):
    file = tmp_path / "big.bin"
    file.write_bytes(BIG)
    code, out, err = _curl_upload(served, file, "0" * 64, "/srv/a.bin")
    assert code == 22
    assert json.loads(out)["failure"]["code"] == "hash_mismatch"
    assert served.deliver.calls == []


# --- the commands docs/clients.md gives clients, run as written ---------------------

import re
from pathlib import Path

CLIENTS = Path(__file__).resolve().parent.parent / "docs" / "clients.md"
LONG = "L" * 43  # the shape of a real token, which nervus-headers checks
ITEM = "nervus-token-claude-code-project-a"


def _documented(name):
    match = re.search(rf"<!-- {name} -->\n```bash\n(.*?)\n```", CLIENTS.read_text(), re.S)
    assert match, f"docs/clients.md has no {name} command"
    return match.group(1)


@pytest.fixture
def served_tls(world, tmp_path):
    """The app over HTTPS, as clients reach it (ADR-0021), with NERVUS_CACERT
    naming nervus's root."""
    from nervus.tls import generate_own_authority, root_cert_path

    cert, key = tmp_path / "tls" / "tls.crt", tmp_path / "tls" / "tls.key"
    cert.parent.mkdir()
    generate_own_authority(cert, key, ["127.0.0.1", "nervus.test"])
    world.root = root_cert_path(cert)
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(world.app, host="127.0.0.1", port=port, log_level="error",
                                           ssl_certfile=str(cert), ssl_keyfile=str(key)))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(200):
        if server.started:
            break
        time.sleep(0.01)
    world.base = f"https://127.0.0.1:{port}"
    yield world
    server.should_exit = True
    thread.join(timeout=10)


def _as_run(w, command, file, key="doc-1"):
    return (command.replace("https://<nervus>:8000", w.base).replace("<file>", str(file))
            .replace("<host>", "web").replace("<path>", "/srv/a file.tar").replace("<key>", key)
            .replace("<item>", ITEM))


@curl
@pytest.mark.parametrize("shell", ["zsh", "bash"])
def test_the_codex_command_sends_a_file_and_the_status_command_reports_it(served_tls, tmp_path, shell):
    if shutil.which(shell) is None:
        pytest.skip(f"{shell} is not installed")
    if shutil.which("shasum") is None:
        pytest.skip("shasum is not installed")
    file = tmp_path / "my file.tar"
    file.write_bytes(BIG)
    env = {**os.environ, "NERVUS_CODEX": MINE, "NERVUS_CACERT": str(served_tls.root)}
    command = _as_run(served_tls, _documented("upload:codex"), file)
    done = subprocess.run([shell, "-c", command], env=env, capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    body = json.loads(done.stdout)
    assert body["state"] == "delivered"
    assert body["sha256"] == hashlib.sha256(BIG).hexdigest()
    assert served_tls.deliver.calls[0].destination["path"] == "/srv/a file.tar"
    assert MINE not in command
    status = subprocess.run([shell, "-c", _as_run(served_tls, _documented("upload-status:codex"), file)],
                            env=env, capture_output=True, text=True, timeout=60)
    assert status.returncode == 0, status.stderr
    assert json.loads(status.stdout)["upload_id"] == body["upload_id"]


@curl
def test_the_claude_code_command_sends_through_the_keychain_helper(served_tls, tmp_path):
    if shutil.which("shasum") is None:
        pytest.skip("shasum is not installed")
    served_tls.tokens[LONG] = served_tls.tokens[MINE]  # the same client, by its Keychain value
    fake = tmp_path / "security"
    fake.write_text(f"#!/bin/sh\n[ \"$*\" = 'find-generic-password -a nervus -s {ITEM} -w' ] && echo {LONG}\n")
    fake.chmod(0o755)
    file = tmp_path / "f.bin"
    file.write_bytes(DATA)
    command = _as_run(served_tls, _documented("upload:claude-code"), file)
    done = subprocess.run(["bash", "-c", command], cwd=CLIENTS.parent.parent,
                          env={**os.environ, "NERVUS_SECURITY_BIN": str(fake),
                               "NERVUS_CACERT": str(served_tls.root)},
                          capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    assert json.loads(done.stdout)["state"] == "delivered"


@curl
def test_a_documented_upload_that_fails_shows_why_and_exits_22(served_tls, tmp_path):
    if shutil.which("shasum") is None:
        pytest.skip("shasum is not installed")
    served_tls.deliver.raises = UploadRefused("exists", "/srv/a file.tar exists; send replace=1 to replace it")
    file = tmp_path / "f.bin"
    file.write_bytes(DATA)
    done = subprocess.run(["bash", "-c", _as_run(served_tls, _documented("upload:codex"), file)],
                          env={**os.environ, "NERVUS_CODEX": MINE, "NERVUS_CACERT": str(served_tls.root)},
                          capture_output=True, text=True, timeout=60)
    assert done.returncode == 22
    assert "replace=1" in json.loads(done.stdout)["failure"]["message"]


async def test_puts_description_sends_clients_to_uploads(world):
    """A client looking for how to send a file finds `put` first; it must say
    how to send one from the client's own machine (ADR-0020 decision I)."""
    server = build_server(settings=world.settings, tokens=world.tokens, audit=world.audit, uploader=world.uploader)
    (put,) = [t for t in await server.list_tools() if t.name == "put"]
    assert "PUT /uploads" in put.description
    assert "exec" in put.description


async def test_a_delivery_carries_the_sending_call_and_its_ports_reach_the_record(world):
    """ADR-0025: the delivery runs as a task of its own, and still connects for
    the call that sent the file, whose result record carries the port."""
    from nervus import certs
    seen = []

    async def deliver(upload):
        caller = certs.current()
        seen.append((caller.token_id, caller.run_id))
        caller.ports.append(40001)  # what nervus.ssh.connect notes for each connection
        return "sftp", upload.sha256

    world.uploader.deliver = deliver
    assert (await _put(world)).json()["state"] == "delivered"
    intent = next(r for r in _records(world) if r["phase"] == "intent")
    result = [r for r in _records(world) if r["phase"] == "result" and r["id"] == intent["id"]]
    assert seen == [("t-mine", intent["id"])]
    assert [r.get("ssh_ports") for r in result] == [[40001]]
