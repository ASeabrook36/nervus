"""The download route (ADR-0016 decisions A, B, F, G and H): GET /exports/<id>
beside /mcp, with the client's own token, its own exports only, byte ranges
for resuming, and an audit record for every request.

Most tests go through the app in-process. The last ones run nervus's MCP app
under a real uvicorn on loopback and download with real curl, the way a client
will: the token through standard input, never in a command's arguments, and
`curl -C -` to resume."""

import asyncio
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn

from nervus.audit import AuditLog
from nervus.auth import REFUSAL_SECONDS, Token
from nervus.config import Settings
from nervus.database import Database
from nervus.download import parse_range
from nervus.exporter import Exporter
from nervus.exports import LIFETIME_SECONDS, ExportStore
from nervus.server import build_server

MiB = 1024 * 1024
MINE = "sekret-mine"
THEIRS = "sekret-theirs"
DATA = os.urandom(3 * MiB + 17)
SHA = hashlib.sha256(DATA).hexdigest()


class World:
    pass


@pytest.fixture
def world(tmp_path):
    w = World()
    w.tmp = tmp_path
    w.switches = tmp_path / "switches.yaml"
    w.switches.write_text("lockdown: false\ndisabled: []\n")
    w.settings = Settings(hosts={}, tokens_path=tmp_path / "t", known_hosts_path=tmp_path / "k",
                          ssh_key_path=tmp_path / "s", audit_log_path=tmp_path / "audit.jsonl",
                          transfer_dir=tmp_path, bind_host="127.0.0.1", bind_port=0,
                          switches_path=w.switches)
    w.tokens = {MINE: Token(id="t-mine", client="codex", project="project-b", hosts=frozenset({"hv"})),
                THEIRS: Token(id="t-theirs", client="codex", project="other", hosts=frozenset({"hv"}))}
    w.audit = AuditLog(path=w.settings.audit_log_path)
    db = Database(tmp_path / "nervus.db")
    db.open()
    w.store = ExportStore(db, tmp_path / "exports", free_bytes=lambda: 100 * 1024**3)
    w.store.open()
    exporter = Exporter(w.store, w.audit, connect=None, vm_api=None)
    w.app = build_server(settings=w.settings, tokens=w.tokens, audit=w.audit,
                         exporter=exporter).streamable_http_app()
    export, _ = w.store.begin("t-mine", "k", {"kind": "vm", "vmid": 100, "path": "/tmp/out.tar.gz"},
                              "/tmp/out.tar.gz", len(DATA))
    writer = w.store.writer(export)
    writer.write(DATA)
    w.export = w.store.finish(export, writer)
    w.url = f"/exports/{w.export.id}"
    return w


async def _get(w, path=None, token=MINE, method="GET", **headers):
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=w.app), base_url="http://nervus") as c:
        return await c.request(method, path or w.url, headers=headers)


def _records(w):
    if not w.settings.audit_log_path.exists():
        return []
    return [json.loads(line) for line in w.settings.audit_log_path.read_text().splitlines()]


# --- ranges -----------------------------------------------------------------------


@pytest.mark.parametrize("header, expected", [
    (None, None),
    ("bytes=0-", (0, 99)),
    ("bytes=10-", (10, 99)),
    ("bytes=10-19", (10, 19)),
    ("bytes=90-500", (90, 99)),
    ("bytes=-10", (90, 99)),
    ("bytes=-500", (0, 99)),
    ("bytes=100-", "unsatisfiable"),
    ("bytes=20-10", "unsatisfiable"),
    ("bytes=-0", "unsatisfiable"),
    ("bytes=0-1,5-6", None),  # several ranges: the whole file
    ("items=0-1", None),
    ("bytes=-", None),
    ("bytes=x-", None),
])
def test_ranges(header, expected):
    assert parse_range(header, 100) == expected


# --- a whole download -------------------------------------------------------------


async def test_the_owner_downloads_the_whole_file_with_its_hash(world):
    resp = await _get(world)
    assert resp.status_code == 200
    assert resp.content == DATA
    assert resp.headers["content-length"] == str(len(DATA))
    assert resp.headers["x-nervus-sha256"] == SHA
    assert resp.headers["etag"] == f'"{SHA}"'
    assert resp.headers["accept-ranges"] == "bytes"
    assert 'filename="out.tar.gz"' in resp.headers["content-disposition"]


async def test_each_download_is_audited_without_the_token(world):
    await _get(world)
    intent, result = _records(world)[-2:]
    assert intent["tool"] == "download" and intent["phase"] == "intent"
    assert intent["token_id"] == "t-mine" and intent["export_id"] == world.export.id
    assert result["id"] == intent["id"] and result["all_sent"] is True
    assert result["bytes_sent"] == len(DATA)
    assert MINE not in world.settings.audit_log_path.read_text()


async def test_head_gives_the_size_and_hash_without_the_body(world):
    resp = await _get(world, method="HEAD")
    assert resp.status_code == 200 and resp.content == b""
    assert resp.headers["content-length"] == str(len(DATA))
    assert resp.headers["x-nervus-sha256"] == SHA


# --- resuming (decision F) --------------------------------------------------------


async def test_a_range_from_an_offset_gives_the_rest(world):
    resp = await _get(world, range="bytes=1000000-")
    assert resp.status_code == 206
    assert resp.content == DATA[1000000:]
    assert resp.headers["content-range"] == f"bytes 1000000-{len(DATA) - 1}/{len(DATA)}"
    assert _records(world)[-2]["range"] == "bytes=1000000-"


async def test_a_range_past_the_end_is_refused_with_the_size(world):
    resp = await _get(world, range=f"bytes={len(DATA)}-")
    assert resp.status_code == 416
    assert resp.headers["content-range"] == f"bytes */{len(DATA)}"


async def test_if_range_with_another_version_gets_the_whole_file(world):
    resp = await _get(world, range="bytes=10-", **{"if-range": '"not-this-one"'})
    assert resp.status_code == 200 and resp.content == DATA


async def test_if_range_with_this_version_gets_the_piece(world):
    resp = await _get(world, range="bytes=10-", **{"if-range": f'"{SHA}"'})
    assert resp.status_code == 206 and resp.content == DATA[10:]


# --- who may download (decision B, ADR-0003) --------------------------------------


async def test_another_valid_token_gets_404_and_is_audited(world):
    resp = await _get(world, token=THEIRS)
    assert resp.status_code == 404
    refusal = _records(world)[-1]
    assert refusal["phase"] == "refused" and refusal["token_id"] == "t-theirs"


@pytest.mark.parametrize("token", [None, "wrong"])
async def test_no_token_or_a_wrong_one_gets_401_after_the_refusal_wait(world, token):
    began = time.monotonic()
    resp = await _get(world, token=token)
    assert time.monotonic() - began >= REFUSAL_SECONDS
    assert resp.status_code == 401
    assert resp.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize("switches", ["lockdown: false\ndisabled: [t-mine]\n", "lockdown: true\ndisabled: []\n",
                                      "not: [valid"])
async def test_a_switched_off_client_gets_exactly_an_invalid_tokens_refusal(world, switches):
    world.switches.write_text(switches)
    wrong = await _get(world, token="wrong")
    began = time.monotonic()
    off = await _get(world)
    assert time.monotonic() - began >= REFUSAL_SECONDS
    assert (off.status_code, off.text, dict(off.headers)) == (wrong.status_code, wrong.text, dict(wrong.headers))
    refusal = _records(world)[-1]
    assert refusal["phase"] == "refused" and refusal["reason"].startswith("switches:")


async def test_an_expired_or_deleted_export_is_gone(world):
    world.store.delete("t-mine", world.export.id)
    assert (await _get(world)).status_code == 404


async def test_an_export_still_being_copied_is_not_served(world):
    staging, _ = world.store.begin("t-mine", "k2", {}, "f", 10)
    assert (await _get(world, path=f"/exports/{staging.id}")).status_code == 404


@pytest.mark.parametrize("path", ["/exports/..%2Fnervus.db", "/exports/nervus.db", "/exports/" + "0" * 32,
                                  "/exports/%2E%2E", "/exports/" + "a" * 32 + ".part"])
async def test_an_id_that_is_not_an_export_finds_nothing(world, path):
    resp = await _get(world, path=path)
    assert resp.status_code == 404
    assert b"SQLite" not in resp.content


async def test_a_swapped_file_is_not_served(world):
    final = world.tmp / "exports" / world.export.id
    final.unlink()
    outside = world.tmp / "elsewhere"
    outside.write_bytes(DATA)
    final.symlink_to(outside)
    resp = await _get(world)
    assert resp.status_code == 404
    assert "lost" in _records(world)[-1]["reason"]


async def test_the_route_is_absent_without_an_export_store(world):
    bare = build_server(settings=world.settings, tokens=world.tokens, audit=world.audit).streamable_http_app()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=bare), base_url="http://nervus") as c:
        resp = await c.get(world.url, headers={"Authorization": f"Bearer {MINE}"})
    assert resp.status_code == 404
    assert _records(world) == []


# --- with real curl, against a real server ----------------------------------------

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


def _curl(w, out, *extra, rate=None):
    """As the client instructions will say: the header through standard input."""
    args = ["curl", "-fsS", "-H", "@-", "-o", str(out), *extra]
    if rate:
        args += ["--limit-rate", rate]
    args.append(w.base + w.url)
    return subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def _run(proc, token=MINE):
    out, err = proc.communicate(f"Authorization: Bearer {token}\n".encode(), timeout=60)
    return proc.returncode, err.decode()


@curl
def test_curl_saves_the_file_and_its_hash_matches(served, tmp_path):
    out = tmp_path / "saved.tar.gz"
    code, err = _run(_curl(served, out))
    assert code == 0, err
    assert hashlib.sha256(out.read_bytes()).hexdigest() == SHA


@curl
def test_curl_resumes_a_partial_file(served, tmp_path):
    out = tmp_path / "saved"
    out.write_bytes(DATA[:1234567])
    code, err = _run(_curl(served, out, "-C", "-"))
    assert code == 0, err
    assert hashlib.sha256(out.read_bytes()).hexdigest() == SHA
    assert _records(served)[-2]["range"] == "bytes=1234567-"


@curl
def test_curl_resumes_a_download_that_was_cut_off(served, tmp_path):
    out = tmp_path / "saved"
    proc = _curl(served, out, rate="200k")
    proc.stdin.write(f"Authorization: Bearer {MINE}\n".encode())
    proc.stdin.close()
    for _ in range(100):
        if out.exists() and out.stat().st_size > 100_000:
            break
        time.sleep(0.05)
    proc.kill()
    proc.wait()
    partial = out.stat().st_size
    assert 0 < partial < len(DATA)
    code, err = _run(_curl(served, out, "-C", "-"))
    assert code == 0, err
    assert hashlib.sha256(out.read_bytes()).hexdigest() == SHA
    # Two requests: the one cut off, and the resume from where the file ended.
    # Whether the first says all_sent depends on how much the operating system
    # had buffered when curl was killed, so the hash above is the evidence.
    intents = [r for r in _records(served) if r["tool"] == "download" and r["phase"] == "intent"]
    assert [r["range"] for r in intents] == [None, f"bytes={partial}-"]


@curl
def test_curl_resuming_a_complete_file_changes_nothing(served, tmp_path):
    out = tmp_path / "saved"
    out.write_bytes(DATA)
    code, err = _run(_curl(served, out, "-C", "-"))
    assert out.read_bytes() == DATA
    # curl takes the 416 to a resume as "already complete" and succeeds, even
    # with -f (curl 8.7.1 on macOS, 2026-10-14), so a client may simply run the
    # same command again.
    assert code == 0, err


@curl
def test_curl_with_another_clients_token_fails_and_saves_nothing(served, tmp_path):
    out = tmp_path / "saved"
    code, _ = _run(_curl(served, out), token=THEIRS)
    assert code == 22  # curl -f: HTTP 404
    assert not out.exists()


# --- the commands docs/clients.md gives clients, run as written ---------------------

CLIENTS = Path(__file__).resolve().parent.parent / "docs" / "clients.md"
LONG = "L" * 43  # the shape of a real token, which nervus-headers checks
ITEM = "nervus-token-claude-code-project-a"  # what <item> stands for in the doc


def _documented(name):
    text = CLIENTS.read_text()
    match = re.search(rf"<!-- download:{name} -->\n```bash\n(.*?)\n```", text, re.S)
    assert match, f"docs/clients.md has no download:{name} command"
    return match.group(1)


@pytest.fixture
def served_tls(world, tmp_path):
    """The same app over HTTPS, as clients reach it (ADR-0021): a certificate of
    nervus's own authority, and NERVUS_CACERT naming its root, as
    tools/nervus-trust saves it."""
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


def _as_run(w, command, out):
    return (command.replace("https://<nervus>:8000", w.base)
            .replace("<export_id>", w.export.id).replace("<file>", str(out)).replace("<item>", ITEM))


@curl
@pytest.mark.parametrize("shell", ["zsh", "bash"])
def test_the_codex_command_downloads_and_resumes(served_tls, tmp_path, shell):
    served = served_tls
    if shutil.which(shell) is None:
        pytest.skip(f"{shell} is not installed")
    out = tmp_path / "saved"
    out.write_bytes(DATA[:777])  # cut off earlier
    command = _as_run(served, _documented("codex"), out)
    done = subprocess.run([shell, "-c", command],
                          env={**os.environ, "NERVUS_CODEX": MINE, "NERVUS_CACERT": str(served.root)},
                          capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    assert hashlib.sha256(out.read_bytes()).hexdigest() == SHA
    assert _records(served)[-2]["range"] == "bytes=777-"  # resumed, not fetched again
    assert MINE not in command


@curl
def test_the_claude_code_command_downloads_through_the_keychain_helper(served_tls, tmp_path):
    served = served_tls
    served.tokens[LONG] = served.tokens[MINE]  # the same client, by its Keychain value
    fake = tmp_path / "security"
    fake.write_text(f"#!/bin/sh\n[ \"$*\" = 'find-generic-password -a nervus -s {ITEM} -w' ]"
                    f" && echo {LONG}\n")
    fake.chmod(0o755)
    out = tmp_path / "saved"
    command = _as_run(served, _documented("claude-code"), out)
    done = subprocess.run(["bash", "-c", command], cwd=CLIENTS.parent.parent,
                          env={**os.environ, "NERVUS_SECURITY_BIN": str(fake), "NERVUS_CACERT": str(served.root)},
                          capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    assert hashlib.sha256(out.read_bytes()).hexdigest() == SHA


def _set_up_by_the_line(tmp_path, served, name="nervus.test-laptop"):
    """A home where the laptop's line has run (ADR-0032): its helper, its roots, and the token where the
    helper reads it, in a file and, for a Mac, through a stand-in keychain."""
    from nervus.laptop import TARGET

    home = tmp_path / "home"
    folder = home / ".config" / "nervus"
    folder.mkdir(parents=True)
    shutil.copy(TARGET / "nervus-headers", folder / "nervus-headers")
    (folder / "nervus-headers").chmod(0o755)
    shutil.copy(served.root, folder / "roots.pem")
    (folder / f"token-{name}").write_text(LONG + "\n")
    fake = tmp_path / "security"
    fake.write_text(f"#!/bin/sh\n[ \"$*\" = 'find-generic-password -a nervus -s nervus-{name} -w' ] && echo {LONG}\n")
    fake.chmod(0o755)
    return {**os.environ, "HOME": str(home), "NERVUS_SECURITY_BIN": str(fake)}, name


@curl
@pytest.mark.parametrize("shell", ["zsh", "bash"])
def test_the_command_for_a_client_set_up_by_the_line_downloads_through_its_helper(served_tls, tmp_path, shell):
    if shutil.which(shell) is None:
        pytest.skip(f"{shell} is not installed")
    served = served_tls
    served.tokens[LONG] = served.tokens[MINE]
    env, name = _set_up_by_the_line(tmp_path, served)
    out = tmp_path / "saved"
    command = _as_run(served, _documented("laptop"), out).replace("<name>", name)
    done = subprocess.run([shell, "-c", command], env=env, capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stderr
    assert hashlib.sha256(out.read_bytes()).hexdigest() == SHA
    assert LONG not in command
