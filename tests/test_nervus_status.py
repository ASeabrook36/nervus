"""tools/nervus-status against a real nervus: its MCP app under uvicorn on
loopback, over HTTPS with nervus's own certificate or over plain HTTP, and a
real SSH server behind it, so every line the script prints is earned the way a
client would earn it (ADR-0021 order of work, step 1).

The script is run as a client runs it, with nothing in its environment but
PATH, HOME and the NERVUS_ variables a test gives it. NERVUS_TOKEN is always
set, so the script never falls back to NERVUS_TOKEN_COMMAND."""

import asyncio
import os
import re
import shutil
import socket
import threading
import time
from pathlib import Path

import pytest
import uvicorn

from nervus.audit import AuditLog
from nervus.auth import Token
from nervus.config import Host, Settings
from nervus.server import build_server
from nervus.tls import generate_own_authority, generate_self_signed, root_cert_path

TOOL = Path(__file__).resolve().parent.parent / "tools" / "nervus-status"
TOKEN = "sekret-status"

pytestmark = pytest.mark.skipif(
    shutil.which("curl") is None or shutil.which("bash") is None, reason="needs bash and curl"
)


def _ipv6_loopback() -> bool:
    try:
        with socket.socket(socket.AF_INET6) as s:
            s.bind(("::1", 0))
        return True
    except OSError:
        return False


class Counted:
    """The app, counting the HTTP requests that reach it: the evidence that a
    refused TLS handshake sent nothing, token included."""

    def __init__(self, app):
        self.app, self.requests = app, 0

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            self.requests += 1
        await self.app(scope, receive, send)


class Nervus:
    pass


def _cert(d: Path, name: str) -> tuple[Path, Path]:
    cert, key = d / f"{name}.crt", d / f"{name}.key"
    generate_self_signed(cert, key, ["localhost", "127.0.0.1", "::1"])
    return cert, key


def _serve(tmp_path, ssh_server, bind: str, tls: bool, authority: bool = False) -> Nervus:
    n = Nervus()
    host = Host(name="testhost", address=ssh_server.host, os="test", role="test",
                agent_user=ssh_server.username, status="onboarded")
    settings = Settings(hosts={"testhost": host}, tokens_path=tmp_path / "tokens.yaml",
                        known_hosts_path=ssh_server.known_hosts_path,
                        ssh_key_path=ssh_server.client_key_path,
                        audit_log_path=tmp_path / "audit.jsonl", transfer_dir=tmp_path,
                        bind_host=bind, bind_port=0, ssh_port=ssh_server.port)
    tokens = {TOKEN: Token(id="t-status", client="claude-code", project="p",
                           hosts=frozenset({"testhost"}))}
    n.app = Counted(build_server(settings=settings, tokens=tokens,
                                 audit=AuditLog(path=settings.audit_log_path)).streamable_http_app())
    family = socket.AF_INET6 if ":" in bind else socket.AF_INET
    with socket.socket(family) as s:
        s.bind((bind, 0))
        n.port = s.getsockname()[1]
    extra = {}
    if authority:  # what tls-init makes since ADR-0021: clients trust its root
        served, key = tmp_path / "own.crt", tmp_path / "own.key"
        generate_own_authority(served, key, ["127.0.0.1", "::1", "nervus.test"])
        n.cert = root_cert_path(served)
        extra = {"ssl_certfile": str(served), "ssl_keyfile": str(key)}
    elif tls:
        n.cert, key = _cert(tmp_path, "nervus")
        extra = {"ssl_certfile": str(n.cert), "ssl_keyfile": str(key)}
    n.server = uvicorn.Server(uvicorn.Config(n.app, host=bind, port=n.port, log_level="error", **extra))
    n.thread = threading.Thread(target=n.server.run, daemon=True)
    n.thread.start()
    for _ in range(500):
        if n.server.started:
            break
        time.sleep(0.01)
    assert n.server.started
    return n


@pytest.fixture
def served(tmp_path, ssh_server):
    started = []

    def start(bind="127.0.0.1", tls=True, authority=False):
        n = _serve(tmp_path, ssh_server, bind, tls, authority)
        started.append(n)
        return n

    yield start
    for n in started:
        n.server.should_exit = True
        n.thread.join(timeout=10)


async def status(tmp_path, url, **env) -> tuple[int, str]:
    """Run the script as a client would. The ssh_server fixture lives on this
    test's event loop, so the script runs as an asyncio subprocess, leaving the
    loop free to answer nervus's SSH connection."""
    environment = {"PATH": os.environ["PATH"], "HOME": str(tmp_path), "NERVUS_URL": url,
                   "NERVUS_TOKEN": TOKEN, **env}
    proc = await asyncio.create_subprocess_exec(
        "bash", str(TOOL), env=environment,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    out, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
    return proc.returncode, re.sub(r"\x1b\[[0-9;]*m", "", out.decode())


def line(out: str, mark: str, label: str) -> str:
    """The one line marked `mark` (ok, FAIL, warn) whose check is `label`."""
    found = [l for l in out.splitlines() if re.match(rf"\s*\[\s*{mark}\s*\]\s+{label}\b", l)]
    assert len(found) == 1, f"no single [{mark}] {label} line in:\n{out}"
    return found[0]


async def test_https_by_address_with_nervus_certificate_is_green(served, tmp_path):
    n = served()
    code, out = await status(tmp_path, f"https://127.0.0.1:{n.port}/mcp", NERVUS_CACERT=str(n.cert))
    assert code == 0, out
    assert "127.0.0.1" in line(out, "ok", "address")
    assert str(n.cert) in line(out, "ok", "TLS")
    line(out, "ok", "auth")
    assert "testhost" in line(out, "ok", "tools")
    assert "testhost reachable" in line(out, "ok", "fleet")
    assert "FAIL" not in out


async def test_https_trusting_only_the_root_of_nervuss_own_authority(served, tmp_path):
    """ADR-0021 F1: what a friend's machine does, NERVUS_CACERT naming the root
    tls-init made, and nothing else."""
    n = served(authority=True)
    code, out = await status(tmp_path, f"https://127.0.0.1:{n.port}/mcp", NERVUS_CACERT=str(n.cert))
    assert code == 0, out
    assert "own-root.crt" in line(out, "ok", "TLS")
    line(out, "ok", "fleet")


async def test_https_by_a_name_outside_dns(served, tmp_path):
    # `localhost` is in /etc/hosts, not in DNS: `dig +short localhost` prints nothing.
    n = served()
    code, out = await status(tmp_path, f"https://localhost:{n.port}/mcp", NERVUS_CACERT=str(n.cert))
    assert code == 0, out
    assert "localhost ->" in line(out, "ok", "name")
    line(out, "ok", "fleet")


@pytest.mark.skipif(not _ipv6_loopback(), reason="no IPv6 loopback")
async def test_https_by_an_ipv6_address(served, tmp_path):
    n = served(bind="::1")
    code, out = await status(tmp_path, f"https://[::1]:{n.port}/mcp", NERVUS_CACERT=str(n.cert))
    assert code == 0, out
    assert "::1" in line(out, "ok", "address")
    assert f"port {n.port}" in line(out, "ok", "TCP")
    line(out, "ok", "fleet")


async def test_https_without_nervus_certificate_stops_before_the_token(served, tmp_path):
    n = served()
    code, out = await status(tmp_path, f"https://127.0.0.1:{n.port}/mcp")
    assert code == 1, out
    assert "NERVUS_CACERT" in line(out, "FAIL", "TLS")
    assert "nervus's root" in line(out, "FAIL", "TLS")  # ADR-0021: the root, not tls.crt
    assert "tools/nervus-trust" in line(out, "FAIL", "TLS")
    assert "auth" not in out
    assert n.app.requests == 0


async def test_https_with_another_certificate_is_refused(served, tmp_path):
    n = served()
    other, _ = _cert(tmp_path, "other")
    code, out = await status(tmp_path, f"https://127.0.0.1:{n.port}/mcp", NERVUS_CACERT=str(other))
    assert code == 1, out
    assert "nervus's root" in line(out, "FAIL", "TLS")
    assert n.app.requests == 0


async def test_a_missing_certificate_file_is_named(served, tmp_path):
    n = served()
    missing = tmp_path / "nowhere.pem"
    code, out = await status(tmp_path, f"https://127.0.0.1:{n.port}/mcp", NERVUS_CACERT=str(missing))
    assert code == 1, out
    assert str(missing) in line(out, "FAIL", "TLS")
    assert n.app.requests == 0


async def test_plain_http_on_loopback_is_green_without_a_tls_line(served, tmp_path):
    n = served(tls=False)
    code, out = await status(tmp_path, f"http://127.0.0.1:{n.port}/mcp")
    assert code == 0, out
    assert "TLS" not in out
    line(out, "ok", "fleet")


async def test_a_certificate_given_for_plain_http_is_said_to_be_unused(served, tmp_path):
    n = served(tls=False)
    code, out = await status(tmp_path, f"http://127.0.0.1:{n.port}/mcp", NERVUS_CACERT="/x.pem")
    assert code == 0, out
    assert "NERVUS_CACERT" in line(out, "warn", "TLS")


async def test_a_refused_token_is_reported(served, tmp_path):
    n = served()
    code, out = await status(tmp_path, f"https://127.0.0.1:{n.port}/mcp",
                             NERVUS_CACERT=str(n.cert), NERVUS_TOKEN="wrong")
    assert code == 1, out
    assert "refused" in line(out, "FAIL", "auth")


async def test_a_name_that_does_not_resolve(tmp_path):
    # .invalid never resolves (RFC 6761).
    code, out = await status(tmp_path, "https://nervus-status-test.invalid:8000/mcp")
    assert code == 1, out
    assert "does not resolve" in line(out, "FAIL", "name")


async def test_a_url_that_is_not_http_is_refused(tmp_path):
    code, out = await status(tmp_path, "ftp://127.0.0.1:8000/mcp")
    assert code == 2, out
    assert "http://" in out and "https://" in out


def test_never_turns_certificate_checking_off():
    text = TOOL.read_text()
    for switch in (r"\s-k\b", r"--insecure\b", r"--proxy-insecure\b", r"NODE_TLS_REJECT_UNAUTHORIZED"):
        assert not re.search(switch, text), switch


async def test_the_token_is_never_in_a_command_line(served, tmp_path):
    """Any user on the machine can list another's command lines (`ps`), so the
    token goes to curl in a file only this user can read, never as an argument.
    A curl ahead of the real one on PATH records every argument it is given."""
    n = served()
    real = shutil.which("curl")
    shim, log = tmp_path / "shim", tmp_path / "curl-args.log"
    shim.mkdir()
    (shim / "curl").write_text(f'#!/bin/sh\nprintf "%s\\n" "$*" >> "{log}"\nexec "{real}" "$@"\n')
    (shim / "curl").chmod(0o755)
    private = tmp_path / "tmp"
    private.mkdir()
    code, out = await status(tmp_path, f"https://127.0.0.1:{n.port}/mcp", NERVUS_CACERT=str(n.cert),
                             PATH=f"{shim}:{os.environ['PATH']}", TMPDIR=str(private))
    assert code == 0, out
    line(out, "ok", "fleet")
    args = log.read_text()
    assert args.count("\n") >= 5, args  # the TLS check, initialize, initialized, hosts, exec
    assert TOKEN not in args
    assert list(private.iterdir()) == []  # its private files, the token's included, are gone
