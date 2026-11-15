"""tools/check-up (ADR-0029 question 7): nervus counts as up only when its MCP endpoint refuses a
call without a token in nervus's own words, and its web UI answers, both over HTTPS checked
against nervus's own root. Served here by stand-ins over a certificate nervus's own tls-init made,
so that what is checked is what an installation has."""

import http.server
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

TOOL = Path(__file__).resolve().parent.parent / "tools" / "check-up"
NERVUS = Path(sys.executable).parent / "nervus"

REFUSAL = ('event: message\ndata: {"jsonrpc":"2.0","id":1,"error":{"code":-32001,'
           '"message":"unauthorized: invalid or missing bearer token"}}\n\n')


def _tls(folder: Path) -> Path:
    """nervus's TLS, as the installer makes it: its authority, and a certificate for this machine."""
    (folder / "secrets").mkdir(parents=True)
    done = subprocess.run([str(NERVUS), "tls-init", "--bind-host", "0.0.0.0", "--name", "nervus.test"],
                          cwd=folder, capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stdout + done.stderr
    return folder / "secrets"


@pytest.fixture(scope="module")
def secrets(tmp_path_factory):
    return _tls(tmp_path_factory.mktemp("nervus"))


class _Answers(http.server.BaseHTTPRequestHandler):
    mcp = (200, "text/event-stream", REFUSAL)
    ui = (200, "text/html", "<!doctype html><title>nervus</title>Sign in")

    def _send(self, answer):
        status, kind, body = answer
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.end_headers()
        self.wfile.write(body.encode())

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self._send(self.mcp if self.path == "/mcp" else (404, "text/plain", "no"))

    def do_GET(self):
        self._send(self.ui if self.path == "/" else (404, "text/plain", "no"))

    def log_message(self, *args):
        pass


def _serve(secrets: Path, mcp=None, ui=None, port=0) -> int:
    """A server on 127.0.0.1 with nervus's certificate, answering as told; its port."""
    handler = type("Answers", (_Answers,), {k: v for k, v in (("mcp", mcp), ("ui", ui)) if v is not None})
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(secrets / "tls.crt", secrets / "tls.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server.server_address[1]


def _closed_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _serve_later(secrets: Path, seconds: float, **answers) -> int:
    """The port a server will listen on once `seconds` have passed, as nervus does as it starts."""
    port = _closed_port()
    threading.Timer(seconds, _serve, (secrets,), {**answers, "port": port}).start()
    return port


def _check(root: Path, mcp_port: int, ui_port: int, *python_flags: str, wait=0) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-I", *python_flags, str(TOOL), "--wait", str(wait), str(root), str(mcp_port),
                           str(ui_port)], capture_output=True, text=True, timeout=60)


def test_nervus_answering_as_it_does_is_up(secrets):
    port = _serve(secrets)
    done = _check(secrets / "tls-root.crt", port, port)
    assert done.returncode == 0, done.stderr
    assert "nervus answers" in done.stdout and done.stderr == ""


def test_a_refusal_sent_as_an_http_error_is_nervus_answering_too(secrets):
    port = _serve(secrets, mcp=(401, "application/json", REFUSAL.split("data: ")[1]))
    assert _check(secrets / "tls-root.crt", port, port).returncode == 0


@pytest.mark.parametrize("mcp, says", [
    ((200, "application/json", '{"jsonrpc":"2.0","id":1,"result":{"serverInfo":{"name":"other"}}}'),
     "not with nervus's refusal"),
    ((503, "text/plain", "starting"), "not with nervus's refusal"),
    ((200, "application/json", '{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"unauthorized"}}'),
     "not with nervus's refusal"),
], ids=["something-else-answers", "not-ready", "another-error"])
def test_an_mcp_endpoint_that_does_not_refuse_as_nervus_does_is_not_up(secrets, mcp, says):
    port = _serve(secrets, mcp=mcp)
    done = _check(secrets / "tls-root.crt", port, port)
    assert done.returncode == 1 and says in done.stderr, done.stderr


def test_nothing_on_the_mcp_port_is_not_up(secrets):
    port = _serve(secrets)
    done = _check(secrets / "tls-root.crt", _closed_port(), port)
    assert done.returncode == 1 and "the MCP endpoint" in done.stderr and "did not answer" in done.stderr


@pytest.mark.parametrize("ui_status", [500, 404])
def test_a_web_ui_that_does_not_answer_with_its_page_is_not_up(secrets, ui_status):
    port = _serve(secrets, ui=(ui_status, "text/plain", "broken"))
    done = _check(secrets / "tls-root.crt", port, port)
    assert done.returncode == 1 and f"the web UI answered {ui_status}" in done.stderr, done.stderr


def test_nothing_on_the_web_ui_port_is_not_up(secrets):
    port = _serve(secrets)
    done = _check(secrets / "tls-root.crt", port, _closed_port())
    assert done.returncode == 1 and "the web UI" in done.stderr and "did not answer" in done.stderr


def test_a_nervus_that_begins_to_listen_a_few_seconds_after_it_starts_is_up(secrets):
    # nervus listened 1.1 seconds after starting on the trial's machine. Asked once, at 5 seconds, a
    # machine five times slower would have had a good release sent back (procedure 051, finding 3).
    port = _serve_later(secrets, 2.5)
    started = time.monotonic()
    done = _check(secrets / "tls-root.crt", port, port, wait=30)
    assert done.returncode == 0, done.stderr
    assert time.monotonic() - started >= 2.5


def test_each_of_its_two_ports_is_waited_for(secrets):
    up = _serve(secrets)
    assert _check(secrets / "tls-root.crt", up, _serve_later(secrets, 1.5), wait=30).returncode == 0
    assert _check(secrets / "tls-root.crt", _serve_later(secrets, 1.5), up, wait=30).returncode == 0


def test_a_release_that_never_listens_is_not_up_once_the_wait_is_over(secrets):
    started = time.monotonic()
    done = _check(secrets / "tls-root.crt", _closed_port(), _closed_port(), wait=2)
    assert done.returncode == 1 and "the MCP endpoint" in done.stderr and "did not answer" in done.stderr
    assert 2 <= time.monotonic() - started < 15


@pytest.mark.parametrize("answers", [
    {"mcp": (200, "application/json", '{"jsonrpc":"2.0","id":1,"result":{}}')},
    {"mcp": (503, "text/plain", "starting")},
    {"ui": (500, "text/plain", "broken")},
], ids=["not-nervus", "not-ready", "web-ui-broken"])
def test_only_nothing_listening_is_waited_for_any_answer_counts_at_once(secrets, answers):
    port = _serve(secrets, **answers)
    started = time.monotonic()
    assert _check(secrets / "tls-root.crt", port, port, wait=40).returncode == 1
    assert time.monotonic() - started < 20


def test_another_certificate_is_not_waited_for(secrets, tmp_path):
    other = _tls(tmp_path / "other")
    port = _serve(secrets)
    started = time.monotonic()
    assert _check(other / "tls-root.crt", port, port, wait=40).returncode == 1
    assert time.monotonic() - started < 20


def test_unless_told_otherwise_it_waits_a_minute():
    done = subprocess.run([sys.executable, "-I", str(TOOL), "--help"], capture_output=True, text=True, timeout=30)
    assert done.returncode == 0 and "(default 60)" in done.stdout


def test_only_nervus_can_answer_its_certificate_is_checked_against_its_own_root(secrets, tmp_path):
    # Another nervus's root, as if something else held this port with a certificate of its own.
    other = _tls(tmp_path / "other")
    port = _serve(secrets)
    done = _check(other / "tls-root.crt", port, port)
    assert done.returncode == 1 and "certificate" in done.stderr.lower(), done.stderr


def test_a_root_that_cannot_be_read_says_so(tmp_path):
    done = _check(tmp_path / "missing.crt", _closed_port(), _closed_port())
    assert done.returncode == 1 and "cannot read nervus's root certificate" in done.stderr, done.stderr


def test_it_needs_only_the_standard_library(secrets):
    # The machine's own python3 runs it, whichever release is installed.
    port = _serve(secrets)
    done = _check(secrets / "tls-root.crt", port, port, "-S")
    assert done.returncode == 0, done.stderr


def test_a_real_nervus_asked_the_moment_it_starts_is_up(tmp_path):
    # As install.sh asks, and before it listens: what it is to wait for.
    from test_main import _Nervus

    secrets = _tls(tmp_path / "machine")
    nervus = _Nervus(tmp_path, "--tls-cert", str(secrets / "tls.crt"), "--tls-key", str(secrets / "tls.key"))
    try:
        done = _check(secrets / "tls-root.crt", nervus.port, nervus.ui_port, wait=30)
        assert done.returncode == 0, done.stderr + nervus.text()
    finally:
        nervus.stop()


def test_a_real_nervus_starting_on_its_own_tls_is_up(tmp_path):
    # Not a stand-in: nervus itself, run as `python -m nervus` is, with the TLS tls-init made.
    from test_main import _Nervus

    secrets = _tls(tmp_path / "machine")
    nervus = _Nervus(tmp_path, "--tls-cert", str(secrets / "tls.crt"), "--tls-key", str(secrets / "tls.key"))
    try:
        nervus.wait_listening()
        done = _check(secrets / "tls-root.crt", nervus.port, nervus.ui_port)
        assert done.returncode == 0, done.stderr + nervus.text()
    finally:
        nervus.stop()


def test_a_pipe_at_the_root_certificate_is_said_and_not_waited_on(tmp_path):
    """The root sits in a folder nervus's own account owns. Given its name, the TLS library opened
    it itself: a pipe put there held this, and the upgrade that was judging nervus up, for ever."""
    root = tmp_path / "tls-root.crt"
    os.mkfifo(root)
    done = subprocess.run([sys.executable, "-I", str(TOOL), "--wait", "0", str(root), "1", "2"],
                          capture_output=True, text=True, timeout=10)
    assert done.returncode == 1, done.stdout + done.stderr
    assert "cannot read nervus's root certificate" in done.stderr and "is a pipe, not a file" in done.stderr
