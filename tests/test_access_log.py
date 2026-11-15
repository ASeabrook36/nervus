"""MCP's request log (procedure 037, step 12): uvicorn writes each request
line to the journal, so an enrollment code in a path would be there whole
for anyone who reads the journal before the machine reports. nervus's
web servers write `/enroll/<code>` in its place, and every other line as it
was. A real uvicorn server on loopback, built as nervus builds MCP's."""

import contextlib
import logging
import socket
import threading
import time
import urllib.error
import urllib.request

import uvicorn
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from nervus.__main__ import _web_server_config

CODE = "kq7Vt0lB2xY9-secret_code"


class Seen(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_the_request_log_never_writes_an_enrollment_code():
    async def answer(request):
        return PlainTextResponse("x")

    app = Starlette(routes=[Route("/enroll/{code}", answer, methods=["GET", "POST"]),
                            Route("/exports/{export_id}", answer)])
    port = _free_port()
    server = uvicorn.Server(_web_server_config(app, "127.0.0.1", port, None))
    seen = Seen()
    logging.getLogger("uvicorn.access").addHandler(seen)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        for _ in range(100):
            if server.started:
                break
            time.sleep(0.05)
        base = f"http://127.0.0.1:{port}"
        urllib.request.urlopen(f"{base}/enroll/{CODE}", timeout=5).read()
        urllib.request.urlopen(urllib.request.Request(f"{base}/enroll/{CODE}?again=1", b"report", method="POST"),
                               timeout=5).read()
        urllib.request.urlopen(f"{base}/exports/e123", timeout=5).read()
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        logging.getLogger("uvicorn.access").removeHandler(seen)
    assert len(seen.lines) == 3, seen.lines
    assert all(CODE not in line for line in seen.lines)
    assert '"GET /enroll/<code> HTTP/1.1" 200' in seen.lines[0]
    assert '"POST /enroll/<code> HTTP/1.1" 200' in seen.lines[1]
    assert '"GET /exports/e123 HTTP/1.1" 200' in seen.lines[2]  # every other line as it was


@contextlib.contextmanager
def _serving(app):
    """A real uvicorn server built as nervus builds MCP's, on a free loopback port: its base URL, and the
    request log's lines as they are written."""
    port = _free_port()
    server = uvicorn.Server(_web_server_config(app, "127.0.0.1", port, None))
    seen = Seen()
    logging.getLogger("uvicorn.access").addHandler(seen)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        for _ in range(100):
            if server.started:
                break
            time.sleep(0.05)
        yield f"http://127.0.0.1:{port}", seen.lines
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        logging.getLogger("uvicorn.access").removeHandler(seen)


def _logged(app, *paths):
    """The request log's lines for GETs of `paths`."""
    with _serving(app) as (base, lines):
        for path in paths:
            try:
                urllib.request.urlopen(f"{base}{path}", timeout=5).read()
            except urllib.error.HTTPError:
                pass
    return lines


def test_a_code_followed_by_a_slash_or_more_is_hidden_too():
    """Procedure 056: the mask took only a path that ended at the code, so `/enroll/<code>/`, which Starlette
    redirects to the path without the slash, wrote the code whole in the journal, as did anything further
    after it. Whatever follows the code is dropped with it now, as a query always was."""
    async def answer(request):
        return PlainTextResponse("x")

    app = Starlette(routes=[Route("/enroll/{code}", answer, methods=["GET", "POST"])])
    lines = _logged(app, f"/enroll/{CODE}/", f"/enroll/{CODE}/more")
    assert len(lines) == 3, lines  # the slash redirected, then followed; the further path not found
    assert all(CODE not in line for line in lines), lines
    assert all('"GET /enroll/<code> HTTP/1.1"' in line for line in lines), lines


def test_an_address_or_scheme_a_header_claims_is_not_believed():
    """Procedure 056. uvicorn believed X-Forwarded-For and X-Forwarded-Proto from loopback, so a local process
    could put an address of its choosing in the UI's audit records, as the address an enrollment report came
    from (where a code made without one enrolls the machine) and in this log, and pass plain HTTP as HTTPS.
    nervus serves TLS itself, behind no proxy (ADR-0006), so no header names the address or the scheme."""
    async def answer(request):
        return PlainTextResponse(f"{request.client.host} {request.url.scheme}")

    app = Starlette(routes=[Route("/who", answer)])
    with _serving(app) as (base, lines):
        claimed = urllib.request.Request(f"{base}/who", headers={"X-Forwarded-For": "203.0.113.9",
                                                                   "X-Forwarded-Proto": "https"})
        said = urllib.request.urlopen(claimed, timeout=5).read().decode()
    assert said == "127.0.0.1 http"
    assert lines and lines[0].startswith("127.0.0.1:") and "203.0.113.9" not in lines[0], lines
