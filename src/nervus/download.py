"""The download route (ADR-0016 decisions A, B, G and H): GET /exports/<id> on
nervus's MCP port, beside /mcp.

A client fetches its export with its own token in the Authorization header,
checked exactly as an MCP call is: an unknown token, and a switched-off one,
get the same refusal after the same 50 ms (ADR-0003 questions B and D), and a
switched-off client's attempt is audited. The id names the export and grants
nothing alone: only the token that made it finds it, and any other gets 404,
audited (decision B).

The bytes come from the file the export store opened, not through a link and
at its recorded size (exports.open_ready), so nothing can swap the file
between that check and the read. Byte ranges are served from it too: one
range, `bytes=N-`, `bytes=N-M` or `bytes=-N`, which is all `curl -C -` and
other resuming clients ask for. Anything else is answered with the whole file,
which HTTP allows. A finished export never changes, so its SHA-256 is its ETag,
and `If-Range` with any other value gets the whole file rather than a piece of
something else.

Each request is audited (decision H): an intent with the export and the range
asked for, and a result with the bytes sent and `all_sent`, whether nervus
handed every byte asked for to the connection. That is all a server can know:
bytes in the operating system's buffers when a client is cut off count as
sent, so `all_sent: true` does not prove the client has them. The client's own
SHA-256 check does. A resume is another request, with its own range.
"""

from __future__ import annotations

import re
import time
import urllib.parse
from collections.abc import AsyncIterator
from pathlib import Path
from typing import BinaryIO

import anyio
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response, StreamingResponse

from nervus.audit import AuditLog
from nervus.auth import Tokens, _hold, attribution, resolve_token
from nervus.exports import ExportRefused, ExportStore
from nervus import switches

TOOL = "download"
CHUNK = 1024 * 1024
_RANGE = re.compile(r"bytes=(\d*)-(\d*)")


def parse_range(header: str | None, size: int) -> tuple[int, int] | None | str:
    """The one byte range asked for, as (first, last) inclusive; None for the
    whole file; or "unsatisfiable" for a range that starts past the end."""
    if not header:
        return None
    match = _RANGE.fullmatch(header.strip())
    if match is None:
        return None  # several ranges, or not bytes: the whole file
    first, last = match.groups()
    if not first and not last:
        return None
    if not first:  # the last N bytes
        n = int(last)
        if n == 0:
            return "unsatisfiable"
        return max(0, size - n), size - 1
    start = int(first)
    end = size - 1 if not last else min(int(last), size - 1)
    if start >= size or (last and int(last) < start):
        return "unsatisfiable"
    return start, end


def _disposition(filename: str) -> str:
    plain = filename.encode("ascii", "replace").decode().replace('"', "'").replace("?", "_")
    return f"attachment; filename=\"{plain}\"; filename*=UTF-8''{urllib.parse.quote(filename)}"


def download_endpoint(store: ExportStore, tokens: Tokens, audit: AuditLog, switches_path: Path | None):
    unauthorized = PlainTextResponse("unauthorized: invalid or missing bearer token\n", status_code=401,
                                     headers={"WWW-Authenticate": "Bearer"})
    not_found = PlainTextResponse("no such export\n", status_code=404)

    async def download(request: Request) -> Response:
        began = time.monotonic()
        token = resolve_token(request.headers, tokens)
        if token is None:
            await _hold(began)
            return unauthorized
        export_id = request.path_params["export_id"]
        asked = request.headers.get("range")
        if switches_path is not None:
            reason = switches.refusal(switches_path, token.id)
            if reason is not None:
                audit.record_refusal(TOOL, {**attribution(token), "export_id": export_id,
                                            "reason": f"switches: {reason}"})
                await _hold(began)
                return unauthorized
        try:
            opened = store.open_ready(token.id, export_id)
        except ExportRefused as exc:
            audit.record_refusal(TOOL, {**attribution(token), "export_id": export_id,
                                        "reason": f"{exc.code}: {exc.message}"})
            return not_found
        if opened is None:
            audit.record_refusal(TOOL, {**attribution(token), "export_id": export_id,
                                        "reason": "no ready export with this id for this token"})
            return not_found
        export, f = opened

        etag = f'"{export.sha256}"'
        headers = {
            "Accept-Ranges": "bytes",
            "ETag": etag,
            "X-Nervus-SHA256": export.sha256,
            "Content-Disposition": _disposition(export.filename),
            "Cache-Control": "no-store",
        }
        if_range = request.headers.get("if-range")
        wanted = parse_range(asked, export.size) if if_range in (None, etag) else None
        if wanted == "unsatisfiable":
            f.close()
            audit.record_refusal(TOOL, {**attribution(token), "export_id": export_id, "range": asked,
                                        "reason": "range not satisfiable"})
            return PlainTextResponse("range not satisfiable\n", status_code=416,
                                     headers={**headers, "Content-Range": f"bytes */{export.size}"})
        first, last = wanted if wanted is not None else (0, export.size - 1)
        length = last - first + 1 if export.size else 0
        headers["Content-Length"] = str(length)
        status = 200
        if wanted is not None:
            status = 206
            headers["Content-Range"] = f"bytes {first}-{last}/{export.size}"

        run_id = audit.record_intent(TOOL, {**attribution(token), "export_id": export.id, "range": asked,
                                            "first": first, "length": length})
        if request.method == "HEAD":
            f.close()
            audit.record_result(run_id, TOOL, {"bytes_sent": 0, "all_sent": True, "head": True})
            return Response(status_code=status, headers=headers, media_type="application/octet-stream")
        return StreamingResponse(_send(f, first, length, run_id, audit), status_code=status,
                                 headers=headers, media_type="application/octet-stream")

    return download


async def _send(f: BinaryIO, first: int, length: int, run_id: str, audit: AuditLog) -> AsyncIterator[bytes]:
    sent = 0
    try:
        f.seek(first)
        while sent < length:
            chunk = await anyio.to_thread.run_sync(f.read, min(CHUNK, length - sent))
            if not chunk:
                break
            yield chunk
            sent += len(chunk)
    finally:
        f.close()
        audit.record_result(run_id, TOOL, {"bytes_sent": sent, "all_sent": sent == length})
