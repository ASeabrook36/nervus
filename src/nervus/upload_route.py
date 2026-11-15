"""The upload route (ADR-0020 decisions A, F, G and H): PUT /uploads and
GET /uploads/<request key> on nervus's MCP port, beside /mcp.

A client sends a file with one command from its own shell: its token in the
Authorization header, checked exactly as an MCP call is (an unknown token and
a switched-off one get the same refusal after the same 50 ms, ADR-0003
questions B and D), and the destination, the file's SHA-256 and a request key
as URL parameters. Its declared size is the request's Content-Length, and
space for it is reserved before the body is read (decision F).

Which destinations a token may send to is decided before anything is
recorded as intended: a host in its allowlist and the inventory, as `put`; or
a VM, where the allowlist names the Proxmox host, after which Proxmox's
permissions decide (decision H). A refusal is audited, as every refusal is.

The body is hashed and counted as it arrives and is delivered only if it is
the file declared (decision B). Delivery runs apart from the request
(uploader.py), which waits up to `wait` seconds and answers with the upload's
state: 200 delivered, 202 still receiving or delivering, 422 failed. A refusal
before anything was received answers 4xx or 507 with the reason. Every answer
is JSON with the reason in words, so `curl --fail-with-body` shows the client
why. GET /uploads/<key> asks again later. The same key with the same file
returns the same upload without reading the body again.

Each request is an audit intent and a result (decision H). No token, and no
path on nervus, is in either.

GET /upload-pull is the one route without a client token: a VM fetching a
file nervus is delivering to it, with the one-time secret nervus gave it
through the guest agent (decision E). The secret is spent on first use.
"""

from __future__ import annotations

import re
import time

import anyio
from starlette.requests import ClientDisconnect, Request
from starlette.responses import JSONResponse, PlainTextResponse, Response, StreamingResponse

from nervus import certs, switches
from nervus.audit import AuditLog
from nervus.auth import Token, Tokens, _hold, attribution, resolve_token
from nervus.config import Settings, hypervisor_host
from nervus.exporter import DEFAULT_WAIT_SECONDS
from nervus.uploader import TOOL, Uploader, upload_fields
from nervus.uploads import DELIVERED, FAILED, Upload, UploadRefused

# The header a VM sends its one-time secret in (upload_targets.PULL_SCRIPT).
PULL_SECRET_HEADER = "x-nervus-upload-secret"
PULL_CHUNK = 1024 * 1024
# How often, in bytes, the record of how much has arrived is brought up to date.
PROGRESS_BYTES = 4 * 1024 * 1024
PATH_CHARACTERS = 4096
_VMID = re.compile(r"[1-9][0-9]{0,8}")
_MODE = re.compile(r"[0-7]{3,4}")
_FLAGS = {None: False, "": False, "0": False, "false": False, "1": True, "true": True}

STATUS = {
    "bad_destination": 400, "bad_wait": 400, "bad_request_key": 400, "bad_sha256": 400, "bad_size": 400,
    "not_allowed": 403, "no_proxmox": 403, "no_such_upload": 404, "key_reused": 409, "length_required": 411,
    "too_large": 413, "too_long": 413, "quota": 507, "disk_floor": 507,
}


def parse_destination(query) -> dict:
    """Where the client wants the file, from the URL parameters. Raises
    UploadRefused("bad_destination") for anything malformed. The path itself is
    the target's business (ADR-0016 G1): nervus checks only that it is
    absolute, names a file, and holds no NUL."""
    host, vmid, path = query.get("host"), query.get("vmid"), query.get("path")
    if (host is None) == (vmid is None):
        raise UploadRefused("bad_destination", "name one destination: `host`, or `vmid` for a VM")
    if vmid is not None and not _VMID.fullmatch(vmid):
        raise UploadRefused("bad_destination", f"`vmid` is a VM's number: {vmid!r}")
    if (not path or not path.startswith("/") or path.endswith("/") or "\x00" in path
            or len(path) > PATH_CHARACTERS):
        raise UploadRefused("bad_destination", "`path` is the absolute path of the file to write")
    flags = {}
    for name in ("replace", "root"):
        value = query.get(name)
        if value not in _FLAGS:
            raise UploadRefused("bad_destination", f"`{name}` is 1 or 0: {value!r}")
        flags[name] = _FLAGS[value]
    if vmid is not None and flags["root"]:
        raise UploadRefused("bad_destination", "`root` is for hosts; in a VM the guest agent writes as root already")
    mode = query.get("mode")
    if mode is not None and not _MODE.fullmatch(mode):
        raise UploadRefused("bad_destination", f"`mode` is octal permissions, such as 0644 or 0755: {mode!r}")
    where = {"kind": "host", "host": host} if host is not None else {"kind": "vm", "vmid": int(vmid)}
    return {**where, "path": path, **flags, "mode": mode}


def parse_wait(query) -> float:
    raw = query.get("wait")
    if raw is None:
        return DEFAULT_WAIT_SECONDS
    try:
        wait = float(raw)
    except ValueError:
        wait = float("nan")
    if wait != wait or wait in (float("inf"), float("-inf")):
        raise UploadRefused("bad_wait", f"`wait` is a number of seconds: {raw!r}")
    return wait


def authorize(token: Token, destination: dict, settings: Settings, hosts: dict | None = None) -> None:
    """Refuse a destination this token may not send to (decision H). `hosts`
    is the inventory now, enrolled machines included (ADR-0024); without it,
    hosts.yaml's."""
    if destination["kind"] == "host":
        host = destination["host"]
        if host not in token.hosts or host not in (settings.hosts if hosts is None else hosts):
            raise UploadRefused("not_allowed", f"this token may not reach host {host!r}")
        return
    proxmox = hypervisor_host(settings.hosts)
    if proxmox is None:
        raise UploadRefused("no_proxmox", "no inventory entry is marked `hypervisor: proxmox`, so this nervus "
                                          "has no Proxmox host")
    if proxmox not in token.hosts:
        raise UploadRefused("not_allowed", "this token may not reach the Proxmox host, so it may not reach VMs")


def declared_length(request: Request) -> int:
    raw = request.headers.get("content-length")
    if "transfer-encoding" in request.headers or raw is None or not raw.isdigit():
        raise UploadRefused("length_required", "send the file with its length (curl -T does), not in chunks")
    return int(raw)


def answer(upload: Upload, run_id: str) -> JSONResponse:
    """An upload's state as the client sees it."""
    body = {"run_id": run_id, "upload_id": upload.id, "request_key": upload.request_key, "state": upload.state,
            "destination": upload.destination, "size": upload.size, "sha256": upload.sha256,
            "bytes_received": upload.bytes_received, "bytes_delivered": upload.bytes_delivered,
            "route": upload.route}
    if upload.failure_code is not None:
        body["failure"] = {"code": upload.failure_code, "message": upload.failure_message}
    status = 200 if upload.state == DELIVERED else 422 if upload.state == FAILED else 202
    return JSONResponse(body, status_code=status)


def refused(exc: UploadRefused, run_id: str) -> JSONResponse:
    return JSONResponse({"run_id": run_id, "state": "refused", "failure": {"code": exc.code, "message": exc.message}},
                        status_code=STATUS.get(exc.code, 400))


def upload_endpoints(uploader: Uploader, settings: Settings, tokens: Tokens, audit: AuditLog, hosts_now=None):
    """The PUT and GET handlers, for server.py to mount."""
    store = uploader.store
    unauthorized = PlainTextResponse("unauthorized: invalid or missing bearer token\n", status_code=401,
                                     headers={"WWW-Authenticate": "Bearer"})

    async def caller(request: Request, began: float, fields: dict) -> Token | Response:
        """The request's token, or the 401 to answer with."""
        token = resolve_token(request.headers, tokens)
        if token is None:
            await _hold(began)
            return unauthorized
        if settings.switches_path is not None:
            reason = switches.refusal(settings.switches_path, token.id)
            if reason is not None:
                audit.record_refusal(TOOL, {**attribution(token), **fields, "reason": f"switches: {reason}"})
                await _hold(began)
                return unauthorized
        return token

    def refuse(token: Token, fields: dict, exc: UploadRefused) -> JSONResponse:
        run_id = audit.record_refusal(TOOL, {**attribution(token), **fields, "reason": f"{exc.code}: {exc.message}"})
        return refused(exc, run_id)

    async def send(request: Request) -> Response:
        began = time.monotonic()
        query = request.query_params
        key, sha256 = query.get("key"), query.get("sha256")
        token = await caller(request, began, {"request_key": key})
        if not isinstance(token, Token):
            return token
        # `host` or `vmid` at the top, where every tool's records have them.
        fields = {"request_key": key, "destination": dict(query),
                  **{k: query[k] for k in ("host", "vmid") if k in query}}
        try:
            destination = parse_destination(query)
            fields["destination"] = destination
            wait = parse_wait(query)
            authorize(token, destination, settings, hosts_now() if hosts_now else None)
            size = declared_length(request)
        except UploadRefused as exc:
            return refuse(token, fields, exc)

        run_id = audit.record_intent(TOOL, {**attribution(token), **fields, "size": size, "sha256": sha256})
        try:
            store.sweep()
            upload, created = store.begin(token.id, key, destination, size, sha256)
        except UploadRefused as exc:
            audit.record_result(run_id, TOOL, {"failure_code": exc.code, "failure_message": exc.message})
            return refused(exc, run_id)
        if not created:
            # A retry: the body is the file already sent, and is not read again.
            await uploader.wait(upload.id, wait)
            upload = store.get(token.id, upload.id) or upload
            audit.record_result(run_id, TOOL, {**upload_fields(upload), "repeat": True})
            return answer(upload, run_id)

        upload = await receive(request, upload, run_id)
        if upload.state != FAILED:
            # The delivery runs as a task of its own and carries this call (ADR-0025).
            certs.acting_for(token.id, run_id)
            uploader.start(upload, run_id)
            await uploader.wait(upload.id, wait)
            upload = store.get(token.id, upload.id) or upload
        return answer(upload, run_id)

    async def receive(request: Request, upload: Upload, run_id: str) -> Upload:
        """Read the body into the store. A body that fails, or ends badly,
        gets its result recorded here; one that is whole gets it when its
        delivery ends."""
        receiver = store.receiver(upload)
        reported = 0
        try:
            async for chunk in request.stream():
                receiver.write(chunk)
                if receiver.written - reported >= PROGRESS_BYTES:
                    store.progress(upload.id, receiver.written)
                    reported = receiver.written
        except UploadRefused as exc:
            upload = store.fail(upload, exc.code, exc.message, receiver)
        except ClientDisconnect:
            upload = store.fail(upload, "disconnected",
                                f"the connection closed after {receiver.written} of {upload.size} bytes; send it again "
                                f"with a new request key", receiver)
        except BaseException:
            store.fail(upload, "interrupted", "nervus stopped while the body was arriving", receiver)
            raise
        else:
            # Sealing flushes the whole file to disk: not on the event loop.
            upload = await anyio.to_thread.run_sync(store.received, upload, receiver)
        if upload.state == FAILED:
            audit.record_result(run_id, TOOL, upload_fields(upload))
        return upload

    async def status(request: Request) -> Response:
        began = time.monotonic()
        key = request.path_params["request_key"]
        token = await caller(request, began, {"request_key": key})
        if not isinstance(token, Token):
            return token
        fields = {"request_key": key, "action": "status"}
        try:
            wait = parse_wait(request.query_params)
        except UploadRefused as exc:
            return refuse(token, fields, exc)
        upload = store.by_key(token.id, key)
        if upload is None:
            return refuse(token, fields, UploadRefused("no_such_upload", "this token has no upload with this key"))
        run_id = audit.record_intent(TOOL, {**attribution(token), **fields, "upload_id": upload.id})
        await uploader.wait(upload.id, wait)
        upload = store.get(token.id, upload.id) or upload
        audit.record_result(run_id, TOOL, upload_fields(upload))
        return answer(upload, run_id)

    async def pull(request: Request) -> Response:
        """A VM fetching a file being delivered to it (decision E). No client
        token: the one-time secret nervus gave that VM, in a header, is the
        whole of the permission, for one fetch of one upload."""
        began = time.monotonic()
        upload = store.claim_pull_secret(request.headers.get(PULL_SECRET_HEADER, ""))
        if upload is None:
            audit.record_refusal(TOOL, {"action": "pull", "reason": "no unused, unexpired secret for an upload "
                                                                    "being delivered"})
            await _hold(began)
            return PlainTextResponse("no such upload\n", status_code=404)
        try:
            staged = store.open_staged(upload)
        except UploadRefused as exc:
            audit.record_refusal(TOOL, {"token_id": upload.token_id, "upload_id": upload.id, "action": "pull",
                                        "reason": f"{exc.code}: {exc.message}"})
            return PlainTextResponse("no such upload\n", status_code=404)
        run_id = audit.record_intent(TOOL, {"token_id": upload.token_id, "upload_id": upload.id, "action": "pull",
                                            "destination": upload.destination, "size": upload.size})
        return StreamingResponse(_send(staged, upload.size, run_id), media_type="application/octet-stream",
                                 headers={"Content-Length": str(upload.size), "Cache-Control": "no-store"})

    async def _send(staged, size: int, run_id: str):
        sent = 0
        try:
            while chunk := await anyio.to_thread.run_sync(staged.read, PULL_CHUNK):
                yield chunk
                sent += len(chunk)
        finally:
            staged.close()
            audit.record_result(run_id, TOOL, {"action": "pull", "bytes_sent": sent, "all_sent": sent == size})

    return send, status, pull
