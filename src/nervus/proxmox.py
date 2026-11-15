"""The Proxmox API client behind the `proxmox` tool (ADR-0009 decision 2).

One call takes any API request -- method, path, parameters -- and sends it
with nervus's scoped API token. The boundary is Proxmox's own permission
system, not a list of operations here: that is ADR-0001 s5 (no command
filtering) applied to a new target. So this module does only what has to be
done on nervus's side:

- trust exactly one certificate authority, Proxmox's own "PVE Cluster
  Manager CA", and nothing else -- not the system trust store;
- keep a request inside the API: the path is checked and encoded here, so a
  caller cannot reach anything on port 8006 outside /api2/json;
- keep the token secret out of every error message and repr;
- refuse, rather than truncate, a response too large to return. Truncated
  JSON is not JSON, and truncated output is not evidence (rule 3).

It uses the standard library's HTTPS client, run in a worker thread, so
nervus gains no new dependency. mcp's own HTTP stack is not httpx, and httpx
is only a test dependency here.
"""

from __future__ import annotations

import http.client
import json
import re
import ssl
import urllib.parse
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Any

import anyio
import yaml

from nervus import plainfile
from nervus.config import ConfigError, require_private_file

API_PREFIX = "/api2/json"
METHODS = ("GET", "POST", "PUT", "DELETE")
DEFAULT_PORT = 8006
DEFAULT_MAX_RESPONSE_BYTES = 256 * 1024

# Proxmox paths carry user ids (nervus@pve), token ids (nervus@pve!name) and
# task ids (UPID:<node>:...:root@pam:), so ':', '@' and '!' stay literal.
_SEGMENT_SAFE = ":@!-._~"
_TOKEN_ID = re.compile(r"[^@!\s]+@[^@!\s]+![A-Za-z][A-Za-z0-9._-]*")
_TEXT_LIMIT = 4096


class ProxmoxError(Exception):
    """A request was refused before it was sent, or the API could not be
    reached safely. Never carries the token secret."""


@dataclass(frozen=True)
class ProxmoxConfig:
    host: str
    port: int
    token_id: str
    ca_file: Path
    secret: str = field(repr=False)


@dataclass(frozen=True)
class ProxmoxResponse:
    """What the API answered. An HTTP error is a response, not an exception:
    a refusal from Proxmox's permission system is the boundary working, and
    the caller needs its reason ("Permission check failed (/vms/<vmid>, ...)")."""

    status: int
    reason: str
    data: Any
    errors: Any
    body_bytes: int
    text: str | None = None


def load_config(path: Path) -> ProxmoxConfig:
    """Load nervus's Proxmox settings: API address, token id, secret, CA.

    The file holds the scoped token's secret, so it must be 0600 like the
    token file. `ca_file` may be relative, meaning relative to this file.
    """
    require_private_file(path)
    try:
        raw = yaml.safe_load(plainfile.read_text(path))
    except OSError as exc:
        raise ConfigError(f"cannot read the proxmox file: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"proxmox file is not valid YAML: {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"proxmox file must be a mapping: {path}")
    missing = [f for f in ("url", "token_id", "secret", "ca_file") if not raw.get(f)]
    if missing:
        raise ConfigError(f"proxmox file missing fields {missing}: {path}")

    url = urllib.parse.urlsplit(str(raw["url"]))
    if url.scheme != "https" or not url.hostname:
        raise ConfigError(f"proxmox url must be https://host[:port]: {path}")
    if url.path not in ("", "/") or url.query or url.fragment or url.username:
        raise ConfigError(f"proxmox url must be only https://host[:port]: {path}")

    token_id = str(raw["token_id"])
    if not _TOKEN_ID.fullmatch(token_id):
        raise ConfigError(f"proxmox token_id must look like user@realm!name: {path}")

    ca_file = Path(raw["ca_file"])
    if not ca_file.is_absolute():
        ca_file = path.parent / ca_file
    if not ca_file.is_file():
        raise ConfigError(f"proxmox ca_file not found: {ca_file}")

    return ProxmoxConfig(
        host=url.hostname,
        port=url.port or DEFAULT_PORT,
        token_id=token_id,
        ca_file=ca_file,
        secret=str(raw["secret"]),
    )


def make_ssl_context(ca_file: Path) -> ssl.SSLContext:
    """A TLS context that trusts `ca_file` and nothing else.

    PROTOCOL_TLS_CLIENT turns on certificate and hostname verification;
    not calling load_default_certs() is what keeps the system trust store
    out. The CA is pinned rather than the node certificate because Proxmox
    renews the node certificate on its own (2028), while the CA runs to 2036.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        # Read by nervus and handed over: given the name, the TLS library opens it itself.
        ctx.load_verify_locations(cadata=plainfile.read_bytes(ca_file).decode("ascii", errors="replace"))
    except (OSError, ssl.SSLError, ValueError) as exc:  # ValueError: an empty file
        raise ConfigError(f"proxmox ca_file is not a usable certificate: {ca_file}: {exc}") from exc
    return ctx


def api_path(path: str) -> str:
    """Turn a caller's API path ("/nodes/<node>/qemu") into a request target.

    Refuses anything that could step outside /api2/json or smuggle a query:
    dot segments, empty segments, '?', '#', backslashes, control characters.
    Each segment is percent-encoded, so what reaches Proxmox is exactly the
    path that was checked.
    """
    if not path.startswith("/"):
        raise ProxmoxError(f"path must start with '/': {path!r}")
    if any(c in path for c in "?#\\") or any(ord(c) < 0x20 or ord(c) == 0x7F for c in path):
        raise ProxmoxError(f"path may not contain '?', '#', '\\' or control characters: {path!r}")
    trimmed = path[1:].removesuffix("/")
    segments = trimmed.split("/") if trimmed else []
    for seg in segments:
        if seg in ("", ".", ".."):
            raise ProxmoxError(f"path may not contain empty, '.' or '..' segments: {path!r}")
    return API_PREFIX + "/" + "/".join(urllib.parse.quote(s, safe=_SEGMENT_SAFE) for s in segments)


def encode_params(params: dict[str, Any] | None) -> str:
    """Form-encode parameters the way Proxmox expects: booleans as 1/0,
    numbers and strings as text. A list of strings is the key repeated, which
    is how Proxmox takes an array such as the guest agent's `command`; the
    `proxmox` tool's own parameters cannot carry one, so only nervus's own
    calls send it (ADR-0016). Anything else nested is refused, not guessed at."""
    pairs: list[tuple[str, str]] = []
    for key, value in (params or {}).items():
        if isinstance(value, bool):
            pairs.append((key, "1" if value else "0"))
        elif isinstance(value, (str, int, float)):
            pairs.append((key, str(value)))
        elif isinstance(value, (list, tuple)) and value and all(isinstance(v, str) for v in value):
            pairs.extend((key, v) for v in value)
        else:
            raise ProxmoxError(
                f"parameter {key!r} must be a string, number or boolean, "
                f"not {type(value).__name__}"
            )
    return urllib.parse.urlencode(pairs)


# Proxmox's whole-node bulk actions check the privilege on the node, then act on
# every guest with no per-guest check, so the NoAccess nervus sets on its own
# container (tools/proxmox-access) does not stop them: a VM-capable token could
# stop nervus's own container along with the rest. nervus acts on specific guests,
# never all at once, so these are refused here (procedure 056, finding 4).
BULK_ENDPOINTS = frozenset({"startall", "stopall", "suspendall", "migrateall"})


def check_request(method: str, path: str, params: dict[str, Any] | None) -> str:
    """Everything nervus refuses before sending, in one place, so the server
    can record a refusal before it writes an intent. Returns the method,
    upper-cased."""
    method = method.upper()
    if method not in METHODS:
        raise ProxmoxError(f"method must be one of {', '.join(METHODS)}: {method!r}")
    api_path(path)
    action = path.rstrip("/").rsplit("/", 1)[-1].lower()
    if action in BULK_ENDPOINTS:
        raise ProxmoxError(f"nervus does not allow the whole-node bulk action {action!r}: it acts on every guest, "
                           "nervus's own container included, past the access limit set on it")
    encode_params(params)
    return method


class ProxmoxClient:
    """Sends API requests to one Proxmox host with one token."""

    def __init__(
        self,
        config: ProxmoxConfig,
        *,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    ) -> None:
        self.config = config
        self.max_response_bytes = max_response_bytes
        self._ctx = make_ssl_context(config.ca_file)

    async def request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        *,
        timeout: float = 60.0,
    ) -> ProxmoxResponse:
        """Validate, then send in a worker thread. Validation happens here,
        before the thread, so a refused request never opens a connection."""
        method = check_request(method, path, params)
        target = api_path(path)
        encoded = encode_params(params)
        return await anyio.to_thread.run_sync(
            partial(self._send, method, target, encoded, timeout)
        )

    def _send(self, method: str, target: str, encoded: str, timeout: float) -> ProxmoxResponse:
        cfg = self.config
        headers = {
            # API tokens authenticate per request and need no CSRF token.
            "Authorization": f"PVEAPIToken={cfg.token_id}={cfg.secret}",
            "Accept": "application/json",
        }
        body: bytes | None = None
        if method in ("GET", "DELETE"):
            if encoded:
                target = f"{target}?{encoded}"
        else:
            body = encoded.encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"

        where = f"{cfg.host}:{cfg.port}"
        conn = http.client.HTTPSConnection(cfg.host, cfg.port, context=self._ctx, timeout=timeout)
        try:
            conn.request(method, target, body=body, headers=headers)
            resp = conn.getresponse()
            raw = resp.read(self.max_response_bytes + 1)
        except ssl.SSLCertVerificationError as exc:
            raise ProxmoxError(
                f"refused {where}: its certificate is not trusted by the pinned CA "
                f"({exc.verify_message})"
            ) from None
        except (OSError, http.client.HTTPException) as exc:
            raise ProxmoxError(f"could not complete the request to {where}: {exc}") from None
        finally:
            conn.close()

        if len(raw) > self.max_response_bytes:
            raise ProxmoxError(
                f"the response is larger than {self.max_response_bytes} bytes and was not "
                "returned; narrow the request (a node, a type filter, a limit)"
            )

        try:
            payload = json.loads(raw) if raw else None
        except ValueError:
            payload = None
            text: str | None = raw[:_TEXT_LIMIT].decode(errors="replace")
        else:
            text = None
        data = payload.get("data") if isinstance(payload, dict) else payload
        errors = payload.get("errors") if isinstance(payload, dict) else None
        return ProxmoxResponse(
            status=resp.status,
            reason=resp.reason,
            data=data,
            errors=errors,
            body_bytes=len(raw),
            text=text,
        )
