from __future__ import annotations

import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import anyio
import yaml

from nervus import plainfile, switches
from nervus.config import ConfigError, require_private_file


# ADR-0003 decision D: no refusal is answered sooner than this after the check
# began, so a switched-off client's refusal, which reads the switches file and
# writes an audit line first, takes no longer than an invalid token's.
REFUSAL_SECONDS = 0.05


class AuthError(Exception):
    """A request presented no valid bearer token, or asked for a host outside its allowlist."""


@dataclass(frozen=True)
class Token:
    id: str
    client: str
    project: str
    hosts: frozenset[str]
    # A static bearer token, from the token file or issued in the UI, is a
    # fallback token: any program that can read where a client keeps it can
    # use it (ADR-0006 decision 7). Grants, when OAuth comes (piece 7), will
    # not be.
    unconfined: bool = True


def attribution(token: Token) -> dict[str, object]:
    """Who a call is, as every audit record of it says: the token, its client
    and project, and whether it is unconfined, which ADR-0006 decision 7 says
    the audit log marks on every call made with one."""
    return {"token_id": token.id, "client": token.client, "project": token.project,
            "unconfined": token.unconfined}


class Tokens:
    """Every token nervus accepts (ADR-0014 decision C): the token file's,
    read at start, and those issued in the UI, looked up in the database on
    every request, so an issued token works at once and a revoked one stops.

    A file token is found without asking the database. If the database fails,
    its tokens are refused, the file's still work, and the console says why.
    """

    def __init__(self, from_file: Mapping[str, Token], issued: Callable[[str], Token | None] | None):
        self._from_file = from_file
        self._issued = issued

    def get(self, value: str) -> Token | None:
        token = self._from_file.get(value)
        if token is not None or self._issued is None:
            return token
        try:
            return self._issued(value)
        except ConfigError as exc:  # the database's DatabaseUnusable
            print(f"nervus: a token issued in the UI could not be checked, so it is refused: {exc}",
                  file=sys.stderr, flush=True)
            return None

    def file_ids(self) -> set[str]:
        return {t.id for t in self._from_file.values()}

    def in_file(self) -> list[Token]:
        return list(self._from_file.values())


def load_tokens(path: Path) -> dict[str, Token]:
    """Load the token file: secret value -> Token record.

    Refuses a token file that isn't 0600 (rule 7 -- unlike hosts.yaml,
    this file holds live credentials, not just references to them).
    """
    require_private_file(path)
    try:
        raw = yaml.safe_load(plainfile.read_text(path))
    except OSError as exc:
        raise ConfigError(f"cannot read the tokens file: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"tokens file is not valid YAML: {path}: {exc}") from exc

    if not isinstance(raw, dict) or not isinstance(raw.get("tokens"), list):
        raise ConfigError(f"tokens file must have a top-level 'tokens' list: {path}")

    tokens: dict[str, Token] = {}
    required_fields = ("token", "id", "client", "project", "hosts")
    for entry in raw["tokens"]:
        if not isinstance(entry, dict):
            raise ConfigError(f"tokens file entry is not a mapping: {entry!r}")
        missing = [f for f in required_fields if f not in entry]
        if missing:
            raise ConfigError(
                f"tokens file entry missing fields {missing}: id={entry.get('id')!r}"
            )
        secret = entry["token"]
        if secret in tokens:
            raise ConfigError(
                f"duplicate token value in tokens file "
                f"(ids {tokens[secret].id!r} and {entry['id']!r})"
            )
        tokens[secret] = Token(
            id=entry["id"],
            client=entry["client"],
            project=entry["project"],
            hosts=frozenset(entry["hosts"]),
        )

    return tokens


def resolve_token(headers: Mapping[str, str] | None, tokens: Tokens | Mapping[str, Token]) -> Token | None:
    """Look up the bearer token carried by an Authorization header, or None."""
    if headers is None:
        return None
    raw = headers.get("authorization") or headers.get("Authorization")
    if not raw or not raw.startswith("Bearer "):
        return None
    return tokens.get(raw[len("Bearer ") :])


def require_token(headers: Mapping[str, str] | None, tokens: Tokens | Mapping[str, Token]) -> Token:
    token = resolve_token(headers, tokens)
    if token is None:
        raise AuthError("invalid or missing bearer token")
    return token


def require_host_allowed(token: Token, host: str) -> None:
    if host not in token.hosts:
        raise AuthError(f"token {token.id!r} is not allowed to reach host {host!r}")


class BearerAuthMiddleware:
    """MCP-level middleware: reject any request carrying an unknown bearer token.

    Registered via ``MCPServer(middleware=[...])``. This runs around every
    inbound JSON-RPC request and notification -- ``initialize``,
    ``tools/list``, ``tools/call``, all of it -- per mcp 2.x's
    ``ServerMiddleware`` contract, so an unauthenticated client learns
    nothing about the tool surface either.

    Deliberately not the SDK's TokenVerifier/AuthSettings machinery: that
    models OAuth resource-server semantics (issuer_url, resource
    indicators) this project doesn't have. ADR-0001 section 6 calls for a
    flat static token -> (client, project, host allowlist) mapping, and
    the per-host allowlist -- the *only* authorization check beyond token
    validity -- is enforced by tool code, because the target host isn't
    known until a tool call's arguments are parsed.
    """

    def __init__(
        self,
        tokens: Tokens | Mapping[str, Token],
        switches_path: Path | None = None,
        audit: Any = None,
    ):
        """`switches_path` is the off switch (ADR-0003, nervus.switches),
        re-read on every request. nervus's entrypoint always passes one;
        None, which skips the check, is for tests of other things."""
        self._tokens = tokens
        self._switches_path = switches_path
        self._audit = audit

    async def __call__(self, ctx: Any, call_next: Any) -> Any:
        from mcp.shared.exceptions import MCPError

        began = time.monotonic()
        refused = MCPError(code=-32001, message="unauthorized: invalid or missing bearer token")
        headers = getattr(ctx.request, "headers", None)
        token = resolve_token(headers, self._tokens)
        if token is None:
            await _hold(began)
            raise refused
        if self._switches_path is not None:
            reason = switches.refusal(self._switches_path, token.id)
            if reason is not None:
                # ADR-0003 question C: a switched-off client's attempts are
                # visible, to the operator only. Notifications carry no call
                # worth a record, so only requests are written.
                if self._audit is not None and getattr(ctx, "request_id", None) is not None:
                    params = getattr(ctx, "params", None) or {}
                    self._audit.record_refusal(
                        getattr(ctx, "method", "unknown"),
                        {
                            **attribution(token),
                            "name": params.get("name") if isinstance(params, dict) else None,
                            "reason": f"switches: {reason}",
                        },
                    )
                # Question B: exactly what an invalid token gets, after the
                # same wait (decision D).
                await _hold(began)
                raise refused
        return await call_next(ctx)


async def _hold(began: float) -> None:
    """Return REFUSAL_SECONDS after `began`, as exactly as the event loop allows.

    Sleeping for the remainder is not enough: the loop rounds each wait up to a
    whole millisecond counted from when the wait starts, so work done before it
    still shows in the total (measured: a 0.26 ms difference came through
    unchanged). So it sleeps to within 2 ms of the deadline, then yields to the
    loop, which goes on serving other requests, until the deadline passes.
    """
    deadline = began + REFUSAL_SECONDS
    await anyio.sleep(max(0.0, deadline - time.monotonic() - 0.002))
    while time.monotonic() < deadline:
        await anyio.sleep(0)
