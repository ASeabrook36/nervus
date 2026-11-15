import os
from types import SimpleNamespace

import pytest

from nervus.auth import (
    AuthError,
    BearerAuthMiddleware,
    Token,
    load_tokens,
    require_host_allowed,
    require_token,
    resolve_token,
)
from nervus.config import ConfigError

TOKENS_YAML = """
tokens:
  - token: sekret-claude-em
    id: claude-code-project-a
    client: claude-code
    project: project-a
    hosts: [node-a, node-b]
  - token: sekret-codex-em
    id: codex-project-a
    client: codex
    project: project-a
    hosts: [node-a]
"""


def _write_tokens(tmp_path, text=TOKENS_YAML, mode=0o600):
    path = tmp_path / "tokens.yaml"
    path.write_text(text)
    os.chmod(path, mode)
    return path


def test_load_tokens_parses_all_entries(tmp_path):
    path = _write_tokens(tmp_path)

    tokens = load_tokens(path)

    assert set(tokens) == {"sekret-claude-em", "sekret-codex-em"}
    assert tokens["sekret-claude-em"] == Token(
        id="claude-code-project-a",
        client="claude-code",
        project="project-a",
        hosts=frozenset({"node-a", "node-b"}),
    )


def test_load_tokens_refuses_group_readable_file(tmp_path):
    path = _write_tokens(tmp_path, mode=0o640)

    with pytest.raises(ConfigError, match="0600"):
        load_tokens(path)


def test_load_tokens_rejects_duplicate_token_values(tmp_path):
    path = _write_tokens(
        tmp_path,
        text="""
tokens:
  - token: same
    id: a
    client: claude-code
    project: p
    hosts: [node-a]
  - token: same
    id: b
    client: codex
    project: p
    hosts: [node-a]
""",
    )

    with pytest.raises(ConfigError, match="duplicate"):
        load_tokens(path)


def test_load_tokens_rejects_missing_fields(tmp_path):
    path = _write_tokens(tmp_path, text="tokens:\n  - token: x\n")

    with pytest.raises(ConfigError, match="missing fields"):
        load_tokens(path)


TOKENS = {
    "good": Token(id="t1", client="claude-code", project="p", hosts=frozenset({"node-a"})),
}


def test_resolve_token_accepts_valid_bearer_header():
    token = resolve_token({"authorization": "Bearer good"}, TOKENS)
    assert token is TOKENS["good"]


def test_resolve_token_rejects_unknown_token():
    assert resolve_token({"authorization": "Bearer bad"}, TOKENS) is None


def test_resolve_token_rejects_missing_header():
    assert resolve_token({}, TOKENS) is None
    assert resolve_token(None, TOKENS) is None


def test_resolve_token_rejects_non_bearer_scheme():
    assert resolve_token({"authorization": "Basic good"}, TOKENS) is None


def test_require_token_raises_on_bad_token():
    with pytest.raises(AuthError):
        require_token({"authorization": "Bearer bad"}, TOKENS)


def test_require_host_allowed_permits_listed_host():
    require_host_allowed(TOKENS["good"], "node-a")  # must not raise


def test_require_host_allowed_rejects_unlisted_host():
    with pytest.raises(AuthError, match="not allowed"):
        require_host_allowed(TOKENS["good"], "node-b")


async def test_bearer_middleware_rejects_unknown_token():
    from mcp.shared.exceptions import MCPError

    middleware = BearerAuthMiddleware(TOKENS)
    ctx = SimpleNamespace(request=SimpleNamespace(headers={"authorization": "Bearer bad"}))

    async def call_next(_ctx):
        raise AssertionError("call_next must not run for a bad token")

    with pytest.raises(MCPError):
        await middleware(ctx, call_next)


async def test_bearer_middleware_rejects_missing_header():
    from mcp.shared.exceptions import MCPError

    middleware = BearerAuthMiddleware(TOKENS)
    ctx = SimpleNamespace(request=SimpleNamespace(headers={}))

    async def call_next(_ctx):
        raise AssertionError("call_next must not run without a token")

    with pytest.raises(MCPError):
        await middleware(ctx, call_next)


async def test_bearer_middleware_allows_known_token_through():
    middleware = BearerAuthMiddleware(TOKENS)
    ctx = SimpleNamespace(request=SimpleNamespace(headers={"authorization": "Bearer good"}))

    calls = []

    async def call_next(passed_ctx):
        calls.append(passed_ctx)
        return "ok"

    result = await middleware(ctx, call_next)

    assert result == "ok"
    assert calls == [ctx]
