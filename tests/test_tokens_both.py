"""Tokens from both places (ADR-0014 decision C): the token file's, read at
start, and those issued in the UI, looked up in the database on every request,
so an issued token works at once and a revoked one stops. Every static token
is a fallback token, and every audit record made with one says it is
unconfined (ADR-0006 decision 7, ADR-0014 decision G)."""

import http.client
import json
import sys
from pathlib import Path

from types import SimpleNamespace

import pytest

from nervus.audit import AuditLog
from nervus.auth import BearerAuthMiddleware, Token, Tokens, attribution, require_token
from nervus.database import Database, DatabaseUnusable

sys.path.insert(0, str(Path(__file__).parent))


def _Ctx(headers):
    """An MCP request as the middleware sees one: a connection request."""
    return SimpleNamespace(request=SimpleNamespace(headers=headers), request_id=1, method="initialize",
                           params={})

FILE_TOKEN = "f" * 43
FILE = {FILE_TOKEN: Token(id="from-file", client="codex", project="p", hosts=frozenset({"node-a"}))}


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "nervus.db")
    database.open()
    return database


def test_a_file_token_is_found_without_asking_the_database():
    def never(value):
        raise AssertionError("the database was asked for a file token")
    assert Tokens(FILE, never).get(FILE_TOKEN).id == "from-file"


def test_an_issued_token_works_at_once_and_a_revoked_one_stops(db):
    tokens = Tokens(FILE, db.token)  # made before the token is issued
    value = db.issue_token("laptop", "codex", "laptop", ["node-b"], taken=tokens.file_ids())
    assert require_token({"authorization": f"Bearer {value}"}, tokens).id == "laptop"
    db.revoke_token("laptop")
    assert tokens.get(value) is None
    assert tokens.get("nothing like it") is None


def test_a_database_that_fails_refuses_its_tokens_and_says_so(capsys):
    def broken(value):
        raise DatabaseUnusable("the database x: disk I/O error")
    tokens = Tokens(FILE, broken)
    assert tokens.get("an-issued-value") is None
    assert tokens.get(FILE_TOKEN).id == "from-file"  # the file's still work
    assert "disk I/O error" in capsys.readouterr().err


def test_file_ids_are_the_files():
    assert Tokens(FILE, None).file_ids() == {"from-file"}


def test_every_static_token_is_attributed_as_unconfined(db):
    value = db.issue_token("laptop", "codex", "laptop", ["node-b"])
    for token in (FILE[FILE_TOKEN], db.token(value)):
        assert attribution(token) == {"token_id": token.id, "client": token.client,
                                      "project": token.project, "unconfined": True}


async def test_the_off_switch_and_its_refusal_apply_to_issued_tokens(db, tmp_path):
    """An issued token is switched off by its id, like any other, and a revoked
    one is refused exactly as an unknown token, after the same wait (ADR-0003
    decisions B and D)."""
    switches = tmp_path / "switches.yaml"
    switches.write_text("lockdown: false\ndisabled: [laptop]\n")
    audit = AuditLog(path=tmp_path / "audit.jsonl")
    tokens = Tokens(FILE, db.token)
    value = db.issue_token("laptop", "codex", "laptop", ["node-b"])
    middleware = BearerAuthMiddleware(tokens, switches, audit)

    async def call_next(ctx):
        return "served"

    errors = []
    for presented in (value, "never-issued"):
        with pytest.raises(Exception) as caught:
            await middleware(_Ctx({"authorization": f"Bearer {presented}"}), call_next)
        errors.append(str(caught.value))
    switches.write_text("lockdown: false\ndisabled: []\n")
    assert await middleware(_Ctx({"authorization": f"Bearer {value}"}), call_next) == "served"
    db.revoke_token("laptop")
    with pytest.raises(Exception) as caught:
        await middleware(_Ctx({"authorization": f"Bearer {value}"}), call_next)
    errors.append(str(caught.value))
    assert errors[0] == errors[1] == errors[2]
    refusal, = [json.loads(line) for line in audit.path.read_text().splitlines()]
    assert refusal["token_id"] == "laptop" and refusal["unconfined"] is True


def test_a_token_issued_to_a_running_nervus_works_on_its_next_call(tmp_path):
    """End to end, with no restart and no file of nervus's edited: issued into
    the database a running nervus uses, accepted at once; revoked, refused at
    once. Its calls are recorded as unconfined."""
    from test_main import INIT, MCP_HEADERS, _jsonrpc, _Nervus, _post

    nervus = _Nervus(tmp_path)
    try:
        nervus.wait_listening()
        value = Database(nervus.database).issue_token("issued", "c", "p", ["node-a"], taken={"t"})
        conn = http.client.HTTPConnection("127.0.0.1", nervus.port, timeout=10)
        auth = {**MCP_HEADERS, "Authorization": f"Bearer {value}"}
        assert "result" in _jsonrpc(_post(conn, INIT, auth)[1])
        Database(nervus.database).revoke_token("issued")
        assert _jsonrpc(_post(conn, INIT, auth)[1])["error"]["code"] == -32001
    finally:
        nervus.stop()
