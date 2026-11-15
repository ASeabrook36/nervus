"""What the clients page shows of each token (ADR-0014 decision G): where it
lives, whether it is switched off, and its last call, read from the audit log
as the viewer reads it."""

import pytest

from nervus.audit import AuditLog
from nervus.auth import Token, Tokens
from nervus.clients import ClientRow, clients_view
from nervus.database import Database

FILE = {"v1": Token(id="from-file", client="codex", project="global", hosts=frozenset({"node-b", "node-a"}))}


@pytest.fixture
def parts(tmp_path):
    db = Database(tmp_path / "nervus.db")
    db.open()
    db.issue_token("issued", "claude-code", "laptop", ["hv"], now=1_800_000_000.0)
    switches = tmp_path / "switches.yaml"
    switches.write_text("lockdown: false\ndisabled: [issued]\n")
    audit = AuditLog(path=tmp_path / "audit.jsonl")
    return Tokens(FILE, db.token), db, switches, audit


def test_every_token_from_both_places_by_id(parts):
    tokens, db, switches, audit = parts
    view = clients_view(tokens, db.issued_tokens(), switches, audit.path)
    assert view.rows == [
        ClientRow(id="from-file", client="codex", project="global", hosts=("node-a", "node-b"), issued=False,
                  off=False, last_call=None),
        ClientRow(id="issued", client="claude-code", project="laptop", hosts=("hv",), issued=True,
                  off=True, last_call=None),
    ]
    assert (view.lockdown, view.unreadable) == (False, "")


def test_the_last_call_is_the_newest_call_and_not_a_refusal(parts):
    tokens, db, switches, audit = parts
    first = audit.record_intent("exec", {"token_id": "from-file", "command": "true"})
    audit.record_result(first, "exec", {"exit_code": 0})
    audit.record_refusal("initialize", {"token_id": "from-file", "reason": "switches: disabled"})
    audit.record_refusal("initialize", {"token_id": "issued", "reason": "switches: disabled"})
    view = clients_view(tokens, db.issued_tokens(), switches, audit.path)
    calls = [r for r in map(__import__("json").loads, audit.path.read_text().splitlines())
             if r["phase"] == "intent"]
    assert view.rows[0].last_call == calls[0]["ts"]
    assert view.rows[1].last_call is None  # refused only: never called


def test_lockdown_and_an_unreadable_file_are_said(parts):
    tokens, db, switches, audit = parts
    switches.write_text("lockdown: true\ndisabled: []\n")
    assert clients_view(tokens, db.issued_tokens(), switches, audit.path).lockdown is True
    switches.write_text("lockdown: [\n")
    view = clients_view(tokens, db.issued_tokens(), switches, audit.path)
    assert "not valid YAML" in view.unreadable  # the page says every client is refused
    assert not any(row.off for row in view.rows)  # one by one, nothing can be read
