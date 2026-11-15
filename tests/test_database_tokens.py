"""Tokens issued in the UI, kept in nervus's database (ADR-0014 decisions C, D
and F): by hash only, beside the token file's, never holding an entry marked
`issue: never`, and
added to the database without changing its version, so the release before
still opens it."""

import importlib.util
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from nervus.database import TOKEN_BYTES, Database, TokenRefused

T0 = 1_800_000_000.0
REPO = Path(__file__).resolve().parent.parent
# The release deployed before piece 4 (procedures/021). Its database code is
# the code a rollback would run.
PREVIOUS_RELEASE = "2740c30"


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "nervus.db")
    database.open()
    return database


def _issue(db, id="laptop-codex", hosts=("node-a", "node-b"), taken=()):
    return db.issue_token(id, "codex", "laptop", list(hosts), taken=taken, now=T0)


def test_an_issued_token_is_found_by_its_value_at_once(db):
    value = _issue(db)
    assert len(value) == 43 and TOKEN_BYTES == 32  # 256 random bits, url-safe
    token = db.token(value)
    assert (token.id, token.client, token.project, token.hosts) == ("laptop-codex", "codex", "laptop",
                                                                     frozenset({"node-a", "node-b"}))
    assert db.token("not-a-token") is None
    assert db.token(value[:-1]) is None


def test_values_are_distinct(db):
    values = {_issue(db, f"t{i}") for i in range(20)}
    assert len(values) == 20


def test_a_revoked_token_is_gone(db):
    value = _issue(db)
    assert db.revoke_token("laptop-codex") is True
    assert db.token(value) is None
    assert db.revoke_token("laptop-codex") is False
    assert db.issued_tokens() == []


def test_issued_tokens_are_listed_by_id_with_when(db):
    _issue(db, "b-token")
    _issue(db, "a-token", hosts=("hv",))
    listed = db.issued_tokens()
    assert [(t.token.id, sorted(t.token.hosts), t.issued_at) for t in listed] == [
        ("a-token", ["hv"], T0), ("b-token", ["node-a", "node-b"], T0)]


def test_no_token_value_is_in_the_files(db):
    """ADR-0014 decision D: only a hash, so a copy of the database lets no one
    in. Read every file SQLite keeps while a connection is open."""
    values = [_issue(db, f"t{i}") for i in range(3)]
    with sqlite3.connect(db.path) as other:
        other.execute("SELECT 1").fetchall()
        raw = b"".join(p.read_bytes() for p in db.path.parent.iterdir())
    assert b"issued_token" in raw
    for value in values:
        assert value.encode() not in raw


@pytest.mark.parametrize("hosts", [["hv-root"], ["node-a", "hv-root"]])
def test_an_entry_marked_never_is_never_issued(db, hosts):
    """ADR-0009 decision 3 and ADR-0019 decision D: an entry the inventory
    marks `issue: never` is the token file's alone, whatever it is called."""
    with pytest.raises(TokenRefused, match="hv-root is never issued"):
        db.issue_token("a-token", "claude-code", "laptop", hosts, never_issued={"hv-root"}, now=T0)
    assert db.issued_tokens() == []


def test_no_name_is_never_issued_by_itself(db):
    """The name `hv-root` once was refused by name. Now only the inventory decides."""
    db.issue_token("a-token", "claude-code", "laptop", ["hv-root"], now=T0)
    assert [t.token.id for t in db.issued_tokens()] == ["a-token"]


def test_an_id_already_taken_is_refused_in_either_place(db):
    _issue(db, "laptop-codex")
    with pytest.raises(TokenRefused, match="already"):
        _issue(db, "laptop-codex")
    with pytest.raises(TokenRefused, match="already"):
        _issue(db, "codex-anywhere", taken={"codex-anywhere", "claude-code-ops"})
    assert [t.token.id for t in db.issued_tokens()] == ["laptop-codex"]


@pytest.mark.parametrize("id", ["", "Upper", "has space", "-leading", "dot.ted", "x" * 65, "ünï", "a\nb"])
def test_an_id_must_be_plain(db, id):
    with pytest.raises(TokenRefused, match="id"):
        _issue(db, id)


@pytest.mark.parametrize("client, project, hosts", [
    ("", "laptop", ["node-a"]), ("codex", "  ", ["node-a"]), ("codex", "laptop", []),
    ("c" * 65, "laptop", ["node-a"]), ("codex", "laptop", ["node-a", 3]),
])
def test_client_project_and_hosts_are_required(db, client, project, hosts):
    with pytest.raises(TokenRefused):
        db.issue_token("ok-id", client, project, hosts, taken=(), now=T0)


# --- ADR-0014 decision F: added without changing the version ---------------------


def test_a_database_from_before_gains_the_table_and_keeps_its_version(tmp_path):
    """A deployed nervus's database is version 1 with two tables. Opened by this release,
    it gains the tokens table, keeps what it held, and stays version 1."""
    path = tmp_path / "nervus.db"
    with sqlite3.connect(path) as old:
        old.executescript("""
            CREATE TABLE signin_link (hash TEXT PRIMARY KEY, made_at REAL NOT NULL,
                                      expires_at REAL NOT NULL, used_at REAL);
            CREATE TABLE session (hash TEXT PRIMARY KEY, signed_in_at REAL NOT NULL,
                                  expires_at REAL NOT NULL);
            INSERT INTO session VALUES ('h', 1.0, 2.0);
            PRAGMA user_version = 1;
        """)
    db = Database(path)
    db.open()
    with sqlite3.connect(path) as check:
        assert check.execute("PRAGMA user_version").fetchone()[0] == 1
        assert check.execute("SELECT COUNT(*) FROM session").fetchone()[0] == 1
    _issue(db)
    db.open()  # again, as after a restart: the table is not made twice
    assert len(db.issued_tokens()) == 1


def _previous_database_module(tmp_path):
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    shown = subprocess.run(["git", "-C", str(REPO), "show", f"{PREVIOUS_RELEASE}:src/nervus/database.py"],
                           capture_output=True, text=True)
    if shown.returncode != 0:
        pytest.skip(f"this checkout has no {PREVIOUS_RELEASE}")
    source = tmp_path / "previous_database.py"
    source.write_text(shown.stdout)
    spec = importlib.util.spec_from_file_location("previous_database", source)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # its dataclasses look themselves up there
    try:
        spec.loader.exec_module(module)
    finally:
        del sys.modules[spec.name]
    return module


def test_the_release_before_still_opens_a_database_with_tokens(tmp_path):
    """ADR-0014 decision F and verification 5: a deploy that rolls back runs
    the release before against the database this one left. That release's own
    code is run here, from git, and must open it and sign in as before."""
    previous = _previous_database_module(tmp_path)
    db = Database(tmp_path / "nervus.db")
    db.open()
    _issue(db)
    rolled_back = previous.Database(db.path)
    rolled_back.open()
    link, _ = rolled_back.make_link(now=T0)
    rolled_back.use_link(link, now=T0)
    # and forward again, with the token still there
    db.open()
    assert [t.token.id for t in db.issued_tokens()] == ["laptop-codex"]
