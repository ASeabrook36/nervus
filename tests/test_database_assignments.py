"""A token read-only on some of its machines (ADR-0031, order of work step 2).

A token with any read-only assignment is kept whole in a table of its own,
`assigned_token`, never in `issued_token`, so a release before this one, which
knows only `issued_token`, refuses it as unknown after a rollback ("Settled
already": an older release must refuse it, not widen it). The table is in
ADDED and the version stays 1 (ADR-0014 decision F). An id names one token
across both tables and the token file. A token issued without a read-only
assignment is kept where it always was, and so is read-write wherever it
reaches, as every token before this release.
"""

import shutil
import sqlite3
import subprocess
import importlib.util
import sys
from pathlib import Path

import pytest

from nervus.database import SCHEMA_VERSION, Database, TokenRefused

T0 = 1_800_000_000.0
REPO = Path(__file__).resolve().parent.parent
# nervus 0.2.2's release commit (procedures/066): the code a rollback from this
# release runs against the database it leaves.
RELEASE_BEFORE = "bcc2bc4"


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "nervus.db")
    database.open()
    return database


def _issue(db, id="reader-look", hosts=("node-a", "node-b"), readonly=("node-a",), taken=()):
    return db.issue_token(id, "claude-code", "reader", list(hosts), taken=taken, readonly=list(readonly), now=T0)


def _tables(path: Path) -> dict[str, list]:
    with sqlite3.connect(path) as raw:
        return {name: raw.execute(f"SELECT id FROM {name}").fetchall() for name in ("issued_token", "assigned_token")}


def test_a_token_read_only_on_a_machine_is_found_with_that_level(db):
    value = _issue(db)
    token = db.token(value)
    assert token is not None
    assert token.id == "reader-look"
    assert token.hosts == frozenset({"node-a", "node-b"})
    assert token.readonly == frozenset({"node-a"})


def test_it_is_kept_in_its_own_table_and_not_with_the_tokens_before_it(db):
    _issue(db)
    tables = _tables(db.path)
    assert tables["assigned_token"] == [("reader-look",)]
    assert tables["issued_token"] == []


def test_a_token_with_no_read_only_assignment_is_kept_where_tokens_always_were(db):
    value = _issue(db, id="laptop-codex", readonly=())
    tables = _tables(db.path)
    assert tables["issued_token"] == [("laptop-codex",)]
    assert tables["assigned_token"] == []
    assert db.token(value).readonly == frozenset()


def test_only_a_hash_of_the_value_is_kept(db):
    value = _issue(db)
    assert value.encode() not in db.path.read_bytes()


def test_both_tables_are_listed_by_id(db):
    _issue(db, id="b-look")
    _issue(db, id="a-plain", readonly=())
    listed = db.issued_tokens()
    assert [i.token.id for i in listed] == ["a-plain", "b-look"]
    assert [i.token.readonly for i in listed] == [frozenset(), frozenset({"node-a"})]
    assert all(i.issued_at == T0 for i in listed)


def test_one_is_revoked_from_its_own_table(db):
    value = _issue(db)
    assert db.revoke_token("reader-look") is True
    assert db.token(value) is None
    assert db.revoke_token("reader-look") is False


@pytest.mark.parametrize("first", [(), ("node-a",)], ids=["plain-first", "read-only-first"])
@pytest.mark.parametrize("second", [(), ("node-a",)], ids=["plain-second", "read-only-second"])
def test_an_id_names_one_token_across_both_tables(db, first, second):
    _issue(db, id="same", readonly=first)
    with pytest.raises(TokenRefused, match="already a token's"):
        _issue(db, id="same", readonly=second)


def test_an_id_in_the_token_file_is_refused_too(db):
    with pytest.raises(TokenRefused, match="token file"):
        _issue(db, id="from-file", taken={"from-file"})


def test_a_read_only_machine_must_be_one_of_the_token_s_machines(db):
    with pytest.raises(TokenRefused, match="read-only"):
        _issue(db, hosts=("node-b",), readonly=("node-a",))
    assert _tables(db.path) == {"issued_token": [], "assigned_token": []}


def test_a_level_this_release_does_not_know_reads_as_read_only(db):
    """A later release's word for a level is never read as more than read-only."""
    value = _issue(db)
    with sqlite3.connect(db.path) as raw:
        raw.execute("""UPDATE assigned_token SET levels = '{"node-a": "read-only", "node-b": "look-and-tell"}'""")
    assert db.token(value).readonly == frozenset({"node-a", "node-b"})


def test_the_table_is_added_and_the_version_stays(tmp_path):
    """ADR-0014 decision F: a database from before gains the table on open and
    keeps its version, so the release before still starts on it."""
    path = tmp_path / "nervus.db"
    Database(path).open()
    with sqlite3.connect(path) as raw:
        raw.execute("DROP TABLE assigned_token")
    Database(path).open()
    with sqlite3.connect(path) as raw:
        assert raw.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 1
        assert raw.execute("SELECT name FROM sqlite_master WHERE name = 'assigned_token'").fetchone()


def _release_before(tmp_path):
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    shown = subprocess.run(["git", "-C", str(REPO), "show", f"{RELEASE_BEFORE}:src/nervus/database.py"],
                           capture_output=True, text=True)
    if shown.returncode != 0:
        pytest.skip(f"this checkout has no {RELEASE_BEFORE}")
    source = tmp_path / "before_database.py"
    source.write_text(shown.stdout)
    spec = importlib.util.spec_from_file_location("before_database", source)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # its dataclasses look themselves up there
    try:
        spec.loader.exec_module(module)
    finally:
        del sys.modules[spec.name]
    return module


def test_the_release_before_refuses_such_a_token_as_unknown(tmp_path):
    """ADR-0031 verification 7, as ADR-0014 verification 5 did: 0.2.2's own
    code, from git, given this release's database, opens it, finds a plain
    token as before, and does not find one read-only on a machine, which it
    could only have read as read-write everywhere."""
    before = _release_before(tmp_path)
    db = Database(tmp_path / "nervus.db")
    db.open()
    limited = _issue(db)
    plain = _issue(db, id="laptop-codex", readonly=())
    rolled_back = before.Database(db.path)
    rolled_back.open()
    assert rolled_back.token(limited) is None
    assert rolled_back.token(plain).id == "laptop-codex"
    assert [i.token.id for i in rolled_back.issued_tokens()] == ["laptop-codex"]
    # and forward again, with both still there
    db.open()
    assert db.token(limited).readonly == frozenset({"node-a"})
