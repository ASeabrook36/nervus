"""nervus's database: the operator's sign-in links and browser sessions
(ADR-0012 decisions 3 to 5), and the guarantees ADR-0011 decision 1 chose
SQLite for (its verification item 1)."""

import os
import sqlite3
import stat
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from nervus.database import (
    LINK_SECONDS,
    SESSION_SECONDS,
    Database,
    DatabaseUnusable,
    LinkRefused,
)

T0 = 1_800_000_000.0  # a fixed "now", so no test depends on the clock


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "nervus.db")
    database.open()
    return database


def _signed_in(db, now=T0):
    secret, _ = db.make_link(now=now)
    return db.use_link(secret, now=now)


# --- the file ------------------------------------------------------------------


def test_open_makes_the_file_0600_whatever_the_umask(tmp_path):
    old = os.umask(0)
    try:
        Database(tmp_path / "nervus.db").open()
    finally:
        os.umask(old)
    assert stat.S_IMODE((tmp_path / "nervus.db").stat().st_mode) == 0o600


def test_its_side_files_are_0600_too(db):
    """SQLite's write-ahead files (-wal, -shm) carry what is being written; they
    must be no more readable than the database."""
    db.make_link(now=T0)
    with sqlite3.connect(db.path) as other:  # held open, so the side files stay
        other.execute("SELECT 1 FROM signin_link").fetchall()
        side = [p for p in db.path.parent.iterdir() if p.name != db.path.name]
        assert side, "expected -wal and -shm files while a connection is open"
        assert {stat.S_IMODE(p.stat().st_mode) for p in side} == {0o600}


def test_open_again_keeps_what_is_there(tmp_path):
    first = Database(tmp_path / "nervus.db")
    first.open()
    secret, _ = first.make_link(now=T0)
    again = Database(tmp_path / "nervus.db")  # as after a restart
    again.open()
    again.use_link(secret, now=T0)


def test_nothing_but_open_makes_the_file(tmp_path):
    """Using a database that was never opened is an error, not a quiet new,
    empty one, which would sign everyone out without saying why."""
    database = Database(tmp_path / "nervus.db")
    with pytest.raises(DatabaseUnusable):
        database.make_link(now=T0)
    with pytest.raises(DatabaseUnusable):
        database.session("anything", now=T0)
    assert list(tmp_path.iterdir()) == []


def test_open_refuses_a_file_that_is_not_a_database(tmp_path):
    (tmp_path / "nervus.db").write_bytes(b"this is not SQLite, and it is long enough to tell" * 10)
    with pytest.raises(DatabaseUnusable, match="nervus.db"):
        Database(tmp_path / "nervus.db").open()


def test_open_refuses_a_database_from_a_newer_nervus(tmp_path):
    with sqlite3.connect(tmp_path / "nervus.db") as other:
        other.execute("PRAGMA user_version = 99")
    with pytest.raises(DatabaseUnusable, match="99"):
        Database(tmp_path / "nervus.db").open()


def test_open_refuses_a_database_nervus_did_not_make(tmp_path):
    with sqlite3.connect(tmp_path / "nervus.db") as other:
        other.execute("CREATE TABLE someone_elses (x)")
    with pytest.raises(DatabaseUnusable, match="did not make"):
        Database(tmp_path / "nervus.db").open()


# --- links -------------------------------------------------------------------------


def test_a_link_signs_in_once(db):
    """ADR-0011 verification 5: a sign-in link works once and only once."""
    secret, expires = db.make_link(now=T0)
    assert expires == T0 + LINK_SECONDS
    session_secret, session = db.use_link(secret, now=T0 + 1)
    assert db.session(session_secret, now=T0 + 2) == session
    with pytest.raises(LinkRefused) as refused:
        db.use_link(secret, now=T0 + 3)
    assert refused.value.reason == "used"


def test_a_link_lasts_5_minutes(db):
    """ADR-0012 decision 4 and verification 3."""
    assert LINK_SECONDS == 5 * 60
    early, _ = db.make_link(now=T0)
    db.use_link(early, now=T0 + LINK_SECONDS - 1)
    late, _ = db.make_link(now=T0)
    with pytest.raises(LinkRefused) as refused:
        db.use_link(late, now=T0 + LINK_SECONDS)
    assert refused.value.reason == "expired"
    with pytest.raises(LinkRefused) as again:
        db.use_link(late, now=T0 + LINK_SECONDS + 1)
    assert again.value.reason == "expired"  # trying again does not make it usable


def test_an_unknown_link_is_refused(db):
    db.make_link(now=T0)
    with pytest.raises(LinkRefused) as refused:
        db.use_link("not-a-link-nervus-made", now=T0)
    assert refused.value.reason == "unknown"


def test_links_are_unguessable_and_distinct(db):
    """ADR-0012: a link carries 128 random bits."""
    secrets = {db.make_link(now=T0)[0] for _ in range(200)}
    assert len(secrets) == 200
    assert all(len(s) >= 22 for s in secrets)  # 16 bytes, URL-safe base64


def test_a_spent_link_is_still_told_apart_the_next_day(db):
    """A used link is remembered long enough to be refused as used, not unknown."""
    secret, _ = db.make_link(now=T0)
    db.use_link(secret, now=T0)
    db.make_link(now=T0 + 23 * 3600)  # making a link is when old ones are cleared
    with pytest.raises(LinkRefused) as refused:
        db.use_link(secret, now=T0 + 23 * 3600)
    assert refused.value.reason == "used"


def test_old_links_are_cleared(db):
    for _ in range(3):
        db.make_link(now=T0)
    db.make_link(now=T0 + 2 * 24 * 3600)
    with sqlite3.connect(db.path) as other:
        assert other.execute("SELECT COUNT(*) FROM signin_link").fetchone()[0] == 1


# --- sessions ----------------------------------------------------------------------


def test_a_session_lasts_12_hours_from_sign_in_and_use_does_not_extend_it(db):
    """ADR-0012 decision 5; ADR-0011 verification 5."""
    assert SESSION_SECONDS == 12 * 3600
    session_secret, session = _signed_in(db)
    assert session.signed_in_at == T0 and session.expires_at == T0 + SESSION_SECONDS
    for hour in range(12):
        assert db.session(session_secret, now=T0 + hour * 3600 + 3599) == session
    assert db.session(session_secret, now=T0 + SESSION_SECONDS) is None


def test_an_unknown_session_is_none(db):
    _signed_in(db)
    assert db.session("not-a-session", now=T0) is None
    assert db.session("", now=T0) is None


def test_a_session_survives_a_restart(tmp_path):
    """ADR-0012 verification 4: a new Database on the same file, as a restarted
    nervus would make, knows the session."""
    first = Database(tmp_path / "nervus.db")
    first.open()
    session_secret, session = _signed_in(first)
    restarted = Database(tmp_path / "nervus.db")
    restarted.open()
    assert restarted.session(session_secret, now=T0 + 60) == session


def test_several_browsers_may_be_signed_in(db):
    a, _ = _signed_in(db)
    b, _ = _signed_in(db)
    assert a != b
    assert db.session(a, now=T0) and db.session(b, now=T0)


def test_sign_out_ends_that_session_only(db):
    a, _ = _signed_in(db)
    b, _ = _signed_in(db)
    assert db.sign_out(a) is True
    assert db.session(a, now=T0) is None
    assert db.session(b, now=T0) is not None
    assert db.sign_out(a) is False  # already gone


def test_sign_out_all_ends_every_session(db):
    """ADR-0012 decision 5: `nervus-ctl signout --all`."""
    a, _ = _signed_in(db)
    b, _ = _signed_in(db)
    _signed_in(db, now=T0 - SESSION_SECONDS)  # long expired: not counted as ended
    assert db.sign_out_all(now=T0) == 2
    assert db.session(a, now=T0) is None and db.session(b, now=T0) is None
    assert db.sign_out_all(now=T0) == 0


# --- only hashes are kept --------------------------------------------------------


def test_no_link_or_session_value_is_in_the_files(db):
    """ADR-0012 decision 3 and verification 5: a copy of the database signs no
    one in. Read every file SQLite keeps, while a connection is still open, so
    nothing has been checkpointed out of the write-ahead log yet."""
    unused, _ = db.make_link(now=T0)
    used, _ = db.make_link(now=T0)
    session_secret, _ = db.use_link(used, now=T0)
    with sqlite3.connect(db.path) as other:
        other.execute("SELECT 1").fetchall()
        raw = b"".join(p.read_bytes() for p in db.path.parent.iterdir())
    for value in (unused, used, session_secret):
        assert value.encode() not in raw
    assert b"signin_link" in raw  # the files were read, and are the database's


# --- ADR-0011 verification 1: two writers, and a write cut off -------------------


def test_one_link_pressed_twice_at_once_signs_in_once(db):
    secret, _ = db.make_link(now=T0)
    barrier = threading.Barrier(8)
    outcomes = []

    def press():
        barrier.wait()
        try:
            db.use_link(secret, now=T0)
            outcomes.append("signed in")
        except LinkRefused as refused:
            outcomes.append(refused.reason)

    threads = [threading.Thread(target=press) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(outcomes) == ["signed in"] + ["used"] * 7


WRITER = """
import sys
from nervus.database import Database
db = Database(__import__("pathlib").Path(sys.argv[1]))
print("ready", flush=True)
sys.stdin.readline()
for _ in range(50):
    db.make_link(now=1_800_000_000.0)
"""


def test_two_processes_writing_at_the_same_moment_both_land(db):
    """nervus and nervus-ctl are separate processes. Both start writing when
    told to, at once; every write of each must land."""
    writers = [
        subprocess.Popen([sys.executable, "-c", WRITER, str(db.path)],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        for _ in range(2)
    ]
    for w in writers:
        assert w.stdout.readline().strip() == "ready"
    for w in writers:
        w.stdin.write("go\n")
        w.stdin.flush()
    for w in writers:
        assert w.wait(timeout=60) == 0
    with sqlite3.connect(db.path) as other:
        assert other.execute("SELECT COUNT(*) FROM signin_link").fetchone()[0] == 100


CUT_OFF = """
import os, signal, sys
from pathlib import Path
from nervus.database import Database
db = Database(Path(sys.argv[1]))
with db._transaction() as conn:
    conn.execute("INSERT INTO session (hash, signed_in_at, expires_at) VALUES ('half', 0, 9e99)")
    conn.execute("DELETE FROM signin_link")
    os.kill(os.getpid(), signal.SIGKILL)  # mid-write, before it is committed
"""


def test_a_write_cut_off_part_way_leaves_the_state_before_it(db):
    secret, _ = db.make_link(now=T0)
    killed = subprocess.run([sys.executable, "-c", CUT_OFF, str(db.path)])
    assert killed.returncode == -9
    again = Database(db.path)
    again.open()
    with sqlite3.connect(db.path) as other:
        assert other.execute("SELECT COUNT(*) FROM session").fetchone()[0] == 0
    again.use_link(secret, now=T0)  # the link the half-write deleted is still there


def test_an_audit_id_names_a_value_without_being_it(db):
    """ADR-0012 decision 6: what the audit log calls a link or a session."""
    import hashlib
    from nervus.database import audit_id

    value, _ = db.make_link(now=T0)
    assert audit_id(value) == hashlib.sha256(value.encode()).hexdigest()[:16]
    assert value not in audit_id(value)
