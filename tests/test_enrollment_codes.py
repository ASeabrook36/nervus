"""One-time enrollment codes (ADR-0024 step 3, decision 2): made in the UI for a
machine's name, address and level; only a hash kept; good for 15 minutes; the
script fetched with it any number of times in that time, the report back
accepted once; what became of it kept for the UI to show. A code made from
nervus's page also keeps the account it logs in as and the host key that
answered (ADR-0026 step 1), never a password."""

import sqlite3

import asyncssh
import pytest

from nervus.database import Database
from nervus.enrollment_codes import CODE_SECONDS, CodeLogin, EnrollmentCodes
from nervus.enrollments import host_keys
from nervus.enrolled_hosts import HostRefused

T0 = 1_800_000_000.0
KEY = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode().strip()
OTHER = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode().strip()


@pytest.fixture
def codes(tmp_path):
    db = Database(tmp_path / "nervus.db")
    db.open()
    return EnrollmentCodes(db)


def _make(codes, **kw):
    args = dict(name="web", address="192.0.2.10", level="read-only", made_by="operator", now=T0)
    args.update(kw)
    return codes.make(**args)


def test_a_code_names_what_it_will_enroll_and_expires_in_15_minutes(codes):
    value, code = _make(codes)
    assert CODE_SECONDS == 15 * 60
    assert (code.name, code.address, code.level, code.made_at, code.expires_at) == (
        "web", "192.0.2.10", "read-only", T0, T0 + CODE_SECONDS)
    assert len(value) >= 32 and code.used_at is None and code.outcome is None


def test_only_its_hash_is_kept(codes):
    value, _ = _make(codes)
    with sqlite3.connect(codes.database.path) as db:
        dump = "\n".join(db.iterdump())
    assert value not in dump


def test_it_can_be_found_until_it_expires(codes):
    value, code = _make(codes)
    assert codes.find(value, now=T0 + CODE_SECONDS - 1) == code
    assert codes.find(value, now=T0 + CODE_SECONDS) is None
    assert codes.find("not-a-code", now=T0) is None


def test_it_is_spent_once(codes):
    value, _ = _make(codes)
    first = codes.spend(value, now=T0 + 60)
    assert first is not None and first.used_at == T0 + 60
    assert codes.spend(value, now=T0 + 61) is None
    assert codes.find(value, now=T0 + 62) is None  # nor fetched again


def test_an_expired_code_is_never_spent(codes):
    value, _ = _make(codes)
    assert codes.spend(value, now=T0 + CODE_SECONDS) is None


def test_what_became_of_it_is_kept_for_the_ui(codes):
    value, code = _make(codes)
    codes.spend(value, now=T0)
    codes.finish(code.id, "enrolled web, read-only")
    assert codes.get(code.id).outcome == "enrolled web, read-only"


@pytest.mark.parametrize("field, bad, refused", [
    ("name", "Web Host", "bad_name"),
    ("address", "http://web", "bad_address"),
    ("level", "root", "bad_level"),
])
def test_it_is_made_only_for_what_can_be_enrolled(codes, field, bad, refused):
    with pytest.raises(HostRefused) as exc:
        _make(codes, **{field: bad})
    assert exc.value.code == refused


def test_never_for_a_name_hosts_yaml_has(codes):
    with pytest.raises(HostRefused) as exc:
        _make(codes, reserved={"web"})
    assert exc.value.code == "name_taken"


def test_the_table_is_added_without_changing_the_version(codes):
    with sqlite3.connect(codes.database.path) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM enrollment_code").fetchone()[0] == 0


def test_left_blank_the_address_is_taken_from_the_report(codes):
    """Decision 4a: pre-filled with the address the enrollment request came
    from, which the owner may change."""
    _, code = _make(codes, address="")
    assert code.address == ""


def test_the_ui_lists_the_latest_codes_first(codes):
    _make(codes, name="a", now=T0)
    _make(codes, name="b", now=T0 + 1)
    assert [c.name for c in codes.recent(now=T0 + 2)] == ["b", "a"]


def test_codes_a_day_past_their_expiry_are_dropped(codes):
    _make(codes, name="old", now=T0)
    _make(codes, name="new", now=T0 + CODE_SECONDS + 24 * 3600)
    assert [c.name for c in codes.recent(now=T0 + CODE_SECONDS + 24 * 3600)] == ["new"]


def test_a_cancelled_code_fetches_and_reports_nothing(codes):
    value, code = _make(codes)
    codes.cancel(code.id, now=T0 + 1)
    assert codes.find(value, now=T0 + 2) is None and codes.spend(value, now=T0 + 2) is None


# --- the login beside a code (ADR-0026 step 1) ------------------------------------------

def _rows(codes, table):
    with sqlite3.connect(codes.database.path) as db:
        return db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def test_a_code_made_with_a_login_keeps_the_account_and_the_key_as_host_keys_keeps_it(codes):
    _, code = _make(codes, login="alice", host_key=KEY + " comment")
    kept = codes.login_of(code.id)
    assert kept == CodeLogin("alice", host_keys([KEY])[0])
    assert " " not in kept.host_key.split(" ", 1)[1] and "comment" not in kept.host_key


@pytest.mark.parametrize("login", ["root", "svc_user", "a.b-c", "_x", "A1", "a" + "b" * 31])
def test_the_accounts_a_machine_can_have_are_taken(codes, login):
    _, code = _make(codes, login=login, host_key=KEY)
    assert codes.login_of(code.id).login == login


def test_a_code_made_without_a_login_has_none(codes):
    _, code = _make(codes)
    assert codes.login_of(code.id) is None and _rows(codes, "enrollment_login") == 0
    assert codes.login_of("no-such-code") is None


@pytest.mark.parametrize("given", [dict(login="alice"), dict(host_key=KEY)])
def test_one_of_the_account_and_the_key_without_the_other_is_refused_and_nothing_is_made(codes, given):
    with pytest.raises(HostRefused) as exc:
        _make(codes, **given)
    assert exc.value.code == "bad_login"
    assert codes.recent(now=T0) == [] and _rows(codes, "enrollment_login") == 0


@pytest.mark.parametrize("login", ["", "-lead", "has space", "root\n", "a" * 33, "with/slash", "caf\u00e9", 5])
def test_an_account_name_that_is_not_one_is_refused_and_nothing_is_made(codes, login):
    with pytest.raises(HostRefused) as exc:
        _make(codes, login=login, host_key=KEY)
    assert exc.value.code == "bad_login"
    assert codes.recent(now=T0) == [] and _rows(codes, "enrollment_login") == 0


@pytest.mark.parametrize("key", [
    "", "not a key", 5,
    asyncssh.generate_private_key("ssh-ed25519").export_private_key().decode(),
    KEY + "\n" + OTHER,  # host_keys alone keeps the first and drops the rest
    "\n" + KEY + "\n" + OTHER + "\n",
])
def test_a_host_key_that_is_not_exactly_one_key_is_refused_and_nothing_is_made(codes, key):
    with pytest.raises(HostRefused) as exc:
        _make(codes, login="alice", host_key=key)
    assert exc.value.code == "bad_host_keys"
    assert codes.recent(now=T0) == [] and _rows(codes, "enrollment_login") == 0


def test_a_key_with_a_trailing_newline_is_one_key(codes):
    _, code = _make(codes, login="alice", host_key=KEY + "\n")
    assert codes.login_of(code.id).host_key == host_keys([KEY])[0]


def test_a_code_purged_takes_its_login_with_it(codes):
    _, old = _make(codes, name="old", login="alice", host_key=KEY, now=T0)
    _, kept = _make(codes, name="kept", login="bob", host_key=OTHER, now=T0 + CODE_SECONDS + 24 * 3600 - 1)
    assert codes.login_of(old.id) is not None  # a day past its expiry has not yet passed
    _make(codes, name="new", now=T0 + CODE_SECONDS + 24 * 3600)
    assert codes.get(old.id) is None and codes.login_of(old.id) is None
    assert codes.login_of(kept.id) == CodeLogin("bob", host_keys([OTHER])[0])
    assert _rows(codes, "enrollment_login") == 1


def test_a_login_with_no_code_is_swept_too(codes):
    """A row left by anything else that removed its code is cleared at the next making."""
    with sqlite3.connect(codes.database.path) as db:
        db.execute("INSERT INTO enrollment_login (code_id, login, host_key) VALUES ('orphan', 'x', 'y')")
    _make(codes)
    assert codes.login_of("orphan") is None


def test_a_database_made_before_the_table_gains_it_when_opened_and_keeps_its_codes(tmp_path):
    first = Database(tmp_path / "old.db")
    first.open()
    codes = EnrollmentCodes(first)
    value, code = _make(codes, now=T0)
    with sqlite3.connect(first.path) as db:
        db.execute("DROP TABLE enrollment_login")  # as a release before this one left it
    reopened = Database(tmp_path / "old.db")
    reopened.open()
    codes = EnrollmentCodes(reopened)
    with sqlite3.connect(reopened.path) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 1
    assert _rows(codes, "enrollment_login") == 0
    assert codes.find(value, now=T0 + 1) == code and codes.login_of(code.id) is None
    _, again = _make(codes, name="again", login="alice", host_key=KEY, now=T0 + 2)
    assert codes.login_of(again.id).login == "alice"
