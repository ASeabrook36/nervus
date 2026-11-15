"""First-run setup's choices, kept in the database (ADR-0015 consequence 1.2):
the tier the operator declares (ADR-0007 decision 2, ADR-0015 decisions A and
B) and the ranges declared internal (ADR-0015 decision C), each with who and
when, in tables added without changing the version (ADR-0014 decision F)."""

import sqlite3

import pytest

from nervus.database import SCHEMA, SCHEMA_VERSION, Database
from nervus.exposure import Declared
from nervus.first_run import FirstRun, SetupRefused, Tier

# 2026-10-20 12:00:00 UTC, and a day later.
NOON = 1792497600.0
DAY = 24 * 3600


@pytest.fixture
def first_run(tmp_path):
    database = Database(tmp_path / "nervus.db")
    database.open()
    return FirstRun(database)


def test_a_new_installation_has_no_tier_and_no_declared_range(first_run):
    assert first_run.tier() is None
    assert first_run.declared() == []


@pytest.mark.parametrize("tier", [1, 2, 3])
def test_a_tier_is_kept_with_who_chose_it_and_when(first_run, tier):
    assert first_run.choose_tier(tier, by="operator", now=NOON) is None
    assert first_run.tier() == Tier(tier=tier, chosen_at=NOON, chosen_by="operator")


def test_changing_the_tier_replaces_it_and_returns_the_one_it_replaced(first_run):
    # ADR-0015 decision B: changeable, the change audited by the caller.
    first_run.choose_tier(1, by="operator", now=NOON)
    assert first_run.choose_tier(3, by="operator", now=NOON + DAY) == Tier(1, NOON, "operator")
    assert first_run.tier() == Tier(3, NOON + DAY, "operator")


@pytest.mark.parametrize("bad", [0, 4, -1, "1", 1.0, True, None])
def test_only_tiers_one_to_three_are_kept(first_run, bad):
    with pytest.raises(SetupRefused):
        first_run.choose_tier(bad, by="operator", now=NOON)
    assert first_run.tier() is None


def test_a_declared_range_is_kept_whole_with_who_and_the_day(first_run):
    assert first_run.declare("1.2.3.0/24", by="operator", now=NOON) == "1.2.3.0/24"
    assert first_run.declared() == [Declared("1.2.3.0/24", by="operator", on="2026-10-20")]


@pytest.mark.parametrize("given, kept", [
    ("1.2.3.77/24", "1.2.3.0/24"),       # the range the address is in
    ("1.2.3.4", "1.2.3.4/32"),           # one address
    (" 1.2.3.0/24 ", "1.2.3.0/24"),
    ("2A01:4F8::/32", "2a01:4f8::/32"),
])
def test_a_range_is_kept_in_one_spelling(first_run, given, kept):
    assert first_run.declare(given, by="operator", now=NOON) == kept
    assert [d.network for d in first_run.declared()] == [kept]


@pytest.mark.parametrize("everything", ["0.0.0.0/0", "::/0", "1.2.3.4/0"])
def test_a_range_is_never_everything(first_run, everything):
    # ADR-0015 decision C: the declaration names a range, never "everything".
    with pytest.raises(SetupRefused, match="everything"):
        first_run.declare(everything, by="operator", now=NOON)
    assert first_run.declared() == []


@pytest.mark.parametrize("bad", ["", "nervus.example", "1.2.3.0/33", "1.2.3", None, 24])
def test_what_is_not_a_range_is_refused(first_run, bad):
    with pytest.raises(SetupRefused):
        first_run.declare(bad, by="operator", now=NOON)
    assert first_run.declared() == []


def test_a_range_declared_twice_is_refused_and_keeps_the_first_declaration(first_run):
    first_run.declare("1.2.3.0/24", by="operator", now=NOON)
    with pytest.raises(SetupRefused, match="already"):
        first_run.declare("1.2.3.9/24", by="operator", now=NOON + DAY)
    assert first_run.declared() == [Declared("1.2.3.0/24", by="operator", on="2026-10-20")]


def test_ranges_are_listed_in_the_order_declared(first_run):
    first_run.declare("1.2.3.0/24", by="operator", now=NOON + DAY)
    first_run.declare("5.6.7.0/24", by="operator", now=NOON)
    assert [d.network for d in first_run.declared()] == ["5.6.7.0/24", "1.2.3.0/24"]


def test_a_declaration_can_be_withdrawn(first_run):
    # ADR-0015 consequence 2: one that later matches nothing can be removed.
    first_run.declare("1.2.3.0/24", by="operator", now=NOON)
    assert first_run.withdraw("1.2.3.0/24") is True
    assert first_run.withdraw("1.2.3.0/24") is False
    assert first_run.declared() == []


def test_a_withdrawal_names_the_range_in_any_spelling(first_run):
    first_run.declare("1.2.3.0/24", by="operator", now=NOON)
    assert first_run.withdraw("1.2.3.77/24") is True


def test_a_database_from_before_gains_the_tables_and_keeps_its_version(tmp_path):
    # ADR-0014 decision F: added, not a new version, so a rollback still starts.
    path = tmp_path / "nervus.db"
    with sqlite3.connect(path) as db:
        db.executescript(SCHEMA)
        db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    database = Database(path)
    database.open()
    FirstRun(database).choose_tier(2, by="operator", now=NOON)
    with sqlite3.connect(path) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    assert FirstRun(database).tier().tier == 2


def test_a_tier_can_be_put_back_exactly_as_it_was(first_run):
    # What the UI does when a change's audit record cannot be written.
    first_run.choose_tier(1, by="operator", now=NOON)
    previous = first_run.choose_tier(3, by="operator", now=NOON + DAY)
    first_run.restore_tier(previous)
    assert first_run.tier() == Tier(1, NOON, "operator")
    first_run.restore_tier(None)
    assert first_run.tier() is None
