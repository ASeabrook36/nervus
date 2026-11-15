"""The enrolled-host store (ADR-0024 step 2, decision 3): one row per machine
enrolled from the web UI, its name, the address nervus uses, its level, its
pinned host keys, its machine id, and when and by whom; a hand-written
hosts.yaml entry's name is never taken."""

import shutil
import sqlite3
import subprocess
import importlib.util
import sys
from pathlib import Path

import asyncssh
import pytest

from nervus.database import Database
from nervus.enrolled_hosts import LEVELS, EnrolledHost, EnrolledHostStore, HostRefused

T0 = 1_800_000_000.0
REPO = Path(__file__).resolve().parent.parent
PREVIOUS_RELEASE = "2161c24"  # deployed by procedure 034; a rollback runs its database code
MACHINE = "0123456789abcdef0123456789abcdef"


def _key(kind="ssh-ed25519"):
    return asyncssh.generate_private_key(kind, comment="root@host").export_public_key().decode().strip()


KEY_A, KEY_B = _key(), _key("ecdsa-sha2-nistp256")


def _bare(line):
    return " ".join(line.split()[:2])


@pytest.fixture
def database(tmp_path):
    db = Database(tmp_path / "nervus.db")
    db.open()
    return db


@pytest.fixture
def store(database):
    return EnrolledHostStore(database)


def _add(store, name="web", **kw):
    args = dict(address="192.0.2.10", level="read-only", host_keys=[KEY_A], machine_id=MACHINE,
                enrolled_by="operator", now=T0)
    args.update(kw)
    return store.add(name, **args)


def test_nothing_is_enrolled_at_first(store):
    assert store.get("web") is None and store.all() == []


def test_a_machine_is_kept_with_everything_enrollment_learned(store):
    row, replaced = _add(store, host_keys=[KEY_B, KEY_A])
    assert replaced is None
    assert row == EnrolledHost(name="web", address="192.0.2.10", level="read-only",
                               host_keys=tuple(sorted([_bare(KEY_A), _bare(KEY_B)])), machine_id=MACHINE,
                               enrolled_at=T0, enrolled_by="operator")
    assert store.get("web") == row and store.all() == [row]


def test_it_outlives_the_store_and_the_connection(database, store):
    _add(store)
    assert EnrolledHostStore(Database(database.path)).get("web").address == "192.0.2.10"


def test_enrolling_again_replaces_the_row_and_returns_what_it_replaced(store):
    first, _ = _add(store)
    second, replaced = _add(store, level="full", host_keys=[KEY_B], now=T0 + 60)
    assert replaced == first and second.level == "full" and store.all() == [second]


def test_a_removed_machine_is_forgotten(store):
    _add(store)
    assert store.remove("web") is True and store.get("web") is None
    assert store.remove("web") is False


def test_the_levels_are_the_three_adr_0024_decided():
    assert LEVELS == ("read-only", "standard", "full")


@pytest.mark.parametrize("level", ["readonly", "root", "", None, "FULL"])
def test_only_a_known_level_is_kept(store, level):
    with pytest.raises(HostRefused) as refused:
        _add(store, level=level)
    assert refused.value.code == "bad_level" and store.get("web") is None


@pytest.mark.parametrize("name", ["", "Web", "web host", "-web", "web/1", "w" * 64, None, 7])
def test_only_a_plain_name_is_kept(store, name):
    with pytest.raises(HostRefused) as refused:
        _add(store, name=name)
    assert refused.value.code == "bad_name"


def test_a_name_hosts_yaml_has_is_never_taken(store):
    with pytest.raises(HostRefused) as refused:
        _add(store, name="in-hosts-yaml", reserved={"in-hosts-yaml"})
    assert refused.value.code == "name_taken" and "hosts.yaml" in refused.value.message


@pytest.mark.parametrize("address, kept", [("192.0.2.10", "192.0.2.10"), ("2001:DB8::1", "2001:db8::1"),
                                           ("web.home.example.net", "web.home.example.net"),
                                           ("Web.Example.NET", "web.example.net")])
def test_an_address_is_an_ip_or_a_dns_name_in_one_form(store, address, kept):
    row, _ = _add(store, address=address)
    assert row.address == kept


@pytest.mark.parametrize("address", ["", "web host", "http://web", "web:22", "-web", None, 3221226010])
def test_anything_else_is_not_an_address(store, address):
    with pytest.raises(HostRefused) as refused:
        _add(store, address=address)
    assert refused.value.code == "bad_address"


@pytest.mark.parametrize("keys", [[], ["not a key"], "ssh-ed25519 AAAA", [KEY_A, None]])
def test_only_host_public_keys_are_pinned(store, keys):
    with pytest.raises(HostRefused) as refused:
        _add(store, host_keys=keys)
    assert refused.value.code == "bad_host_keys"


@pytest.mark.parametrize("machine_id", ["", "xyz", MACHINE.upper(), MACHINE + "0", None])
def test_a_machine_id_is_what_etc_machine_id_holds(store, machine_id):
    with pytest.raises(HostRefused) as refused:
        _add(store, machine_id=machine_id)
    assert refused.value.code == "bad_machine_id"


def test_as_a_host_it_is_agent_at_its_address_with_its_keys_and_level(store):
    row, _ = _add(store, level="standard")
    host = row.as_host()
    assert (host.name, host.address, host.agent_user, host.status) == ("web", "192.0.2.10", "agent", "onboarded")
    assert host.host_keys == row.host_keys and host.level == "standard"
    assert host.hypervisor is None and host.never_issued is False


def test_the_table_is_added_without_changing_the_version(database):
    with sqlite3.connect(database.path) as check:
        assert check.execute("PRAGMA user_version").fetchone()[0] == 1
        assert check.execute("SELECT COUNT(*) FROM enrolled_host").fetchone()[0] == 0


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
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        del sys.modules[spec.name]
    return module


def test_the_release_before_still_opens_a_database_with_enrolled_hosts(database, store, tmp_path):
    row, _ = _add(store)
    rolled_back = _previous_database_module(tmp_path).Database(database.path)
    rolled_back.open()
    link, _ = rolled_back.make_link(now=T0)
    rolled_back.use_link(link, now=T0)
    database.open()
    assert store.get("web") == row


def test_a_machine_that_moved_keeps_its_keys_at_its_new_address(store):
    """Decision 4a: if it moves, the page lets the owner change the address;
    the pinned keys stay."""
    row, _ = _add(store)
    assert store.move("web", "192.0.2.11") is True
    moved = store.get("web")
    assert moved.address == "192.0.2.11" and moved.host_keys == row.host_keys and moved.level == row.level
    assert store.move("nothing", "192.0.2.11") is False


def test_a_move_takes_only_an_address(store):
    _add(store)
    with pytest.raises(HostRefused) as refused:
        store.move("web", "http://web")
    assert refused.value.code == "bad_address" and store.get("web").address == "192.0.2.10"
