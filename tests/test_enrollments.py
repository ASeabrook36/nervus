"""The enrollment store (ADR-0022 step 1, decision 5a): one row per enrolled VM,
keyed by VM id, holding the address nervus reaches it at, the host keys its
guest agent reported, and when and by which token it was enrolled. Repaired
when the address moves, replaced when the VM is enrolled afresh, dropped when
the VM is gone; a repair or drop meant for keys a newer enrollment replaced
does nothing. Only addresses nervus can reach a VM at are kept, never a name."""

import importlib.util
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import asyncssh
import pytest

from nervus.database import Database
from nervus.enrollments import EnrolledVM, EnrollmentRefused, EnrollmentStore

T0 = 1_800_000_000.0
REPO = Path(__file__).resolve().parent.parent
# The release deployed now (procedures/031). Its database code is what a
# rollback would run.
PREVIOUS_RELEASE = "84dc5bd"


def _key(kind="ssh-ed25519", comment="root@vm"):
    """A host public key line as `sshd` writes it, comment included."""
    return asyncssh.generate_private_key(kind, comment=comment).export_public_key().decode().strip()


def _bare(line):
    """The key's type and base64, which is all a pin is."""
    return " ".join(line.split()[:2])


KEY_A, KEY_B = _key(), _key("ecdsa-sha2-nistp256")
KEY_C = _key()


@pytest.fixture
def database(tmp_path):
    db = Database(tmp_path / "nervus.db")
    db.open()
    return db


@pytest.fixture
def store(database):
    return EnrollmentStore(database)


def test_nothing_is_enrolled_at_first(store):
    assert store.get(123) is None
    assert store.all() == []


def test_an_enrolled_vm_is_kept_with_its_address_keys_and_who_enrolled_it(store):
    vm, replaced = store.enroll(123, "192.0.2.10", [KEY_B, KEY_A], "client-a", now=T0)
    assert replaced is None
    assert vm == EnrolledVM(vmid=123, address="192.0.2.10", host_keys=tuple(sorted([_bare(KEY_A), _bare(KEY_B)])),
                            enrolled_at=T0, enrolled_by="client-a", moved_at=None)
    assert store.get(123) == vm
    assert store.all() == [vm]


def test_it_outlives_the_store_and_the_connection(database, store):
    store.enroll(123, "192.0.2.10", [KEY_A], "t", now=T0)
    assert EnrollmentStore(Database(database.path)).get(123).address == "192.0.2.10"


def test_keys_are_kept_without_comments_once_each(store):
    vm, _ = store.enroll(123, "192.0.2.10", [KEY_A, KEY_A.rsplit(" ", 1)[0] + " other@comment"], "t", now=T0)
    assert vm.host_keys == (_bare(KEY_A),)


@pytest.mark.parametrize("given, kept", [("2001:DB8::0:1", "2001:db8::1"), ("192.0.2.010", None)])
def test_an_address_is_kept_in_one_form(store, given, kept):
    if kept is None:  # a leading zero is not an address Python reads, so not one nervus keeps
        with pytest.raises(EnrollmentRefused):
            store.enroll(123, given, [KEY_A], "t", now=T0)
        return
    vm, _ = store.enroll(123, given, [KEY_A], "t", now=T0)
    assert vm.address == kept


def test_enrolling_afresh_replaces_the_row_and_returns_what_it_replaced(store):
    first, _ = store.enroll(123, "192.0.2.10", [KEY_A], "client-a", now=T0)
    second, replaced = store.enroll(123, "192.0.2.11", [KEY_C], "claude-code", now=T0 + 60)
    assert replaced == first
    assert second.host_keys == (_bare(KEY_C),) and second.enrolled_by == "claude-code"
    assert store.all() == [second]


def test_a_moved_address_is_repaired_keeping_the_keys(store):
    store.enroll(123, "192.0.2.10", [KEY_A], "t", now=T0)
    vm = store.moved(123, (_bare(KEY_A),), "192.0.2.20", now=T0 + 5)
    assert (vm.address, vm.host_keys, vm.enrolled_at, vm.moved_at) == ("192.0.2.20", (_bare(KEY_A),), T0, T0 + 5)
    assert store.get(123) == vm


def test_a_repair_meant_for_keys_since_replaced_does_nothing(store):
    """Two calls race: one re-enrolled the VM with new keys; the other, still
    holding the old row, must not move the new one's address."""
    old, _ = store.enroll(123, "192.0.2.10", [KEY_A], "t", now=T0)
    new, _ = store.enroll(123, "192.0.2.11", [KEY_C], "t", now=T0 + 1)
    assert store.moved(123, old.host_keys, "192.0.2.99", now=T0 + 2) is None
    assert store.get(123) == new


def test_a_repair_of_a_vm_not_enrolled_does_nothing(store):
    assert store.moved(123, (_bare(KEY_A),), "192.0.2.20", now=T0) is None
    assert store.get(123) is None


def test_a_gone_vm_is_dropped(store):
    vm, _ = store.enroll(123, "192.0.2.10", [KEY_A], "t", now=T0)
    assert store.drop(123, vm.host_keys) is True
    assert store.get(123) is None
    assert store.drop(123, vm.host_keys) is False


def test_a_drop_meant_for_keys_since_replaced_does_nothing(store):
    old, _ = store.enroll(123, "192.0.2.10", [KEY_A], "t", now=T0)
    new, _ = store.enroll(123, "192.0.2.10", [KEY_C], "t", now=T0 + 1)
    assert store.drop(123, old.host_keys) is False
    assert store.get(123) == new


def test_rows_for_vms_no_longer_there_are_dropped_together(store):
    for vmid in (123, 124, 200):
        store.enroll(vmid, f"192.0.2.{vmid - 100}", [_key()], "t", now=T0)  # each machine its own host key
    assert store.keep_only({124, 999}) == [123, 200]
    assert [vm.vmid for vm in store.all()] == [124]
    assert store.keep_only({124}) == []


@pytest.mark.parametrize("address", [
    "vm-123.example",  # a name: nervus never asks DNS for a VM (ADR-0022 question 9)
    "",
    "127.0.0.1",       # the VM's own loopback, which from nervus is nervus's machine
    "::1",
    "0.0.0.0",
    "169.254.10.2",    # link-local: unreachable without saying which interface
    "fe80::1",
    "fe80::1%eth0",
    "224.0.0.1",
    "ff02::1",
    3_221_226_010,     # 192.0.2.26 as a number, which ipaddress would take
])
def test_an_address_nervus_cannot_reach_a_vm_at_is_never_kept(store, address):
    with pytest.raises(EnrollmentRefused) as refused:
        store.enroll(123, address, [KEY_A], "t", now=T0)
    assert refused.value.code == "bad_address"
    assert store.get(123) is None


def test_a_repair_to_an_address_nervus_cannot_reach_is_refused(store):
    store.enroll(123, "192.0.2.10", [KEY_A], "t", now=T0)
    with pytest.raises(EnrollmentRefused) as refused:
        store.moved(123, (_bare(KEY_A),), "127.0.0.1", now=T0)
    assert refused.value.code == "bad_address"
    assert store.get(123).address == "192.0.2.10"


@pytest.mark.parametrize("keys", [
    [],
    ["not a key"],
    ["ssh-ed25519 AAAA"],
    [asyncssh.generate_private_key("ssh-ed25519").export_private_key().decode()],
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI",  # one string, not a list of them
    [KEY_A, None],
])
def test_only_host_public_keys_are_pinned(store, keys):
    with pytest.raises(EnrollmentRefused) as refused:
        store.enroll(123, "192.0.2.10", keys, "t", now=T0)
    assert refused.value.code == "bad_host_keys"
    assert store.get(123) is None


@pytest.mark.parametrize("vmid", [99, 0, -1, 1_000_000_000, True, "123", 123.0, None])
def test_only_a_proxmox_vm_id_is_a_key(store, vmid):
    with pytest.raises(EnrollmentRefused) as refused:
        store.enroll(vmid, "192.0.2.10", [KEY_A], "t", now=T0)
    assert refused.value.code == "bad_vmid"
    for ask in (store.get, lambda v: store.moved(v, (_bare(KEY_A),), "192.0.2.10"),
                lambda v: store.drop(v, (_bare(KEY_A),))):
        with pytest.raises(EnrollmentRefused):
            ask(vmid)


@pytest.mark.parametrize("token_id", ["", None, 7])
def test_an_enrollment_names_the_token_that_made_it(store, token_id):
    with pytest.raises(EnrollmentRefused) as refused:
        store.enroll(123, "192.0.2.10", [KEY_A], token_id, now=T0)
    assert refused.value.code == "bad_token"


def test_the_table_is_added_without_changing_the_version(database):
    with sqlite3.connect(database.path) as check:
        assert check.execute("PRAGMA user_version").fetchone()[0] == 1
        assert check.execute("SELECT COUNT(*) FROM enrolled_vm").fetchone()[0] == 0


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


def test_the_release_before_still_opens_a_database_with_enrollments(database, store, tmp_path):
    """A deploy that rolls back runs the deployed release against the
    database this one left."""
    vm, _ = store.enroll(123, "192.0.2.10", [KEY_A], "t", now=T0)
    previous = _previous_database_module(tmp_path)
    rolled_back = previous.Database(database.path)
    rolled_back.open()
    link, _ = rolled_back.make_link(now=T0)
    rolled_back.use_link(link, now=T0)
    database.open()
    assert store.get(123) == vm


# --- a VM cannot alias itself to another machine nervus knows (procedure 056, finding 2) ---
#
# A root-compromised VM can make its guest agent report another machine's real host keys
# and address. That machine, trusting nervus's CA, would answer the enrollment check, so the
# VM would be enrolled pointing at it and reached outside the token's allowlist. A reported
# key that already belongs to a machine nervus knows under another identity is refused.


def test_a_vm_cannot_enroll_with_another_enrolled_vms_host_key(store):
    store.enroll(123, "192.0.2.10", [KEY_A], "client-a", now=T0)
    with pytest.raises(EnrollmentRefused) as exc:
        store.enroll(456, "192.0.2.99", [KEY_A], "attacker", now=T0 + 1)
    assert exc.value.code == "host_key_in_use"
    assert store.get(456) is None
    assert store.get(123).address == "192.0.2.10"


def test_re_enrolling_the_same_vm_with_its_own_keys_is_allowed(store):
    store.enroll(123, "192.0.2.10", [KEY_A, KEY_B], "t", now=T0)
    vm, replaced = store.enroll(123, "192.0.2.11", [KEY_A, KEY_B], "t", now=T0 + 1)
    assert vm.address == "192.0.2.11" and replaced is not None


def test_a_vm_cannot_enroll_with_an_enrolled_hosts_host_key(database, store):
    from nervus.enrolled_hosts import EnrolledHostStore
    hosts = EnrolledHostStore(database)
    hosts.add("box", address="192.0.2.5", level="full", host_keys=[KEY_A], machine_id="a" * 32, enrolled_by="op")
    with pytest.raises(EnrollmentRefused) as exc:
        store.enroll(456, "192.0.2.99", [KEY_A], "attacker", now=T0)
    assert exc.value.code == "host_key_in_use"
    assert store.get(456) is None
