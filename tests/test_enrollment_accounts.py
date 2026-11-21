"""ADR-0031 step 5: enrollment makes both accounts, and nervus checks and
records them.

- **The script** makes the read-write account at standard or full and the
  read-only one at every level, by the names the form gave; tries the read-only
  shell as the read-only account before its line; where the sandbox cannot
  start, adds a machine at standard or full read-write alone and says why
  (question 5), and refuses at read-only; never uses root or a system account;
  takes nervus's line off the accounts nervus used there before, and nothing
  else of theirs; and, for a machine described by hand, makes the read-only
  account alone and changes nothing else (question 4).
- **The codes** keep the accounts, nervus's names by default.
- **The route** serves the script with them, refuses a code an older release
  made, logs in as each account, and records what it found, tied to the
  enrollment; a machine described by hand is checked as nervus reaches it.
- **The form** carries the names, and asks before a name other than nervus's own.
"""

import json
import re

import pytest

from nervus import accounts
from nervus.accounts import MachineAccounts
from nervus.enrolled_hosts import HostRefused, merged
from nervus.enrollment_codes import READONLY_ACCOUNT

from nervus.host_enrollment import remove_commands, remove_readonly_commands
from test_host_enrollment_script import (KEY, RO, RW, Machine, enroll_script, PIN, URL,  # noqa: F401
                                         READONLY_SHELL_PATH)
from test_host_enrollment_route import CHECK_READONLY, World as RouteWorld  # noqa: F401
from test_ui_machines import World as PageWorld, _lines


# --- the script -------------------------------------------------------------------------------------


@pytest.fixture
def machine(tmp_path):
    return Machine(tmp_path)


def _report(machine):
    return (machine.w / "report").read_text().splitlines()


@pytest.mark.parametrize("level", ["standard", "full"])
def test_where_the_sandbox_cannot_start_standard_and_full_are_added_read_write_alone(machine, level):
    done = machine.run(level, SU_FAILS="1")
    assert done.returncode == 0, done.stderr
    assert machine.keys == f"cert-authority {KEY}\n" and machine.readonly_keys is None
    assert "this machine cannot have a read-only account: bubblewrap cannot run here (" in done.stdout
    assert f"It is added with {RW} alone, read-write" in done.stdout
    assert any(line.startswith("nervus-readonly-none bubblewrap cannot run here") for line in _report(machine))


def test_without_bubblewrap_or_apt_get_full_is_added_read_write_alone(tmp_path):
    machine = Machine(tmp_path, installed=("sudo", "visudo", "tmux"))
    machine.without("apt-get")
    done = machine.run("full")
    assert done.returncode == 0, done.stderr
    assert "bwrap is missing and there is no apt-get here to install bubblewrap" in done.stdout
    assert machine.sudoers.exists() and machine.readonly_keys is None


def test_where_the_sandbox_cannot_start_read_only_is_still_refused(machine):
    done = machine.run("read-only", SU_FAILS="1")
    assert done.returncode == 1 and "so this machine cannot be read-only" in done.stderr
    assert machine.readonly_keys is None


def test_the_report_says_nothing_of_the_read_only_account_where_it_was_made(machine):
    assert machine.run("standard").returncode == 0
    assert not any(line.startswith("nervus-readonly-none") for line in _report(machine))


@pytest.mark.parametrize("uid", [0, 999])
def test_root_and_the_machine_s_system_accounts_are_refused_before_anything_changes(machine, uid):
    machine.add_user(RO, uid=uid)
    done = machine.run("standard")
    assert done.returncode == 1 and "system accounts" in done.stderr and "Nothing here was changed" in done.stderr
    assert not machine.exists(RW) and machine.readonly_keys is None and not machine.shell.exists()


@pytest.mark.parametrize("uid", [60001, 65534, 65535, 4294967294])
def test_the_accounts_a_machine_keeps_for_itself_above_uid_max_are_refused_too(machine, uid):
    """Procedure 068, section 13: above UID_MAX, up to 65535, a machine keeps accounts for itself, nobody (65534)
    among them, and systemd's dynamic users; the last two uids are never an account."""
    machine.add_user(RO, uid=uid)
    done = machine.run("standard")
    assert done.returncode == 1 and f"system accounts (uid {uid})" in done.stderr, done.stderr
    assert "Nothing here was changed" in done.stderr and not machine.exists(RW)


@pytest.mark.parametrize("uid", [1000, 60000, 65536, 1234567])
def test_an_ordinary_account_a_directory_s_included_is_used(machine, uid):
    """From 65536, a directory's ordinary accounts, as SSSD gives them."""
    machine.add_user(RO, uid=uid)
    assert machine.run("standard").returncode == 0


def test_the_login_defs_uid_max_is_the_upper_line(machine):
    (machine.root / "etc/login.defs").write_text("UID_MIN 1000\nUID_MAX\t30000\n")
    machine.add_user(RO, uid=30001)
    done = machine.run("standard")
    assert done.returncode == 1 and "system accounts (uid 30001)" in done.stderr


def test_the_login_defs_uid_min_is_the_line(machine):
    (machine.root / "etc/login.defs").write_text("# a comment\nUID_MIN\t\t 500\n")
    machine.add_user(RO, uid=600)
    assert machine.run("standard").returncode == 0


def test_names_root_is_never_written_into_a_script():
    with pytest.raises(ValueError):
        enroll_script(name="web", level="standard", origin="o", url=URL, pin=PIN, key=KEY, readonly="root")
    with pytest.raises(ValueError):
        enroll_script(name="web", level="standard", origin="o", url=URL, pin=PIN, key=KEY, readwrite="x", readonly="x")


@pytest.mark.parametrize("level", ["read-only", "standard", "full"])
def test_nervus_s_line_is_taken_off_an_account_it_used_before_and_nothing_else_of_it(machine, level):
    machine.add_user("agent", keys=f"cert-authority {KEY}\nssh-ed25519 AAAAtheowner own\n")
    machine.legacy_sudoers.write_text("agent ALL=(ALL) NOPASSWD: ALL\n")
    done = machine.run(level, script_args={"off": ["agent"]})
    assert done.returncode == 0, done.stderr
    assert machine.keys_of("agent") == "ssh-ed25519 AAAAtheowner own\n"
    assert "took nervus's line off agent, which nervus used here before" in done.stdout
    # The sudoers file nervus wrote for agent is gone, and the new account has its own at full.
    assert not machine.legacy_sudoers.exists()
    assert (machine.sudoers.read_text() == f"{RW} ALL=(ALL) NOPASSWD: ALL\n") if level == "full" \
        else not machine.sudoers.exists()


@pytest.mark.parametrize("level", ["read-only", "standard", "full"])
def test_another_account_s_sudoers_line_is_left_as_it_is(machine, level):
    """Procedure 068: a VM nervus uses by its id has `agent` with /etc/sudoers.d/nervus-agent. Added from
    the web page as well, with nervus's names, that file stays as it is: only accounts nervus used here
    for this machine lose theirs (`off`)."""
    machine.add_user("agent", keys=f"cert-authority {KEY}\n")
    machine.legacy_sudoers.write_text("agent ALL=(ALL) NOPASSWD: ALL\n")
    assert machine.run(level).returncode == 0
    assert machine.legacy_sudoers.read_text() == "agent ALL=(ALL) NOPASSWD: ALL\n"
    assert machine.keys_of("agent") == f"cert-authority {KEY}\n"


def test_an_account_that_does_not_trust_nervus_is_left_as_it_is(machine):
    machine.add_user("agent", keys="ssh-ed25519 AAAAtheowner own\n")
    done = machine.run("standard", script_args={"off": ["agent"]})
    assert done.returncode == 0, done.stderr
    assert machine.keys_of("agent") == "ssh-ed25519 AAAAtheowner own\n" and "took nervus's line off" not in done.stdout


def test_read_only_alone_again_takes_the_read_write_account_s_line_off(machine):
    assert machine.run("full").returncode == 0 and machine.keys_of(RW) == f"cert-authority {KEY}\n"
    done = machine.run("read-only", script_args={"off": [RW]})
    assert done.returncode == 0, done.stderr
    assert machine.keys_of(RW) == "" and not machine.sudoers.exists()
    assert machine.readonly_keys == f'cert-authority,restrict,command="{READONLY_SHELL_PATH}" {KEY}\n'


def _hand(machine, **env):
    script = machine.w / "nervus-enroll.sh"
    script.write_text(enroll_script(name="node-a", level=READONLY_ACCOUNT, origin="https://n:8000", url=URL, pin=PIN,
                                    key=KEY, kind=READONLY_ACCOUNT))
    import shutil
    import subprocess
    base = {"PATH": str(machine.bin), "W": str(machine.w), "NERVUS_ENROLL_ROOT": str(machine.root), "LANG": "C"}
    return subprocess.run([shutil.which("sh"), str(script)], capture_output=True, text=True, env={**base, **env},
                          timeout=30)


def test_a_machine_described_by_hand_gains_the_read_only_account_alone_and_nothing_else_changes(machine):
    machine.add_user("agent", keys=f"cert-authority {KEY}\n")
    machine.legacy_sudoers.write_text("agent ALL=(ALL) NOPASSWD: ALL\n")
    done = _hand(machine)
    assert done.returncode == 0, done.stderr
    assert machine.keys_of(RO) == f'cert-authority,restrict,command="{READONLY_SHELL_PATH}" {KEY}\n'
    assert machine.keys_of("agent") == f"cert-authority {KEY}\n"  # the account it is described with, as it was
    assert machine.legacy_sudoers.read_text() == "agent ALL=(ALL) NOPASSWD: ALL\n"
    assert not machine.exists(RW)
    head = (machine.w / "nervus-enroll.sh").read_text().split("\nset -u\n")[0]
    assert f"give node-a the read-only account {RO}" in head and "not sudo" in head


def test_a_machine_described_by_hand_where_the_sandbox_cannot_start_gains_nothing(machine):
    done = _hand(machine, SU_FAILS="1")
    assert done.returncode == 1 and "cannot be a read-only account here. Nothing was added." in done.stderr
    assert machine.keys_of(RO) is None


# --- the codes --------------------------------------------------------------------------------------


def test_a_code_keeps_the_accounts_nervus_s_names_by_default(tmp_path):
    world = PageWorld(tmp_path)
    _, code = world.codes.make(name="nas", address="", level="full", made_by="operator")
    made = world.codes.accounts_of(code.id)
    assert (made.kind, made.readwrite, made.readonly, made.off) == ("machine", RW, RO, ())
    _, code = world.codes.make(name="nas", address="", level="read-only", made_by="operator", off=["agent", RW])
    made = world.codes.accounts_of(code.id)
    assert (made.readwrite, made.readonly, made.off) == (None, RO, ("agent", RW))


@pytest.mark.parametrize("names", [{"readonly": "root"}, {"readwrite": "Bad Name"}, {"readwrite": "x", "readonly": "x"}])
def test_a_code_with_accounts_nervus_does_not_use_is_not_made(tmp_path, names):
    world = PageWorld(tmp_path)
    with pytest.raises(HostRefused):
        world.codes.make(name="nas", address="", level="standard", made_by="operator", **names)


def test_a_read_only_account_code_is_made_only_for_a_machine_described_by_hand(tmp_path):
    world = PageWorld(tmp_path)
    _, code = world.codes.make_readonly_account(name="node-a", made_by="operator", described={"node-a"})
    assert code.level == READONLY_ACCOUNT and world.codes.accounts_of(code.id).kind == READONLY_ACCOUNT
    with pytest.raises(HostRefused):
        world.codes.make_readonly_account(name="nas", made_by="operator", described={"node-a"})


# --- the route ------------------------------------------------------------------------------------


@pytest.fixture
def route(tmp_path, ca_ssh_server, monkeypatch):
    world = RouteWorld(tmp_path, ca_ssh_server, monkeypatch)
    world.enrollment.machine_accounts = world.machine_accounts = MachineAccounts(world.codes.database)
    yield world
    world.home.chmod(0o700)


async def test_the_script_is_served_with_the_code_s_accounts(route):
    value, _ = route.codes.make(name="web", address="127.0.0.1", level="standard", made_by="operator",
                                readwrite="svc-nervus", readonly="svc-nervus-ro", off=["agent"])
    script = (await route.get(value)).text
    assert "rw=svc-nervus ro=svc-nervus-ro off=agent" in script


async def test_a_code_an_older_release_made_is_refused_at_fetch_and_report(route):
    value, code = route.make("standard")
    with route.codes.database.transaction() as db:
        db.execute("DELETE FROM enrollment_accounts")
    assert (await route.get(value)).status_code == 409
    answer = await route.post(value)
    assert answer.status_code == 409 and "release of nervus before this one" in answer.text
    assert route.store.get("web") is None


async def test_both_accounts_are_recorded_tied_to_the_enrollment(route):
    value, _ = route.make("full")
    route.play("full")
    answer = await route.post(value)
    assert answer.status_code == 200, answer.text
    row, kept = route.store.get("web"), route.machine_accounts.get("web")
    assert (kept.enrolled_at, kept.readwrite, kept.readonly, kept.why_none) == (row.enrolled_at, RW, RO, None)
    assert route.logins == [RW, RO]
    assert route.records[-1]["readwrite"] == RW and route.records[-1]["readonly"] == RO


async def test_a_machine_that_could_not_have_one_is_recorded_read_write_alone_saying_why(route):
    value, _ = route.make("standard")
    body = (f"machine-id 0123456789abcdef0123456789abcdef\nnervus-readonly-none bubblewrap cannot run here (x)\n"
            f"{route.host_key}\n")
    answer = await route.post(value, body=body)
    assert answer.status_code == 200, answer.text
    assert "It has no read-only account (bubblewrap cannot run here (x))" in answer.text
    kept = route.machine_accounts.get("web")
    assert (kept.readwrite, kept.readonly, kept.why_none) == (RW, None, "bubblewrap cannot run here (x)")
    assert route.logins == [RW]  # nothing to check as the read-only account
    assert route.records[-1]["readonly_none"] == "bubblewrap cannot run here (x)"


async def test_a_machine_s_reason_for_no_read_only_account_is_kept_short_and_printable(route):
    """Procedure 068, section 13: the reason comes from the machine, which may say anything up to the report's
    64 KiB. nervus keeps what its own script sends at most, 300 characters, any unprintable one shown as "?",
    in its record, its audit result and its answer alike."""
    value, _ = route.make("standard")
    why = "bwrap \x1b[31mfailed\x07 " + "x" * 5000
    body = f"machine-id {MID}\nnervus-readonly-none {why}\n{route.host_key}\n"
    answer = await route.post(value, body=body)
    assert answer.status_code == 200, answer.text
    kept = route.machine_accounts.get("web").why_none
    assert len(kept) == 300 and kept.startswith("bwrap ?[31mfailed? x")
    assert route.records[-1]["readonly_none"] == kept and kept in answer.text and "\x1b" not in answer.text


async def test_read_only_alone_without_its_account_is_refused(route):
    value, _ = route.make("read-only")
    route.play("read-only")
    body = f"machine-id 0123456789abcdef0123456789abcdef\nnervus-readonly-none no bwrap\n{route.host_key}\n"
    answer = await route.post(value, body=body)
    assert answer.status_code == 422 and route.store.get("web") is None


async def test_a_read_only_account_that_can_write_is_not_added(route):
    value, _ = route.make("standard")
    route.ro_writes = True
    answer = await route.post(value)
    assert answer.status_code == 422 and "read-only shell is not in force" in answer.text
    assert route.store.get("web") is None and route.machine_accounts.get("web") is None


async def test_its_groups_are_kept_as_nervus_saw_them(route):
    value, _ = route.make("standard")
    (route.bin / ".groups").write_text("adm systemd-journal\n")
    assert (await route.post(value)).status_code == 200
    assert route.machine_accounts.get("web").groups == ("adm", "systemd-journal")


async def test_groups_whose_names_are_not_account_names_are_kept_as_shown(route):
    """Procedure 068, section 12: a group is only shown, so a name nervus would not give an account, such
    as a group id with no name, as `id -Gn` prints it, or a directory's, is kept as it is, not refused
    after the machine was stored."""
    value, _ = route.make("standard")
    (route.bin / ".groups").write_text("1005 Domain users@corp.example\n")
    answer = await route.post(value)
    assert answer.status_code == 200, answer.text
    assert route.machine_accounts.get("web").groups == ("1005", "Domain", "users@corp.example")


def _accounts_unwritable(route):
    """The machine_account table refuses every write from here on, as a full disk or a fault would."""
    with route.codes.database.transaction() as db:
        db.execute("CREATE TRIGGER no_accounts BEFORE INSERT ON machine_account "
                   "BEGIN SELECT RAISE(ABORT, 'refused by the test'); END")


@pytest.mark.parametrize("level", ["standard", "read-only"])
async def test_where_the_accounts_cannot_be_recorded_the_machine_is_not_added(route, level):
    """Procedure 068, section 12: the machine and its accounts are kept together or not at all. A machine
    kept without the record of its accounts reads as one added before this release, through `agent`."""
    value, code = route.make(level)
    route.play(level)
    _accounts_unwritable(route)
    answer = await route.post(value)
    assert answer.status_code == 500 and "did not add the machine" in answer.text
    assert route.store.get("web") is None and route.machine_accounts.get("web") is None
    assert route.codes.get(code.id).outcome.startswith("refused: ")
    assert "did not add the machine" in route.records[-1]["failure_message"]


async def test_where_the_accounts_cannot_be_recorded_adding_again_leaves_the_machine_as_it_was(route):
    value, _ = route.make("full")
    route.play("full")
    assert (await route.post(value)).status_code == 200
    before, kept = route.store.get("web"), route.machine_accounts.get("web")
    value, _ = route.make("full")
    _accounts_unwritable(route)
    assert (await route.post(value)).status_code == 500
    assert route.store.get("web") == before and route.machine_accounts.get("web") == kept
    host = merged({}, route.store, route.machine_accounts)["web"]
    assert (host.agent_user, host.readonly_user) == (RW, RO)


async def test_a_machine_described_by_hand_is_checked_as_nervus_reaches_it_and_recorded(route):
    from nervus.config import Host
    from nervus.server import connect_host
    host = Host(name="node-a", address="127.0.0.1", os="", role="r", agent_user="agent", status="onboarded")
    reached = []

    async def connect_described(h):
        reached.append(h.name)
        return await route.enrollment.connect(h.address, (route.host_key,), machine=h.name)

    route.enrollment.described = lambda: {"node-a": host}
    route.enrollment.connect_described = connect_described
    value, code = route.codes.make_readonly_account(name="node-a", made_by="operator", described={"node-a"})
    answer = await route.post(value)
    assert answer.status_code == 200, answer.text
    assert f"node-a has the read-only account {RO}" in answer.text
    kept = route.machine_accounts.get("node-a")
    assert (kept.enrolled_at, kept.readwrite, kept.readonly) == (None, None, RO)
    assert reached == ["node-a"] and route.logins == [RO] and route.store.get("node-a") is None
    del connect_host


async def test_where_a_hand_described_machine_s_account_cannot_be_recorded_it_is_refused_with_its_record(route):
    """Procedure 068, section 12: a failure to record is a refusal, with the code's outcome and the audit
    result, so the script takes its line off again."""
    from nervus.config import Host
    host = Host(name="node-a", address="127.0.0.1", os="", role="r", agent_user="agent", status="onboarded")

    async def connect_described(h):
        return await route.enrollment.connect(h.address, (route.host_key,), machine=h.name)

    route.enrollment.described = lambda: {"node-a": host}
    route.enrollment.connect_described = connect_described
    value, code = route.codes.make_readonly_account(name="node-a", made_by="operator", described={"node-a"})
    _accounts_unwritable(route)
    answer = await route.post(value)
    assert answer.status_code == 500 and route.machine_accounts.get("node-a") is None
    assert route.codes.get(code.id).outcome.startswith("refused: ")
    assert "read-only account" in route.records[-1]["failure_message"]


# --- the form ------------------------------------------------------------------------------------


@pytest.fixture
def page(tmp_path):
    world = PageWorld(tmp_path)
    world.machines = world.machines.__class__(**{**world.machines.__dict__, "accounts": MachineAccounts(world.db)})
    return world


def test_the_add_form_has_both_names_filled_in_with_nervus_s(page):
    form = page.browser.get("/machines").text
    assert f'name="readwrite" value="{RW}"' in form and f'name="readonly" value="{RO}"' in form


def test_a_name_other_than_nervus_s_own_is_asked_about_first_and_made_once_typed(page):
    asked = page.act(action="add", name="nas", confirm="nas", address="192.0.2.20", level="standard",
                     readwrite="ops", readonly=RO)
    assert asked.status_code == 200 and "Use ops on nas?" in asked.text
    assert "its own SSH keys are" in asked.text and "replaced by nervus&#x27;s line alone" in asked.text
    assert page.codes.recent() == []  # nothing made yet
    done = page.act(action="add", name="nas", confirm="nas", address="192.0.2.20", level="standard",
                    readwrite="ops", readonly=RO, typed_readwrite="ops")
    assert "Add nas, standard" in done.text
    made = page.codes.accounts_of(page.codes.recent()[0].id)
    assert (made.readwrite, made.readonly) == ("ops", RO)
    record = page.records("enrollment_code")[-1]
    assert (record["readwrite"], record["readonly"]) == ("ops", RO)


def test_nervus_s_own_names_are_not_asked_about(page):
    done = page.act(action="add", name="nas", confirm="nas", address="192.0.2.20", level="standard",
                    readwrite=RW, readonly=RO)
    assert "Add nas, standard" in done.text


def test_adding_again_takes_nervus_s_line_off_the_accounts_it_used_there_before(page):
    page.enroll(name="nas", level="full")  # added before this release: agent
    page.act(action="add", name="nas", confirm="nas", address="192.0.2.20", level="full")
    made = page.codes.accounts_of(page.codes.recent()[0].id)
    assert made.off == ("agent",) and (made.readwrite, made.readonly) == (RW, RO)


@pytest.mark.parametrize("level", ["standard", "full"])
def test_the_read_write_account_s_line_goes_in_last(machine, level):
    """Note 8: the read-only account's line after its shell is tried, and the read-write one's last, so a
    script that stops partway never leaves an account with more than the level."""
    assert machine.run(level).returncode == 0
    writes = [line for line in machine.log if line.startswith("su ") and ".authorized_keys.nervus" in line]
    assert len(writes) == 2 and writes[0].endswith(f" {RO}") and writes[1].endswith(f" {RW}")


@pytest.mark.parametrize("who", ["readwrite", "readonly", "off"])
def test_a_symbolic_link_for_an_account_s_ssh_stops_the_script_before_anything_changes(machine, tmp_path, who):
    """Procedure 068, section 12: each account's line is written as the account, and a link where its
    ~/.ssh is would take it elsewhere. Every account the script will touch is looked at first, so a
    script refused for it has changed nothing: no account made, no sudoers line, no shell, no key."""
    name = {"readwrite": "deploy", "readonly": "watcher", "off": "agent"}[who]
    machine.add_user(name, keys="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOwnKeyOfTheAccount own\n")
    elsewhere = tmp_path / "elsewhere"
    (machine.home_of(name) / ".ssh").rename(elsewhere)
    (machine.home_of(name) / ".ssh").symlink_to(elsewhere)
    args = {"readwrite": {"readwrite": name}, "readonly": {"readonly": name}, "off": {"off": [name]}}[who]
    done = machine.run("full", script_args=args)
    assert done.returncode == 1 and "is a symbolic link" in done.stderr, done.stderr
    assert "Nothing here was changed" in done.stderr
    assert not any(line.startswith(("useradd", "su ")) for line in machine.log), machine.log
    assert list((machine.root / "etc/sudoers.d").iterdir()) == [] and not machine.shell.exists()
    assert (elsewhere / "authorized_keys").read_text().endswith(" own\n")


def test_at_full_the_sudoers_line_goes_in_only_after_the_read_write_account_s_line(machine):
    """Procedure 068, section 12: a script that stops before the read-write account's line is in leaves
    no account with sudo it did not have, though the line was checked by visudo before any key."""
    machine.add_user("deploy", keys="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOwnKeyOfTheAccount own\n")
    home = machine.home_of("deploy")
    (home / ".ssh" / "authorized_keys").unlink()
    (home / ".ssh").rmdir()
    home.chmod(0o500)  # deploy cannot make its ~/.ssh, so its line cannot go in
    try:
        done = machine.run("full", script_args={"readwrite": "deploy"})
    finally:
        home.chmod(0o700)
    assert done.returncode == 1 and "deploy could not write its authorized_keys" in done.stderr, done.stderr
    assert any(line.startswith("visudo -cqf") for line in machine.log)
    assert list((machine.root / "etc/sudoers.d").iterdir()) == []


def test_when_nervus_does_not_add_the_machine_every_line_not_nervus_s_stays(machine):
    """Procedure 068, section 12: undo takes off nervus's lines and nothing else. Where the sandbox could not
    start, the script never wrote the read-only account's line, so an existing one keeps its own keys."""
    own = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAlicesOwnKeyForTheseTests alice\n"
    machine.add_user("alice", uid=1002, keys=own)
    done = machine.run("standard", script_args={"readonly": "alice"}, SU_FAILS="1", STATUS="422",
                       ANSWER="nervus: nervus checked 192.0.2.10 and did not add it")
    assert done.returncode == 1 and "cannot have a read-only account" in done.stdout
    assert machine.keys_of("alice") == own
    assert KEY not in (machine.keys or "")
    assert f"the accounts it made are deleted: {RW}\n" in done.stderr and machine.exists("alice")


# nervus's own public key, which a machine given it by hand, or enrolled before ADR-0025, holds in a line.
PLAIN = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeNervusOwnKeyForTheseTestsOnly01234567"


@pytest.mark.parametrize("line", [f"{PLAIN} nervus", f'restrict,command="x" {PLAIN} nervus@host'])
def test_a_line_with_nervus_s_own_key_is_taken_off_an_account_it_used_before_too(machine, line):
    """Procedure 068, section 12: question 8 takes nervus's line off the accounts it used there before. On a
    machine enrolled before ADR-0025 that line holds nervus's own key, not its authority's."""
    own = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITheOwnersOwnKeyForTheseTests own\n"
    machine.add_user("agent", keys=line + "\n" + own)
    done = machine.run("standard", script_args={"off": ["agent"], "nervus_key": PLAIN + " nervus"})
    assert done.returncode == 0, done.stderr
    assert machine.keys_of("agent") == own
    assert "took nervus's line off agent, which nervus used here before" in done.stdout


def test_an_account_holding_only_nervus_s_own_key_is_not_said_to_lose_its_own(machine):
    machine.add_user(RO, keys=f"{PLAIN} nervus\n")
    done = machine.run("standard", script_args={"nervus_key": PLAIN})
    assert done.returncode == 0, done.stderr
    assert "own SSH keys are replaced" not in done.stdout


async def test_the_script_is_served_with_nervus_s_own_key(route):
    route.enrollment.nervus_key = lambda: PLAIN
    value, _ = route.make("standard")
    assert f"plainkey='{PLAIN}'\n" in (await route.get(value)).text


@pytest.mark.parametrize("level", ["standard", "full"])
def test_root_reads_nothing_in_an_account_s_home_either(machine, level):
    """Procedure 068, section 12, beside test_root_does_nothing_by_path_in_agents_home: root reading an
    account's authorized_keys by path follows a link the account swaps in, to a file only root may read,
    or to a pipe that never ends. Each read is the account's own, through su."""
    import shutil as _shutil
    from test_host_enrollment_script import _command
    real = _shutil.which("grep")
    (machine.bin / "grep").unlink()
    _command(machine.bin / "grep", f'echo "${{AS_ACCOUNT:+account: }}grep $*" >> "$W/log"; exec {real} "$@"')
    su = (machine.bin / "su").read_text()
    (machine.bin / "su").write_text(su.replace("HOME=$W/home/$5 exec", "AS_ACCOUNT=1 HOME=$W/home/$5 exec"))
    own = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITheOwnersOwnKeyForTheseTests own\n"
    for name in (RW, RO):
        machine.add_user(name, keys=own)
    machine.add_user("agent", keys=f"cert-authority {KEY}\n" + own)
    done = machine.run(level, script_args={"off": ["agent"]})
    assert done.returncode == 0, done.stdout + done.stderr
    by_root = [line for line in machine.log if line.startswith("grep ") and "authorized_keys" in line]
    by_account = [line for line in machine.log if line.startswith("account: grep ") and "authorized_keys" in line]
    assert by_root == [] and len(by_account) >= 3, machine.log  # each account's keys, and agent's line
    assert machine.keys_of("agent") == own


@pytest.mark.parametrize("shared", ["another account's own group", "a group with another member"])
def test_where_the_read_only_account_s_group_is_not_its_alone_nervus_makes_no_copy_of_bwrap(tmp_path, shared):
    """Procedure 068, section 12: AppArmor lets nervus's copy of bwrap make user namespaces, and the copy
    runs for one group. That group must be the read-only account's alone, or there is no copy: at
    standard, the machine is added read-write alone, saying why."""
    machine = Machine(tmp_path, restricted=True)
    machine.add_user("watcher", uid=1005)
    if shared == "another account's own group":
        machine.add_user("other", uid=1006, gid=1005)
    else:
        machine.members(1005, "watcher", "bob")
    done = machine.run("standard", script_args={"readonly": "watcher"}, USERNS_RESTRICTED="1")
    assert done.returncode == 0, done.stderr
    assert machine.nothing_of_question_9 and machine.keys_of("watcher") is None
    assert "is not watcher's alone" in done.stdout
    assert any(line.startswith("nervus-readonly-none ") and "is not watcher's alone" in line
               for line in _report(machine))


def test_a_read_only_account_s_own_group_gets_the_copy(tmp_path):
    machine = Machine(tmp_path, restricted=True)
    machine.add_user("watcher", uid=1005, gid=1007)
    machine.members(1007, "watcher")
    done = machine.run("read-only", script_args={"readonly": "watcher"}, USERNS_RESTRICTED="1")
    assert done.returncode == 0, done.stderr
    assert f"chown root:1007 {machine.copy.parent}/.bwrap" in machine.log
    assert "chown root:1007 /usr/local/lib/nervus/.bwrap" in machine.hook.read_text()


def test_a_hand_described_machine_s_opening_comment_says_it_takes_off_an_earlier_copy_of_bwrap(tmp_path):
    """Procedure 068, section 12: the script does only what its opening comment says, and for a machine
    described by hand it takes off nervus's copy of bwrap, its profile and its hook where one was left."""
    machine = Machine(tmp_path)
    machine.copy.parent.mkdir(parents=True)
    machine.copy.write_text("an earlier copy")
    done = _hand(machine)
    assert done.returncode == 0, done.stderr
    assert "took off nervus's copy of bwrap" in done.stdout
    head = (machine.w / "nervus-enroll.sh").read_text().split("\nset -u\n")[0]
    assert "Takes off nervus's copy of bwrap" in head


def test_a_hand_described_machine_s_removal_leaves_the_read_only_shell(tmp_path):
    """Procedure 068, section 12: the account a machine is described with may itself be read-only by hand,
    through the same shell (docs/install.md), so taking the read-only account off leaves the shell."""
    machine = Machine(tmp_path, restricted=True)
    done = _hand(machine, USERNS_RESTRICTED="1")
    assert done.returncode == 0, done.stderr
    assert machine.copy.exists() and machine.profile.exists() and machine.hook.exists()
    assert f"nervus-made {RO}" in _report(machine)
    gone = machine.remove(remove_readonly_commands(RO, made=(RO,)))
    assert gone.returncode == 0, gone.stderr
    assert not machine.exists(RO) and machine.nothing_of_question_9
    assert machine.shell.exists()


async def test_a_hand_described_machine_s_read_only_account_is_refused_where_an_entry_at_its_address_uses_it(route):
    """Procedure 068, section 12: checked again when the report comes, as the account it is described with is."""
    from nervus.config import Host
    host = Host(name="hv", address="127.0.0.1", os="", role="r", agent_user="observer", status="onboarded")
    route.enrollment.described = lambda: {"hv": host}
    route.enrollment.connect_described = lambda h: pytest.fail("nervus logged in")
    route.enrollment.taken = lambda name: frozenset({"observer", "agent"})
    value, _ = route.codes.make_readonly_account(name="hv", made_by="operator", described={"hv"},
                                                 readonly="agent")
    answer = await route.post(value)
    assert answer.status_code == 409 and "agent" in answer.text
    assert route.machine_accounts.get("hv") is None


@pytest.mark.parametrize("answer", [{"STATUS": "422", "ANSWER": "nervus: nervus checked 192.0.2.10 and did not add it"},
                                    {"CURL_DOWN": "1"}])
def test_a_refused_re_add_leaves_the_accounts_nervus_used_before_as_they_were(machine, answer):
    """ADR-0031 question 11: the old accounts keep nervus's line, and its sudo file, until nervus has accepted
    the new ones, so a re-add nervus refuses, or cannot hear, leaves the machine as it was."""
    machine.add_user("agent", keys=f"cert-authority {KEY}\n")
    machine.legacy_sudoers.write_text("agent ALL=(ALL) NOPASSWD: ALL\n")
    done = machine.run("full", script_args={"off": ["agent"]}, **answer)
    assert done.returncode == 1
    assert machine.keys_of("agent") == f"cert-authority {KEY}\n"
    assert machine.legacy_sudoers.read_text() == "agent ALL=(ALL) NOPASSWD: ALL\n"
    assert "took nervus's line off agent" not in done.stdout and "removed agent's sudoers line" not in done.stdout


def test_the_accounts_nervus_used_before_lose_its_line_only_once_nervus_has_added_the_machine(machine):
    machine.add_user("agent", keys=f"cert-authority {KEY}\n")
    machine.legacy_sudoers.write_text("agent ALL=(ALL) NOPASSWD: ALL\n")
    done = machine.run("full", script_args={"off": ["agent"]})
    assert done.returncode == 0, done.stderr
    assert machine.keys_of("agent") == "" and not machine.legacy_sudoers.exists()
    log = machine.log
    report = next(i for i, line in enumerate(log) if line.startswith("curl") and "--data-binary" in line)
    taken = next(i for i, line in enumerate(log)
                 if line.startswith("su ") and line.endswith(" agent") and ".authorized_keys.nervus" in line)
    assert taken > report
    head = (machine.w / "nervus-enroll.sh").read_text().split("\nset -u\n")[0]
    assert ("once nervus has added this machine, takes nervus's line and sudoers file off\n#      agent, which nervus"
            in head)


# --- question 9: which accounts nervus made, and what removal does to the others ------------------------

MID, OTHER_MID = "0123456789abcdef0123456789abcdef", "fedcba9876543210fedcba9876543210"
CA_WORDS = " ".join(KEY.split()[:2])


def test_the_report_names_the_accounts_the_script_made_and_no_other(machine):
    """ADR-0031 question 9: the script tells nervus which accounts it made."""
    machine.add_user(RO)
    assert machine.run("standard").returncode == 0
    report = _report(machine)
    assert f"nervus-made {RW}" in report and f"nervus-made {RO}" not in report


async def test_the_accounts_nervus_made_are_recorded_and_no_other(route):
    value, _ = route.make("standard")
    body = f"machine-id {MID}\nnervus-made {RW}\nnervus-made root\nnervus-made someone\n{route.host_key}\n"
    assert (await route.post(value, body=body)).status_code == 200, body
    kept = route.machine_accounts.get("web")
    assert (kept.made, kept.machine_id) == ((RW,), MID)


async def test_added_again_the_same_machine_keeps_what_nervus_made_there(route):
    value, _ = route.make("standard")
    body = f"machine-id {MID}\nnervus-made {RW}\nnervus-made {RO}\n{route.host_key}\n"
    assert (await route.post(value, body=body)).status_code == 200
    value, _ = route.make("standard")
    assert (await route.post(value, body=f"machine-id {MID}\n{route.host_key}\n")).status_code == 200
    assert set(route.machine_accounts.get("web").made) == {RW, RO}


async def test_another_machine_by_the_same_name_keeps_nothing_of_what_nervus_made_on_the_first(route):
    value, _ = route.make("standard")
    body = f"machine-id {MID}\nnervus-made {RW}\nnervus-made {RO}\n{route.host_key}\n"
    assert (await route.post(value, body=body)).status_code == 200
    value, _ = route.make("standard")
    assert (await route.post(value, body=f"machine-id {OTHER_MID}\n{route.host_key}\n")).status_code == 200
    assert route.machine_accounts.get("web").made == ()


def test_a_record_that_says_nothing_of_what_nervus_made_counts_as_nothing_made(tmp_path):
    """Fail closed: a row with no word of it, or one that cannot be read, names no account nervus made. One
    naming an account not among its two names it, since question 13: nervus made it under an earlier name."""
    from nervus.database import Database
    db = Database(tmp_path / "nervus.db")
    db.open()
    with db.transaction() as c:
        c.execute("INSERT INTO machine_account (name, enrolled_at, readwrite, readonly, readonly_groups, why_none, "
                  "checked_at) VALUES ('web', 1.0, ?, ?, '[]', NULL, 1.0)", (RW, RO))
        for name, made in (("nas", "not a list"), ("box", json.dumps(RW)), ("cell", json.dumps(["someone"]))):
            c.execute("INSERT INTO machine_account (name, enrolled_at, readwrite, readonly, readonly_groups, "
                      "why_none, checked_at, made) VALUES (?, 1.0, ?, ?, '[]', NULL, 1.0, ?)", (name, RW, RO, made))
    assert [MachineAccounts(db).get(n).made for n in ("web", "nas", "box", "cell")] == [(), (), (), ("someone",)]


def test_removal_deletes_the_accounts_nervus_made_and_takes_only_nervus_s_parts_off_the_others(machine):
    """ADR-0031 question 9a: an account that was there before nervus keeps itself, its home and its own keys;
    nervus's line and its sudoers file come off. The ones nervus made are deleted, as before."""
    own = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITheOwnersOwnKeyForTheseTests own\n"
    machine.add_user("alice", keys=own)
    done = machine.run("full", script_args={"readwrite": "alice"})
    assert done.returncode == 0, done.stderr
    assert machine.root.joinpath("etc/sudoers.d/nervus-alice").exists()
    # The owner gives alice a key of their own again, beside nervus's line.
    machine.home_of("alice").joinpath(".ssh/authorized_keys").write_text(f"cert-authority {KEY}\n" + own)
    commands = remove_commands("alice", RO, made=(RO,), keys=(CA_WORDS,))
    assert "userdel -r alice" not in commands and "pkill -KILL -u alice" not in commands
    gone = machine.remove(commands)
    assert gone.returncode == 0, gone.stderr
    assert machine.exists("alice") and machine.home_of("alice").exists() and machine.keys_of("alice") == own
    assert not machine.root.joinpath("etc/sudoers.d/nervus-alice").exists()
    assert not machine.exists(RO) and not machine.home_of(RO).exists()


def test_removal_deletes_no_account_nervus_cannot_tell_it_made():
    """A machine added before this release, or a record that says nothing: every account is kept."""
    commands = remove_commands("agent", None, keys=(CA_WORDS,))
    assert "userdel" not in commands and "pkill" not in commands
    assert "su -s /bin/sh -c" in commands and commands.rstrip().endswith("rm -rf /usr/local/lib/nervus")


def test_a_hand_described_machine_s_read_only_account_is_kept_where_nervus_did_not_make_it(machine):
    own = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITheOwnersOwnKeyForTheseTests own\n"
    machine.add_user(RO, keys=own)
    done = _hand(machine)
    assert done.returncode == 0, done.stderr
    assert f"nervus-made {RO}" not in _report(machine)
    gone = machine.remove(remove_readonly_commands(RO, keys=(CA_WORDS,)))
    assert gone.returncode == 0, gone.stderr
    assert machine.exists(RO) and machine.keys_of(RO) == ""


# --- question 12: an add nervus refuses, or that stops part way, leaves the machine as it was -----------

RO_LINE = f'cert-authority,restrict,command="{READONLY_SHELL_PATH}" {KEY}\n'
OLD_SHELL = "#!/bin/sh\n# the read-only shell an earlier enrollment left\n"
REFUSED = [{"STATUS": "422", "ANSWER": "nervus: nervus checked 192.0.2.10 and did not add it"}, {"CURL_DOWN": "1"}]


def _enrolled(machine, level):
    """A machine nervus already uses at `level`, under nervus's names, as an earlier enrollment left it."""
    machine.add_user(RW, uid=1001, keys=f"cert-authority {KEY}\n")
    machine.add_user(RO, uid=1002, keys=RO_LINE)
    if level == "full":
        machine.sudoers.write_text(f"{RW} ALL=(ALL) NOPASSWD: ALL\n")
    machine.shell.parent.mkdir(parents=True, exist_ok=True)
    machine.shell.write_text(OLD_SHELL)


@pytest.mark.parametrize("answer", REFUSED, ids=["refused", "unreachable"])
@pytest.mark.parametrize("before, level", [("standard", "full"), ("full", "standard")])
def test_a_refused_re_add_under_the_same_names_leaves_nervus_the_access_it_had(machine, answer, before, level):
    """ADR-0031 question 12, the example it was put with: a machine nervus uses at standard, added again at
    full, and the way back. Each account's keys and sudoers line, and the read-only shell, are as they were."""
    _enrolled(machine, before)
    sudoers = machine.sudoers.read_text() if machine.sudoers.exists() else None
    done = machine.run(level, **answer)
    assert done.returncode == 1, done.stderr
    assert machine.keys_of(RW) == f"cert-authority {KEY}\n" and machine.keys_of(RO) == RO_LINE
    assert (machine.sudoers.read_text() if machine.sudoers.exists() else None) == sudoers
    assert machine.shell.read_text() == OLD_SHELL
    assert machine.exists(RW) and machine.exists(RO) and not any(l.startswith("userdel") for l in machine.log)
    assert "so this put back what was here before it ran: " in done.stderr and "could NOT" not in done.stderr


def test_an_account_that_was_there_gets_its_own_keys_back_when_nervus_refuses(machine):
    """An account named for nervus (question 8) has its keys replaced by nervus's line as the script runs; a
    refused add puts back every line it had, its own keys included, and gives it no sudo."""
    own = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAlicesOwnKeyForTheseTests alice\n"
    machine.add_user("alice", uid=1002, keys=own)
    done = machine.run("full", script_args={"readwrite": "alice"}, STATUS="422", ANSWER="nervus: not added")
    assert done.returncode == 1
    assert "alice's own SSH keys are replaced by nervus's line" in done.stdout  # as the run went
    assert machine.exists("alice") and machine.keys_of("alice") == own
    assert not machine.root.joinpath("etc/sudoers.d/nervus-alice").exists()
    assert "alice's SSH keys" in done.stderr


def test_an_account_with_no_ssh_folder_before_is_left_with_none(machine):
    machine.add_user("bob", uid=1003)
    done = machine.run("standard", script_args={"readwrite": "bob"}, STATUS="422", ANSWER="nervus: not added")
    assert done.returncode == 1 and machine.exists("bob")
    assert not (machine.home_of("bob") / ".ssh").exists()


def test_a_refused_re_add_under_a_new_read_only_name_puts_the_copy_of_bwrap_back_for_the_old_one(tmp_path):
    """Where AppArmor needs nervus's copy of bubblewrap, the copy is the read-only account's own group's, and a
    re-add under a new read-only name makes it again for the new account before nervus checks it. Refused,
    the copy, its profile and its hook are put back for the old account, and the new account is deleted."""
    machine = Machine(tmp_path, restricted=True)
    assert machine.run("standard", USERNS_RESTRICTED="1").returncode == 0
    old, hook = machine.gid_of(RO), machine.hook.read_text()
    assert f"chown root:{old} " in hook
    done = machine.run("standard", script_args={"readonly": "watcher", "off": [RO]}, USERNS_RESTRICTED="1",
                       STATUS="422", ANSWER="nervus: nervus checked 192.0.2.10 and did not add it")
    assert done.returncode == 1, done.stderr
    log = machine.log
    report = max(i for i, line in enumerate(log) if line.startswith("curl") and "--data-binary" in line)
    made_for = [line for line in log[:report] if line.startswith("chown root:") and line.endswith("/.bwrap")]
    assert made_for[-1] != f"chown root:{old} {machine.copy.parent}/.bwrap"  # the new account's, first
    assert machine.copy.exists() and machine.profile.exists() and machine.hook.read_text() == hook
    assert f"apparmor_parser -r {machine.profile}" in log[report:]  # its profile loaded again
    assert not machine.exists("watcher") and machine.keys_of(RO) == RO_LINE
    assert "copy of bwrap with its AppArmor profile as it was" in done.stderr


def test_when_the_script_stops_part_way_it_puts_back_what_it_changed(machine):
    """Question 12 holds for an add that never reached nervus: here the machine has no host keys to send, so
    the script stops at its last step, after the level's changes."""
    _enrolled(machine, "full")
    (machine.root / "etc/ssh/ssh_host_ed25519_key.pub").unlink()
    done = machine.run("standard")
    assert done.returncode == 1 and "the SSH server has no host keys" in done.stderr
    assert "removed nervusagent's sudoers line" in done.stdout  # as the run went
    assert machine.sudoers.read_text() == f"{RW} ALL=(ALL) NOPASSWD: ALL\n"
    assert machine.keys_of(RW) == f"cert-authority {KEY}\n" and machine.keys_of(RO) == RO_LINE
    assert not any("--data-binary" in line for line in machine.log)  # nervus never heard of it


def test_a_run_stopped_from_outside_puts_back_what_it_changed(machine):
    """Stopped part way, as by Ctrl-C or a closed terminal: put back the same."""
    done = machine.run("standard", INTERRUPT="1")
    assert done.returncode == 1 and "stopped before it finished" in done.stderr
    assert not machine.exists(RW) and not machine.exists(RO) and not machine.shell.exists()


def test_once_nervus_has_added_the_machine_nothing_is_put_back(machine):
    """After nervus's answer, a failure to take the old accounts' lines off is the owner's to see to: the
    machine is nervus's, as added."""
    machine.add_user("agent", keys=f"cert-authority {KEY}\n")
    ssh = machine.home_of("agent") / ".ssh"
    ssh.chmod(0o500)  # agent cannot rewrite its authorized_keys, so its line cannot come off
    try:
        done = machine.run("standard", script_args={"off": ["agent"]})
    finally:
        ssh.chmod(0o700)
    assert done.returncode == 1 and "could not take its line or sudoers file off agent" in done.stderr
    assert machine.exists(RW) and machine.keys_of(RW) == f"cert-authority {KEY}\n"
    assert "put back" not in done.stderr


def test_a_refused_read_only_account_for_a_machine_described_by_hand_leaves_it_as_it_was(machine):
    machine.add_user("agent", keys=f"cert-authority {KEY}\n")
    machine.shell.parent.mkdir(parents=True)
    machine.shell.write_text(OLD_SHELL)
    done = _hand(machine, STATUS="422", ANSWER="nervus: nervus checked node-a and did not record it")
    assert done.returncode == 1
    assert not machine.exists(RO) and machine.shell.read_text() == OLD_SHELL
    assert machine.keys_of("agent") == f"cert-authority {KEY}\n"


# --- question 13: nervus remembers every account it made on a machine, until it is removed ---------------


async def test_added_again_under_other_names_nervus_remembers_the_accounts_it_made_before(route):
    """ADR-0031 question 13: a re-add under other names keeps, beside the new accounts nervus made, the old
    ones it made on the same machine, so that removing the machine deletes them too."""
    value, _ = route.make("standard")
    body = f"machine-id {MID}\nnervus-made {RW}\nnervus-made {RO}\n{route.host_key}\n"
    assert (await route.post(value, body=body)).status_code == 200
    value, _ = route.codes.make(name="web", address="127.0.0.1", level="standard", made_by="operator",
                                readwrite="deploy", readonly="watcher", off=[RW, RO])
    answer = await route.post(value, body=f"machine-id {MID}\nnervus-made watcher\n{route.host_key}\n")
    assert answer.status_code == 200, answer.text
    kept = route.machine_accounts.get("web")
    assert (kept.readwrite, kept.readonly, set(kept.made)) == ("deploy", "watcher", {RW, RO, "watcher"})


def test_a_record_names_an_account_of_an_earlier_name_but_never_root_or_what_is_no_account_name(tmp_path):
    from nervus.database import Database
    db = Database(tmp_path / "nervus.db")
    db.open()
    with db.transaction() as c:
        for name, made in (("web", json.dumps(["old-name", RW])), ("nas", json.dumps(["root", "Bad Name", 7, ""]))):
            c.execute("INSERT INTO machine_account (name, enrolled_at, readwrite, readonly, readonly_groups, "
                      "why_none, checked_at, made) VALUES (?, 1.0, ?, ?, '[]', NULL, 1.0, ?)", (name, RW, RO, made))
    assert [MachineAccounts(db).get(n).made for n in ("web", "nas")] == [(RW, "old-name"), ()]


def test_removal_deletes_the_accounts_nervus_made_under_names_the_machine_had_before(machine):
    """The whole of it on the script's test machine: added under nervus's names, added again under others
    (deploy there already, watcher made), then removed. Every account nervus made goes; deploy stays."""
    assert machine.run("standard").returncode == 0
    own = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDeploysOwnKeyForTheseTests deploy\n"
    machine.add_user("deploy", uid=1500, keys=own)
    again = machine.run("standard", script_args={"readwrite": "deploy", "readonly": "watcher", "off": [RW, RO]})
    assert again.returncode == 0, again.stderr
    assert machine.keys_of(RW) == "" and machine.exists(RW) and machine.exists(RO)  # question 11: lines off
    commands = remove_commands("deploy", "watcher", made=(RW, RO, "watcher"), keys=(CA_WORDS,))
    assert "userdel -r deploy" not in commands
    for gone in (RW, RO, "watcher"):
        assert f"userdel -r {gone}\n" in commands and f"/etc/sudoers.d/nervus-{gone}" in commands
    done = machine.remove(commands)
    assert done.returncode == 0, done.stderr
    assert not any(machine.exists(a) for a in (RW, RO, "watcher"))
    assert machine.exists("deploy") and machine.keys_of("deploy") == ""  # its keys were nervus's line alone
    assert not machine.root.joinpath("etc/sudoers.d/nervus-deploy").exists()


def test_a_hand_described_machine_s_removal_deletes_an_earlier_read_only_account_nervus_made():
    commands = remove_readonly_commands("watcher", made=(RO,), keys=(CA_WORDS,))
    assert f"userdel -r {RO}\n" in commands and "userdel -r watcher" not in commands
    assert "su -s /bin/sh -c" in commands  # watcher, which nervus did not make, loses only its line
