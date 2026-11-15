"""tools/ensure-switches: the deploy creates the off switch if missing, keeps
it if valid, and stops rather than overwrite a malformed one (ADR-0003, A;
ADR-0011 consequence 1)."""

import getpass
import importlib.machinery
import importlib.util
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from nervus.switches import SwitchesUnreadable, load_switches

TOOL = Path(__file__).parent.parent / "tools" / "ensure-switches"


def _run(*args):
    done = subprocess.run([sys.executable, str(TOOL), *map(str, args)], capture_output=True, text=True)
    return done.returncode, done.stdout + done.stderr


def _module():
    loader = importlib.machinery.SourceFileLoader("ensure_switches", str(TOOL))
    spec = importlib.util.spec_from_loader("ensure_switches", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def test_missing_is_created_with_nothing_off(tmp_path):
    path = tmp_path / "switches.yaml"
    rc, out = _run("--owner", getpass.getuser(), path)
    assert rc == 0 and "created" in out
    assert load_switches(path).lockdown is False and load_switches(path).disabled == frozenset()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert [p.name for p in tmp_path.iterdir()] == ["switches.yaml"]  # no staging file left


def test_a_valid_file_is_kept_byte_for_byte(tmp_path):
    path = tmp_path / "switches.yaml"
    text = "# the operator's note\nlockdown: true\ndisabled:\n  - codex-anywhere\n"
    path.write_text(text)
    rc, out = _run(path)
    assert rc == 0 and "lockdown ON; switched off: codex-anywhere" in out
    assert path.read_text() == text


def test_a_malformed_file_stops_the_deploy_and_is_left_alone(tmp_path):
    path = tmp_path / "switches.yaml"
    path.write_text("lockdown: [\n")
    for args in ([path], ["--check", path]):
        rc, out = _run(*args)
        assert rc == 1 and "STOP" in out and "not overwritten" in out
        assert path.read_text() == "lockdown: [\n"


def test_check_writes_nothing(tmp_path):
    path = tmp_path / "switches.yaml"
    rc, out = _run("--check", path)
    assert rc == 0 and "will be created" in out
    assert not path.exists()


MALFORMED = [
    "lockdown: false\ndisabled: [\n", "", "lockdown: false\n",
    "lockdown: false\ndisabled: []\nextra: 1\n", "lockdown: \"no\"\ndisabled: []\n",
    "lockdown: false\ndisabled: t1\n", "lockdown: false\ndisabled: [1]\n", "- lockdown\n",
]
VALID = ["lockdown: false\ndisabled: []\n", "lockdown: true\ndisabled: [a, b]\n", "lockdown: false\ndisabled:\n"]


@pytest.mark.parametrize("text", MALFORMED + VALID)
def test_its_idea_of_valid_is_nervuss(tmp_path, text):
    """The script cannot import nervus (the old package may lack the module),
    so it carries its own check. It must agree with load_switches exactly."""
    path = tmp_path / "switches.yaml"
    path.write_text(text)
    try:
        load_switches(path)
        nervus_says_valid = True
    except SwitchesUnreadable:
        nervus_says_valid = False
    assert (_module().problem(text) is None) == nervus_says_valid


# --- the one-time copy to /var/lib/nervus (ADR-0014 decision A, consequence 2) ----------

ON = "lockdown: false\ndisabled: []\n"


def test_a_missing_switch_file_is_copied_from_its_old_place_exactly(tmp_path):
    old = tmp_path / "secrets" / "switches.yaml"
    old.parent.mkdir()
    text = "# the operator's note\nlockdown: false\ndisabled:\n  - codex-anywhere\n"
    old.write_text(text)
    new = tmp_path / "state" / "switches.yaml"
    new.parent.mkdir()
    rc, out = _run("--owner", getpass.getuser(), "--from", old, new)
    assert rc == 0 and "copied" in out and "switched off: codex-anywhere" in out
    assert new.read_text() == text and old.read_text() == text  # the old one stays, for a rollback
    assert stat.S_IMODE(new.stat().st_mode) == 0o600
    assert [p.name for p in new.parent.iterdir()] == ["switches.yaml"]


def test_an_existing_switch_file_is_kept_and_the_old_one_ignored(tmp_path):
    old = tmp_path / "old.yaml"
    old.write_text("lockdown: true\ndisabled: []\n")
    new = tmp_path / "switches.yaml"
    new.write_text(ON)
    rc, out = _run("--from", old, new)
    assert rc == 0 and "kept as it is" in out
    assert new.read_text() == ON


def test_a_malformed_old_file_is_not_copied_and_stops_the_deploy(tmp_path):
    old = tmp_path / "old.yaml"
    old.write_text("lockdown: [\n")
    new = tmp_path / "switches.yaml"
    for args in (["--from", old, new], ["--check", "--from", old, new]):
        rc, out = _run(*args)
        assert rc == 1 and "STOP" in out
        assert not new.exists()


def test_with_no_old_file_one_is_made_with_nothing_off(tmp_path):
    new = tmp_path / "switches.yaml"
    rc, out = _run("--owner", getpass.getuser(), "--from", tmp_path / "absent.yaml", new)
    assert rc == 0 and "created" in out and new.read_text() == ON


def test_check_says_it_would_copy_and_writes_nothing(tmp_path):
    old = tmp_path / "old.yaml"
    old.write_text(ON)
    new = tmp_path / "switches.yaml"
    rc, out = _run("--check", "--from", old, new)
    assert rc == 0 and "will be copied" in out and not new.exists()


def test_a_missing_folder_is_made_for_the_owner_only(tmp_path):
    new = tmp_path / "state" / "switches.yaml"
    rc, out = _run("--owner", getpass.getuser(), new)
    assert rc == 0, out
    assert stat.S_IMODE(new.parent.stat().st_mode) == 0o700




# --- written through its handle (procedure 058) --------------------------------------------


def test_a_new_copy_swapped_for_a_link_is_not_chmodded_or_linked_through(tmp_path, monkeypatch):
    # As nervus-ctl's writer: the folder is nervus's account's, the deploy runs this as root.
    import os
    module = _module()
    path = tmp_path / "state" / "switches.yaml"
    path.parent.mkdir()
    outside = tmp_path / "root-file"
    outside.write_text("root's\n")
    outside.chmod(0o644)
    real_fsync = os.fsync

    def swap(fd):
        real_fsync(fd)
        new = next(p for p in path.parent.iterdir() if p.name.startswith(".switches."))
        new.unlink()
        new.symlink_to(outside)
    monkeypatch.setattr(module.os, "fsync", swap)
    assert module.main(["--owner", getpass.getuser(), str(path)]) == 1
    assert stat.S_IMODE(outside.stat().st_mode) == 0o644 and outside.read_text() == "root's\n"
    assert not path.exists() and not path.is_symlink()
    assert list(path.parent.iterdir()) == []


def _run_within(seconds, *args):
    """As _run, but a tool still running after `seconds` fails its test: waiting on a pipe looks so."""
    done = subprocess.run([sys.executable, str(TOOL), *map(str, args)], capture_output=True, text=True, timeout=seconds)
    return done.returncode, done.stdout + done.stderr


@pytest.mark.parametrize("check", [[], ["--check"]])
def test_a_pipe_at_the_off_switch_stops_the_deploy_and_is_not_waited_on(tmp_path, check):
    """nervus's account owns the folder and can put a pipe where the file was. A deploy and an
    upgrade both run this as root before anything else; a plain read waited there for ever."""
    path = tmp_path / "switches.yaml"
    os.mkfifo(path)
    rc, out = _run_within(10, *check, path)
    assert rc == 1 and "STOP" in out and "is a pipe, not a file" in out
    assert stat.S_ISFIFO(path.lstat().st_mode) and [p.name for p in tmp_path.iterdir()] == ["switches.yaml"]


def test_a_pipe_where_the_off_switch_used_to_live_stops_it_too(tmp_path):
    old = tmp_path / "old.yaml"
    os.mkfifo(old)
    rc, out = _run_within(10, "--from", old, "--owner", getpass.getuser(), tmp_path / "switches.yaml")
    assert rc == 1 and "STOP" in out and "is a pipe, not a file" in out
    assert not (tmp_path / "switches.yaml").exists()
