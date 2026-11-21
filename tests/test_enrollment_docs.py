"""docs/install.md step 3 and docs/clients.md on enrolled machines (ADR-0024
step 5, ADR-0026 step 5), tested as written: the commands that check the key
Connect shows print the fingerprint the page shows; the two lines and the removal commands are the
ones nervus's page shows; the levels are the three decided, read-only said
honestly (decision 1's "the docs must say exactly that"); and what the docs
tell a client about a read-only machine is what the read-only shell does."""

import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path

import asyncssh
import pytest

from nervus.enrolled_hosts import LEVELS
from nervus.accounts import READONLY, READWRITE
from nervus.host_enrollment import READONLY_SHELL, enroll_lines, enroll_url, remove_commands
from nervus.host_login import fingerprint
from nervus.pages import NON_GOALS
from test_first_run_docs import README

DOCS = Path(__file__).resolve().parent.parent / "docs"
INSTALL, CLIENTS = (DOCS / "install.md").read_text(), (DOCS / "clients.md").read_text()
PIN = "sha256//47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="


def _block(name):
    match = re.search(rf"<!-- install:{name} -->\n *```bash\n(.*?)\n *```", INSTALL, re.S)
    assert match, f"docs/install.md has no install:{name} block"
    return "\n".join(line.strip() for line in match.group(1).splitlines()) + "\n"


def _section(text, heading):
    match = re.search(rf"^## {re.escape(heading)}\n(.*?)(?=^## |\Z)", text, re.S | re.M)
    assert match, f"no section {heading!r}"
    return match.group(1)


def _table(section):
    rows = [[c.strip() for c in line.strip().strip("|").split("|")]
            for line in section.splitlines() if line.strip().startswith("|")]
    return [r for r in rows if not all(re.fullmatch(r"-+", c) for c in r)]


def test_the_two_lines_are_the_ones_the_page_shows():
    written = _block("enroll").replace("<nervus's key>", PIN[len("sha256//"):]).replace(
        "<nervus>", "nervus.example").replace("<one-time code>", "C0DE")
    shown = enroll_lines(enroll_url("nervus.example", 8000, "C0DE"), PIN)
    assert [shlex.split(line) for line in written.splitlines()] == [shlex.split(line) for line in shown.splitlines()]


def test_the_removal_commands_are_the_ones_the_page_shows():
    # ADR-0031: the commands for a machine with nervus's two accounts, by nervus's names.
    assert _block("remove") == remove_commands(READWRITE, READONLY, made=(READWRITE, READONLY))


def test_step_3_offers_the_three_levels_read_only_first_and_says_what_read_only_leaves():
    step = _section(INSTALL, "3. Sign in, choose the tier, and add the machines nervus reaches")
    table = _table(step)
    assert [row[0] for row in table[1:]] == list(LEVELS)
    assert "Read-only is the default" in step
    said = " ".join(step.split())
    assert "nervus can still read anything its account can read, run programs, and reach the network" in said
    assert "never choose it for the machine nervus runs on, which nervus refuses anyway" in said


def test_step_3_says_reinstalling_is_adding_again_not_removing():
    said = " ".join(_section(INSTALL, "3. Sign in, choose the tier, and add the machines nervus reaches").split())
    assert "add it again under its name, by Connect or the two lines. Don't remove it first" in said


def test_the_hand_steps_are_kept_and_say_what_they_give():
    hand = " ".join(_section(INSTALL, "By hand: a machine nervus reaches").split())
    assert "This gives nervus full access there" in hand and "useradd --create-home" in hand


def test_clients_learn_the_three_levels():
    table = _table(_section(CLIENTS, "What each machine lets you do (ADR-0024)"))
    assert [row[0] for row in table[1:]] == list(LEVELS)
    assert table[1][-1] == "no" and table[2][-1] == "no" and table[3][-1].startswith("yes")


def test_what_clients_are_told_of_a_read_only_machine_is_what_its_shell_does():
    said = " ".join(_section(CLIENTS, "What each machine lets you do (ADR-0024)").split())
    shell = READONLY_SHELL.read_text()
    assert "`~/.nervus` is the one folder a command can write" in said
    assert 'work=$HOME/.nervus' in shell and '--bind "$work" "$work"' in shell and "--ro-bind / /" in shell
    assert "`/tmp` is private to each command and empty at the start of the next" in said
    assert "--tmpfs /tmp" in shell
    assert "`put` and uploads are refused" in said and "sandbox \"$server\" -R" in shell


def test_step_3_says_what_the_script_does_since_procedure_037():
    said = " ".join(_section(INSTALL, "3. Sign in, choose the tier, and add the machines nervus reaches").split())
    script = (Path(__file__).resolve().parent.parent / "src" / "nervus" / "host_enrollment.py").read_text()
    assert "the script checks its code first, so a used or expired one, or a copy left from an earlier try, " \
           "changes nothing" in said
    assert '|| fail "could not reach nervus at $url. Nothing here was changed."' in script
    assert "and `tmux` for background jobs at every level" in said and "need tmux tmux" in script


# --- Connect (ADR-0026 step 5) ----------------------------------------------------------------

def test_the_commands_that_check_the_key_print_the_fingerprint_the_page_shows(tmp_path):
    """Run as written, against a key the test makes: the first as on a computer that has logged in to the
    machine, the second against the machine's own host key, at the path the docs name, moved into a folder of
    the test's. ssh-keygen finds ~ from the account's password entry, not from HOME, so the first is given the
    test's known_hosts with -f, which names the file it reads by default; nothing else is added."""
    if shutil.which("ssh-keygen") is None:
        pytest.skip("ssh-keygen is not installed")
    line = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode().strip()
    shown = fingerprint(line).split(" ")[1]
    known_hosts = tmp_path / ".ssh" / "known_hosts"
    known_hosts.parent.mkdir()
    known_hosts.write_text(f"192.0.2.20 {line}\n")
    machine_key = tmp_path / "etc" / "ssh" / "ssh_host_ed25519_key.pub"
    machine_key.parent.mkdir(parents=True)
    machine_key.write_text(line + " root@machine\n")
    first, second = _block("fingerprint").splitlines()
    assert first == "ssh-keygen -lF <the machine's address>" and second == "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub"
    for command in (first.replace("<the machine's address>", "192.0.2.20") + f" -f {shlex.quote(str(known_hosts))}",
                    second.replace("/etc/ssh/ssh_host_ed25519_key.pub", shlex.quote(str(machine_key)))):
        done = subprocess.run(["sh", "-c", command], env={"PATH": os.environ["PATH"]}, capture_output=True, text=True,
                              timeout=30)
        assert done.returncode == 0 and shown in done.stdout.split(), (command, done.stdout, done.stderr)


def test_step_3_offers_connect_first_and_keeps_the_two_lines_as_advanced():
    step = _section(INSTALL, "3. Sign in, choose the tier, and add the machines nervus reaches")
    said = " ".join(step.split())
    assert said.index("**Connect.**") < said.index("**Log in once**") < said.index("### Advanced: two lines run on")
    assert said.index("<!-- install:fingerprint -->") < said.index("### Advanced") < said.index("<!-- install:enroll -->")
    for words in ("a `.local` name works only where nervus's machine runs mDNS", "`avahi-daemon` and `libnss-mdns`",
                  "the account name, in its audit log", "never the password",
                  "where the machine takes only SSH keys", "where only `su` reaches root",
                  "where you do not trust the network", "read the script before it runs",
                  "For Connect, also a password login over SSH for root or for an account that can use `sudo`"):
        assert words in said, words


def test_the_readme_and_the_setup_page_say_whoever_runs_nervus_could_see_a_password():
    readme = " ".join(README.read_text().split())
    words = "rewrite its audit log, and see a password you type to add a machine."
    assert words in readme and any(goal.endswith(words) for goal in NON_GOALS)
    assert "by an admin login given once, or with two lines run on them" in readme
