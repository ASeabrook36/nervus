"""docs/install.md's "Where nervus may run" says what ADR-0023 decided (its
verification 6): each place with its tier, by which computer hosts nervus; what
the preview supports; and that nervus must not hold root on its own machine.
Its backups say what ADR-0027 decided, and the commands they give are ones
nervus-ctl takes (step 6). What it says to leave out of a backup of nervus's
whole machine is every secret and record nervus's own backup holds, and nothing
a restore needs (procedure 048, step 2), and the system's journal, where nervus's
own log goes (step 11). Its hand steps lay a release out as install.sh does, run
here as written and compared with an install by install.sh (ADR-0023
verification 5, ADR-0029 question 3a), started afresh or again after a line
failed; and they say that a hand install is upgraded by hand."""

import inspect
import os
import re
import shlex
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

import pytest

from nervus import backup, ctl, restore
from test_first_run_docs import README
from test_install_sh import Machine, _files, _given_to_nervus, _mode, _named, _release, _script, _tree

INSTALL = Path(__file__).resolve().parent.parent / "docs" / "install.md"


def _section():
    text = INSTALL.read_text()
    match = re.search(r"^## Where nervus may run\n(.*?)^## ", text, re.S | re.M)
    assert match, "docs/install.md has no \"Where nervus may run\" section"
    return match.group(1)


def _tables(section):
    """Each markdown table as a list of rows, each a list of cells, header first."""
    tables, rows = [], []
    for line in section.splitlines() + [""]:
        if line.startswith("|"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if not all(re.fullmatch(r"-+", c) for c in cells):
                rows.append(cells)
        elif rows:
            tables.append(rows)
            rows = []
    return tables


def test_the_tier_turns_on_which_computer_hosts_nervus():
    by_host, _ = _tables(_section())
    assert by_host[0][1:] == ["on a separate computer", "on your everyday computer"]
    tiers = {row[0]: row[1:] for row in by_host[1:]}
    assert tiers == {
        "a VM": ["tier 1", "tier 3"],
        "a container": ["tier 1", "tier 3"],
        "a service under its own `nervus` account": ["tier 1", "tier 2"],
        "a program run as you": ["—", "tier 3"],
    }


def test_what_the_preview_supports_is_what_adr_0023_decided():
    _, supported = _tables(_section())
    rows = {row[0]: (row[1], row[2]) for row in supported[1:]}
    linux = [r for r in rows if r.startswith("Linux")]
    assert len(linux) == 3
    separate, everyday, vm = (next(r for r in linux if key in r) for key in
                              ("separate computer", "nervus's own account", "VM your everyday computer hosts"))
    assert rows[separate] == ("1", "**yes, recommended**")
    assert rows[everyday] == ("2", "yes")
    assert rows[vm][0] == "3" and rows[vm][1].startswith("yes; declare it as tier 3")
    for name in ("macOS natively", "Windows", "a container image"):
        assert not rows[name][1].startswith("yes"), name


def test_a_vm_the_everyday_computer_hosts_is_said_to_be_tier_3_and_why():
    section = _section()
    assert "in a VM your everyday computer hosts" in section
    assert "its disk is a file in your home folder" in section


def test_it_says_never_to_give_nervus_root_on_its_own_machine():
    assert "**Never give nervus root on the machine it runs on.**" in _section()


# --- backups (ADR-0027 step 6) ------------------------------------------------------

REPO = INSTALL.parent.parent


def _part(heading):
    match = re.search(rf"^## {re.escape(heading)}\n(.*?)(?=^## |\Z)", INSTALL.read_text(), re.S | re.M)
    assert match, f"docs/install.md has no section {heading!r}"
    return " ".join(match.group(1).split())


def _raw(name, lang="bash"):
    block = re.search(rf"<!-- install:{name} -->\n```{lang}\n(.*?)\n```", INSTALL.read_text(), re.S)
    assert block, f"docs/install.md has no install:{name} block"
    return block.group(1)


def _block(name):
    return shlex.split(_raw(name).replace("<the backup's name>", "b"))


@pytest.mark.parametrize("name, command", [("backup-check", ["backup", "--check"]), ("restore", ["restore"])])
def test_each_documented_nervus_ctl_command_is_one_nervus_ctl_takes(name, command):
    words = _block(name)
    assert words[:2] == ["sudo", "/opt/nervus/.venv/bin/nervus-ctl"]
    args = ctl._parser().parse_args(words[2:])
    assert [args.command, *(["--check"] if getattr(args, "check", None) else [])] == command


def test_the_key_is_said_to_be_read_from_the_terminal_even_when_piped_in():
    """Procedure 047, finding 2. nervus-ctl reads the key as getpass does: the terminal whenever
    there is one, standard input only without one (procedure 054, finding 4: without getpass's
    false warning), so a key piped in at a terminal is not read."""
    assert inspect.signature(ctl.run).parameters["secret"].default is ctl.read_secret
    said = _part("5. Check that your recovery key opens a backup")
    for words in ("from the terminal whenever there is one, even when the key is piped in",
                  "Only where there is no terminal", "read it from standard input",
                  "never a file", "`--yes`"):
        assert words in said, words
    assert "from the terminal, as step 5 says" in _part("Backups")


def test_the_installer_step_says_the_recovery_key_is_shown_once_and_where_to_keep_it():
    said = _part("2. Run the installer")
    assert "prints its private half **once**" in said
    assert "never on nervus's machine and never on a machine a client reaches at full access" in said


def test_the_keeping_said_is_the_keeping_nervus_does():
    said = _part("Backups")
    assert "one a day for a week, one a week for a month and one a month for a year, and nothing older" in said
    assert (backup.DAILY, backup.WEEKLY[1], backup.MONTHLY) == ((7, 7), 31, (12, 365))
    assert "/var/lib/nervus/backups" in said and restore.STALE_HOURS == 26


def test_where_copies_go_turns_on_the_tier():
    said = _part("Backups")
    assert "| 1 | a mistake on nervus's machine |" in said
    assert "| 2 or 3 | a mistake on nervus, **not losing your computer** |" in said
    assert "holds every secret of nervus's **unlocked**" in said


# --- a backup of nervus's whole machine (procedure 048, step 2) ---------------------

SHIPPED_UNIT = REPO / "deploy" / "nervus.service"


def _leaves_out():
    """The globs the guide says to leave out of a backup of nervus's whole machine, in order."""
    return [line.split()[0] for line in _raw("machine-backup-leaves-out", "").splitlines()]


def _left_out(path, globs):
    """The glob that leaves `path` out, as vzdump's --exclude-path does: one matching the path, or a
    folder it is in, from the machine's root, its `*` stopping at a slash. None if none does."""
    parts = PurePosixPath(path).parts
    for depth in range(2, len(parts) + 1):
        candidate = "/" + "/".join(parts[1:depth])
        for glob in globs:
            if re.fullmatch("".join("[^/]*" if c == "*" else re.escape(c) for c in glob), candidate):
                return glob
    return None


def _installed(tmp_path, flags=()):
    """The shipped unit as nervus-ctl reads it, with a drop-in giving `flags` as an installer's does."""
    unit = tmp_path / "nervus.service"
    unit.write_text(SHIPPED_UNIT.read_text())
    if flags:
        (tmp_path / "nervus.service.d").mkdir()
        argv = ctl.exec_start(SHIPPED_UNIT) + list(flags)
        (tmp_path / "nervus.service.d" / "flags.conf").write_text(
            f"[Service]\nExecStart=\nExecStart={shlex.join(argv)}\n")
    return ctl.read_unit(unit)


def _proxmox_flags():
    """The two flags `install.sh --proxmox` adds to the drop-in, as the guide gives them."""
    return shlex.split(_raw("proxmox-flags", "").replace("\\\n", " ").replace("<nervus's address>", "nervus.test"))


def _passing(service):
    """The folders files pass through, read from the code that names them: the unit's transfer
    folder, and the two nervus's main() puts beside the database when the unit names none."""
    import nervus.__main__

    words = ctl.exec_start(SHIPPED_UNIT)
    assert "--exports-dir" not in words and "--uploads-dir" not in words
    beside = re.findall(r'args\.\w+_dir or Path\(args\.database\)\.parent / "(\w+)"',
                        inspect.getsource(nervus.__main__.main))
    assert len(beside) == 2
    return [Path(words[words.index("--transfer-dir") + 1]), *(service.database.parent / name for name in beside)]


def test_a_machine_backup_leaves_out_every_piece_a_backup_holds_but_the_inventory_and_off_switch(tmp_path):
    """Each piece nervus's own backup carries locked (restore.locations, for the shipped unit with
    Proxmox settings) is under a path the guide leaves out. The inventory and the off switch are not:
    they hold no secret, and a restored machine has them where nervus looks."""
    service = _installed(tmp_path, _proxmox_flags())
    held = restore.locations(service)
    # The Proxmox CA's path is read from the settings file, which is not here. tools/proxmox-access
    # writes it relative to that file, as nervus.proxmox.load_config reads it.
    ca = re.search(r"ca_file: ([^\s\\]+)", (REPO / "tools" / "proxmox-access").read_text()).group(1)
    held["proxmox_ca"] = service.proxmox.parent / ca
    assert None not in held.values()
    globs = _leaves_out()
    assert {role for role, path in held.items() if not _left_out(path, globs)} == {"hosts", "switches"}


def test_it_leaves_out_the_databases_write_ahead_files_files_in_passing_and_what_a_restore_replaced(tmp_path):
    service = _installed(tmp_path)
    replaced = restore.KEPT_PREFIX  # its folder: the prefix, the time, random characters
    globs = _leaves_out()
    for path in (service.database.with_name(service.database.name + "-wal"),
                 service.database.with_name(service.database.name + "-shm"),
                 *(folder / "a-file" for folder in _passing(service)),
                 service.database.parent / f"{replaced}20260101T000000Z-k2v9x0qa" / "pieces"):
        assert _left_out(path, globs), path


def test_it_keeps_the_backups_the_off_switch_the_code_and_each_folder_nervus_writes_into(tmp_path):
    """What a restore needs stays: the backups folder and every backup in it, the off switch, the
    inventory, the drop-in, nervus's code, by its link and in its release's own folder, and each
    folder nervus's files live in, with its owner and mode: the unit names some (ReadWritePaths,
    StateDirectory), and a restore writes into the rest."""
    service = _installed(tmp_path)
    globs = _leaves_out()
    folder = restore.backups_folder(service)
    code = Path(ctl.exec_start(SHIPPED_UNIT)[0])  # through /opt/nervus/.venv, the link
    released = Path("/opt/nervus/releases/0.2.0-42c0b5a132ef") / code.relative_to("/opt/nervus")  # what it reaches
    stays = [folder, folder / backup.backup_name(datetime(2026, 1, 1, tzinfo=timezone.utc)),
             service.switches, service.hosts, ctl.UNIT.parent / f"{ctl.UNIT.name}.d" / "nervus.conf",
             code, released, service.database.parent, service.tokens.parent,
             service.audit_log.parent, service.tls_renewed.parent, *_passing(service)]
    assert {str(path): _left_out(path, globs) for path in stays} == {str(path): None for path in stays}


def test_it_leaves_out_the_systems_journal_where_nervus_logs_but_keeps_its_folder():
    """Procedure 048, step 11: nervus's units send its log nowhere but the system's journal, where
    asyncssh names each command nervus runs. The journal's contents are left out; its folder stays,
    for the restored system to write into."""
    for unit in (SHIPPED_UNIT, SHIPPED_UNIT.with_name("nervus-backup.service")):
        assert not re.search(r"^Standard(Output|Error)=", unit.read_text(), re.M), unit
    globs = _leaves_out()
    assert _left_out("/var/log/journal/0123456789abcdef/system.journal", globs) == "/var/log/journal/*"
    assert _left_out("/var/log/journal", globs) is None


def test_the_vzdump_words_are_the_list_and_a_scratch_folder():
    words = shlex.split(_raw("vzdump-leaves-out").replace("<nervus's container>", "999")
                        .replace("<its scratch folder>", "/scratch"))
    assert words[:2] == ["vzdump", "999"] and len(words) == 4 + 2 * len(_leaves_out())
    assert [words[i + 1] for i, word in enumerate(words) if word == "--exclude-path"] == _leaves_out()
    assert words[words.index("--tmpdir") + 1] == "/scratch"


def test_it_says_why_how_such_a_copy_comes_back_and_where_proxmox_packs_it():
    """Procedure 048, step 1.2: an unprivileged container's dump, packed as the container's root,
    fails when its scratch folder is left inside a dump folder only root can open."""
    said = _part("Backups")
    for words in ("whoever can read it can act as nervus",
                  "refuses to start, for want of its secrets, until `nervus-ctl restore`",
                  "keep them in a folder only root can open",
                  "a scratch folder of its own, `--tmpdir`: `0700`, owned by the container's root as the host sees it",
                  "every dump fails",
                  "Its records include its own log, in the system's journal",
                  "as `rsyslog` does into `/var/log/syslog`"):
        assert words in said, words


def test_a_restore_is_said_to_check_first_keep_what_it_replaces_and_start_in_lockdown():
    said = _part("Backups")
    for words in ("checks the backup whole before it changes anything", "never deleting it",
                  "**in lockdown**", "nervus-ctl unlock --all", "**at the same name**",
                  "nervus-ctl accept-keys", "nervus-ctl start-empty", "recovery-key --replace",
                  "age -d -i <key file> <backup> | tar -xz", "recovering from a compromised nervus"):
        assert words in said, words


def test_the_rough_edges_no_longer_say_nothing_backs_nervus_up():
    assert "back nervus up" not in _part("Rough edges in this preview")
    assert "Nothing backs nervus up" not in README.read_text()


def test_the_readme_says_a_backup_is_as_safe_as_its_recovery_key_and_no_cure_for_a_compromise():
    match = re.search(r"^## What nervus does not defend against\n(.*?)(?=^## )", README.read_text(), re.S | re.M)
    said = " ".join(match.group(1).split())
    assert "**Losing the recovery key, or giving it away.**" in said
    assert "**A compromised nervus, by restoring it.**" in said


# --- the hand steps, against the installer (ADR-0023 verification 5, ADR-0029 question 3a) ------


def _under(text, root):
    """The guide's system paths under `root`, as install.sh's tests put them; the account's home,
    which only names a folder, as it is."""
    return re.sub(r"(?<![\w./-])(?<!--home-dir )(?=/(?:opt|etc|var)/)", str(root), text)


def _hand_lines():
    """Each line of the commands in "By hand: what the installer does"."""
    match = re.search(r"^## By hand: what the installer does\n(.*?)(?=^## )", INSTALL.read_text(), re.S | re.M)
    assert match, "docs/install.md has no section 'By hand: what the installer does'"
    return [line for block in re.findall(r"```bash\n(.*?)\n```", match.group(1), re.S) for line in block.splitlines()]


@pytest.fixture(scope="module")
def archive(tmp_path_factory):
    """The clone of one commit, and the hand steps' archive of it, made as they make it, in a folder
    of its own as on nervus's machine."""
    clone = _tree(tmp_path_factory.mktemp("clone"))
    subprocess.run(["bash", "-c", _raw("by-hand-archive")], cwd=clone, check=True, capture_output=True)
    on_nervus = tmp_path_factory.mktemp("on-nervus")
    shutil.move(clone / "nervus.tar.gz", on_nervus)
    return clone, on_nervus


def _by_hand(tmp):
    """A machine for the hand steps, root's commands stood in for as in install.sh's tests. With no
    account nervus here to own a folder, `install` leaves out the owner it is given; useradd
    refuses an account that is there, as the real one does, and userdel takes it away."""
    m = Machine(tmp)
    _script(m.bin / "install", 'echo "install $*" >> "$LOG"; a=()\n'
            'while [ $# -gt 0 ]; do case $1 in -o|-g) shift 2 ;; *) a+=("$1"); shift ;; esac; done\n'
            f'exec {shutil.which("install")} "${{a[@]}}"')
    _script(m.bin / "useradd", 'echo "useradd $*" >> "$LOG"; a=$NERVUS_INSTALL_ROOT/.user-nervus\n'
            '[ -e "$a" ] && { echo "useradd: user \'nervus\' already exists" >&2; exit 9; }; touch "$a"')
    _script(m.bin / "userdel", 'echo "userdel $*" >> "$LOG"; rm "$NERVUS_INSTALL_ROOT/.user-nervus"')
    return m


def _run_by_hand(m, commands, cwd, stop=True):
    """The guide's commands in a shell of their own, their system paths under the machine's root:
    stopping at the first that fails, as a script does, or going on past it, as when pasted."""
    env = {"PATH": str(m.bin), "HOME": str(m.root), "LOG": str(m.log), "NERVUS_INSTALL_ROOT": str(m.root),
           "LANG": "C"}
    return subprocess.run(["bash", *(["-e"] if stop else []), "-c", _under(commands, m.root)], cwd=cwd, env=env,
                          capture_output=True, text=True, timeout=120)


@pytest.fixture(scope="module")
def both(archive, tmp_path_factory):
    """One commit installed twice: by the hand steps as written, the code and then the empty
    inventory and token file, from the archive they make; and by install.sh from the clone."""
    clone, on_nervus = archive
    by_hand = _by_hand(tmp_path_factory.mktemp("by-hand"))
    done = _run_by_hand(by_hand, _raw("by-hand-code") + "\n" + _raw("by-hand-empty"), on_nervus)
    assert done.returncode == 0, done.stdout + done.stderr
    installer = Machine(tmp_path_factory.mktemp("installer"))
    done = installer.run(clone, "--address", "192.0.2.5", "--yes")
    assert done.returncode == 0, done.stdout + done.stderr
    return by_hand, installer, clone


def test_the_by_hand_steps_lay_out_the_release_as_the_installer_does(both):
    """What every later release reads: the release's folder, named by tools/release-name; the tree
    in it, less its own inventory; its venv, made and filled where it stays; and /opt/nervus/.venv a
    link to that venv, made once the release is whole."""
    by_hand, installer, clone = both
    name = _named(clone)[0]
    assert os.listdir(by_hand.opt / "releases") == os.listdir(installer.opt / "releases") == [name]
    rel = _release(by_hand)
    assert _files(rel, leave_out={".venv"}) == _files(_release(installer), leave_out={".venv"})
    assert os.readlink(by_hand.opt / ".venv") == os.readlink(installer.opt / ".venv") == f"releases/{name}/.venv"
    log = by_hand.logged()
    assert [line for line in log if line.startswith("venv ")] == [f"venv {rel}/.venv"]
    # As the installer fills it: the lock's libraries, each file checked; nervus itself, nothing fetched.
    assert [line for line in log if "/bin/pip " in line] == [
        f"{rel}/.venv/bin/pip install --require-hashes -r {rel}/requirements.lock",
        f"{rel}/.venv/bin/pip install --no-deps --no-index --no-build-isolation {rel}",
        f"{rel}/.venv/bin/pip check"]
    code = _raw("by-hand-code").splitlines()
    pip, link = (next(i for i, line in enumerate(code) if word in line) for word in ("/bin/pip", "ln -s "))
    assert pip < link


def test_the_guide_says_a_stopped_install_says_what_to_remove():
    _says(_part("2. Run the installer"), "If it stops partway", "the commands that remove what it made")


def test_the_by_hand_steps_set_the_umask_the_installer_sets_before_they_make_the_venv():
    # A stricter one makes a venv nervus's account cannot read (procedure 051, finding 1).
    code = _raw("by-hand-code").splitlines()
    assert code[0] == "umask 022"
    assert re.search(r"(?m)^umask 022$", (REPO / "install.sh").read_text())
    assert "mode `0644` since each backup reads it" in _part("By hand: what the installer does")


def test_the_by_hand_steps_give_nervus_its_own_as_the_installer_does_and_never_the_code(both):
    """ADR-0029 question 12, and ADR-0023 verification 5's owners: the account is given its
    secrets, the transfer folder, the inventory and its log, by the hand steps as by the installer,
    and neither gives it the code or /opt/nervus; the code is unpacked as root's, whoever owned the
    archive."""
    by_hand, installer, _ = both
    assert _given_to_nervus(by_hand) == _given_to_nervus(installer) == {"secrets", "transfer", "hosts.yaml",
                                                                         "var/log/nervus"}
    unpacked = [line for line in by_hand.logged() if line.startswith("tar -x")]
    assert unpacked and all("--no-same-owner" in line.split() for line in unpacked), unpacked


def test_the_by_hand_steps_leave_beside_the_release_what_the_installer_does(both):
    """What nervus keeps, at the top of /opt/nervus beside the release: the same entries, the empty
    inventory and token file, the same folders' modes; and the same account."""
    by_hand, installer, clone = both
    assert sorted(os.listdir(by_hand.opt)) == sorted(os.listdir(installer.opt))
    for path in ("hosts.yaml", "secrets/tokens.yaml"):
        assert (by_hand.opt / path).read_bytes() == (installer.opt / path).read_bytes(), path
    assert _mode(by_hand.opt / "secrets" / "tokens.yaml") == _mode(installer.opt / "secrets" / "tokens.yaml") == 0o600
    name = _named(clone)[0]
    for path in ("opt/nervus", "opt/nervus/releases", f"opt/nervus/releases/{name}", "opt/nervus/secrets",
                 "opt/nervus/transfer", "var/log/nervus"):
        assert _mode(by_hand.root / path) == _mode(installer.root / path), path
    useradd = [[line for line in m.logged() if line.startswith("useradd ")] for m in (by_hand, installer)]
    assert len(useradd[0]) == 1 and useradd[0] == useradd[1]


def test_a_failed_hand_run_started_again_as_the_guide_says_lays_out_the_same_release(archive, both, tmp_path):
    """pip failing part-way is the likeliest failure (ADR-0029 question 3). Pasted into a shell, the
    block goes on past the failing line, the account made and the link too. Started again from the
    clean slate the guide gives, it ends with the release install.sh makes; run again over what the
    failure left, it would put a second copy of the tree inside the release's folder."""
    _, on_nervus = archive
    _, installer, _ = both
    m = _by_hand(tmp_path)
    (m.root / ".pip-fails").touch()
    failed = _run_by_hand(m, _raw("by-hand-code"), on_nervus, stop=False)
    assert "No matching distribution" in failed.stderr and (m.root / ".user-nervus").exists()
    (m.root / ".pip-fails").unlink()
    said = re.search(r"If a line fails, [^.]*\.", _part("By hand: what the installer does"))
    assert said, "the hand steps do not say what to do when a line fails"
    for command in re.findall(r"`([^`]+)`", said.group(0)):
        done = _run_by_hand(m, command, on_nervus)
        assert done.returncode == 0, command + ": " + done.stderr
    done = _run_by_hand(m, _raw("by-hand-code"), on_nervus)
    assert done.returncode == 0, done.stdout + done.stderr
    assert os.listdir(m.opt / "releases") == os.listdir(installer.opt / "releases")
    assert _files(_release(m), leave_out={".venv"}) == _files(_release(installer), leave_out={".venv"})
    assert os.readlink(m.opt / ".venv") == os.readlink(installer.opt / ".venv")


def test_the_hand_steps_ways_to_read_the_release_work_in_a_shell_of_their_own(both):
    """The later hand parts are often done in another shell than the code's, where its `$release`
    is gone: what the guide gives to find `<release>` prints it there, and so does the Check line's
    readlink, as it says."""
    by_hand, _, clone = both
    name = _named(clone)[0]
    said = _part("By hand: what the installer does")
    found = re.search(r"`<release>` is that name: `([^`]+)` prints it", said)
    check = re.search(r"Check: `(readlink [^`]+)` prints `([^`]+)`", said)
    assert found and check
    for command, printed in ((found.group(1), name), (check.group(1), check.group(2).replace("<release>", name))):
        done = _run_by_hand(by_hand, command, by_hand.root)
        assert done.stdout == printed + "\n", command


def test_the_by_hand_steps_install_the_units_the_installer_does(both):
    """Each hand command that takes a file from the release's folder is one install.sh runs: the
    unit, the off switch's tool and the backup's units, from the release installed."""
    _, installer, _ = both
    name = _release(installer).name
    from_release = [line for line in _hand_lines() if "/opt/nervus/releases/<release>/" in line]
    assert len(from_release) == 3, from_release
    for line in from_release:
        assert _under(line.replace("<release>", name), installer.root) in installer.logged(), line
    text = INSTALL.read_text()
    assert "systemctl enable --now nervus-backup.timer" in text
    assert "/opt/nervus/.venv/bin/nervus-ctl recovery-key\n" in text


def test_every_path_the_guide_gives_into_opt_nervus_is_one_an_installation_has(both):
    # The tree is in its release's folder now, not at the top; what nervus keeps stays there.
    _, installer, _ = both
    named = set(re.findall(r"/opt/nervus/([^/\s`'\"*]+)", INSTALL.read_text()))
    assert {".venv", "releases", "secrets", "hosts.yaml"} <= named <= set(os.listdir(installer.opt))


def test_a_hand_install_is_said_to_be_upgraded_by_hand():
    # ADR-0029 question 8a: the installer's upgrade takes only installations it made.
    assert ("An installation made by hand is upgraded by hand: the installer's upgrade takes only installations "
            "the installer made") in " ".join(_part("By hand: what the installer does").split())


def test_upgrading_is_no_longer_a_rough_edge():
    edges = _part("Rough edges in this preview")
    assert "newer tree" not in edges and "being built" not in edges and "Upgrading" not in edges


def _says(section: str, *words: str) -> None:
    flat = " ".join(section.split())
    for said in words:
        assert said in flat, said


def test_the_guide_says_what_to_read_where_the_newer_tree_comes_from_by_tier_and_the_command():
    # ADR-0029 order of work, step 5: "By tier" in its Context, and question 1a; run as written in test_install_sh.
    part = _part("Upgrading")
    _says(part, "keeps everything of yours", "No client's configuration changes", "you may skip some",
          "`CHANGES.md`", "what each client must do", "`git pull`", "On tier 1", "not over the old copy",
          "Check its SHA-256 before you unpack it", "cannot see the archive", "On tiers 2 and 3",
          "a program running as you could change it first", "On tier 2, a package the upgrade adds")
    assert "cd <your copy of this repository> && sudo ./install.sh --upgrade" in part


def test_the_guide_says_what_the_upgrade_refuses_shows_and_does_in_its_order():
    part = " ".join(_part("Upgrading").split())
    _says(part, "an older release", "\"nothing to do\"", "uncommitted changes", "no `apt-get`",
          "this installer did not install nervus here", "(it says where)", "newer than this release knows",
          "waits for `yes`", "the name of its folder", "its commit", "when the recovery key last opened a backup")
    _says(part, "within a minute of starting", "with nervus's last lines")
    steps = [part.index(words) for words in ("It builds the new release beside the running one", "It makes a backup",
                                              "It stops nervus", "It checks that nervus is up",
                                              "goes back to the release before by itself")]
    assert steps == sorted(steps)


def test_the_guide_says_the_check_after_the_way_back_and_when_it_is_refused():
    part = _part("Upgrading")
    _says(part, "check the backup it made with the recovery key, as step 5 says",
          "shown by tests and by a trial on throwaway machines", "The database stays as it is",
          "It is refused once a release has raised the database's version",
          "only the backup made before the upgrade holds a database it can use", "any with this script",
          "Never install a newer tree over an installation")
    assert "cd <your copy of this repository> && sudo ./install.sh --back" in part


def test_the_clients_guide_says_what_a_client_does_after_an_upgrade():
    # ADR-0029 question 10a, and "Clients across a restart" in its Context.
    clients = (REPO / "docs" / "clients.md").read_text()
    part = clients[clients.index("## After nervus is upgraded (ADR-0029)"):]
    part = part[:part.index("\n## ", 1)]
    _says(part, "Nothing in your client's configuration changes", "its root and every token",
          "reconnect it to nervus, or start a new session", "error it can retry", "runs on",
          "marked failed", "keeps the tool descriptions it was given", "until you start a new session",
          "`CHANGES.md`", "pull this repository on each client machine")
    assert "\"After nervus is upgraded\"" in _part("Upgrading")


def _clients_part(heading: str) -> str:
    clients = (REPO / "docs" / "clients.md").read_text()
    part = clients[clients.index(f"## {heading}\n"):]
    return part[:part.index("\n## ", 1)]


def test_the_clients_guide_says_the_issuer_limits_names_but_not_addresses():
    # Procedure 056, C5. The issuer's limit names DNS names only, since Claude Code's TLS library cannot apply one
    # written as an address (ADR-0021 B), so the issuer's key could vouch for any address. The guide said the root
    # "cannot be used to impersonate any other site", and the install guide that the issuer vouches "only for nervus's
    # own names".
    part = _clients_part("Trust nervus's certificate, once per machine (ADR-0021)")
    assert "cannot be used to impersonate any other site to your clients" not in " ".join(part.split())
    _says(part, "can vouch for no DNS name but nervus's", "any other site your clients reach by name",
          "It does not limit addresses", "a site they reach by an IP address", "beside nervus's SSH key",
          "locked to your recovery key")
    install = " ".join((REPO / "docs" / "install.md").read_text().split())
    assert "an issuer that can vouch only for nervus's own names" not in install
    assert "an issuer that can vouch for no DNS name but nervus's own" in install


def test_the_clients_guide_says_claude_code_asks_once_before_it_uses_the_project_s_nervus():
    # Procedure 054, finding 2: a newcomer's `claude mcp list` said "Pending approval", and nothing said why.
    _says(_clients_part("Claude Code"), "The first time you start Claude Code in the project",
          "whether you trust the folder", "approve the project's `nervus`",
          "`claude mcp list` shows nervus as \"Pending approval\"", "a run with `claude -p` goes without it")


def test_the_clients_guide_says_a_failed_call_s_result_says_why():
    # Procedure 054, finding 3: a call that failed after its intent wrote no result.
    _says(_clients_part("Check it"), "A call writes two records, an intent before it runs and a result after",
          "If it failed, the result's `error` says why.")


def test_the_clients_guide_says_where_a_terminal_s_token_variable_is_set_and_its_line_works(tmp_path):
    # Procedure 054, finding 2: on Linux the guide named only macOS's desktop apps.
    part = _clients_part("Where the token lives")
    _says(part, "For a client in a terminal", "a file only you can read", "`chmod 600`",
          "`~/.profile` on Linux", "`~/.zprofile` on macOS", "Log in again")
    line = re.search(r"`(export NERVUS_CLAUDE_CODE=[^`]+)`", part).group(1)
    folder = tmp_path / ".config" / "nervus"
    folder.mkdir(parents=True)
    (folder / "token-claude-code").write_text("the-token\n")
    done = subprocess.run(["bash", "-c", f'{line}\nprintf "%s" "$NERVUS_CLAUDE_CODE"'], capture_output=True,
                          text=True, env={"HOME": str(tmp_path), "PATH": os.environ["PATH"]}, check=True)
    assert done.stdout == "the-token"


def test_the_readme_says_nervus_upgrades_and_how_far_that_is_shown():
    _says(README.read_text(), "upgrading to a newer release with one line",  # the release page's (ADR-0032)
          "goes back by itself if the new release does not come up",
          "ADR-0029; shown by tests and on throwaway machines")


def _installer_flags():
    """The flags install.sh's argument loop takes."""
    return set(re.findall(r"^ +(?:-h\|)?(--[\w-]+)\)", (REPO / "install.sh").read_text(), re.M))


def test_every_flag_of_the_installer_the_guide_gives_is_one_it_takes():
    given = {flag for words in re.findall(r"install\.sh([^`\n]*)", INSTALL.read_text())
             for flag in re.findall(r"(?<!\S)--[\w-]+", words)}
    assert {"--address", "--name", "--proxmox", "--restore", "--upgrade", "--back"} <= given <= _installer_flags()


def test_ubuntu_24_04_and_26_04_are_said_to_be_tried_for_nervus_and_for_read_only():
    # ADR-0023 question 5 and ADR-0024 question 9, after procedure 054's newcomer trial on 24.04
    # and procedure 055's on 26.04.
    _says(_part("What you need"), "tested on Debian 13 with Python 3.13, Ubuntu 24.04 with Python 3.12 and "
          "Ubuntu 26.04 with Python 3.14")
    _says(_part("Rough edges in this preview"), "Read-only is tried on Debian 13, on Ubuntu 24.04",
          "and on Ubuntu 26.04, which lets bubblewrap through itself", "Ubuntu's other releases are not tried")
    _says(_part("3. Sign in, choose the tier, and add the machines nervus reaches"),
          "as Ubuntu 24.04's does (26.04 lets it through, by a profile of Ubuntu's own)")
    readme = " ".join(README.read_text().split())
    assert "not yet tried on Ubuntu 24.04" not in readme and "not yet on later Ubuntu releases" not in readme
    assert "Read-only is tried on Debian 13, Ubuntu 24.04 and Ubuntu 26.04, not yet on Ubuntu's other releases." \
        in readme


def test_the_guide_s_release_lines_are_the_ones_the_release_page_gives():
    # ADR-0032 question 2: what tools/release-archive writes on the release page, for install and upgrade.
    import importlib.machinery
    import importlib.util

    loader = importlib.machinery.SourceFileLoader("release_archive", str(REPO / "tools" / "release-archive"))
    spec = importlib.util.spec_from_loader("release_archive", loader)
    tool = importlib.util.module_from_spec(spec)
    loader.exec_module(tool)
    page = tool.page("https://example.test/download", "ab" * 32, "9.8.7", [])
    given = re.findall(r"```bash\n(curl .*?)\n```", page)
    guide = (REPO / "docs" / "install.md").read_text()

    def block(name):
        found = re.search(rf"<!-- install:{name} -->\n *```bash\n *(.*?)\n *```", guide, re.S)
        assert found, f"docs/install.md has no install:{name} block"
        return (found.group(1).replace("<the release's download folder>", "https://example.test/download")
                .replace("<its SHA-256>", "ab" * 32).replace("<number>", "9.8.7"))
    assert block("release") == given[0] and given[0].endswith("&& sudo ./install.sh")
    assert block("release-upgrade") in given and block("release-upgrade").endswith("sudo ./install.sh --upgrade")
