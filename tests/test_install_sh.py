"""install.sh (ADR-0023 step 2, decisions 5 to 7): what it checks before it
changes anything, what it refuses, and what it writes, compared with
docs/install.md's hand steps (verification 2 to 5); and the folder of its own
that the release goes in, with /opt/nervus/.venv a link to the venv inside it
(ADR-0029 question 3a).

It runs here in a real bash with its system paths under NERVUS_INSTALL_ROOT,
from a throwaway git clone of this repository's files. `PATH` holds only the
commands named below, so a missing one can be simulated. The commands that
need root (useradd, runuser, chown, systemctl, journalctl, apt-get) and the
venv's pip and nervus-ctl are stood in for, and `install` is logged on its way
to the real one, so where each unit came from can be read; tar unpacks as it
does run as root, keeping the modes it reads; tls-init, tls-fingerprint,
ensure-switches, tools/release-name, ssh-keygen and git are real. A Python too
old fails tools/release-name as 3.10 would. nervus-ctl's stand-in plays
signin, recovery-key and restore (ADR-0027), whose own tests are
tests/test_restore.py; tools/release-name's are tests/test_release_name.py."""

import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from nervus.ctl import exec_start
from nervus.tls import certificate_fingerprint

REPO = Path(__file__).resolve().parent.parent
VENV_BIN = Path(sys.executable).parent
# The number these tests' trees are at. They raise it to 0.2.0 and 0.3.0 and read what the upgrade says
# about them, so it must not move with this repository's own: the commit an export is made from raises
# that (tools/export-preview step 4), and step 7 runs these tests on that commit.
NUMBER = "0.1.0"
REAL = ["bash", "sh", "git", "awk", "sed", "cut", "grep", "cat", "mkdir", "chmod", "rm",
        "seq", "sleep", "dirname", "env", "ls", "cp", "mv", "ssh-keygen", "printf", "tr", "head", "tail", "uname",
        "basename", "touch", "readlink", "date", "wc", "find", "xargs", "sort", "gzip", "mktemp", "ln",
        "age", "age-keygen"]

STANDINS = {
    "useradd": 'echo "useradd $*" >> "$LOG"; touch "$NERVUS_INSTALL_ROOT/.user-nervus"',
    "userdel": 'echo "userdel $*" >> "$LOG"; rm "$NERVUS_INSTALL_ROOT/.user-nervus"',
    # `id nervus` asks whether the account exists; anything else is the real id.
    "id": '[ "$1" = nervus ] && { [ -e "$NERVUS_INSTALL_ROOT/.user-nervus" ]; exit; }; exec /usr/bin/id "$@"',
    "runuser": 'echo "runuser $*" >> "$LOG"; [ "$1" = -u ] && shift 2; [ "$1" = -- ] && shift; exec "$@"',
    # The time a read is given; not every machine these tests run on has a `timeout` of its own.
    "timeout": '[ "$1" = --foreground ] && shift; shift; exec "$@"',
    "chown": 'echo "chown $*" >> "$LOG"',
    "install": f'echo "install $*" >> "$LOG"; exec {shutil.which("install")} "$@"',
    # Run as root, GNU tar and bsdtar both keep the modes of what they unpack (-p), the folder
    # unpacked into too when the stream names it ('./').
    "tar": f'echo "tar $*" >> "$LOG"; [ "$1" = -x ] && set -- -xp "${{@:2}}"; exec {shutil.which("tar")} "$@"',
    # A start runs the machine's .on-start, where a test has one: what the release started does.
    "systemctl": ('echo "systemctl $*" >> "$LOG"\n'
                  'case "$*" in "enable --now nervus"|"restart nervus"|"start nervus") touch "$NERVUS_INSTALL_ROOT/.active"\n'
                  '    [ -x "$NERVUS_INSTALL_ROOT/.on-start" ] && "$NERVUS_INSTALL_ROOT/.on-start"; true;;\n'
                  '  "stop nervus"|"disable --now nervus") rm -f "$NERVUS_INSTALL_ROOT/.active";;\n'
                  '  "is-active --quiet nervus") [ -e "$NERVUS_INSTALL_ROOT/.active" ]; exit;;\n'
                  '  "is-active --quiet nervus-backup.service") exit 1;;\n'
                  # .pids, where a test wrote one: the main process each asking finds, then 4242.
                  '  "show -p MainPID --value nervus") p=$NERVUS_INSTALL_ROOT/.pids\n'
                  '    if [ -s "$p" ]; then head -n 1 "$p"; tail -n +2 "$p" > "$p.next"; mv "$p.next" "$p"; else echo 4242; fi;; esac'),
    # The start lines of the release the link names: .journal-<release> where a test wrote one; the
    # last of them, where it is asked for so many.
    "journalctl": ('cur=$(readlink "$NERVUS_INSTALL_ROOT/opt/nervus/.venv"); cur=${cur#releases/}; cur=${cur%/.venv}\n'
                   'lines=100000; a=("$@"); for i in "${!a[@]}"; do [ "${a[i]}" = -n ] && lines=${a[i+1]}; done\n'
                   'case " $* " in *" --since "*) ;; *) echo "a line from before this start";; esac\n'
                   'if [ -e "$NERVUS_INSTALL_ROOT/.journal-$cur" ]; then tail -n "$lines" "$NERVUS_INSTALL_ROOT/.journal-$cur"; '
                   'else echo "nervus: serving HTTPS"; fi'),
    "apt-get": ('echo "apt-get $*" >> "$LOG"\n'
                'for p in "$@"; do [ "$p" = openssh-client ] && ln -sf "$(cat "$NERVUS_INSTALL_ROOT/.ssh-keygen")" '
                '"$(dirname "$0")/ssh-keygen"\n'
                '[ "$p" = age ] && for c in age age-keygen; do ln -sf "$(cat "$NERVUS_INSTALL_ROOT/.$c")" '
                '"$(dirname "$0")/$c"; done; done; true'),
    # nervus-ctl, as the venv's: signin's link; recovery-key's public half kept and its private half
    # printed; restore's pieces put in place, its nervus started, as `nervus-ctl restore` does.
    "nervus-ctl-standin": (
        'echo "nervus-ctl $*" >> "$LOG"\n'
        's="$NERVUS_INSTALL_ROOT/opt/nervus/secrets"\n'
        'case " $* " in\n'
        '  *" recovery-key "*) printf "age1%058d\\n" 0 > "$s/recovery.pub"\n'
        '    echo "A new recovery key."; echo; echo "  AGE-SECRET-KEY-1STANDIN";;\n'
        '  *" restore "*) [ -e "$NERVUS_INSTALL_ROOT/.restore-fails" ] && { echo "nervus-ctl: not the key. Nothing changed"; exit 1; }\n'
        '    ssh-keygen -q -t ed25519 -N "" -C nervus -f "$s/nervus_ed25519"\n'
        '    ssh-keygen -q -t ed25519 -N "" -C nervus-ca -f "$s/nervus_ca_ed25519"\n'
        f'    (cd "$s/.." && {Path(sys.executable).parent}/nervus tls-init --bind-host 0.0.0.0 --name restored.test >/dev/null)\n'
        '    [ -e "$NERVUS_INSTALL_ROOT/.backup-has-key" ] && printf "age1%058d\\n" 1 > "$s/recovery.pub"\n'
        '    systemctl start nervus; echo "restored. Lockdown is on.";;\n'
        '  *" --last-check "*) echo "last check passed 2026-11-03 10:00, of nervus-2026-11-03T100000Z.age";;\n'
        # upgrade-backup: which nervus-ctl was asked, by its path under the machine; .keep-fails, .only-fails.
        '  *" upgrade-backup "*) echo "upgrade-backup asked of ${CALLED_AS#$NERVUS_INSTALL_ROOT}" >> "$LOG"\n'
        '    for stage in keep only; do case " $* " in *" upgrade-backup $stage "*)\n'
        '      [ -e "$NERVUS_INSTALL_ROOT/.$stage-fails" ] && { echo "nervus-ctl: cannot keep: disk full"; exit 1; };; esac; done\n'
        # keep says what it kept the backup as, in the words of the real nervus-ctl.
        '    case " $* " in *" upgrade-backup keep "*) echo "kept nervus-2026-11-04T120000Z.age as '
        'nervus-2026-11-04T120000Z.before-it.age, until the upgrade after the one to it";; *) echo "kept";; esac;;\n'
        '  *" backup "*) [ -e "$NERVUS_INSTALL_ROOT/.backup-fails" ] && { echo "nervus-ctl: the backup failed: disk full"; exit 1; }\n'
        '    echo "made nervus-2026-11-04T120000Z.age (1.0 MB), locked to the recovery key age1000…";;\n'
        '  *" upgrade-record "*) [ -e "$NERVUS_INSTALL_ROOT/.record-fails" ] && { echo "nervus-ctl: cannot write"; exit 1; }\n'
        # .no-down-stage: the nervus-ctl of a release from before the stage "down", refusing it as argparse does.
        '    case " $* " in *" upgrade-record down "*) [ -e "$NERVUS_INSTALL_ROOT/.no-down-stage" ] && {\n'
        '      echo "nervus-ctl upgrade-record: error: argument stage: invalid choice: down" >&2; exit 2; };; esac\n'
        '    [ -e "$NERVUS_INSTALL_ROOT/.down-record-fails" ] && case " $* " in *"NERVUS IS DOWN"*|*" upgrade-record down "*)\n'
        '      echo "nervus-ctl: cannot write"; exit 1;; esac\n'
        '    echo "recorded";;\n'
        '  *) echo "  https://ui.test:8443/signin?link=ONE-TIME";;\n'
        'esac'),
}


def _script(path: Path, body: str) -> None:
    path.write_text(f"#!/bin/bash\n{body}\n")
    path.chmod(0o755)


class Machine:
    """nervus's machine, under one folder: its system paths, its commands."""

    def __init__(self, tmp: Path):
        self.root = tmp / "root"
        for d in ("run/systemd/system", "var/lib", "var/log", "etc/systemd/system", "opt"):
            (self.root / d).mkdir(parents=True)  # as on any Linux machine with systemd
        self.log = tmp / "log"
        self.log.touch()
        self.bin = tmp / "bin"
        self.bin.mkdir()
        for name in REAL:
            found = shutil.which(name)
            if found:
                (self.bin / name).symlink_to(found)
        for command in ("ssh-keygen", "age", "age-keygen"):
            (self.root / f".{command}").write_text(shutil.which(command) or "")
        for name, body in STANDINS.items():
            _script(self.bin / name, body)
        self.python(version=None)
        self.at_start = self._everything()

    def _everything(self):
        return {str(p.relative_to(self.root)) for p in self.root.rglob("*")}

    def python(self, version=None, venv=True):
        """python3: the venv's own, which is 3.11 or later; `-m venv` logs the
        folder it makes a venv in, whose nervus is this repository's, whose pip
        only logs how it was called, failing while .pip-fails exists, and whose
        python logs how it was called and runs ensure-switches without --owner
        (no root to chown with). Given a version, it is that version, too old,
        and fails release-name as 3.10 does, having no tomllib."""
        too_old = (f'case "$*" in *version_info*) exit 1;; *python_version*) echo {version}; exit;;\n'
                   '  *release-name*) echo "ModuleNotFoundError: No module named tomllib" >&2; exit 1;; esac\n') \
            if version else ""
        no_venv = 'case "$*" in *ensurepip*) exit 1;; esac\n' if not venv else ""
        make_venv = (
            'if [ "$1" = -m ] && [ "$2" = venv ]; then d=$3; echo "venv $d" >> "$LOG"; mkdir -p "$d/bin"\n'
            '  printf \'#!/bin/bash\\necho "$0 $*" >> "$LOG"\\n'
            # .pip-hashes-differ: a file that is not the one the lock names; .pip-check-fails: a set that does not fit.
            'case " $* " in *" --require-hashes "*) [ -e "$NERVUS_INSTALL_ROOT/.pip-hashes-differ" ] && {\\n'
            '  echo "ERROR: THESE PACKAGES DO NOT MATCH THE HASHES FROM THE REQUIREMENTS FILE." >&2; exit 1; };;\\n'
            '  " check ") [ -e "$NERVUS_INSTALL_ROOT/.pip-check-fails" ] && {\\n'
            '  echo "nervus 0.1.0 has requirement mcp==2.2.0, but you have mcp 2.1.0."; exit 1; };; esac\\n'
            '[ -e "$NERVUS_INSTALL_ROOT/.pip-fails" ] || exit 0\\n'
            'echo "ERROR: No matching distribution found for mcp" >&2; exit 1\\n\' > "$d/bin/pip"\n'
            f'  printf \'#!/bin/bash\\nexec {VENV_BIN}/nervus "$@"\\n\' > "$d/bin/nervus"\n'
            f'  printf \'#!/bin/bash\\nCALLED_AS="$0" exec {self.bin}/nervus-ctl-standin "$@"\\n\' > "$d/bin/nervus-ctl"\n'
            f'  printf \'#!/bin/bash\\necho "$0 $*" >> "$LOG"\\n'
            f'if [ "${{1##*/}}" = ensure-switches ]; then a=(); for x in "$@"; do '
            f'[ "$x" = --owner ] && {{ skip=1; continue; }}; [ -n "$skip" ] && {{ skip=; continue; }}; a+=("$x"); done; '
            f'set -- "${{a[@]}}"; fi\\nexec {VENV_BIN}/python "$@"\\n\' > "$d/bin/python"\n'
            '  chmod +x "$d/bin/"*; exit 0; fi\n')
        # tools/check-up: nervus answers, unless the release the link names has a .down-<release>.
        # (or the machine has a .down: nervus answers on no release). Each asking is logged.
        check_up = ('case "$*" in *tools/check-up*) echo "check-up" >> "$LOG"\n'
                    '  echo "check-up asked on ${@: -2:1} ${@: -1}" >> "$LOG"\n'  # the two ports it was given
                    '  cur=$(readlink "$NERVUS_INSTALL_ROOT/opt/nervus/.venv")\n'
                    '  cur=${cur#releases/}; cur=${cur%/.venv}\n'
                    '  if [ -e "$NERVUS_INSTALL_ROOT/.down" ] || [ -e "$NERVUS_INSTALL_ROOT/.down-$cur" ]; then '
                    'echo "check-up: the MCP endpoint did not answer" >&2; exit 1; fi\n'
                    '  echo "nervus answers"; exit 0;; esac\n')
        _script(self.bin / "python3", too_old + no_venv + make_venv + check_up + f'exec {VENV_BIN}/python "$@"')

    def run(self, tree: Path, *args, answer=None, umask=None):
        """install.sh, run from a shell with that umask, which sudo passes on, or as the tests run."""
        start = ["bash", "-c", f'umask {umask}; exec bash "$0" "$@"'] if umask else ["bash"]
        return subprocess.run([*start, str(tree / "install.sh"), *args], capture_output=True, text=True,
                              env=self.env(), input=answer, timeout=120)

    def env(self):
        return {"PATH": str(self.bin), "HOME": str(self.root), "LOG": str(self.log),
                "NERVUS_INSTALL_ROOT": str(self.root), "LANG": "C"}

    @property
    def opt(self):
        return self.root / "opt" / "nervus"

    @property
    def unit(self):
        return self.root / "etc" / "systemd" / "system" / "nervus.service"

    @property
    def dropin(self):
        return self.root / "etc" / "systemd" / "system" / "nervus.service.d" / "instance.conf"

    def logged(self):
        return self.log.read_text().splitlines()

    def changed(self):
        """Everything under the root that was not there at the start."""
        return sorted(self._everything() - self.at_start)


def _own_files() -> set[str]:
    """This repository's files: what git lists, in a checkout. The export's run of tests/
    (tools/export-preview step 7) is in a tree with no .git, so there, the tree's files themselves,
    less the bytecode Python writes as the tests run."""
    if (REPO / ".git").exists():
        return set(subprocess.run(["git", "-C", str(REPO), "ls-files"], capture_output=True, text=True).stdout.split())
    return {str(p.relative_to(REPO)) for p in REPO.rglob("*") if p.is_file() and "__pycache__" not in p.parts}


def _numbered(tree: Path, number: str) -> None:
    """The tree's release number made `number`, and its lock, where it has one, a lock made for that
    release, as tools/lock-libraries makes one for each."""
    pyproject = tree / "pyproject.toml"
    pyproject.write_text(re.sub(r'(?m)^version = ".*"$', f'version = "{number}"', pyproject.read_text()))
    lock = tree / "requirements.lock"
    if lock.is_file():
        lock.write_text(re.sub(r"(?m)^# Made for nervus \S+ on ", f"# Made for nervus {number} on ", lock.read_text()))


def _tree(tmp: Path, git=True) -> Path:
    """This repository's files (install.sh included), as a clone or a plain copy, at NUMBER whatever
    release this repository is at."""
    tree = tmp / "nervus"
    for f in _own_files() | {"install.sh"}:
        if (REPO / f).is_file():
            (tree / f).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO / f, tree / f)
    _numbered(tree, NUMBER)
    if git:
        g = ["git", "-C", str(tree), "-c", "user.name=t", "-c", "user.email=t@t"]
        subprocess.run([*g[:3], "init", "-q"], check=True)
        subprocess.run([*g, "add", "-A"], check=True)
        subprocess.run([*g, "commit", "-qm", "tree"], check=True)
    return tree


def test_a_tree_with_no_git_gives_its_own_files_less_the_bytecode(tmp_path, monkeypatch):
    # The export's run of tests/ is in such a tree. Listed by git, it would give install.sh alone,
    # and no test of the installer could run there (ADR-0018's amendment: the export runs them).
    source = tmp_path / "source"
    for name in ("install.sh", ".mcp.json.example", "pyproject.toml", "tools/release-name",
                 "tools/__pycache__/release.pyc"):
        (source / name).parent.mkdir(parents=True, exist_ok=True)
        (source / name).write_text("the file\n")
    monkeypatch.setitem(globals(), "REPO", source)
    tree = _tree(tmp_path / "copy", git=False)
    assert sorted(str(p.relative_to(tree)) for p in tree.rglob("*") if p.is_file()) == [
        ".mcp.json.example", "install.sh", "pyproject.toml", "tools/release-name"]


def test_a_tree_is_at_these_tests_own_number_whatever_this_repository_is_at(tmp_path, monkeypatch):
    # The commit an export is made from raises this repository's number, and step 7 runs these tests on it.
    # If a tree took its number from there, each export would stop itself here.
    source = tmp_path / "source"
    source.mkdir()
    (source / "install.sh").write_text("the file\n")
    (source / "pyproject.toml").write_text('[project]\nversion = "9.8.7"\n')
    monkeypatch.setitem(globals(), "REPO", source)
    tree = _tree(tmp_path / "copy", git=False)
    assert tomllib.loads((tree / "pyproject.toml").read_text())["project"]["version"] == NUMBER


@pytest.fixture
def machine(tmp_path):
    return Machine(tmp_path)


@pytest.fixture(scope="module")
def clone(tmp_path_factory):
    return _tree(tmp_path_factory.mktemp("clone"))


def _mode(p):
    return stat.S_IMODE(p.stat().st_mode)


def _commit(tree: Path, *new: str) -> None:
    """A clone's changes, committed, so install.sh takes them; `new` names files it does not track yet."""
    if new:
        subprocess.run(["git", "-C", str(tree), "add", *new], check=True)
    subprocess.run(["git", "-C", str(tree), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qam", "changed"],
                   check=True)


def _named(tree: Path) -> list[str]:
    """tools/release-name's name, number and code for what install.sh installs from the tree:
    a clone's `git archive HEAD`, or the plain copy itself."""
    tool = [sys.executable, "-I", str(tree / "tools" / "release-name"), "--full"]
    if (tree / ".git").exists():
        archive = subprocess.run(["git", "-C", str(tree), "archive", "HEAD"], capture_output=True, check=True).stdout
        done = subprocess.run([*tool, "--archive"], input=archive, capture_output=True, check=True)
    else:
        done = subprocess.run([*tool, str(tree)], capture_output=True, check=True)
    return done.stdout.decode().split()


def _release(m) -> Path:
    """The one folder an install leaves under /opt/nervus/releases/."""
    folders = sorted((m.opt / "releases").iterdir())
    assert len(folders) == 1, folders
    return folders[0]


def _entry(p: Path):
    """What the release's code counts of a file or a link: whether its owner may run it, and its
    bytes (a link's: its target)."""
    if p.is_symlink():
        return "l", os.readlink(p).encode()
    return "x" if os.stat(p).st_mode & stat.S_IXUSR else "f", p.read_bytes()


def _files(top: Path, leave_out=()) -> dict:
    """Each file and link under top, by its path, but for the names left out at the top."""
    found = {}
    for folder, dirs, files in os.walk(top):  # a link to a folder is listed, not followed
        if Path(folder) == top:
            dirs[:] = [d for d in dirs if d not in leave_out]
            files = [f for f in files if f not in leave_out]
        for name in dirs + files:
            p = Path(folder) / name
            if p.is_symlink() or p.is_file():
                found[str(p.relative_to(top))] = _entry(p)
    return found


def _given_to_nervus(m) -> set[str]:
    """What the logged chown and `install -o` calls gave nervus's account, each by the entry of
    /opt/nervus it is in ('' for /opt/nervus itself), or as var/log/nervus."""
    given = set()
    for line in m.logged():
        words = line.split()
        if words[0] == "chown":
            paths = [w for w in words[1:] if not w.startswith("-")]
            if not paths[0].startswith("nervus"):
                continue
            paths = paths[1:]
        elif words[0] == "install" and "-o" in words and words[words.index("-o") + 1] == "nervus":
            paths, skip = [], False
            for w in words[1:]:
                if skip or w in ("-o", "-g", "-m"):
                    skip = not skip
                elif not w.startswith("-"):
                    paths.append(w)
        else:
            continue
        for p in paths:
            rel = Path(p).relative_to(m.root)
            if rel.parts[:2] == ("opt", "nervus"):
                given.add(rel.parts[2] if len(rel.parts) > 2 else "")
            else:
                given.add(str(rel))
    return given


def _snapshot(top: Path) -> dict:
    """Every path under top, folders and links too: its mode, and a file's bytes or a link's target."""
    seen = {}
    for folder, dirs, files in os.walk(top):
        for name in dirs + files:
            p = Path(folder) / name
            mode = os.lstat(p).st_mode
            seen[str(p.relative_to(top))] = (stat.S_IMODE(mode), os.readlink(p) if stat.S_ISLNK(mode) else
                                             p.read_bytes() if stat.S_ISREG(mode) else None)
    return seen


# --- a fresh install (verification 1 and 5) ------------------------------------------


@pytest.fixture
def installed(machine, clone):
    done = machine.run(clone, "--address", "192.0.2.5", "--name", "nervus.test", "--yes")
    assert done.returncode == 0, done.stdout + done.stderr
    return machine, done


def test_it_installs_nervus_and_starts_it(installed):
    # What it installs, and where, is under "the release's own folder" below.
    m, done = installed
    log = m.logged()
    assert "useradd --system --home-dir /opt/nervus --shell /usr/sbin/nologin nervus" in log
    systemd = [line for line in log if line.startswith("systemctl")]
    assert systemd[:2] == ["systemctl daemon-reload", "systemctl enable --now nervus"]
    assert systemd[2:] == ["systemctl is-active --quiet nervus", "systemctl enable --now nervus-backup.timer"]
    assert not any(line.startswith("apt-get") for line in log)  # nothing was missing
    assert "nervus is installed and running." in done.stdout


def test_root_reads_nothing_by_name_in_nervus_s_secrets_as_it_installs(installed):
    """It shows the start of each key it has just had nervus's account make. Root read them by
    name, in a folder that account owns; now that account reads them, each read given a time, as
    everywhere else root needs something from a folder that is not its own (procedure 062)."""
    m, done = installed
    reads = [line for line in m.logged() if line.startswith("runuser -u nervus -- timeout --foreground 10 cut ")]
    assert [line.rsplit("/", 1)[1] for line in reads] == ["nervus_ed25519.pub", "nervus_ca_ed25519.pub"], reads
    shown = [line for line in done.stdout.splitlines() if "nervus's SSH key: " in line or "certificate authority: " in line]
    assert len(shown) == 2 and all("ssh-ed25519 AAAA" in line for line in shown), shown


def test_it_asks_nervus_itself_before_it_makes_the_recovery_key(installed):
    # systemd calls a service active the moment its process exists. nervus makes its database as
    # it first starts, and a record in its audit log before that -- the recovery key's -- made
    # nervus refuse to start for good, as if its database were lost, while the installer said
    # "running". Seen on a fresh install on a real machine (procedure 058).
    m, _ = installed
    log = m.logged()
    made_key = next(i for i, line in enumerate(log) if line.startswith("nervus-ctl") and "recovery-key" in line)
    assert log.index("systemctl is-active --quiet nervus") < log.index("check-up") < made_key


def test_a_nervus_that_starts_and_never_answers_is_not_called_running(machine, clone):
    (machine.root / ".down").touch()
    done = machine.run(clone, "--address", "192.0.2.5", "--yes")
    said = done.stdout + done.stderr
    assert done.returncode != 0 and "does not answer" in said, said
    assert "nervus is installed and running" not in said
    log = machine.logged()
    assert not any(line.startswith("nervus-ctl") and "recovery-key" in line for line in log)
    assert "systemctl enable --now nervus-backup.timer" not in log


def test_nervus_is_given_its_own_and_never_the_code(installed):
    # ADR-0029 question 12: the code, and /opt/nervus with the link to it in, stay root's. The
    # account gets its secrets, the transfer folder, the inventory and its log, as a restore does.
    m, _ = installed
    assert _given_to_nervus(m) == {"secrets", "transfer", "hosts.yaml", "var/log/nervus"}


@pytest.mark.parametrize("git", [True, False], ids=["clone", "plain-copy"])
def test_the_code_is_unpacked_as_roots_whoever_owned_the_tree(machine, tmp_path, git):
    # Run as root, tar keeps the owners it reads: a plain copy's files would stay its owner's.
    tree = _tree(tmp_path / "tree", git=git)
    done = machine.run(tree, "--address", "192.0.2.5", "--yes")
    assert done.returncode == 0, done.stdout + done.stderr
    unpacked = [line for line in machine.logged() if line.startswith("tar -x")]
    assert unpacked and all("--no-same-owner" in line.split() for line in unpacked), unpacked


def test_the_inventory_and_token_file_start_empty(installed):
    m, _ = installed
    assert (m.opt / "hosts.yaml").read_text() == "hosts: []\n"  # never the tree's own
    tokens = m.opt / "secrets" / "tokens.yaml"
    assert tokens.read_text() == "tokens: []\n" and _mode(tokens) == 0o600


def test_folders_and_keys_are_as_the_hand_steps_make_them(installed):
    m, _ = installed
    assert _mode(m.opt / "secrets") == 0o700
    assert _mode(m.opt / "transfer") == 0o750 and _mode(m.root / "var" / "log" / "nervus") == 0o750
    pub = (m.opt / "secrets" / "nervus_ed25519.pub").read_text()
    assert pub.startswith("ssh-ed25519 ") and pub.rstrip().endswith(" nervus")
    # The certificate authority beside it, kept the same way (ADR-0025).
    ca = (m.opt / "secrets" / "nervus_ca_ed25519.pub").read_text()
    assert ca.startswith("ssh-ed25519 ") and ca.rstrip().endswith(" nervus-ca") and ca.split()[1] != pub.split()[1]
    assert _mode(m.opt / "secrets" / "nervus_ca_ed25519") == 0o600
    assert sorted(p.name for p in (m.opt / "secrets").iterdir()) == [
        "nervus_ca_ed25519", "nervus_ca_ed25519.pub", "nervus_ed25519", "nervus_ed25519.pub", "recovery.pub", "tls-issuer.crt", "tls-issuer.key", "tls-root.crt",
        "tls.crt", "tls.key", "tokens.yaml"]
    assert (m.root / "var" / "lib" / "nervus" / "switches.yaml").is_file()


def test_the_certificate_names_the_address_and_name_given(installed):
    from cryptography import x509
    m, _ = installed
    cert = x509.load_pem_x509_certificates((m.opt / "secrets" / "tls.crt").read_bytes())[0]
    names = {str(n.value) for n in cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value}
    assert {"192.0.2.5", "nervus.test"} <= names


def test_the_unit_and_drop_in_are_what_the_hand_steps_write(installed, clone):
    """docs/install.md step 8: the unit as shipped; a drop-in restating its
    ExecStart with the installation's flags, at least --ui-url."""
    m, _ = installed
    assert m.unit.read_bytes() == (clone / "deploy" / "nervus.service").read_bytes()
    assert _mode(m.unit) == 0o644 and _mode(m.dropin) == 0o644
    text = m.dropin.read_text()
    assert text.startswith("# Written by install.sh (ADR-0023).\n[Service]\nExecStart=\nExecStart=")
    words = exec_start(m.unit)
    assert words == [*exec_start(clone / "deploy" / "nervus.service"), "--ui-url", "https://nervus.test:8443"]


def test_it_says_what_to_do_next_with_the_real_fingerprint(installed):
    m, done = installed
    fp = certificate_fingerprint((m.opt / "secrets" / "tls-root.crt").read_bytes())
    out = done.stdout
    assert f"  {fp}\n" in out
    assert f"tools/nervus-trust https://192.0.2.5:8000/mcp --expect '{fp}'" in out
    assert "https://ui.test:8443/signin?link=ONE-TIME" in out
    # docs/install.md step 3 as it is since ADR-0015: the tier at setup first, then the Machines
    # page, no restart (procedure 037).
    tier = out.index("On its setup page, the first it shows, choose nervus's tier (docs/install.md step 3)")
    assert tier < out.index("On its Machines page, add each machine nervus will reach (docs/install.md step 3)")
    assert "restart" not in out
    assert "Never give nervus full access to this machine" in out


# --- the release's own folder (ADR-0029 question 3a) ---------------------------------------
#
# What every later release reads: the release's tree and its venv in /opt/nervus/releases/<name>/,
# the name its number and twelve hex digits of its code, and /opt/nervus/.venv a link to its venv.


def test_the_release_goes_in_one_folder_named_for_its_number_and_its_code(installed, clone):
    m, _ = installed
    number = tomllib.loads((clone / "pyproject.toml").read_text())["project"]["version"]
    _, _, code = _named(clone)
    assert os.listdir(m.opt / "releases") == [f"{number}-{code[:12]}"]
    assert re.fullmatch(r"(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*)){2}-[0-9a-f]{12}", _release(m).name)


def test_the_folder_takes_the_trees_own_number(machine, tmp_path):
    tree = _tree(tmp_path / "seven", git=False)
    _numbered(tree, "0.7.0")
    done = machine.run(tree, "--address", "192.0.2.5", "--yes")
    assert done.returncode == 0, done.stdout + done.stderr
    assert _release(machine).name.startswith("0.7.0-")
    assert f"It will install nervus 0.7.0 from the tree at {tree} (not a git clone):" in done.stdout


def test_other_code_under_the_same_number_names_another_release(installed, tmp_path):
    # What step 3's upgrade tells apart: the same release with the same code, or with other code.
    m, _ = installed
    tree = _tree(tmp_path / "other", git=False)
    server = tree / "src" / "nervus" / "server.py"
    server.write_bytes(server.read_bytes() + b"\n")
    second = Machine(tmp_path / "second")
    done = second.run(tree, "--address", "192.0.2.5", "--yes")
    assert done.returncode == 0, done.stdout + done.stderr
    number, code = _release(second).name.split("-")
    clones_number, clones_code = _release(m).name.split("-")
    assert number == clones_number and code != clones_code


def test_a_clone_and_an_archive_of_one_commit_install_one_release(installed, clone, tmp_path):
    m, _ = installed
    archive = tmp_path / "archive"
    archive.mkdir()
    stream = subprocess.run(["git", "-C", str(clone), "archive", "HEAD"], capture_output=True, check=True).stdout
    subprocess.run(["tar", "-x", "-C", str(archive)], input=stream, check=True)
    second = Machine(tmp_path / "second")
    done = second.run(archive, "--address", "192.0.2.5", "--yes")
    assert done.returncode == 0, done.stdout + done.stderr
    assert "(not a git clone)" in done.stdout
    assert _release(second).name == _release(m).name
    assert _files(_release(second), leave_out={".venv"}) == _files(_release(m), leave_out={".venv"})


def test_the_release_holds_the_committed_tree_less_its_inventory(machine, tmp_path):
    # An inventory of its own: this repository's tree has one, and an export's has none to leave out.
    tree = _tree(tmp_path / "copy")
    (tree / "hosts.yaml").write_text("hosts:\n  - name: theirs\n")
    _commit(tree, "hosts.yaml")
    done = machine.run(tree, "--address", "192.0.2.5", "--yes")
    assert done.returncode == 0, done.stdout + done.stderr
    rel = _release(machine)
    committed = subprocess.run(["git", "-C", str(tree), "ls-files", "-z"], capture_output=True, check=True)
    names = [n for n in committed.stdout.decode().split("\0") if n]
    assert "hosts.yaml" in names  # the tree's own inventory, which the release goes without
    assert _files(rel, leave_out={".venv"}) == {n: _entry(tree / n) for n in names if n != "hosts.yaml"}
    for name in (".git", "secrets", "transfer", "hosts.yaml"):
        assert not os.path.lexists(rel / name), name
    assert (rel / ".venv").is_dir() and not (rel / ".venv").is_symlink()


def test_nothing_of_the_tree_is_at_the_top(installed):
    # What nervus keeps stays at the top (ADR-0029 question 3a); the code is the release's.
    m, _ = installed
    assert sorted(os.listdir(m.opt)) == [".venv", "hosts.yaml", "releases", "secrets", "transfer"]
    assert _mode(m.opt / "releases") == 0o755 and _mode(_release(m)) == 0o755


def test_the_release_folder_is_0755_whatever_the_trees_own_mode(machine, tmp_path):
    # A plain copy's stream names its top folder ('./'), whose mode root's tar gives the folder it
    # unpacks into: here a copy kept private to its owner.
    tree = _tree(tmp_path / "private", git=False)
    tree.chmod(0o700)
    done = machine.run(tree, "--address", "192.0.2.5", "--yes")
    assert done.returncode == 0, done.stdout + done.stderr
    assert _mode(_release(machine)) == 0o755


def test_opt_nervus_venv_is_a_relative_link_to_the_releases_own_venv(installed):
    # Relative, so it names the same release wherever the folder is reached from.
    m, _ = installed
    rel = _release(m)
    link = m.opt / ".venv"
    assert link.is_symlink() and os.readlink(link) == f"releases/{rel.name}/.venv"
    assert link.resolve() == (rel / ".venv").resolve()
    assert (rel / ".venv").is_dir() and not (rel / ".venv").is_symlink()


def test_the_venv_is_made_and_filled_at_its_final_path_by_its_own_pip(installed):
    """A venv's scripts name the path they were installed at, so a venv cannot be moved
    (procedure 050): it is made in the release's folder, and filled by that venv's own pip
    from that folder, never through the link."""
    m, _ = installed
    rel = _release(m)
    log = m.logged()
    assert [line for line in log if line.startswith("venv ")] == [f"venv {rel}/.venv"]
    # Its libraries from the lock, each file checked against its hash; then nervus itself, with nothing
    # more fetched; then that the set fits together (ADR-0029, settled 2026-11-15).
    assert [line for line in log if "/bin/pip " in line] == [
        f"{rel}/.venv/bin/pip install --quiet --require-hashes -r {rel}/requirements.lock",
        f"{rel}/.venv/bin/pip install --quiet --no-deps --no-index --no-build-isolation {rel}",
        f"{rel}/.venv/bin/pip check"]


def test_the_units_and_the_off_switch_come_from_the_release(installed):
    m, _ = installed
    rel = _release(m)
    log = m.logged()
    assert f"install -m 0644 {rel}/deploy/nervus.service {m.unit}" in log
    assert (f"install -m 0644 {rel}/deploy/nervus-backup.service {rel}/deploy/nervus-backup.timer "
            f"{m.unit.parent}/") in log
    assert (f"{m.opt}/.venv/bin/python {rel}/tools/ensure-switches --owner nervus "
            f"{m.root}/var/lib/nervus/switches.yaml") in log


def test_the_units_and_the_commands_printed_name_the_link_never_a_release(machine, clone, backup):
    """Switching releases is pointing the link (ADR-0029 question 3a): a unit, or a command given
    to the person, that named a release's own folder would stay on that release. A restore of a
    backup without a recovery key prints the most commands."""
    done = machine.run(clone, "--restore", str(backup), "--address", "192.0.2.5", "--yes")
    assert done.returncode == 0, done.stdout + done.stderr
    systemd = machine.unit.parent
    for unit in (machine.unit, machine.dropin, systemd / "nervus-backup.service", systemd / "nervus-backup.timer"):
        assert "releases" not in unit.read_text(), unit
    assert "\nExecStart=/opt/nervus/.venv/bin/nervus \\\n" in machine.dropin.read_text()
    assert exec_start(machine.unit)[0] == "/opt/nervus/.venv/bin/nervus"
    assert set(re.findall(r"\S*/nervus-ctl\b", done.stdout)) == {f"{machine.opt}/.venv/bin/nervus-ctl"}


def test_what_a_plain_copy_keeps_beside_its_code_is_not_copied(machine, tmp_path, clone):
    # A copy someone ran nervus from, or worked in: its own secrets, venv, uploads, releases and
    # bytecode are not the release's, so they are neither copied nor counted.
    tree = _tree(tmp_path / "used", git=False)
    for path in ("secrets/tokens.yaml", ".venv/pyvenv.cfg", "transfer/upload.bin", "releases/0.1.0-0123456789ab/x",
                 ".release", "src/nervus/__pycache__/server.cpython-313.pyc"):
        (tree / path).parent.mkdir(parents=True, exist_ok=True)
        (tree / path).write_text("theirs\n")
    done = machine.run(tree, "--address", "192.0.2.5", "--yes")
    assert done.returncode == 0, done.stdout + done.stderr
    rel = _release(machine)
    assert rel.name == _named(clone)[0]
    for name in ("secrets", "transfer", "releases", ".release", "src/nervus/__pycache__"):
        assert not os.path.lexists(rel / name), name
    assert not (rel / ".venv" / "pyvenv.cfg").exists()


@pytest.mark.parametrize("git", [True, False], ids=["a clone", "a plain copy"])
def test_no_copy_of_the_trees_own_inventory_is_left(machine, tmp_path, git):
    tree = _tree(tmp_path / "copy", git=git)
    theirs = f"someone-elses-{os.urandom(8).hex()}"  # in no file of this repository's, as its own name is
    (tree / "hosts.yaml").write_text(f"hosts:\n  - name: {theirs}\n")
    if git:
        _commit(tree, "hosts.yaml")  # an export's tree has none until now
    done = machine.run(tree, "--address", "192.0.2.5", "--yes")
    assert done.returncode == 0, done.stdout + done.stderr
    assert (machine.opt / "hosts.yaml").read_text() == "hosts: []\n"
    assert not os.path.lexists(_release(machine) / "hosts.yaml")
    for folder, _, files in os.walk(machine.root):
        for name in files:
            p = Path(folder) / name
            assert p.is_symlink() or theirs.encode() not in p.read_bytes(), p


# --- refusals: nothing changed (verification 2 to 4) -------------------------------------


def test_run_again_it_changes_nothing_and_says_nervus_is_there(installed, clone):
    m, _ = installed
    before = _snapshot(m.opt)
    lines = len(m.logged())
    again = m.run(clone, "--address", "192.0.2.5", "--yes")
    assert again.returncode == 1 and "already installed" in again.stderr
    assert _snapshot(m.opt) == before
    assert len(os.listdir(m.opt / "releases")) == 1
    assert len(m.logged()) == lines


def test_an_existing_account_nervus_is_refused(machine, clone):
    (machine.root / ".user-nervus").touch()
    done = machine.run(clone, "--address", "192.0.2.5", "--yes")
    assert done.returncode == 1 and "already installed" in done.stderr
    assert machine.changed() == [".user-nervus"]


def test_without_systemd_it_changes_nothing(machine, clone):
    shutil.rmtree(machine.root / "run" / "systemd")
    done = machine.run(clone, "--address", "192.0.2.5", "--yes")
    assert done.returncode == 1 and "systemd is not running" in done.stderr
    assert machine.changed() == []


def test_a_python_too_old_is_refused_by_its_version(machine, clone):
    # release-name would fail on it too; the version, checked first, is the reason given.
    machine.python(version="3.10.12")
    done = machine.run(clone, "--address", "192.0.2.5", "--yes")
    assert done.returncode == 1 and "Python 3.10.12 is too old" in done.stderr
    assert machine.changed() == []


def test_without_apt_it_names_everything_missing_and_changes_nothing(machine, clone):
    (machine.bin / "ssh-keygen").unlink()
    (machine.bin / "apt-get").unlink()
    machine.python(venv=False)
    done = machine.run(clone, "--address", "192.0.2.5", "--yes")
    assert done.returncode == 1
    assert "missing, and no apt-get" in done.stderr
    assert "Python's venv" in done.stderr and "ssh-keygen" in done.stderr
    assert machine.changed() == []


def test_with_apt_it_installs_what_is_missing_first(machine, clone):
    (machine.bin / "ssh-keygen").unlink()
    done = machine.run(clone, "--address", "192.0.2.5", "--yes")
    assert done.returncode == 0, done.stderr
    assert "apt-get update, then apt-get install openssh-client (missing: ssh-keygen)" in done.stdout
    # A fresh container template's package lists can be stale: they are
    # refreshed first (procedure 035 step 3, a 404 without it).
    assert machine.logged()[:2] == ["apt-get update", "apt-get install -y openssh-client"]


def test_uncommitted_changes_in_a_clone_are_refused(machine, tmp_path):
    tree = _tree(tmp_path / "dirty")
    with open(tree / "src" / "nervus" / "server.py", "a") as f:
        f.write("# changed\n")
    done = machine.run(tree, "--address", "192.0.2.5", "--yes")
    assert done.returncode == 1 and "uncommitted changes" in done.stderr
    assert machine.changed() == []


def test_an_untracked_file_does_not_count_and_is_not_installed(machine, tmp_path, clone):
    tree = _tree(tmp_path / "untracked")
    (tree / "notes.txt").write_text("mine")
    done = machine.run(tree, "--address", "192.0.2.5", "--yes")
    assert done.returncode == 0, done.stderr
    assert not [p for p in machine.root.rglob("notes.txt")]
    assert _release(machine).name == _named(clone)[0]  # the release a clean clone of the same commit names


@pytest.mark.parametrize("git", [True, False], ids=["a clone", "a plain copy"])
def test_a_release_number_not_in_its_form_is_refused_and_nothing_changes(machine, tmp_path, git):
    tree = _tree(tmp_path / "two", git=git)
    pyproject = tree / "pyproject.toml"
    pyproject.write_text(re.sub(r'(?m)^version = ".*"$', 'version = "0.2"', pyproject.read_text(), count=1))
    if git:
        _commit(tree)
    done = machine.run(tree, "--address", "192.0.2.5", "--yes")
    assert done.returncode == 1
    assert "'0.2', is not three numbers with no leading zeros" in done.stderr
    assert "release cannot be named" in done.stderr and "nothing changed" in done.stderr
    assert "It will install" not in done.stdout and machine.changed() == []


# --- a machine with no Python at all (ADR-0023 question 5a) ---------------------------------------

def _without_python(m) -> None:
    """The machine has no python3. Its apt-get, where it has one, brings python3 when asked for it."""
    kept = m.root.parent / "python3-kept"
    shutil.move(m.bin / "python3", kept)
    _script(m.bin / "apt-get", f'for p in "$@"; do [ "$p" = python3 ] && cp -p {kept} "$(dirname "$0")/python3"; done\n'
            + STANDINS["apt-get"])


def test_a_machine_with_no_python_is_given_python_first_and_then_read_as_any_other(machine, clone):
    # Question 5a promised such a machine Python. It was told "--address 192.0.2.5 is not an IP address":
    # the address was checked with the Python it lacked, and the release was named with it too.
    _without_python(machine)
    done = machine.run(clone, "--address", "192.0.2.5", "--yes")
    assert done.returncode == 0, done.stdout + done.stderr
    assert "is not an IP address" not in done.stderr
    assert machine.logged()[:2] == ["apt-get update", "apt-get install -y python3 python3-venv"]
    out = done.stdout
    assert out.index("This machine has no Python") < out.index("installed python3 python3-venv") \
        < out.index("It will install nervus") < out.index("nervus is installed and running.")


def test_without_python_a_no_to_the_first_question_changes_nothing(machine, clone):
    _without_python(machine)
    done = machine.run(clone, "--address", "192.0.2.5", answer="no\n")
    assert done.returncode == 1 and "nothing changed" in done.stderr and "stay installed" not in done.stderr
    assert "apt-get install python3 python3-venv" in done.stdout  # it said what the yes would be for
    assert machine.logged() == [] and machine.changed() == [] and not (machine.bin / "python3").exists()


def test_without_python_a_no_to_the_plan_leaves_python_and_says_so(machine, clone):
    # Two questions, two answers: the first is for Python alone, the second for the plan, as on any machine.
    _without_python(machine)
    done = machine.run(clone, "--address", "192.0.2.5", answer="yes\nno\n")
    assert done.returncode == 1 and "It will install nervus" in done.stdout
    assert "nothing changed (python3 and python3-venv, installed first, stay installed)" in done.stderr
    assert machine.logged() == ["apt-get update", "apt-get install -y python3 python3-venv"]
    assert machine.changed() == []


def test_without_python_a_bad_address_is_refused_once_python_can_say_so(machine, clone):
    _without_python(machine)
    done = machine.run(clone, "--address", "nervus.test", "--yes")
    assert done.returncode == 1 and "--address nervus.test is not an IP address" in done.stderr
    assert "python3 and python3-venv, installed first, stay installed" in done.stderr and machine.changed() == []


def test_without_python_or_apt_get_everything_missing_is_named_and_nothing_changes(machine, clone):
    _without_python(machine)
    (machine.bin / "apt-get").unlink()
    (machine.bin / "ssh-keygen").unlink()
    done = machine.run(clone, "--address", "192.0.2.5", "--yes")
    assert done.returncode == 1 and "missing, and no apt-get" in done.stderr
    assert "python3, 3.11 or later" in done.stderr and "ssh-keygen" in done.stderr
    assert "is not an IP address" not in done.stderr and machine.changed() == []


def test_with_python_here_nothing_is_asked_before_the_plan(machine, clone):
    done = machine.run(clone, "--address", "192.0.2.5", answer="yes\n")
    assert done.returncode == 0, done.stdout + done.stderr
    assert "This machine has no Python" not in done.stdout and done.stdout.count("Type yes to go ahead") == 1


@pytest.mark.parametrize("answer, installs", [("no\n", False), ("", False), ("yes\n", True)])
def test_it_waits_for_yes(machine, clone, answer, installs):
    done = machine.run(clone, "--address", "192.0.2.5", answer=answer)
    name, number, _ = _named(clone)
    assert f"It will install nervus {number} from commit" in done.stdout
    assert (f"the code and its own venv in {machine.opt}/releases/{name}, root's, and {machine.opt}/.venv a "
            "link to that venv") in done.stdout
    assert "owned by nervus, which can change nothing else" in done.stdout
    assert (done.returncode == 0) == installs
    if not installs:
        assert "nothing changed" in done.stderr and machine.changed() == []


@pytest.mark.parametrize("args, says", [
    ([], "give --address"),
    (["--address", "nervus.test"], "not an IP address"),
    (["--address", "192.0.2.5", "--name", "bad name!"], "not a DNS name"),
    (["--address", "192.0.2.5", "--sideways"], "unknown argument"),
])
def test_bad_arguments_change_nothing(machine, clone, args, says):
    done = machine.run(clone, *args, "--yes")
    assert done.returncode == 1 and says in done.stderr
    assert machine.changed() == []


def test_help_is_the_whole_comment_at_its_top(machine, clone):
    # --help prints a range of install.sh's own lines, which must follow the comment as it grows.
    lines = (clone / "install.sh").read_text().splitlines()
    comment = lines[1:lines.index("set -euo pipefail")]
    assert all(line.startswith("#") for line in comment)
    done = machine.run(clone, "--help")
    assert done.returncode == 0
    assert done.stdout.splitlines() == [re.sub(r"^# ?", "", line) for line in comment]


def test_an_ipv6_address_is_bracketed_in_urls(machine, clone):
    done = machine.run(clone, "--address", "2001:db8::5", "--yes")
    assert done.returncode == 0, done.stderr
    assert "--ui-url https://[2001:db8::5]:8443" in machine.dropin.read_text()
    assert "tools/nervus-trust https://[2001:db8::5]:8000/mcp" in done.stdout


# --- a failure part-way: what is left, and what it says (ADR-0029 question 3a) -----------------
#
# Each leaves only the unfinished release's folder: no link to it, no account, no unit.


def _modes(m) -> dict:
    """Each path the machine holds, and its mode."""
    return {str(p.relative_to(m.root)): _mode(p) for p in m.root.rglob("*") if not p.is_symlink()}


def test_a_strict_umask_in_the_persons_shell_changes_nothing_the_install_makes(machine, clone, tmp_path):
    # sudo passes the shell's umask on. From `umask 077`, a venv nervus's account could not read, and
    # an install stopped at `Permission denied` (procedure 051, finding 1).
    usual = Machine(tmp_path / "usual")
    done = usual.run(clone, "--address", "192.0.2.5", "--yes", umask="022")
    assert done.returncode == 0, done.stdout + done.stderr
    done = machine.run(clone, "--address", "192.0.2.5", "--yes", umask="077")
    assert done.returncode == 0, done.stdout + done.stderr
    assert _modes(machine) == _modes(usual)
    venv = machine.opt / "releases" / _named(clone)[0] / ".venv"
    assert _mode(venv) == _mode(venv / "bin") == _mode(venv / "bin" / "nervus") == 0o755
    assert _mode(machine.dropin) == 0o644
    assert _mode(machine.opt / "secrets" / "tokens.yaml") == 0o600  # what is private stays so


def test_it_writes_nothing_into_the_clone_it_runs_from(machine, tmp_path):
    # Under sudo whatever git wrote there would be root's, and from a strict umask root's alone, so
    # that the person's own `git pull` failed on .git/index (procedure 051, finding 1). A tracked
    # file touched since the index was written is what `git status` refreshes it for.
    tree = _tree(tmp_path / "copy")
    os.utime(tree / "README.md", (1_700_000_000, 1_700_000_000))
    before = {p: p.read_bytes() for p in (tree / ".git").rglob("*") if p.is_file()}
    done = machine.run(tree, "--address", "192.0.2.5", "--yes", umask="077")
    assert done.returncode == 0, done.stdout + done.stderr
    assert {p: p.read_bytes() for p in (tree / ".git").rglob("*") if p.is_file()} == before


def test_uncommitted_changes_are_still_seen_with_the_index_left_alone(machine, tmp_path):
    tree = _tree(tmp_path / "copy")
    os.utime(tree / "README.md", (1_700_000_000, 1_700_000_000))  # stale in the index, and unchanged
    (tree / "CHANGES.md").write_text("changed\n")
    done = machine.run(tree, "--address", "192.0.2.5", "--yes")
    assert done.returncode == 1 and "uncommitted changes" in done.stderr
    assert machine.changed() == []


def _stops_at_the_account(m):
    _script(m.bin / "useradd", 'echo "useradd: cannot lock /etc/passwd" >&2; exit 1')


def _stops_at_the_certificate(m):
    _script(m.bin / "runuser", '[ "$1" = -u ] && shift 2; [ "$1" = -- ] && shift\n'
            'case "$*" in *tls-init*) echo "nervus: cannot write the certificate" >&2; exit 1;; esac; exec "$@"')


def _will_not_start(m):
    # Started, and gone at once; its `sleep` instant, so that the fifteen seconds pass at once.
    hook = m.root / ".on-start"
    hook.write_text('#!/bin/bash\nrm -f "$NERVUS_INSTALL_ROOT/.active"\n')
    hook.chmod(0o755)
    (m.bin / "sleep").unlink()
    _script(m.bin / "sleep", "true")


def _again_from_the_words(m, said: str) -> None:
    """The commands it gave, each run as it gave them, but for sudo, which root has no need of here."""
    commands = [line.removeprefix("  sudo ") for line in said.splitlines() if line.startswith("  sudo ")]
    assert any(c.startswith("rm -rf ") for c in commands), said
    env = {"PATH": str(m.bin), "HOME": str(m.root), "LOG": str(m.log), "NERVUS_INSTALL_ROOT": str(m.root), "LANG": "C"}
    for command in commands:
        done = subprocess.run(["bash", "-c", command], env=env, capture_output=True, text=True)
        assert done.returncode == 0, command + ": " + done.stderr


@pytest.mark.parametrize("stop, its_own_words, account, service", [
    (_stops_at_the_account, "cannot lock /etc/passwd", False, False),
    (_stops_at_the_certificate, "cannot write the certificate", True, False),
    (_will_not_start, "nervus did not start", True, True),
], ids=["at-the-account", "at-the-certificate", "at-the-start"])
def test_an_install_that_stops_after_the_code_says_what_to_remove_and_that_is_enough(machine, clone, stop, its_own_words,
                                                                                     account, service):
    # Run again it took itself for an installed nervus, and said so, in words with no way forward
    # (procedure 051, finding 2).
    stop(machine)
    done = machine.run(clone, "--address", "192.0.2.5", "--yes")
    assert done.returncode == 1 and its_own_words in done.stderr, done.stdout + done.stderr
    assert "the install here did not finish" in done.stderr and "nothing of yours is in it" in done.stderr
    assert ("  sudo userdel nervus" in done.stderr) is account
    assert ("  sudo systemctl disable --now nervus" in done.stderr) is service

    # What it gave is all it takes: what the install made gone, and the same install from there.
    (machine.root / ".on-start").unlink(missing_ok=True)
    _script(machine.bin / "useradd", STANDINS["useradd"])
    _script(machine.bin / "runuser", STANDINS["runuser"])
    _again_from_the_words(machine, done.stderr)
    assert not machine.opt.exists() and not machine.unit.exists() and not (machine.root / ".user-nervus").exists()
    assert not (machine.root / "var" / "lib" / "nervus" / "switches.yaml").exists()
    assert not os.listdir(machine.root / "etc" / "systemd" / "system")  # the units and the drop-in's folder
    again = machine.run(clone, "--address", "192.0.2.5", "--yes")
    assert again.returncode == 0, again.stdout + again.stderr
    assert "nervus is installed and running" in again.stdout and "did not finish" not in again.stdout + again.stderr


@pytest.mark.parametrize("args", [("--address", "192.0.2.5", "--yes"), ("--upgrade", "--yes"), ("--back", "--yes")],
                         ids=["install", "upgrade", "back"])
def test_run_again_over_an_install_that_stopped_it_says_so_and_changes_nothing(machine, clone, args):
    _stops_at_the_certificate(machine)
    assert machine.run(clone, "--address", "192.0.2.5", "--yes").returncode == 1
    before, lines = _snapshot(machine.opt), len(machine.logged())
    again = machine.run(clone, *args)
    assert again.returncode == 1
    assert "the install here did not finish" in again.stderr and "  sudo rm -rf " in again.stderr
    assert "already installed" not in again.stderr and "upgraded by hand" not in again.stderr
    assert _snapshot(machine.opt) == before and len(machine.logged()) == lines


@pytest.mark.parametrize("sign", ["var/lib/nervus/nervus.db", "var/lib/nervus/backups/nervus-backup-1.tar.gz.age",
                                  "var/log/nervus/audit.jsonl", "opt/nervus/secrets/recovery.pub"],
                         ids=["database", "backups", "audit-log", "recovery-key"])
@pytest.mark.parametrize("args", [("--address", "192.0.2.5", "--yes"), ("--upgrade", "--yes"), ("--back", "--yes")],
                         ids=["install", "upgrade", "back"])
def test_a_machine_where_nervus_has_run_is_never_told_to_remove_it(machine, clone, args, sign):
    # The folders with neither unit nor drop-in, as an install stopped partway has them, but for a
    # sign that nervus has run. An earlier installation's backups may be the only ones.
    (machine.opt / "releases").mkdir(parents=True)
    (machine.root / sign).parent.mkdir(parents=True, exist_ok=True)
    (machine.root / sign).touch()
    done = machine.run(clone, *args)
    assert done.returncode == 1
    assert "did not finish" not in done.stderr and "rm -rf" not in done.stderr, done.stderr


def test_a_restore_that_stops_beside_an_earlier_installations_backups_offers_no_removal(machine, clone, tmp_path):
    # A person who cleared away an installation, then restores from a backup still in its folder.
    folder = machine.root / "var" / "lib" / "nervus" / "backups"
    folder.mkdir(parents=True)
    backup = folder / "nervus-backup-20261101T000000Z.tar.gz.age"
    backup.write_bytes(b"age-encryption.org/v1\n")
    (machine.root / ".restore-fails").touch()
    done = machine.run(clone, "--restore", str(backup), "--address", "192.0.2.5", "--yes")
    assert done.returncode == 1 and "the restore did not finish" in done.stderr
    assert "the install here did not finish" in done.stderr and "what it keeps is left as it is" in done.stderr
    assert "rm -rf" not in done.stderr and backup.exists()


def test_a_restore_that_stops_on_a_new_machine_says_what_to_remove_but_never_the_folder_its_backup_may_be_in(machine, clone, tmp_path):
    backup = machine.root / "var" / "lib" / "nervus" / "my-backup.tar.gz.age"
    backup.parent.mkdir(parents=True)
    backup.write_bytes(b"age-encryption.org/v1\n")
    (machine.root / ".restore-fails").touch()
    done = machine.run(clone, "--restore", str(backup), "--address", "192.0.2.5", "--yes")
    assert done.returncode == 1 and "the restore did not finish" in done.stderr
    _again_from_the_words(machine, done.stderr)
    assert backup.exists() and not machine.opt.exists()
    (machine.root / ".restore-fails").unlink()
    again = machine.run(clone, "--restore", str(backup), "--address", "192.0.2.5", "--yes")
    assert again.returncode == 0, again.stdout + again.stderr


def test_an_install_that_stops_after_nervus_has_begun_to_run_offers_no_removal(machine, clone):
    # It wrote its audit log, then went: what it keeps is not to be offered up.
    hook = machine.root / ".on-start"
    hook.write_text('#!/bin/bash\nrm -f "$NERVUS_INSTALL_ROOT/.active"\ntouch "$NERVUS_INSTALL_ROOT/var/log/nervus/audit.jsonl"\n')
    hook.chmod(0o755)
    (machine.bin / "sleep").unlink()
    _script(machine.bin / "sleep", "true")
    done = machine.run(clone, "--address", "192.0.2.5", "--yes")
    assert done.returncode == 1 and "nervus did not start" in done.stderr
    assert "what it keeps is left as it is" in done.stderr and "rm -rf" not in done.stderr


def test_a_failure_once_nervus_has_started_offers_no_removal(machine, clone):
    # nervus runs by then: its own words say what to do, and a person is not told to remove it.
    (machine.bin / "nervus-ctl-standin").unlink()
    _script(machine.bin / "nervus-ctl-standin", 'echo "nervus-ctl: cannot write" >&2; exit 1')
    done = machine.run(clone, "--address", "192.0.2.5", "--yes")
    assert done.returncode == 1 and "nervus is running, but no recovery key was made" in done.stderr
    assert "did not finish" not in done.stderr and "rm -rf" not in done.stderr


# --- the lock (ADR-0029, "Not settled here", settled 2026-11-15) --------------------------------

@pytest.mark.parametrize("change, says", [
    (lambda t: re.sub(r"(?m)^# Made for nervus \S+ on ", "# Made for nervus 9.9.9 on ", t), "was made for 9.9.9"),
    (lambda t: re.sub(r"(?m)^mcp==\S+", "mcp==0.0.1", t), "the lock has mcp 0.0.1"),
    (None, "has no requirements.lock"),
])
def test_a_tree_whose_lock_is_not_its_releases_is_refused_before_anything_changes(machine, tmp_path, change, says):
    tree = _tree(tmp_path / "unlocked")
    lock = tree / "requirements.lock"
    if change is None:
        lock.unlink()
    else:
        lock.write_text(change(lock.read_text()))
    _commit(tree)
    done = machine.run(tree, "--address", "192.0.2.5", "--yes")
    assert done.returncode == 1 and says in done.stderr, done.stdout + done.stderr
    assert "nothing changed" in done.stderr and machine.changed() == [] and machine.logged() == []


def test_a_library_that_is_not_the_one_the_lock_names_stops_the_install_before_nervus_is_built(machine, clone):
    (machine.root / ".pip-hashes-differ").touch()
    done = machine.run(clone, "--address", "192.0.2.5", "--yes")
    assert done.returncode == 1 and "DO NOT MATCH THE HASHES" in done.stderr  # pip's own words, shown
    assert "is not the one this release was tested with" in done.stderr
    assert len([line for line in machine.logged() if "/bin/pip " in line]) == 1  # nothing after it
    assert os.listdir(machine.opt) == ["releases"]


def test_libraries_that_do_not_fit_nervus_stop_the_install(machine, clone):
    (machine.root / ".pip-check-fails").touch()
    done = machine.run(clone, "--address", "192.0.2.5", "--yes")
    assert done.returncode == 1 and "but you have mcp 2.1.0" in done.stderr
    assert "do not fit together" in done.stderr and os.listdir(machine.opt) == ["releases"]


def test_an_upgrade_whose_library_is_not_the_locks_changes_nothing_and_nervus_serves_on(upgradable, clone, tmp_path):
    m = upgradable
    was, tree = _running(m), _newer(clone, tmp_path, "0.2.0")
    (m.root / ".pip-hashes-differ").touch()
    done = m.run(tree, "--upgrade", "--yes")
    assert done.returncode == 1 and "is not the one this release was tested with" in done.stderr
    assert _running(m) == was and "systemctl stop nervus" not in m.logged()


def test_when_pip_fails_no_link_is_made_and_it_says_what_is_left(machine, clone):
    # The likeliest failure part-way: the package index out of reach.
    (machine.root / ".pip-fails").touch()
    done = machine.run(clone, "--address", "192.0.2.5", "--yes")
    assert done.returncode == 1
    assert "No matching distribution" in done.stderr  # pip's own reason, shown
    assert "pip could not install nervus's libraries" in done.stderr and "package index" in done.stderr
    assert "The account nervus and the service were not made" in done.stderr
    assert f"remove {machine.opt} (sudo rm -rf {machine.opt}) before running it again" in done.stderr
    assert os.listdir(machine.opt) == ["releases"]
    assert [p for p in machine.changed() if not p.startswith("opt/nervus")] == [".pip-fails"]


@pytest.mark.parametrize("change", ["lost", "gained", "changed"])
def test_a_copy_that_is_not_the_tree_named_is_stopped_before_its_venv(machine, clone, change):
    # tar stood in for, losing, gaining or changing a file as it unpacks. GNU and BSD tar apply the
    # plain copy's leave-outs differently below its top, so either could; and a tree changed while
    # the plan waits for yes is copied changed.
    real = shutil.which("tar")
    (machine.bin / "tar").unlink()
    act = {"lost": 'rm "$3/README.md"', "gained": 'touch "$3/gained.txt"',
           "changed": 'echo >> "$3/README.md"'}[change]
    _script(machine.bin / "tar", f'"{real}" "$@" || exit; if [ "$1" = -x ] && [ "$2" = -C ]; then {act}; fi')
    done = machine.run(clone, "--address", "192.0.2.5", "--yes")
    assert done.returncode == 1
    assert f"is not the tree named {_named(clone)[0]}: a file was lost, gained or changed" in done.stderr
    assert f"were not made; remove {machine.opt} (sudo rm -rf {machine.opt}) before running it again" in done.stderr
    assert not [line for line in machine.logged() if line.startswith("venv ") or "/bin/pip " in line]
    assert os.listdir(machine.opt) == ["releases"]
    assert [p for p in machine.changed() if not p.startswith("opt/nervus")] == []


# tar stood in for, failing as it copies: unpacking a clone's archive, as on a full disk; packing a
# plain copy, as GNU tar does when a file is written to while it reads it. Either side of the pipe.
COPY_FAILS = {
    "a clone, unpacking": (True, '[ "$1" = -x ] && { "$real" "$@"; echo "tar: src/nervus/server.py: Cannot '
                                 'write: No space left on device" >&2; exit 2; }'),
    "a plain copy, packing": (False, 'case " $* " in *" -cf - . "*) "$real" "$@"; '
                                     'echo "tar: ./src: file changed as we read it" >&2; exit 1;; esac'),
}


@pytest.mark.parametrize("how", COPY_FAILS)
def test_a_copy_that_fails_part_way_says_what_is_left(machine, tmp_path, how):
    git, fails = COPY_FAILS[how]
    tree = _tree(tmp_path / "copy", git=git)
    (machine.bin / "tar").unlink()
    _script(machine.bin / "tar", f'real={shutil.which("tar")}\n{fails}\nexec "$real" "$@"')
    done = machine.run(tree, "--address", "192.0.2.5", "--yes")
    assert done.returncode == 1
    assert re.search(r"^tar: .*(No space left|changed as we read it)", done.stderr, re.M)  # tar's own reason
    assert (f"install.sh: the code could not be copied into {machine.opt}/releases/{_named(tree)[0]}, as it says "
            "above. The account nervus and the service were not made") in done.stderr
    assert f"remove {machine.opt} (sudo rm -rf {machine.opt}) before running it again" in done.stderr
    assert not [line for line in machine.logged() if line.startswith("venv ") or "/bin/pip " in line]
    assert os.listdir(machine.opt) == ["releases"]
    assert [p for p in machine.changed() if not p.startswith("opt/nervus")] == []


# --- --proxmox ----------------------------------------------------------------------------


def test_proxmox_waits_for_its_settings_and_its_inventory_entry(installed, clone):
    m, _ = installed
    before = m.dropin.read_text()
    done = m.run(clone, "--proxmox", "--address", "192.0.2.5", "--yes")
    assert done.returncode == 1 and "run tools/proxmox-access" in done.stderr
    (m.opt / "secrets" / "proxmox.yaml").write_text("url: x\n")
    done = m.run(clone, "--proxmox", "--address", "192.0.2.5", "--yes")
    assert done.returncode == 1 and "hypervisor: proxmox" in done.stderr
    assert m.dropin.read_text() == before


def test_proxmox_adds_its_two_flags_and_restarts_nervus(installed, clone):
    m, _ = installed
    (m.opt / "secrets" / "proxmox.yaml").write_text("url: x\n")
    (m.opt / "hosts.yaml").write_text("hosts:\n  - name: hv\n    hypervisor: proxmox\n")
    done = m.run(clone, "--proxmox", "--address", "192.0.2.5", "--yes")
    assert done.returncode == 0, done.stderr
    assert exec_start(m.unit)[-6:] == [
        "--ui-url", "https://nervus.test:8443", "--proxmox", "/opt/nervus/secrets/proxmox.yaml",
        "--upload-pull-url", "https://192.0.2.5:8000/upload-pull"]
    assert "systemctl restart nervus" in m.logged()
    again = m.run(clone, "--proxmox", "--address", "192.0.2.5", "--yes")
    assert again.returncode == 1 and "already has --proxmox" in again.stderr


def test_proxmox_refuses_a_nervus_not_installed_by_it(machine, clone):
    done = machine.run(clone, "--proxmox", "--address", "192.0.2.5", "--yes")
    assert done.returncode == 1 and "not installed by install.sh" in done.stderr


# --- docs/install.md's commands, as written (ADR-0023 step 3) ---------------------------------

INSTALL_DOC = REPO / "docs" / "install.md"


def _documented(name, tree, backup=None):
    """The marked command, its placeholders filled in, `sudo` dropped (the
    tests run unprivileged, with every system path under a prefix)."""
    import re
    import shlex
    block = re.search(rf"<!-- install:{name} -->\n```bash\n(.*?)\n```", INSTALL_DOC.read_text(), re.S)
    assert block, f"docs/install.md has no install:{name} block"
    cmd = (block.group(1).replace("<your copy of this repository>", str(tree))
           .replace("<nervus's address>", "192.0.2.5").replace("<nervus's name>", "nervus.test")
           .replace("<the backup>", str(backup)))
    words = shlex.split(cmd)
    assert words[:3] == ["cd", str(tree), "&&"] and words[3] == "sudo" and words[4] == "./install.sh"
    return words[5:]


def test_the_install_docs_installer_command_works_as_written(machine, clone):
    done = machine.run(clone, *_documented("installer", clone), answer="yes\n")
    assert done.returncode == 0, done.stderr
    assert "--ui-url https://nervus.test:8443" in machine.dropin.read_text()


def test_the_install_docs_proxmox_command_works_as_written(installed, clone):
    m, _ = installed
    (m.opt / "secrets" / "proxmox.yaml").write_text("url: x\n")
    (m.opt / "hosts.yaml").write_text("hosts:\n  - name: hv\n    hypervisor: proxmox\n")
    done = m.run(clone, *_documented("installer-proxmox", clone), answer="yes\n")
    assert done.returncode == 0, done.stderr
    assert "--upload-pull-url https://192.0.2.5:8000/upload-pull" in m.dropin.read_text()


# --- backups (ADR-0027 step 4) ------------------------------------------------------


def test_the_recovery_key_is_made_once_nervus_runs_and_its_private_half_shown_once(installed):
    m, done = installed
    log = m.logged()
    unit = str(m.unit)
    assert log.index("systemctl enable --now nervus") < log.index(f"nervus-ctl --unit {unit} recovery-key")
    assert done.stdout.count("AGE-SECRET-KEY-1STANDIN") == 1
    # Shown after "installed and running", where it is not scrolled past by the steps.
    assert done.stdout.index("nervus is installed and running.") < done.stdout.index("AGE-SECRET-KEY-1STANDIN")
    assert (m.opt / "secrets" / "recovery.pub").read_text().startswith("age1")


def test_the_daily_backup_is_installed_and_its_timer_enabled(installed, clone):
    m, _ = installed
    systemd_dir = m.unit.parent
    for name in ("nervus-backup.service", "nervus-backup.timer"):
        assert (systemd_dir / name).read_bytes() == (clone / "deploy" / name).read_bytes()
        assert _mode(systemd_dir / name) == 0o644
    log = m.logged()
    assert log.index(f"nervus-ctl --unit {m.unit} recovery-key") < log.index("systemctl enable --now nervus-backup.timer")
    service = (clone / "deploy" / "nervus-backup.service").read_text()
    assert "ExecStart=/opt/nervus/.venv/bin/nervus-ctl backup\n" in service and "Type=oneshot" in service
    timer = (clone / "deploy" / "nervus-backup.timer").read_text()
    assert "OnCalendar=daily" in timer and "Persistent=true" in timer and "WantedBy=timers.target" in timer


def test_age_is_installed_when_missing(machine, clone):
    (machine.bin / "age").unlink()
    (machine.bin / "age-keygen").unlink()
    done = machine.run(clone, "--address", "192.0.2.5", "--yes")
    assert done.returncode == 0, done.stdout + done.stderr
    assert "apt-get install age (missing: age)" in done.stdout
    assert "apt-get install -y age" in machine.logged()


@pytest.fixture
def backup(tmp_path):
    path = tmp_path / "nervus-backup-20261028T163000Z.tar.gz.age"
    path.write_bytes(b"age-encryption.org/v1\n")
    return path


def test_restore_makes_no_keys_and_starts_nervus_only_through_the_restore(machine, clone, backup):
    (machine.root / ".backup-has-key").touch()
    done = machine.run(clone, "--restore", str(backup), "--address", "192.0.2.5", "--yes")
    assert done.returncode == 0, done.stdout + done.stderr
    log = machine.logged()
    assert not [line for line in log if line.startswith("runuser") and ("ssh-keygen" in line or "tls-init" in line)]
    assert "systemctl enable --now nervus" not in log
    restore = log.index(f"nervus-ctl --unit {machine.unit} restore {backup} --yes")
    assert restore < log.index("systemctl start nervus") < log.index("systemctl enable nervus")
    assert log.index("systemctl enable nervus") < log.index("systemctl enable --now nervus-backup.timer")
    assert not [line for line in log if line.endswith("recovery-key")]
    assert "no new keys: nervus's keys, certificates, database and audit log from the backup" in done.stdout
    assert "LOCKDOWN" in done.stdout and "nervus-ctl unlock --all" in done.stdout
    assert "AGE-SECRET-KEY" not in done.stdout and "NOTE" not in done.stdout
    # The drop-in is this machine's: its address.
    assert exec_start(machine.unit)[-2:] == ["--ui-url", "https://192.0.2.5:8443"]


def test_a_restore_ends_with_what_is_true_after_one_not_a_fresh_installs_steps(machine, clone, backup):
    """Procedure 047, finding 3: the tier, the machines, the tokens and the trust came back with the
    backup, so a restore ends with what to check, and that clients need nothing changed."""
    (machine.root / ".backup-has-key").touch()
    done = machine.run(clone, "--restore", str(backup), "--address", "192.0.2.5", "--yes")
    assert done.returncode == 0, done.stdout + done.stderr
    end = done.stdout[done.stdout.index("nervus is restored from"):]
    for fresh in ("choose nervus's tier", "add each machine nervus will reach", "issue a token for each client",
                  "tools/nervus-trust", "keep it with your tokens"):
        assert fresh not in end, fresh
    fp = certificate_fingerprint((machine.opt / "secrets" / "tls-root.crt").read_bytes())
    assert f"the backup's, unchanged by the restore:\n  {fp}\n" in end
    assert "Clients and machines need nothing changed" in end and "at the same name or address" in end
    steps = [end.index(s) for s in ("https://ui.test:8443/signin?link=ONE-TIME",
                                    "tokens issued after it are not here: add them again",
                                    "nervus-ctl unlock --all, or on its Clients page",
                                    "nervus-ctl backup --check <its name>")]
    assert steps == sorted(steps)
    assert "Never give nervus full access to this machine" in end


def test_a_restored_backup_without_a_recovery_key_says_to_make_one(machine, clone, backup):
    done = machine.run(clone, "--restore", str(backup), "--address", "192.0.2.5", "--yes")
    assert done.returncode == 0, done.stderr
    assert "the backup held no recovery key" in done.stdout and "nervus-ctl recovery-key" in done.stdout


def test_a_restore_that_fails_leaves_nervus_installed_and_not_started(machine, clone, backup):
    (machine.root / ".restore-fails").touch()
    done = machine.run(clone, "--restore", str(backup), "--address", "192.0.2.5", "--yes")
    assert done.returncode == 1 and "the restore did not finish" in done.stderr
    log = machine.logged()
    assert not [line for line in log if line.startswith("systemctl enable")]
    assert not (machine.root / ".active").exists()


def test_without_yes_the_restore_asks_for_itself(machine, clone, backup):
    done = machine.run(clone, "--restore", str(backup), "--address", "192.0.2.5", answer="yes\n")
    assert done.returncode == 0, done.stderr
    assert f"nervus-ctl --unit {machine.unit} restore {backup}" in machine.logged()


@pytest.mark.parametrize("args, says", [
    (["--restore", "/no/such/backup", "--address", "192.0.2.5"], "no such file"),
    (["--restore", "BACKUP", "--proxmox", "--address", "192.0.2.5"], "separate steps"),
])
def test_a_restore_that_cannot_be_done_changes_nothing(machine, clone, backup, args, says):
    done = machine.run(clone, *[str(backup) if a == "BACKUP" else a for a in args], "--yes")
    assert done.returncode == 1 and says in done.stderr
    assert machine.changed() == []


def test_the_install_docs_restore_command_works_as_written(machine, clone, backup):
    done = machine.run(clone, *_documented("installer-restore", clone, backup), answer="yes\n")
    assert done.returncode == 0, done.stderr
    assert f"nervus-ctl --unit {machine.unit} restore {backup}" in machine.logged()
    assert "--ui-url https://nervus.test:8443" in machine.dropin.read_text()


# --- an upgrade (ADR-0029 step 3) ------------------------------------------------------

PROXMOX_FLAGS = " \\\n    --proxmox /opt/nervus/secrets/proxmox.yaml \\\n    --upload-pull-url https://192.0.2.5:8000/upload-pull\n"


@pytest.fixture
def upgradable(machine, clone):
    """An installation this installer made, of the clone's release, ready for --upgrade; its `sleep`
    instant, so that the judge's five seconds pass at once, and its log only what follows."""
    done = machine.run(clone, "--address", "192.0.2.5", "--name", "nervus.test", "--yes")
    assert done.returncode == 0, done.stdout + done.stderr
    (machine.bin / "sleep").unlink()  # a link to the real one
    _script(machine.bin / "sleep", "true")
    machine.log.write_text("")
    return machine


def _newer(clone: Path, tmp: Path, number: str, sections=(), unit=None, schema=None) -> Path:
    """A clone of another release: the clone's files with its release number raised to `number`, CHANGES.md
    given `sections` (number, what each client must do) above its own, the unit's command line `unit` added
    at its end, and the database's version made `schema`; committed."""
    tree = tmp / f"tree-{number}"
    shutil.copytree(clone, tree, symlinks=True)
    _numbered(tree, number)
    if sections:
        changes = tree / "CHANGES.md"
        text = changes.read_text()
        at = text.index("\n## ")
        changes.write_text(text[:at] + "".join(
            f"\n## {n}\n\nExported 2026-11-20.\n\n**What you will see:** what {n} changed.\n\n"
            f"**What each client must do:** {client}\n\n**What the upgrade does:** nothing more.\n"
            for n, client in sections) + text[at:])
    if unit:
        service = tree / "deploy" / "nervus.service"
        service.write_text(service.read_text().replace("    --ui-port 8443\n", f"    --ui-port 8443 \\\n    {unit}\n"))
    if schema:
        database = tree / "src" / "nervus" / "database.py"
        database.write_text(database.read_text().replace("SCHEMA_VERSION = 1\n", f"SCHEMA_VERSION = {schema}\n"))
    _commit(tree)
    return tree


def _running(m) -> str:
    """The release /opt/nervus/.venv names."""
    return os.readlink(m.opt / ".venv").removeprefix("releases/").removesuffix("/.venv")


def _database(m, version=1) -> Path:
    """A database of the given version, as nervus makes it, with one row of its own."""
    path = m.root / "var" / "lib" / "nervus" / "nervus.db"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE kept (x)")
        db.execute("INSERT INTO kept VALUES ('before the upgrade')")
        db.execute(f"PRAGMA user_version = {version}")
    db.close()
    return path


def _tables(path: Path) -> list[str]:
    with sqlite3.connect(path) as db:
        names = sorted(row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'"))
    db.close()
    return names


def _writes_once_started(m, release: str) -> None:
    """What nervus does at a start, on `release` alone: it writes to its database."""
    hook = m.root / ".on-start"
    hook.write_text('#!/bin/bash\ncase $(readlink "$NERVUS_INSTALL_ROOT/opt/nervus/.venv") in '
                    f'*{release}*) python3 -c \'import sqlite3, sys; db = sqlite3.connect(sys.argv[1]); '
                    'db.execute("CREATE TABLE written_by_the_new_release (x)"); db.commit()\' '
                    '"$NERVUS_INSTALL_ROOT/var/lib/nervus/nervus.db";; esac\n')
    hook.chmod(0o755)


def test_an_upgrade_builds_the_new_release_beside_the_old_and_switches_nervus_to_it(upgradable, clone, tmp_path):
    m = upgradable
    was, tree = _running(m), _newer(clone, tmp_path, "0.2.0")
    new = _named(tree)[0]
    dropin = m.dropin.read_bytes()
    done = m.run(tree, "--upgrade", "--yes")
    assert done.returncode == 0, done.stdout + done.stderr
    assert sorted(os.listdir(m.opt / "releases")) == sorted([was, new]) and _running(m) == new
    for unit in ("nervus.service", "nervus-backup.service", "nervus-backup.timer"):
        assert (m.root / "etc" / "systemd" / "system" / unit).read_bytes() == (tree / "deploy" / unit).read_bytes(), unit
    assert m.dropin.read_bytes() == dropin  # the same command line, and the installation's own flags
    log = m.logged()
    assert f"venv {m.opt}/releases/{new}/.venv" in log  # built where it stays
    ctl = f"nervus-ctl --unit {m.unit}"
    order = ["systemctl stop nervus-backup.timer", f"{ctl} backup", f"{ctl} upgrade-record begin {was} {new}",
             "systemctl stop nervus", "systemctl start nervus", f"{ctl} upgrade-record up {was} {new}",
             "systemctl start nervus-backup.timer"]
    assert [line for line in log if line in order] == order
    assert "nervus is upgraded, from 0.1.0 to 0.2.0" in done.stdout
    # The kept backup, which a backup later the same day does not remove, as it removes the daily one.
    assert "backup --check nervus-2026-11-04T120000Z.before-it.age" in done.stdout
    assert "backup --check nervus-2026-11-04T120000Z.age" not in done.stdout


def test_the_plan_names_both_releases_what_changed_and_the_last_check_and_waits_for_yes(upgradable, clone, tmp_path):
    m = upgradable
    was, tree = _running(m), _newer(clone, tmp_path, "0.2.0")
    before = _snapshot(m.root)
    done = m.run(tree, "--upgrade", answer="no\n")
    assert done.returncode == 1 and "nothing changed" in done.stderr
    assert _snapshot(m.root) == before and not [line for line in m.logged() if line == "systemctl stop nervus"]
    for says in ("It will upgrade nervus 0.1.0 to 0.2.0", f"installed now: {was}; this tree: {_named(tree)[0]}",
                 "## 0.2.0", "last check passed 2026-11-03 10:00", "the database kept as it is",
                 "or a step after the stop fails,", f"it goes back to {was} by itself"):
        assert says in done.stdout, says


def test_without_upgrade_an_installed_nervus_is_left_as_it_is_naming_both_releases(upgradable, clone, tmp_path):
    # Verification 9, and ADR-0023 verification 2.
    m = upgradable
    was, tree = _running(m), _newer(clone, tmp_path, "0.2.0")
    before = _snapshot(m.root)
    done = m.run(tree, "--address", "192.0.2.5", "--yes")
    assert done.returncode == 1 and _snapshot(m.root) == before
    for says in ("already installed", f"It runs {was}", f"this tree holds {_named(tree)[0]}", "install.sh --upgrade"):
        assert says in done.stderr, says


def test_an_older_release_is_refused_and_nothing_changes(upgradable, clone, tmp_path):
    m = upgradable
    before = _snapshot(m.root)
    done = m.run(_newer(clone, tmp_path, "0.0.9"), "--upgrade", "--yes")
    assert done.returncode == 1 and "older than the 0.1.0 installed here" in done.stderr
    assert _snapshot(m.root) == before


def test_uncommitted_changes_in_a_clone_refuse_an_upgrade_before_anything_changes(upgradable, clone, tmp_path):
    # ADR-0029 question 1 and verification 3: as at install, it installs only a committed tree.
    m = upgradable
    tree = _newer(clone, tmp_path, "0.2.0")
    (tree / "README.md").write_text("changed\n")
    before = _snapshot(m.root)
    done = m.run(tree, "--upgrade", "--yes")
    assert done.returncode == 1 and "uncommitted changes" in done.stderr and _snapshot(m.root) == before


def test_the_release_installed_is_nothing_to_do(upgradable, clone):
    m = upgradable
    before = _snapshot(m.root)
    done = m.run(clone, "--upgrade", "--yes")
    assert done.returncode == 1 and "nothing to do" in done.stderr and _snapshot(m.root) == before


def test_a_newer_archive_unpacked_upgrades_as_a_clone_does(upgradable, tmp_path):
    # A friend's newer archive, unpacked in a folder of its own: no git, its release named from its files.
    m = upgradable
    tree = _tree(tmp_path / "archive", git=False)
    _numbered(tree, "0.2.0")
    done = m.run(tree, "--upgrade", "--yes")
    assert done.returncode == 0, done.stdout + done.stderr
    assert f"from the tree at {tree} (not a git clone)" in done.stdout and _running(m) == _named(tree)[0]
    assert not (m.dropin.parent / "instance.conf.new").exists()


def test_the_same_number_with_other_code_goes_ahead_saying_so(upgradable, clone, tmp_path):
    # A build between exports, which only this repository makes (question 2a).
    m = upgradable
    tree = tmp_path / "other-code"
    shutil.copytree(clone, tree, symlinks=True)
    (tree / "README.md").write_text((tree / "README.md").read_text() + "\nOther code.\n")
    _commit(tree)
    done = m.run(tree, "--upgrade", "--yes")
    assert done.returncode == 0, done.stdout + done.stderr
    assert "the same number with other code" in done.stdout and _running(m) == _named(tree)[0]


@pytest.mark.parametrize("how", ["another-drop-in", "a-venv-not-a-link"])
def test_an_installation_this_installer_did_not_make_in_release_folders_is_refused(upgradable, clone, tmp_path, how):
    m = upgradable
    if how == "another-drop-in":
        m.dropin.write_text(m.dropin.read_text().replace("# Written by install.sh (ADR-0023).", "# my own"))
    else:
        (m.opt / ".venv").unlink()
        (m.opt / ".venv").mkdir()
    before = _snapshot(m.root)
    done = m.run(_newer(clone, tmp_path, "0.2.0"), "--upgrade", "--yes")
    assert done.returncode == 1 and "upgraded by hand" in done.stderr and _snapshot(m.root) == before


@pytest.mark.parametrize("change, says", [
    (lambda text: text + "Environment=EXTRA=1\n", "not the installation's own flags"),
    (lambda text: text.replace("--bind-port 8000", "--bind-port 9000"), "--bind-port 9000"),
], ids=["a-line-added", "its-command-line-changed"])
def test_a_drop_in_not_as_the_installer_writes_it_is_refused_saying_where(upgradable, clone, tmp_path, change, says):
    m = upgradable
    m.dropin.write_text(change(m.dropin.read_text()))
    before = _snapshot(m.root)
    done = m.run(_newer(clone, tmp_path, "0.2.0"), "--upgrade", "--yes")
    assert done.returncode == 1 and "is not as install.sh writes it" in done.stderr and says in done.stderr, done.stderr
    assert _snapshot(m.root) == before


def test_a_unit_whose_command_line_changed_runs_it_with_exactly_the_installations_own_flags(upgradable, clone, tmp_path):
    # Verification 4: the drop-in written again, the new command line then this installation's flags.
    m = upgradable
    m.dropin.write_text(m.dropin.read_text().rstrip("\n") + PROXMOX_FLAGS)
    tree = _newer(clone, tmp_path, "0.2.0", unit="--example-new-option on")
    done = m.run(tree, "--upgrade", "--yes")
    assert done.returncode == 0, done.stdout + done.stderr
    unit = (tree / "deploy" / "nervus.service").read_text().splitlines()
    command = unit[next(i for i, line in enumerate(unit) if line.startswith("ExecStart=")):]
    command = command[:next(i for i, line in enumerate(command) if not line.endswith("\\")) + 1]
    assert m.dropin.read_text() == "\n".join(
        ["# Written by install.sh (ADR-0023).", "[Service]", "ExecStart=", *command[:-1], command[-1] + " \\",
         "    --ui-url https://nervus.test:8443"]) + PROXMOX_FLAGS
    assert "--example-new-option on" in done.stdout  # the plan showed the drop-in as it would be


def test_when_the_new_release_is_not_up_it_goes_back_by_itself(upgradable, clone, tmp_path):
    # Verification 2: the release before runs again, from its own venv, with its unit and drop-in.
    m = upgradable
    was, tree = _running(m), _newer(clone, tmp_path, "0.2.0", unit="--example-new-option on")
    new = _named(tree)[0]
    unit, dropin = m.unit.read_bytes(), m.dropin.read_bytes()
    (m.root / f".down-{new}").touch()
    done = m.run(tree, "--upgrade", "--yes")
    assert done.returncode == 1, done.stdout + done.stderr
    assert f"went back to {was} by itself" in done.stderr and "the MCP endpoint did not answer" in done.stderr
    assert _running(m) == was and m.unit.read_bytes() == unit and m.dropin.read_bytes() == dropin
    assert (m.opt / "releases" / new).is_dir()  # left for reading
    log = m.logged()
    assert any(line.startswith(f"nervus-ctl --unit {m.unit} upgrade-record back {was} {new} --why ") for line in log)
    assert log[-1] == "systemctl start nervus-backup.timer"
    order = ["systemctl stop nervus", "systemctl start nervus"] * 2  # stopped on the new release, before the switch back
    assert [line for line in log if line in order] == order


def test_from_a_strict_umask_an_upgrade_builds_a_release_nervus_can_read(upgradable, clone, tmp_path):
    # From `umask 077`, the release it built could not be run, so it went back (procedure 051, finding 1).
    m = upgradable
    tree = _newer(clone, tmp_path, "0.2.0", unit="--example-new-option on")
    done = m.run(tree, "--upgrade", "--yes", umask="077")
    assert done.returncode == 0, done.stdout + done.stderr
    venv = m.opt / "releases" / _named(tree)[0] / ".venv"
    assert _mode(venv) == _mode(venv / "bin") == _mode(venv / "bin" / "nervus") == 0o755
    assert _mode(m.dropin) == 0o644


def test_from_a_strict_umask_going_back_leaves_a_drop_in_every_backup_can_read(upgradable, clone, tmp_path):
    # Each backup reads the drop-in as nervus's account. Written 0600 by going back, it stopped every
    # later backup, the daily one too, with nothing else wrong (procedure 051, finding 1).
    m = upgradable
    tree = _newer(clone, tmp_path, "0.2.0", unit="--example-new-option on")
    (m.root / f".down-{_named(tree)[0]}").touch()
    done = m.run(tree, "--upgrade", "--yes", umask="077")
    assert done.returncode == 1 and "by itself" in done.stderr, done.stdout + done.stderr
    assert _mode(m.dropin) == 0o644


@pytest.mark.parametrize("pids, says", [
    ("4242\n0\n", "main process 4242, then 0"),
    ("4242\n4300\n", "main process 4242, then 4300"),
    ("0\n4300\n", "main process 0, then 4300"),
    ("0\n0\n", "main process 0, then 0"),
    ("4242\n4242\n4300\n", "it restarted while it was being checked (main process 4242, then 4300)"),
], ids=["gone", "restarted", "not-yet", "never-one", "restarted-during-the-check"])
def test_a_release_that_does_not_stay_on_one_main_process_is_not_up(upgradable, clone, tmp_path, pids, says):
    # The check can now take a minute, so a release may restart behind it and answer all the same.
    m = upgradable
    was, tree = _running(m), _newer(clone, tmp_path, "0.2.0")
    (m.root / ".pids").write_text(pids)
    done = m.run(tree, "--upgrade", "--yes")
    assert done.returncode == 1 and f"went back to {was} by itself" in done.stderr, done.stdout + done.stderr
    assert says in done.stderr
    assert _running(m) == was


def test_when_it_goes_back_it_shows_nervus_s_own_last_lines_first(upgradable, clone, tmp_path):
    # "It did not stay running" is true and tells a person nothing; the release's own last words, or
    # systemd's "Permission denied", do (procedure 051, finding 4).
    m = upgradable
    tree = _newer(clone, tmp_path, "0.2.0")
    new = _named(tree)[0]
    (m.root / f".journal-{new}").write_text("".join(f"line {n}\n" for n in range(1, 21)) + "ValueError: bad option\n")
    (m.root / ".pids").write_text("4242\n0\n")
    done = m.run(tree, "--upgrade", "--yes")
    assert done.returncode == 1, done.stdout + done.stderr
    said = done.stdout
    words = ("it did not stay running", "Its journal since it started, the last lines:", "    ValueError: bad option", "Going back to")
    at = [said.index(w) for w in words]
    assert at == sorted(at), said
    assert "    line 7\n" in said and "    line 6\n" not in said  # the last fifteen, no more
    assert "before this start" not in said


def test_going_back_shows_those_lines_for_the_release_it_could_not_start(upgraded):
    m, was, now, tree, _, _ = upgraded
    (m.root / f".journal-{was}").write_text("ValueError: bad option\n")
    (m.root / ".pids").write_text("4242\n0\n")
    done = m.run(tree, "--back", "--yes")
    assert done.returncode == 1, done.stdout + done.stderr
    assert "    ValueError: bad option" in done.stdout
    assert done.stdout.index("Its journal since it started") < done.stdout.index(f"Returning to {now}")


def test_a_journal_that_cannot_be_read_does_not_stop_it_going_back(upgradable, clone, tmp_path):
    # Going back matters more than the words.
    m = upgradable
    was, tree = _running(m), _newer(clone, tmp_path, "0.2.0")
    (m.root / ".pids").write_text("4242\n0\n")
    (m.bin / "journalctl").unlink()
    _script(m.bin / "journalctl", 'echo "journalctl: no journal" >&2; exit 1')
    done = m.run(tree, "--upgrade", "--yes")
    assert done.returncode == 1 and f"went back to {was} by itself" in done.stderr, done.stdout + done.stderr
    assert _running(m) == was


def test_an_off_switch_the_new_release_cannot_read_is_not_up(upgradable, clone, tmp_path):
    # Active is not up: nervus says at its start that it refuses every client (question 7).
    m = upgradable
    was, tree = _running(m), _newer(clone, tmp_path, "0.2.0")
    (m.root / f".journal-{_named(tree)[0]}").write_text(
        "WARNING: every client is refused until the off switch is fixed: unreadable\n")
    done = m.run(tree, "--upgrade", "--yes")
    assert done.returncode == 1 and "off switch is unreadable" in done.stderr and _running(m) == was


def test_the_words_the_upgrade_looks_for_are_the_ones_nervus_prints(tmp_path):
    # Its stand-in journal shows what the check does with them; this holds them to nervus's own.
    import asyncssh
    from nervus.tls import generate_own_authority, root_cert_path
    from test_main import _write_hosts, _write_key, _write_proxmox, _write_tokens

    installer = (REPO / "install.sh").read_text()
    assert "grep -q 'off switch is fixed'" in installer and "grep -q 'no inventory entry is marked'" in installer
    ca = tmp_path / "ca"
    ca.write_bytes(asyncssh.generate_private_key("ssh-ed25519").export_private_key())
    ca.chmod(0o600)
    generate_own_authority(tmp_path / "tls.crt", tmp_path / "tls.key", ["nervus.test"])
    proxmox = _write_proxmox(tmp_path, root_cert_path(tmp_path / "tls.crt"))
    done = subprocess.run(
        [sys.executable, "-c", "import sys; import nervus.__main__ as m; m.serve = lambda *a: None; sys.exit(m.main(sys.argv[1:]))",
         "--hosts", str(_write_hosts(tmp_path)), "--tokens", str(_write_tokens(tmp_path)), "--ssh-key", str(_write_key(tmp_path)),
         "--ssh-ca-key", str(ca), "--switches", str(tmp_path / "absent.yaml"), "--proxmox", str(proxmox)],
        capture_output=True, text=True, timeout=60)
    assert "off switch is fixed" in done.stderr, done.stderr
    assert "no inventory entry is marked" in done.stderr, done.stderr


def _moves_its_ports(tree: Path) -> None:
    """The tree's unit made to serve MCP on 9000 and the web UI on 9443; committed."""
    service = tree / "deploy" / "nervus.service"
    text = service.read_text()
    assert "--bind-port 8000" in text and "--ui-port 8443" in text
    service.write_text(text.replace("--bind-port 8000", "--bind-port 9000").replace("--ui-port 8443", "--ui-port 9443"))
    _commit(tree)


def _asked_on(m) -> list[str]:
    """The ports nervus was asked on, each time it was judged, in order."""
    return [line.removeprefix("check-up asked on ") for line in m.logged() if line.startswith("check-up asked on ")]


def test_going_back_asks_the_release_before_on_its_own_ports(upgradable, clone, tmp_path):
    # A release that moves nervus's ports and does not come up. The release before is asked on the ports
    # it serves, not on those of the release it came from, or it is called down while it answers.
    m = upgradable
    was, tree = _running(m), _newer(clone, tmp_path, "0.2.0")
    _moves_its_ports(tree)
    (m.root / f".down-{_named(tree)[0]}").touch()
    done = m.run(tree, "--upgrade", "--yes")
    assert done.returncode == 1 and f"went back to {was} by itself" in done.stderr, done.stdout + done.stderr
    assert _asked_on(m) == ["9000 9443", "8000 8443"]


def test_returning_from_a_release_kept_that_is_not_up_asks_this_release_on_its_own_ports(upgradable, clone, tmp_path):
    # The same on --back: the release kept serves the old ports and does not come up, so nervus returns
    # to the release it was on, which moved them, and is asked there.
    m = upgradable
    was, tree = _running(m), _newer(clone, tmp_path, "0.2.0")
    _moves_its_ports(tree)
    now = _named(tree)[0]
    done = m.run(tree, "--upgrade", "--yes")
    assert done.returncode == 0, done.stdout + done.stderr
    m.log.write_text("")
    (m.root / f".down-{was}").touch()
    done = m.run(tree, "--back", "--yes")
    assert done.returncode == 1 and f"returned to {now} by itself" in done.stderr, done.stdout + done.stderr
    assert _asked_on(m) == ["8000 8443", "9000 9443"]


@pytest.mark.parametrize("how", ["--upgrade", "--back"])
def test_an_installation_whose_own_command_line_gives_no_port_is_refused_before_anything_changes(
        upgradable, clone, tmp_path, how):
    # Going back by itself must be able to ask the release it returns to. One whose command line names no
    # port could not be asked, so the run stops before the stop, as for the new release's.
    m = upgradable
    tree = _newer(clone, tmp_path, "0.2.0")
    if how == "--back":
        assert m.run(tree, "--upgrade", "--yes").returncode == 0
    for path in (m.unit, m.dropin):  # the unit installed and its copy in the drop-in, alike
        text = path.read_text()
        assert "    --bind-port 8000 \\\n" in text
        path.write_text(text.replace("    --bind-port 8000 \\\n", ""))
    m.log.write_text("")
    before = _running(m)
    done = m.run(tree, how, "--yes")
    assert done.returncode == 1 and "gives no --bind-port or no --ui-port" in done.stderr, done.stdout + done.stderr
    assert "nothing changed" in done.stderr and _running(m) == before
    assert not any(line.startswith("systemctl stop") for line in m.logged())


def test_if_neither_release_comes_up_it_says_nervus_is_down(upgradable, clone, tmp_path):
    m = upgradable
    was, tree = _running(m), _newer(clone, tmp_path, "0.2.0")
    (m.root / f".down-{_named(tree)[0]}").touch()
    (m.root / f".down-{was}").touch()
    done = m.run(tree, "--upgrade", "--yes")
    assert done.returncode == 1 and "NERVUS IS DOWN" in done.stderr and "nervus-2026-11-04T120000Z.age" in done.stderr


def _down_records(m) -> list[str]:
    """The records of a run's end with nervus down, as nervus-ctl was asked for them, in order."""
    return [line.removeprefix(f"nervus-ctl --unit {m.unit} upgrade-record ") for line in m.logged()
            if " upgrade-record down " in line or "NERVUS IS DOWN" in line]


def test_an_upgrade_that_leaves_nervus_down_puts_that_end_on_record(upgradable, clone, tmp_path):
    # ADR-0029, "Settled already": an upgrade's end is an operator record, and this is the end that most
    # needs one. nervus-ctl writes it without nervus running. Before, only the terminal was told.
    m = upgradable
    was, tree = _running(m), _newer(clone, tmp_path, "0.2.0")
    new = _named(tree)[0]
    (m.root / f".down-{new}").touch()
    (m.root / f".down-{was}").touch()
    done = m.run(tree, "--upgrade", "--yes")
    assert done.returncode == 1 and "NERVUS IS DOWN" in done.stderr, done.stdout + done.stderr
    record, = _down_records(m)
    assert record.startswith(f"down {was} {new} --why not up on {new} (") and f"nor, gone back, on {was} (" in record
    assert "the MCP endpoint did not answer" in record  # why, for each release
    assert "could not be written" not in done.stdout


def test_going_back_that_leaves_nervus_down_puts_that_end_on_record(upgraded):
    m, was, now, tree, *_ = upgraded
    (m.root / f".down-{was}").touch()
    (m.root / f".down-{now}").touch()
    done = m.run(tree, "--back", "--yes")
    assert done.returncode == 1 and "NERVUS IS DOWN" in done.stderr, done.stdout + done.stderr
    record, = _down_records(m)
    assert record.startswith(f"down {was} {now} --why not up on {was} (") and f"nor, returned, on {now} (" in record


@pytest.mark.parametrize("how", ["--upgrade", "--back"])
def test_a_release_from_before_the_stage_down_records_it_with_a_stage_it_knows(upgradable, clone, tmp_path, how):
    # Each record is written by the nervus-ctl of the release current at that moment. Gone back to a release
    # from before "down", that one refuses the word: the same is then said as "back", its reason beginning
    # NERVUS IS DOWN, and the refused try shows nowhere.
    m = upgradable
    was, tree = _running(m), _newer(clone, tmp_path, "0.2.0")
    new = _named(tree)[0]
    if how == "--back":
        assert m.run(tree, "--upgrade", "--yes").returncode == 0
        m.log.write_text("")
    (m.root / f".down-{new}").touch()
    (m.root / f".down-{was}").touch()
    (m.root / ".no-down-stage").touch()
    done = m.run(tree, how, "--yes")
    assert done.returncode == 1 and "NERVUS IS DOWN" in done.stderr, done.stdout + done.stderr
    tried, written = _down_records(m)
    assert tried.startswith(f"down {was} {new} --why ")
    assert written.startswith(f"back {was} {new} --why NERVUS IS DOWN: not up on ")
    assert "invalid choice" not in done.stdout + done.stderr and "could not be written" not in done.stdout


def test_a_down_record_that_cannot_be_written_says_so_and_stops_nothing(upgradable, clone, tmp_path):
    m = upgradable
    was, tree = _running(m), _newer(clone, tmp_path, "0.2.0")
    (m.root / f".down-{_named(tree)[0]}").touch()
    (m.root / f".down-{was}").touch()
    (m.root / ".down-record-fails").touch()
    done = m.run(tree, "--upgrade", "--yes")
    assert done.returncode == 1 and "NERVUS IS DOWN" in done.stderr, done.stdout + done.stderr
    assert "nervus is down, and the record of that could not be written to its audit log" in done.stdout
    assert m.logged()[-1] == "systemctl start nervus-backup.timer"


def test_going_back_puts_the_database_copy_back_where_its_version_rose(upgradable, clone, tmp_path):
    # Verification 5: what the new release wrote after its start is lost, as question 7 says.
    m = upgradable
    database = _database(m, version=1)
    tree = _newer(clone, tmp_path, "0.2.0", schema=2)
    new = _named(tree)[0]
    _writes_once_started(m, new)
    (m.root / f".down-{new}").touch()
    done = m.run(tree, "--upgrade", "--yes")
    assert done.returncode == 1 and "rises from 1 to 2" in done.stdout, done.stdout + done.stderr
    assert _tables(database) == ["kept"]
    assert sorted(p.name for p in database.parent.glob("nervus.db*")) == ["nervus.db"]


def test_with_its_version_unchanged_the_database_is_kept_on_going_back(upgradable, clone, tmp_path):
    m = upgradable
    database = _database(m, version=1)
    tree = _newer(clone, tmp_path, "0.2.0")
    new = _named(tree)[0]
    _writes_once_started(m, new)
    (m.root / f".down-{new}").touch()
    done = m.run(tree, "--upgrade", "--yes")
    assert done.returncode == 1 and "the database kept as it is, at version 1" in done.stdout
    assert _tables(database) == ["kept", "written_by_the_new_release"]


def test_a_database_newer_than_the_release_knows_is_refused(upgradable, clone, tmp_path):
    m = upgradable
    _database(m, version=5)
    before = _snapshot(m.root)
    done = m.run(_newer(clone, tmp_path, "0.2.0"), "--upgrade", "--yes")
    assert done.returncode == 1 and "newer than this release knows" in done.stderr and _snapshot(m.root) == before


def test_an_upgrade_from_two_releases_back_shows_both_sections(upgradable, clone, tmp_path):
    # Verification 7.
    m = upgradable
    tree = _newer(clone, tmp_path, "0.3.0", sections=[("0.3.0", "pull the repository on each client machine.")])
    done = m.run(tree, "--upgrade", "--yes")
    assert done.returncode == 0, done.stdout + done.stderr
    plan, closing = done.stdout.split("nervus is upgraded")
    assert "## 0.3.0" in plan and "## 0.2.0" in plan and "## 0.1.0" not in plan
    assert "\n  0.3.0: pull the repository on each client machine." in closing and "\n  0.2.0: " in closing


# --- the backup made before the upgrade, kept until the next (ADR-0029 step 7) -----------------

def _kept_calls(m) -> list[str]:
    """Each asking about the kept backup, as nervus-ctl was given it, with the nervus-ctl asked."""
    log = m.logged()
    return [f"{line.split(' upgrade-backup ', 1)[1]} [{log[i + 1].removeprefix('upgrade-backup asked of ')}]"
            for i, line in enumerate(log) if line.startswith("nervus-ctl ") and " upgrade-backup " in line]


def test_an_upgrade_has_its_backup_kept_until_the_next_by_the_release_it_built(upgradable, clone, tmp_path):
    # Procedure 051, finding 5: a second backup the same day removed the one made before the upgrade.
    # It is asked of the release just built, which knows how: the one running may be from before it did.
    m = upgradable
    was, tree = _running(m), _newer(clone, tmp_path, "0.2.0")
    new = _named(tree)[0]
    done = m.run(tree, "--upgrade", "--yes")
    assert done.returncode == 0, done.stdout + done.stderr
    assert _kept_calls(m) == [
        f"keep {new} nervus-2026-11-04T120000Z.age [/opt/nervus/releases/{new}/.venv/bin/nervus-ctl]",
        f"only {new} [/opt/nervus/.venv/bin/nervus-ctl]"]
    log = m.logged()
    keep = next(i for i, line in enumerate(log) if " upgrade-backup keep " in line)
    only = next(i for i, line in enumerate(log) if " upgrade-backup only " in line)
    made = log.index(f"nervus-ctl --unit {m.unit} backup")
    assert made < keep < log.index("systemctl stop nervus") < log.index("systemctl start nervus") < only
    assert "that backup kept until the next upgrade" in done.stdout


def test_a_backup_that_cannot_be_kept_stops_the_upgrade_before_anything_is_stopped(upgradable, clone, tmp_path):
    m = upgradable
    was, tree = _running(m), _newer(clone, tmp_path, "0.2.0")
    (m.root / ".keep-fails").touch()
    done = m.run(tree, "--upgrade", "--yes")
    assert done.returncode == 1 and "could not be kept until the next upgrade" in done.stderr, done.stdout + done.stderr
    assert "disk full" in done.stderr and "Nothing was stopped" in done.stderr
    assert _running(m) == was and "systemctl stop nervus" not in m.logged()
    assert m.logged()[-1] == "systemctl start nervus-backup.timer"


def test_an_upgrade_that_goes_back_drops_the_backup_kept_for_it(upgradable, clone, tmp_path):
    # nervus runs again on the release that made that backup, which needs no second name for it.
    m = upgradable
    was, tree = _running(m), _newer(clone, tmp_path, "0.2.0")
    new = _named(tree)[0]
    (m.root / f".down-{new}").touch()
    done = m.run(tree, "--upgrade", "--yes")
    assert done.returncode == 1 and f"went back to {was} by itself" in done.stderr, done.stdout + done.stderr
    assert _kept_calls(m) == [
        f"keep {new} nervus-2026-11-04T120000Z.age [/opt/nervus/releases/{new}/.venv/bin/nervus-ctl]",
        f"drop {new} [/opt/nervus/releases/{new}/.venv/bin/nervus-ctl]"]


def test_with_nervus_down_the_backup_kept_stays(upgradable, clone, tmp_path):
    # It is what a restore would start from.
    m = upgradable
    was, tree = _running(m), _newer(clone, tmp_path, "0.2.0")
    (m.root / f".down-{_named(tree)[0]}").touch()
    (m.root / f".down-{was}").touch()
    done = m.run(tree, "--upgrade", "--yes")
    assert done.returncode == 1 and "NERVUS IS DOWN" in done.stderr
    assert [call.split()[0] for call in _kept_calls(m)] == ["keep"]


def test_older_kept_backups_that_cannot_be_removed_do_not_undo_an_upgrade_that_is_up(upgradable, clone, tmp_path):
    m = upgradable
    tree = _newer(clone, tmp_path, "0.2.0")
    (m.root / ".only-fails").touch()
    done = m.run(tree, "--upgrade", "--yes")
    assert done.returncode == 0 and _running(m) == _named(tree)[0], done.stdout + done.stderr
    assert "a backup kept for an earlier upgrade could not be removed" in done.stdout


def test_the_release_before_is_kept_and_any_older_removed(upgradable, clone, tmp_path):
    m = upgradable
    second, third = _newer(clone, tmp_path, "0.2.0"), _newer(clone, tmp_path, "0.3.0")
    for tree in (second, third):
        done = m.run(tree, "--upgrade", "--yes")
        assert done.returncode == 0, done.stdout + done.stderr
    assert sorted(os.listdir(m.opt / "releases")) == sorted([_named(second)[0], _named(third)[0]])


@pytest.mark.parametrize("fails, says", [(".backup-fails", "the backup did not succeed"),
                                         (".record-fails", "first record could not be written")],
                         ids=["the-backup", "the-first-record"])
def test_without_its_backup_or_its_first_record_nothing_is_stopped(upgradable, clone, tmp_path, fails, says):
    m = upgradable
    was = _running(m)
    (m.root / fails).touch()
    done = m.run(_newer(clone, tmp_path, "0.2.0"), "--upgrade", "--yes")
    assert done.returncode == 1 and says in done.stderr and "Nothing was stopped" in done.stderr
    log = m.logged()
    assert "systemctl stop nervus" not in log and _running(m) == was
    assert log[-1] == "systemctl start nervus-backup.timer"  # the daily backup held off no longer


def test_what_the_new_release_needs_and_the_installation_lacks_is_made_and_what_it_has_kept(upgradable, clone, tmp_path):
    # "Settled already": made as the installer makes it; what exists is never replaced.
    m = upgradable
    _database(m)  # it has run, as any installation lacking a recovery key but upgraded has
    secrets = m.opt / "secrets"
    key = (secrets / "nervus_ed25519").read_bytes()
    for name in ("nervus_ca_ed25519", "nervus_ca_ed25519.pub", "recovery.pub"):
        (secrets / name).unlink()
    done = m.run(_newer(clone, tmp_path, "0.2.0"), "--upgrade", "--yes")
    assert done.returncode == 0, done.stdout + done.stderr
    assert (secrets / "nervus_ca_ed25519").exists() and (secrets / "recovery.pub").exists()
    assert (secrets / "nervus_ed25519").read_bytes() == key
    assert "AGE-SECRET-KEY-1STANDIN" in done.stdout  # the recovery key's private half, shown once


def test_an_upgrade_gives_nervus_nothing_and_unpacks_its_release_as_roots(upgradable, clone, tmp_path):
    # ADR-0029 question 12, kept by the upgrade.
    m = upgradable
    done = m.run(_newer(clone, tmp_path, "0.2.0"), "--upgrade", "--yes")
    assert done.returncode == 0, done.stdout + done.stderr
    assert _given_to_nervus(m) == set()
    unpacked = [line for line in m.logged() if line.startswith("tar -x")]
    assert unpacked and all("--no-same-owner" in line.split() for line in unpacked)


def test_a_missing_package_with_no_apt_get_is_refused(upgradable, clone, tmp_path):
    m = upgradable
    for name in ("age", "apt-get"):
        (m.bin / name).unlink()
    before = _snapshot(m.root)
    done = m.run(_newer(clone, tmp_path, "0.2.0"), "--upgrade", "--yes")
    assert done.returncode == 1 and "missing, and no apt-get" in done.stderr and _snapshot(m.root) == before


def test_with_no_nervus_here_there_is_nothing_to_upgrade(machine, clone):
    done = machine.run(clone, "--upgrade", "--yes")
    assert done.returncode == 1 and "nothing to upgrade" in done.stderr and machine.changed() == []


def test_an_upgrade_keeps_the_installations_own_address_and_names(upgradable, clone):
    done = upgradable.run(clone, "--upgrade", "--address", "192.0.2.6", "--yes")
    assert done.returncode == 1 and "takes no --address" in done.stderr


# --- going back on purpose (ADR-0029 step 4, question 7b) --------------------------------


@pytest.fixture
def upgraded(upgradable, clone, tmp_path):
    """An installation upgraded once, to a release whose unit's command line differs: the machine, the
    release before and the one now, the tree it came from, and the unit and drop-in from before; its log
    only what follows."""
    m = upgradable
    was, unit, dropin = _running(m), m.unit.read_bytes(), m.dropin.read_bytes()
    tree = _newer(clone, tmp_path, "0.2.0", unit="--example-new-option on")
    done = m.run(tree, "--upgrade", "--yes")
    assert done.returncode == 0, done.stdout + done.stderr
    m.log.write_text("")
    return m, was, _named(tree)[0], tree, unit, dropin


def _migrates_once_started(m, release: str, version: int) -> None:
    """What a release that raises the database's version does at its start."""
    hook = m.root / ".on-start"
    hook.write_text('#!/bin/bash\ncase $(readlink "$NERVUS_INSTALL_ROOT/opt/nervus/.venv") in '
                    f'*{release}*) python3 -c \'import sqlite3, sys; db = sqlite3.connect(sys.argv[1]); '
                    f'db.execute("PRAGMA user_version = {version}"); db.commit()\' '
                    '"$NERVUS_INSTALL_ROOT/var/lib/nervus/nervus.db";; esac\n')
    hook.chmod(0o755)


def test_back_puts_back_the_release_kept_from_the_last_upgrade(upgraded):
    # Verification 6: with its own unit and drop-in, its venv through the link, and two records.
    m, was, now, tree, unit, dropin = upgraded
    done = m.run(tree, "--back", "--yes")
    assert done.returncode == 0, done.stdout + done.stderr
    assert _running(m) == was and m.unit.read_bytes() == unit and m.dropin.read_bytes() == dropin
    for name in ("nervus-backup.service", "nervus-backup.timer"):
        assert (m.root / "etc" / "systemd" / "system" / name).read_bytes() == \
            (m.opt / "releases" / was / "deploy" / name).read_bytes(), name
    assert sorted(os.listdir(m.opt / "releases")) == sorted([was, now])  # its folder stays, till the next upgrade
    ctl = f"nervus-ctl --unit {m.unit} upgrade-record back {was} {now} --why"
    order = ["systemctl stop nervus-backup.timer", f"{ctl} on the operator's word: install.sh --back",
             "systemctl stop nervus", "systemctl start nervus", f"{ctl} done: nervus runs {was} again",
             "systemctl start nervus-backup.timer"]
    assert [line for line in m.logged() if line in order] == order
    assert f"gone back, from {now} to {was}" in done.stdout
    assert _given_to_nervus(m) == set()  # question 12: the code stays root's


def test_the_plan_of_going_back_names_both_releases_and_waits_for_yes(upgraded):
    m, was, now, tree, *_ = upgraded
    before = _snapshot(m.root)
    done = m.run(tree, "--back", answer="no\n")
    assert done.returncode == 1 and "nothing changed" in done.stderr and _snapshot(m.root) == before
    assert not [line for line in m.logged() if line.startswith("systemctl")]
    for says in (f"It will go back from {now} to {was}", "the database kept as it is, at version none yet",
                 "its drop-in written again", "or a step after the stop fails,", f"it returns to {now} by itself"):
        assert says in done.stdout, says


def test_back_is_refused_once_a_migration_has_run_saying_why(upgradable, clone, tmp_path):
    # Verification 6, with a stand-in release that raises the database's version.
    m = upgradable
    database = _database(m, version=1)
    tree = _newer(clone, tmp_path, "0.2.0", schema=2)
    _migrates_once_started(m, _named(tree)[0], 2)
    done = m.run(tree, "--upgrade", "--yes")
    assert done.returncode == 0 and not list(database.parent.glob("nervus.db.before-*")), done.stdout + done.stderr
    before = _snapshot(m.root)
    done = m.run(tree, "--back", "--yes")
    assert done.returncode == 1 and _snapshot(m.root) == before and _running(m) == _named(tree)[0]
    for says in ("a migration has run since the upgrade", "Only the backup made before the upgrade"):
        assert says in done.stderr, says
    assert "it is kept as" not in done.stderr  # none is kept here: the stand-in nervus-ctl keeps nothing


def test_the_refusal_to_go_back_names_the_backup_kept_from_before_the_upgrade(upgradable, clone, tmp_path):
    # ADR-0029 step 7: the one backup the release before can read is kept until the next upgrade, by a
    # name that says which upgrade it was made before.
    m = upgradable
    _database(m, version=1)
    tree = _newer(clone, tmp_path, "0.2.0", schema=2)
    now = _named(tree)[0]
    _migrates_once_started(m, now, 2)
    assert m.run(tree, "--upgrade", "--yes").returncode == 0
    backups = m.root / "var" / "lib" / "nervus" / "backups"
    backups.mkdir()
    for name in (f"nervus-backup-20261104T120000Z.before-{now}.tar.gz.age",
                 "nervus-backup-20261001T120000Z.before-0.0.9-000000000000.tar.gz.age",  # an earlier upgrade's
                 "nervus-backup-20261105T120000Z.tar.gz.age"):
        (backups / name).write_bytes(b"locked")
    done = m.run(tree, "--back", "--yes")
    assert done.returncode == 1 and "Only the backup made before the upgrade" in done.stderr
    assert f"it is kept as {backups}/nervus-backup-20261104T120000Z.before-{now}.tar.gz.age" in done.stderr
    assert "0.0.9" not in done.stderr


def test_with_its_version_unchanged_going_back_keeps_the_database(upgradable, clone, tmp_path):
    # What the newer release wrote stays; the release before ignores a table it does not know (question 7).
    m = upgradable
    database = _database(m, version=1)
    tree = _newer(clone, tmp_path, "0.2.0")
    _writes_once_started(m, _named(tree)[0])
    assert m.run(tree, "--upgrade", "--yes").returncode == 0
    done = m.run(tree, "--back", "--yes")
    assert done.returncode == 0, done.stdout + done.stderr
    assert "the database kept as it is, at version 1" in done.stdout
    assert _tables(database) == ["kept", "written_by_the_new_release"]


def test_with_no_upgrade_yet_no_release_is_kept(upgradable, clone):
    m = upgradable
    before = _snapshot(m.root)
    done = m.run(clone, "--back", "--yes")
    assert done.returncode == 1 and "no release is kept here" in done.stderr and _snapshot(m.root) == before


def test_going_back_twice_is_refused(upgraded):
    # What it went back from is newer: the way there is an upgrade.
    m, was, _, tree, *_ = upgraded
    assert m.run(tree, "--back", "--yes").returncode == 0
    before = _snapshot(m.root)
    done = m.run(tree, "--back", "--yes")
    assert done.returncode == 1 and "no release is kept here" in done.stderr and "upgrade from its tree" in done.stderr
    assert _snapshot(m.root) == before and _running(m) == was


def test_after_going_back_an_upgrade_goes_forward_again(upgraded):
    m, was, now, tree, *_ = upgraded
    assert m.run(tree, "--back", "--yes").returncode == 0
    done = m.run(tree, "--upgrade", "--yes")
    assert done.returncode == 0, done.stdout + done.stderr
    assert "here already and not the release running, removed first" in done.stdout
    assert _running(m) == now and sorted(os.listdir(m.opt / "releases")) == sorted([was, now])


def test_the_release_a_failed_upgrade_left_is_never_the_one_kept(upgraded, clone, tmp_path):
    m, was, now, *_ = upgraded
    tree = _newer(clone, tmp_path, "0.3.0")
    failed = _named(tree)[0]
    (m.root / f".down-{failed}").touch()
    assert m.run(tree, "--upgrade", "--yes").returncode == 1 and _running(m) == now
    assert sorted(os.listdir(m.opt / "releases")) == sorted([was, now, failed])
    done = m.run(tree, "--back", "--yes")
    assert done.returncode == 0, done.stdout + done.stderr
    assert _running(m) == was


def test_a_failed_first_upgrade_leaves_nothing_to_go_back_to(upgradable, clone, tmp_path):
    m = upgradable
    was, tree = _running(m), _newer(clone, tmp_path, "0.2.0")
    (m.root / f".down-{_named(tree)[0]}").touch()
    assert m.run(tree, "--upgrade", "--yes").returncode == 1
    done = m.run(tree, "--back", "--yes")
    assert done.returncode == 1 and "no release is kept here" in done.stderr and _running(m) == was


def _other_code(tree: Path, tmp: Path, name: str) -> Path:
    """A clone of the same number with other code: a build between exports."""
    other = tmp / name
    shutil.copytree(tree, other, symlinks=True)
    (other / "README.md").write_text((other / "README.md").read_text() + f"\n{name}\n")
    _commit(other)
    return other


def test_another_build_of_the_same_number_is_the_one_kept_when_none_is_below(upgradable, clone, tmp_path):
    m = upgradable
    was, tree = _running(m), _other_code(clone, tmp_path, "build")
    assert m.run(tree, "--upgrade", "--yes").returncode == 0
    done = m.run(tree, "--back", "--yes")
    assert done.returncode == 0, done.stdout + done.stderr
    assert _running(m) == was


def test_a_release_below_is_the_one_kept_before_another_build_of_the_same_number(upgraded, tmp_path):
    # A build that failed, of the number running, is not what going back means when one below is kept.
    m, was, now, tree, *_ = upgraded
    build = _other_code(tree, tmp_path, "build")
    (m.root / f".down-{_named(build)[0]}").touch()
    assert m.run(build, "--upgrade", "--yes").returncode == 1 and _running(m) == now
    done = m.run(tree, "--back", "--yes")
    assert done.returncode == 0, done.stdout + done.stderr
    assert _running(m) == was


def test_a_release_not_whole_is_not_the_one_kept(upgradable, clone):
    # What a failed build left: no nervus in its venv.
    m = upgradable
    number = _running(m).split("-")[0]
    (m.opt / "releases" / f"{number}-{'0' * 12}" / ".venv" / "bin").mkdir(parents=True)
    done = m.run(clone, "--back", "--yes")
    assert done.returncode == 1 and "no release is kept here" in done.stderr


def test_more_than_one_release_that_could_be_kept_is_refused_naming_them(upgraded):
    # The upgrade leaves one; more is someone's hand, so it asks rather than guesses.
    m, was, _, tree, *_ = upgraded
    other = "0.0.1-" + "0" * 12
    nervus = m.opt / "releases" / other / ".venv" / "bin" / "nervus"
    nervus.parent.mkdir(parents=True)
    nervus.write_text("#!/bin/bash\n")
    nervus.chmod(0o755)
    before = _snapshot(m.root)
    done = m.run(tree, "--back", "--yes")
    assert done.returncode == 1 and "more than one release" in done.stderr and _snapshot(m.root) == before
    assert other in done.stderr and was in done.stderr


def test_when_the_release_kept_is_not_up_it_returns_by_itself(upgraded):
    m, was, now, tree, *_ = upgraded
    unit, dropin = m.unit.read_bytes(), m.dropin.read_bytes()
    (m.root / f".down-{was}").touch()
    done = m.run(tree, "--back", "--yes")
    assert done.returncode == 1 and f"returned to {now} by itself" in done.stderr, done.stdout + done.stderr
    assert "the MCP endpoint did not answer" in done.stderr
    assert _running(m) == now and m.unit.read_bytes() == unit and m.dropin.read_bytes() == dropin
    log = m.logged()
    assert any(line.startswith(f"nervus-ctl --unit {m.unit} upgrade-record up {was} {now} --why returned to it: ")
               for line in log)
    assert log[-1] == "systemctl start nervus-backup.timer"


def test_if_neither_comes_up_going_back_says_nervus_is_down(upgraded):
    m, was, now, tree, *_ = upgraded
    (m.root / f".down-{was}").touch()
    (m.root / f".down-{now}").touch()
    done = m.run(tree, "--back", "--yes")
    assert done.returncode == 1 and "NERVUS IS DOWN" in done.stderr


def test_without_its_first_record_going_back_stops_nothing(upgraded):
    # ADR-0001 s10.
    m, _, now, tree, *_ = upgraded
    (m.root / ".record-fails").touch()
    done = m.run(tree, "--back", "--yes")
    assert done.returncode == 1 and "Nothing was stopped" in done.stderr and _running(m) == now
    log = m.logged()
    assert "systemctl stop nervus" not in log and log[-1] == "systemctl start nervus-backup.timer"


def test_an_installation_this_installer_did_not_make_has_nothing_to_go_back_to(upgraded):
    m, *_, tree, _, _ = upgraded
    m.dropin.write_text(m.dropin.read_text().replace("# Written by install.sh (ADR-0023).", "# my own"))
    before = _snapshot(m.root)
    done = m.run(tree, "--back", "--yes")
    assert done.returncode == 1 and "not installed by this installer" in done.stderr and _snapshot(m.root) == before


def test_a_drop_in_not_as_the_installer_writes_it_is_refused_when_going_back(upgraded):
    m, *_, tree, _, _ = upgraded
    m.dropin.write_text(m.dropin.read_text() + "Environment=EXTRA=1\n")
    before = _snapshot(m.root)
    done = m.run(tree, "--back", "--yes")
    assert done.returncode == 1 and "is not as install.sh writes it" in done.stderr and _snapshot(m.root) == before


@pytest.mark.parametrize("where", ["a-clone-with-changes", "the-releases-own-folder"])
def test_going_back_installs_nothing_so_any_tree_with_this_script_will_do(upgraded, where):
    # What a tree must be for an install or an upgrade does not apply: a friend may have pulled, or changed it.
    m, was, now, tree, *_ = upgraded
    if where == "a-clone-with-changes":
        (tree / "README.md").write_text((tree / "README.md").read_text() + "\nNot committed.\n")
    else:
        tree = m.opt / "releases" / now
    done = m.run(tree, "--back", "--yes")
    assert done.returncode == 0, done.stdout + done.stderr
    assert _running(m) == was


def test_going_back_keeps_the_installations_own_address_and_names(upgraded):
    m, *_, tree, _, _ = upgraded
    done = m.run(tree, "--back", "--address", "192.0.2.6", "--yes")
    assert done.returncode == 1 and "--back takes no --address" in done.stderr


# --- what can stop an upgrade comes before the stop (procedure 052's finding) ------------------


def _during(m, command, match, shell, times=1):
    """`shell` runs in `command` when its arguments match the shell pattern `match`, the first `times`
    such calls; after it, the command does what it did. $PPID there is what called it, install.sh."""
    real = m.bin / f"{command}.real"
    (m.bin / command).rename(real)
    count = m.log.parent / f"calls-{command}"
    _script(m.bin / command,
            f'case "$*" in {match}) n=$(cat "{count}" 2>/dev/null || echo 0); echo $((n + 1)) > "{count}"\n'
            f'  if [ "$n" -lt {times} ]; then {shell}\n  fi;; esac\n'
            f'exec "{real}" "$@"')


def _fails(m, command, match, times=1):
    """`command` fails when its arguments match, the first `times` such calls, as on a full disk."""
    _during(m, command, match, f'echo "{command}: No space left on device" >&2; exit 1', times)


def _switches(m) -> Path:
    return m.root / "var" / "lib" / "nervus" / "switches.yaml"


@pytest.mark.parametrize("text", ["lockdown: [\n", "lockdown: true\n"], ids=["not-yaml", "a-key-missing"])
def test_an_off_switch_nervus_cannot_read_refuses_the_upgrade_with_nothing_changed(upgradable, clone, tmp_path, text):
    # Found only after the stop, it left nervus stopped. It is the person's to put right: overwriting
    # it could lift a lock nobody can now read.
    m = upgradable
    _switches(m).write_text(text)
    before = _snapshot(m.root)
    done = m.run(_newer(clone, tmp_path, "0.2.0"), "--upgrade", "--yes")
    assert done.returncode == 1, done.stdout + done.stderr
    assert "is malformed" in done.stderr and "nothing changed" in done.stderr
    assert _snapshot(m.root) == before
    assert not [line for line in m.logged() if line.startswith("systemctl")]


@pytest.mark.parametrize("text, says", [
    ("lockdown: true\ndisabled: [a-client]\n", "is kept as it is: lockdown ON; switched off: a-client"),
    (None, "is missing; it will be created with nothing switched off"),
], ids=["a-lock-set", "missing"])
def test_the_plan_says_what_becomes_of_the_off_switch(upgradable, clone, tmp_path, text, says):
    m = upgradable
    if text is None:
        _switches(m).unlink()
    else:
        _switches(m).write_text(text)
    done = m.run(_newer(clone, tmp_path, "0.2.0"), "--upgrade", answer="no\n")
    assert done.returncode == 1 and f"  - the off switch: {_switches(m)} {says}" in done.stdout, done.stdout


def test_a_lock_the_person_set_survives_an_upgrade(upgradable, clone, tmp_path):
    m = upgradable
    _switches(m).write_text("lockdown: true\ndisabled: [a-client]\n")
    done = m.run(_newer(clone, tmp_path, "0.2.0"), "--upgrade", "--yes")
    assert done.returncode == 0, done.stdout + done.stderr
    assert _switches(m).read_text() == "lockdown: true\ndisabled: [a-client]\n"


def test_what_the_new_release_lacks_is_made_while_nervus_serves_and_so_is_in_the_backup(upgradable, clone, tmp_path):
    m = upgradable
    for name in ("nervus_ca_ed25519", "nervus_ca_ed25519.pub"):
        (m.opt / "secrets" / name).unlink()
    _switches(m).unlink()
    done = m.run(_newer(clone, tmp_path, "0.2.0"), "--upgrade", "--yes")
    assert done.returncode == 0, done.stdout + done.stderr
    assert (m.opt / "secrets" / "nervus_ca_ed25519").exists() and _switches(m).exists()
    log = m.logged()
    made = [next(i for i, line in enumerate(log) if words in line) for words in ("ensure-switches --owner", "-C nervus-ca")]
    assert max(made) < log.index(f"nervus-ctl --unit {m.unit} backup") < log.index("systemctl stop nervus"), log


@pytest.mark.parametrize("how", ["the-off-switch-goes-bad-after-the-plan", "a-key-cannot-be-made"])
def test_if_what_the_new_release_lacks_cannot_be_made_nothing_is_stopped(upgradable, clone, tmp_path, how):
    m = upgradable
    was = _running(m)
    if how == "a-key-cannot-be-made":
        (m.opt / "secrets" / "nervus_ca_ed25519").unlink()
        _fails(m, "ssh-keygen", "*nervus-ca*")
    else:
        _during(m, "tar", "-x*", f'echo "lockdown: [" > "{_switches(m)}"')
    done = m.run(_newer(clone, tmp_path, "0.2.0"), "--upgrade", "--yes")
    assert done.returncode == 1, done.stdout + done.stderr
    assert f"nervus runs on as it was, on {was}" in done.stderr
    assert ("No space left on device" if how == "a-key-cannot-be-made" else "is malformed") in done.stdout + done.stderr
    assert "systemctl stop nervus" not in m.logged() and _running(m) == was


def test_an_off_switch_no_release_could_read_refuses_going_back_with_nothing_changed(upgraded):
    # Going back could not help: the release kept would refuse every client too, and so would this one.
    m, _, now, tree, *_ = upgraded
    _switches(m).write_text("lockdown: [\n")
    before = _snapshot(m.root)
    done = m.run(tree, "--back", "--yes")
    assert done.returncode == 1, done.stdout + done.stderr
    assert "is malformed" in done.stderr and "nothing changed" in done.stderr
    assert _snapshot(m.root) == before and _running(m) == now
    assert not [line for line in m.logged() if line.startswith("systemctl")]


# --- from the stop until nervus is judged up, any way the run ends goes back (procedure 052's finding) ---


# Each step of the switch, by what it runs: the first call of it fails, the one going back does not.
SWITCH_STEPS = {
    "the-link": ("ln", "*.venv.new*"),
    "the-unit": ("install", "*deploy/nervus.service*"),
    "the-backup-timer": ("install", "*deploy/nervus-backup.timer*"),
    "the-drop-in": ("mv", "*instance.conf.new*"),
    "telling-systemd": ("systemctl", "daemon-reload"),
}


def _in_place(m) -> dict:
    """The units and the drop-in as they are, by name."""
    return {p.name: p.read_bytes() for p in (m.unit, m.unit.with_name("nervus-backup.service"),
                                             m.unit.with_name("nervus-backup.timer"), m.dropin)}


def _went_back(m, done, was, new, in_place, why):
    """nervus is running on the release it was on, with what it had, having said so and why, and recorded it."""
    assert done.returncode == 1, done.stdout + done.stderr
    assert f"went back to {was} by itself, and runs as before" in done.stderr and why in done.stderr, done.stderr
    assert _running(m) == was and _in_place(m) == in_place
    assert (m.root / ".active").exists() and not list(m.root.rglob("*.new"))
    assert (m.opt / "releases" / new).is_dir()  # left for reading
    log = m.logged()
    assert "systemctl start nervus" in log[log.index(f"nervus-ctl --unit {m.unit} upgrade-record begin {was} {new}"):]
    assert any(line.startswith(f"nervus-ctl --unit {m.unit} upgrade-record back {was} {new} --why ") for line in log)
    assert log[-1] == "systemctl start nervus-backup.timer"


def _older_copies(database: Path) -> list:
    return list(database.parent.glob("nervus.db.before-*"))


@pytest.mark.parametrize("step", SWITCH_STEPS)
def test_a_switch_that_fails_goes_back_by_itself(upgradable, clone, tmp_path, step):
    # It ended there, under set -e, with nervus stopped and nothing to start it.
    m = upgradable
    was, tree = _running(m), _newer(clone, tmp_path, "0.2.0", unit="--example-new-option on")
    new, in_place = _named(tree)[0], _in_place(m)
    _fails(m, *SWITCH_STEPS[step])
    done = m.run(tree, "--upgrade", "--yes")
    _went_back(m, done, was, new, in_place, f"the switch to {new} failed, as it says above")
    assert m.logged().count("systemctl start nervus") == 1  # never started on the new release
    assert "Its journal since it started" not in done.stdout  # so it has none to show


def test_if_nervus_cannot_be_stopped_nothing_is_switched_and_it_is_started_and_judged(upgradable, clone, tmp_path):
    # Whatever state a failed stop left it in, it is not assumed to be running.
    m = upgradable
    was, tree = _running(m), _newer(clone, tmp_path, "0.2.0", unit="--example-new-option on")
    new, in_place = _named(tree)[0], _in_place(m)
    _fails(m, "systemctl", '"stop nervus"', times=2)
    done = m.run(tree, "--upgrade", "--yes")
    _went_back(m, done, was, new, in_place, "systemctl could not stop nervus, as it says above")
    log = m.logged()
    assert "systemctl start nervus" in log
    assert "systemctl daemon-reload" not in log and not [line for line in log if "deploy/" in line]  # no unit touched


def test_a_database_copy_that_fails_goes_back_and_leaves_the_database_as_it_was(upgradable, clone, tmp_path):
    # Half a copy is neither kept nor put back: the new release never ran, so the database is as it was.
    m = upgradable
    database = _database(m, version=1)
    inode = database.stat().st_ino
    was, tree = _running(m), _newer(clone, tmp_path, "0.2.0", schema=2)
    new, in_place = _named(tree)[0], _in_place(m)
    _during(m, "runuser", "*before-*", 'echo "half a copy" > "${@: -1}"; echo "runuser: database or disk is full" >&2; exit 1')
    done = m.run(tree, "--upgrade", "--yes")
    _went_back(m, done, was, new, in_place, "the database could not be copied before its version rises, as it says above")
    assert database.stat().st_ino == inode and _tables(database) == ["kept"] and not _older_copies(database)
    log = m.logged()
    assert "systemctl daemon-reload" not in log and not [line for line in log if "deploy/" in line]  # no unit touched


def test_a_switch_that_fails_after_the_copy_keeps_the_database_the_new_release_never_touched(upgradable, clone, tmp_path):
    m = upgradable
    database = _database(m, version=1)
    inode = database.stat().st_ino
    was, tree = _running(m), _newer(clone, tmp_path, "0.2.0", schema=2)
    new, in_place = _named(tree)[0], _in_place(m)
    _fails(m, *SWITCH_STEPS["the-unit"])
    done = m.run(tree, "--upgrade", "--yes")
    _went_back(m, done, was, new, in_place, f"the switch to {new} failed")
    assert database.stat().st_ino == inode and not _older_copies(database)


@pytest.mark.parametrize("signal", ["HUP", "INT", "TERM"])
@pytest.mark.parametrize("when", ["daemon-reload", '"start nervus"'], ids=["in-the-switch", "once-started"])
def test_a_signal_goes_back_by_itself(upgradable, clone, tmp_path, signal, when):
    # A dropped connection, or Ctrl-C while it seems slow.
    m = upgradable
    was, tree = _running(m), _newer(clone, tmp_path, "0.2.0", unit="--example-new-option on")
    new, in_place = _named(tree)[0], _in_place(m)
    _during(m, "systemctl", when, f"kill -{signal} $PPID")
    done = m.run(tree, "--upgrade", "--yes")
    _went_back(m, done, was, new, in_place, "this run was stopped by a signal")


def test_a_signal_once_it_has_started_puts_the_database_copy_back(upgradable, clone, tmp_path):
    # The new release may have migrated it by then.
    m = upgradable
    database = _database(m, version=1)
    was, tree = _running(m), _newer(clone, tmp_path, "0.2.0", schema=2)
    new, in_place = _named(tree)[0], _in_place(m)
    _writes_once_started(m, new)
    _during(m, "systemctl", '"start nervus"', "kill -TERM $PPID")
    done = m.run(tree, "--upgrade", "--yes")
    _went_back(m, done, was, new, in_place, "this run was stopped by a signal")
    assert _tables(database) == ["kept"] and not _older_copies(database)


def test_nothing_interrupts_going_back(upgradable, clone, tmp_path):
    m = upgradable
    was, tree = _running(m), _newer(clone, tmp_path, "0.2.0", unit="--example-new-option on")
    new, in_place = _named(tree)[0], _in_place(m)
    _during(m, "systemctl", "daemon-reload", "kill -TERM $PPID", times=2)  # the switch's, then going back's
    _went_back(m, m.run(tree, "--upgrade", "--yes"), was, new, in_place, "this run was stopped by a signal")


def test_a_terminal_that_has_gone_does_not_stop_it_going_back(upgradable, clone, tmp_path):
    # Nothing can be read any more, and every line it writes fails, so that must stop nothing.
    m = upgradable
    was, tree = _running(m), _newer(clone, tmp_path, "0.2.0", unit="--example-new-option on")
    new, in_place = _named(tree)[0], _in_place(m)
    (m.root / f".down-{new}").touch()
    # The last line it prints before it stops nervus: what it writes next, it writes after the stop.
    reader = 'while read -r line; do case $line in *"that backup kept until the next upgrade"*) exit;; esac; done'
    subprocess.run(["bash", "-c", f'bash "$0" "$@" | {{ {reader}; }}', str(tree / "install.sh"), "--upgrade", "--yes"],
                   env=m.env(), capture_output=True, text=True, timeout=120)
    log = m.logged()
    assert "systemctl stop nervus" in log  # so it had begun
    assert _running(m) == was and _in_place(m) == in_place and (m.root / ".active").exists()
    assert any(line.startswith(f"nervus-ctl --unit {m.unit} upgrade-record back {was} {new} --why ") for line in log)
    assert log[-1] == "systemctl start nervus-backup.timer"


def test_a_terminal_that_goes_before_nervus_is_stopped_ends_the_upgrade_with_nothing_stopped_or_kept(
        upgradable, clone, tmp_path):
    # One line earlier: the run ends where its next line cannot be written, before the stop. nervus
    # serves on, the daily backups go on, and the backup is not left kept for an upgrade that never began.
    m = upgradable
    was, tree = _running(m), _newer(clone, tmp_path, "0.2.0")
    new, in_place = _named(tree)[0], _in_place(m)
    reader = 'while read -r line; do case $line in *"a backup by the running release"*) exit;; esac; done'
    subprocess.run(["bash", "-c", f'bash "$0" "$@" | {{ {reader}; }}', str(tree / "install.sh"), "--upgrade", "--yes"],
                   env=m.env(), capture_output=True, text=True, timeout=120)
    log = m.logged()
    assert "systemctl stop nervus" not in log and not any(" upgrade-record " in line for line in log)
    assert _running(m) == was and _in_place(m) == in_place and (m.root / ".active").exists()
    assert [call.split()[0] for call in _kept_calls(m)] == ["keep", "drop"]
    assert log[-1] == "systemctl start nervus-backup.timer"


def test_an_upgrade_that_cannot_write_its_first_record_keeps_no_backup_for_it(upgradable, clone, tmp_path):
    m = upgradable
    tree = _newer(clone, tmp_path, "0.2.0")
    (m.root / ".record-fails").touch()
    done = m.run(tree, "--upgrade", "--yes")
    assert done.returncode == 1 and "first record could not be written" in done.stderr
    assert [call.split()[0] for call in _kept_calls(m)] == ["keep", "drop"]
    assert m.logged()[-1] == "systemctl start nervus-backup.timer"


@pytest.mark.parametrize("step", SWITCH_STEPS)
def test_a_step_that_fails_on_the_way_back_too_stops_nothing_else_and_it_says_so(upgradable, clone, tmp_path, step):
    # Everything is tried and nervus is started: it is the last chance. What it has is what it says.
    m = upgradable
    was, tree = _running(m), _newer(clone, tmp_path, "0.2.0", unit="--example-new-option on")
    in_place = _in_place(m)
    command, match = SWITCH_STEPS[step]
    _fails(m, command, match, times=2)
    done = m.run(tree, "--upgrade", "--yes")
    assert done.returncode == 1, done.stdout + done.stderr
    assert "and runs, but not all of it could be put back, as it says above" in done.stderr
    assert _running(m) == was and _in_place(m) == in_place and (m.root / ".active").exists()
    assert m.logged()[-1] == "systemctl start nervus-backup.timer"


def test_going_back_tries_every_step_whichever_fails(upgradable, clone, tmp_path):
    # The unit cannot be put back: the drop-in, which decides how nervus starts, still can, and systemd is told.
    m = upgradable
    was, tree = _running(m), _newer(clone, tmp_path, "0.2.0", unit="--example-new-option on")
    new, in_place = _named(tree)[0], _in_place(m)
    (m.root / f".down-{new}").touch()
    _fails(m, "install", f"*releases/{was}/deploy/nervus.service*")
    done = m.run(tree, "--upgrade", "--yes")
    assert done.returncode == 1 and "not all of it could be put back" in done.stderr, done.stdout + done.stderr
    assert _running(m) == was and m.dropin.read_bytes() == in_place["instance.conf"]
    assert m.logged().count("systemctl daemon-reload") == 2


def test_a_unit_that_cannot_be_written_leaves_the_one_there(upgradable, clone, tmp_path):
    # GNU install removes what it is replacing before it writes, so a full disk would leave no unit to start.
    m = upgradable
    was, tree = _running(m), _newer(clone, tmp_path, "0.2.0", unit="--example-new-option on")
    in_place = _in_place(m)
    _during(m, "install", "*deploy/nervus.service*",
            'rm -f "${@: -1}"; echo "install: No space left on device" >&2; exit 1', times=2)
    done = m.run(tree, "--upgrade", "--yes")
    assert done.returncode == 1, done.stdout + done.stderr
    assert _running(m) == was and _in_place(m) == in_place and not list(m.root.rglob("*.new"))


def test_a_copy_that_cannot_be_put_back_still_starts_nervus_and_says_so(upgradable, clone, tmp_path):
    m = upgradable
    _database(m, version=1)
    was, tree = _running(m), _newer(clone, tmp_path, "0.2.0", schema=2)
    (m.root / f".down-{_named(tree)[0]}").touch()
    _fails(m, "mv", "*before-*")
    done = m.run(tree, "--upgrade", "--yes")
    assert done.returncode == 1 and "not all of it could be put back" in done.stderr, done.stdout + done.stderr
    assert _running(m) == was and (m.root / ".active").exists()


def test_a_failed_switch_with_the_release_before_not_up_says_nervus_is_down_and_why_twice(upgradable, clone, tmp_path):
    m = upgradable
    was, tree = _running(m), _newer(clone, tmp_path, "0.2.0")
    new = _named(tree)[0]
    (m.root / f".down-{was}").touch()
    _fails(m, *SWITCH_STEPS["the-unit"])
    done = m.run(tree, "--upgrade", "--yes")
    assert done.returncode == 1 and "NERVUS IS DOWN" in done.stderr, done.stdout + done.stderr
    assert f"the switch to {new} failed" in done.stderr and "the MCP endpoint did not answer" in done.stderr
    assert m.logged()[-1] == "systemctl start nervus-backup.timer"


def test_once_it_is_judged_up_a_later_failure_does_not_go_back(upgraded, clone, tmp_path):
    # An older release that cannot be removed is no reason to take down the one that is up.
    m, was, *_ = upgraded
    tree = _newer(clone, tmp_path, "0.3.0")
    _fails(m, "rm", f"*-rf*{was}*")
    done = m.run(tree, "--upgrade", "--yes")
    assert done.returncode != 0, done.stdout + done.stderr
    assert _running(m) == _named(tree)[0] and (m.root / ".active").exists()
    # The installer's own line, at the start of a line, not the words: an upgrade shows the new release's
    # CHANGES.md, indented, and it may use them.
    assert not re.search(r"(?m)^Going back to ", done.stdout) and m.logged().count("systemctl stop nervus") == 1
    assert m.logged()[-1] == "systemctl start nervus-backup.timer"


def _returned(m, done, was, now, in_place, why):
    """Going back on purpose did not finish: nervus is running on the release it was on, having said so."""
    assert done.returncode == 1, done.stdout + done.stderr
    assert f"returned to {now} by itself, and runs as before" in done.stderr and why in done.stderr, done.stderr
    assert _running(m) == now and _in_place(m) == in_place
    assert (m.root / ".active").exists() and not list(m.root.rglob("*.new"))
    log = m.logged()
    assert any(line.startswith(f"nervus-ctl --unit {m.unit} upgrade-record up {was} {now} --why returned to it: ") for line in log)
    assert log[-1] == "systemctl start nervus-backup.timer"


@pytest.mark.parametrize("step", SWITCH_STEPS)
def test_going_back_returns_by_itself_when_a_step_of_it_fails(upgraded, step):
    m, was, now, tree, *_ = upgraded
    in_place = _in_place(m)
    _fails(m, *SWITCH_STEPS[step])
    done = m.run(tree, "--back", "--yes")
    _returned(m, done, was, now, in_place, f"the switch to {was} failed, as it says above")
    assert m.logged().count("systemctl start nervus") == 1 and "Its journal since it started" not in done.stdout


def test_going_back_that_cannot_stop_nervus_starts_and_judges_it(upgraded):
    m, was, now, tree, *_ = upgraded
    in_place = _in_place(m)
    _fails(m, "systemctl", '"stop nervus"', times=2)
    done = m.run(tree, "--back", "--yes")
    _returned(m, done, was, now, in_place, "systemctl could not stop nervus, as it says above")
    assert "systemctl daemon-reload" not in m.logged()


@pytest.mark.parametrize("when", ["daemon-reload", '"start nervus"'], ids=["in-the-switch", "once-started"])
def test_a_signal_while_going_back_returns_by_itself(upgraded, when):
    m, was, now, tree, *_ = upgraded
    in_place = _in_place(m)
    _during(m, "systemctl", when, "kill -TERM $PPID")
    _returned(m, m.run(tree, "--back", "--yes"), was, now, in_place, "this run was stopped by a signal")


def test_going_back_that_fails_with_this_release_not_up_says_nervus_is_down(upgraded):
    m, was, now, tree, *_ = upgraded
    (m.root / f".down-{now}").touch()
    _fails(m, *SWITCH_STEPS["the-unit"])
    done = m.run(tree, "--back", "--yes")
    assert done.returncode == 1 and "NERVUS IS DOWN" in done.stderr, done.stdout + done.stderr
    assert f"the switch to {was} failed" in done.stderr and m.logged()[-1] == "systemctl start nervus-backup.timer"


# --- the guide's commands, as written (ADR-0029 step 5) -------------------------------------


def test_the_install_docs_upgrade_command_works_as_written(upgradable, clone, tmp_path):
    m, tree = upgradable, _newer(clone, tmp_path, "0.2.0")
    done = m.run(tree, *_documented("installer-upgrade", tree), answer="yes\n")
    assert done.returncode == 0, done.stdout + done.stderr
    assert _running(m) == _named(tree)[0]


def test_the_install_docs_back_command_works_as_written(upgraded):
    m, was, _, tree, *_ = upgraded
    done = m.run(tree, *_documented("installer-back", tree), answer="yes\n")
    assert done.returncode == 0, done.stdout + done.stderr
    assert _running(m) == was
