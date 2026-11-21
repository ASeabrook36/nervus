"""The enrollment script for each level (ADR-0024 step 3, decisions 1, 2 and 7):
what it makes, in what order, what it refuses, and what it sends back.

It runs here in a real sh (and dash, where there is one) with its system paths
under NERVUS_ENROLL_ROOT. `PATH` holds only the commands named below. The
ones that need root, or a Linux kernel, are stood in for: id, getent,
useradd, su, chown, visudo, apt-get, systemctl, bwrap, apparmor_parser, and
curl, which keeps what it was sent and answers as nervus would. A machine whose
AppArmor restricts user namespaces (question 9) has the kernel's switch at 1
under its folder, and its su fails as bwrap does there until nervus's profile
is loaded. Procedure 036 tried the
read-only shell itself on real machines; the trial in step 6 runs this."""

import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

from nervus.host_enrollment import (APPARMOR_PROFILE_PATH, APT_HOOK_PATH, BWRAP_COPY_PATH, READONLY_ACCOUNT,
                                    READONLY_SHELL, READONLY_SHELL_PATH, enroll_script, own_hash,
                                    remove_commands, remove_readonly_commands)

# nervus's CA public key, as nervus passes it (ADR-0025 decision 4).
KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeNervusKeyForTheseTestsOnly0123456789ab nervus-ca"
HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeHostKeyForTheseTestsOnly0123456789abc root@web"
MACHINE = "0123456789abcdef0123456789abcdef"
ELSEWHERE = "fedcba9876543210fedcba9876543210"  # the machine nervus runs on, unless a test says it is this one
PIN = "sha256//47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
URL = "https://192.0.2.1:8000/enroll/CODE"
REAL = ["sh", "wc", "cat", "cut", "rm", "mkdir", "chmod", "mv", "printf", "ls", "mktemp", "env", "touch", "dirname", "cp",
        "sha256sum", "grep", "tr", "rmdir"]
# The accounts nervus's page names by default (ADR-0031 question 8).
RW, RO = "nervusagent", "nervusagent-readonly"
SHELLS = ["sh"] + (["dash"] if shutil.which("dash") else [])

STANDINS = {
    # Each account is a file under $W/users holding its uid, and its groups, where it has others, under
    # $W/groups (ADR-0031: the script names two accounts, and says an existing one's groups).
    # Its own group's id is its uid, unless $W/gids says another; a group's other members are in $W/members.
    "id": ('case "$1" in -u) if [ -n "${2:-}" ]; then [ -e "$W/users/$2" ] && cat "$W/users/$2" || exit 1; '
           'else echo "${AS_UID:-0}"; fi; exit;; -g) [ -e "$W/users/$2" ] || exit 1; '
           'cat "$W/gids/$2" 2>/dev/null || cat "$W/users/$2"; exit;; -Gn) [ -e "$W/users/$2" ] || exit 1; '
           'cat "$W/groups/$2" 2>/dev/null || echo "$2"; exit;; esac; exit 1'),
    "getent": ('gid() { cat "$W/gids/$1" 2>/dev/null || cat "$W/users/$1"; }; '
               'case "$1" in passwd) if [ -n "${2:-}" ]; then [ -e "$W/users/$2" ] || exit 2; '
               'echo "$2:x:$(cat "$W/users/$2"):$(gid "$2")::$W/home/$2:/bin/sh"; exit 0; fi; '
               'for f in "$W"/users/*; do [ -e "$f" ] || continue; n=${f##*/}; '
               'echo "$n:x:$(cat "$f"):$(gid "$n")::$W/home/$n:/bin/sh"; done; exit 0;; '
               'group) [ -n "${2:-}" ] || exit 2; echo "g$2:x:$2:$(cat "$W/members/$2" 2>/dev/null)"; exit 0;; '
               'esac; exit 2'),
    "useradd": ('echo "useradd $*" >> "$W/log"; for a; do n=$a; done; mkdir -p "$W/home/$n" "$W/users"; '
                'echo $((1001 + $(ls "$W/users" | wc -l))) > "$W/users/$n"'),
    # su -s /bin/sh -c CMD NAME: CMD as that account, in its home. bwrap's failures are the read-only
    # shell's, so they come only when CMD runs it, not when an account writes its own key.
    "su": ('echo "su $*" >> "$W/log"; case "$4" in *readonly-shell*) '
           '[ -n "${SU_FAILS:-}" ] && { echo "bwrap: No permissions to create new namespace" >&2; exit 1; }; '
           # Where AppArmor restricts user namespaces, as bwrap fails there until nervus's profile is in.
           '[ -n "${USERNS_RESTRICTED:-}" ] && { [ ! -e "$W/.profile-loaded" ] || [ -n "${STILL_FAILS:-}" ]; } '
           '&& { echo "bwrap: setting up uid map: Permission denied" >&2; exit 1; };; esac; '
           'HOME=$W/home/$5 exec sh -c "$4"'),
    "apparmor_parser": ('echo "apparmor_parser $*" >> "$W/log"; [ -n "${PARSER_FAILS:-}" ] && '
                        '{ echo "AppArmor parser error: the test\'s" >&2; exit 1; }; '
                        'case $1 in -r) touch "$W/.profile-loaded";; -R) rm -f "$W/.profile-loaded";; esac'),
    "chown": 'echo "chown $*" >> "$W/log"',
    "visudo": 'echo "visudo $*" >> "$W/log"; [ -z "${VISUDO_FAILS:-}" ]',
    # Asked to, it stops the script from outside part way, as Ctrl-C or a closed terminal would.
    "systemctl": 'echo "systemctl $*" >> "$W/log"; [ -z "${INTERRUPT:-}" ] || kill -TERM $PPID; true',
    "apt-get": ('echo "apt-get $*" >> "$W/log"; for p in "$@"; do case $p in '
                'bubblewrap) cp "$W/store/bwrap" "$W/bin/";; tmux) cp "$W/store/tmux" "$W/bin/";; '
                'sudo) cp "$W/store/sudo" "$W/store/visudo" "$W/bin/";; esac; done'),
    # Asked --help, it answers as bubblewrap 0.8 and later do, unrecorded.
    "bwrap": ('[ "$1" = --help ] && { echo "    --disable-userns  Disable further use of user namespaces"; exit 0; }; '
              'echo "bwrap $*" >> "$W/log"; while [ "$1" != -- ]; do shift; done; shift; exec "$@"'),
    "sudo": 'exit 1',
    "pkill": 'echo "pkill $*" >> "$W/log"; exit 1',  # no process of agent's: pkill says so, and the rest goes on
    "sleep": 'true',
    "userdel": ('echo "userdel $*" >> "$W/log"; for a; do n=$a; done; [ -e "$W/users/$n" ] || exit 6; '
                'rm -f "$W/users/$n"; [ "$1" = -r ] && rm -rf "$W/home/$n"; true'),
    # The answer nervus gives, and everything curl was asked to do.
    "curl": ('echo "curl $*" >> "$W/log"; out=; data=; while [ $# -gt 0 ]; do case $1 in '
             '-o) out=$2; shift;; --data-binary) data=${2#@}; shift;; esac; shift; done; '
             # No data: the script asking whether its code is still good, before anything.
             'if [ -z "$data" ]; then [ -n "${DOWN_AT_FIRST:-}" ] && { echo "curl: (7) Failed to connect" >&2; '
             'exit 7; }; printf %s "${FIRST_STATUS:-200}"; exit 0; fi; '
             '[ -n "${CURL_DOWN:-}" ] && { echo "curl: (7) Failed to connect" >&2; exit 7; }; '
             'cp "$data" "$W/report"; echo "${ANSWER:-nervus: web is enrolled}" > "$out"; '
             'printf %s "${STATUS:-200}"'),
    "tmux": 'true',
}


def _command(path: Path, body: str) -> None:
    path.write_text(f"#!/bin/sh\n{body}\n")
    path.chmod(0o755)


class Machine:
    """A Linux machine that has never seen nervus, under one folder."""

    def __init__(self, tmp: Path, *, installed=("bwrap", "sudo", "visudo", "tmux"), restricted=False):
        self.w = tmp
        self.root = tmp / "root"
        for d in ("etc/sudoers.d", "etc/ssh", "usr/sbin", "etc/apparmor.d", "etc/apt/apt.conf.d", "proc/sys/kernel"):
            (self.root / d).mkdir(parents=True)
        # The kernel's switch, as Ubuntu's apparmor package sets it since 24.04 (question 9).
        (self.root / "proc/sys/kernel/apparmor_restrict_unprivileged_userns").write_text(
            "1\n" if restricted else "0\n")
        (self.root / "etc/machine-id").write_text(MACHINE + "\n")
        (self.root / "etc/ssh/ssh_host_ed25519_key.pub").write_text(HOST_KEY + "\n")
        _command(self.root / "usr/sbin/sshd", "exit 0")
        self.bin, self.store = tmp / "bin", tmp / "store"
        self.bin.mkdir()
        self.store.mkdir()
        (tmp / "log").touch()
        for name in REAL:
            (self.bin / name).symlink_to(shutil.which(name))
        for name, body in STANDINS.items():
            _command(self.store / name, body)
            if name not in ("bwrap", "sudo", "visudo", "tmux") or name in installed:
                shutil.copy(self.store / name, self.bin / name)
        self.level = "read-only"

    def without(self, *names):
        for name in names:
            (self.bin / name).unlink()

    def add_user(self, name, uid=1001, groups=None, keys=None, gid=None):
        """An account already here, before the script; its own group's id is `gid`, or its uid."""
        (self.w / "users").mkdir(exist_ok=True)
        (self.w / "users" / name).write_text(f"{uid}\n")
        if gid is not None:
            (self.w / "gids").mkdir(exist_ok=True)
            (self.w / "gids" / name).write_text(f"{gid}\n")
        (self.w / "home" / name).mkdir(parents=True, exist_ok=True)
        if groups:
            (self.w / "groups").mkdir(exist_ok=True)
            (self.w / "groups" / name).write_text(" ".join(groups) + "\n")
        if keys is not None:
            (self.w / "home" / name / ".ssh").mkdir(exist_ok=True)
            (self.w / "home" / name / ".ssh" / "authorized_keys").write_text(keys)

    def exists(self, name):
        return (self.w / "users" / name).exists()

    def gid_of(self, name):
        """The id of the account's own group (ADR-0031: nervus's copy of bwrap is that group's)."""
        gids = self.w / "gids" / name
        return (gids if gids.exists() else self.w / "users" / name).read_text().strip()

    def members(self, gid, *names):
        """Accounts in group `gid` besides those whose own group it is."""
        (self.w / "members").mkdir(exist_ok=True)
        (self.w / "members" / str(gid)).write_text(",".join(names) + "\n")

    def home_of(self, name):
        return self.w / "home" / name

    def keys_of(self, name):
        path = self.home_of(name) / ".ssh" / "authorized_keys"
        return path.read_text() if path.exists() else None

    @property
    def home(self):
        """The home of the account the level is about: the read-only one at read-only, else the read-write one."""
        return self.home_of(RO if self.level == "read-only" else RW)

    def run(self, level="read-only", shell="sh", nervus_machine=ELSEWHERE, script_args=None, **env):
        """The script for `level`, run here; nervus runs on `nervus_machine`."""
        self.level = level
        script = self.w / "nervus-enroll.sh"
        own = own_hash(URL.rsplit("/", 1)[1], nervus_machine) if level == "full" else None
        script.write_text(enroll_script(name="web", level=level, origin="https://192.0.2.1:8000", url=URL,
                                        pin=PIN, key=KEY, own_hash=own, **(script_args or {})))
        base = {"PATH": str(self.bin), "W": str(self.w), "NERVUS_ENROLL_ROOT": str(self.root), "LANG": "C"}
        return subprocess.run([shutil.which(shell), str(script)], capture_output=True, text=True,
                              env={**base, **env}, timeout=30)

    def remove(self, commands=None):
        """The removal commands as the page shows them for this machine's
        accounts (ADR-0031), run in a root shell, the system paths under this
        machine's folder."""
        if commands is None:  # as nervus's record has them: the accounts the script said it made (question 9)
            report = (self.w / "report").read_text().splitlines() if (self.w / "report").exists() else []
            made = [line.split()[1] for line in report if line.startswith("nervus-made ")]
            commands = remove_commands(None if self.level == "read-only" else RW, RO, made=made,
                                       keys=(" ".join(KEY.split()[:2]),))
        commands = commands.replace("/etc/", f"{self.root}/etc/").replace("/usr/local/", f"{self.root}/usr/local/")
        base = {"PATH": str(self.bin), "W": str(self.w), "LANG": "C"}
        return subprocess.run([shutil.which("sh"), "-c", commands], capture_output=True, text=True, env=base,
                              timeout=30)

    @property
    def log(self):
        return (self.w / "log").read_text().splitlines()

    @property
    def keys(self):
        path = self.home / ".ssh" / "authorized_keys"
        return path.read_text() if path.exists() else None

    @property
    def readonly_keys(self):
        return self.keys_of(RO)

    @property
    def sudoers(self):
        """The read-write account's own sudoers file (procedure 068: one for each account)."""
        return self.root / f"etc/sudoers.d/nervus-{RW}"

    @property
    def legacy_sudoers(self):
        """`agent`'s, as nervus wrote it before 0.3.0 and as a VM used by its id has it."""
        return self.root / "etc/sudoers.d/nervus-agent"

    @property
    def shell(self):
        return self.root / READONLY_SHELL_PATH.lstrip("/")

    @property
    def copy(self):
        return self.root / BWRAP_COPY_PATH.lstrip("/")

    @property
    def profile(self):
        return self.root / APPARMOR_PROFILE_PATH.lstrip("/")

    @property
    def hook(self):
        return self.root / APT_HOOK_PATH.lstrip("/")

    @property
    def nothing_of_question_9(self):
        return not self.copy.exists() and not self.profile.exists() and not self.hook.exists()


@pytest.fixture
def machine(tmp_path):
    return Machine(tmp_path)


@pytest.mark.parametrize("shell", SHELLS)
def test_read_only_makes_the_read_only_account_behind_the_read_only_shell(machine, shell):
    done = machine.run("read-only", shell=shell)
    assert done.returncode == 0, done.stderr
    # ADR-0031: at read-only alone, the read-only account alone.
    assert f"useradd -m -s /bin/sh {RO}" in machine.log and not machine.exists(RW)
    assert machine.keys == f'cert-authority,restrict,command="{READONLY_SHELL_PATH}" {KEY}\n'
    assert oct((machine.home / ".ssh/authorized_keys").stat().st_mode & 0o777) == "0o600"
    assert machine.shell.read_text() == READONLY_SHELL.read_text()
    assert oct(machine.shell.stat().st_mode & 0o777) == "0o755"
    assert f"chown root:root {machine.shell.parent}" in machine.log
    assert not machine.sudoers.exists()
    assert "nervus: web is enrolled" in done.stdout


@pytest.mark.parametrize("level", ["read-only", "standard", "full"])
def test_its_progress_says_each_account_trusts_nervus_certificate_authority(machine, level):
    """Since ADR-0025 the line written is nervus's CA, not its key (procedure
    042, finding 2); the owner reads this line on nervus's progress page."""
    done = machine.run(level)
    assert done.returncode == 0, done.stderr
    lines = done.stdout.splitlines()
    assert f"nervus enrollment: {RO} trusts nervus's certificate authority, read-only" in lines
    assert (f"nervus enrollment: {RW} trusts nervus's certificate authority" in lines) == (level != "read-only")
    assert "nervus's key" not in done.stdout and machine.keys.startswith("cert-authority")


@pytest.mark.parametrize("level", ["read-only", "standard", "full"])
def test_the_shell_is_tried_as_the_read_only_account_inside_bwrap_before_its_key(machine, level):
    machine.run(level)
    log = machine.log
    tried = next(i for i, line in enumerate(log) if line.startswith("su "))
    assert log[tried] == f"su -s /bin/sh -c SSH_ORIGINAL_COMMAND=true {machine.shell} {RO}"
    assert log[tried + 1].startswith("bwrap --unshare-user --disable-userns --ro-bind / /")
    assert (machine.home_of(RO) / ".nervus").is_dir()  # made by the account, as nervus will find it
    assert tried < next(i for i, line in enumerate(log) if line.startswith("su ") and "authorized_keys" in line)


def test_where_bwrap_cannot_run_read_only_is_refused_and_no_key_is_written(machine):
    done = machine.run("read-only", SU_FAILS="1")
    assert done.returncode == 1
    assert "bubblewrap cannot run here" in done.stderr and "add it as standard" in done.stderr
    assert "No permissions to create new namespace" in done.stderr
    assert machine.keys is None and not any("--data-binary" in line for line in machine.log)
    # The kernel's switch is not on here, so no AppArmor profile is tried (question 9).
    assert machine.nothing_of_question_9 and not any(line.startswith("apparmor_parser") for line in machine.log)


def test_read_only_installs_bubblewrap_when_it_is_missing(tmp_path):
    machine = Machine(tmp_path, installed=("sudo", "visudo"))
    done = machine.run("read-only")
    assert done.returncode == 0, done.stderr
    assert "apt-get update -q" in machine.log and "apt-get install -y -q bubblewrap" in machine.log


def test_without_apt_get_it_says_what_to_install(tmp_path):
    machine = Machine(tmp_path, installed=("tmux",))
    machine.without("apt-get")
    done = machine.run("read-only")
    assert done.returncode == 1 and "install bubblewrap" in done.stderr and machine.keys is None


def test_standard_is_the_key_alone_and_takes_away_an_earlier_sudoers_line(machine):
    machine.sudoers.write_text(f"{RW} ALL=(ALL) NOPASSWD: ALL\n")
    done = machine.run("standard")
    assert done.returncode == 0, done.stderr
    assert machine.keys == f"cert-authority {KEY}\n"
    assert not machine.sudoers.exists()
    # ADR-0031 question 6: standard always makes the read-only account too, behind the read-only shell.
    assert machine.readonly_keys == f'cert-authority,restrict,command="{READONLY_SHELL_PATH}" {KEY}\n'
    assert machine.shell.exists()


def test_full_writes_a_sudoers_line_visudo_checked(machine):
    done = machine.run("full")
    assert done.returncode == 0, done.stderr
    assert machine.keys == f"cert-authority {KEY}\n"
    assert machine.sudoers.read_text() == f"{RW} ALL=(ALL) NOPASSWD: ALL\n"
    assert oct(machine.sudoers.stat().st_mode & 0o777) == "0o440"
    assert f"visudo -cqf {machine.root}/etc/sudoers.d/.nervus-{RW}" in machine.log


def test_full_installs_sudo_when_it_is_missing(tmp_path):
    machine = Machine(tmp_path, installed=())
    assert machine.run("full").returncode == 0
    assert "apt-get install -y -q sudo" in machine.log and machine.sudoers.exists()


def test_a_sudoers_line_visudo_refuses_is_never_put_in_place_and_no_key_is_written(machine):
    done = machine.run("full", VISUDO_FAILS="1")
    assert done.returncode == 1 and "visudo refused" in done.stderr
    assert list((machine.root / "etc/sudoers.d").iterdir()) == [] and machine.keys is None


@pytest.mark.parametrize("level", ["read-only", "standard", "full"])
def test_an_existing_account_ends_with_exactly_nervus_key_and_says_so(machine, level):
    for name in (RW, RO):
        machine.add_user(name, groups=[name, "adm"], keys="ssh-ed25519 AAAAsomeoneelse x\n")
    done = machine.run(level)
    assert done.returncode == 0, done.stderr
    assert "someoneelse" not in machine.keys and machine.keys.count("\n") == 1
    assert not any(line.startswith("useradd") for line in machine.log)
    # ADR-0031 question 8: used as it is, its groups said, and its own keys' replacement said.
    assert f"nervus enrollment: using the account {RO}, which was here already, as it is: it is in the groups {RO} adm" \
        in done.stdout
    assert f"nervus enrollment: {RO}'s own SSH keys are replaced by nervus's line" in done.stdout


@pytest.mark.parametrize("level", ["read-only", "standard", "full"])
def test_root_does_nothing_by_path_in_agents_home(machine, level):
    # agent's home is agent's own. Where agent has no sudo, a write, a chown, a chmod or a rename
    # that root makes there by path can be turned, by a link agent swaps in at the right instant,
    # onto a file elsewhere: root's own chown, onto a file of root's (procedure 056, C32, whose
    # first fix closed only a link planted beforehand; procedure 058). So every command that
    # names a path inside agent's home runs as agent, where a link reaches only what agent
    # could reach already.
    for name in ("mkdir", "chmod", "mv", "rm", "cat", "cp", "touch"):  # log who ran it, then run it
        real = shutil.which(name)
        (machine.bin / name).unlink()
        _command(machine.bin / name, f'echo "${{AS_ACCOUNT:+account: }}{name} $*" >> "$W/log"; exec {real} "$@"')
    _command(machine.bin / "chown", 'echo "${AS_ACCOUNT:+account: }chown $*" >> "$W/log"')
    su = (machine.bin / "su").read_text()
    assert "HOME=$W/home/$5 exec" in su
    (machine.bin / "su").write_text(su.replace("HOME=$W/home/$5 exec", "AS_ACCOUNT=1 HOME=$W/home/$5 exec"))
    done = machine.run(level)
    assert done.returncode == 0, done.stdout + done.stderr
    # ADR-0031: in each account's home, the read-only one's too.
    for home in {machine.home, machine.home_of(RO)}:
        inside = str(home) + "/"
        # (bwrap's own line is the read-only shell, which su runs as the account.)
        by_root = [line for line in machine.log if inside in line and not line.startswith(("account: ", "su ", "bwrap "))]
        assert by_root == [], by_root
        assert oct((home / ".ssh/authorized_keys").stat().st_mode & 0o777) == "0o600"
        assert oct((home / ".ssh").stat().st_mode & 0o777) == "0o700"


def test_a_symbolic_link_for_ssh_is_refused(machine, tmp_path):
    machine.home.mkdir(parents=True)
    (machine.w / ".agent").touch()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (machine.home / ".ssh").symlink_to(elsewhere)
    done = machine.run("standard")
    assert done.returncode == 1 and "symbolic link" in done.stderr and list(elsewhere.iterdir()) == []


def test_it_sends_the_machine_id_and_host_keys_back_pinned(machine):
    machine.run("standard")
    # With the accounts it made, which removal deletes and no other (ADR-0031 question 9).
    assert (machine.w / "report").read_text() == (f"machine-id {MACHINE}\nnervus-made {RW}\nnervus-made {RO}\n"
                                                  f"{HOST_KEY}\n")
    curl = next(line for line in machine.log if line.startswith("curl") and "--data-binary" in line)
    assert f"-sSk --pinnedpubkey {PIN} " in curl and curl.endswith(URL)
    assert "--data-binary @" in curl


def test_what_nervus_answers_is_shown_and_a_refusal_fails(machine):
    done = machine.run("full", STATUS="422", ANSWER="nervus: nervus checked 192.0.2.10 and did not add it")
    assert done.returncode == 1 and "did not add it" in done.stdout


@pytest.mark.parametrize("level", ["read-only", "standard", "full"])
def test_when_nervus_does_not_add_the_machine_the_accounts_it_made_are_deleted_again(machine, level):
    """ADR-0031 question 12: an add nervus refuses leaves the machine as it was: the accounts the script made
    are deleted, and nervus's sudoers line and read-only shell go with them."""
    done = machine.run(level, STATUS="422", ANSWER="nervus: nervus checked 192.0.2.10 and did not add it")
    assert done.returncode == 1
    assert not machine.exists(RO) and not machine.home_of(RO).exists() and not machine.sudoers.exists()
    assert not machine.exists(RW) and not machine.home_of(RW).exists()
    assert not machine.shell.exists() and not machine.shell.parent.exists()
    made = RO if level == "read-only" else f"{RW} {RO}"
    assert "nervus enrollment: nervus did not add this machine\n" in done.stderr
    assert f"the accounts it made are deleted: {made}\n" in done.stderr and "could NOT" not in done.stderr


def test_when_nervus_cannot_be_reached_its_key_is_taken_off_again(machine):
    done = machine.run("full", CURL_DOWN="1")
    assert done.returncode == 1 and "could not reach nervus" in done.stderr
    assert not machine.keys and not machine.sudoers.exists()


@pytest.mark.parametrize("shell", SHELLS)
def test_full_on_the_machine_nervus_runs_on_is_refused_before_anything_changes(machine, shell):
    """ADR-0024 decision 6, enforced by the script too: nervus's machine id
    reaches it only hashed with the code, and nothing is made before the
    comparison."""
    done = machine.run("full", nervus_machine=MACHINE, shell=shell)
    assert done.returncode == 1 and "the machine nervus runs on" in done.stderr
    assert machine.log == [] and machine.keys is None and not machine.sudoers.exists()
    assert not (machine.w / ".agent").exists()


def test_the_script_never_holds_nervus_machine_id():
    script = enroll_script(name="web", level="full", origin="o", url=URL, pin=PIN, key=KEY,
                           own_hash=own_hash("CODE", ELSEWHERE))
    assert ELSEWHERE not in script and own_hash("CODE", ELSEWHERE) in script


@pytest.mark.parametrize("level, own", [("full", None), ("standard", "x" * 64)])
def test_a_full_script_needs_nervus_hash_and_only_a_full_one_has_it(level, own):
    with pytest.raises(ValueError):
        enroll_script(name="web", level=level, origin="o", url=URL, pin=PIN, key=KEY, own_hash=own)


def test_without_sha256sum_full_stops_before_anything_changes(machine):
    machine.without("sha256sum")
    done = machine.run("full")
    assert done.returncode == 1 and "sha256sum" in done.stderr and machine.log == []


def test_nervus_out_of_reach_fails_saying_so(machine):
    done = machine.run("standard", CURL_DOWN="1")
    assert done.returncode == 1 and f"could not reach nervus at {URL}" in done.stderr


def test_it_runs_only_as_root(machine):
    done = machine.run("full", AS_UID="1000")
    assert done.returncode == 1 and "run this as root" in done.stderr
    assert machine.log == [] and machine.keys is None


def test_it_needs_an_ssh_server(machine):
    (machine.root / "usr/sbin/sshd").unlink()
    done = machine.run("standard")
    assert done.returncode == 1 and "install openssh-server" in done.stderr and machine.log == []


def test_without_a_machine_id_it_stops_before_anything_changes(machine):
    (machine.root / "etc/machine-id").unlink()
    done = machine.run("standard")
    assert done.returncode == 1 and "no machine id" in done.stderr
    assert machine.log == [] and machine.keys is None


@pytest.mark.parametrize("level, says, never", [
    ("read-only", "bubblewrap", "without a password"),
    ("standard", f"{RW}, the read-write account, can change only what it owns", "without a password"),
    ("full", "without a password", "can change only what it owns"),
])
def test_its_opening_comment_says_what_this_level_does_and_nothing_else(level, says, never):
    own = own_hash("CODE", ELSEWHERE) if level == "full" else None
    script = enroll_script(name="web", level=level, origin="https://n:8000", url=URL, pin=PIN, key=KEY, own_hash=own)
    head = script.split("\nset -u\n")[0]
    assert f"enroll this machine as web, {level}." in head and says in head and never not in head


def test_its_values_reach_the_shell_exactly(tmp_path):
    url = "https://n:8000/enroll/a'b\"$(touch x)`id`"
    script = enroll_script(name="web", level="standard", origin="o", url=url, pin=PIN, key=KEY)
    assignments = script.split("\nset -u\n")[1].split("root=")[0]
    out = subprocess.run(["sh", "-c", assignments + 'printf "%s\\n" "$url" "$pin" "$key" "$level"'],
                         capture_output=True, text=True, cwd=tmp_path).stdout
    assert out.splitlines() == [url, PIN, KEY, "standard"] and not (tmp_path / "x").exists()


@pytest.mark.parametrize("field", ["name", "origin", "url", "pin", "key"])
def test_a_line_break_in_a_value_is_refused(field):
    values = dict(name="web", level="standard", origin="o", url=URL, pin=PIN, key=KEY)
    values[field] += "\nrm -rf /"
    with pytest.raises(ValueError):
        enroll_script(**values)


def test_a_read_only_shell_that_would_end_its_own_heredoc_is_refused():
    with pytest.raises(ValueError):
        enroll_script(name="web", level="read-only", origin="o", url=URL, pin=PIN, key=KEY,
                      readonly_shell="echo hi\nNERVUS_READONLY_SHELL\nrm -rf /\n")


def test_shlex_is_what_quotes_them():
    assert shlex.quote(PIN) in enroll_script(name="web", level="full", origin="o", url=URL, pin=PIN, key=KEY,
                                             own_hash=own_hash("CODE", ELSEWHERE))


@pytest.mark.parametrize("level", ["read-only", "full"])
def test_the_removal_commands_leave_no_account_no_key_no_sudoers_line_and_no_shell(machine, level):
    """ADR-0024 verification 7, as the page shows them for the accounts the script made."""
    assert machine.run(level).returncode == 0
    assert machine.keys and (machine.sudoers.exists() or machine.shell.exists())
    done = machine.remove()
    assert done.returncode == 0, done.stderr
    for name in ([RO] if level == "read-only" else [RW, RO]):
        assert f"pkill -KILL -u {name}" in machine.log and f"userdel -r {name}" in machine.log
        assert not machine.exists(name) and machine.keys_of(name) is None and not machine.home_of(name).exists()
    assert not machine.sudoers.exists() and not machine.shell.parent.exists()


def test_the_removal_commands_name_only_what_the_script_made():
    assert remove_commands(made=("agent",)).splitlines() == [
        "pkill -KILL -u agent; sleep 1", "userdel -r agent", "rm -f /etc/sudoers.d/nervus-agent",
        "apparmor_parser -R /etc/apparmor.d/nervus-bwrap 2>/dev/null; "
        "rm -f /etc/apparmor.d/nervus-bwrap /etc/apt/apt.conf.d/99nervus-bwrap",
        "rm -rf /usr/local/lib/nervus"]
    # ADR-0031 question 9: a machine added before this release, where nervus cannot tell, keeps `agent`.
    assert "userdel" not in remove_commands() and "pkill" not in remove_commands()
    assert READONLY_SHELL_PATH.startswith("/usr/local/lib/nervus/") and BWRAP_COPY_PATH.startswith("/usr/local/lib/nervus/")



# --- the code checked first; tmux for background jobs (procedure 037's findings) ------

def test_the_script_asks_nervus_whether_its_code_is_still_good_before_anything(machine):
    assert machine.run("standard").returncode == 0
    first = machine.log[0]
    assert first.startswith("curl -sSk --pinnedpubkey " + PIN) and "-o /dev/null" in first and first.endswith(URL)
    assert "--data-binary" not in first


@pytest.mark.parametrize("level", ["read-only", "standard", "full"])
def test_a_used_or_expired_code_changes_nothing(machine, level):
    """Procedure 037 step 7: a fetch that failed leaves an older script in
    the folder for the second line to run. Its code is spent, so it stops at
    once instead of changing the machine and taking nervus's key off."""
    done = machine.run(level, FIRST_STATUS="404")
    assert done.returncode == 1 and "used or expired" in done.stderr and "Nothing here was changed" in done.stderr
    assert len(machine.log) == 1 and machine.keys is None and not machine.sudoers.exists()
    assert not (machine.w / ".agent").exists()


def test_nervus_out_of_reach_at_first_changes_nothing(machine):
    done = machine.run("full", DOWN_AT_FIRST="1")
    assert done.returncode == 1 and "could not reach nervus" in done.stderr
    assert len(machine.log) == 1 and not (machine.w / ".agent").exists()


@pytest.mark.parametrize("level", ["read-only", "standard", "full"])
def test_tmux_is_installed_for_background_jobs_at_every_level(tmp_path, level):
    """ADR-0024 decision 7, as amended after procedure 037: exec_bg needs it."""
    machine = Machine(tmp_path, installed=("bwrap", "sudo", "visudo"))
    assert machine.run(level).returncode == 0
    assert "apt-get install -y -q tmux" in machine.log and (machine.bin / "tmux").exists()


def test_tmux_already_there_is_left_alone(machine):
    assert machine.run("standard").returncode == 0
    assert not any(line.startswith("apt-get") for line in machine.log)


# --- where AppArmor keeps programs from making user namespaces (question 9) ----------------------
# Ubuntu since 24.04: bwrap cannot start as installed, so read-only gives nervus's own copy of it,
# which only agent may run, a profile letting that copy alone make them, and an apt hook keeping the
# copy the system's. Read-only's alone: every other level, and removal, takes the three off.


@pytest.mark.parametrize("shell", SHELLS)
def test_read_only_where_apparmor_restricts_namespaces_gives_nervus_copy_of_bwrap_a_profile(tmp_path, shell):
    machine = Machine(tmp_path, restricted=True)
    done = machine.run("read-only", shell=shell, USERNS_RESTRICTED="1")
    assert done.returncode == 0, done.stderr
    assert "AppArmor keeps programs from making user namespaces" in done.stdout
    assert machine.copy.read_bytes() == (machine.bin / "bwrap").read_bytes()
    assert oct(machine.copy.stat().st_mode & 0o777) == "0o750"
    assert f"chown root:{machine.gid_of(RO)} {machine.copy.parent}/.bwrap" in machine.log  # its group alone (ADR-0031)
    profile = machine.profile.read_text()
    assert "abi <abi/4.0>," in profile and "include <tunables/global>" in profile
    assert "profile nervus-bwrap /usr/local/lib/nervus/bwrap flags=(unconfined) {\n  userns,\n}\n" in profile
    assert machine.hook.read_text().count("DPkg::Post-Invoke") == 1
    assert f"! cmp -s {machine.bin / 'bwrap'} /usr/local/lib/nervus/bwrap; then cp {machine.bin / 'bwrap'} " \
           f"/usr/local/lib/nervus/.bwrap && chown root:{machine.gid_of(RO)}" in machine.hook.read_text()
    # Tried as the read-only account, refused; the profile loaded; tried again; and only then nervus's key.
    tries = [i for i, line in enumerate(machine.log) if line.startswith("su ") and "readonly-shell" in line]
    loaded = machine.log.index(f"apparmor_parser -r {machine.profile}")
    keyed = next(i for i, line in enumerate(machine.log) if line.startswith("su ") and "authorized_keys" in line)
    assert len(tries) == 2 and tries[0] < loaded < tries[1] < keyed
    assert machine.keys == f'cert-authority,restrict,command="{READONLY_SHELL_PATH}" {KEY}\n'


def test_where_the_copy_still_cannot_start_nothing_is_left_and_read_only_is_refused(tmp_path):
    machine = Machine(tmp_path, restricted=True)
    done = machine.run("read-only", USERNS_RESTRICTED="1", STILL_FAILS="1")
    assert done.returncode == 1 and "even as nervus's own copy with its AppArmor profile" in done.stderr
    assert "add it as standard" in done.stderr and "setting up uid map" in done.stderr
    assert machine.nothing_of_question_9 and f"apparmor_parser -R {machine.profile}" in machine.log
    assert machine.keys is None


def test_a_profile_apparmor_will_not_load_leaves_nothing_and_read_only_is_refused(tmp_path):
    machine = Machine(tmp_path, restricted=True)
    done = machine.run("read-only", USERNS_RESTRICTED="1", PARSER_FAILS="1")
    assert done.returncode == 1 and "AppArmor would not load nervus's profile" in done.stderr
    assert "the test's" in done.stderr and machine.nothing_of_question_9 and machine.keys is None


def test_without_apparmor_parser_a_restricted_machine_is_refused_as_before(tmp_path):
    machine = Machine(tmp_path, restricted=True)
    machine.without("apparmor_parser")
    done = machine.run("read-only", USERNS_RESTRICTED="1")
    assert done.returncode == 1 and "bubblewrap cannot run here (" in done.stderr
    assert "so this machine cannot be read-only" in done.stderr
    assert machine.nothing_of_question_9 and machine.keys is None


@pytest.mark.parametrize("level", ["standard", "full"])
def test_another_level_takes_the_three_off_then_makes_them_afresh_for_the_read_only_account(tmp_path, level):
    """ADR-0031: at standard and full the read-only account needs them too, so what an earlier
    enrollment left is taken off first and made again, the copy the read-only account's alone."""
    machine = Machine(tmp_path, restricted=True)
    assert machine.run("read-only", USERNS_RESTRICTED="1").returncode == 0 and machine.copy.exists()
    done = machine.run(level, USERNS_RESTRICTED="1")
    assert done.returncode == 0, done.stderr
    assert "took off nervus's copy of bwrap, its AppArmor profile and its apt hook" in done.stdout
    removed = machine.log.index(f"apparmor_parser -R {machine.profile}")
    loaded = len(machine.log) - 1 - machine.log[::-1].index(f"apparmor_parser -r {machine.profile}")
    assert removed < loaded and machine.copy.exists() and machine.profile.exists() and machine.hook.exists()
    assert machine.log.count(f"chown root:{machine.gid_of(RO)} {machine.copy.parent}/.bwrap") == 2


def test_read_only_again_makes_the_three_afresh(tmp_path):
    machine = Machine(tmp_path, restricted=True)
    assert machine.run("read-only", USERNS_RESTRICTED="1").returncode == 0
    done = machine.run("read-only", USERNS_RESTRICTED="1")
    assert done.returncode == 0, done.stderr
    assert machine.copy.exists() and machine.profile.exists() and machine.hook.exists()
    assert machine.log.count(f"apparmor_parser -r {machine.profile}") == 2


def test_when_nervus_does_not_add_a_restricted_machine_the_three_go_too(tmp_path):
    machine = Machine(tmp_path, restricted=True)
    done = machine.run("read-only", USERNS_RESTRICTED="1", STATUS="422", ANSWER="nervus: did not add it")
    assert done.returncode == 1 and "copy of bwrap with its AppArmor profile" in done.stderr
    assert machine.nothing_of_question_9 and not machine.keys  # no line of nervus's


def test_the_removal_commands_take_the_copy_its_profile_and_its_hook_off(tmp_path):
    machine = Machine(tmp_path, restricted=True)
    assert machine.run("read-only", USERNS_RESTRICTED="1").returncode == 0
    done = machine.remove()
    assert done.returncode == 0, done.stderr
    assert f"apparmor_parser -R {machine.profile}" in machine.log and machine.nothing_of_question_9
    assert not machine.shell.parent.exists()


@pytest.mark.parametrize("level", ["standard", "full"])
def test_every_other_level_s_opening_comment_says_it_takes_the_three_off(level):
    own = own_hash("CODE", ELSEWHERE) if level == "full" else None
    head = enroll_script(name="web", level=level, origin="https://n:8000", url=URL, pin=PIN, key=KEY,
                         own_hash=own).split("\nset -u\n")[0]
    assert "Takes off nervus's copy of bwrap (/usr/local/lib/nervus/bwrap), its AppArmor" in head


def test_read_only_s_opening_comment_names_the_three_and_when():
    head = enroll_script(name="web", level="read-only", origin="https://n:8000", url=URL, pin=PIN,
                         key=KEY).split("\nset -u\n")[0]
    flat = " ".join(line.lstrip("# ") for line in head.splitlines())
    for words in ("AppArmor keeps programs from making user namespaces", "Ubuntu's does since 24.04",
                  BWRAP_COPY_PATH, APPARMOR_PROFILE_PATH, APT_HOOK_PATH, f"only {RO} may run",
                  "and its apt hook first"):
        assert words in flat, words
