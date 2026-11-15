"""nervus's read-only shell (ADR-0024 step 1): what it asks bubblewrap for, and
what it refuses. bwrap itself, the kernel's enforcement, runs only on Linux;
here a stand-in records its arguments and then runs what follows `--`,
unconfined, so the shell's own logic is tested in a real sh. Asked `--help`,
it answers as bubblewrap 0.8 and later do, naming `--disable-userns`, or as an
older one, without it. Procedure 036 tries the real thing on throwaway machines."""

import os
import subprocess
from pathlib import Path

import pytest

SHELL = Path(__file__).resolve().parent.parent / "src" / "nervus" / "target" / "readonly-shell"

# What a stand-in for bwrap answers to `--help`: bubblewrap 0.8 and later name --disable-userns; with
# BWRAP_OLD set, it answers as an older one. Never recorded as a sandbox's arguments.
_HELP = ('[ "$1" = --help ] && { echo "usage: bwrap [OPTIONS...] [--] COMMAND [ARGS...]"; '
         '[ -n "$BWRAP_OLD" ] || echo "    --disable-userns             Disable further use of user namespaces"; '
         'exit 0; }\n')


@pytest.fixture
def host(tmp_path):
    home = tmp_path / "home" / "agent"
    home.mkdir(parents=True)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "bwrap.log"
    bwrap = bin_dir / "bwrap"
    bwrap.write_text('#!/bin/sh\n' + _HELP +
                     'printf "%s\\n" "$@" > "$BWRAP_LOG"\n'
                     '[ -n "$BWRAP_FAILS" ] && { echo "bwrap: No permissions to create new namespace" >&2; exit 1; }\n'
                     'while [ "$1" != -- ]; do shift; done; shift; exec "$@"\n')
    bwrap.chmod(0o755)

    def run(command, *, stdin="", bwrap=True, fails=False, old=False):
        path = f"{bin_dir}:/usr/bin:/bin" if bwrap else "/usr/bin:/bin"
        env = {"PATH": path, "HOME": str(home), "BWRAP_LOG": str(log)}
        if command is not None:
            env["SSH_ORIGINAL_COMMAND"] = command
        if fails:
            env["BWRAP_FAILS"] = "1"
        if old:
            env["BWRAP_OLD"] = "1"
        done = subprocess.run(["sh", str(SHELL)], input=stdin, capture_output=True, text=True, env=env, timeout=30)
        return done, (log.read_text().splitlines() if log.exists() else None)

    run.home = home
    return run


def test_a_command_runs_in_bash_inside_the_sandbox(host):
    done, args = host("echo hello; id -un >/dev/null")
    assert done.returncode == 0 and done.stdout == "hello\n"
    work = str(host.home / ".nervus")
    assert args[:2] == ["--unshare-user", "--disable-userns"]  # question 9, as amended after procedure 055
    assert args[2:4] == ["--ro-bind", "/"] and args[4] == "/"
    assert args[args.index("--bind") + 1:args.index("--bind") + 3] == [work, work]
    assert ["--tmpfs", "/tmp"] == args[args.index("/tmp") - 1:args.index("/tmp") + 1]
    # /run/user is masked so the sandbox cannot reach agent's session bus and the
    # systemd --user manager outside it (procedure 057, finding 5).
    assert ["--tmpfs", "/run/user"] == args[args.index("/run/user") - 1:args.index("/run/user") + 1]
    assert "--tmpfs" in args and "/dev/shm" in args
    assert args[args.index("--setenv") + 1:args.index("--setenv") + 3] == ["TMUX_TMPDIR", f"{work}/tmux"]
    assert args[args.index("--") + 1:] == ["/bin/bash", "-c", "echo hello; id -un >/dev/null"]


def test_a_system_bwrap_that_knows_no_disable_userns_runs_as_before(host):
    """bubblewrap before 0.8 (Ubuntu 22.04 has 0.6.1): the flag would stop it, so it is not given."""
    done, args = host("echo hello", old=True)
    assert done.returncode == 0 and done.stdout == "hello\n", done.stderr
    assert args[:3] == ["--ro-bind", "/", "/"] and "--disable-userns" not in args and "--unshare-user" not in args


def test_standard_input_reaches_the_command_as_nervus_sends_it(host):
    """nervus's exec runs `bash -s` with its script on standard input."""
    done, _ = host("bash -s", stdin="echo from-stdin\n")
    assert done.returncode == 0 and done.stdout == "from-stdin\n"


def test_nervus_working_folder_is_made_private(host):
    host("true")
    for folder in (host.home / ".nervus", host.home / ".nervus" / "tmux"):
        assert folder.is_dir() and oct(folder.stat().st_mode & 0o777) == "0o700"


@pytest.mark.parametrize("command", [None, ""])
def test_without_a_command_nothing_runs(host, command):
    done, args = host(command)
    assert done.returncode == 1 and "runs commands only" in done.stderr
    assert args is None


def test_without_bwrap_nothing_runs(host, tmp_path):
    marker = tmp_path / "ran"
    done, args = host(f"touch {marker}", bwrap=False)
    assert done.returncode == 1 and "bwrap is not installed" in done.stderr
    assert not marker.exists() and args is None


def test_a_bwrap_that_cannot_start_runs_nothing_unconfined(host, tmp_path):
    marker = tmp_path / "ran"
    done, _ = host(f"touch {marker}", fails=True)
    assert done.returncode == 1 and "namespace" in done.stderr
    assert not marker.exists()


@pytest.mark.parametrize("command", ["/usr/lib/openssh/sftp-server", "internal-sftp", "/usr/libexec/sftp-server -l INFO"])
def test_sftp_is_only_ever_the_read_only_server(host, command):
    """Each candidate sftp-server is run with -R, inside the sandbox; where none
    exists, as on this Mac, nothing runs."""
    done, args = host(command)
    existing = [s for s in ("/usr/lib/openssh/sftp-server", "/usr/libexec/openssh/sftp-server",
                            "/usr/lib/ssh/sftp-server", "/usr/libexec/sftp-server") if os.access(s, os.X_OK)]
    if existing:
        assert args[args.index("--") + 1:] == [existing[0], "-R"]
    else:
        assert done.returncode == 1 and "no sftp-server" in done.stderr and args is None


def test_a_command_naming_sftp_server_elsewhere_is_just_a_command(host):
    done, args = host("echo /usr/lib/openssh/sftp-server")
    assert args[args.index("--") + 1:] == ["/bin/bash", "-c", "echo /usr/lib/openssh/sftp-server"]


# --- nervus's own copy of bubblewrap, where AppArmor restricts user namespaces (ADR-0024 question 9) ---
# Enrollment puts it at /usr/local/lib/nervus/bwrap, 0750 root:agent, with a profile letting it alone make
# user namespaces; the shell runs it with --disable-userns, so nothing inside makes one of its own.


def _shell_with_copy_at(tmp_path, copy):
    """The read-only shell as enrollment carries it, its copy's path moved under this test's folder."""
    text = SHELL.read_text()
    assert text.count("copy=/usr/local/lib/nervus/bwrap\n") == 1
    shell = tmp_path / "readonly-shell"
    shell.write_text(text.replace("copy=/usr/local/lib/nervus/bwrap\n", f"copy={copy}\n"))
    return shell


def _bwrap_stand_in(path, log, mode=0o755):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f'#!/bin/sh\n{_HELP}printf "%s\\n" "$0" "$@" > "{log}"\n'
                    'while [ "$1" != -- ]; do shift; done; shift; exec "$@"\n')
    path.chmod(mode)


def _run(shell, home, path, command="echo hello"):
    env = {"PATH": path, "HOME": str(home), "SSH_ORIGINAL_COMMAND": command}
    return subprocess.run(["sh", str(shell)], capture_output=True, text=True, env=env, timeout=30)


def test_nervus_copy_of_bwrap_runs_where_it_is_and_nothing_inside_makes_a_namespace(tmp_path):
    home, log, copy = tmp_path / "home", tmp_path / "copy.log", tmp_path / "lib" / "bwrap"
    home.mkdir()
    _bwrap_stand_in(copy, log)
    done = _run(_shell_with_copy_at(tmp_path, copy), home, "/usr/bin:/bin")  # no bwrap on the path at all
    assert done.returncode == 0 and done.stdout == "hello\n", done.stderr
    args = log.read_text().splitlines()
    assert args[0] == str(copy)
    assert args[1:5] == ["--unshare-user", "--disable-userns", "--ro-bind", "/"]
    assert args[args.index("--") + 1:] == ["/bin/bash", "-c", "echo hello"]


def test_a_copy_agent_may_not_run_is_passed_over_for_the_system_bwrap(tmp_path):
    home, log, copy = tmp_path / "home", tmp_path / "bwrap.log", tmp_path / "lib" / "bwrap"
    home.mkdir()
    _bwrap_stand_in(copy, tmp_path / "copy.log", mode=0o644)
    _bwrap_stand_in(tmp_path / "bin" / "bwrap", log)
    done = _run(_shell_with_copy_at(tmp_path, copy), home, f"{tmp_path / 'bin'}:/usr/bin:/bin")
    assert done.returncode == 0 and done.stdout == "hello\n", done.stderr
    args = log.read_text().splitlines()
    assert args[0] == str(tmp_path / "bin" / "bwrap") and not (tmp_path / "copy.log").exists()
    assert args[1:5] == ["--unshare-user", "--disable-userns", "--ro-bind", "/"]  # as amended after procedure 055
