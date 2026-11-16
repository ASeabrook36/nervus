"""Enrolling by an admin login (ADR-0026 step 3): nervus fetches a machine's host
key to show, logs in pinned to exactly that key with an account and password
its owner typed, becomes root there directly or by `sudo`, and runs ADR-0024's
two lines. The password is held for one run and kept nowhere.

A real asyncssh server on loopback plays the machine: it takes one account and
password (by `password` or `keyboard-interactive`), records every password and
every public key it is offered, and runs each command with the real shell of
tests/sshd_shell.py. `id`, `sudo` and `curl` are stood in on PATH, as
tests/test_host_enrollment_route.py stands in `id` and `sudo`. Where a test
needs the route's judgement, it plays it on the code's record."""

import asyncio
import contextlib
import json
import logging
import shlex
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

import asyncssh
import pytest
from sshd_shell import _handle_process

from nervus.audit import AuditLog
from nervus.database import Database
from nervus.enrollment_codes import EnrollmentCodes
from nervus.enrollments import host_keys
import nervus.host_login as host_login
from nervus.host_login import (KEEP_SECONDS, LINE_CHARS, MAX_LINES, TAIL_LINES, HideCodesInSSHLog, LoginEnrollment,
                               LoginRefused,
                               _lines, fingerprint, key_file, login_command, root_command)

PIN = "sha256//47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
SHOWN = "https://nervus.example:8000/enroll/<code>"
ACCOUNT = "alice"
PASSWORD = "correct horse 7"
OK_SCRIPT = ("echo 'nervus enrollment: asking nervus to check and add this machine'\n"
             "echo \"nervus: web is enrolled, standard. In nervus's page, give a token this machine to let a "
             "client use it.\"\n")


def _url(value):
    return f"https://nervus.example:8000/enroll/{value}"


# --- the machine ---------------------------------------------------------------------------

class _Auth(asyncssh.SSHServer):
    def __init__(self, play):
        self.play = play

    def connection_made(self, conn):
        self.play.connections += 1
        if self.play.watch is not None:
            self.play.seen_at_connect.append(self.play.watch())

    def connection_lost(self, exc):
        self.play.closed += 1

    def begin_auth(self, username):
        self.play.usernames.append(username)
        return True

    def password_auth_supported(self):
        return "password" in self.play.methods

    def validate_password(self, username, password):
        self.play.passwords.append((username, password))
        return username == self.play.account and password == self.play.password

    def kbdint_auth_supported(self):
        return "keyboard-interactive" in self.play.methods

    def get_kbdint_challenge(self, username, lang, submethods):
        return "", "", "", [("Password: ", False)]

    def validate_kbdint_response(self, username, responses):
        self.play.passwords.append((username, responses[0] if responses else ""))
        return username == self.play.account and list(responses) == [self.play.password]

    def public_key_auth_supported(self):
        return True

    def validate_public_key(self, username, key):
        self.play.offered.append(key.export_public_key("openssh").decode().strip())
        return self.play.accepts is not None and key.export_public_key() == self.play.accepts.export_public_key()


class Playing:
    """One SSH server playing a machine, and everything it was offered."""

    def __init__(self, account=ACCOUNT, password=PASSWORD, methods=("password",), key_type="ssh-ed25519",
                 more_key_types=()):
        self.account, self.password, self.methods = account, password, methods
        self.passwords, self.offered, self.usernames, self.commands = [], [], [], []
        self.connections = self.closed = 0
        self.accepts = None  # a public key this machine would accept, if offered
        self.watch, self.seen_at_connect = None, []
        self.host_key = asyncssh.generate_private_key(key_type)
        self.more_keys = [asyncssh.generate_private_key(t) for t in more_key_types]  # a machine has one of each
        self.server = self.port = None

    async def start(self):
        self.server = await asyncssh.listen("127.0.0.1", 0, server_factory=lambda: _Auth(self),
                                            server_host_keys=[self.host_key, *self.more_keys],
                                            process_factory=self._process)
        self.port = self.server.sockets[0].getsockname()[1]

    async def _process(self, process):
        self.commands.append(process.command)
        await _handle_process(process)

    async def stop(self):
        self.server.close()
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(self.server.wait_closed(), 5)

    @property
    def key_line(self):
        return host_keys([self.host_key.export_public_key("openssh").decode()])[0]


class Standins:
    """What the machine's shell finds first on PATH: `id`, `sudo` and `curl`, and the script `curl`
    brings back."""

    def __init__(self, tmp_path):
        self.bin = tmp_path / "machine-bin"
        self.bin.mkdir()
        self.args, self.sudo_args = tmp_path / "curl-args", tmp_path / "sudo-args"
        self.downloaded, self.gate = tmp_path / "downloaded-script", tmp_path / "gate"
        self.play()
        self.curl()
        self.script(OK_SCRIPT)

    def _exe(self, name, text):
        path = self.bin / name
        path.write_text("#!/bin/sh\n" + text)
        path.chmod(0o755)

    def play(self, *, root=False, sudo="password", sudo_password=PASSWORD):
        """`id -u`, and `sudo -S -p ''` in a mode: password (reads a line and compares it), passwordless
        (reads nothing), denied, echo (prints what it read to its errors), or missing."""
        self._exe("id", f'[ "$1" = -u ] && echo {0 if root else 1000}\n')
        reads = {
            "password": ('IFS= read -r line\n[ "$line" = ' + shlex.quote(sudo_password) + ' ] '
                         '|| { echo "Sorry, try again." >&2; exit 1; }\n'),
            "passwordless": "",
            "denied": 'IFS= read -r line\necho "alice is not in the sudoers file." >&2\nexit 1\n',
            "echo": 'IFS= read -r line\necho "sudo: no, $line" >&2\nexit 1\n',
        }
        if sudo == "missing":
            self._exe("sudo", 'echo "sh: 1: sudo: not found" >&2\nexit 127\n')
            return
        self._exe("sudo", f'printf "%s\\n" "$@" > {shlex.quote(str(self.sudo_args))}\n'
                          '[ "$1" = -S ] && [ "$2" = -p ] && [ -z "$3" ] '
                          '|| { echo "sudo called oddly: $*" >&2; exit 2; }\nshift 3\n' + reads[sudo] + 'exec "$@"\n')

    def curl(self, *, reachable=True):
        """curl records its arguments, then writes the script to `-o`'s path, or fails with 22."""
        self._exe("curl", f'printf "%s\\n" "$@" > {shlex.quote(str(self.args))}\n'
                          + ("" if reachable else "exit 22\n")
                          + 'out=\nwhile [ $# -gt 0 ]; do [ "$1" = -o ] && out=$2; shift; done\n'
                          f'cp {shlex.quote(str(self.downloaded))} "$out"\n')

    def script(self, text):
        self.downloaded.write_text(text)

    def curl_args(self):
        return self.args.read_text().splitlines() if self.args.exists() else None

    def sudo_called(self):
        return self.sudo_args.read_text().splitlines() if self.sudo_args.exists() else None

    @property
    def path(self):
        return f"{self.bin}:/usr/bin:/bin"

    def no_curl(self, *, apt="installs"):
        """The machine has no curl anywhere on its PATH, which from here is this folder and one of links
        to the few real commands the root command uses. Its apt-get records its arguments and what was on
        its standard input, and then brings curl ("installs"), or fails ("fails"), or there is none
        ("missing")."""
        (self.bin / "curl").unlink()
        real = self.bin.parent / "machine-real"
        real.mkdir()
        for name in ("sh", "dash", "bash", "mktemp", "rm", "cp", "cat", "printf", "env", "chmod", "true", "sleep"):
            if found := shutil.which(name, path="/usr/bin:/bin"):
                (real / name).symlink_to(found)
        self.only = f"{self.bin}:{real}"
        self.apt_calls = self.bin.parent / "apt-calls"
        if apt == "missing":
            return
        curl = ('printf "%s\\n" "$@" > ' + shlex.quote(str(self.args)) + '\n'
                'out=\nwhile [ $# -gt 0 ]; do [ "$1" = -o ] && out=$2; shift; done\n'
                f'cp {shlex.quote(str(self.downloaded))} "$out"\n')
        self._exe("apt-get", f'echo "$DEBIAN_FRONTEND apt-get $* [$(cat)]" >> {shlex.quote(str(self.apt_calls))}\n'
                             + ('[ "$1" = install ] && { echo "E: Unable to locate package curl" >&2; exit 100; }\nexit 0\n'
                                if apt == "fails" else
                                f'[ "$1" = install ] && {{ printf \'#!/bin/sh\\n%s\' {shlex.quote(curl)} > {shlex.quote(str(self.bin / "curl"))}; '
                                f'chmod 755 {shlex.quote(str(self.bin / "curl"))}; }}\nexit 0\n'))

    def apt_called(self):
        return self.apt_calls.read_text().splitlines() if self.apt_calls.exists() else []


class World:
    def __init__(self, tmp_path, monkeypatch, playing):
        self.tmp, self.playing = tmp_path, playing
        self.db = Database(tmp_path / "nervus.db")
        self.db.open()
        self.codes = EnrollmentCodes(self.db)
        self.audit_path = tmp_path / "audit.jsonl"
        self.audit = AuditLog(path=self.audit_path)
        self.host_key = playing.key_line
        self.enrollment = LoginEnrollment(self.codes, self.audit, port=playing.port)
        self.stand = Standins(tmp_path)
        self.home = tmp_path / "nervus-home"
        self.home.mkdir()
        monkeypatch.setenv("PATH", self.stand.path)
        monkeypatch.setenv("HOME", str(self.home))
        monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)

    def make(self, level="standard", name="web", login=ACCOUNT):
        return self.codes.make(name=name, address="127.0.0.1", level=level, made_by="operator", login=login,
                               host_key=self.host_key)

    def start(self, made, *, login=ACCOUNT, password=PASSWORD, host_key=None, pin=PIN):
        value, code = made
        return self.enrollment.start(code, url=_url(value), pin=pin, host_key=host_key or self.host_key, login=login,
                                     password=password, shown=SHOWN)

    async def enroll(self, *, judged=None, level="standard", name="web", login=ACCOUNT, password=PASSWORD, pin=PIN):
        """Make a code, play the route's judgement on it if given, run, and wait. The code is not spent, so
        that it is the run that ends it."""
        value, code = made = self.make(level, name, login)
        if judged is not None:
            self.codes.finish(code.id, judged)
        run = self.start(made, login=login, password=password, pin=pin)
        await self.enrollment.finished()
        return run, value, code

    @property
    def records(self):
        return [json.loads(line) for line in self.audit_path.read_text().splitlines()] if self.audit_path.exists() else []

    def stored(self):
        """What nervus keeps: the database file and its write-ahead log as bytes, and the audit log."""
        out = {}
        for suffix in ("", "-wal"):
            path = Path(str(self.db.path) + suffix)
            out["database" + suffix] = path.read_bytes() if path.exists() else b""
        out["audit"] = self.audit_path.read_bytes() if self.audit_path.exists() else b""
        return out


@pytest.fixture
async def world(tmp_path, monkeypatch):
    playing = Playing()
    await playing.start()
    world = World(tmp_path, monkeypatch, playing)
    yield world
    world.stand.gate.touch()  # lets any script still waiting go
    await world.enrollment.finished()
    await playing.stop()


def _nowhere(world, runs, capsys=None, secret=PASSWORD):
    """The password is in none of what nervus keeps, shows or prints."""
    needle = secret.encode()
    for what, data in world.stored().items():
        assert needle not in data, what
    for run in runs:
        assert secret not in repr(run) and secret not in run.outcome and not any(secret in l for l in run.lines)
        code = world.codes.get(run.code_id)
        assert code is None or secret not in (code.outcome or "")
    if capsys is not None:
        seen = capsys.readouterr()
        assert secret not in seen.out and secret not in seen.err


# --- the host key to show ------------------------------------------------------------------

async def test_the_host_key_shown_is_the_servers_own_and_nothing_else_is_sent(world):
    assert await world.enrollment.host_key("127.0.0.1") == world.host_key
    assert world.playing.usernames == [] and world.playing.passwords == [] and world.playing.offered == []


def _line(key):
    return host_keys([key.export_public_key("openssh").decode()])[0]


async def test_the_key_shown_is_the_machines_ed25519_one_where_it_has_several_and_the_login_follows_it(world):
    """ADR-0026 question 9, found by procedure 040: asyncssh asks for RSA first, so a Debian machine showed its RSA
    key while the docs name the ed25519 file. The login is pinned to the key shown, and still logs in."""
    machine = Playing(key_type="ssh-rsa", more_key_types=("ecdsa-sha2-nistp256", "ssh-ed25519"))
    await machine.start()
    try:
        world.enrollment.port = machine.port
        shown = await world.enrollment.host_key("127.0.0.1")
        assert shown == _line(machine.more_keys[1]) and shown.startswith("ssh-ed25519 ")
        value, code = world.codes.make(name="web", address="127.0.0.1", level="standard", made_by="operator",
                                       login=ACCOUNT, host_key=shown)
        world.codes.finish(code.id, "enrolled web, standard")
        run = world.enrollment.start(code, url=_url(value), pin=PIN, host_key=shown, login=ACCOUNT,
                                     password=PASSWORD, shown=SHOWN)
        await world.enrollment.finished()
        assert run.enrolled, run.outcome
    finally:
        await machine.stop()


@pytest.mark.parametrize("key_type", ["ssh-rsa", "ecdsa-sha2-nistp256"])
async def test_a_machine_without_an_ed25519_key_shows_another_and_is_logged_in_to_by_it(world, key_type):
    machine = Playing(key_type=key_type)
    await machine.start()
    try:
        world.enrollment.port = machine.port
        shown = await world.enrollment.host_key("127.0.0.1")
        assert shown == machine.key_line
        value, code = world.codes.make(name="web", address="127.0.0.1", level="standard", made_by="operator",
                                       login=ACCOUNT, host_key=shown)
        world.codes.finish(code.id, "enrolled web, standard")
        run = world.enrollment.start(code, url=_url(value), pin=PIN, host_key=shown, login=ACCOUNT,
                                     password=PASSWORD, shown=SHOWN)
        await world.enrollment.finished()
        assert run.enrolled, run.outcome
    finally:
        await machine.stop()


@pytest.mark.parametrize("key_type, file", [("ssh-ed25519", "/etc/ssh/ssh_host_ed25519_key.pub"),
                                            ("ssh-rsa", "/etc/ssh/ssh_host_rsa_key.pub"),
                                            ("ecdsa-sha2-nistp256", "/etc/ssh/ssh_host_ecdsa_key.pub"),
                                            ("ecdsa-sha2-nistp521", "/etc/ssh/ssh_host_ecdsa_key.pub")])
def test_the_key_file_named_is_where_openssh_keeps_a_key_of_that_type(key_type, file):
    assert key_file(_line(asyncssh.generate_private_key(key_type))) == file


def test_the_fingerprint_is_what_ssh_keygen_prints(tmp_path):
    key = asyncssh.generate_private_key("ssh-ed25519")
    line = key.export_public_key("openssh").decode()
    algorithm, shown = fingerprint(line).split(" ")
    assert algorithm == "ssh-ed25519" and shown.startswith("SHA256:")
    if shutil.which("ssh-keygen") is None:
        pytest.skip("ssh-keygen is not installed")
    (tmp_path / "k.pub").write_text(line)
    printed = subprocess.run(["ssh-keygen", "-lf", str(tmp_path / "k.pub")], capture_output=True, text=True).stdout
    assert printed.split()[1] == shown


async def test_a_name_that_does_not_resolve_says_so(world):
    with pytest.raises(LoginRefused) as exc:
        await world.enrollment.host_key("no-such-host.invalid")
    assert "cannot find no-such-host.invalid" in exc.value.message and "avahi-daemon" in exc.value.message


async def test_a_port_nothing_answers_on_says_so(world):
    with socket.socket() as spare:
        spare.bind(("127.0.0.1", 0))
        world.enrollment.port = spare.getsockname()[1]
    with pytest.raises(LoginRefused) as exc:
        await world.enrollment.host_key("127.0.0.1")
    assert f"nothing answers SSH at 127.0.0.1, port {world.enrollment.port}" in exc.value.message


@contextlib.asynccontextmanager
async def _plain_server(banner):
    async def handle(reader, writer):
        if banner:
            await reader.read(1)  # as a web server reads the request, so the close is not a reset
            writer.write(banner)
            await writer.drain()
            writer.close()
        else:
            await reader.read()  # silent until the client gives up
    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    try:
        yield server.sockets[0].getsockname()[1]
    finally:
        server.close()


async def test_a_server_that_is_not_ssh_says_so(world):
    async with _plain_server(b"HTTP/1.0 200 OK\r\n\r\nhello") as port:
        world.enrollment.port = port
        with pytest.raises(LoginRefused) as exc:
            await world.enrollment.host_key("127.0.0.1")
    assert "did not answer as an SSH server" in exc.value.message


async def test_a_server_that_does_not_answer_in_time_says_so(world):
    world.enrollment.connect_seconds = 0.5
    async with _plain_server(None) as port:
        world.enrollment.port = port
        with pytest.raises(LoginRefused) as exc:
            await world.enrollment.host_key("127.0.0.1")
    assert "127.0.0.1 did not answer within 0.5 seconds" in exc.value.message


# --- the password goes only to the key shown, and nervus lends nothing ----------------------

async def test_the_password_goes_only_to_the_key_shown(world):
    impostor = Playing()  # at the address used, with another key
    await impostor.start()
    try:
        world.enrollment.port = impostor.port
        run, *_ = await world.enroll()
        assert "now answers with another key than the one shown, so nervus sent it no password" in run.outcome
        assert impostor.connections >= 1  # it was reached; it was never given anything
        assert impostor.passwords == [] and impostor.usernames == [] and impostor.offered == []
        assert impostor.commands == [] and world.playing.connections == 0 and not run.enrolled
    finally:
        await impostor.stop()


async def test_a_server_with_another_kind_of_key_is_given_no_password_either(world):
    """asyncssh offers only the pinned key's type, so such a server fails the key exchange before any login; the owner
    is told it as another key (ADR-0026 question 8)."""
    impostor = Playing(key_type="ssh-rsa")
    await impostor.start()
    try:
        world.enrollment.port = impostor.port
        run, *_ = await world.enroll()
        assert impostor.passwords == [] and impostor.usernames == [] and impostor.offered == []
        assert impostor.commands == [] and not run.enrolled
        assert "now answers with another key than the one shown, so nervus sent it no password" in run.outcome
    finally:
        await impostor.stop()


async def test_nervus_lends_nothing_of_its_own_account(world, tmp_path, monkeypatch):
    ssh_dir = world.home / ".ssh"
    ssh_dir.mkdir()
    mine = asyncssh.generate_private_key("ssh-ed25519")
    (ssh_dir / "id_ed25519").write_bytes(mine.export_private_key())
    (ssh_dir / "id_ed25519").chmod(0o600)
    world.playing.accepts = mine  # the machine would take it, if nervus offered it
    ran = tmp_path / "proxy-command-ran"
    (ssh_dir / "config").write_text(
        f"Host *\n  User attacker\n  Port 1\n  ProxyCommand sh -c 'echo ran > {ran}; exit 1'\n")
    agent_asked = []
    sockets = Path(tempfile.mkdtemp(prefix="nv"))
    agent = await asyncio.start_unix_server(lambda r, w: (agent_asked.append(1), w.close()), path=str(sockets / "a"))
    monkeypatch.setenv("SSH_AUTH_SOCK", str(sockets / "a"))
    try:
        shown = await world.enrollment.host_key("127.0.0.1")
        run, *_ = await world.enroll(judged="enrolled web, standard")
    finally:
        agent.close()
        shutil.rmtree(sockets, ignore_errors=True)
    assert shown == world.host_key and run.enrolled, run.outcome
    assert world.playing.offered == [] and agent_asked == [] and not ran.exists()
    assert world.playing.usernames == [ACCOUNT] and world.playing.passwords == [(ACCOUNT, PASSWORD)]


@pytest.mark.parametrize("methods", [("password",), ("keyboard-interactive",)])
async def test_either_way_the_machine_takes_a_password_it_gets_one(world, methods):
    world.playing.methods = methods
    run, *_ = await world.enroll(judged="enrolled web, standard")
    assert run.enrolled, run.outcome
    assert {p for _, p in world.playing.passwords} == {PASSWORD}


# --- becoming root --------------------------------------------------------------------------

async def test_root_runs_the_two_lines_without_sudo_and_curl_is_given_exactly_the_pin_and_the_url(world):
    world.playing.account = "root"
    world.stand.play(root=True)
    run, value, _ = await world.enroll(login="root", judged="enrolled web, standard")
    assert run.enrolled, run.outcome
    assert "root is root" in run.lines and world.stand.sudo_called() is None
    args = world.stand.curl_args()
    assert args[:3] == ["-fsSk", "--pinnedpubkey", PIN] and args[3] == "-o" and args[5] == _url(value)
    assert len(args) == 6 and args[4]


async def test_an_account_with_sudo_runs_the_two_lines_through_it_with_its_password_on_standard_input(world):
    run, value, _ = await world.enroll(judged="enrolled web, standard")
    assert run.enrolled and f"{ACCOUNT} can use sudo" in run.lines, run.outcome
    called = world.stand.sudo_called()  # the second call: the stand-in compared the line it read with the password
    assert called[:5] == ["-S", "-p", "", "sh", "-c"] and called[5] == root_command(_url(value), PIN, SHOWN)
    assert world.stand.curl_args()[5] == _url(value)


@pytest.mark.parametrize("sudo, play, says", [
    ("password", dict(sudo_password="another password"), "cannot use sudo with that password (sudo said: Sorry, try again.)"),
    ("denied", {}, "cannot use sudo with that password (sudo said: alice is not in the sudoers file.)"),
    ("missing", {}, "alice is not root, and this machine has no sudo: give root's login, or add it with the two lines"),
])
async def test_a_failed_sudo_stops_before_curl_runs_saying_which(world, sudo, play, says):
    world.stand.play(sudo=sudo, **play)
    run, _, code = await world.enroll()
    assert says in run.outcome and not run.enrolled and world.stand.curl_args() is None
    assert world.codes.get(code.id).outcome == run.outcome


async def test_whatever_sudo_leaves_unread_on_standard_input_reaches_nothing_the_script_runs(world):
    world.stand.play(sudo="passwordless")  # sudo asks for nothing, so the password is left on standard input
    world.stand.script("echo \"nervus: the script's standard input was [$(cat)]\"\n")
    run, *_ = await world.enroll(judged="enrolled web, standard")
    assert "the script's standard input was []" in run.lines and PASSWORD not in " ".join(run.lines)


# --- a login that fails ----------------------------------------------------------------------

async def test_a_wrong_password_says_so_and_nothing_runs(world):
    run, *_ = await world.enroll(password="not it")
    assert run.outcome == "127.0.0.1 refused alice with that password." and not run.enrolled
    assert {p for _, p in world.playing.passwords} == {"not it"}
    assert world.playing.commands == [] and world.stand.curl_args() is None


async def test_a_server_that_takes_only_keys_says_so_without_a_password_going_anywhere(world):
    world.playing.methods = ("publickey",)
    run, *_ = await world.enroll()
    assert run.outcome == "127.0.0.1 takes no password for alice, only keys, so nervus cannot log in. Add it with the two lines (Advanced)."
    assert world.playing.passwords == [] and world.playing.commands == []


async def test_root_refused_says_so(world):
    run, *_ = await world.enroll(login="root")  # the machine takes alice's password, not root's
    assert "127.0.0.1 refused root with that password" in run.outcome and "PermitRootLogin" in run.outcome
    assert "use an account that can use sudo" in run.outcome and world.playing.commands == []


# --- the password is never kept -------------------------------------------------------------

async def test_the_password_is_in_nothing_nervus_keeps_after_a_run_that_enrolls(world, capsys):
    world.stand.script("echo \"nervus: the machine echoed $(printf %s '" + PASSWORD + "')\"\n"
                       "echo \"an ordinary line that holds " + PASSWORD + "\"\n" + OK_SCRIPT)
    run, *_ = await world.enroll(judged="enrolled web, standard")
    assert run.enrolled and "the machine echoed <password>" in run.lines
    stored = world.stored()
    assert b"alice" in stored["database"] + stored["database-wal"] and b"alice" in stored["audit"]
    _nowhere(world, [run], capsys)


async def test_the_password_is_in_nothing_nervus_keeps_after_a_run_that_fails(world, capsys):
    world.stand.play(sudo="echo")  # sudo prints what it read to its errors
    run, *_ = await world.enroll()
    assert "sudo said: sudo: no, <password>" in run.outcome and not run.enrolled
    _nowhere(world, [run], capsys)


async def test_the_code_is_not_in_nervus_log_where_asyncssh_names_the_command_it_runs(world, caplog):
    """Found by procedure 041: asyncssh logs each command at INFO, and the one a run sends the machine holds the code
    in its URL; nervus's journal held it until the run ended. Shown with asyncssh's own logger, as the journal has it."""
    caplog.set_level(logging.INFO, logger="asyncssh")
    run, value, _ = await world.enroll(judged="enrolled web, standard")
    assert run.enrolled, run.outcome
    commands = [r.getMessage() for r in caplog.records if r.name == "asyncssh" and "Command:" in r.getMessage()]
    assert any("/enroll/<code>" in line for line in commands), commands  # the line is there, the code is not
    assert value not in caplog.text and PASSWORD not in caplog.text


def test_only_a_code_is_hidden_in_ssh_log_lines():
    record = logging.LogRecord("asyncssh", logging.INFO, "x", 1, "[conn=1]   Command: %s %s",
                               ("curl https://h:8000/enroll/AbC-d_9 -o x", 42), None)
    HideCodesInSSHLog().filter(record)
    assert record.getMessage() == "[conn=1]   Command: curl https://h:8000/enroll/<code> -o x 42"
    plain = logging.LogRecord("asyncssh", logging.INFO, "x", 1, "Opened channel to %s", ("enroll host",), None)
    HideCodesInSSHLog().filter(plain)
    assert plain.getMessage() == "Opened channel to enroll host"


async def test_a_run_that_nervus_itself_fails_is_told_without_the_password_and_ends_the_code(world, capsys):
    async def broken(*args, **kwargs):
        raise RuntimeError(f"boom {PASSWORD}")
    world.enrollment._become_root = broken
    run, value, code = await world.enroll()
    assert run.outcome == "nervus failed (RuntimeError)" and run.done and not run.enrolled
    assert world.codes.find(value) is None and world.codes.get(code.id).outcome == run.outcome
    assert world.records[-1]["phase"] == "result" and world.records[-1]["outcome"] == run.outcome
    _nowhere(world, [run], capsys, secret=PASSWORD)


async def test_the_standard_error_of_a_failure_names_it_without_the_password(world, capsys):
    async def broken(*args, **kwargs):
        raise RuntimeError(f"boom {PASSWORD}")
    world.enrollment._become_root = broken
    await world.enroll()
    printed = capsys.readouterr().err
    assert "RuntimeError" in printed and "boom <password>" in printed and PASSWORD not in printed


async def test_a_word_from_the_route_that_holds_the_password_is_shown_without_it(world):
    """The last line of defence: whatever the outcome is made from, the run shows it scrubbed."""
    run, *_ = await world.enroll(judged=f"refused: the machine said {PASSWORD}")
    assert run.outcome == "refused: the machine said <password>" and not run.enrolled
    assert PASSWORD not in repr(run)


async def test_a_password_straddling_the_cut_of_a_long_line_is_not_left_in_pieces(world):
    before = LINE_CHARS - 3 - len("nervus: ")  # so the password begins three characters before the line is cut
    world.stand.script(f"echo \"nervus: $(head -c {before} /dev/zero | tr '\\0' x){PASSWORD}tail\"\n")
    run, *_ = await world.enroll(judged="enrolled web, standard")
    long = [l for l in run.lines if l.startswith("x" * 50)]
    assert long and len(long[0]) <= LINE_CHARS and PASSWORD[:3] not in long[0][-30:] and PASSWORD not in long[0]
    assert long[0] == "x" * before + "<pa"  # the password replaced, then the line cut: no piece of it left


async def test_a_machine_cannot_fill_nervus_with_one_endless_line(world):
    world.stand.script("head -c 3000000 /dev/zero | tr '\\0' x; echo\n"
                       "echo 'nervus: the long line ended'\n")
    run, *_ = await world.enroll(judged="enrolled web, standard")
    assert run.enrolled and "the long line ended" in run.lines
    assert all(len(line) <= LINE_CHARS for line in run.lines)


async def test_no_more_than_the_most_lines_are_kept_and_the_outcome_is_still_the_routes(world):
    world.stand.script("i=0; while [ $i -lt 300 ]; do echo \"nervus: step $i\"; i=$((i + 1)); done\n")
    run, *_ = await world.enroll(judged="enrolled web, standard")
    assert len(run.lines) == MAX_LINES and run.enrolled


async def test_a_password_that_holds_a_line_break_is_refused_before_anything_is_attempted(world):
    run, *_ = await world.enroll(password="one\ntwo")
    assert "cannot hold a line break" in run.outcome and world.playing.connections == 0


async def test_asking_which_methods_a_server_takes_lends_nothing_either(world, tmp_path):
    ssh_dir = world.home / ".ssh"
    ssh_dir.mkdir()
    ran = tmp_path / "proxy-command-ran"
    (ssh_dir / "config").write_text(f"Host *\n  ProxyCommand sh -c 'echo ran > {ran}; exit 1'\n")
    world.playing.methods = ("publickey",)  # a login is refused, so nervus asks what the server takes
    run, *_ = await world.enroll()
    assert "takes no password for alice, only keys" in run.outcome and not ran.exists()


async def test_the_login_is_made_with_only_the_password_and_the_key_shown(world, monkeypatch):
    """What a server cannot show: Kerberos and host-based logins are off, and nothing but the password
    methods is tried, by the arguments asyncssh is given."""
    seen, real = [], host_login.asyncssh.connect
    monkeypatch.setattr(host_login.asyncssh, "connect", lambda *a, **kw: (seen.append(kw), real(*a, **kw))[1])
    run, *_ = await world.enroll(judged="enrolled web, standard")
    kw, = seen
    assert run.enrolled
    assert kw["client_keys"] is None and kw["agent_path"] is None and kw["config"] is None
    assert kw["gss_auth"] is False and kw["host_based_auth"] is False
    assert kw["preferred_auth"] == "keyboard-interactive,password" and kw["known_hosts"] is not None


async def _closed(playing):
    for _ in range(40):
        if playing.closed >= playing.connections:
            return True
        await asyncio.sleep(0.05)
    return False


async def test_the_connection_is_closed_however_the_run_ends(world):
    run, *_ = await world.enroll(judged="enrolled web, standard")
    assert run.enrolled and world.playing.connections == 1 and await _closed(world.playing)
    await world.enroll(password="not it")  # a refused login, then asking which methods: no connection left open
    assert await _closed(world.playing)
    world.stand.play(sudo="denied")
    await world.enroll()
    assert await _closed(world.playing)


async def test_the_connection_is_closed_when_a_run_is_stopped_for_its_time(world):
    world.enrollment.run_seconds = 1
    world.stand.script(f"i=0; while [ $i -lt 40 ] && [ ! -e {shlex.quote(str(world.stand.gate))} ]; do "
                       "sleep 0.1; i=$((i + 1)); done\n")
    run, *_ = await world.enroll()
    assert run.outcome.startswith("did not finish") and await _closed(world.playing)


# --- the lines of what a machine prints -------------------------------------------------------

class _Reader:
    def __init__(self, *chunks, endless=None):
        self.chunks, self.endless, self.reads = list(chunks), endless, 0

    async def read(self, n):
        self.reads += 1
        await asyncio.sleep(0)  # a real read waits for data, so a loop that never stops can be timed out
        if self.chunks:
            return self.chunks.pop(0)
        return self.endless if self.endless is not None else ""


async def _all(reader, keep=20):
    return [line async for line in _lines(reader, keep)]


@pytest.mark.parametrize("chunks, lines", [
    (["one\ntwo\n"], ["one", "two"]),
    (["on", "e\nt", "wo\n"], ["one", "two"]),  # a line split between reads
    (["one\r\ntwo"], ["one", "two"]),  # CRLF, and a last line with no end
    (["a" * 30 + "\nnext\n"], ["a" * 20, "next"]),  # a long line cut, the next intact
    (["a" * 25, "b" * 25, "\nnext\n"], ["a" * 20, "next"]),  # the rest of a long line dropped
    (["", ], []),
])
async def test_lines_are_cut_whole_from_pieces(chunks, lines):
    assert await _all(_Reader(*chunks)) == lines


async def test_a_line_without_an_end_is_given_up_at_its_size_not_waited_for():
    reader = _Reader(endless="x" * 4096)
    lines = _lines(reader, 100)
    first = await asyncio.wait_for(anext(lines), 5)  # a clean failure, not a wait for ever, if it is waited for
    assert first == "x" * 100 and reader.reads == 1  # not read to the end of an endless stream
    await lines.aclose()


# --- what is recorded -----------------------------------------------------------------------

async def test_the_login_is_recorded_before_nervus_connects_with_the_account_and_the_fingerprint_only(world):
    world.playing.watch = world.audit_path.read_text
    run, _, code = await world.enroll(judged="enrolled web, standard")
    assert run.enrolled
    before = [json.loads(line) for line in world.playing.seen_at_connect[0].splitlines()]
    intent = before[-1]
    assert (intent["phase"], intent["tool"], intent["actor"], intent["action"]) == ("intent", "enroll", "operator",
                                                                                    "login")
    assert (intent["code_id"], intent["name"], intent["address"], intent["level"], intent["login"]) == (
        code.id, "web", "127.0.0.1", "standard", ACCOUNT)
    assert intent["host_key"] == fingerprint(world.host_key) and PASSWORD not in json.dumps(intent)
    result = world.records[-1]
    assert (result["phase"], result["id"]) == ("result", intent["id"])
    assert result["enrolled"] is True and result["outcome"] == "enrolled web, standard" and result["exit_status"] == 0


# --- what a run shows ------------------------------------------------------------------------

async def test_the_scripts_step_lines_appear_in_the_run_as_they_come_before_it_ends(world):
    world.stand.script("echo 'nervus enrollment: installing bubblewrap'\n"
                       f"while [ ! -e {shlex.quote(str(world.stand.gate))} ]; do sleep 0.1; done\n"
                       "echo 'nervus enrollment: agent has nervus key'\n")
    run = world.start(world.make())
    for _ in range(100):
        if "installing bubblewrap" in run.lines:
            break
        await asyncio.sleep(0.1)
    assert "installing bubblewrap" in run.lines and not run.done and "agent has nervus key" not in run.lines
    assert run.lines[:3] == [f"connecting to 127.0.0.1 as {ACCOUNT}, trusting only the key {run.fingerprint}",
                             f"logged in as {ACCOUNT}", f"{ACCOUNT} can use sudo"]
    world.stand.gate.touch()
    await world.enrollment.finished()
    assert run.done and "agent has nervus key" in run.lines and run.lines[-1] == "agent has nervus key"


async def test_a_machine_without_curl_shows_installing_curl_among_its_steps_and_enrolls(world, monkeypatch):
    world.stand.no_curl()
    monkeypatch.setenv("PATH", world.stand.only)
    run, _, _ = await world.enroll()
    assert "installing curl" in run.lines, run.lines
    assert run.lines.index("installing curl") < len(run.lines) - 1  # then the script's own steps
    assert "could not reach nervus" not in run.outcome


async def test_a_machine_without_curl_or_apt_get_is_told_that_not_that_nervus_is_out_of_reach(world, monkeypatch):
    world.stand.no_curl(apt="missing")
    monkeypatch.setenv("PATH", world.stand.only)
    run, _, _ = await world.enroll()
    assert run.outcome == ("this machine has no curl, which fetches nervus's script, and no apt-get to install it "
                           "with: install curl, then add the machine again. Nothing here was changed")
    assert not run.enrolled


async def test_a_machine_that_cannot_reach_nervus_says_so_naming_the_url_without_its_code(world):
    world.stand.curl(reachable=False)
    run, value, _ = await world.enroll()
    assert run.outcome == "this machine could not reach nervus at https://nervus.example:8000/enroll/<code>, so nothing here was changed"
    assert value not in run.outcome and not run.enrolled


@pytest.mark.parametrize("judged, script, enrolled, outcome", [
    ("enrolled web, standard", "exit 0\n", True, "enrolled web, standard"),
    ("refused: nope", "exit 1\n", False, "refused: nope"),
    ("enrolled web, standard", "exit 3\n", False, "enrolled web, standard"),  # said enrolled, but the script failed
    (None, "echo 'nervus enrollment: apt-get could not install tmux' >&2\nexit 1\n", False,
     "apt-get could not install tmux"),
    (None, "echo 'something odd'\necho 'then something stranger'\nexit 1\n", False, "then something stranger"),
    (None, "exit 3\n", False, "the script ended with status 3"),
])
async def test_the_routes_word_is_the_outcome(world, judged, script, enrolled, outcome):
    world.stand.script(script)
    run, _, code = await world.enroll(judged=judged)
    assert run.enrolled is enrolled and run.outcome == outcome
    assert world.codes.get(code.id).outcome == outcome and run.done and run.finished_at >= run.started_at


async def test_only_the_last_lines_of_other_output_are_kept_for_a_failure(world):
    world.stand.script(f"i=0; while [ $i -lt {TAIL_LINES + 30} ]; do echo \"line $i\"; i=$((i + 1)); done\nexit 1\n")
    run, *_ = await world.enroll()
    assert run.outcome == f"line {TAIL_LINES + 29}" and not any(l.startswith("line ") for l in run.lines)


async def test_only_the_last_lines_of_other_output_are_held_in_memory(world, monkeypatch):
    """The tail is used for its last line only, so its size is a bound on memory and shows nowhere else."""
    held = []

    class Spy(host_login.deque):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            held.append(self)
    monkeypatch.setattr(host_login, "deque", Spy)
    world.stand.script(f"i=0; while [ $i -lt {TAIL_LINES * 5} ]; do echo \"line $i\"; i=$((i + 1)); done\nexit 1\n")
    run, *_ = await world.enroll()
    assert held and max(len(tail) for tail in held) == TAIL_LINES and run.outcome == f"line {TAIL_LINES * 5 - 1}"


async def test_a_machine_cannot_say_it_is_enrolled_by_what_it_prints(world):
    """Only the route's word, and the script's exit status, make a machine enrolled."""
    world.stand.script("echo \"nervus: web is enrolled, standard.\"\necho 'nervus enrollment: enrolled web, standard' >&2\n")
    run, *_ = await world.enroll()  # the route said nothing
    assert not run.enrolled and "web is enrolled, standard." in run.lines
    assert run.outcome == "enrolled web, standard"  # what the script printed, as the last word it wrote
    world.stand.script("exit 0\n")
    claimed, *_ = await world.enroll(judged="refused: not so")
    assert not claimed.enrolled and claimed.outcome == "refused: not so"


# --- the code dies with the run ---------------------------------------------------------------

@pytest.mark.parametrize("judged, script", [("enrolled web, standard", "exit 0\n"), ("refused: no", "exit 1\n"),
                                            (None, "exit 1\n")])
async def test_the_code_dies_with_the_run(world, judged, script):
    world.stand.script(script)
    value, code = world.make()
    if judged:
        world.codes.finish(code.id, judged)
    assert world.codes.find(value) is not None  # unspent and in time until the run ends
    world.start((value, code))
    await world.enrollment.finished()
    assert world.codes.find(value) is None and world.codes.spend(value) is None


async def test_a_run_longer_than_its_time_is_stopped_and_the_code_dies_with_it(world):
    world.enrollment.run_seconds = 1
    world.stand.script(f"i=0; while [ $i -lt 40 ] && [ ! -e {shlex.quote(str(world.stand.gate))} ]; do "
                       "sleep 0.1; i=$((i + 1)); done\n")
    value, code = made = world.make()
    run = world.start(made)
    await world.enrollment.finished()
    assert run.outcome.startswith("did not finish within ") and "the code no longer works" in run.outcome
    assert run.done and not run.enrolled and world.codes.find(value) is None
    assert world.codes.get(code.id).outcome == run.outcome
    assert world.records[-1]["phase"] == "result" and world.records[-1]["outcome"] == run.outcome


async def test_a_failed_login_ends_the_code_too(world):
    value, code = made = world.make()
    world.start(made, password="not it")
    await world.enrollment.finished()
    assert world.codes.find(value) is None and "refused alice" in world.codes.get(code.id).outcome


# --- what is attempted at all -------------------------------------------------------------------

async def test_without_an_audit_log_the_machine_sees_no_connection(world, tmp_path):
    world.enrollment.audit = AuditLog(path=tmp_path / "no-such-folder" / "audit.jsonl")
    run, value, _ = await world.enroll()
    assert run.outcome == "nervus cannot write its audit log, so it did nothing" and not run.enrolled
    assert world.playing.connections == 0 and world.codes.find(value) is None


async def test_in_lockdown_the_machine_sees_no_connection_and_the_refusal_is_recorded(world):
    world.enrollment.locked = lambda: True
    run, value, _ = await world.enroll()
    assert run.outcome == "nervus is locked down, so it enrolls nothing" and world.playing.connections == 0
    assert world.codes.find(value) is None
    refusal, = world.records
    assert (refusal["phase"], refusal["tool"], refusal["reason"], refusal["login"]) == ("refused", "enroll", "lockdown",
                                                                                         ACCOUNT)
    assert PASSWORD not in json.dumps(refusal)


@pytest.mark.parametrize("pin", [None, "", "sha256//short", "not-a-pin"])
async def test_without_an_https_key_to_pin_the_machine_sees_no_connection(world, pin):
    run, value, _ = await world.enroll(pin=pin)
    assert "no HTTPS key to pin" in run.outcome and world.playing.connections == 0 and world.codes.find(value) is None
    assert world.records[-1]["reason"] == "plain HTTP"


# --- the runs ----------------------------------------------------------------------------------

async def test_a_run_that_finished_more_than_an_hour_ago_is_forgotten(world):
    first, *_ = await world.enroll(name="one")
    assert world.enrollment.get(first.code_id) is first
    first.finished_at = time.time() - KEEP_SECONDS - 1
    second, *_ = await world.enroll(name="two")
    assert world.enrollment.get(first.code_id) is None and world.enrollment.get(second.code_id) is second


async def test_a_run_that_is_still_going_is_kept_whatever_its_age(world):
    world.stand.script(f"while [ ! -e {shlex.quote(str(world.stand.gate))} ]; do sleep 0.1; done\n")
    going = world.start(world.make(name="going"))
    going.started_at -= 10 * KEEP_SECONDS
    world.start(world.make(name="later"))
    assert world.enrollment.get(going.code_id) is going and not going.done
    world.stand.gate.touch()


# --- the two lines as nervus runs them, in real shells ------------------------------------------

SHELLS = [shell for shell in ("sh", "dash", "bash") if shutil.which(shell)]
ODD_URL = "https://nervus.example:8000/enroll/it's \"x\" $y `z` ; (w)"
ODD_SHOWN = "https://nervus.example:8000/enroll/<code> it's \"x\" $y `z`"


def _run_root(stand, shell, tmp_path, *, url=_url("C0DE"), shown=SHOWN, stdin="a line left on standard input\n"):
    return subprocess.run([shell, "-c", root_command(url, PIN, shown)], input=stdin, capture_output=True, text=True,
                          env={"PATH": stand.path, "TMPDIR": str(tmp_path)}, timeout=30)


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("status", [0, 1, 3])
def test_the_scripts_exit_status_passes_through_unchanged(tmp_path, shell, status):
    stand = Standins(tmp_path)
    stand.script(f"exit {status}\n")
    assert _run_root(stand, shell, tmp_path).returncode == status


@pytest.mark.parametrize("shell", SHELLS)
def test_a_line_on_standard_input_never_reaches_the_script(tmp_path, shell):
    stand = Standins(tmp_path)
    stand.script("echo \"stdin was [$(cat)]\"\n")
    done = _run_root(stand, shell, tmp_path)
    assert done.stdout == "stdin was []\n"


@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("script, reachable", [("exit 0\n", True), ("exit 1\n", True), ("exit 0\n", False)])
def test_the_temporary_copy_is_gone_afterwards_when_the_script_succeeds_fails_and_the_fetch_fails(
        tmp_path, shell, script, reachable):
    stand = Standins(tmp_path)
    stand.script(script)
    stand.curl(reachable=reachable)
    _run_root(stand, shell, tmp_path)
    copy = Path(stand.curl_args()[4])  # the file curl was told to write: made by mktemp, wherever that puts it
    assert copy.name and not copy.exists()


@pytest.mark.parametrize("shell", SHELLS)
def test_a_failed_fetch_says_so_naming_the_url_without_its_code_and_runs_nothing(tmp_path, shell):
    stand = Standins(tmp_path)
    stand.script("echo the script ran\n")
    stand.curl(reachable=False)
    done = _run_root(stand, shell, tmp_path)
    assert done.returncode == 1 and "the script ran" not in done.stdout
    assert done.stderr == ("nervus enrollment: this machine could not reach nervus at "
                           "https://nervus.example:8000/enroll/<code>, so nothing here was changed\n")


@pytest.mark.parametrize("shell", SHELLS)
def test_values_holding_quotes_reach_curl_exactly(tmp_path, shell):
    stand = Standins(tmp_path)
    stand.curl(reachable=False)
    done = _run_root(stand, shell, tmp_path, url=ODD_URL, shown=ODD_SHOWN)
    args = stand.curl_args()
    assert args[:3] == ["-fsSk", "--pinnedpubkey", PIN] and args[5] == ODD_URL and len(args) == 6
    assert done.stderr == f"nervus enrollment: this machine could not reach nervus at {ODD_SHOWN}, so nothing here was changed\n"


def _run_root_without_curl(stand, shell, tmp_path, stdin="a line left on standard input\n"):
    return subprocess.run([shutil.which(shell), "-c", root_command(_url("C0DE"), PIN, SHOWN)], input=stdin,
                          capture_output=True, text=True, env={"PATH": stand.only, "TMPDIR": str(tmp_path)}, timeout=30)


@pytest.mark.parametrize("shell", SHELLS)
def test_a_machine_without_curl_is_given_it_by_apt_get_and_then_runs_the_two_lines(tmp_path, shell):
    # ADR-0026 question 10. Such a machine was told "this machine could not reach nervus": true, and not
    # the cause. nervus is root there, and its script installs tmux the same way.
    stand = Standins(tmp_path)
    stand.script("echo the script ran\n")
    stand.no_curl()
    done = _run_root_without_curl(stand, shell, tmp_path)
    assert done.returncode == 0, done.stderr
    assert done.stdout == "nervus enrollment: installing curl\nthe script ran\n"
    # As the script installs tmux: the lists first, nothing asked, and nothing of standard input reaches apt-get.
    assert stand.apt_called() == ["noninteractive apt-get update -q []", "noninteractive apt-get install -y -q curl []"]
    assert stand.curl_args()[:3] == ["-fsSk", "--pinnedpubkey", PIN]


@pytest.mark.parametrize("shell", SHELLS)
def test_a_machine_with_curl_is_asked_nothing_of_apt_get(tmp_path, shell):
    stand = Standins(tmp_path)
    stand.script("echo the script ran\n")
    calls = tmp_path / "apt-calls"
    stand._exe("apt-get", f'echo called >> {calls}\n')
    done = _run_root(stand, shell, tmp_path)
    assert done.returncode == 0 and done.stdout == "the script ran\n" and not calls.exists()


@pytest.mark.parametrize("shell", SHELLS)
def test_without_curl_or_apt_get_it_says_so_and_changes_nothing(tmp_path, shell):
    stand = Standins(tmp_path)
    stand.script("echo the script ran\n")
    stand.no_curl(apt="missing")
    done = _run_root_without_curl(stand, shell, tmp_path)
    assert done.returncode == 1 and done.stdout == ""
    assert done.stderr == ("nervus enrollment: this machine has no curl, which fetches nervus's script, and no "
                           "apt-get to install it with: install curl, then add the machine again. Nothing here "
                           "was changed\n")


@pytest.mark.parametrize("shell", SHELLS)
def test_a_curl_that_apt_get_cannot_install_says_so_and_runs_nothing(tmp_path, shell):
    stand = Standins(tmp_path)
    stand.script("echo the script ran\n")
    stand.no_curl(apt="fails")
    done = _run_root_without_curl(stand, shell, tmp_path)
    assert done.returncode == 1 and "the script ran" not in done.stdout
    assert done.stderr.splitlines()[-1] == ("nervus enrollment: apt-get could not install curl, which fetches "
                                            "nervus's script: install it, then add the machine again")
    assert "could not reach nervus" not in done.stderr


def test_the_command_nervus_runs_is_the_two_lines_as_the_adr_gives_them():
    pin_arg = shlex.quote(PIN)
    assert root_command("https://h/e/C0DE", PIN, "https://h/e/<code>") == (
        "if ! command -v curl >/dev/null 2>&1; then "
        "command -v apt-get >/dev/null 2>&1 || { echo 'nervus enrollment: this machine has no curl, which fetches "
        "nervus'\"'\"'s script, and no apt-get to install it with: install curl, then add the machine again. "
        "Nothing here was changed' >&2; exit 1; }; "
        "echo 'nervus enrollment: installing curl'; "
        "DEBIAN_FRONTEND=noninteractive apt-get update -q </dev/null >/dev/null "
        "&& DEBIAN_FRONTEND=noninteractive apt-get install -y -q curl </dev/null >/dev/null "
        "&& command -v curl >/dev/null 2>&1 "
        "|| { echo 'nervus enrollment: apt-get could not install curl, which fetches nervus'\"'\"'s script: "
        "install it, then add the machine again' >&2; exit 1; }; fi; "
        "t=$(mktemp) || exit 1; trap 'rm -f \"$t\"' EXIT; "
        f"curl -fsSk --pinnedpubkey {pin_arg} -o \"$t\" https://h/e/C0DE "
        "|| { echo 'nervus enrollment: this machine could not reach nervus at https://h/e/<code>, "
        "so nothing here was changed' >&2; exit 1; }; sh \"$t\" </dev/null")
    assert login_command("true", sudo=False) == "sh -c true"
    assert login_command("echo 'a b'", sudo=True) == "sudo -S -p '' sh -c 'echo '\"'\"'a b'\"'\"''"


@pytest.mark.parametrize("pin", ["", "sha256//", "sha256//short=", "md5//abc", "x" * 50])
def test_a_command_is_never_made_without_a_key_to_pin(pin):
    with pytest.raises(ValueError):
        root_command("https://h/e/C0DE", pin, "https://h/e/<code>")
