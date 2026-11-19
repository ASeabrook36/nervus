"""ADR-0025 step 1: the certificate nervus signs for each connection, the CA key
it is signed with, and the port each call records.

The certificate's worth is in what a machine's own `sshd` does with it, so the
tests that matter run a real OpenSSH `sshd`, as this account, on a port of its
own: the line it logs at login, a read-only line's forced command, a window
that has passed, and a machine still on the bare key. They are skipped where
no `sshd` can be started.
"""

import asyncio
import dataclasses
import getpass
import io
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

import asyncssh
import pytest

from nervus import certs, ssh
from nervus.audit import AuditLog
from nervus.certs import WINDOW_SECONDS, Caller, CertificateAuthority
from nervus.config import ConfigError
from nervus.server import build_server

from test_server import GOOD_TOKEN, _call_tool, _content, _settings, _tokens
from test_upload_targets import store  # noqa: F401  the fixture

RUN = "0b9f4c2e-5d1a-4e8b-9c3f-7a6d2e1b0c94"


def _key_file(path: Path, comment: str | None = None) -> Path:
    key = asyncssh.generate_private_key("ssh-ed25519", comment=comment)
    path.write_bytes(key.export_private_key())
    path.chmod(0o600)
    return path


@pytest.fixture
def ca(tmp_path) -> CertificateAuthority:
    return CertificateAuthority(_key_file(tmp_path / "ca"))


@pytest.fixture(autouse=True)
def _no_caller():
    """Each test starts outside any call, as nervus's own tasks do."""
    token = certs._caller.set(None)
    yield
    certs._caller.reset(token)


# --- the certificate --------------------------------------------------------


def test_the_key_id_names_the_token_and_the_run():
    assert Caller("t-good", RUN).key_id() == f"token=t-good run={RUN}"


@pytest.mark.parametrize("token_id", ["has space", "a\nb", "x=y run=forged", "ünï", 'q"uote'])
def test_a_token_id_outside_the_alphabet_cannot_add_words_to_the_line(token_id):
    """Decision 1: nothing in the key ID is anyone's free text. A token file's
    ids are checked by nobody, so one is encoded, never copied in."""
    key_id = Caller(token_id, RUN).key_id()
    assert re.fullmatch(rf"token=[A-Za-z0-9._%-]+ run={RUN}", key_id), key_id


def _read(cert: asyncssh.SSHCertificate, tmp_path: Path) -> str:
    """The certificate as OpenSSH's own ssh-keygen reads it."""
    path = tmp_path / "nervus-cert.pub"
    path.write_bytes(cert.export_certificate())
    return subprocess.run(["ssh-keygen", "-L", "-f", str(path)], capture_output=True, text=True, check=True).stdout


def test_the_certificate_is_for_one_account_one_window_and_nothing_else(ca, tmp_path):
    key = asyncssh.generate_private_key("ssh-ed25519")
    now = 1_800_000_000
    text = _read(ca.sign(key, "agent", Caller("t-good", RUN), now=now), tmp_path)

    assert f'Key ID: "token=t-good run={RUN}"' in text
    assert re.search(r"Principals:\s*\n\s*agent\s*\n\s*Critical Options:", text), text
    # Five minutes either side (question 2a), as OpenSSH reads it.
    window = re.search(r"Valid: from (\S+) to (\S+)", text)
    from datetime import datetime
    begin, end = (datetime.fromisoformat(t) for t in window.groups())
    assert (end - begin).total_seconds() == 2 * WINDOW_SECONDS == 600
    # No forced command and no permissions (decision 1): the machine's own line decides.
    assert re.search(r"Critical Options: \(none\)\s*\n\s*Extensions: \(none\)", text), text
    ca_fingerprint = subprocess.run(["ssh-keygen", "-lf", str(ca.path)], capture_output=True, text=True,
                                    check=True).stdout.split()[1]
    assert f"Signing CA: ED25519 {ca_fingerprint}" in text


def test_each_certificate_has_its_own_serial(ca, tmp_path):
    key = asyncssh.generate_private_key("ssh-ed25519")
    serials = {re.search(r"Serial: (\d+)", _read(ca.sign(key, "agent", Caller("t", RUN)), tmp_path)).group(1)
               for _ in range(10)}
    assert len(serials) == 10


def test_the_ca_key_must_be_private_and_must_be_a_key(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        CertificateAuthority(tmp_path / "absent")
    loose = _key_file(tmp_path / "loose")
    loose.chmod(0o640)
    with pytest.raises(ConfigError, match="0600"):
        CertificateAuthority(loose)
    junk = tmp_path / "junk"
    junk.write_text("not a key")
    junk.chmod(0o600)
    with pytest.raises(ConfigError, match="certificate authority"):
        CertificateAuthority(junk)


async def test_two_calls_at_once_each_keep_their_own_caller():
    async def call(token_id: str) -> str:
        certs.acting_for(token_id, RUN)
        await asyncio.sleep(0.01)
        return certs.current().token_id

    assert await asyncio.gather(call("a"), call("b")) == ["a", "b"]
    assert certs.current() is None


async def test_work_a_call_starts_carries_the_call():
    """An export's copy and an upload's delivery run as tasks of their own."""
    async def current():
        return certs.current()

    caller = certs.acting_for("t-good", RUN)
    assert await asyncio.get_running_loop().create_task(current()) is caller


# --- against an SSH server that trusts only the CA (asyncssh's) -------------


@pytest.fixture
async def ca_server(tmp_path, ca):
    """asyncssh's server, trusting nervus's CA alone: a machine moved to the
    `cert-authority` line."""
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    keys = tmp_path / "ca_server_authorized_keys"
    keys.write_text(f"cert-authority {ca.public_key()}\n")
    seen: list[int] = []

    class Server(asyncssh.SSHServer):
        def connection_made(self, conn):
            seen.append(conn.get_extra_info("peername")[1])

    server = await asyncssh.listen("127.0.0.1", 0, server_host_keys=[host_key], authorized_client_keys=str(keys),
                                   server_factory=Server, process_factory=lambda p: p.exit(0))
    port = server.sockets[0].getsockname()[1]
    known = tmp_path / "ca_server_known_hosts"
    known.write_text(f"[127.0.0.1]:{port} {host_key.export_public_key().decode()}")
    try:
        yield SimpleNamespace(port=port, known=known, key=_key_file(tmp_path / "nervus"), peers=seen)
    finally:
        server.close()
        await server.wait_closed()


async def _connect(server, authority):
    return await ssh.connect(address="127.0.0.1", port=server.port, username="agent",
                             client_keys=[server.key], known_hosts=server.known, authority=authority)


async def test_on_a_call_nervus_logs_in_by_certificate_and_notes_its_port(ca_server, ca):
    caller = certs.acting_for("t-good", RUN)
    conn = await _connect(ca_server, ca)
    conn.close()
    assert caller.ports == ca_server.peers and len(caller.ports) == 1
    assert certs.ssh_ports() == {"ssh_ports": caller.ports}


async def test_what_a_call_did_to_a_vm_on_its_way_goes_with_the_call_to_its_result_record():
    """As its ports do: the work a call starts carries the call, so what it notes reaches the call's record."""
    assert certs.vm_note() == {}
    certs.note("not in a call: kept nowhere")
    assert certs.vm_note() == {}
    caller = certs.acting_for("t-good", RUN)
    certs.note(None)
    certs.note("")
    assert certs.vm_note() == {} and caller.notes == []

    async def work():
        certs.note("VM 123 enrolled, at 192.0.2.7")

    await asyncio.get_running_loop().create_task(work())  # a task of its own, as a copy or a delivery is
    assert certs.vm_note() == {"vm_note": "VM 123 enrolled, at 192.0.2.7"}
    certs.note("VM 124 moved from 192.0.2.8 to 192.0.2.9")
    assert certs.vm_note() == {"vm_note": "VM 123 enrolled, at 192.0.2.7; VM 124 moved from 192.0.2.8 to 192.0.2.9"}
    certs.acting_for("t-other", RUN)  # another call: none of the first's
    assert certs.vm_note() == {}


async def test_outside_a_call_nervus_offers_its_plain_key_alone(ca_server, ca):
    """No call, no certificate: enrollment's check and nervus-ctl are later steps."""
    with pytest.raises(asyncssh.PermissionDenied) as refused:
        await _connect(ca_server, ca)
    assert certs.ssh_ports() == {}
    assert "clock" not in str(refused.value)  # no certificate was offered, so it cannot be the clock


async def test_without_its_ca_nervus_offers_its_plain_key_and_still_notes_the_port(ca_server, ssh_server):
    """Decision 3: the port is recorded even where no certificate is."""
    caller = certs.acting_for("t-good", RUN)
    with pytest.raises(asyncssh.PermissionDenied):
        await _connect(ca_server, None)
    conn = await ssh.connect(address=ssh_server.host, port=ssh_server.port, username=ssh_server.username,
                             client_keys=[ssh_server.client_key_path], known_hosts=ssh_server.known_hosts_path)
    conn.close()
    assert len(caller.ports) == 1


# --- a real OpenSSH sshd ----------------------------------------------------

SSHD = shutil.which("sshd") or ("/usr/sbin/sshd" if os.path.exists("/usr/sbin/sshd") else None)


class Sshd:
    """OpenSSH's sshd as this account, on a free port, logging to a file: what
    a machine's journal holds. Only this account can log in to it."""

    def __init__(self, root: Path, line: str):
        self.root, self.user = root, getpass.getuser()
        root.mkdir()
        self.home = root / "home"
        self.home.mkdir()
        _key_file(root / "host_key")
        self.keys = root / "authorized_keys"
        self.set_line(line)
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        self.port = sock.getsockname()[1]
        sock.close()
        (root / "sshd_config").write_text(
            f"Port {self.port}\nListenAddress 127.0.0.1\nHostKey {root}/host_key\n"
            f"AuthorizedKeysFile {self.keys}\nStrictModes no\nUsePAM no\nPasswordAuthentication no\n"
            f"KbdInteractiveAuthentication no\nPidFile {root}/sshd.pid\nLogLevel INFO\n")
        self.log = root / "journal"
        self.proc = subprocess.Popen([SSHD, "-D", "-e", "-f", str(root / "sshd_config")],
                                     stderr=self.log.open("w"), stdin=subprocess.DEVNULL)
        host_pub = asyncssh.read_private_key(str(root / "host_key")).export_public_key().decode()
        self.known = root / "known_hosts"
        self.known.write_text(f"[127.0.0.1]:{self.port} {host_pub}")
        deadline = time.monotonic() + 10
        while "Server listening" not in self.journal():
            if self.proc.poll() is not None or time.monotonic() > deadline:
                self.stop()
                pytest.skip(f"sshd would not start here: {self.journal()[-300:]}")
            time.sleep(0.05)

    def set_line(self, line: str) -> None:
        self.keys.write_text(line + "\n")
        self.keys.chmod(0o600)

    def journal(self) -> str:
        return self.log.read_text() if self.log.exists() else ""

    def wait_for(self, pattern: str) -> re.Match:
        deadline = time.monotonic() + 5
        while (found := re.search(pattern, self.journal())) is None and time.monotonic() < deadline:
            time.sleep(0.05)
        assert found, self.journal()
        return found

    def stop(self) -> None:
        self.proc.terminate()
        self.proc.wait(timeout=5)


@pytest.fixture
def sshd(tmp_path):
    if SSHD is None:
        pytest.skip("no OpenSSH sshd on this machine")
    started: list[Sshd] = []

    def start(line_for) -> Sshd:
        server = Sshd(tmp_path / f"sshd{len(started)}", "")
        started.append(server)
        server.set_line(line_for(server))
        return server

    yield start
    for server in started:
        server.stop()


def _shell(server: Sshd) -> str:
    """The command nervus's script runs under, with this test's HOME, so
    nothing lands in the home of the account running the tests."""
    return f'command="env HOME={server.home} bash -s"'


async def _login(server: Sshd, key: Path, authority, command: str = "echo hello") -> str:
    conn = await ssh.connect(address="127.0.0.1", port=server.port, username=server.user,
                             client_keys=[key], known_hosts=server.known, authority=authority)
    try:
        # On standard input, as nervus sends its script: the line's command decides what runs.
        return (await conn.run("bash -s", input=command, check=True, timeout=20)).stdout
    finally:
        conn.close()


async def test_the_machine_writes_the_token_and_the_run_into_its_own_log(sshd, ca, tmp_path):
    """Verification 1, as far as one machine: the line is sshd's, written at
    login, and its port is the one the call records."""
    server = sshd(lambda s: f"cert-authority,{_shell(s)} {ca.public_key()}")
    key = _key_file(tmp_path / "nervus")
    caller = certs.acting_for("t-good", RUN)
    assert await _login(server, key, ca, "echo hello") == "hello\n"
    line = server.wait_for(r"Accepted publickey for \S+ from 127\.0\.0\.1 port (\d+) ssh2: ED25519-CERT "
                           r"SHA256:\S+ ID (token=\S+ run=\S+) \(serial \d+\) CA ED25519 SHA256:\S+")
    assert line.group(2) == f"token=t-good run={RUN}"
    assert [int(line.group(1))] == caller.ports


async def test_two_clients_appear_under_their_own_tokens(sshd, ca, tmp_path):
    """Verification 2: one account, one line on the machine, two names in its log."""
    server = sshd(lambda s: f"cert-authority,{_shell(s)} {ca.public_key()}")
    key = _key_file(tmp_path / "nervus")
    for token_id in ("t-one", "t-two"):
        certs.acting_for(token_id, RUN)
        await _login(server, key, ca)
    server.wait_for(rf"ID token=t-one run={RUN} .*\n(.*\n)*.*ID token=t-two run={RUN} ")


async def test_a_read_only_line_keeps_its_forced_command_with_a_certificate(sshd, ca, tmp_path):
    """Verification 4: the certificate carries no forced command, so the
    line's runs; and one that carried another would be refused."""
    server = sshd(lambda s: f'cert-authority,restrict,command="echo read-only" {ca.public_key()}')
    key = _key_file(tmp_path / "nervus")
    certs.acting_for("t-good", RUN)
    assert await _login(server, key, ca, "touch /tmp/should-not-run") == "read-only\n"

    class Forcing:  # a certificate that tries to name its own command
        def __init__(self, authority):
            self.authority = authority

        def sign(self, k, user, caller):
            return self.authority._key.generate_user_certificate(
                k, caller.key_id(), principals=[user], force_command="echo other")

    with pytest.raises(asyncssh.PermissionDenied):
        await ssh.connect(address="127.0.0.1", port=server.port, username=server.user,
                          client_keys=[asyncssh.read_private_key(str(key))], known_hosts=server.known,
                          authority=Forcing(ca))
    server.wait_for("forced command options do not match")


async def test_a_certificate_past_its_window_is_refused(sshd, ca, tmp_path):
    """Verification 5, first half; the clock out by four minutes is the trial's."""
    server = sshd(lambda s: f"cert-authority,{_shell(s)} {ca.public_key()}")
    key = _key_file(tmp_path / "nervus")

    class Stale:
        def sign(self, k, user, caller):
            return ca.sign(k, user, caller, now=time.time() - 2 * WINDOW_SECONDS - 60)

    certs.acting_for("t-good", RUN)
    with pytest.raises(asyncssh.PermissionDenied) as refused:
        await _login(server, key, Stale())
    server.wait_for(r"(?i)expired|not yet valid|outside")
    assert str(refused.value).startswith("Permission denied")
    assert "certificate valid 5 minutes either side of its own clock" in str(refused.value)
    assert "a clock on 127.0.0.1 further than that from nervus's" in str(refused.value)


async def test_a_client_refused_for_the_clock_is_told_the_clock_is_one_cause(sshd, ca, tmp_path, ssh_server):
    """Procedure 042, finding 1: the trial's client saw a bare "Permission
    denied" for a machine whose clock was out, and nothing to act on."""
    server = sshd(lambda s: f"cert-authority,{_shell(s)} {ca.public_key()}")
    key = _key_file(tmp_path / "nervus")

    class Stale:
        path = ca.path

        def sign(self, k, user, caller):
            return ca.sign(k, user, caller, now=time.time() - 2 * WINDOW_SECONDS - 60)

    settings = _settings(tmp_path, ssh_server)
    real = dataclasses.replace(
        settings, ssh_ca=Stale(), ssh_port=server.port, known_hosts_path=server.known, ssh_key_path=key,
        hosts={"testhost": dataclasses.replace(settings.hosts["testhost"], address="127.0.0.1",
                                               agent_user=server.user)})
    mcp_server = build_server(settings=real, tokens=_tokens(), audit=AuditLog(path=real.audit_log_path))

    result = await _call_tool(mcp_server, GOOD_TOKEN, "exec", {"host": "testhost", "command": "echo hi"})
    assert result.is_error
    text = result.content[0].text
    assert "PermissionDenied: Permission denied for user" in text, text
    assert "one cause is a clock on 127.0.0.1 further than that from nervus's" in text, text


async def test_a_machine_still_on_the_bare_key_takes_the_plain_key(sshd, ca, tmp_path):
    """Question 1a and verification 6: a machine not yet moved works as
    before, its log names no client, and the port matches the record."""
    key = _key_file(tmp_path / "nervus")
    pub = asyncssh.read_private_key(str(key)).export_public_key().decode().strip()
    server = sshd(lambda s: f"{_shell(s)} {pub}")
    caller = certs.acting_for("t-good", RUN)
    assert await _login(server, key, ca) == "hello\n"
    line = server.wait_for(r"Accepted publickey for \S+ from 127\.0\.0\.1 port (\d+) ssh2: ED25519 SHA256:")
    assert [int(line.group(1))] == caller.ports
    assert "ID token=" not in server.journal().split("Accepted publickey")[-1].splitlines()[0]


async def test_exec_through_nervus_names_its_run_on_the_machine_and_its_port_in_the_record(
        sshd, ca, tmp_path, ssh_server):
    """The whole path: a client's exec, the intent record's run in the
    machine's log line, and that line's port in the result record."""
    server = sshd(lambda s: f"cert-authority,{_shell(s)} {ca.public_key()}")
    key = _key_file(tmp_path / "nervus")
    settings = _settings(tmp_path, ssh_server)
    real = dataclasses.replace(
        settings, ssh_ca=ca, ssh_port=server.port, known_hosts_path=server.known, ssh_key_path=key,
        hosts={"testhost": dataclasses.replace(settings.hosts["testhost"], address="127.0.0.1",
                                               agent_user=server.user)})
    mcp_server = build_server(settings=real, tokens=_tokens(), audit=AuditLog(path=real.audit_log_path))

    answer = _content(await _call_tool(mcp_server, GOOD_TOKEN, "exec", {"host": "testhost", "command": "echo hi"}))
    assert answer["exit_code"] == 0 and answer["output"] == "hi\n"

    records = [json.loads(line) for line in real.audit_log_path.read_text().splitlines()]
    intent = next(r for r in records if r["tool"] == "exec" and r["phase"] == "intent")
    result = next(r for r in records if r["tool"] == "exec" and r["phase"] == "result")
    line = server.wait_for(r"port (\d+) ssh2: ED25519-CERT \S+ ID token=t-good run=(\S+) ")
    assert line.group(2) == intent["id"] == answer["run_id"]
    assert result["ssh_ports"] == [int(line.group(1))]
    assert intent["command"] == "echo hi"


@pytest.mark.parametrize("tool,arguments", [
    ("exec", {"command": "true"}),
    ("exec_bg", {"command": "true"}),
    ("put", {"local_path": "f.txt", "remote_path": "PLACEHOLDER/out.txt"}),
    ("get", {"remote_path": "PLACEHOLDER/in.txt", "local_path": "g.txt"}),
])
async def test_each_ssh_tool_records_its_port(tool, arguments, tmp_path, ssh_server):
    """Decision 3, on a machine still on the bare key: the result record
    carries the local port of the call's one connection."""
    settings = _settings(tmp_path, ssh_server)
    (settings.transfer_dir / "f.txt").write_text("x")
    (tmp_path / "in.txt").write_text("y")
    arguments = {k: v.replace("PLACEHOLDER", str(tmp_path)) for k, v in arguments.items()}
    mcp_server = build_server(settings=settings, tokens=_tokens(), audit=AuditLog(path=settings.audit_log_path))
    result = await _call_tool(mcp_server, GOOD_TOKEN, tool, {"host": "testhost", **arguments})
    assert not result.is_error, result.content
    records = [json.loads(line) for line in settings.audit_log_path.read_text().splitlines()]
    done = next(r for r in records if r["tool"] == tool and r["phase"] == "result")
    assert len(done["ssh_ports"]) == 1 and 0 < done["ssh_ports"][0] < 65536


# --- step 2: the label line -------------------------------------------------
#
# On a Mac, `logger` writes to the system's own log, which a test cannot read
# back, so a stand-in `logger` first on PATH records what it was given. The
# test SSH server's shell inherits this process's environment. The real
# journal, and the read-only sandbox, are the trial's.


def _stand_in_logger(tmp_path, monkeypatch, body: str) -> Path:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    logger = bin_dir / "logger"
    logger.write_text(f"#!/bin/sh\n{body}\n")
    logger.chmod(0o755)
    record = tmp_path / "logger-calls"
    monkeypatch.setenv("LOGGER_CALLS", str(record))
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    return record


def _recording(tmp_path, monkeypatch) -> Path:
    return _stand_in_logger(tmp_path, monkeypatch, 'printf "%s|" "$@" >> "$LOGGER_CALLS"; echo >> "$LOGGER_CALLS"')


def _records(settings):
    return [json.loads(line) for line in settings.audit_log_path.read_text().splitlines()]


def test_the_label_line_is_nothing_outside_a_call_and_never_fails_the_script():
    assert ssh.label_line(None) == ""
    line = ssh.label_line(f"token=t-good run={RUN}")
    assert line == f"logger -t nervus -- 'token=t-good run={RUN}' >/dev/null 2>&1 || true\n"
    script, _ = ssh.build_exec_script(RUN, "~", "echo hi", f"token=t-good run={RUN}")
    assert script.startswith(line)
    assert ssh.build_exec_script(RUN, "~", "echo hi")[0] == script[len(line):]


async def test_exec_labels_the_machines_journal_and_keeps_the_label_out_of_the_record(
        tmp_path, ssh_server, monkeypatch):
    calls = _recording(tmp_path, monkeypatch)
    settings = _settings(tmp_path, ssh_server)
    mcp_server = build_server(settings=settings, tokens=_tokens(), audit=AuditLog(path=settings.audit_log_path))

    answer = _content(await _call_tool(mcp_server, GOOD_TOKEN, "exec", {"host": "testhost", "command": "echo hi"}))
    intent = next(r for r in _records(settings) if r["tool"] == "exec" and r["phase"] == "intent")
    assert calls.read_text() == f"-t|nervus|--|token=t-good run={intent['id']}|\n"
    # Nothing of the label in the answer, and the record holds the command as sent.
    assert answer["output"] == "hi\n" and answer["exit_code"] == 0
    assert intent["command"] == "echo hi"


async def test_exec_bg_labels_the_journal_as_its_job_starts(tmp_path, ssh_server, monkeypatch):
    if shutil.which("tmux") is None:
        pytest.skip("needs tmux")
    import tempfile
    monkeypatch.setenv("TMUX_TMPDIR", tempfile.mkdtemp(prefix="nt-", dir="/tmp"))  # see test_ctl
    calls = _recording(tmp_path, monkeypatch)
    settings = _settings(tmp_path, ssh_server)
    mcp_server = build_server(settings=settings, tokens=_tokens(), audit=AuditLog(path=settings.audit_log_path))

    answer = _content(await _call_tool(mcp_server, GOOD_TOKEN, "exec_bg", {"host": "testhost", "command": "true"}))
    try:
        intent = next(r for r in _records(settings) if r["tool"] == "exec_bg" and r["phase"] == "intent")
        assert answer["job_id"] == intent["id"]
        assert calls.read_text() == f"-t|nervus|--|token=t-good run={intent['id']}|\n"
        assert intent["command"] == "true"
    finally:
        subprocess.run(["tmux", "kill-server"], capture_output=True)


@pytest.mark.parametrize("command,exit_code,output", [("echo hi", 0, "hi\n"), ("echo no; exit 7", 7, "no\n")])
async def test_a_logger_that_fails_changes_nothing_the_client_sees(
        tmp_path, ssh_server, monkeypatch, command, exit_code, output):
    """No `logger`, or one the sandbox stops: the command runs, and its exit
    code and output are its own."""
    _stand_in_logger(tmp_path, monkeypatch, 'echo "logger: cannot reach the journal" >&2; echo noise; exit 1')
    settings = _settings(tmp_path, ssh_server)
    mcp_server = build_server(settings=settings, tokens=_tokens(), audit=AuditLog(path=settings.audit_log_path))
    answer = _content(await _call_tool(mcp_server, GOOD_TOKEN, "exec", {"host": "testhost", "command": command}))
    assert (answer["exit_code"], answer["output"]) == (exit_code, output)


def test_the_ca_public_line_carries_nothing_but_the_key_and_its_name(tmp_path):
    """What enrollment writes after `cert-authority` (decision 4)."""
    key = asyncssh.generate_private_key("ssh-ed25519", comment="secret-comment")
    path = tmp_path / "k"
    path.write_bytes(key.export_private_key())
    path.chmod(0o600)
    line = CertificateAuthority(path).public_key()
    assert line.split()[:2] == key.export_public_key().decode().split()[:2]
    assert line.endswith(" nervus-ca") and "PRIVATE" not in line and "secret-comment" not in line


# --- step 3: what enrollment writes, as a real sshd reads it ----------------


@pytest.mark.parametrize("level", ["read-only", "standard"])
async def test_the_line_host_enrollment_writes_admits_nervus_by_certificate_alone(level, sshd, ca, tmp_path,
                                                                                   monkeypatch):
    """Decision 4: the host script, run for a level, writes the CA's line with
    that level's options; a real sshd given that line admits nervus's
    certificate, logs it, and refuses nervus's plain key. The read-only
    shell's path is pointed at a stand-in, the line otherwise as written."""
    import test_host_enrollment_script as script_tests
    monkeypatch.setattr(script_tests, "KEY", ca.public_key())
    machine = script_tests.Machine(tmp_path / "machine")
    done = machine.run(level)
    assert done.returncode == 0, done.stderr
    written = machine.keys.strip()
    assert written.startswith("cert-authority") and written.endswith(ca.public_key())

    stand_in = tmp_path / "readonly-shell"
    stand_in.write_text("#!/bin/sh\necho read-only shell\n")
    stand_in.chmod(0o755)
    server = sshd(lambda s: written.replace(script_tests.READONLY_SHELL_PATH, str(stand_in)))
    key = _key_file(tmp_path / "nervus")

    certs.acting_for(None, RUN)  # the check after enrolling: the operator's
    out = await _login(server, key, ca, "id -un")
    assert out == ("read-only shell\n" if level == "read-only" else f"{server.user}\n")
    server.wait_for(rf"ED25519-CERT SHA256:\S+ ID operator run={RUN} \(serial \d+\)")
    with pytest.raises(asyncssh.PermissionDenied):
        await _login(server, key, None)  # the bare key opens nothing here


# --- what no client asks for: nervus-ctl, and the clean-up after a restart -----


async def test_nervus_ctl_reaches_a_ca_only_machine_signed_for_its_own_records(sshd, ca, tmp_path):
    """nervus-ctl's listing logs in signed `operator run=<its list_jobs
    record>`, and its kill `operator run=<the lock record>`, on a machine
    whose line admits nervus's CA alone (the operator's choice, 2026-10-27).
    The line's command stands in for tmux, naming one job."""
    from nervus import ctl
    server = sshd(lambda s: f'cert-authority,command="echo nervus-abc" {ca.public_key()}')
    key = _key_file(tmp_path / "nervus")
    root = tmp_path / "opt"
    root.mkdir()
    (root / "hosts.yaml").write_text(
        f"hosts:\n  - {{name: h1, address: 127.0.0.1, os: x, role: x, agent_user: {server.user}, status: onboarded}}\n")
    tokens = root / "tokens.yaml"
    tokens.write_text("tokens:\n  - {token: aaaa, id: t1, client: c, project: p, hosts: [h1]}\n")
    tokens.chmod(0o600)
    (root / "switches.yaml").write_text("lockdown: false\ndisabled: []\n")
    audit_log = tmp_path / "audit.jsonl"
    unit = tmp_path / "nervus.service"
    unit.write_text(
        f"[Service]\nWorkingDirectory={root}\nExecStart=/opt/nervus/.venv/bin/nervus --hosts hosts.yaml "
        f"--tokens tokens.yaml --switches switches.yaml --known-hosts {server.known} --ssh-key {key} "
        f"--ssh-ca-key {ca.path} --audit-log {audit_log} --ssh-port {server.port}\n")
    # nervus's database, as every installation has once nervus has started: nervus-ctl reads the
    # machines added from the web UI and the VMs used by id from it, and says so when it cannot.
    from nervus.database import Database
    Database(ctl.read_unit(unit).database).open()

    out = io.StringIO()
    assert await ctl.run(["--unit", str(unit), "lock", "--all", "--kill-work", "--yes"], out=out) == 0
    assert "unattributed" not in out.getvalue() and "could not read" not in out.getvalue(), out.getvalue()
    assert "h1 abc" in out.getvalue()
    records = {r["action"]: r for r in map(json.loads, audit_log.read_text().splitlines())}
    server.wait_for(rf"ID operator run={records['list_jobs']['id']} \(serial \d+\)")
    server.wait_for(rf"ID operator run={records['lock']['id']} \(serial \d+\)")
    with pytest.raises(asyncssh.PermissionDenied):
        await _login(server, key, None)  # the plain key nervus-ctl used to offer opens nothing here


async def test_the_clean_up_after_a_restart_is_signed_for_its_own_record(sshd, ca, tmp_path, store):
    """An upload a restart cut off left a temporary file. Its clean-up has an
    audit record of its own, `actor: operator`, and logs in signed for it,
    on a machine that admits nervus's CA alone; its port is recorded."""
    from nervus.config import Host
    from nervus.upload_targets import HostDelivery, temp_path
    from nervus.uploader import Uploader
    from test_upload_targets import _delivering

    server = sshd(lambda s: f"cert-authority {ca.public_key()}")
    key = _key_file(tmp_path / "nervus")
    host = Host(name="web", address="127.0.0.1", os="x", role="x", agent_user=server.user, status="active")

    async def _connect(_host):
        return await ssh.connect(address="127.0.0.1", port=server.port, username=server.user,
                                 client_keys=[key], known_hosts=server.known, authority=ca)

    dest = tmp_path / "run.sh"
    upload = _delivering(store, dest)
    leftover = Path(temp_path(str(dest), upload.id))
    leftover.write_bytes(b"part")
    audit = AuditLog(path=tmp_path / "audit.jsonl")
    await Uploader(store, audit, deliver=HostDelivery(store, {"web": host}, _connect)).tidy([upload])

    assert not leftover.exists()
    intent, result = map(json.loads, audit.path.read_text().splitlines())
    assert (intent["actor"], intent["action"], intent["upload_id"]) == ("operator", "cleanup", upload.id)
    line = server.wait_for(rf"port (\d+) ssh2: ED25519-CERT SHA256:\S+ ID operator run={intent['id']} ")
    assert (result["id"], result["ssh_ports"]) == (intent["id"], [int(line.group(1))])


async def test_without_its_record_the_clean_up_connects_nowhere(tmp_path, store):
    from nervus.uploader import Uploader
    from test_upload_targets import _delivering

    class Deliver:
        cleaned: list = []

        async def __call__(self, upload):
            raise AssertionError("no delivery here")

        async def cleanup(self, upload):
            self.cleaned.append(upload.id)

    (tmp_path / "audit").mkdir()
    deliver = Deliver()
    await Uploader(store, AuditLog(path=tmp_path / "audit"), deliver=deliver).tidy([_delivering(store, tmp_path / "x")])
    assert deliver.cleaned == []


# --- step 4: the docs' own commands, against a real sshd -------------------


def _install_block(name: str) -> str:
    text = (Path(__file__).resolve().parent.parent / "docs" / "install.md").read_text()
    match = re.search(rf"<!-- install:{name} -->\n```bash\n(.*?)\n```", text, re.S)
    assert match, f"docs/install.md has no install:{name} block"
    return match.group(1)


@pytest.mark.parametrize("level", ["standard", "read-only"])
def test_the_docs_move_a_machine_and_check_it_as_nervus_will_connect(level, sshd, ca, tmp_path):
    """docs/install.md: the line that moves a machine to nervus's CA, then the
    by-hand check, run as written but for this test's paths, port and account:
    the check's certificate logs in and its log names it; the plain key is
    refused. The read-only shell is a stand-in; `sudo` is left out."""
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    _key_file(secrets / "nervus_ed25519")
    (secrets / "nervus_ed25519.pub").write_text(
        asyncssh.read_private_key(str(secrets / "nervus_ed25519")).export_public_key().decode())
    shutil.copy(ca.path, secrets / "nervus_ca_ed25519")
    stand_in = tmp_path / "readonly-shell"
    stand_in.write_text("#!/bin/sh\necho read-only shell\n")
    stand_in.chmod(0o755)
    server = sshd(lambda s: "")
    move = (_install_block(f"move-{level}")
            .replace("'<certificate authority line>'", shlex.quote(ca.public_key()))
            .replace("~agent/.ssh/authorized_keys", str(server.keys))
            .replace("/usr/local/lib/nervus/readonly-shell", str(stand_in)))
    subprocess.run(["bash", "-c", move], check=True)

    check = (_install_block("by-hand-check")
             .replace("/opt/nervus/secrets/", f"{secrets}/")
             .replace("runuser -u nervus -- ", "")
             .replace('chown -R nervus "$d" && ', "")
             .replace("-n agent", f"-n {server.user}")
             .replace("UserKnownHostsFile=" + f"{secrets}/known_hosts", f"UserKnownHostsFile={server.known}")
             .replace("agent@<address> 'id -un; sudo -n id -un'", f"-p {server.port} {server.user}@127.0.0.1 'id -un'"))
    assert "<" not in check, check
    done = subprocess.run(["bash", "-c", check], capture_output=True, text=True, timeout=30)
    expected = "read-only shell\n" if level == "read-only" else f"{server.user}\n"  # the line's command ran
    assert done.stdout == expected, done.stderr  # the status is rm's; the docs say to read the output
    server.wait_for(r"ED25519-CERT SHA256:\S+ ID operator check-by-hand \(serial \d+\)")
    plain = check.replace('-o CertificateFile="$d/nervus_ed25519-cert.pub" ', "")
    refused = subprocess.run(["bash", "-c", plain], capture_output=True, text=True, timeout=30)
    assert refused.stdout == "" and "Permission denied" in refused.stderr
    assert not list(Path(tempfile.gettempdir()).glob("tmp.*/nervus_ed25519-cert.pub"))  # its folder is gone
