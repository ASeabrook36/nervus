"""A pipe put where one of nervus's files was is refused by name, and never waited on.

nervus's files sit in folders its own account owns. nervus-ctl reads the same
names as root, and the audit copy's reader as an account of its own. Whoever
owns a folder can put a named pipe where a file was, and a plain open of a pipe
waits for a writer that never comes: the off switch's commands stopped
answering, and so did every page and command that reads the audit log
(procedures 058 and 060). So nervus's own code opens its files through
nervus.plainfile, hands another program the file already read or already open
instead of its name wherever that program will take it (procedure 062), and
the last tests here keep it that way."""

from __future__ import annotations

import ast
import asyncio
import contextlib
import importlib.machinery
import importlib.util
import os
import signal
import stat
from pathlib import Path

import asyncssh
import pytest

import nervus
from nervus import backup, clients, ctl, identity, plainfile, proxmox, restore, ssh
from nervus.audit import AuditError, AuditLog
from nervus.audit_view import read_page, read_row
from nervus.auth import load_tokens
from nervus.certs import CertificateAuthority
from nervus.config import ConfigError, load_hosts, require_private_file
from nervus.switches import SwitchesUnreadable, change_switches, load_switches, locked, refusal
from nervus.tls import ServingCertificate, generate_self_signed

SRC = Path(nervus.__file__).parent
TOOLS = SRC.parent.parent / "tools"
SAID = "is a pipe, not a file"


PIPES: list[Path] = []


def _let_go() -> None:
    """Ends whatever still waits on a pipe these tests made, and puts an empty file at its
    name. A library that reads a file in a thread of its own (the SSH library reads keys so,
    and tries a second time) would otherwise wait there after its test had failed, and hold
    pytest at its end."""
    for path in PIPES:
        with contextlib.suppress(OSError):
            try:
                other_end = os.open(path, os.O_WRONLY | os.O_NONBLOCK)
            except OSError:  # ENXIO: nobody waits on this one
                other_end = None
            os.unlink(path)
            path.write_bytes(b"")
            if other_end is not None:
                os.close(other_end)


@pytest.fixture(autouse=True)
def never_waits():
    """Fails a test still running after a few seconds, which is what waiting on a
    pipe looks like: nothing ever writes to the pipes these tests make."""
    def waited(signum, frame):
        _let_go()
        pytest.fail("it waited on the pipe at the file's name")
    before = signal.signal(signal.SIGALRM, waited)
    signal.setitimer(signal.ITIMER_REAL, 5)
    yield
    signal.setitimer(signal.ITIMER_REAL, 0)
    signal.signal(signal.SIGALRM, before)
    _let_go()
    PIPES.clear()


def pipe(path: Path) -> Path:
    os.mkfifo(path, 0o600)
    PIPES.append(path)
    return path


# --- the off switch, and what its commands read with it ------------------------------


def test_a_pipe_at_the_off_switch_refuses_everyone_and_is_not_written_through(tmp_path):
    switches = pipe(tmp_path / "switches.yaml")
    with pytest.raises(SwitchesUnreadable, match=SAID):
        load_switches(switches)
    assert refusal(switches, "t1").startswith("switches unreadable, so everything is refused")
    assert locked(switches) is True
    with pytest.raises(SwitchesUnreadable, match=SAID):
        change_switches(switches, lambda now: now)
    assert stat.S_ISFIFO(switches.lstat().st_mode) and os.listdir(tmp_path) == ["switches.yaml"]


def test_a_pipe_at_the_token_file_is_refused(tmp_path):
    with pytest.raises(ConfigError, match=SAID):
        load_tokens(pipe(tmp_path / "tokens.yaml"))


def test_a_pipe_at_the_inventory_is_refused(tmp_path):
    with pytest.raises(ConfigError, match=SAID):
        load_hosts(pipe(tmp_path / "hosts.yaml"))


def test_a_pipe_at_the_proxmox_settings_is_refused(tmp_path):
    with pytest.raises(ConfigError, match=SAID):
        proxmox.load_config(pipe(tmp_path / "proxmox.yaml"))


def test_a_pipe_at_the_recovery_key_makes_no_backup(tmp_path):
    with pytest.raises(backup.BackupFailed, match=SAID):
        backup.recipient(pipe(tmp_path / "recovery.pub"))


def test_a_pipe_at_a_piece_makes_no_backup(tmp_path):
    with pytest.raises(backup.BackupFailed, match=SAID):
        backup._read("tokens", pipe(tmp_path / "tokens.yaml"))


# --- the audit log's readers, and its writer ------------------------------------------


def test_the_audit_page_says_it_cannot_read_a_pipe(tmp_path):
    log = pipe(tmp_path / "audit.jsonl")
    with pytest.raises(OSError, match=SAID):
        read_page(log)
    with pytest.raises(OSError, match=SAID):
        read_row(log, 0)
    assert clients._last_call(log, "t1") is None  # the Clients page: no last call, and no wait


def test_nervus_ctl_says_it_cannot_read_a_pipe_for_who_owns_each_job(tmp_path):
    with pytest.raises(ConfigError, match=SAID):
        ctl._jobs_by_run(pipe(tmp_path / "audit.jsonl"))


def test_no_record_is_written_into_a_pipe_nobody_reads(tmp_path):
    with pytest.raises(AuditError, match=SAID):
        AuditLog(path=pipe(tmp_path / "audit.jsonl")).record_operator("lock", {"target": "all"})


def test_no_record_is_written_into_a_pipe_somebody_reads(tmp_path):
    """With a reader holding the pipe open, opening it to write succeeds at once:
    the record would go to whoever put the pipe there, and not into the log."""
    log = pipe(tmp_path / "audit.jsonl")
    reader = os.open(log, os.O_RDONLY | os.O_NONBLOCK)
    try:
        with pytest.raises(AuditError, match=SAID):
            AuditLog(path=log).record_operator("lock", {"target": "all"})
        assert os.read(reader, 4096) == b""  # nothing was written to it
    finally:
        os.close(reader)


def test_a_log_that_is_not_there_yet_is_still_made(tmp_path):
    log = tmp_path / "audit.jsonl"
    AuditLog(path=log).record_operator("lock", {"target": "all"})
    AuditLog(path=log).record_operator("unlock", {"target": "all"})
    assert stat.S_ISREG(log.lstat().st_mode) and len(log.read_text().splitlines()) == 2


# --- names nervus used to hand to another program, which opened them itself -------------


def _ssh_key(path: Path) -> Path:
    asyncssh.generate_private_key("ssh-ed25519").write_private_key(str(path))
    path.chmod(0o600)
    return path


def test_a_secret_that_is_not_a_file_is_refused_by_what_it_is(tmp_path):
    """Every secret nervus reads passes this check first, and a pipe made 0600 passed it."""
    with pytest.raises(ConfigError, match=SAID):
        require_private_file(pipe(tmp_path / "nervus_ed25519"))


def test_a_pipe_at_nervus_s_ssh_key_is_refused_before_any_connection(tmp_path):
    (tmp_path / "known_hosts").write_text("")
    with pytest.raises(OSError, match=SAID):
        asyncio.run(ssh.connect(address="127.0.0.1", port=9, username="agent", connect_timeout=2,
                                client_keys=[pipe(tmp_path / "nervus_ed25519")],
                                known_hosts=tmp_path / "known_hosts"))


def test_a_pipe_at_known_hosts_is_refused_and_does_not_hold_nervus(tmp_path):
    """The SSH library read known_hosts itself, by name, once a machine had answered with its
    key: inside nervus's one loop, so a pipe there held every client's call, not this one's."""
    key = _ssh_key(tmp_path / "nervus_ed25519")
    known_hosts = pipe(tmp_path / "known_hosts")

    async def a_machine_answers():
        machine = await asyncssh.listen("127.0.0.1", 0, server_host_keys=[asyncssh.generate_private_key("ssh-ed25519")])
        try:
            await ssh.connect(address="127.0.0.1", port=machine.sockets[0].getsockname()[1], username="agent",
                              client_keys=[key], known_hosts=known_hosts, connect_timeout=3)
        finally:
            machine.close()

    with pytest.raises(OSError, match=SAID):
        asyncio.run(a_machine_answers())


def test_a_pipe_at_the_certificate_authority_s_key_is_refused(tmp_path):
    with pytest.raises(ConfigError, match=SAID):
        CertificateAuthority(pipe(tmp_path / "nervus_ca_ed25519"))


def test_a_pipe_at_a_key_nervus_checks_itself_by_is_refused(tmp_path):
    with pytest.raises(identity.IdentityRefused, match=SAID):
        identity._ssh_fingerprint(pipe(tmp_path / "nervus_ed25519"))


def test_a_pipe_at_the_proxmox_ca_is_refused(tmp_path):
    with pytest.raises(ConfigError, match=SAID):
        proxmox.make_ssl_context(pipe(tmp_path / "pve-root-ca.pem"))


def test_a_pipe_at_the_key_nervus_serves_tls_with_is_refused(tmp_path):
    """The TLS library takes only names. The key's name is looked at first, as every secret's is."""
    cert, key = tmp_path / "tls.crt", tmp_path / "tls.key"
    generate_self_signed(cert, key, ["localhost"])
    key.unlink()
    with pytest.raises(ConfigError, match=SAID):
        ServingCertificate(cert, pipe(key)).load()


def test_a_pipe_at_a_backup_s_name_is_refused_by_what_it_is(tmp_path, monkeypatch):
    monkeypatch.setattr(restore.shutil, "which", lambda name: "/usr/bin/age")
    with pytest.raises(restore.BackupRefused, match=SAID):
        restore.open_backup(pipe(tmp_path / "nervus-backup.tar.gz.age"), "AGE-SECRET-KEY-1NOTONE")


def test_age_is_given_the_backup_already_open_and_never_its_name(tmp_path, monkeypatch):
    """A name is whatever is at it when age opens it; an open file is the file that was checked."""
    given = {}

    class Stop(Exception):
        pass

    def popen(argv, stdin=None, **rest):
        given["argv"], given["is a file"] = argv, stat.S_ISREG(os.fstat(stdin.fileno()).st_mode)
        raise Stop

    monkeypatch.setattr(restore.shutil, "which", lambda name: "/usr/bin/age")
    monkeypatch.setattr(restore.subprocess, "Popen", popen)
    made = tmp_path / "nervus-backup.tar.gz.age"
    made.write_bytes(b"age-encryption.org/v1\n")
    with pytest.raises(Stop):
        restore.open_backup(made, "AGE-SECRET-KEY-1NOTONE")
    assert str(made) not in given["argv"] and given["is a file"]


# --- the reader itself ----------------------------------------------------------------


def test_a_plain_file_is_read_as_it_always_was(tmp_path):
    f = tmp_path / "f"
    f.write_bytes(b"one\ntwo\n")
    assert plainfile.read_bytes(f) == f.read_bytes()
    assert plainfile.read_text(f) == f.read_text()
    with plainfile.open_file(f) as opened:
        opened.seek(4)
        assert opened.read() == b"two\n"


def test_a_link_to_a_file_is_followed(tmp_path):
    (tmp_path / "kept-elsewhere").write_text("as before\n")
    (tmp_path / "f").symlink_to(tmp_path / "kept-elsewhere")
    assert plainfile.read_text(tmp_path / "f") == "as before\n"


@pytest.mark.parametrize("what", ["pipe", "folder", "link to a pipe", "link to a device"])
def test_anything_else_is_refused_by_what_it_is(tmp_path, what):
    name = tmp_path / "f"
    if what == "pipe":
        pipe(name)
    elif what == "folder":
        name.mkdir()
    elif what == "link to a pipe":
        name.symlink_to(pipe(tmp_path / "elsewhere"))
    else:
        name.symlink_to("/dev/zero")  # read as a file, it never ends
    kind = what.split()[-1]
    for read in (plainfile.read_bytes, plainfile.read_text, plainfile.open_file):
        with pytest.raises(plainfile.NotAFile, match=f"{name} is a {kind}, not a file"):
            read(name)


def test_a_missing_file_is_missing_as_it_always_was(tmp_path):
    with pytest.raises(FileNotFoundError):
        plainfile.read_bytes(tmp_path / "f")


# --- and nothing opens a file any other way --------------------------------------------

# Where nervus's own code still opens a file by pathlib or the built-in open, and why
# that file is not one nervus's account can put a pipe at.
NOT_ITS_ACCOUNTS = {
    ("ctl.py", "_effective"): "the unit file and its drop-ins, which are root's",
    ("restore.py", "place"): "the unit's drop-ins, which are root's",
    ("host_enrollment.py", "enroll_script"): "a file of nervus's own package",
    ("laptop.py", "_helper"): "the laptop's scripts and helpers, files of nervus's own package (ADR-0032)",
    ("host_enrollment.py", "own_machine_id"): "the system's machine id, which is root's",
}


def _opens_by_name(module: Path) -> set[tuple[str, str]]:
    """(module, function) of each call that opens a file by pathlib's read_text,
    read_bytes, write_text, write_bytes or open("mode"), or by the built-in open."""
    found = set()

    def walk(node, inside):
        for child in ast.iter_child_nodes(node):
            now = child.name if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) else inside
            if isinstance(child, ast.Call):
                call = child.func
                if isinstance(call, ast.Name) and call.id == "open":
                    found.add((module.name, inside))
                elif isinstance(call, ast.Attribute) and ast.unparse(call.value) != "plainfile":
                    mode = child.args[0].value if child.args and isinstance(child.args[0], ast.Constant) else None
                    if call.attr in ("read_text", "read_bytes", "write_text", "write_bytes") or (
                            call.attr == "open" and isinstance(mode, str) and set(mode) <= set("rwabxt+")):
                        found.add((module.name, inside))
            walk(child, now)

    walk(ast.parse(module.read_text()), "<module>")
    return found


def test_nervus_opens_its_files_no_other_way():
    """A new read_text() of one of nervus's files would wait on a pipe again. os.open and
    a name handed to another program are the two tests below."""
    found = set().union(*(_opens_by_name(module) for module in sorted(SRC.glob("*.py"))))
    assert found == set(NOT_ITS_ACCOUNTS)


# Where nervus's own code calls os.open without one of the three flags that cannot wait on a
# pipe: O_NONBLOCK (it is opened, then seen not to be a file), O_DIRECTORY (refused at once)
# and O_EXCL (the name is made new).
OPENED_OTHERWISE = {
    ("plainfile.py", "_opened"): "the reader itself, which adds O_NONBLOCK to the flags it is given",
    ("sftp.py", "_step"): "one step of a path; every caller gives it O_DIRECTORY or O_NONBLOCK",
    ("restore.py", "_open_folder"): "a folder on the way down, its flags set with O_DIRECTORY the line before",
    ("ctl.py", "read_secret"): "/dev/tty, to learn whether there is a terminal to ask at",
}


def _os_opens_that_may_wait(module: Path) -> set[tuple[str, str]]:
    found = set()

    def walk(node, inside):
        for child in ast.iter_child_nodes(node):
            now = child.name if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) else inside
            if isinstance(child, ast.Call) and ast.unparse(child.func) == "os.open":
                flags = ast.unparse(child.args[1]) if len(child.args) > 1 else ""
                if not any(flag in flags for flag in ("O_NONBLOCK", "O_DIRECTORY", "O_EXCL")):
                    found.add((module.name, inside))
            walk(child, now)

    walk(ast.parse(module.read_text()), "<module>")
    return found


def test_nervus_s_os_opens_cannot_wait_either():
    found = set().union(*(_os_opens_that_may_wait(module) for module in sorted(SRC.glob("*.py"))))
    assert found == set(OPENED_OTHERWISE)


# Where nervus's own code still gives a file's name to another program or library to open.
NAMES_HANDED_ON = {
    ("tls.py", "load"): "the TLS library takes its certificate and key by name only; both are read "
                        "as plain files on the lines before, and only the account that serves "
                        "with them can change either in between",
}


def _names_handed_on(module: Path) -> set[tuple[str, str]]:
    """(module, function) of each call that has a library read a file by its name: the SSH
    library's read_* functions, and the TLS library's load_cert_chain and cafile."""
    found = set()

    def walk(node, inside):
        for child in ast.iter_child_nodes(node):
            now = child.name if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) else inside
            if isinstance(child, ast.Call):
                called = ast.unparse(child.func)
                by_keyword = {k.arg for k in child.keywords} & {"cafile", "capath", "certfile", "keyfile"}
                if (called.startswith("asyncssh.read_") or called.endswith(".load_cert_chain") or by_keyword
                        or (called.endswith(".load_verify_locations") and child.args)):
                    found.add((module.name, inside))
            walk(child, now)

    walk(ast.parse(module.read_text()), "<module>")
    return found


def test_nervus_hands_no_other_program_a_name_to_open():
    found = set().union(*(_names_handed_on(module) for module in sorted(SRC.glob("*.py"))))
    assert found == set(NAMES_HANDED_ON)


# --- the tools root runs beside nervus, which read the same names ---------------------

# Each stands by itself: a deploy runs it from the tree it is about to install, with the nervus
# still installed, which may have no nervus.plainfile.
READERS = {"set-token": "read_plain", "set-hosts": "read_plain", "ensure-switches": "read_plain", "check-up": "read_root"}


def _tool(name: str):
    loader = importlib.machinery.SourceFileLoader(name.replace("-", "_"), str(TOOLS / name))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


@pytest.mark.parametrize("name", sorted(READERS))
def test_a_tool_s_own_reader_refuses_a_pipe_and_reads_a_file(tmp_path, name):
    read = getattr(_tool(name), READERS[name])
    with pytest.raises(OSError, match=SAID):
        read(pipe(tmp_path / "pipe"))
    with pytest.raises(OSError, match="is a folder, not a file"):
        read(tmp_path)
    (tmp_path / "file").write_text("as it was\n")
    assert read(tmp_path / "file") == "as it was\n"
    (tmp_path / "link").symlink_to(tmp_path / "file")  # followed, as nervus.plainfile follows one
    assert read(tmp_path / "link") == "as it was\n"


# Where one of those tools, or tools/compare-refusals, still opens a file by pathlib or the built-in open.
TOOLS_NOT_ITS_ACCOUNTS = {
    ("compare-refusals", "address"): "nervus's unit file, which is root's",
}


def test_the_tools_root_runs_open_these_files_no_other_way():
    tools = [TOOLS / name for name in (*READERS, "compare-refusals")]
    assert set().union(*(_opens_by_name(tool) for tool in tools)) == set(TOOLS_NOT_ITS_ACCOUNTS)
    assert not set().union(*(_names_handed_on(tool) for tool in tools))
