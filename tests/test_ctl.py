"""nervus-ctl (ADR-0003): status, lock, unlock and --kill-work, against a real
SSH server running real tmux jobs. Each test has its own tmux server."""

import io
import json
import os
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

import asyncssh
import pytest

from nervus import ctl
from nervus.audit import AuditLog
from nervus.jobs import job_status, start_job
from nervus.ssh import connect
from nervus.switches import load_switches, refusal

needs_tmux = pytest.mark.skipif(shutil.which("tmux") is None, reason="needs tmux")
ON = "lockdown: false\ndisabled: []\n"


@pytest.fixture
def service(tmp_path, ssh_server, monkeypatch):
    """A nervus installation as nervus-ctl finds it: a unit file whose ExecStart
    names every file, relative to its WorkingDirectory where it can be."""
    # This test's own tmux server. Not under tmp_path: tmux's socket lives in
    # this folder, and macOS refuses socket paths over 104 bytes, which a
    # pytest tmp_path on a Mac can already exceed ("File name too long").
    tmux_dir = tempfile.mkdtemp(prefix="nt-", dir="/tmp")
    monkeypatch.setenv("TMUX_TMPDIR", tmux_dir)
    root = tmp_path / "opt"
    (root / "secrets").mkdir(parents=True)
    (root / "hosts.yaml").write_text(
        "hosts:\n"
        f"  - {{name: h1, address: {ssh_server.host}, os: x, role: x, agent_user: {ssh_server.username}, status: onboarded}}\n"
        f"  - {{name: other, address: nervus-test.invalid, os: x, role: x, agent_user: {ssh_server.username}, status: onboarded}}\n"
    )
    tokens = root / "secrets" / "tokens.yaml"
    tokens.write_text("tokens:\n"
                      "  - {token: aaaa, id: t1, client: claude-code, project: p, hosts: [h1]}\n"
                      "  - {token: bbbb, id: t2, client: codex, project: q, hosts: [h1]}\n")
    os.chmod(tokens, 0o600)
    switches = root / "secrets" / "switches.yaml"
    switches.write_text(ON)
    os.chmod(switches, 0o640)
    ca = root / "secrets" / "nervus_ca_ed25519"
    ca.write_bytes(asyncssh.generate_private_key("ssh-ed25519").export_private_key())
    os.chmod(ca, 0o600)
    unit = tmp_path / "nervus.service"
    unit.write_text(
        "[Service]\n"
        f"WorkingDirectory={root}\n"
        "ExecStart=/opt/nervus/.venv/bin/nervus \\\n"
        "    --hosts hosts.yaml \\\n"
        "    --tokens secrets/tokens.yaml \\\n"
        f"    --known-hosts {ssh_server.known_hosts_path} \\\n"
        f"    --ssh-key {ssh_server.client_key_path} \\\n"
        "    --ssh-ca-key secrets/nervus_ca_ed25519 \\\n"
        f"    --audit-log {tmp_path / 'audit.jsonl'} \\\n"
        f"    --ssh-port {ssh_server.port}\n"
    )
    yield ctl.read_unit(unit), unit, ssh_server
    subprocess.run(["tmux", "kill-server"], capture_output=True)
    shutil.rmtree(tmux_dir, ignore_errors=True)


async def _job(service_, token_id):
    """A running job owned by token_id, as exec_bg makes one: its id is the
    audit run id of an exec_bg intent naming the token."""
    svc, _, server = service_
    run_id = AuditLog(path=svc.audit_log).record_intent("exec_bg", {"token_id": token_id, "host": "h1"})
    conn = await connect(address=server.host, port=server.port, username=server.username,
                         client_keys=[server.client_key_path], known_hosts=server.known_hosts_path)
    try:
        await start_job(conn, cwd="/tmp", command="sleep 60", job_id=run_id)
    finally:
        conn.close()
    return run_id


async def _running(service_, job_id):
    _, _, server = service_
    conn = await connect(address=server.host, port=server.port, username=server.username,
                         client_keys=[server.client_key_path], known_hosts=server.known_hosts_path)
    try:
        return (await job_status(conn, job_id)).running
    finally:
        conn.close()


async def _ctl(service_, *argv, ask=None):
    out = io.StringIO()
    rc = await ctl.run(["--unit", str(service_[1]), *argv], out=out, ask=ask or (lambda _: ""))
    return rc, out.getvalue()


def _operator_records(svc):
    return [r for r in map(json.loads, svc.audit_log.read_text().splitlines()) if r["phase"] == "operator"]


def test_the_unit_decides_every_path(monkeypatch):
    """Relative paths resolve against WorkingDirectory; nervus-ctl's own
    environment is ignored, because systemd does not pass it to nervus. The
    generic unit alone; an installation's drop-in is tested with it."""
    monkeypatch.setenv("NERVUS_SWITCHES", "/elsewhere/switches.yaml")
    svc = ctl.read_unit(Path(__file__).parent.parent / "deploy" / "nervus.service")
    assert svc.switches == Path("/var/lib/nervus/switches.yaml")  # ADR-0014 decision A
    assert svc.tokens == Path("/opt/nervus/secrets/tokens.yaml")
    assert svc.audit_log == Path("/var/log/nervus/audit.jsonl")
    assert svc.database == Path("/var/lib/nervus/nervus.db")  # ADR-0012 decision 3
    assert svc.ui_url == ""  # an installation's address, in its own drop-in
    assert svc.tls_cert == Path("/opt/nervus/secrets/tls.crt")
    assert svc.user == "nervus"  # whom signin writes the database as


def _unit_with(tmp_path, unit: str, **drop_ins: str) -> Path:
    path = tmp_path / "nervus.service"
    path.write_text(unit)
    if drop_ins:
        (tmp_path / "nervus.service.d").mkdir()
        for name, text in drop_ins.items():
            (tmp_path / "nervus.service.d" / f"{name}.conf").write_text(text)
    return path


GENERIC = "[Service]\nUser=nervus\nWorkingDirectory=/opt/nervus\nExecStart=/n --hosts h --tokens t\n"


def test_a_drop_in_that_restates_execstart_is_what_nervus_runs(tmp_path):
    """ADR-0019: an installation's own flags live in a drop-in, which clears the
    unit's ExecStart and gives its own, as systemd reads it."""
    unit = _unit_with(tmp_path, GENERIC, instance="[Service]\nExecStart=\n"
                      "ExecStart=/n --hosts h --tokens t --ui-url https://hv.example.net:8443\n")
    svc = ctl.read_unit(unit)
    assert (svc.ui_url, svc.tokens, svc.user) == ("https://hv.example.net:8443", Path("/opt/nervus/t"), "nervus")


def test_with_no_drop_in_the_unit_alone_is_what_nervus_runs(tmp_path):
    svc = ctl.read_unit(_unit_with(tmp_path, GENERIC))
    assert (svc.ui_url, svc.tokens) == ("", Path("/opt/nervus/t"))


def test_drop_ins_are_read_in_name_order_and_the_last_execstart_wins(tmp_path):
    unit = _unit_with(tmp_path, GENERIC,
                      a="[Service]\nExecStart=\nExecStart=/n --hosts h --tokens first\n",
                      b="[Service]\nExecStart=\nExecStart=/n --hosts h --tokens second\nUser=other\n")
    svc = ctl.read_unit(unit)
    assert (svc.tokens, svc.user) == (Path("/opt/nervus/second"), "other")


def test_a_drop_in_that_adds_execstart_without_clearing_it_is_refused(tmp_path):
    """systemd would refuse two ExecStart lines for a simple service; so does this."""
    unit = _unit_with(tmp_path, GENERIC, instance="[Service]\nExecStart=/n --hosts h --tokens other\n")
    with pytest.raises(ctl.ConfigError, match="exactly one ExecStart"):
        ctl.read_unit(unit)


def test_a_drop_in_that_sets_an_environment_is_refused(tmp_path):
    unit = _unit_with(tmp_path, GENERIC, instance="[Service]\nEnvironment=NERVUS_TOKENS=/x\n")
    with pytest.raises(ctl.ConfigError, match="instance.conf sets an environment"):
        ctl.read_unit(unit)


def test_a_unit_that_sets_an_environment_is_refused(tmp_path):
    unit = tmp_path / "u"
    unit.write_text("Environment=NERVUS_SWITCHES=/x\nExecStart=/n --hosts h\n")
    with pytest.raises(ctl.ConfigError, match="environment"):
        ctl.read_unit(unit)


@needs_tmux
async def test_status_shows_each_client_and_its_jobs(service):
    job = await _job(service, "t1")
    rc, out = await _ctl(service, "status")
    assert rc == 0
    t1 = next(l for l in out.splitlines() if l.startswith("t1 "))
    assert " on " in t1 and "jobs: 1" in t1
    assert f"    h1 {job}" in out
    assert "jobs: 0" in next(l for l in out.splitlines() if l.startswith("t2 "))
    assert "could not read jobs on other:" in out  # one host down hides nothing else


@needs_tmux
async def test_status_records_its_listing_first_and_without_the_record_asks_no_machine(service):
    """ADR-0025: every login nervus-ctl makes is signed for an audit record,
    so listing jobs writes one, `list_jobs`, before any machine is asked
    (the operator's choice, 2026-10-27). If it cannot be written, status
    still shows the switches and says no machine was asked."""
    svc = service[0]
    await _job(service, "t1")
    rc, out = await _ctl(service, "status")
    assert rc == 0
    assert [r["action"] for r in _operator_records(svc)] == ["list_jobs"]
    svc.audit_log.chmod(0o444)
    try:
        rc, out = await _ctl(service, "status")
    finally:
        svc.audit_log.chmod(0o644)
    assert rc == 0
    assert "jobs: 0" in next(l for l in out.splitlines() if l.startswith("t1 "))
    assert "could not read jobs on any machine, so none was asked: could not write audit record" in out
    assert [r["action"] for r in _operator_records(svc)] == ["list_jobs"]


@needs_tmux
async def test_lock_switches_one_client_off_and_is_audited(service):
    svc = service[0]
    rc, out = await _ctl(service, "lock", "t1")
    assert rc == 0
    assert load_switches(svc.switches).disabled == {"t1"}
    assert (refusal(svc.switches, "t1"), refusal(svc.switches, "t2")) == ("disabled", None)
    assert stat.S_IMODE(svc.switches.stat().st_mode) == 0o640       # owner and mode kept
    assert not [p for p in svc.switches.parent.iterdir() if p.name.startswith(".switches.")]
    assert [(r["actor"], r["action"], r["target"]) for r in _operator_records(svc)] == [("operator", "lock", "t1")]


@needs_tmux
async def test_an_unknown_token_changes_nothing(service):
    svc = service[0]
    rc, out = await _ctl(service, "lock", "t9")
    assert rc == 1 and "no token 't9'" in out
    assert svc.switches.read_text() == ON


@needs_tmux
async def test_lockdown_and_its_lifting_keep_clients_switched_off_one_by_one(service):
    svc = service[0]
    await _ctl(service, "lock", "t1")
    await _ctl(service, "lock", "--all")
    assert refusal(svc.switches, "t2") == "lockdown"
    rc, out = await _ctl(service, "unlock", "--all")
    assert rc == 0 and "still off one by one: t1" in out
    assert (refusal(svc.switches, "t1"), refusal(svc.switches, "t2")) == ("disabled", None)
    await _ctl(service, "unlock", "t1")
    assert refusal(svc.switches, "t1") is None


@needs_tmux
async def test_kill_work_stops_only_that_clients_jobs(service):
    svc = service[0]
    mine, theirs = await _job(service, "t1"), await _job(service, "t2")
    rc, out = await _ctl(service, "lock", "t1", "--kill-work", "--yes")
    assert rc == 0
    assert f"h1 {mine}: stopped" in out
    assert not await _running(service, mine)
    assert await _running(service, theirs)
    records = _operator_records(svc)
    assert [(r["action"], r.get("target")) for r in records] == [("list_jobs", None), ("lock", "t1"),
                                                                 ("kill_work", "t1")]
    assert records[0]["hosts"] == ["h1", "other"]
    assert records[2]["jobs"] == [f"h1/{mine}"]
    assert len(records[2]["ssh_ports"]) == 1  # the kill's one login, its port as the machine logs it


@needs_tmux
async def test_kill_work_asks_first_and_does_nothing_unconfirmed(service):
    svc = service[0]
    job = await _job(service, "t1")
    rc, out = await _ctl(service, "lock", "t1", "--kill-work", ask=lambda _: "no")
    assert rc == 1 and "nothing changed" in out
    assert svc.switches.read_text() == ON and await _running(service, job)
    rc, out = await _ctl(service, "lock", "t1", "--kill-work", ask=lambda _: "t1")
    assert rc == 0 and not await _running(service, job)


@needs_tmux
async def test_an_unreadable_switches_file_is_left_for_the_operator(service):
    svc = service[0]
    svc.switches.write_text("lockdown: [\n")
    rc, out = await _ctl(service, "lock", "t1")
    assert rc == 1 and "Fix it by hand" in out
    assert svc.switches.read_text() == "lockdown: [\n"


@pytest.mark.parametrize("piece, argv, said", [
    ("switches", ("lock", "t1"), "Fix it by hand"),
    ("switches", ("unlock", "--all"), "Fix it by hand"),
    ("tokens", ("lock", "t1"), "is a pipe, not a file"),
    ("tokens", ("status",), "is a pipe, not a file"),
    ("audit_log", ("status",), "is a pipe, not a file"),
    ("audit_log", ("lock", "t1"), "is a pipe, not a file"),
    ("audit_log", ("unlock", "--all"), "is a pipe, not a file"),
])
async def test_a_pipe_where_a_file_belongs_is_said_and_never_waited_on(service, piece, argv, said):
    """nervus's account owns the folders these files are in, and can put a pipe at
    any of their names. A plain open waited on it for good, so the off switch's own
    commands sat there saying nothing (procedure 060)."""
    path = getattr(service[0], piece)
    path.unlink(missing_ok=True)
    os.mkfifo(path, 0o600)
    signal.signal(signal.SIGALRM, lambda *_: pytest.fail("it waited on the pipe"))
    signal.alarm(20)
    try:
        rc, out = await _ctl(service, *argv)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, signal.SIG_DFL)
    assert rc == 1 and said in out, out


def test_nervus_ctl_locks_a_client_of_a_running_nervus(tmp_path):
    """End to end: nervus-ctl, reading a unit with nervus's real arguments,
    switches off a client of a running nervus, which refuses its next call."""
    sys.path.insert(0, str(Path(__file__).parent))
    from test_main import INIT, MCP_HEADERS, TOKEN, _Nervus, _jsonrpc, _post

    nervus = _Nervus(tmp_path)
    try:
        nervus.wait_listening()
        unit = tmp_path / "nervus.service"
        unit.write_text("WorkingDirectory=/\nExecStart=/usr/bin/nervus " + shlex.join(nervus.args) + "\n")
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", nervus.port, timeout=10)
        auth = {**MCP_HEADERS, "Authorization": f"Bearer {TOKEN}"}
        assert "result" in _jsonrpc(_post(conn, INIT, auth)[1])

        done = subprocess.run([sys.executable, "-c", "from nervus.ctl import main; raise SystemExit(main())",
                               "--unit", str(unit), "lock", "t"], capture_output=True, text=True, timeout=60)
        assert done.returncode == 0, done.stdout + done.stderr

        assert _jsonrpc(_post(conn, INIT, auth)[1])["error"]["code"] == -32001
    finally:
        nervus.stop()


# --- signin and signout --all (ADR-0012 decisions 3 to 7) ------------------------

from nervus.database import Database, audit_id  # noqa: E402
from nervus.tls import certificate_fingerprint, fingerprint, generate_self_signed  # noqa: E402

T0 = 1_800_000_000.0
LINK = re.compile(r"(\S+)/signin\?link=([A-Za-z0-9_-]+)")


@pytest.fixture
def ui(tmp_path):
    """A nervus installation as nervus-ctl finds it for the UI: its unit names the
    database, the UI's address and the certificate; nervus has made the
    database and tls-init the certificate. No host is needed."""
    root = tmp_path / "opt"
    (root / "secrets").mkdir(parents=True)
    generate_self_signed(root / "secrets" / "tls.crt", root / "secrets" / "tls.key", ["localhost"])
    database = Database(tmp_path / "state" / "nervus.db")
    database.path.parent.mkdir()
    database.open()
    unit = tmp_path / "nervus.service"
    _ui_unit(unit, root, tmp_path, ui_url="https://nervus.example:8443")
    return database, unit, root


def _ui_unit(unit, root, tmp_path, ui_url=None, extra=""):
    unit.write_text(
        "[Service]\n"
        "User=nervus\n"
        f"WorkingDirectory={root}\n"
        "ExecStart=/opt/nervus/.venv/bin/nervus \\\n"
        f"    --audit-log {tmp_path / 'audit.jsonl'} \\\n"
        f"    --database {tmp_path / 'state' / 'nervus.db'} \\\n"
        + (f"    --ui-url {ui_url} \\\n" if ui_url else "")
        + extra
        + "    --insecure-plain-http\n"
    )


async def _ui_ctl(unit, *argv):
    out = io.StringIO()
    rc = await ctl.run(["--unit", str(unit), *argv], out=out, ask=lambda _: "")
    return rc, out.getvalue()


def _links(database):
    import sqlite3
    with sqlite3.connect(database.path) as other:
        return other.execute("SELECT COUNT(*) FROM signin_link").fetchone()[0]


def _records(tmp_path):
    path = tmp_path / "audit.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def test_the_unit_gives_the_database_the_ui_and_the_account(ui):
    database, unit, root = ui
    svc = ctl.read_unit(unit)
    assert svc.database == database.path
    assert svc.ui_url == "https://nervus.example:8443"
    assert svc.tls_cert == root / "secrets" / "tls.crt"  # nervus's own: the UI's even on plain-HTTP MCP
    assert svc.user == "nervus"


async def test_signin_prints_a_link_that_signs_in_once(ui):
    database, unit, _ = ui
    rc, out = await _ui_ctl(unit, "signin")
    assert rc == 0, out
    (base, value), = LINK.findall(out)
    assert base == "https://nervus.example:8443"
    database.use_link(value)
    with pytest.raises(Exception, match="used"):
        database.use_link(value)
    assert "5 minutes" in out


async def test_signin_prints_the_certificate_fingerprint_a_browser_shows(ui):
    """ADR-0012 decision 7a: the reference is read on the nervus machine, and
    it is the certificate's, which a browser shows, not the public key's."""
    _, unit, root = ui
    cert = (root / "secrets" / "tls.crt").read_bytes()
    rc, out = await _ui_ctl(unit, "signin")
    assert rc == 0, out
    assert f"certificate SHA-256 {certificate_fingerprint(cert)}" in out
    assert fingerprint(cert) not in out  # never the pinned one, to be mistaken for it


async def test_signin_is_audited_and_the_record_cannot_sign_in(ui, tmp_path):
    """ADR-0012 decision 6: the link made is recorded, by the start of its
    hash, which ties it to its use without being usable."""
    _, unit, _ = ui
    rc, out = await _ui_ctl(unit, "signin")
    (_, value), = LINK.findall(out)
    record, = _records(tmp_path)
    assert (record["phase"], record["actor"], record["action"]) == ("operator", "operator", "signin")
    assert record["link"] == audit_id(value)
    assert record["expires"] > record["ts"]
    assert value not in (tmp_path / "audit.jsonl").read_text()


async def test_signin_without_a_ui_url_says_what_to_add_and_makes_no_link(ui, tmp_path):
    database, unit, root = ui
    _ui_unit(unit, root, tmp_path, ui_url=None)
    rc, out = await _ui_ctl(unit, "signin")
    assert rc == 1
    assert "--ui-url" in out
    assert _links(database) == 0 and _records(tmp_path) == []


async def test_signin_without_the_certificate_makes_no_link(ui, tmp_path):
    """Without the fingerprint there is nothing to check the browser's warning
    against, so no link is made."""
    database, unit, root = ui
    (root / "secrets" / "tls.crt").unlink()
    rc, out = await _ui_ctl(unit, "signin")
    assert rc == 1
    assert "tls.crt" in out and "signin?link=" not in out
    assert _links(database) == 0 and _records(tmp_path) == []


async def test_signin_on_loopback_over_plain_http_needs_no_certificate(ui, tmp_path):
    database, unit, root = ui
    (root / "secrets" / "tls.crt").unlink()
    _ui_unit(unit, root, tmp_path, ui_url="http://127.0.0.1:8443")
    rc, out = await _ui_ctl(unit, "signin")
    assert rc == 0, out
    (base, value), = LINK.findall(out)
    assert base == "http://127.0.0.1:8443"
    assert "SHA-256" not in out
    database.use_link(value)


async def test_signin_uses_the_certificate_the_unit_names(ui, tmp_path):
    database, unit, root = ui
    generate_self_signed(tmp_path / "given.crt", tmp_path / "given.key", ["localhost"])
    _ui_unit(unit, root, tmp_path, ui_url="https://nervus.example:8443",
             extra=f"    --tls-cert {tmp_path / 'given.crt'} --tls-key {tmp_path / 'given.key'} \\\n")
    unit.write_text(unit.read_text().replace("    --insecure-plain-http\n", "    --bind-host 127.0.0.1\n"))
    rc, out = await _ui_ctl(unit, "signin")
    assert rc == 0, out
    assert certificate_fingerprint((tmp_path / "given.crt").read_bytes()) in out


async def test_signin_gives_the_renewed_certificates_fingerprint_once_there_is_one(ui, tmp_path):
    """ADR-0021 D1: nervus serves its renewal from the state directory, so that
    is the certificate the browser shows, and the one whose fingerprint counts."""
    from nervus.tls import generate_own_authority, reissue_under_issuer, renewal_path

    database, unit, root = ui
    for name in ("tls.crt", "tls.key"):
        (root / "secrets" / name).unlink()
    generate_own_authority(root / "secrets" / "tls.crt", root / "secrets" / "tls.key", ["nervus.example"],
                           validity_days=10)
    rc, out = await _ui_ctl(unit, "signin")
    assert rc == 0, out
    assert certificate_fingerprint((root / "secrets" / "tls.crt").read_bytes()) in out

    renewed = renewal_path(root / "secrets" / "tls.crt", database.path.parent)
    reissue_under_issuer(root / "secrets" / "tls.crt", root / "secrets" / "tls-issuer.key", renewed)
    rc, out = await _ui_ctl(unit, "signin")
    assert rc == 0, out
    assert certificate_fingerprint(renewed.read_bytes()) in out
    assert certificate_fingerprint((root / "secrets" / "tls.crt").read_bytes()) not in out


async def test_signin_before_nervus_made_its_database_says_so(ui, tmp_path):
    database, unit, _ = ui
    for p in database.path.parent.iterdir():
        p.unlink()
    rc, out = await _ui_ctl(unit, "signin")
    assert rc == 1
    assert "nervus.db" in out
    assert list(database.path.parent.iterdir()) == []  # nervus-ctl never makes it


async def test_signout_all_ends_every_session_and_is_audited(ui, tmp_path):
    database, unit, _ = ui
    sessions = []
    for _ in range(2):
        value, _ = database.make_link()
        sessions.append(database.use_link(value)[0])
    rc, out = await _ui_ctl(unit, "signout", "--all")
    assert rc == 0, out
    assert "2" in out
    assert all(database.session(s) is None for s in sessions)
    record, = _records(tmp_path)
    assert (record["action"], record["target"], record["ended"]) == ("signout", "all", 2)


def test_signout_needs_all():
    with pytest.raises(SystemExit):
        ctl._parser().parse_args(["signout"])


def test_as_root_the_database_is_changed_as_the_units_account(ui, monkeypatch):
    """ADR-0012 decision 3: as root, nervus-ctl changes the database as the
    account nervus runs as, so every file SQLite makes stays that account's.
    Only root can change account, so this checks what is asked of the system;
    a deployed nervus shows the outcome (ADR-0012 verification 5)."""
    import pwd
    import types

    _, unit, _ = ui
    asked = {}
    real_run = subprocess.run

    def run(argv, **kwargs):
        asked.update(kwargs)
        return real_run(argv, **{k: v for k, v in kwargs.items() if k not in ("user", "group", "extra_groups")})

    monkeypatch.setattr(ctl.os, "geteuid", lambda: 0)
    monkeypatch.setattr(ctl.pwd, "getpwnam",
                        lambda name: types.SimpleNamespace(pw_name=name, pw_uid=4242, pw_gid=4343)
                        if name == "nervus" else pwd.getpwnam(name))
    monkeypatch.setattr(ctl.subprocess, "run", run)
    svc = ctl.read_unit(unit)
    ctl.database_change(svc, "make_link")
    assert (asked["user"], asked["group"], asked["extra_groups"]) == (4242, 4343, [])


# --- tokens issued in the UI (ADR-0014 decision C) -----------------------------------


@pytest.fixture
def issued(service, monkeypatch):
    """The installation above with nervus's database made and one token issued
    in it, as the UI would. nervus-ctl, run as the test's own user, reads it."""
    svc, unit, server = service
    database = Database(svc.database)
    database.open()
    database.issue_token("laptop", "codex", "laptop", ["h1"], taken={"t1", "t2"})
    return service


@needs_tmux
async def test_status_lists_issued_tokens_too(issued):
    rc, out = await _ctl(issued, "status")
    assert rc == 0, out
    line = next(l for l in out.splitlines() if l.startswith("laptop "))
    assert " on " in line and "codex/laptop" in line and "issued in the UI" in line


@needs_tmux
async def test_an_issued_token_can_be_switched_off_and_on(issued):
    svc = issued[0]
    rc, out = await _ctl(issued, "lock", "laptop")
    assert rc == 0, out
    assert refusal(svc.switches, "laptop") == "disabled"
    rc, out = await _ctl(issued, "unlock", "laptop")
    assert rc == 0 and refusal(svc.switches, "laptop") is None


@needs_tmux
async def test_without_nervus_database_status_still_shows_the_files_tokens(service):
    rc, out = await _ctl(service, "status")
    assert rc == 0 and "t1 " in out
    assert "issued tokens unknown" in out


@needs_tmux
async def test_nervus_ctl_waits_for_the_ui_and_keeps_its_change(service):
    """ADR-0014 verification 4: the UI is changing the switch file when
    nervus-ctl locks a client. nervus-ctl waits its turn, and both changes land."""
    import threading
    import time

    from nervus.switches import Switches, change_switches

    svc = service[0]
    inside = threading.Event()

    def slow_ui_change(s):
        inside.set()
        time.sleep(0.5)
        return Switches(lockdown=s.lockdown, disabled=s.disabled | {"t2"})

    ui = threading.Thread(target=change_switches, args=(svc.switches, slow_ui_change))
    ui.start()
    assert inside.wait(5)
    rc, out = await _ctl(service, "lock", "t1")
    ui.join()
    assert rc == 0, out
    assert load_switches(svc.switches).disabled == {"t1", "t2"}


# --- the audit log, written as nervus's account (procedure 035) -------------------------


@pytest.fixture
def as_root(monkeypatch):
    """nervus-ctl as root, on a machine where nervus's unit names the account
    `nervus`: every child it runs is asked to be that account (recorded, not
    applied: only root can change account). Any audit record written in
    nervus-ctl's own process, which as root would be root's, fails the test."""
    import pwd
    import types

    from nervus import audit as audit_module

    asked = []
    real_run = subprocess.run

    def run(argv, **kwargs):
        asked.append({k: kwargs.get(k) for k in ("user", "group", "extra_groups")})
        return real_run(argv, **{k: v for k, v in kwargs.items() if k not in ("user", "group", "extra_groups")})

    def as_root_in_process(self, record):
        raise AssertionError(f"nervus-ctl wrote an audit record in its own process, as root: {record['action']}")

    monkeypatch.setattr(ctl.os, "geteuid", lambda: 0)
    monkeypatch.setattr(ctl.pwd, "getpwnam",
                        lambda name: types.SimpleNamespace(pw_name=name, pw_uid=4242, pw_gid=4343)
                        if name == "nervus" else pwd.getpwnam(name))
    monkeypatch.setattr(ctl.subprocess, "run", run)
    monkeypatch.setattr(audit_module.AuditLog, "_append", as_root_in_process)
    return asked


def _operator_actions(audit_log):
    return [json.loads(line)["action"] for line in audit_log.read_text().splitlines() if '"operator"' in line]


def test_as_root_a_sign_in_and_sign_out_are_audited_as_the_units_account(ui, as_root):
    """Found by procedure 035: on a fresh install the installer's
    `nervus-ctl signin`, as root, was the first thing to write nervus's audit
    log, so root made the file and nervus could write nothing after it."""
    _, unit, _ = ui
    svc = ctl.read_unit(unit)
    assert not svc.audit_log.exists()
    assert ctl.signin(svc, io.StringIO()) == 0
    assert ctl.signout(svc, io.StringIO()) == 0
    assert _operator_actions(svc.audit_log) == ["signin", "signout"]
    assert as_root and all(a == {"user": 4242, "group": 4343, "extra_groups": []} for a in as_root)


async def test_as_root_lock_and_unlock_are_audited_as_the_units_account(service, as_root):
    svc, _, _ = service
    assert await ctl.lock(svc, None, False, True, io.StringIO(), lambda _: "") == 0
    assert await ctl.unlock(svc, None, io.StringIO()) == 0
    assert _operator_actions(svc.audit_log)[-2:] == ["lock", "unlock"]
    # This unit names no User=, so the child is whoever runs nervus-ctl; the
    # sign-in test above checks the account when the unit names one.
    assert svc.user is None and len(as_root) >= 2


# --- the tier (ADR-0015 decision E) ----------------------------------------------------


@needs_tmux
async def test_status_shows_the_tier_chosen_at_setup(issued):
    from nervus.first_run import FirstRun
    svc = issued[0]
    rc, out = await _ctl(issued, "status")
    assert rc == 0 and "tier: not chosen yet; choose it on the web UI's setup page" in out
    FirstRun(Database(svc.database)).choose_tier(2, by="operator")
    rc, out = await _ctl(issued, "status")
    assert rc == 0 and "tier: Tier 2: your everyday computer, nervus's own account" in out


@needs_tmux
async def test_without_nervus_database_status_says_the_tier_is_unknown(service):
    rc, out = await _ctl(service, "status")
    assert rc == 0 and "tier unknown: " in out


# --- the release (ADR-0029 question 2a) --------------------------------------------------


@needs_tmux
async def test_status_says_first_which_release_is_installed(service, monkeypatch):
    """An installed nervus knows its own release, and status says it before
    anything else. The number is one of the test's own, put in the package's
    place, so a status that wrote a number in, or read one anywhere but
    `nervus.__version__`, fails whatever the installed number is."""
    import nervus
    monkeypatch.setattr(nervus, "__version__", "0.0.0+this-test")
    rc, out = await _ctl(service, "status")
    assert rc == 0, out
    assert out.splitlines()[:1] == ["release: " + nervus.__version__], out


# --- an upgrade's records (ADR-0029, "Settled already") ------------------------------------

WAS, NOW = "0.2.0-42c0b5a132ef", "0.3.0-09bcc2ef1cd8"


@pytest.mark.parametrize("stage", ctl.UPGRADE_STAGES)
async def test_an_upgrades_start_its_end_and_its_going_back_are_operator_records(ui, stage):
    # ADR-0001 s10: install.sh --upgrade writes each, naming both releases, and why it went back.
    _, unit, _ = ui
    out = io.StringIO()
    assert await ctl.run(["--unit", str(unit), "upgrade-record", stage, WAS, NOW, "--why", "not up"], out=out) == 0
    records = _operator_records(ctl.read_unit(unit))
    assert [(r["action"], r["stage"], r["from"], r["to"], r["why"]) for r in records] == \
        [("upgrade", stage, WAS, NOW, "not up")], out.getvalue()


@pytest.mark.parametrize("was, now", [("0.2.0", NOW), (WAS, "0.3.0-09BCC2EF1CD8"), (WAS, "0.3-09bcc2ef1cd8"),
                                      ("../0.2.0-42c0b5a132ef", NOW), (WAS, "0.3.0-09bcc2ef1cd8 x")])
async def test_an_upgrade_record_names_two_releases_or_records_nothing(ui, was, now):
    _, unit, _ = ui
    out = io.StringIO()
    assert await ctl.run(["--unit", str(unit), "upgrade-record", "begin", was, now], out=out) == 1
    assert "not a release's name" in out.getvalue()
    audit_log = ctl.read_unit(unit).audit_log
    assert not audit_log.exists() or '"upgrade"' not in audit_log.read_text()


def test_as_root_an_upgrade_record_is_written_as_the_units_account(ui, as_root):
    # install.sh runs it as root, so its child, which writes the record, must be nervus's account.
    _, unit, _ = ui
    svc = ctl.read_unit(unit)
    assert ctl.upgrade_record(svc, "begin", WAS, NOW, None, io.StringIO()) == 0
    assert _operator_actions(svc.audit_log) == ["upgrade"]
    assert as_root and all(a == {"user": 4242, "group": 4343, "extra_groups": []} for a in as_root)


# --- the recovery key, piped where there is no terminal (procedure 054, finding 4) --------------------
# getpass, given no terminal, printed Python's GetPassWarning and "Password input may be echoed",
# which a person checking a backup through a pipe, as docs/install.md step 5 says to, would take
# for the key having leaked. With no terminal nothing is echoed anywhere.


def test_the_key_piped_where_there_is_no_terminal_is_read_without_a_false_warning():
    code = ("import inspect, nervus.ctl as ctl\n"
            "read = inspect.signature(ctl.run).parameters['secret'].default\n"
            "print(repr(read('the key: ')))\n")
    # A session of its own has no controlling terminal: /dev/tty does not open, as under a timer.
    done = subprocess.run([sys.executable, "-c", code], input="AGE-SECRET-KEY-1EXAMPLE\n", text=True,
                          capture_output=True, start_new_session=True, timeout=60)
    assert done.returncode == 0, done.stderr
    assert done.stdout == "'AGE-SECRET-KEY-1EXAMPLE'\n"
    assert done.stderr == "the key: \n"


def test_nothing_piped_where_there_is_no_terminal_is_an_end_of_input():
    code = "import nervus.ctl as ctl\nctl.read_secret('the key: ')\n"
    done = subprocess.run([sys.executable, "-c", code], input="", text=True, capture_output=True,
                          start_new_session=True, timeout=60)
    assert done.returncode == 1 and "EOFError" in done.stderr


def test_with_a_terminal_the_key_is_read_there_by_getpass(monkeypatch):
    """Procedure 047, finding 2, kept: whenever /dev/tty opens, getpass reads the key there, even
    with something piped in."""
    real_open = os.open
    monkeypatch.setattr(ctl.os, "open", lambda path, flags, *rest: real_open(os.devnull, os.O_RDONLY)
                        if path == "/dev/tty" else real_open(path, flags, *rest))
    monkeypatch.setattr(ctl.getpass, "getpass", lambda prompt: f"read from the terminal after {prompt!r}")
    assert ctl.read_secret("the key: ") == "read from the terminal after 'the key: '"
