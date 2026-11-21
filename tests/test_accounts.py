"""ADR-0031 step 3: the account a connection logs in to, chosen in one place.

- **The choice** (`accounts.choose`): read-only where the token's assignment
  or the machine itself is read-only, through the machine's read-only account;
  otherwise the machine's read-write account at its own level. A read-only
  call to a machine with no read-only account is refused, saying how its owner
  adds one; nothing runs.
- **What nervus knows of a machine's accounts** (`merged`, `as_host`): a
  machine added before this release keeps `agent`; one added since has the
  accounts its enrollment recorded, but only while that record is tied to the
  enrollment it was made for, so a row an older release left stale is not
  believed; a machine described by hand has the account its entry names and
  the read-only account its owner added.
- **The connection** (`ssh.connect`): every connection made for a client's call
  carries the choice, and one that does not, or names another account, is
  refused before anything is sent; a read-only one offers only a certificate
  naming the read-only account and carrying the read-only shell, never the
  plain key.
- **`~/.nervus` is its account's alone** wherever nervus uses it.
"""

import dataclasses
import os
import subprocess
from pathlib import Path

import asyncssh
import pytest

from nervus import accounts, certs, jobs, ssh
from nervus.auth import Token
from nervus.certs import CertificateAuthority, Route
from nervus.config import Host
from nervus.database import Database
from nervus.enrolled_hosts import EnrolledHost, EnrolledHostStore, merged

RUN = "0b9f4c2e-5d1a-4e8b-9c3f-7a6d2e1b0c94"
MID = "0123456789abcdef0123456789abcdef"
KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMyVrCBvJ0Hw6blUHEIrmuP7F/811pBvedzyqJwJl0ca"


@pytest.fixture(autouse=True)
def _no_caller():
    token = certs._caller.set(None)
    yield
    certs._caller.reset(token)


def _token(readonly=(), hosts=("m",)) -> Token:
    return Token(id="t", client="c", project="p", hosts=frozenset(hosts), readonly=frozenset(readonly))


def _host(**kw) -> Host:
    base = dict(name="m", address="192.0.2.10", os="", role="r", agent_user="nervusagent", status="onboarded")
    return Host(**{**base, **kw})


# --- the choice ---------------------------------------------------------------------------


def test_a_token_read_only_on_a_machine_with_both_accounts_goes_through_the_read_only_one():
    host = _host(level="full", readonly_user="nervusagent-readonly")
    assert accounts.choose(_token(readonly=("m",)), host) == Route("m", "nervusagent-readonly", True, "read-only")


def test_a_token_read_write_there_goes_through_the_read_write_account_at_the_machine_s_level():
    host = _host(level="full", readonly_user="nervusagent-readonly")
    assert accounts.choose(_token(), host) == Route("m", "nervusagent", False, "full")


def test_on_a_machine_that_is_read_only_every_token_is_read_only():
    host = _host(level="read-only", agent_user="agent", readonly_user="agent")
    assert accounts.choose(_token(), host) == Route("m", "agent", True, "read-only")


def test_a_read_only_call_where_there_is_no_read_only_account_is_refused_saying_how_to_add_one():
    host = _host(level="standard", agent_user="agent", readonly_user=None)
    with pytest.raises(accounts.NoReadOnlyAccount) as refused:
        accounts.choose(_token(readonly=("m",)), host)
    assert "Machines page" in str(refused.value) and "nothing" in str(refused.value).lower()


def test_a_machine_described_by_hand_is_read_write_at_a_level_nervus_does_not_know():
    host = _host(agent_user="agent", readonly_user="nervusagent-readonly")  # no level
    assert accounts.choose(_token(), host) == Route("m", "agent", False, "read-write")
    assert accounts.choose(_token(readonly=("m",)), host).username == "nervusagent-readonly"


def test_the_operator_s_own_work_is_read_write_unless_the_machine_is_read_only():
    assert accounts.choose(None, _host(level="standard")).readonly is False
    assert accounts.choose(None, _host(level="read-only", readonly_user="agent")).readonly is True


def test_a_vm_used_by_its_id_is_agent_at_full():
    assert accounts.vm_route(123) == Route("vmid 123", "agent", False, "full")


# --- what nervus knows of a machine's accounts -------------------------------------------------


@pytest.fixture
def stores(tmp_path):
    db = Database(tmp_path / "nervus.db")
    db.open()
    return EnrolledHostStore(db), accounts.MachineAccounts(db)


def _enroll(store, name="m", level="standard", now=1_800_000_000.0) -> EnrolledHost:
    row, _ = store.add(name, address="192.0.2.10", level=level, host_keys=[KEY], machine_id=MID,
                       enrolled_by="operator", now=now)
    return row


@pytest.mark.parametrize("level,agent,readonly", [("read-only", "agent", "agent"),
                                                  ("standard", "agent", None), ("full", "agent", None)])
def test_a_machine_added_before_this_release_keeps_agent(stores, level, agent, readonly):
    enrolled, _ = stores
    _enroll(enrolled, level=level)
    host = merged({}, enrolled, stores[1])["m"]
    assert (host.agent_user, host.readonly_user, host.level) == (agent, readonly, level)


def test_one_added_since_has_the_accounts_its_enrollment_recorded(stores):
    enrolled, machine_accounts = stores
    row = _enroll(enrolled, level="full")
    machine_accounts.record("m", enrolled_at=row.enrolled_at, readwrite="nervusagent",
                            readonly="nervusagent-readonly", groups=[], why_none=None)
    host = merged({}, enrolled, machine_accounts)["m"]
    assert (host.agent_user, host.readonly_user) == ("nervusagent", "nervusagent-readonly")


def test_at_read_only_alone_the_one_account_is_the_read_only_one(stores):
    enrolled, machine_accounts = stores
    row = _enroll(enrolled, level="read-only")
    machine_accounts.record("m", enrolled_at=row.enrolled_at, readwrite=None, readonly="nervusagent-readonly",
                            groups=[], why_none=None)
    host = merged({}, enrolled, machine_accounts)["m"]
    assert (host.agent_user, host.readonly_user) == ("nervusagent-readonly", "nervusagent-readonly")
    assert accounts.choose(_token(), host) == Route("m", "nervusagent-readonly", True, "read-only")


def test_a_record_left_by_an_enrollment_since_replaced_is_not_believed(stores):
    """Note 2: a release before this one adds the machine again; the row it
    leaves is not this enrollment's, so the machine is read as one from before."""
    enrolled, machine_accounts = stores
    row = _enroll(enrolled, level="full")
    machine_accounts.record("m", enrolled_at=row.enrolled_at, readwrite="nervusagent",
                            readonly="nervusagent-readonly", groups=[], why_none=None)
    _enroll(enrolled, level="full", now=row.enrolled_at + 60)  # added again, by a release that knows no accounts
    host = merged({}, enrolled, machine_accounts)["m"]
    assert (host.agent_user, host.readonly_user) == ("agent", None)


def test_a_machine_described_by_hand_gains_the_read_only_account_its_owner_added(stores):
    enrolled, machine_accounts = stores
    by_hand = {"m": _host(agent_user="agent")}
    assert merged(by_hand, enrolled, machine_accounts)["m"].readonly_user is None
    machine_accounts.record("m", enrolled_at=None, readwrite=None, readonly="nervusagent-readonly",
                            groups=["adm"], why_none=None)
    host = merged(by_hand, enrolled, machine_accounts)["m"]
    assert (host.agent_user, host.readonly_user) == ("agent", "nervusagent-readonly")


def test_where_no_read_only_account_could_be_made_there_is_none(stores):
    enrolled, machine_accounts = stores
    row = _enroll(enrolled, level="standard")
    machine_accounts.record("m", enrolled_at=row.enrolled_at, readwrite="nervusagent", readonly=None,
                            groups=[], why_none="bubblewrap cannot run here")
    host = merged({}, enrolled, machine_accounts)["m"]
    assert (host.agent_user, host.readonly_user) == ("nervusagent", None)
    assert machine_accounts.get("m").why_none == "bubblewrap cannot run here"


# --- the connection ------------------------------------------------------------------------------


@pytest.fixture
def ca(tmp_path) -> CertificateAuthority:
    key = asyncssh.generate_private_key("ssh-ed25519")
    path = tmp_path / "ca"
    path.write_bytes(key.export_private_key())
    path.chmod(0o600)
    return CertificateAuthority(path)


@pytest.fixture
def offered(tmp_path, monkeypatch):
    """What nervus would offer the machine: the SSH library's connect, caught."""
    seen: dict = {}

    async def fake_connect(address, port, **kwargs):
        seen.update(kwargs, address=address)
        raise asyncssh.PermissionDenied("stopped by the test")

    monkeypatch.setattr(ssh.asyncssh, "connect", fake_connect)
    key = asyncssh.generate_private_key("ssh-ed25519")
    path = tmp_path / "nervus"
    path.write_bytes(key.export_private_key())
    seen["key_path"] = path
    known = tmp_path / "known"
    known.write_text("")
    seen["known"] = known
    return seen


async def _open(offered, username, authority):
    return await ssh.connect(address="192.0.2.10", username=username, client_keys=[offered["key_path"]],
                             known_hosts=offered["known"], authority=authority, machine="m")


async def test_a_client_s_connection_that_did_not_come_through_the_choice_is_refused(offered, ca):
    certs.acting_for("t", RUN)
    with pytest.raises(ssh.NotChosen):
        await _open(offered, "nervusagent", ca)
    assert "username" not in offered  # nothing was sent


async def test_one_naming_another_account_than_the_choice_is_refused(offered, ca):
    certs.acting_for("t", RUN)
    certs.take(Route("m", "nervusagent-readonly", True, "read-only"))
    with pytest.raises(ssh.NotChosen):
        await _open(offered, "nervusagent", ca)
    assert "username" not in offered


def _signing(ca) -> list:
    """The certificates `ca` signs from here on, kept for the test."""
    signed, sign = [], ca.sign

    def keep(*args, **kwargs):
        signed.append(sign(*args, **kwargs))
        return signed[-1]

    ca.sign = keep
    return signed


def _as_offered(client_keys) -> list:
    """What the SSH library offers the machine for `client_keys`, in order: a key given with a
    certificate is offered as the certificate, and then as itself (asyncssh's load_keypairs)."""
    return asyncssh.load_keypairs(list(client_keys))


async def test_a_read_only_connection_offers_only_a_certificate_carrying_the_read_only_shell(offered, ca):
    certs.acting_for("t", RUN)
    certs.take(Route("m", "nervusagent-readonly", True, "read-only"))
    signed = _signing(ca)
    with pytest.raises(asyncssh.PermissionDenied):
        await _open(offered, "nervusagent-readonly", ca)
    pairs = _as_offered(offered["client_keys"])
    assert signed and [p.public_data for p in pairs] == [c.public_data for c in signed], "a plain key was offered"
    for cert in signed:
        assert cert.principals == ["nervusagent-readonly"]
        assert cert.options["force-command"] == certs.READONLY_SHELL == "/usr/local/lib/nervus/readonly-shell"


async def test_a_machine_admitting_only_nervus_s_plain_key_refuses_a_read_only_call(ssh_server, ca):
    """Question 1a on the wire (procedure 068, section 12): given a key with its certificate, the SSH
    library offers the certificate and then the bare key, so a machine whose line admits nervus's plain
    key with no forced command would have run a read-only call unconfined. This one trusts the plain
    key and not the authority: it must refuse the call."""
    certs.acting_for("t", RUN)
    certs.take(Route("m", ssh_server.username, True, "read-only"))
    try:
        conn = await ssh.connect(address=ssh_server.host, port=ssh_server.port, username=ssh_server.username,
                                 client_keys=[ssh_server.client_key_path], known_hosts=ssh_server.known_hosts_path,
                                 authority=ca, machine="m")
    except asyncssh.PermissionDenied:
        return
    conn.close()  # so the server's close does not wait on it
    pytest.fail("a machine that admits only nervus's plain key admitted a read-only call")


async def test_the_same_machine_still_admits_a_read_write_call_by_the_plain_key(ssh_server, ca):
    """A machine not yet moved to the CA still accepts nervus for a read-write call, as before."""
    certs.acting_for("t", RUN)
    certs.take(Route("m", ssh_server.username, False, "full"))
    conn = await ssh.connect(address=ssh_server.host, port=ssh_server.port, username=ssh_server.username,
                             client_keys=[ssh_server.client_key_path], known_hosts=ssh_server.known_hosts_path,
                             authority=ca, machine="m")
    conn.close()


async def test_without_the_ca_a_read_only_connection_is_refused_before_anything_is_sent(offered):
    certs.acting_for("t", RUN)
    certs.take(Route("m", "nervusagent-readonly", True, "read-only"))
    with pytest.raises(ssh.NotChosen):
        await _open(offered, "nervusagent-readonly", None)
    assert "username" not in offered


async def test_a_read_write_connection_offers_the_certificate_then_the_plain_key_as_before(offered, ca):
    certs.acting_for("t", RUN)
    certs.take(Route("m", "nervusagent", False, "full"))
    signed = _signing(ca)
    with pytest.raises(asyncssh.PermissionDenied):
        await _open(offered, "nervusagent", ca)
    first, second = _as_offered(offered["client_keys"])
    (cert,) = signed
    assert first.public_data == cert.public_data and "force-command" not in cert.options
    assert second.public_data == cert.key.public_data  # the plain key, after it


async def test_the_operator_s_own_work_may_connect_unchosen_as_before(offered, ca):
    certs.acting_for(None, RUN)
    with pytest.raises(asyncssh.PermissionDenied):
        await _open(offered, "agent", ca)
    assert offered["username"] == "agent"


async def test_the_operator_s_read_only_work_is_signed_read_only_too(offered, ca):
    certs.acting_for(None, RUN)
    certs.take(Route("m", "nervusagent-readonly", True, "read-only"))
    signed = _signing(ca)
    with pytest.raises(asyncssh.PermissionDenied):
        await _open(offered, "nervusagent-readonly", ca)
    assert [p.public_data for p in _as_offered(offered["client_keys"])] == [c.public_data for c in signed]


def test_the_certificate_s_forced_command_is_set_only_when_asked(ca, tmp_path):
    key = asyncssh.generate_private_key("ssh-ed25519")
    caller = certs.Caller("t", RUN)
    assert "force-command" not in ca.sign(key, "nervusagent", caller).options
    forced = ca.sign(key, "nervusagent-readonly", caller, force_command=certs.READONLY_SHELL)
    assert forced.options["force-command"] == certs.READONLY_SHELL


# --- ~/.nervus, its account's alone ---------------------------------------------------------------


def _run_head(script: str, home: Path) -> None:
    """The lines of nervus's script before the client's command, as bash runs them."""
    head = script.split("{\n", 1)[0]
    subprocess.run(["bash", "-c", head.replace("set -o pipefail\n", "") + "\ntrue"], check=True,
                   env={**os.environ, "HOME": str(home)})


@pytest.mark.parametrize("build", [
    lambda: ssh.build_exec_script("r-1", "~", "true")[0],
    lambda: jobs.build_job_script("j-1", "~", "true")[0].split("tmux new-session")[0],
])
def test_nervus_s_folder_is_made_its_account_s_alone_even_if_it_was_open_before(tmp_path, build):
    home = tmp_path / "home"
    (home / ".nervus").mkdir(parents=True)
    (home / ".nervus").chmod(0o775)  # as some machines have it, and as mkdir -p made it on the trial VM
    _run_head(build(), home)
    assert ((home / ".nervus").stat().st_mode & 0o777) == 0o700


def test_a_folder_that_cannot_be_made_private_stops_the_call(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    (home / ".nervus").write_text("a file where the folder should be")
    script, _ = ssh.build_exec_script("r-1", "~", "echo ran")
    run = subprocess.run(["bash", "-s"], input=script, capture_output=True, text=True,
                         env={**os.environ, "HOME": str(home)})
    assert run.returncode == 96 and "ran" not in run.stdout


# --- the whole path, through a tool call -------------------------------------------------------

from nervus.audit import AuditLog  # noqa: E402
from nervus.server import build_server  # noqa: E402

from test_server import _call_tool, _settings  # noqa: E402

LIMITED, PLAIN = "sekret-limited", "sekret-plain"


def _built(tmp_path, ssh_server, ca, readonly_user="nervusagent-readonly"):
    settings = _settings(tmp_path, ssh_server)
    host = dataclasses.replace(settings.hosts["testhost"], agent_user="nervusagent", level="full",
                               readonly_user=readonly_user)
    settings = dataclasses.replace(settings, hosts={"testhost": host}, ssh_ca=ca)
    tokens = {LIMITED: Token(id="t-limited", client="c", project="p", hosts=frozenset({"testhost"}),
                             readonly=frozenset({"testhost"})),
              PLAIN: Token(id="t-plain", client="c", project="p", hosts=frozenset({"testhost"}))}
    return build_server(settings=settings, tokens=tokens, audit=AuditLog(path=settings.audit_log_path)), settings


def _records(settings):
    import json
    return [json.loads(line) for line in settings.audit_log_path.read_text().splitlines()]


async def test_a_read_only_exec_logs_in_as_the_read_only_account_and_says_so_in_its_record(
        tmp_path, ssh_server, ca, offered):
    mcp_server, settings = _built(tmp_path, ssh_server, ca)
    signed = _signing(ca)
    result = await _call_tool(mcp_server, LIMITED, "exec", {"host": "testhost", "command": "true"})
    assert result.is_error  # the test's stand-in refused the login; what nervus offered is what matters
    assert offered["username"] == "nervusagent-readonly"
    assert signed and all(c.options["force-command"] == certs.READONLY_SHELL for c in signed)
    assert [p.public_data for p in _as_offered(offered["client_keys"])] == [c.public_data for c in signed]
    intent = next(r for r in _records(settings) if r["tool"] == "exec" and r["phase"] == "intent")
    assert (intent["user"], intent["level"]) == ("nervusagent-readonly", "read-only")


async def test_the_same_machine_read_write_for_another_token_logs_in_as_its_read_write_account(
        tmp_path, ssh_server, ca, offered):
    mcp_server, settings = _built(tmp_path, ssh_server, ca)
    signed = _signing(ca)
    await _call_tool(mcp_server, PLAIN, "exec", {"host": "testhost", "command": "true"})
    assert offered["username"] == "nervusagent"
    (cert,) = signed
    assert [p.public_data for p in _as_offered(offered["client_keys"])] == [cert.public_data, cert.key.public_data]
    intent = next(r for r in _records(settings) if r["tool"] == "exec" and r["phase"] == "intent")
    assert (intent["user"], intent["level"]) == ("nervusagent", "full")


async def test_where_there_is_no_read_only_account_the_call_is_refused_with_a_record_and_nothing_is_sent(
        tmp_path, ssh_server, ca, offered):
    mcp_server, settings = _built(tmp_path, ssh_server, ca, readonly_user=None)
    result = await _call_tool(mcp_server, LIMITED, "exec", {"host": "testhost", "command": "true"})
    assert result.is_error and "no read-only account" in result.content[0].text
    assert "username" not in offered
    refusal = [r for r in _records(settings) if r["tool"] == "exec"]
    assert [r["phase"] for r in refusal] == ["refused"]
    assert refusal[0]["level"] == "read-only" and "Machines page" in refusal[0]["reason"]


def test_the_accounts_of_a_machine_described_by_hand_are_those_of_every_entry_at_its_address():
    """Procedure 068, section 12: one machine may be two entries, behind two accounts (ADR-0009)."""
    def entry(name, address, user, **more):
        return Host(name=name, address=address, os="", role="r", agent_user=user, status="onboarded", **more)
    hosts = {"hv": entry("hv", "hv.example", "observer"),
             "hv-root": entry("hv-root", "hv.example", "agent", never_issued=True),
             "web": entry("web", "web.example", "deploy")}
    assert accounts.accounts_at(hosts, "hv") == {"observer", "agent"}
    assert accounts.accounts_at(hosts, "web") == {"deploy"}


async def test_a_connection_for_another_machine_than_the_one_chosen_is_refused(offered, ca):
    """Procedure 068, section 12: an account is chosen on one machine; a connection to another under the
    same account's name is refused before anything is sent."""
    certs.acting_for("t", RUN)
    certs.take(Route("m", "nervusagent", False, "full"))
    with pytest.raises(ssh.NotChosen):
        await ssh.connect(address="192.0.2.10", username="nervusagent", client_keys=[offered["key_path"]],
                          known_hosts=offered["known"], authority=ca, machine="elsewhere")
    with pytest.raises(ssh.NotChosen):  # and one that does not say which machine it is for
        await ssh.connect(address="192.0.2.10", username="nervusagent", client_keys=[offered["key_path"]],
                          known_hosts=offered["known"], authority=ca)
    assert "username" not in offered


async def test_connect_host_says_which_machine_it_connects_to(tmp_path, ssh_server, ca, offered):
    from nervus.server import connect_host
    _, settings = _built(tmp_path, ssh_server, ca)
    certs.acting_for("t", RUN)
    certs.take(Route("testhost", "nervusagent", False, "full"))
    elsewhere = Host(name="elsewhere", address="192.0.2.11", os="", role="r", agent_user="nervusagent",
                     status="onboarded")
    with pytest.raises(ssh.NotChosen):
        await connect_host(settings, elsewhere)
    assert "username" not in offered


async def test_the_vm_connector_says_which_vm_it_connects_to(offered, ca):
    from nervus.enroller import ssh_connector
    certs.acting_for("t", RUN)
    certs.take(accounts.vm_route(123))
    key = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode().strip()
    connect = ssh_connector(offered["key_path"], authority=ca)
    with pytest.raises(ssh.NotChosen):
        await connect("192.0.2.12", (key,), machine=accounts.vm_name(124))
    assert "username" not in offered
