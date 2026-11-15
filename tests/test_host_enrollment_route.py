"""The enrollment route (ADR-0024 step 3, decisions 2 and 6): GET /enroll/<code>
serves the script for the code's machine and level; POST takes the machine's
host keys and machine id back, refuses full access to nervus's own machine,
logs in as agent with only those keys pinned, checks the level, and only then
adds the machine. Plain HTTP and lockdown enroll nothing.

A real SSH server on loopback plays the machine, its commands run by a real
shell whose `id` and `sudo` are stood in for, so each level can be played.
Real curl, against a real HTTPS server, shows the pin holds with `-k`.

A code made from nervus's page (ADR-0026 step 2) also keeps the host key that
answered its login; a report whose own host keys do not include it is refused
before any SSH."""

import base64
import json
import shlex
import shutil
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import asyncssh
import httpx
import pytest
from cryptography import x509
from starlette.applications import Starlette
from starlette.routing import Route

from nervus.audit import AuditLog
from nervus.database import Database
from nervus.enrolled_hosts import EnrolledHostStore
from nervus import certs
from nervus.enroller import ssh_connector
from nervus.enrollment_codes import EnrollmentCodes
from nervus.host_enrollment import (HTTPS_ONLY, NOT_ITS_OWN, UNKNOWN, HostEnrollment, check_failed,
                                    enroll_endpoint)
from nervus.tls import generate_self_signed, key_fingerprint, key_pin

PIN = "sha256//47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
NERVUS_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeNervusKeyForTheseTestsOnly0123456789ab nervus"
MACHINE = "0123456789abcdef0123456789abcdef"
OWN = "fedcba9876543210fedcba9876543210"


class World:
    def __init__(self, tmp_path, ssh_server, monkeypatch):
        db = Database(tmp_path / "nervus.db")
        db.open()
        self.codes, self.store = EnrollmentCodes(db), EnrolledHostStore(db)
        self.audit_path = tmp_path / "audit.jsonl"
        self.audit = AuditLog(path=self.audit_path)
        self.host_key = open(ssh_server.known_hosts_path).read().split(" ", 1)[1].strip()
        self.pin, self.locked, self.reserved, self.own = PIN, False, {"in-hosts-yaml"}, OWN
        self.connects = []
        real = ssh_connector(Path(ssh_server.client_key_path), ssh_server.port)

        self.callers = []

        def connect(address, keys):
            self.connects.append((address, keys))
            self.callers.append(certs.current())  # who the certificate would name (ADR-0025)
            return real(address, keys)

        self.enrollment = HostEnrollment(
            self.codes, self.store, self.audit, key=lambda: NERVUS_KEY, connect=connect, pin=lambda: self.pin,
            own_machine_id=OWN, reserved=lambda: self.reserved, locked=lambda: self.locked)
        # The machine's shell: `id -un` is agent, sudo is the level's, HOME is agent's.
        self.bin, self.home = tmp_path / "machine-bin", tmp_path / "home-agent"
        self.bin.mkdir()
        self.home.mkdir()
        (self.bin / "id").write_text('#!/bin/sh\n[ "$*" = -un ] && echo agent\n')
        monkeypatch.setenv("PATH", f"{self.bin}:/usr/bin:/bin")
        monkeypatch.setenv("HOME", str(self.home))
        self.play("standard")

    def play(self, level, *, sudo=None, writes=None):
        sudo = (level == "full") if sudo is None else sudo
        writes = (level != "read-only") if writes is None else writes
        (self.bin / "sudo").write_text("#!/bin/sh\necho root\n" if sudo else "#!/bin/sh\nexit 1\n")
        for name in ("id", "sudo"):
            (self.bin / name).chmod(0o755)
        self.home.chmod(0o700 if writes else 0o500)

    def make(self, level="standard", name="web", address="127.0.0.1"):
        value, code = self.codes.make(name=name, address=address, level=level, made_by="operator")
        return value, code

    def make_with_login(self, key=None, level="standard", name="web", address="127.0.0.1", login="alice"):
        """A code as nervus's page makes it: with the account it logs in as and the host key that answered
        (by default, the one the test machine's SSH server has)."""
        return self.codes.make(name=name, address=address, level=level, made_by="operator", login=login,
                               host_key=self.host_key if key is None else key)

    def client(self):
        app = Starlette(routes=[Route("/enroll/{code}", enroll_endpoint(self.enrollment), methods=["GET", "POST"])])
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://192.0.2.1:8000")

    async def get(self, value):
        async with self.client() as c:
            return await c.get(f"/enroll/{value}")

    async def post(self, value, body=None, machine_id=MACHINE, keys=None):
        if body is None:
            body = f"machine-id {machine_id}\n" + "".join(k + "\n" for k in (keys or [self.host_key]))
        async with self.client() as c:
            return await c.post(f"/enroll/{value}", content=body)

    @property
    def records(self):
        if not self.audit_path.exists():
            return []
        return [json.loads(line) for line in self.audit_path.read_text().splitlines()]


@pytest.fixture
def world(tmp_path, ssh_server, monkeypatch):
    world = World(tmp_path, ssh_server, monkeypatch)
    yield world
    world.home.chmod(0o700)


# --- GET: the script -----------------------------------------------------------

async def test_a_code_fetches_the_script_for_its_machine_and_level(world):
    value, code = world.make("read-only")
    answer = await world.get(value)
    assert answer.status_code == 200 and answer.headers["content-type"].startswith("text/plain")
    script = answer.text
    assert "enroll this machine as web, read-only." in script and "at https://192.0.2.1:8000" in script
    assert f"url=https://192.0.2.1:8000/enroll/{value}\n" in script
    assert f"pin={shlex.quote(PIN)}\n" in script and f"key='{NERVUS_KEY}'" in script


async def test_it_may_be_fetched_again_while_unspent(world):
    value, _ = world.make()
    assert (await world.get(value)).status_code == 200
    assert (await world.get(value)).status_code == 200


async def test_a_head_request_spends_nothing(world):
    """Procedure 056. Starlette answers HEAD on a route that takes GET, and the endpoint took every request
    that was not a GET for the machine's report: a HEAD, from a link preview or a checker, spent the one-time
    code, and the machine then got a 404 for its script. A HEAD is a GET without its body."""
    value, code = world.make()
    async with world.client() as c:
        head = await c.head(f"/enroll/{value}")
    assert head.status_code == 200
    assert world.codes.get(code.id).used_at is None
    assert (await world.get(value)).status_code == 200
    assert (await world.post(value)).status_code == 200


async def test_an_unknown_code_fetches_nothing(world):
    answer = await world.get("not-a-code")
    assert answer.status_code == 404 and UNKNOWN in answer.text


async def test_each_fetch_is_audited_under_the_code_id_never_the_code(world):
    value, code = world.make()
    await world.get(value)
    await world.get("not-a-code")
    intent, result, refused = world.records
    assert (intent["phase"], intent["tool"], intent["actor"], intent["action"]) == ("intent", "enroll", "operator",
                                                                                    "fetch")
    assert intent["code_id"] == code.id and intent["level"] == "standard" and result["served"] is True
    assert refused["phase"] == "refused" and "unknown" in refused["reason"]
    assert value not in world.audit_path.read_text()


# --- POST: the report ----------------------------------------------------------

async def test_a_report_is_checked_over_ssh_with_its_keys_pinned_then_enrolled(world):
    value, code = world.make("standard")
    answer = await world.post(value)
    assert answer.status_code == 200, answer.text
    assert answer.text == ("nervus: web is enrolled, standard. In nervus's page, give a token this machine "
                           "to let a client use it.\n")
    row = world.store.get("web")
    assert (row.address, row.level, row.machine_id, row.enrolled_by) == ("127.0.0.1", "standard", MACHINE,
                                                                         "operator")
    assert row.host_keys == (" ".join(world.host_key.split()[:2]),)
    assert world.connects == [("127.0.0.1", row.host_keys)]
    assert world.codes.get(code.id).outcome == "enrolled web, standard"
    result = world.records[-1]
    assert result["enrolled"] is True and result["machine_id"] == MACHINE and result["host_keys"] == list(row.host_keys)


@pytest.mark.parametrize("level", ["read-only", "standard", "full"])
async def test_each_level_is_enrolled_when_the_machine_is_that_level(world, level):
    world.play(level)
    value, _ = world.make(level)
    assert (await world.post(value)).status_code == 200
    assert world.store.get("web").level == level


async def test_a_code_without_an_address_enrolls_the_machine_where_its_report_came_from(world):
    value, _ = world.make(address="")
    assert (await world.post(value)).status_code == 200  # the test client's address is 127.0.0.1
    assert world.store.get("web").address == "127.0.0.1" and world.connects[0][0] == "127.0.0.1"
    assert world.records[-1]["address"] == "127.0.0.1"


async def test_a_code_with_an_address_enrolls_it_there_whatever_the_report_came_from(world):
    value, _ = world.make(address="localhost")
    assert (await world.post(value)).status_code == 200
    assert world.store.get("web").address == "localhost" and world.connects[0][0] == "localhost"


async def test_a_code_reports_once(world):
    value, _ = world.make()
    assert (await world.post(value)).status_code == 200
    again = await world.post(value)
    assert again.status_code == 404 and UNKNOWN in again.text
    assert (await world.get(value)).status_code == 404


async def test_a_server_at_that_address_with_other_keys_is_refused(world):
    other = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode().strip()
    value, code = world.make()
    answer = await world.post(value, keys=[other])
    assert answer.status_code == 422 and "other host keys than this machine sent" in answer.text
    assert world.store.get("web") is None
    assert world.codes.get(code.id).outcome.startswith("refused: ")
    assert (await world.post(value)).status_code == 404  # spent: a new code to try again


async def test_full_access_to_nervus_own_machine_is_refused_before_any_login(world):
    world.play("full")
    value, _ = world.make("full")
    answer = await world.post(value, machine_id=OWN)
    assert answer.status_code == 403 and "the machine nervus runs on" in answer.text
    assert "standard or read-only" in answer.text
    assert world.connects == [] and world.store.get("web") is None


async def test_read_only_on_nervus_own_machine_is_allowed(world):
    world.play("read-only")
    value, _ = world.make("read-only")
    assert (await world.post(value, machine_id=OWN)).status_code == 200


async def test_a_full_script_carries_nervus_machine_id_only_hashed_with_its_code(world):
    from nervus.host_enrollment import own_hash
    value, _ = world.make("full")
    script = (await world.get(value)).text
    assert f"own={own_hash(value, OWN)}\n" in script and OWN not in script


async def test_without_its_own_machine_id_nervus_serves_no_full_script(world):
    world.enrollment.own_machine_id = None
    value, _ = world.make("full")
    answer = await world.get(value)
    assert answer.status_code == 403 and "cannot read its own machine id" in answer.text
    assert (await world.get(world.make("standard", name="other")[0])).status_code == 200


async def test_without_its_own_machine_id_nervus_refuses_full_everywhere(world):
    world.enrollment.own_machine_id = None
    value, _ = world.make("full")
    answer = await world.post(value)
    assert answer.status_code == 403 and "cannot read its own machine id" in answer.text


@pytest.mark.parametrize("level, play, says", [
    ("standard", dict(sudo=True), "can still use sudo"),
    ("read-only", dict(sudo=True), "can still use sudo"),
    ("read-only", dict(writes=True), "read-only shell is not in force"),
    ("full", dict(sudo=False), "cannot use sudo"),
])
async def test_a_machine_that_is_not_its_level_is_not_added(world, level, play, says):
    world.play(level, **play)
    value, _ = world.make(level)
    answer = await world.post(value)
    assert answer.status_code == 422 and says in answer.text and world.store.get("web") is None


@pytest.mark.parametrize("seen, says", [
    (["agent", "no-sudo", "writes"], None),
    (["root", "root", "writes"], "not as agent"),
    ([], "not as agent"),
    (["agent", "no-sudo", "no-writes"], "cannot write in its own home"),
])
def test_what_the_check_concludes_for_standard(seen, says):
    why = check_failed("standard", seen)
    assert why is None if says is None else says in why


@pytest.mark.parametrize("body, says", [
    ("", "machine id"),
    (f"ssh-ed25519 AAAA\nmachine-id {MACHINE}\n", "machine id"),
    ("machine-id XYZ\n", "is not a machine id"),
    (f"machine-id {MACHINE}\nnot a key\n", "is not an SSH host public key"),
    (f"machine-id {MACHINE}\n", "no host key"),
])
async def test_a_report_that_is_not_one_is_refused(world, body, says):
    value, _ = world.make()
    answer = await world.post(value, body=body)
    assert answer.status_code == 400 and says in answer.text and world.connects == []


async def test_a_name_hosts_yaml_gained_since_the_code_was_made_is_not_taken(world):
    value, _ = world.make(name="newbox")
    world.reserved = {"newbox"}
    answer = await world.post(value)
    assert answer.status_code == 409 and "hosts.yaml" in answer.text and world.store.get("newbox") is None


async def test_a_report_too_large_is_refused(world):
    value, _ = world.make()
    answer = await world.post(value, body="x" * (64 * 1024 + 1))
    assert answer.status_code == 413 and world.codes.find(value) is not None


async def test_re_enrolling_says_what_the_level_was(world):
    value, _ = world.make("standard")
    await world.post(value)
    world.play("read-only")
    value, _ = world.make("read-only")
    answer = await world.post(value)
    assert "It was standard before." in answer.text and world.records[-1]["replaced"] is True


# --- A code made with a login: the key that answered it must be the machine's own (ADR-0026) ----

def _other_key():
    return asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode().strip()


async def test_a_code_made_with_a_login_enrolls_when_its_key_is_among_those_reported(world):
    value, code = world.make_with_login()
    answer = await world.post(value)
    assert answer.status_code == 200, answer.text
    assert world.store.get("web").host_keys == (" ".join(world.host_key.split()[:2]),)
    assert len(world.connects) == 1 and world.codes.get(code.id).outcome == "enrolled web, standard"


async def test_one_of_several_reported_keys_is_enough(world):
    """A machine reports every host key it has; the login met one of them."""
    value, _ = world.make_with_login()
    answer = await world.post(value, keys=[_other_key(), world.host_key, _other_key()])
    assert answer.status_code == 200, answer.text
    assert len(world.store.get("web").host_keys) == 3


async def test_the_key_is_compared_as_the_store_keeps_it_not_as_the_machine_wrote_it(world):
    value, _ = world.make_with_login(key=world.host_key + " root@the-machine")
    answer = await world.post(value, keys=[world.host_key + " a-different-comment"])
    assert answer.status_code == 200, answer.text


async def test_a_report_without_the_key_that_answered_the_login_is_refused_before_any_ssh(world):
    value, code = world.make_with_login(key=_other_key())
    answer = await world.post(value)  # the machine's own keys, which do not include the one that answered
    message = NOT_ITS_OWN.format(address="127.0.0.1", login="alice")
    assert answer.status_code == 409 and message in answer.text
    assert "may have answered instead" in answer.text and "alice's password" in answer.text
    assert world.connects == [] and world.store.get("web") is None
    assert world.codes.get(code.id).outcome == f"refused: {message}"
    result = world.records[-1]
    assert result["phase"] == "result" and result["failure_message"] == message and "enrolled" not in result


async def test_a_refused_report_spends_the_code(world):
    value, _ = world.make_with_login(key=_other_key())
    assert (await world.post(value)).status_code == 409
    again = await world.post(value)
    assert again.status_code == 404 and UNKNOWN in again.text and world.connects == []


async def test_a_machine_that_is_not_its_own_answer_is_refused_whatever_its_level(world):
    world.play("full")
    value, _ = world.make_with_login(key=_other_key(), level="full")
    answer = await world.post(value)
    assert answer.status_code == 409 and NOT_ITS_OWN.format(address="127.0.0.1", login="alice") in answer.text
    assert world.connects == [] and world.store.get("web") is None


async def test_the_comparison_is_made_before_the_machine_is_judged_in_any_other_way(world):
    """A key that is not the one that answered is refused as that, not as a bad level or a bad check."""
    world.play("standard", sudo=True)  # this machine would also fail the level check
    value, _ = world.make_with_login(key=_other_key())
    assert "may have answered instead" in (await world.post(value)).text


async def test_a_code_made_without_a_login_is_not_compared_with_anything(world):
    value, code = world.make()
    assert world.codes.login_of(code.id) is None
    assert (await world.post(value, keys=[_other_key(), world.host_key])).status_code == 200


# --- What enrolls nothing ------------------------------------------------------

async def test_over_plain_http_nothing_is_enrolled_and_the_code_is_kept(world):
    world.pin = None
    value, _ = world.make()
    for answer in (await world.get(value), await world.post(value)):
        assert answer.status_code == 503 and HTTPS_ONLY in answer.text
    assert world.codes.find(value) is not None and world.connects == []
    assert [r["reason"] for r in world.records] == ["plain HTTP", "plain HTTP"]


async def test_in_lockdown_nothing_is_enrolled(world):
    world.locked = True
    value, _ = world.make()
    assert (await world.post(value)).status_code == 503 and world.connects == []
    assert world.records[-1]["reason"] == "lockdown"


async def test_without_an_audit_log_nothing_is_enrolled_and_the_code_is_kept(world, tmp_path):
    world.enrollment.audit = AuditLog(path=tmp_path / "no-such-folder" / "audit.jsonl")
    value, _ = world.make()
    answer = await world.post(value)
    assert answer.status_code == 503 and "audit log" in answer.text
    assert world.codes.find(value) is not None and world.connects == []


# --- The pin, with real curl ---------------------------------------------------

def test_key_pin_is_the_key_fingerprint_as_curl_takes_it(tmp_path):
    generate_self_signed(tmp_path / "c.pem", tmp_path / "k.pem", ["127.0.0.1"])
    key = x509.load_pem_x509_certificate((tmp_path / "c.pem").read_bytes()).public_key()
    pin = key_pin(key)
    assert pin.startswith("sha256//")
    assert base64.b64decode(pin[8:]).hex(":").upper() == key_fingerprint(key)


@pytest.fixture
def https(tmp_path):
    """A real HTTPS server with a certificate no machine trusts, as nervus's is
    to a machine that has never seen it."""
    generate_self_signed(tmp_path / "c.pem", tmp_path / "k.pem", ["127.0.0.1"])

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"the script\n")

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(tmp_path / "c.pem", tmp_path / "k.pem")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    key = x509.load_pem_x509_certificate((tmp_path / "c.pem").read_bytes()).public_key()
    yield f"https://127.0.0.1:{server.server_address[1]}/enroll/x", key_pin(key)
    server.shutdown()


def _curl(*args):
    if shutil.which("curl") is None:
        pytest.skip("curl is not installed")
    return subprocess.run(["curl", "-sS", *args], capture_output=True, text=True, timeout=30)


def test_curl_with_the_pin_fetches_from_nervus(https):
    url, pin = https
    done = _curl("-k", "--pinnedpubkey", pin, url)
    assert done.returncode == 0 and done.stdout == "the script\n", done.stderr


def test_curl_with_a_wrong_pin_is_refused_although_k_is_given(https):
    url, _ = https
    done = _curl("-k", "--pinnedpubkey", PIN, url)
    assert done.returncode != 0 and done.stdout == ""


def test_without_k_curl_refuses_nervus_own_authority_which_is_why_the_lines_give_it(https):
    url, pin = https
    done = _curl("--pinnedpubkey", pin, url)
    assert done.returncode != 0 and done.stdout == ""


async def test_nervus_serves_it_beside_mcp_without_a_bearer_token(world, tmp_path, ssh_server):
    from nervus.server import build_server
    from test_server import _settings

    server = build_server(settings=_settings(tmp_path, ssh_server), tokens={}, audit=world.audit,
                          enrollment=world.enrollment)
    value, _ = world.make()
    transport = httpx.ASGITransport(app=server.streamable_http_app())
    async with httpx.AsyncClient(transport=transport, base_url="https://192.0.2.1:8000") as c:
        got = await c.get(f"/enroll/{value}")
        reported = await c.post(f"/enroll/{value}", content=f"machine-id {MACHINE}\n{world.host_key}\n")
    assert got.status_code == 200 and "enroll this machine as web, standard." in got.text
    assert reported.status_code == 200 and world.store.get("web") is not None


def test_nervus_reads_its_own_machine_id_from_the_first_file_that_holds_one(tmp_path):
    from nervus.host_enrollment import own_machine_id
    bad, good = tmp_path / "bad", tmp_path / "good"
    bad.write_text("not an id\n")
    good.write_text(OWN + "\n")
    assert own_machine_id((tmp_path / "missing", bad, good)) == OWN
    assert own_machine_id((tmp_path / "missing", bad)) is None


@pytest.mark.parametrize("text, is_locked", [("lockdown: false\ndisabled: []\n", False),
                                             ("lockdown: true\ndisabled: []\n", True),
                                             ("not: the file\n", True), (None, True)])
def test_lockdown_and_an_unreadable_switches_file_both_lock_enrollment(tmp_path, text, is_locked):
    from nervus.switches import locked
    path = tmp_path / "switches.yaml"
    if text is not None:
        path.write_text(text)
    assert locked(path) is is_locked


async def test_the_check_after_a_report_signs_as_the_operator_under_its_record(world):
    """ADR-0025: no client asked for this check. Its certificate names the
    operator and the report's audit record, as the operator chose on
    2026-10-27, and the record carries the check's local port."""
    value, _ = world.make("standard")
    assert (await world.post(value)).status_code == 200
    report = next(r for r in world.records if r.get("action") == "report" and r["phase"] == "intent")
    [caller] = world.callers
    assert (caller.token_id, caller.run_id) == (None, report["id"])
    assert caller.key_id() == f"operator run={report['id']}"
    result = world.records[-1]
    assert result["id"] == report["id"] and result["ssh_ports"] == caller.ports and len(caller.ports) == 1
