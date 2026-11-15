"""The UI's pages for adding a machine by an admin login (ADR-0026 step 4):
Connect shows the key the machine answers with and asks for the login; the
login makes a code with the account and key, records it, starts the run in the
background and sends the browser to a page that reloads itself until the run
ends. The password goes to the run and nowhere else. Driven through Starlette's
test client, as the rest of the UI is, with LoginEnrollment stood in by an
object that returns a fixed key or refuses, and records what it is started
with. The run itself is tested in tests/test_host_login.py."""

import html
import json
import re
import sqlite3
import time
from pathlib import Path

import asyncssh
import pytest
from starlette.testclient import TestClient
from test_pages import HOSTILE, Parsed

from nervus.audit import AuditLog
from nervus.auth import Token, Tokens
from nervus.database import Database
from nervus.enrolled_hosts import EnrolledHostStore
from nervus.enrollment_codes import CodeLogin, EnrollmentCodes
from nervus.enrollments import host_keys
from nervus.host_login import LoginRefused, LoginRun, fingerprint
from nervus.pages import PLAIN_HTTP, page_enrolling
from nervus.ui import Machines, Management, build_ui

ORIGIN = "https://nervus.example:8443"
PIN = "sha256//47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
KEY = host_keys([asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode()])[0]
OTHER = host_keys([asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode()])[0]
MACHINE = "0123456789abcdef0123456789abcdef"
BY_HAND = ["node-a", "hv"]
FILE_TOKENS = {"file-value": Token(id="codex-anywhere", client="codex", project="p", hosts=frozenset({"nas"}))}
PASSWORD = "hunter2-π ☃ &<>'\""
ADDRESS = "192.0.2.20"


class StubLogin:
    """What the UI works with: a host key to show, and a run to start."""

    def __init__(self):
        self.key, self.refuse, self.is_locked = KEY, None, False
        self.asked, self.started, self.runs = [], [], {}

    def locked(self):
        return self.is_locked

    async def host_key(self, address):
        self.asked.append(address)
        if self.refuse:
            raise LoginRefused(self.refuse)
        return self.key

    def start(self, code, **kwargs):
        self.started.append({"code": code, **kwargs})
        run = LoginRun(code_id=code.id, name=code.name, address=code.address, level=code.level, login=kwargs["login"],
                       fingerprint=fingerprint(kwargs["host_key"]), started_at=time.time())
        self.runs[code.id] = run
        return run

    def get(self, code_id):
        return self.runs.get(code_id)


class World:
    def __init__(self, tmp_path, *, with_login=True, pin=PIN):
        self.db = Database(tmp_path / "nervus.db")
        self.db.open()
        self.audit = AuditLog(path=tmp_path / "audit.jsonl")
        self.codes, self.store = EnrollmentCodes(self.db), EnrolledHostStore(self.db)
        self.pin = pin
        self.login = StubLogin() if with_login else None
        switches = tmp_path / "switches.yaml"
        switches.write_text("lockdown: false\ndisabled: []\n")
        self.tokens = Tokens(FILE_TOKENS, self.db.token)
        self.machines = Machines(self.codes, self.store, lambda: self.pin, 8000, BY_HAND, "", self.login)
        self.browser = TestClient(build_ui(
            self.db, self.audit, secure=True, management=Management(self.tokens, switches, BY_HAND),
            machines=self.machines), base_url=ORIGIN, follow_redirects=False)
        link, _ = self.db.make_link()
        assert self.browser.post("/signin", data={"link": link}, headers={"Origin": ORIGIN}).status_code == 303

    def act(self, path="/machines", **fields):
        token = re.search(r'name="form_token" value="([^"]*)"', self.browser.get(path).text).group(1)
        return self.browser.post(path, data={"form_token": token, **fields}, headers={"Origin": ORIGIN})

    def connect(self, **fields):
        return self.act(action="connect", **{"name": "box", "address": ADDRESS, "level": "standard", **fields})

    def log_in(self, **fields):
        return self.act(action="login", **{"name": "box", "address": ADDRESS, "level": "standard", "host_key": KEY,
                                           "confirm": "", "login": "alice", "password": PASSWORD, **fields})

    def enroll(self, name="nas", level="standard", address=ADDRESS):
        """A machine already here; codex-anywhere, in the token file, names nas, so it is the name that asks."""
        self.store.add(name, address=address, level=level, host_keys=[KEY], machine_id=MACHINE,
                       enrolled_by="operator")

    def break_audit(self):
        self.audit.path.unlink(missing_ok=True)
        self.audit.path.mkdir()

    def records(self, action):
        if not self.audit.path.exists():
            return []
        rows = [json.loads(line) for line in self.audit.path.read_text().splitlines()]
        return [r for r in rows if r.get("tool") == "ui" and r.get("action") == action]

    def nothing_made(self):
        return self.codes.recent() == [] and (self.login is None or self.login.started == [])


@pytest.fixture
def world(tmp_path):
    return World(tmp_path)


def _hidden(page, name):
    found = re.findall(rf'<input type="hidden" name="{name}" value="([^"]*)">', page)
    return [html.unescape(v) for v in found]


def _buttons(page):
    return re.findall(r'<button type="submit"(?: name="action" value="([a-z]+)")?[^>]*>([^<]*)</button>', page)


# --- the add form -----------------------------------------------------------------------

def test_the_add_form_offers_connect_first_and_the_two_lines_as_advanced_with_read_only_chosen(world):
    page = world.browser.get("/machines").text
    form = re.search(r'<form method="post" action="machines" class="enroll">(.*?)</form>', page, re.S).group(1)
    assert [(action, label) for action, label in _buttons(form)] == [
        ("connect", "Connect"), ("add", "Advanced: two lines to run on the machine yourself")]
    assert 'type="hidden" name="action"' not in form  # the button the browser presses says which
    assert 'value="read-only" checked' in page and "A name or address nervus can reach" in page
    assert "Connect shows the key the machine answers with" in " ".join(page.split())
    assert "keeping no password" in " ".join(page.split())


def test_without_a_login_only_the_two_lines_are_offered(tmp_path):
    world = World(tmp_path, with_login=False)
    page = world.browser.get("/machines").text
    assert [action for action, _ in _buttons(page) if action] == ["add"] and ">Connect<" not in page
    for action in ("connect", "login"):
        refused = world.act(action=action, name="nas", address=ADDRESS, level="standard")
        assert refused.status_code == 400 and "not an action nervus knows" in refused.text
    assert world.codes.recent() == []


# --- Connect --------------------------------------------------------------------------------

def test_connect_shows_the_fingerprint_and_asks_for_a_login_with_the_level_kept(world):
    page = world.connect(level="full")
    assert page.status_code == 200 and "Log in to box" in page.text
    assert fingerprint(KEY) in page.text and "SHA256:" in page.text
    assert f"ssh-keygen -lF {ADDRESS}" in page.text and "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub" in page.text
    assert _hidden(page.text, "action")[0] == "login" and _hidden(page.text, "host_key")[0] == KEY
    assert (_hidden(page.text, "name")[0], _hidden(page.text, "address")[0], _hidden(page.text, "confirm")[0]) == (
        "box", ADDRESS, "")
    assert 'value="full" checked' in page.text and 'value="read-only" checked' not in page.text
    assert '<input type="text" name="login"' in page.text and '<input type="password" name="password"' in page.text
    assert re.search(r'<input type="password" name="password"[^>]*value=', page.text) is None
    assert "nervus keeps no password" in " ".join(page.text.split())
    assert world.login.asked == [ADDRESS] and world.codes.recent() == [] and world.records("enrollment_code") == []


def test_the_login_page_names_the_key_file_of_the_type_shown(world):
    """ADR-0026 question 9: a machine with no ed25519 key shows another, and the page names its file."""
    world.login.key = host_keys([asyncssh.generate_private_key("ssh-rsa").export_public_key().decode()])[0]
    page = world.connect().text
    assert "ssh-keygen -lf /etc/ssh/ssh_host_rsa_key.pub" in page and "ssh_host_ed25519_key" not in page
    world.login.key = KEY
    assert "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub" in world.connect().text


@pytest.mark.parametrize("fields, says", [
    (dict(address=""), "Give the address nervus should connect to."),
    (dict(address="   "), "Give the address nervus should connect to."),
    (dict(name="node-a"), "already a machine in hosts.yaml"),
    (dict(name="Nas Box"), "is not a name for a machine"),
    (dict(level="root"), "is not a level"),
    (dict(address="http://nas"), "is not an IP address or a DNS name"),
])
def test_connect_without_what_it_needs_connects_to_nothing(world, fields, says):
    page = world.connect(**fields)
    assert page.status_code == 400 and says in page.text and "Add a machine" in page.text
    assert world.login.asked == [] and world.nothing_made()


def test_connect_over_plain_http_connects_to_nothing(world):
    world.pin = None
    page = world.connect()
    assert page.status_code == 400 and PLAIN_HTTP.split(",")[0] in page.text
    assert world.login.asked == [] and world.nothing_made()


def test_connect_in_lockdown_connects_to_nothing(world):
    world.login.is_locked = True
    page = world.connect()
    assert page.status_code == 400 and "nervus is locked down, so it enrolls nothing" in page.text
    assert world.login.asked == [] and world.nothing_made()


def test_a_machine_that_cannot_be_reached_says_why_on_the_machines_page(world):
    world.login.refuse = f"nothing answers SSH at {ADDRESS}, port 22: is its SSH server running?"
    page = world.connect()
    assert page.status_code == 400 and f"Not connected: {world.login.refuse}" in page.text
    assert "Add a machine" in page.text and "Log in to" not in page.text and world.nothing_made()


# --- Connect's record (ADR-0001 section 10) ----------------------------------------------

def test_connect_is_recorded_before_the_machine_is_asked_for_its_key(world):
    """Reaching out to an address the operator typed leaves a record, written first."""
    ask, there_when_asked = world.login.host_key, []

    async def host_key(address):
        there_when_asked.append(world.records("connect"))
        return await ask(address)

    world.login.host_key = host_key
    assert "Log in to box" in world.connect(level="full").text
    record, = world.records("connect")
    assert (record["phase"], record["actor"], record["target"], record["machine_address"], record["level"]) == (
        "operator", "operator", "box", ADDRESS, "full")
    assert record["address"] == "testclient"  # the browser's, as on every record of the UI's
    assert there_when_asked == [[record]]


def test_a_connect_the_machine_does_not_answer_is_recorded_too(world):
    world.login.refuse = f"nothing answers SSH at {ADDRESS}, port 22: is its SSH server running?"
    assert world.connect().status_code == 400 and world.login.asked == [ADDRESS]
    record, = world.records("connect")
    assert (record["target"], record["machine_address"]) == ("box", ADDRESS)


def test_a_connect_whose_record_cannot_be_written_connects_to_nothing(world):
    world.break_audit()
    page = world.connect()
    assert page.status_code == 500 and "could not write its audit log, so it connected to nothing" in page.text
    assert "Add a machine" in page.text and "Log in to" not in page.text
    assert world.login.asked == [] and world.nothing_made()


def test_a_connect_that_reaches_out_to_nothing_records_no_connect(world):
    """The record says nervus contacted a machine, so one is written only when it is about to."""
    world.connect(address="http://nas")  # not an address
    world.connect(name="nas")  # asked about first: codex-anywhere names nas
    world.login.is_locked = True
    world.connect()
    assert world.login.asked == [] and world.records("connect") == []


def test_a_password_posted_with_connect_is_in_no_record(world):
    """Connect's form has no password field; one sent anyway still reaches no record and no page."""
    page = world.connect(password=PASSWORD, login="alice")
    assert "Log in to box" in page.text and not _holds(page.text)
    assert len(world.records("connect")) == 1 and not _audit_holds(world)


# --- the question about names and levels (ADR-0024 question 8) ---------------------------

def test_a_reused_name_is_asked_about_before_connect_and_connect_goes_on_with_the_name_typed(world):
    """codex-anywhere, in the token file, names nas; no machine is enrolled as nas."""
    asked = world.connect(name="nas")
    assert asked.status_code == 200 and "Add nas?" in asked.text and "codex-anywhere" in asked.text
    assert "No machine has the name nas now" in asked.text
    assert _hidden(asked.text, "action") == ["connect"] and ">Connect</button>" in asked.text
    assert world.login.asked == [] and world.nothing_made()
    typed = world.connect(name="nas", confirm="nas")
    assert "Log in to nas" in typed.text and world.login.asked == [ADDRESS]
    assert _hidden(typed.text, "confirm") == ["nas", "nas"]  # both forms of the login page carry the name typed


def test_a_raised_level_is_asked_about_before_connect(world):
    world.enroll(level="read-only")
    asked = world.connect(name="nas", level="full")
    assert "Add nas?" in asked.text and "from read-only to full" in asked.text and world.login.asked == []


def test_a_name_typed_wrong_connects_to_nothing(world):
    asked = world.connect(name="nas", confirm="nas2")
    assert "Add nas?" in asked.text and world.login.asked == [] and world.nothing_made()


def test_a_login_posted_without_the_name_typed_is_asked_again_and_makes_nothing(world):
    asked = world.log_in(name="nas")
    assert "Add nas?" in asked.text and _hidden(asked.text, "action") == ["connect"]
    assert world.nothing_made() and world.records("enrollment_code") == []
    again = world.log_in(name="nas", confirm="nas", confirmed_level="standard")  # as the login page posts it
    assert again.status_code == 303 and len(world.login.started) == 1


def test_a_level_raised_on_the_login_page_is_asked_about_again(world):
    world.enroll(level="read-only")
    assert "Log in to nas" in world.connect(name="nas", level="read-only").text  # the same level: nothing asked
    asked = world.log_in(name="nas", level="full")  # raised on the login page, where it can still be changed
    assert "from read-only to full" in asked.text and world.nothing_made()


def test_the_login_page_carries_the_level_the_name_was_typed_at(world):
    typed = world.connect(name="nas", level="standard", confirm="nas")
    assert _hidden(typed.text, "confirmed_level") == ["standard"]
    untyped = world.connect(level="full")  # box: nothing asked, nothing typed
    assert _hidden(untyped.text, "confirmed_level") == [""]


@pytest.mark.parametrize("level", ["standard", "read-only"])
def test_the_name_typed_covers_the_level_it_was_typed_at_or_a_lower_one(world, level):
    """ADR-0026 question 7: lowering, or keeping, the level on the login page asks nothing more."""
    assert world.log_in(name="nas", level=level, confirm="nas", confirmed_level="standard").status_code == 303
    assert world.codes.recent()[0].level == level


def test_a_level_raised_above_the_one_the_name_was_typed_at_is_asked_about_again(world):
    """ADR-0026 question 7: a name typed for read-only to standard does not cover full."""
    world.enroll(level="read-only")
    typed = world.connect(name="nas", level="standard", confirm="nas")
    assert _hidden(typed.text, "confirmed_level") == ["standard"]
    asked = world.log_in(name="nas", level="full", confirm="nas", confirmed_level="standard")
    assert "Add nas?" in asked.text and "from read-only to full" in asked.text
    assert _hidden(asked.text, "action") == ["connect"] and _hidden(asked.text, "level") == ["full"]
    assert world.nothing_made() and world.records("enrollment_code") == []


@pytest.mark.parametrize("confirmed_level", ["", "root", "Standard"])
def test_a_name_typed_without_a_level_it_was_typed_at_answers_nothing_on_the_login(world, confirmed_level):
    asked = world.log_in(name="nas", confirm="nas", confirmed_level=confirmed_level)
    assert "Add nas?" in asked.text and world.nothing_made()


def test_a_refused_login_page_keeps_the_level_the_name_was_typed_at(world):
    page = world.log_in(name="nas", confirm="nas", confirmed_level="standard", password="")
    assert page.status_code == 400 and _hidden(page.text, "confirmed_level") == ["standard"]


def test_a_machine_added_again_at_its_own_level_asks_nothing(world):
    world.enroll(level="standard")
    assert "Log in to nas" in world.connect(name="nas").text


# --- the login ----------------------------------------------------------------------------

def test_the_login_makes_a_code_with_the_account_and_key_records_it_starts_the_run_and_shows_its_progress(world):
    done = world.log_in()
    code, = world.codes.recent()
    assert done.status_code == 303 and done.headers["location"] == f"enrolling?id={code.id}"
    assert (code.name, code.address, code.level, code.made_by) == ("box", ADDRESS, "standard", "operator")
    assert world.codes.login_of(code.id) == CodeLogin("alice", KEY)
    record, = world.records("enrollment_code")
    assert (record["target"], record["code_id"], record["level"], record["method"]) == ("box", code.id, "standard",
                                                                                         "login")
    assert (record["login"], record["host_key"], record["machine_address"], record["tokens_shown"]) == (
        "alice", fingerprint(KEY), ADDRESS, [])
    started, = world.login.started
    assert (started["login"], started["password"], started["host_key"], started["pin"]) == ("alice", PASSWORD, KEY, PIN)
    value = started["url"].rsplit("/", 1)[1]
    assert started["url"] == f"https://nervus.example:8000/enroll/{value}" and world.codes.find(value).id == code.id
    assert started["shown"] == "https://nervus.example:8000/enroll/<code>" and started["code"].id == code.id
    assert value not in world.audit.path.read_text() and value not in done.text


def test_an_account_typed_with_spaces_round_it_is_taken_without_them(world):
    world.log_in(login="  alice  ")
    code, = world.codes.recent()
    assert world.codes.login_of(code.id).login == "alice" and world.login.started[0]["login"] == "alice"


def test_the_level_chosen_on_the_login_page_is_the_one_made(world):
    world.log_in(level="full")
    code, = world.codes.recent()
    assert code.level == "full" and world.login.started[0]["code"].level == "full"


def test_the_names_reasons_are_recorded_when_the_name_was_typed(world):
    world.log_in(name="nas", confirm="nas", confirmed_level="standard")
    record, = world.records("enrollment_code")
    assert record["tokens_shown"] == ["codex-anywhere"]


@pytest.mark.parametrize("fields, says", [
    (dict(address=""), "Give the address nervus should connect to."),
    (dict(name="node-a"), "already a machine in hosts.yaml"),
    (dict(level="root"), "is not a level"),
])
def test_a_login_makes_every_check_connect_makes_again(world, fields, says):
    page = world.log_in(**fields)
    assert page.status_code == 400 and says in page.text and world.nothing_made()
    assert PASSWORD not in page.text


def test_a_login_over_plain_http_or_in_lockdown_starts_nothing(world):
    world.pin = None
    over_http = world.log_in()
    world.pin = PIN
    world.login.is_locked = True
    locked = world.log_in()
    assert over_http.status_code == locked.status_code == 400
    assert PLAIN_HTTP.split(",")[0] in over_http.text and "locked down" in locked.text and world.nothing_made()


# --- the password ---------------------------------------------------------------------------

def _database_bytes(world):
    out = b""
    for suffix in ("", "-wal"):
        path = Path(str(world.db.path) + suffix)
        out += path.read_bytes() if path.exists() else b""
    return out


def _strings(value):
    """Every string in what a JSON record holds, keys and values, as they read once decoded."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _strings(k)
            yield from _strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v)


def _audit_holds(world):
    """The password in the audit log, as written (JSON escapes what is not plain ASCII, so the raw text is not
    enough) or as decoded from any field of any record."""
    if not world.audit.path.exists():
        return False
    text = world.audit.path.read_text()
    if PASSWORD in text or json.dumps(PASSWORD)[1:-1] in text:
        return True
    return any(PASSWORD in string for line in text.splitlines() for string in _strings(json.loads(line)))


def _holds(text):
    return PASSWORD in text or html.escape(PASSWORD) in text or html.escape(PASSWORD, quote=False) in text


def test_the_check_that_the_audit_log_holds_no_password_can_see_one(world):
    """A check that cannot see what it looks for proves nothing: this one finds the password however written."""
    world.audit.record_operator("x", {"note": PASSWORD})
    world.audit.record_operator("y", {"nested": [{"deeper": f"before {PASSWORD} after"}]})
    assert _audit_holds(world)
    world.audit.path.write_text(json.dumps({"password": PASSWORD}) + "\n")  # JSON-escaped on the way out
    assert PASSWORD not in world.audit.path.read_text() and _audit_holds(world)


def test_the_password_is_in_no_response_no_audit_record_and_no_database_row(world):
    seen = [world.connect(), world.log_in()]
    code, = world.codes.recent()
    seen += [world.browser.get(f"/enrolling?id={code.id}"), world.browser.get("/machines"), world.browser.get("/clients"),
             world.browser.get("/audit")]
    world.login.runs[code.id].lines.append("logged in")
    for response in seen:
        assert not _holds(response.text) and not _holds(str(dict(response.headers))), response.url
    assert not _audit_holds(world) and PASSWORD.encode() not in _database_bytes(world)
    assert b"alice" in _database_bytes(world) and "alice" in world.audit.path.read_text()  # the account is kept


@pytest.mark.parametrize("fields", [dict(login=""), dict(login="   "), dict(login="not an account"),
                                    dict(login="a" * 33), dict(login="-lead"), dict(login="a/b")])
def test_a_refused_login_page_shows_its_password_field_empty_and_does_not_send_the_password_back(world, fields):
    page = world.log_in(**fields)
    assert page.status_code == 400 and "Give the admin account" in page.text and "Nothing was sent" in page.text
    assert not _holds(page.text) and re.search(r'<input type="password" name="password"[^>]*value=', page.text) is None
    assert '<input type="password" name="password" autocomplete="off">' in page.text
    assert _hidden(page.text, "host_key") == [KEY] and fingerprint(KEY) in page.text
    assert world.nothing_made() and world.records("enrollment_code") == []


def test_an_empty_password_is_asked_for_again_and_nothing_is_made(world):
    page = world.log_in(password="")
    assert page.status_code == 400 and "Give that account's password. Nothing was sent." in html.unescape(page.text)
    assert 'value="full" checked' not in page.text and 'value="standard" checked' in page.text  # the level is kept
    assert world.nothing_made()


@pytest.mark.parametrize("key", ["", "not a key", f"{KEY}\n{OTHER}", f"\n{KEY}\n{OTHER}\n"])
def test_a_host_key_that_is_not_one_key_is_refused_and_nothing_is_made(world, key):
    page = world.log_in(host_key=key)
    assert page.status_code == 400 and "Not connected" in page.text and "Add a machine" in page.text
    assert not _holds(page.text) and world.nothing_made() and world.records("enrollment_code") == []


def test_a_code_whose_record_cannot_be_written_is_cancelled_and_nothing_starts(world):
    world.break_audit()
    page = world.log_in()
    assert page.status_code == 500 and "nothing changed" in page.text and not _holds(page.text)
    code, = world.codes.recent()
    assert code.expires_at <= code.made_at + 5 and world.login.started == []


def test_a_login_posted_from_another_site_or_without_the_form_token_is_refused(world):
    token = re.search(r'name="form_token" value="([^"]*)"', world.browser.get("/machines").text).group(1)
    fields = {"action": "login", "name": "nas", "address": ADDRESS, "level": "standard", "host_key": KEY,
              "confirm": "", "login": "alice", "password": PASSWORD}
    other = world.browser.post("/machines", data={**fields, "form_token": token}, headers={"Origin": "https://evil.example"})
    unsigned = world.browser.post("/machines", data={**fields, "form_token": "x"}, headers={"Origin": ORIGIN})
    connect = world.browser.post("/machines", data={**fields, "action": "connect", "form_token": "x"},
                                 headers={"Origin": ORIGIN})
    assert other.status_code == unsigned.status_code == connect.status_code == 403
    assert world.nothing_made() and world.login.asked == []


def test_signed_out_a_login_is_refused(world, tmp_path):
    stranger = TestClient(build_ui(world.db, world.audit, secure=True, machines=world.machines), base_url=ORIGIN)
    posted = stranger.post("/machines", data={"action": "login", "name": "nas", "password": PASSWORD},
                           headers={"Origin": ORIGIN})
    assert posted.status_code == 403 and world.nothing_made()


# --- the progress page ----------------------------------------------------------------------

def _start(world):
    world.log_in()
    code, = world.codes.recent()
    return code, world.login.runs[code.id]


def test_the_progress_page_reloads_itself_while_the_run_goes_on(world):
    code, run = _start(world)
    run.lines += ["connecting to 192.0.2.20 as alice", "alice can use sudo"]
    page = world.browser.get(f"/enrolling?id={code.id}")
    assert page.status_code == 200 and '<meta http-equiv="refresh" content="2">' in page.text
    assert page.text.index('<meta http-equiv="refresh"') < page.text.index("</head>")
    assert "<li>connecting to 192.0.2.20 as alice</li>" in page.text and "<li>alice can use sudo</li>" in page.text
    assert "Enrolling box" in page.text and "leaving it does not stop the enrollment" in " ".join(page.text.split())
    assert 'href="machines"' in page.text and "was not enrolled" not in page.text


def test_the_progress_page_stops_reloading_once_the_run_ends_and_shows_the_outcome(world):
    code, run = _start(world)
    run.lines.append("agent trusts nervus's certificate authority")
    run.finished_at, run.enrolled, run.outcome = time.time(), True, "enrolled box, standard"
    page = world.browser.get(f"/enrolling?id={code.id}")
    assert "http-equiv" not in page.text and "box is enrolled, standard" in page.text
    assert "enrolled box, standard" in page.text and "<li>agent trusts nervus&#x27;s certificate authority</li>" in page.text
    assert 'In <a href="clients">Clients</a>, give a token this machine to let a client use it.' in page.text


def test_a_run_that_failed_says_so_and_offers_to_try_again_or_use_the_two_lines(world):
    code, run = _start(world)
    run.finished_at, run.outcome = time.time(), "192.0.2.20 refused alice with that password."
    page = world.browser.get(f"/enrolling?id={code.id}")
    assert "box was not enrolled" in page.text and "refused alice with that password." in page.text
    assert "http-equiv" not in page.text and "give a token this machine" not in page.text
    assert '<a href="machines">Try again</a>' in page.text and "Advanced: two lines to run" in page.text
    assert _hidden(page.text, "action")[-1] == "add" and _hidden(page.text, "name")[-1] == "box"


def test_for_a_run_nervus_no_longer_has_the_page_shows_what_the_codes_record_says(world):
    code, _ = _start(world)
    world.login.runs.clear()  # as after a restart
    lost = world.browser.get(f"/enrolling?id={code.id}")
    assert lost.status_code == 200 and "no longer running this enrollment" in lost.text and "http-equiv" not in lost.text
    assert "box was not enrolled" in lost.text and "alice at 192.0.2.20" in lost.text
    world.codes.finish(code.id, "enrolled box, standard")
    done = world.browser.get(f"/enrolling?id={code.id}")
    assert "box is enrolled, standard" in done.text and "http-equiv" not in done.text


def test_what_became_of_a_run_that_ended_before_the_route_saw_a_report_is_shown_on_the_machines_page(world):
    """Found in a browser: such a code was cancelled and never used, and was listed as 'expired, unused'."""
    code, _ = _start(world)
    assert "waiting for the machine" in world.browser.get("/machines").text
    world.codes.cancel(code.id)  # what a run does however it ends,
    world.codes.finish(code.id, "192.0.2.20 refused alice with that password.")  # and says what became of it
    listed = html.unescape(world.browser.get("/machines").text)
    assert "192.0.2.20 refused alice with that password." in listed and "expired, unused" not in listed


def test_a_code_made_for_the_two_lines_has_a_record_page_too(world):
    value, code = world.codes.make(name="box", address=ADDRESS, level="read-only", made_by="operator")
    page = world.browser.get(f"/enrolling?id={code.id}")
    assert page.status_code == 200 and "box was not enrolled" in page.text and "trusting only" not in page.text


@pytest.mark.parametrize("query", ["", "?id=", "?id=nothing", "?id=0123456789ABCDEF", "?id=0123456789abcdef",
                                   "?id=0123456789abcdef0", "?id=../machines"])
def test_an_id_that_is_not_a_run_or_a_code_is_not_found(world, query):
    assert world.browser.get(f"/enrolling{query}").status_code == 404


@pytest.mark.parametrize("id", ["ABCDEF0123456789", "abc", "0123456789abcdeg", "0123456789abcdef\n", "0123456789abcde"])
def test_only_an_id_of_the_shape_a_code_has_is_looked_up_at_all(world, id):
    world.login.runs[id] = LoginRun(code_id=id, name="x", address=ADDRESS, level="standard", login="a",
                                    fingerprint="f", started_at=0.0)
    assert world.browser.get("/enrolling", params={"id": id}).status_code == 404


def test_the_progress_page_needs_a_session_and_a_login(world, tmp_path):
    code, _ = _start(world)
    stranger = TestClient(build_ui(world.db, world.audit, secure=True, machines=world.machines), base_url=ORIGIN)
    assert "nervus-ctl signin" in stranger.get(f"/enrolling?id={code.id}").text
    plain = World(tmp_path / "plain", with_login=False) if (tmp_path / "plain").mkdir() is None else None
    assert plain.browser.get(f"/enrolling?id={code.id}").status_code == 404


@pytest.mark.parametrize("hostile", HOSTILE)
def test_what_a_machine_printed_comes_out_as_text_on_the_page_of_a_run_that_goes_on(hostile):
    def made(text):
        return page_enrolling(LoginRun(code_id=text, name=text, address=text, level=text, login=text,
                                       fingerprint=text, started_at=0.0, lines=[text, text], outcome=text),
                              until=0.0, form_token=text)
    benign, attacked = made("benign"), made(hostile)
    assert '<meta http-equiv="refresh" content="2">' in attacked
    shown = Parsed(attacked.replace("<mark>", "").replace("</mark>", ""))
    assert shown.structure() == Parsed(benign).structure()


# --- the two lines are still there --------------------------------------------------------

def test_advanced_still_makes_the_two_lines(world):
    page = world.act(action="add", name="nas", confirm="nas", address=ADDRESS, level="read-only")
    assert page.status_code == 200 and "Add nas, read-only" in page.text and "/enroll/" in page.text
    code, = world.codes.recent()
    assert world.codes.login_of(code.id) is None and world.login.asked == [] and world.login.started == []


def test_advanced_from_the_login_page_still_makes_the_two_lines(world):
    login_page = world.connect(level="full").text
    forms = re.findall(r'<form method="post" action="machines" class="enroll">(.*?)</form>', login_page, re.S)
    advanced = forms[1]
    assert _hidden(advanced, "action") == ["add"] and _hidden(advanced, "level") == ["full"]
    assert _hidden(advanced, "name") == ["box"] and _hidden(advanced, "address") == [ADDRESS]
    page = world.act(action="add", name="box", address=ADDRESS, level="full", confirm="")
    assert "Add box, full" in page.text and "/enroll/" in page.text


def test_a_name_typed_for_the_two_lines_still_asks_before_them(world):
    asked = world.act(action="add", name="nas", address=ADDRESS, level="standard")
    assert "Add nas?" in asked.text and _hidden(asked.text, "action") == ["add"] and ">Make the commands</button>" in asked.text
