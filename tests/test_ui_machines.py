"""The UI's machines page (ADR-0024 step 4): adding a machine makes a one-time
code and shows its one line once (ADR-0032 question 7), with the script it
runs beneath it; a machine's address can be changed; a
machine removed is forgotten, with what takes nervus off it; tokens may name
enrolled machines. Every change is audited, and undone if its record cannot
be written, except a removal, which takes access away and stands. Driven
through Starlette's test client, as the rest of the UI is."""

import html
import json
import re
import shlex

import pytest
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.testclient import TestClient

from nervus.audit import AuditLog
from nervus.auth import Token, Tokens
from nervus.database import Database
from nervus.enrolled_hosts import EnrolledHostStore
from nervus.enrollment_codes import EnrollmentCodes
from nervus.host_enrollment import HostEnrollment, enroll_endpoint, enroll_url, remove_commands
from nervus.pages import PLAIN_HTTP
from nervus.token_codes import TokenCodes
from nervus.ui import Machines, Management, build_ui

ORIGIN = "https://nervus.example:8443"
PIN = "sha256//47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
# nervus's certificate authority's public key, as the script carries it (ADR-0025).
CA_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeNervusKeyForTheseTestsOnly0123456789ab nervus-ca"
MACHINE = "0123456789abcdef0123456789abcdef"
BY_HAND = ["node-a", "hv"]
FILE_TOKENS = {"file-value": Token(id="codex-anywhere", client="codex", project="p", hosts=frozenset({"nas"}))}


class World:
    def __init__(self, tmp_path, pin=PIN, nervus_host="", enrollment=None):
        self.db = Database(tmp_path / "nervus.db")
        self.db.open()
        self.audit = AuditLog(path=tmp_path / "audit.jsonl")
        self.codes, self.store = EnrollmentCodes(self.db), EnrolledHostStore(self.db)
        self.pin = pin
        switches = tmp_path / "switches.yaml"
        switches.write_text("lockdown: false\ndisabled: []\n")
        self.tokens = Tokens(FILE_TOKENS, self.db.token)
        # With `enrollment`, a HostEnrollment made from this world, the page shows the script each line runs.
        shown = {} if enrollment is None else {"shown": enrollment(self).shown}
        self.machines = Machines(self.codes, self.store, lambda: self.pin, 8000, BY_HAND, nervus_host, **shown)
        self.browser = TestClient(build_ui(
            self.db, self.audit, secure=True,
            management=Management(self.tokens, switches, BY_HAND, codes=TokenCodes(self.db), pin=lambda: self.pin),
            machines=self.machines), base_url=ORIGIN, follow_redirects=False)
        link, _ = self.db.make_link()
        assert self.browser.post("/signin", data={"link": link}, headers={"Origin": ORIGIN}).status_code == 303

    def act(self, path="/machines", **fields):
        token = re.search(r'name="form_token" value="([^"]*)"', self.browser.get(path).text).group(1)
        return self.browser.post(path, data={"form_token": token, **fields}, headers={"Origin": ORIGIN})

    def enroll(self, name="nas", level="standard", address="192.0.2.20"):
        self.store.add(name, address=address, level=level, host_keys=[KEY], machine_id=MACHINE,
                       enrolled_by="operator")

    def break_audit(self):
        """A folder where the log should be: every write to it fails."""
        self.audit.path.unlink(missing_ok=True)
        self.audit.path.mkdir()

    def records(self, action):
        if not self.audit.path.exists():
            return []
        rows = [json.loads(line) for line in self.audit.path.read_text().splitlines()]
        # What was done, by its action: a refusal names the action it refused, and is not one of these.
        return [r for r in rows if r.get("tool") == "ui" and r.get("phase") == "operator" and r.get("action") == action]

    def refusals(self):
        """Every refusal the UI recorded, oldest first."""
        if not self.audit.path.exists():
            return []
        rows = [json.loads(line) for line in self.audit.path.read_text().splitlines()]
        return [r for r in rows if r.get("tool") == "ui" and r.get("phase") == "refused"]


@pytest.fixture
def world(tmp_path):
    return World(tmp_path)


def _lines(page):
    return html.unescape(re.search(r"<pre class=\"lines\"><code>(.*?)</code></pre>", page, re.S).group(1))


def _all_lines(page):
    return [html.unescape(found) for found in re.findall(r"<pre class=\"lines\"><code>(.*?)</code></pre>", page, re.S)]


def _code(lines):
    return re.search(r"/enroll/([A-Za-z0-9_-]+)", lines).group(1)


# --- the page ---------------------------------------------------------------------------

def test_signed_out_it_shows_only_how_to_sign_in(tmp_path, world):
    stranger = TestClient(build_ui(world.db, world.audit, secure=True, machines=world.machines), base_url=ORIGIN)
    assert "nervus-ctl signin" in stranger.get("/machines").text
    assert stranger.post("/machines", data={"action": "add", "name": "x"}, headers={"Origin": ORIGIN}).status_code == 403


def test_every_page_links_to_it(world):
    assert '<a href="machines">Machines</a>' in world.browser.get("/").text


def test_it_lists_enrolled_machines_and_names_those_described_by_hand(world):
    world.enroll()
    page = world.browser.get("/machines").text
    assert "<code>nas</code>" in page and "192.0.2.20" in page and "standard" in page and MACHINE[:12] in page
    assert "hosts.yaml" in page and "node-a, hv" in page


def test_full_access_asks_whether_nervus_runs_on_that_machine(world):
    """ADR-0025 question 3a: nervus cannot tell which machine hosts it, so the
    choice of full access asks, where it is made."""
    page = " ".join(html.unescape(world.browser.get("/machines").text).split())
    assert ("Does nervus run on this machine, as a VM or container? Then a client given full access here can "
            "rewrite nervus's audit log.") in page


def test_read_only_is_the_level_offered_first(world):
    page = world.browser.get("/machines").text
    assert re.findall(r'name="level" value="([a-z-]+)"', page) == ["read-only", "standard", "full"]
    assert 'value="read-only" checked' in page


# --- adding -----------------------------------------------------------------------------

def test_adding_shows_the_one_line_once_and_the_code_in_it_works(world):
    # ADR-0032 question 7: one line, the script fetched pinned to nervus's key and run as root.
    page = world.act(action="add", name="nas", confirm="nas", address="192.0.2.20", level="read-only")
    assert page.status_code == 200 and "Add nas, read-only" in page.text
    line, root_line = _all_lines(page.text)
    assert len(line.strip().splitlines()) == 1
    value = _code(line)
    url = f"https://nervus.example:8000/enroll/{value}"
    assert shlex.split(line) == ["curl", "-fsSk", "--pinnedpubkey", PIN, url, "|", "sudo", "sh"]
    # In a root shell, as on a machine without sudo, the same line ending in `| sh`.
    assert shlex.split(root_line) == ["curl", "-fsSk", "--pinnedpubkey", PIN, url, "|", "sh"]
    code = world.codes.find(value)
    assert (code.name, code.address, code.level, code.made_by) == ("nas", "192.0.2.20", "read-only", "operator")
    later = world.browser.get("/machines").text
    assert value not in later and "waiting for the machine" in later


def test_the_making_is_audited_by_the_code_id_never_the_code(world):
    page = world.act(action="add", name="nas", confirm="nas", address="", level="full")
    value = _code(_lines(page.text))
    record, = world.records("enrollment_code")
    assert (record["target"], record["level"], record["actor"]) == ("nas", "full", "operator")
    assert record["code_id"] == world.codes.find(value).id
    assert record["machine_address"] == "where its report comes from" and record["address"]
    assert value not in world.audit.path.read_text()


def test_the_page_shows_the_key_the_line_checks_to_compare_with_the_installer_s(world):
    page = html.unescape(re.sub(r"<[^>]+>", "", world.act(action="add", name="nas", confirm="nas", level="standard").text))
    said = " ".join(page.split())
    assert f"The key it checks is {PIN}." in said and "if they differ, stop" in said


def test_beneath_the_line_the_page_shows_the_very_script_the_line_runs(tmp_path):
    # ADR-0032 question 7: for anyone who wants to read it first. The text is the route's own, for the
    # same code and URL, and showing it records no fetch: the page's making of the code is recorded.
    made = []

    def enrollment(world):
        made.append(HostEnrollment(world.codes, world.store, world.audit, key=lambda: CA_KEY, connect=None,
                                   pin=lambda: world.pin, own_machine_id=MACHINE, reserved=lambda: BY_HAND))
        return made[0]
    world = World(tmp_path, enrollment=enrollment)
    enrollment = made[0]
    page = world.act(action="add", name="nas", confirm="nas", level="standard").text
    value = _code(_lines(page))
    url = f"https://nervus.example:8000/enroll/{value}"
    shown = html.unescape(re.search(r'<pre class="script"><code>(.*?)</code></pre>', page, re.S).group(1))
    assert "<summary>The script this line runs" in page
    fetches = lambda: [r for r in map(json.loads, world.audit.path.read_text().splitlines())  # noqa: E731
                       if r.get("tool") == "enroll"]
    assert fetches() == []
    # What the route itself serves at the line's URL, fetched as the line fetches it.
    route = Starlette(routes=[Route("/enroll/{code}", enroll_endpoint(enrollment), methods=["GET", "POST"])])
    served = TestClient(route, base_url="https://nervus.example:8000").get(f"/enroll/{value}")
    assert served.status_code == 200 and shown == served.text
    assert shown.rstrip().endswith("nervus_enroll </dev/null\n}")


def test_where_the_route_would_refuse_the_line_the_page_says_why_in_place_of_the_script(tmp_path):
    # In lockdown the route refuses the line (ADR-0024): the page says so, and shows no script it would not serve.
    made = []

    def enrollment(world):
        made.append(HostEnrollment(world.codes, world.store, world.audit, key=lambda: CA_KEY, connect=None,
                                   pin=lambda: world.pin, own_machine_id=MACHINE, reserved=lambda: BY_HAND,
                                   locked=lambda: True))
        return made[0]
    world = World(tmp_path, enrollment=enrollment)
    page = html.unescape(world.act(action="add", name="nas", confirm="nas", level="standard").text)
    assert '<pre class="script">' not in page and len(_all_lines(page)) == 2
    assert "cannot be shown here: nervus is locked down, so it refuses this line until lockdown is lifted" in page


def test_on_port_443_the_line_names_no_port_as_curl_asks_for_none():
    # curl leaves :443 out of what it asks for, so the script the route writes names no port: nor does the line.
    assert enroll_url("nervus.example", 443, "C") == "https://nervus.example/enroll/C"
    assert enroll_url("2001:db8::5", 443, "C") == "https://[2001:db8::5]/enroll/C"


def test_where_there_is_no_script_to_show_the_line_stands_alone(world):
    page = world.act(action="add", name="nas", confirm="nas", level="standard").text
    assert '<pre class="script">' not in page and len(_all_lines(page)) == 2


def test_the_lines_name_nervus_as_its_ui_url_does(tmp_path):
    world = World(tmp_path, nervus_host="2001:db8::5")
    lines = _lines(world.act(action="add", name="nas", confirm="nas", level="standard").text)
    assert "https://[2001:db8::5]:8000/enroll/" in lines


@pytest.mark.parametrize("fields, says", [
    (dict(name="Nas Box", level="standard"), "is not a name for a machine"),
    (dict(name="nas", level="root"), "is not a level"),
    (dict(name="nas", level="standard", address="http://nas"), "is not an IP address or a DNS name"),
    (dict(name="node-a", level="standard"), "already a machine in hosts.yaml"),
])
def test_nothing_is_made_for_what_cannot_be_enrolled(world, fields, says):
    page = world.act(action="add", **fields)
    assert page.status_code == 400 and says in page.text and "No commands made" in page.text
    assert world.codes.recent() == []


def test_over_plain_http_no_commands_are_offered_or_made(world):
    world.pin = None
    page = world.browser.get("/machines").text
    assert PLAIN_HTTP.split(",")[0] in page and 'value="add"' not in page
    refused = world.act(action="add", name="nas", level="standard")
    assert refused.status_code == 400 and world.codes.recent() == []


def test_a_code_whose_making_cannot_be_audited_is_cancelled(world, tmp_path):
    world.break_audit()
    page = world.act(action="add", name="nas", confirm="nas", level="standard")
    assert page.status_code == 500 and "nothing changed" in page.text
    code, = world.codes.recent()
    assert code.expires_at <= code.made_at + 5 and "expired" in world.browser.get("/machines").text


def test_what_became_of_a_code_is_shown(world):
    value = _code(_lines(world.act(action="add", name="nas", confirm="nas", level="standard").text))
    code = world.codes.spend(value)
    world.codes.finish(code.id, "enrolled nas, standard")
    assert "enrolled nas, standard" in world.browser.get("/machines").text


# --- changing an address ------------------------------------------------------------------

def test_a_machine_that_moved_gets_its_new_address_and_keeps_its_keys(world):
    world.enroll()
    assert world.act(action="move", name="nas", address="192.0.2.21").status_code == 303
    row = world.store.get("nas")
    assert row.address == "192.0.2.21" and row.host_keys
    record, = world.records("move_machine")
    assert (record["target"], record["from"], record["to"]) == ("nas", "192.0.2.20", "192.0.2.21")


def test_a_move_that_cannot_be_audited_is_undone(world):
    world.enroll()
    world.break_audit()
    page = world.act(action="move", name="nas", address="192.0.2.21")
    assert page.status_code == 500 and world.store.get("nas").address == "192.0.2.20"


@pytest.mark.parametrize("fields, says", [(dict(name="nas", address="not an address"), "Not changed"),
                                          (dict(name="nothing", address="192.0.2.1"), "no machine nothing")])
def test_a_move_to_nowhere_or_of_nothing_is_refused(world, fields, says):
    world.enroll()
    page = world.act(action="move", **fields)
    assert page.status_code == 400 and says in page.text and world.store.get("nas").address == "192.0.2.20"


# --- removing ---------------------------------------------------------------------------

def test_removing_needs_the_name_typed(world):
    world.enroll()
    page = world.act(action="remove", name="nas", confirm="na")
    assert page.status_code == 400 and "type its name exactly" in page.text and world.store.get("nas")


def test_a_removed_machine_is_forgotten_and_the_page_says_how_to_take_nervus_off_it(world):
    world.enroll(level="full")
    world.db.issue_token("laptop", "claude-code", "p", ["nas", "node-a"], taken=world.tokens.file_ids())
    page = world.act(action="remove", name="nas", confirm="nas")
    assert page.status_code == 200 and world.store.get("nas") is None
    # Added before this release as far as this page knows: `agent` is kept, nervus's line off it (ADR-0031 question 9).
    assert "nas is forgotten" in page.text and _lines(page.text) == remove_commands("agent", None)
    assert "These tokens still name nas: codex-anywhere, laptop." in page.text
    record, = world.records("remove_machine")
    assert (record["target"], record["level"], record["machine_id"]) == ("nas", "full", MACHINE)


def test_a_removal_stands_without_its_record(world):
    world.enroll()
    world.break_audit()
    assert world.act(action="remove", name="nas", confirm="nas").status_code == 200
    assert world.store.get("nas") is None


# --- what protects every change -----------------------------------------------------------

def test_a_change_posted_from_another_site_or_without_the_form_token_is_refused(world):
    world.enroll()
    token = re.search(r'name="form_token" value="([^"]*)"', world.browser.get("/machines").text).group(1)
    other = world.browser.post("/machines", data={"action": "remove", "name": "nas", "confirm": "nas",
                                                  "form_token": token}, headers={"Origin": "https://evil.example"})
    unsigned = world.browser.post("/machines", data={"action": "remove", "name": "nas", "confirm": "nas",
                                                     "form_token": "x"}, headers={"Origin": ORIGIN})
    assert other.status_code == unsigned.status_code == 403 and world.store.get("nas")


def test_an_unknown_action_is_refused(world):
    world.enroll()
    assert world.act(action="explode", name="nas").status_code == 400


# --- a refused form is on record (ADR-0012 decision 6, as amended 2026-11-15) ----------------
#
# Found by procedure 040: the Machines page refused Connect and the login in lockdown, and the audit
# log held nothing of either. No refused form left a record, on any page.

@pytest.mark.parametrize("fields, action, target, reason", [
    (dict(action="add", name="Nas Box", level="standard"), "add", "Nas Box", "is not a name for a machine"),
    (dict(action="add", name="node-a", level="standard"), "add", "node-a", "already a machine in hosts.yaml"),
    (dict(action="move", name="nothing", address="192.0.2.1"), "move", "nothing", "no machine nothing"),
    (dict(action="remove", name="nas", confirm="na"), "remove", "nas", "type its name exactly"),
    (dict(action="explode", name="nas"), "explode", "nas", "not an action nervus knows"),
])
def test_a_refused_form_is_recorded_with_what_was_asked_and_why(world, fields, action, target, reason):
    world.enroll()
    assert world.act(**fields).status_code == 400
    record, = world.refusals()
    assert (record["actor"], record["page"], record["action"], record["target"]) == ("operator", "machines", action, target)
    assert reason in record["reason"] and record["address"] == "testclient"
    assert record.get("level") == fields.get("level") and record.get("machine_address") == fields.get("address")


def test_an_action_that_is_not_a_word_is_recorded_as_none_nervus_knows(world):
    # What a form calls its action is whatever was posted: only a name of an action goes into the record.
    assert world.act(action="x" * 500 + "\n<script>", name="nas").status_code == 400
    record, = world.refusals()
    assert record["action"] == "(not an action nervus knows)"


def test_a_post_from_another_site_or_without_the_form_token_is_recorded_where_a_session_carries_it(world):
    world.enroll()
    token = re.search(r'name="form_token" value="([^"]*)"', world.browser.get("/machines").text).group(1)
    fields = {"action": "remove", "name": "nas", "confirm": "nas"}
    world.browser.post("/machines", data={**fields, "form_token": token}, headers={"Origin": "https://evil.example"})
    world.browser.post("/machines", data={**fields, "form_token": "x"}, headers={"Origin": ORIGIN})
    other, unsigned = world.refusals()
    assert (other["page"], other["action"]) == (unsigned["page"], unsigned["action"]) == ("machines", "remove")
    assert "another site" in other["reason"] and "token" in unsigned["reason"]
    assert "nas" not in json.dumps(other) and "nas" not in json.dumps(unsigned)  # nothing of a form nervus did not make


def test_a_post_that_carries_no_session_is_refused_without_a_record(world):
    # As a call with no token is: anyone who can reach the port could otherwise write to the audit log.
    stranger = TestClient(build_ui(world.db, world.audit, secure=True, machines=world.machines), base_url=ORIGIN)
    for origin in (ORIGIN, "https://evil.example"):
        posted = stranger.post("/machines", data={"action": "remove", "name": "nas"}, headers={"Origin": origin})
        assert posted.status_code == 403
    assert world.refusals() == []


def test_a_refusal_stands_without_its_record(world):
    # It changes nothing, so there is nothing to undo: the page still says why.
    world.enroll()
    world.break_audit()
    page = world.act(action="remove", name="nas", confirm="na")
    assert page.status_code == 400 and "type its name exactly" in page.text and world.store.get("nas")


# --- tokens may name enrolled machines (ADR-0024 decision 3) ------------------------------

def test_the_token_form_offers_enrolled_machines_and_issues_for_them(world):
    world.enroll()
    offered = re.findall(r'name="hosts" value="([^"]+)"', world.browser.get("/clients").text)
    assert offered == ["node-a", "hv", "nas"]
    issued = world.act("/clients", action="issue", id="nas-reader", client="codex", project="p", hosts="nas")
    assert issued.status_code == 200 and "Token issued: nas-reader" in issued.text
    world.store.remove("nas")
    assert "nas" not in re.findall(r'name="hosts" value="([^"]+)"', world.browser.get("/clients").text)
    refused = world.act("/clients", action="issue", id="late", client="codex", project="p", hosts="nas")
    assert refused.status_code == 400 and "Not in the inventory: nas" in refused.text


# --- a reused name or a raised level is asked about (ADR-0024 question 8) ---------------

def _issue(world, token_id, hosts):
    world.db.issue_token(token_id, "claude-code", "p", hosts, taken=world.tokens.file_ids())


def test_a_removed_name_that_tokens_still_name_is_asked_about_first(world):
    """codex-anywhere, in the token file, names nas; no machine is enrolled as nas."""
    page = world.act(action="add", name="nas", address="192.0.2.30", level="standard")
    assert page.status_code == 200 and "Add nas?" in page.text
    assert "codex-anywhere" in page.text and "No machine has the name nas now" in page.text
    assert world.codes.recent() == [] and "/enroll/" not in page.text
    assert re.search(r'name="confirm"', page.text)
    # The form asks again with what was given, so nothing need be typed twice but the name.
    assert 'name="address" value="192.0.2.30"' in page.text and 'name="level" value="standard"' in page.text


def test_with_the_name_typed_the_code_is_made_and_its_record_lists_the_tokens_shown(world):
    _issue(world, "laptop", ["nas"])
    page = world.act(action="add", name="nas", level="standard", confirm="nas")
    assert page.status_code == 200 and "Add nas, standard" in page.text and "/enroll/" in page.text
    record, = world.records("enrollment_code")
    assert record["tokens_shown"] == ["codex-anywhere", "laptop"]


def test_the_name_typed_wrong_makes_nothing(world):
    page = world.act(action="add", name="nas", level="standard", confirm="nas2")
    assert "Add nas?" in page.text and world.codes.recent() == []


def test_raising_a_level_that_tokens_reach_is_asked_about(world):
    world.enroll(level="read-only")
    page = world.act(action="add", name="nas", level="full")
    assert "Add nas?" in page.text and "from read-only to full" in page.text and "codex-anywhere" in page.text
    assert world.codes.recent() == []


@pytest.mark.parametrize("level", ["standard", "read-only"])
def test_adding_a_machine_again_at_its_own_or_a_lower_level_asks_nothing(world, level):
    """A reinstall: add it again under its name; its tokens keep reaching it."""
    world.enroll(level="standard")
    page = world.act(action="add", name="nas", level=level)
    assert "/enroll/" in page.text and "Add nas?" not in page.text
    assert world.records("enrollment_code")[0]["tokens_shown"] == []


def test_a_name_no_token_names_asks_nothing_whatever_it_had(world):
    world.enroll(name="box", level="read-only")
    assert "/enroll/" in world.act(action="add", name="box", level="full").text
    assert "/enroll/" in world.act(action="add", name="newbox", level="full").text


def test_the_page_says_a_reinstall_is_adding_it_again_not_removing_it(world):
    shown = " ".join(world.browser.get("/machines").text.split())
    assert "To reinstall a machine, add it again under its name too, without removing it" in shown
