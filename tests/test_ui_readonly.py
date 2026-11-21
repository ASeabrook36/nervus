"""ADR-0031 step 6: the web UI.

- **Issuing a token** asks, for each machine with both accounts, for an
  explicit pick: not on this token, read-only, or read-write, nothing chosen
  beforehand; machines with one account keep their tick-box. A token read-only
  anywhere is kept in its own table; the record of issuing says where.
- **The clients page** says on which machines each token is read-only.
- **The Machines page** shows each machine's accounts as nervus checked them.
- **The audit page** shows the level each call ran at.
"""

import json
import re

import pytest
from starlette.testclient import TestClient

from nervus.accounts import MachineAccounts
from nervus.audit import AuditLog
from nervus.auth import Tokens
from nervus.config import Host
from nervus.database import Database
from nervus.enrolled_hosts import EnrolledHostStore
from nervus.enrollment_codes import EnrollmentCodes
from nervus.ui import Machines, Management, build_ui

from test_ui_machines import BY_HAND, FILE_TOKENS, KEY, MACHINE, ORIGIN, PIN

RW, RO = "nervusagent", "nervusagent-readonly"


class World:
    def __init__(self, tmp_path, **more):
        self.db = Database(tmp_path / "nervus.db")
        self.db.open()
        self.audit = AuditLog(path=tmp_path / "audit.jsonl")
        self.codes, self.store = EnrollmentCodes(self.db), EnrolledHostStore(self.db)
        self.accounts = MachineAccounts(self.db)
        switches = tmp_path / "switches.yaml"
        switches.write_text("lockdown: false\ndisabled: []\n")
        self.tokens = Tokens(FILE_TOKENS, self.db.token)
        described = {"node-a": Host(name="node-a", address="192.0.2.5", os="", role="r", agent_user="agent",
                                    status="onboarded")}
        machines = Machines(self.codes, self.store, lambda: PIN, 8000, BY_HAND, "", accounts=self.accounts,
                            described=described, **more)
        self.browser = TestClient(build_ui(self.db, self.audit, secure=True,
                                           management=Management(self.tokens, switches, BY_HAND),
                                           machines=machines), base_url=ORIGIN, follow_redirects=False)
        link, _ = self.db.make_link()
        assert self.browser.post("/signin", data={"link": link}, headers={"Origin": ORIGIN}).status_code == 303
        # Two machines added from the page, one with both accounts and one from before, and node-a, described by
        # hand, given its read-only account.
        both, _ = self.store.add("both", address="192.0.2.20", level="full", host_keys=[KEY], machine_id=MACHINE,
                                 enrolled_by="operator")
        self.accounts.record("both", enrolled_at=both.enrolled_at, readwrite=RW, readonly=RO, groups=["adm"],
                             why_none=None)
        self.store.add("old", address="192.0.2.21", level="standard", host_keys=[KEY], machine_id=MACHINE,
                       enrolled_by="operator")
        alone, _ = self.store.add("alone", address="192.0.2.22", level="standard", host_keys=[KEY],
                                  machine_id=MACHINE, enrolled_by="operator")
        self.accounts.record("alone", enrolled_at=alone.enrolled_at, readwrite=RW, readonly=None, groups=[],
                             why_none="bubblewrap cannot run here")
        self.accounts.record("node-a", enrolled_at=None, readwrite=None, readonly=RO, groups=[], why_none=None)

    def act(self, path="/clients", **fields):
        token = re.search(r'name="form_token" value="([^"]*)"', self.browser.get(path).text).group(1)
        return self.browser.post(path, data={"form_token": token, **fields}, headers={"Origin": ORIGIN})

    def records(self, action):
        rows = [json.loads(line) for line in self.audit.path.read_text().splitlines()] if self.audit.path.exists() else []
        return [r for r in rows if r.get("action") == action and r.get("phase") == "operator"]


@pytest.fixture
def world(tmp_path):
    return World(tmp_path)


def _issue(world, **picks):
    return world.act(action="issue", id="reader-look", client="claude-code", project="reader", **picks)


def test_a_machine_with_both_accounts_asks_for_an_explicit_pick_nothing_chosen(world):
    form = world.browser.get("/clients").text
    for host in ("both", "node-a"):
        radios = re.findall(rf'<input type="radio" name="level-{host}" value="([^"]+)"([^>]*)>', form)
        assert [v for v, _ in radios] == ["none", "read-only", "read-write"]
        assert not any("checked" in rest for _, rest in radios)
        assert f'name="hosts" value="{host}"' not in form
    for host in ("old", "alone", "hv"):
        assert f'name="hosts" value="{host}"' in form and f'name="level-{host}"' not in form


def test_without_a_pick_for_each_such_machine_nothing_is_issued(world):
    page = _issue(world, **{"level-both": "read-only"})
    assert page.status_code == 400 and "choose for node-a" in page.text
    assert world.db.issued_tokens() == []


def test_read_only_on_one_and_read_write_on_another_is_issued_in_its_own_table(world):
    page = _issue(world, hosts=["old"], **{"level-both": "read-only", "level-node-a": "read-write"})
    assert page.status_code == 200, page.text
    [issued] = world.db.issued_tokens()
    assert issued.token.hosts == frozenset({"old", "both", "node-a"}) and issued.token.readonly == frozenset({"both"})
    record = world.records("issue_token")[-1]
    assert record["read_only"] == ["both"] and record["hosts"] == ["both", "node-a", "old"]


def test_read_write_and_not_on_this_token_issue_a_token_as_before(world):
    page = _issue(world, hosts=["old"], **{"level-both": "read-write", "level-node-a": "none"})
    assert page.status_code == 200, page.text
    [issued] = world.db.issued_tokens()
    assert issued.token.hosts == frozenset({"old", "both"}) and issued.token.readonly == frozenset()
    with world.db.transaction(write=False) as db:
        assert db.execute("SELECT id FROM issued_token").fetchall() == [("reader-look",)]


@pytest.mark.parametrize("fields", [{"level-old": "read-only"}, {"hosts": ["both"]}],
                         ids=["read-only-without-the-account", "both-as-a-tick-box"])
def test_a_read_only_pick_where_there_is_no_read_only_account_is_refused(world, fields):
    page = _issue(world, **{"level-node-a": "none", **({"level-both": "none"} if "hosts" not in fields else {}),
                            **fields})
    assert page.status_code == 400 and world.db.issued_tokens() == []


def test_the_clients_page_says_where_a_token_is_read_only(world):
    _issue(world, hosts=["old"], **{"level-both": "read-only", "level-node-a": "none"})
    page = world.browser.get("/clients").text
    assert "both (read-only), old" in page


def test_the_machines_page_shows_each_machine_s_accounts(world):
    page = world.browser.get("/machines").text
    assert f"{RW}; {RO}, read-only, in adm" in page
    assert "agent (added before read-only accounts)" in page
    assert f"{RW}; no read-only account: bubblewrap cannot run here" in page
    assert f"<code>{RO}</code>" in page  # node-a's, described by hand


def test_the_audit_page_shows_the_level_a_call_ran_at(world):
    run = world.audit.record_intent("exec", {"token_id": "reader-look", "client": "c", "project": "p",
                                             "host": "both", "user": RO, "level": "read-only", "command": "ls"})
    world.audit.record_result(run, "exec", {"exit_code": 0})
    page = world.browser.get("/audit").text
    assert re.search(r'>both</a> <span class="muted">\(read-only\)</span>', page), page[:2000]


@pytest.mark.parametrize("name", ["agent", "observer"])
def test_a_hand_described_machine_s_read_only_account_is_no_account_an_entry_at_its_address_uses(tmp_path, name):
    """Procedure 068, section 12: one machine may be two entries in hosts.yaml, behind two accounts (ADR-0009).
    Naming the other entry's account would make that account read-only, and the read-only account share it."""
    world = World(tmp_path, taken={"node-a": frozenset({"agent", "observer"})})
    answer = world.act("/machines", action="readonly-account", name="node-a", readonly=name, typed_readonly=name)
    assert "No commands made" in answer.text and name in answer.text
    assert not any(c.level == "readonly-account" for c in world.codes.recent())


def test_removing_a_machine_deletes_only_the_accounts_nervus_made_there(tmp_path):
    """ADR-0031 question 9: the page's commands delete an account nervus's script made, and take only nervus's
    line and sudoers file off any other, by nervus's key words; a machine added before this release keeps
    `agent`."""
    import html
    words = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeNervusKeyForTheseTestsOnly0123456789ab"
    world = World(tmp_path, key_words=lambda: (words,))
    both = world.store.get("both")
    world.accounts.record("both", enrolled_at=both.enrolled_at, readwrite=RW, readonly=RO, groups=[],
                          why_none=None, made=[RW], machine_id=MACHINE)
    text = html.unescape(world.act("/machines", action="remove", name="both", confirm="both").text)
    assert f"userdel -r {RW}\n" in text and f"userdel -r {RO}" not in text
    assert f'grep -v -F -e "{words}"' in text and f"' {RO}\n" in text
    old = html.unescape(world.act("/machines", action="remove", name="old", confirm="old").text)
    assert "userdel" not in old and "' agent\n" in old


def test_removing_a_machine_deletes_the_accounts_nervus_made_under_names_it_had_before(tmp_path):
    """ADR-0031 question 13: the record keeps them, and the page's commands delete them too."""
    import html
    world = World(tmp_path, key_words=lambda: ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeNervusKeyForTheseTestsOnly0123456789ab",))
    both = world.store.get("both")
    world.accounts.record("both", enrolled_at=both.enrolled_at, readwrite=RW, readonly=RO, groups=[], why_none=None,
                          made=[RW], machine_id=MACHINE)
    world.accounts.record("both", enrolled_at=both.enrolled_at, readwrite="deploy", readonly=RO, groups=[],
                          why_none=None, made=[], machine_id=MACHINE)
    text = html.unescape(world.act("/machines", action="remove", name="both", confirm="both").text)
    assert f"userdel -r {RW}\n" in text and "userdel -r deploy" not in text and "' deploy\n" in text
