"""First-run setup in the UI (ADR-0015 consequence 1.4): until a tier is
chosen a signed-in browser sees only setup (decision A); the tier can be
changed later (B); ranges are declared internal and withdrawn, and the banner
follows at once (C, D as clarified 2026-10-20); each change is audited, actor
operator, tool ui, with the browser's address; and every signed-in page
carries the tier (E) and the warning or the notes."""

import ipaddress
import json

import pytest
from starlette.testclient import TestClient

from nervus.audit import AuditLog
from nervus.database import Database
from nervus.exposure import Exposure, check
from nervus.first_run import FirstRun, Tier
from nervus.ui import Setup, build_ui

ORIGIN = "https://nervus.example:8443"
# What the check found at start: one address that looks public, one private.
FOUND = check("0.0.0.0", interfaces=lambda: ["192.168.1.10", "1.2.3.4"])


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "nervus.db")
    database.open()
    return database


@pytest.fixture
def audit(tmp_path):
    return AuditLog(path=tmp_path / "audit.jsonl")


@pytest.fixture
def store(db):
    return FirstRun(db)


def _browser(db, audit, exposure=FOUND):
    return TestClient(build_ui(db, audit, secure=True, setup=Setup(FirstRun(db), exposure)),
                      base_url=ORIGIN, follow_redirects=False)


def _signed_in(db, audit, exposure=FOUND):
    browser = _browser(db, audit, exposure)
    link, _ = db.make_link()
    assert browser.post("/signin", data={"link": link}, headers={"Origin": ORIGIN}).status_code == 303
    return browser


@pytest.fixture
def browser(db, audit):
    return _signed_in(db, audit)


def _form_token(browser):
    page = browser.get("/setup").text
    start = page.index('name="form_token" value="') + len('name="form_token" value="')
    return page[start:page.index('"', start)]


def _post(browser, **fields):
    return browser.post("/setup", data={"form_token": _form_token(browser), **fields}, headers={"Origin": ORIGIN})


def _ui_records(audit, *actions):
    records = [json.loads(line) for line in audit.path.read_text().splitlines()] if audit.path.exists() else []
    return [r for r in records if r.get("tool") == "ui" and r.get("action") in actions]


# --- decision A: until a tier is chosen, setup and nothing else ------------------------


@pytest.mark.parametrize("path", ["/", "/audit", "/audit?at=0", "/clients", "/machines"])
def test_until_a_tier_is_chosen_every_page_sends_the_browser_to_setup(browser, path):
    response = browser.get(path)
    assert response.status_code == 303 and response.headers["location"] == "setup"


@pytest.mark.parametrize("path", ["/clients", "/machines"])
def test_until_a_tier_is_chosen_no_other_form_changes_anything(browser, audit, path):
    token = _form_token(browser)
    response = browser.post(path, data={"form_token": token, "action": "lockdown-on"}, headers={"Origin": ORIGIN})
    assert response.status_code == 303 and response.headers["location"] == "setup"
    assert not audit.path.exists() or "lock" not in audit.path.read_text()


def test_setup_itself_signing_out_and_the_stylesheet_still_work(browser):
    page = browser.get("/setup")
    assert page.status_code == 200 and "Set up nervus" in page.text and "Tier not chosen" in page.text
    assert browser.get("/nervus.css").status_code == 200
    response = browser.post("/signout", data={"form_token": _form_token(browser)}, headers={"Origin": ORIGIN})
    assert response.status_code == 200 and "Signed out." in response.text


def test_signed_out_setup_shows_only_how_to_sign_in(db, audit):
    page = _browser(db, audit).get("/setup")
    assert "nervus-ctl signin" in page.text and "Tier" not in page.text and "1.2.3.4" not in page.text
    assert _browser(db, audit).post("/setup", data={"action": "tier", "tier": "1"},
                                    headers={"Origin": ORIGIN}).status_code == 403


# --- decisions A and B: choosing and changing the tier --------------------------------


def test_choosing_the_tier_ends_setup_shows_it_everywhere_and_is_audited(browser, store, audit):
    response = _post(browser, action="tier", tier="2")
    assert response.status_code == 303 and response.headers["location"] == "./"
    assert store.tier().tier == 2
    for path in ("/", "/audit", "/setup"):
        page = browser.get(path)
        assert page.status_code == 200 and "Tier 2: your everyday computer" in page.text, path
    [record] = _ui_records(audit, "choose_tier")
    assert (record["actor"], record["tier"], record["from"]) == ("operator", 2, None)
    assert record["address"]


def test_changing_the_tier_later_is_audited_with_what_it_was(browser, store, audit):
    _post(browser, action="tier", tier="1")
    response = _post(browser, action="tier", tier="3")
    assert response.status_code == 303 and response.headers["location"] == "setup"
    assert store.tier().tier == 3
    assert [(r["tier"], r["from"]) for r in _ui_records(audit, "choose_tier")] == [(1, None), (3, 1)]


@pytest.mark.parametrize("tier", ["", "0", "4", "one", "2.0"])
def test_what_is_not_a_tier_is_refused_and_says_why(browser, store, audit, tier):
    response = _post(browser, action="tier", tier=tier)
    assert response.status_code == 400 and "is not a tier" in response.text
    assert store.tier() is None and _ui_records(audit, "choose_tier") == []


# --- decisions C and D: declared ranges, applied at once ------------------------------


def test_the_setup_page_names_the_addresses_found_at_start_that_look_public(browser):
    page = browser.get("/setup").text
    assert "1.2.3.4" in page and "192.168.1.10" not in page


def test_declaring_a_range_turns_the_warning_into_a_note_at_once(browser, store, audit):
    _post(browser, action="tier", tier="1")
    page = browser.get("/").text
    assert 'role="alert">nervus listens on 1.2.3.4' in page
    response = _post(browser, action="declare", network="1.2.3.0/24")
    assert response.status_code == 303 and response.headers["location"] == "setup"
    page = browser.get("/").text
    assert 'role="alert"' not in page
    assert "1.2.3.4 is public in form; declared internal by operator on" in page and "(1.2.3.0/24)" in page
    [record] = _ui_records(audit, "declare_internal")
    assert (record["actor"], record["target"]) == ("operator", "1.2.3.0/24") and record["address"]


def test_withdrawing_brings_the_warning_back_at_once_and_is_audited(browser, store, audit):
    _post(browser, action="tier", tier="1")
    _post(browser, action="declare", network="1.2.3.0/24")
    assert _post(browser, action="withdraw", network="1.2.3.0/24").status_code == 303
    assert 'role="alert">nervus listens on 1.2.3.4' in browser.get("/").text
    assert store.declared() == []
    assert [r["target"] for r in _ui_records(audit, "withdraw_internal")] == ["1.2.3.0/24"]


@pytest.mark.parametrize("fields, why", [
    ({"action": "declare", "network": "0.0.0.0/0"}, "never everything"),
    ({"action": "declare", "network": "not a range"}, "is not an address range"),
    ({"action": "withdraw", "network": "5.6.7.0/24"}, "is not declared internal"),
    ({"action": "nonsense"}, "not an action nervus knows"),
])
def test_what_does_not_apply_is_refused_and_says_why(browser, store, audit, fields, why):
    response = _post(browser, **fields)
    assert response.status_code == 400 and why in response.text
    assert store.declared() == [] and _ui_records(audit, "declare_internal", "withdraw_internal") == []


@pytest.mark.parametrize("fields, target, why", [
    ({"action": "tier", "tier": "4"}, "4", "is not a tier"),
    ({"action": "declare", "network": "not a range"}, "not a range", "is not an address range"),
    ({"action": "withdraw", "network": "5.6.7.0/24"}, "5.6.7.0/24", "is not declared internal"),
])
def test_a_refused_form_on_the_setup_page_is_recorded_with_what_was_asked_and_why(browser, audit, fields, target, why):
    # ADR-0012 decision 6, as amended 2026-11-15: no refused form left a record, on any page.
    assert _post(browser, **fields).status_code == 400
    lines = [json.loads(line) for line in audit.path.read_text().splitlines()]
    record, = [r for r in lines if r.get("phase") == "refused"]
    assert (record["tool"], record["page"], record["action"], record["target"]) == ("ui", "setup", fields["action"], target)
    assert why in record["reason"]


def test_a_private_machine_carries_no_banner(db, audit):
    browser = _signed_in(db, audit, check("0.0.0.0", interfaces=lambda: ["192.168.1.10"]))
    _post(browser, action="tier", tier="1")
    page = browser.get("/").text
    assert 'role="alert"' not in page and 'class="note"' not in page


def test_a_check_that_could_not_read_is_said_on_every_page(db, audit):
    browser = _signed_in(db, audit, Exposure("0.0.0.0", unreadable="no ip"))
    _post(browser, action="tier", tier="1")
    assert 'role="alert">could not read the addresses nervus listens on (no ip)' in browser.get("/").text


# --- what protects it -------------------------------------------------------------------


def test_a_change_without_nervuss_own_form_changes_nothing(browser, store):
    for data, headers in (({"form_token": "guessed", "action": "tier", "tier": "1"}, {"Origin": ORIGIN}),
                          ({"form_token": _form_token(browser), "action": "tier", "tier": "1"},
                           {"Origin": "https://evil.example"})):
        assert browser.post("/setup", data=data, headers=headers).status_code == 403
    assert store.tier() is None


def test_without_its_audit_record_only_making_the_warning_louder_stands(browser, store, audit):
    # ADR-0001 s10: what cannot be audited does not happen. Choosing a tier and
    # declaring a range are undone; withdrawing a declaration only brings the
    # warning back, so it stands, as taking access away does (ADR-0014).
    _post(browser, action="tier", tier="1")
    _post(browser, action="declare", network="1.2.3.0/24")
    token = _form_token(browser)
    audit.path.unlink()
    audit.path.mkdir()

    def post(**fields):
        return browser.post("/setup", data={"form_token": token, **fields}, headers={"Origin": ORIGIN})

    assert post(action="tier", tier="3").status_code == 500
    assert store.tier().tier == 1
    assert post(action="declare", network="5.6.7.0/24").status_code == 500
    assert [d.network for d in store.declared()] == ["1.2.3.0/24"]
    assert post(action="withdraw", network="1.2.3.0/24").status_code == 303
    assert store.declared() == []


def test_without_its_audit_record_a_first_tier_is_undone_entirely(browser, store, audit):
    token = _form_token(browser)
    audit.path.unlink()  # the sign-in's record
    audit.path.mkdir()
    response = browser.post("/setup", data={"form_token": token, "action": "tier", "tier": "2"},
                            headers={"Origin": ORIGIN})
    assert response.status_code == 500 and "nothing changed" in response.text
    assert store.tier() is None


def test_without_setup_wired_in_the_ui_carries_nothing_and_sends_nowhere(db, audit):
    browser = TestClient(build_ui(db, audit, secure=True), base_url=ORIGIN, follow_redirects=False)
    link, _ = db.make_link()
    browser.post("/signin", data={"link": link}, headers={"Origin": ORIGIN})
    assert browser.get("/").status_code == 200
    assert browser.get("/setup").status_code == 404


def test_a_tier_chosen_by_a_previous_run_is_kept(db, audit, store):
    store.choose_tier(3, by="operator", now=1792497600.0)
    browser = _signed_in(db, audit)
    page = browser.get("/")
    assert page.status_code == 200 and "Tier 3" in page.text
    assert store.tier() == Tier(3, 1792497600.0, "operator")


def test_the_exposure_kept_from_start_is_matched_again_not_read_again(db, audit):
    read = []
    found = check("0.0.0.0", interfaces=lambda: read.append(1) or ["1.2.3.4"])
    browser = _signed_in(db, audit, found)
    _post(browser, action="tier", tier="1")
    _post(browser, action="declare", network="1.2.3.4")
    for _ in range(3):
        browser.get("/")
    assert read == [1]
    assert found.addresses == (ipaddress.ip_address("1.2.3.4"),)
