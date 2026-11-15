"""The UI's web application (ADR-0012): sign-in by link, the session cookie,
sign-out, the protections every page carries, and the audit records of
decision 6. Driven through Starlette's test client, which speaks HTTP to the
application without a network."""

import json
import re
import time

import pytest
from starlette.testclient import TestClient

from nervus.audit import AuditLog
from nervus.database import SESSION_SECONDS, Database, audit_id
from nervus.pages import STYLESHEET
from nervus.ui import SECURITY_HEADERS, build_ui, form_token

ORIGIN = "https://nervus.example:8443"
COOKIE = "__Host-nervus-session"


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "nervus.db")
    database.open()
    return database


@pytest.fixture
def audit(tmp_path):
    return AuditLog(path=tmp_path / "audit.jsonl")


def _client(db, audit, secure=True, base=ORIGIN, setup=None):
    return TestClient(build_ui(db, audit, secure=secure, setup=setup), base_url=base, follow_redirects=False)


@pytest.fixture
def ui(db, audit):
    return _client(db, audit)


def _records(audit):
    return [json.loads(line) for line in audit.path.read_text().splitlines()] if audit.path.exists() else []


def _sign_in(ui, db):
    link, _ = db.make_link()
    response = ui.post("/signin", data={"link": link}, headers={"Origin": ORIGIN})
    assert response.status_code == 303, response.text
    return link, response


def _hidden(page, name):
    return re.search(rf'name="{name}" value="([^"]*)"', page).group(1)


# --- signed out ---------------------------------------------------------------------


def test_signed_out_the_ui_shows_only_how_to_sign_in(ui):
    """ADR-0011 verification 5."""
    page = ui.get("/")
    assert page.status_code == 200
    assert "nervus-ctl signin" in page.text and "Sign out" not in page.text
    assert ui.get("/anything").status_code == 404


def test_opening_a_link_shows_a_button_and_spends_nothing(ui, db):
    """ADR-0012 decision 4 and verification 3."""
    link, _ = db.make_link()
    page = ui.get(f"/signin?link={link}")
    assert page.status_code == 200
    assert _hidden(page.text, "link") == link
    db.use_link(link)  # still usable: opening it spent nothing


def test_a_link_from_the_address_is_shown_as_text(ui):
    page = ui.get('/signin?link="><script>alert(1)</script>')
    assert "<script>" not in page.text
    assert _hidden(page.text, "link") == "&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;"


# --- signing in ---------------------------------------------------------------------


def test_pressing_sign_in_signs_in_with_a_cookie_scripts_cannot_read(ui, db):
    _, response = _sign_in(ui, db)
    assert response.headers["location"] == "./"
    cookie = response.headers["set-cookie"]
    assert cookie.startswith(f"{COOKIE}=")
    attributes = {a.strip().split("=")[0].lower(): a.strip() for a in cookie.split(";")[1:]}
    assert {"secure", "httponly", "path", "samesite", "max-age"} <= set(attributes)
    assert attributes["path"] == "Path=/" and attributes["samesite"].lower() == "samesite=strict"
    assert SESSION_SECONDS - 5 <= int(attributes["max-age"].split("=")[1]) <= SESSION_SECONDS
    assert "domain" not in attributes  # __Host-: this host only
    home = ui.get("/")
    assert "Sign out" in home.text and "Signed in until" in home.text


def test_a_link_signs_in_once_and_the_refusal_says_no_more(ui, db):
    link, _ = _sign_in(ui, db)
    other = _client(db, AuditLog(path=db.path.parent / "other.jsonl"))
    expired, _ = db.make_link(now=time.time() - 3600)
    replies = []
    for presented in (link, "never-made", expired):
        refused = other.post("/signin", data={"link": presented}, headers={"Origin": ORIGIN})
        assert refused.status_code == 403
        assert "set-cookie" not in refused.headers
        assert "That link cannot be used" in refused.text
        replies.append(refused.text)
    assert replies[0] == replies[1] == replies[2]  # used, unknown, expired: the reason is the audit log's


def test_signing_in_and_refusals_are_audited_without_any_value(ui, db, audit):
    """ADR-0012 decision 6: actor operator, the browser's address, and the
    link and session by their audit ids only."""
    link, response = _sign_in(ui, db)
    session = response.cookies[COOKIE]
    ui.post("/signin", data={"link": link}, headers={"Origin": ORIGIN})
    signed_in, refused = _records(audit)
    assert (signed_in["phase"], signed_in["tool"], signed_in["actor"], signed_in["action"]) == \
        ("operator", "ui", "operator", "signin")
    assert signed_in["link"] == audit_id(link) and signed_in["session"] == audit_id(session)
    assert signed_in["address"] == "testclient"
    assert (refused["phase"], refused["tool"], refused["actor"], refused["action"], refused["reason"]) == \
        ("refused", "ui", "operator", "signin", "used")
    assert refused["link"] == audit_id(link) and refused["address"] == "testclient"
    text = audit.path.read_text()
    assert link not in text and session not in text


def test_without_its_audit_record_a_sign_in_does_not_stand(db, tmp_path):
    """ADR-0001 section 10: what cannot be audited is refused. The session the
    link made is ended at once, and no cookie is set."""
    (tmp_path / "unwritable").mkdir()
    ui = _client(db, AuditLog(path=tmp_path / "unwritable"))
    link, _ = db.make_link()
    response = ui.post("/signin", data={"link": link}, headers={"Origin": ORIGIN})
    assert response.status_code == 500
    assert "set-cookie" not in response.headers
    assert db.sign_out_all() == 0  # nothing left running


def test_a_session_ends_after_12_hours(ui, db):
    link, _ = db.make_link(now=time.time() - SESSION_SECONDS - 60)
    stale, _ = db.use_link(link, now=time.time() - SESSION_SECONDS - 60)
    ui.cookies.set(COOKIE, stale)
    assert "nervus-ctl signin" in ui.get("/").text


# --- signing out -------------------------------------------------------------------


def test_sign_out_ends_the_session_clears_the_cookie_and_is_audited(ui, db, audit):
    _, response = _sign_in(ui, db)
    session = response.cookies[COOKIE]
    token = _hidden(ui.get("/").text, "form_token")
    assert token == form_token(session) and session not in token
    out = ui.post("/signout", data={"form_token": token}, headers={"Origin": ORIGIN})
    assert out.status_code == 200
    assert "Signed out" in out.text and "nervus-ctl signin" in out.text
    assert re.search(rf"{COOKIE}=\"?\"?;.*Max-Age=0", out.headers["set-cookie"], re.I)
    assert db.session(session) is None
    record = _records(audit)[-1]
    assert (record["tool"], record["action"], record["session"], record["address"]) == \
        ("ui", "signout", audit_id(session), "testclient")


def test_sign_out_without_the_form_token_changes_nothing(ui, db):
    """A page on another site can make a browser post a form, but cannot know
    the token in nervus's own page."""
    _, response = _sign_in(ui, db)
    session = response.cookies[COOKIE]
    for data in ({}, {"form_token": "guessed"}, {"form_token": form_token("another session")}):
        assert ui.post("/signout", data=data, headers={"Origin": ORIGIN}).status_code == 403
    assert db.session(session) is not None


@pytest.mark.parametrize("origin", ["https://evil.example", "null", "http://nervus.example:8443",
                                    "https://nervus.example:8444"])
def test_a_form_posted_from_another_origin_is_refused(ui, db, origin):
    link, _ = db.make_link()
    assert ui.post("/signin", data={"link": link}, headers={"Origin": origin}).status_code == 403
    db.use_link(link)  # not spent
    _, response = _sign_in(ui, db)
    token = _hidden(ui.get("/").text, "form_token")
    assert ui.post("/signout", data={"form_token": token}, headers={"Origin": origin}).status_code == 403
    assert db.session(response.cookies[COOKIE]) is not None


# --- what every response carries -------------------------------------------------


def test_every_response_carries_the_protections(ui, db):
    """No script, nothing from elsewhere, no framing, no caching, no referrer
    (the address of the sign-in page holds the link). Never HSTS: with a
    certificate nobody vouches for, it would stop the browser letting the
    operator past its warning."""
    assert SECURITY_HEADERS["referrer-policy"] == "same-origin"  # not no-referrer: see ui.py
    assert SECURITY_HEADERS["content-security-policy"] == (
        "default-src 'none'; style-src 'self'; form-action 'self'; "
        "frame-ancestors 'none'; base-uri 'none'")
    link, _ = db.make_link()
    responses = [
        ui.get("/"), ui.get("/signin?link=x"), ui.get("/nervus.css"), ui.get("/missing"),
        ui.get("/signout"), ui.post("/signin", data={"link": "x"}, headers={"Origin": ORIGIN}),
        ui.post("/signin", data={"link": link}, headers={"Origin": ORIGIN}),
    ]
    assert [r.status_code for r in responses] == [200, 200, 200, 404, 405, 403, 303]
    for response in responses:
        for name, value in SECURITY_HEADERS.items():
            assert response.headers.get(name) == value, (response.request.url, name)
        assert "strict-transport-security" not in response.headers


def test_the_stylesheet(ui):
    response = ui.get("/nervus.css")
    assert response.headers["content-type"].startswith("text/css")
    assert response.text == STYLESHEET


def test_a_large_request_is_refused(ui):
    assert ui.post("/signin", content=b"link=" + b"x" * 100_000,
                   headers={"Origin": ORIGIN, "Content-Type": "application/x-www-form-urlencoded"}).status_code == 413


def test_the_banner_stands_on_every_signed_in_page(db, audit):
    from nervus.exposure import check
    from nervus.first_run import FirstRun
    from nervus.ui import Setup

    FirstRun(db).choose_tier(1, by="operator")
    ui = _client(db, audit, setup=Setup(FirstRun(db), check("0.0.0.0", interfaces=lambda: ["1.2.3.4"])))
    assert "1.2.3.4" not in ui.get("/").text  # signed out: how to sign in, and nothing else
    _sign_in(ui, db)
    for path in ("/", "/audit", "/audit?at=0", "/setup"):
        assert 'role="alert">nervus listens on 1.2.3.4' in ui.get(path).text, path


def test_on_loopback_over_plain_http_the_cookie_does_without_secure(db, audit):
    """Plain HTTP is allowed on loopback only (ADR-0011 B); a Secure cookie,
    and so the __Host- name, needs HTTPS."""
    ui = _client(db, audit, secure=False, base="http://127.0.0.1:8443")
    link, _ = db.make_link()
    response = ui.post("/signin", data={"link": link}, headers={"Origin": "http://127.0.0.1:8443"})
    cookie = response.headers["set-cookie"]
    assert cookie.startswith("nervus-session=") and "secure" not in cookie.lower()
    assert "Sign out" in ui.get("/").text


# --- the audit log viewer: ADR-0013 ----------------------------------------------------------


def _exec(audit, command, token="codex-anywhere", host="node-b"):
    run_id = audit.record_intent("exec", {"token_id": token, "client": "codex", "project": "unscoped",
                                          "host": host, "user": "agent", "cwd": "~", "command": command})
    audit.record_result(run_id, "exec", {"exit_code": 0, "duration_s": 0.5, "output_bytes": 0,
                                         "truncated": False, "timed_out": False, "log_path": "x"})


def test_signed_out_the_viewer_shows_only_how_to_sign_in(ui, audit):
    """ADR-0011 verification 5, ADR-0013 verification 8."""
    _exec(audit, "cat /etc/secret-thing")
    for path in ("/audit", "/audit?at=0", "/audit?q=secret"):
        page = ui.get(path)
        assert page.status_code == 200 and "nervus-ctl signin" in page.text, path
        assert "secret-thing" not in page.text and "Audit log" not in page.text, path


def test_signed_in_the_viewer_shows_the_log_the_ui_was_given(ui, db, audit):
    """ADR-0013 verification 8, and ADR-0007 verification 7's first part: the
    log is readable in the UI. nervus gives the UI the file --audit-log names."""
    _exec(audit, "uname -a")
    _sign_in(ui, db)
    page = ui.get("/audit")
    assert page.status_code == 200
    assert "uname -a" in page.text and "codex-anywhere" in page.text
    assert "signin" in page.text  # the operator's own sign-in, the newest row


def test_reading_the_log_writes_nothing_to_it(ui, db, audit):
    """ADR-0013 decision G: views are not audited."""
    _exec(audit, "true")
    _sign_in(ui, db)
    before = audit.path.read_bytes()
    first = ui.get("/audit").text
    at = re.search(r'href="audit\?at=(\d+)"', first).group(1)
    for path in ("/audit", f"/audit?at={at}", "/audit?q=true&kind=call", "/audit?client=nobody"):
        assert ui.get(path).status_code == 200, path
    assert audit.path.read_bytes() == before


def test_filters_search_and_a_rows_own_page_from_the_address(ui, db, audit):
    _exec(audit, "ls /srv", token="a", host="node-a")
    _exec(audit, "df -h", token="b", host="node-b")
    audit.record_refusal("initialize", {"token_id": "c", "client": "x", "project": "y", "reason": "switches: disabled"})
    _sign_in(ui, db)

    def subjects(path):
        return re.findall(r'<td class="subject"><code>([^<]*)</code>', ui.get(path).text)

    assert subjects("/audit?client=a") == ["ls /srv"]
    assert subjects("/audit?host=node-b") == ["df -h"]
    assert subjects("/audit?kind=refused") == ["switches: disabled"]
    # Not "DF" alone: the search reads every field, and a run id is hex.
    assert subjects("/audit?tool=exec&q=DF+-H") == ["df -h"]
    assert subjects("/audit?q=nothing+like+it") == []
    at = re.search(r'href="audit\?at=(\d+)">', ui.get("/audit?client=a").text).group(1)
    row = ui.get(f"/audit?at={at}")
    assert row.status_code == 200 and "ls /srv" in row.text and "result, at byte" in row.text


def test_paging_from_the_address(ui, db, audit):
    for i in range(205):
        _exec(audit, f"echo {i}")
    _sign_in(ui, db)
    first = ui.get("/audit").text
    older = re.search(r'href="(audit\?before=\d+&amp;upto=\d+)">Older', first).group(1).replace("&amp;", "&")
    second = ui.get("/" + older).text
    # 100 rows a page, the newest being the operator's own sign-in
    assert "<code>echo 204</code>" in first and "<code>echo 106</code>" in first
    assert "<code>echo 105</code>" not in first
    assert "<code>echo 105</code>" in second and "<code>echo 6</code>" in second
    assert "<code>echo 106</code>" not in second and "<code>echo 5</code>" not in second
    assert ">Most recent</a>" in second and ">Most recent</a>" not in first


@pytest.mark.parametrize("at", ["abc", "-1", "1e3", "\uff11", "3", "99999999", "1" * 30])
def test_a_position_that_is_not_a_record_is_not_found(ui, db, audit, at):
    _exec(audit, "true")
    _sign_in(ui, db)
    page = ui.get("/audit", params={"at": at})
    assert page.status_code == 404 and "No record starts there." in page.text


@pytest.mark.parametrize("query", ["before=abc&upto=1", "before=-5&upto=10", "before=10", "upto=10",
                                   "before=1&upto=99999999999999999999999"])
def test_a_page_position_that_does_not_fit_is_ignored(ui, db, audit, query):
    _exec(audit, "the newest")
    _sign_in(ui, db)
    page = ui.get(f"/audit?{query}")
    assert page.status_code == 200 and "the newest" in page.text


def test_a_log_nervus_cannot_read_is_said_so_not_hidden(db, tmp_path):
    audit = AuditLog(path=tmp_path / "audit.jsonl")
    ui = _client(db, audit)
    _sign_in(ui, db)
    audit.path.unlink()
    audit.path.mkdir()
    page = ui.get("/audit")
    assert page.status_code == 500 and "nervus could not read its audit log" in page.text
    assert ui.get("/audit?at=0").status_code == 500


def test_the_viewer_carries_the_protections_and_only_reads(ui, db, audit):
    _sign_in(ui, db)
    for response in (ui.get("/audit"), ui.get("/audit?at=0"), ui.post("/audit", headers={"Origin": ORIGIN})):
        for name, value in SECURITY_HEADERS.items():
            assert response.headers.get(name) == value, (response.request.url, name)
    assert ui.post("/audit", headers={"Origin": ORIGIN}).status_code == 405


def test_the_log_is_read_off_the_thread_that_answers_requests(ui, db, audit, monkeypatch):
    """ADR-0013 consequence 1: a long read must not stop nervus answering, so
    it runs in a worker thread, where no event loop is running."""
    import asyncio

    from nervus import audit_view, ui as ui_module

    seen = []

    def reading(real):
        def read(*args):
            try:
                asyncio.get_running_loop()
                seen.append("event loop")
            except RuntimeError:
                seen.append("worker")
            return real(*args)
        return read

    monkeypatch.setattr(ui_module, "read_page", reading(audit_view.read_page))
    monkeypatch.setattr(ui_module, "read_row", reading(audit_view.read_row))
    _sign_in(ui, db)
    ui.get("/audit")
    ui.get("/audit?at=0")
    assert seen == ["worker", "worker"]


# --- client management: ADR-0014 ------------------------------------------------------

from nervus.auth import Token, Tokens  # noqa: E402
from nervus.switches import load_switches  # noqa: E402
from nervus.ui import Management  # noqa: E402

FILE_TOKENS = {"file-value": Token(id="codex-anywhere", client="codex", project="unscoped",
                                   hosts=frozenset({"node-a", "node-b"}))}
HOSTS = ["node-a", "node-b", "hv", "hv-root"]
# hv-root is marked `issue: never` in this inventory (ADR-0019 decision D).
NEVER_ISSUED = frozenset({"hv-root"})


@pytest.fixture
def managed(db, audit, tmp_path):
    switches = tmp_path / "switches.yaml"
    switches.write_text("lockdown: false\ndisabled: []\n")
    tokens = Tokens(FILE_TOKENS, db.token)
    client = TestClient(build_ui(db, audit, secure=True, management=Management(tokens, switches, HOSTS, NEVER_ISSUED)),
                        base_url=ORIGIN, follow_redirects=False)
    _sign_in(client, db)
    return client, tokens, switches


def _act(browser, **fields):
    page = browser.get("/clients")
    token = _hidden(page.text, "form_token")
    data = {"form_token": token, **fields}
    return browser.post("/clients", data=data, headers={"Origin": ORIGIN})


def _ui_records(audit, action=None):
    return [r for r in _records(audit) if r.get("tool") == "ui" and r["action"] in ((action,) if action else
                                                                                       ("lock", "unlock", "issue_token", "revoke_token"))]


def test_signed_out_the_clients_page_shows_only_how_to_sign_in(ui):
    page = ui.get("/clients")
    assert "nervus-ctl signin" in page.text and "codex-anywhere" not in page.text
    assert ui.post("/clients", data={"action": "lockdown-on"}, headers={"Origin": ORIGIN}).status_code in (200, 403)


def test_the_clients_page_lists_the_files_and_the_databases_tokens(managed, db):
    client, tokens, _ = managed
    db.issue_token("laptop", "claude-code", "laptop", ["hv"], taken=tokens.file_ids())
    page = client.get("/clients")
    assert page.status_code == 200
    assert "codex-anywhere" in page.text and "laptop" in page.text and "issued in the UI" in page.text


def test_an_entry_marked_never_issued_is_not_offered(managed):
    """ADR-0009 decision 3 and ADR-0019 decision D: the inventory decides, not the name."""
    client, _, _ = managed
    offered = re.findall(r'name="hosts" value="([^"]+)"', client.get("/clients").text)
    assert offered == ["node-a", "node-b", "hv"]


def test_switching_a_client_off_and_on_takes_effect_and_is_audited(managed, audit):
    """ADR-0014 verification 3."""
    client, _, switches = managed
    response = _act(client, action="off", id="codex-anywhere")
    assert response.status_code == 303 and response.headers["location"] == "clients"
    assert load_switches(switches).disabled == {"codex-anywhere"}
    assert _act(client, action="on", id="codex-anywhere").status_code == 303
    assert load_switches(switches).disabled == frozenset()
    records = _ui_records(audit)
    assert [(r["action"], r["target"], r["actor"]) for r in records] == [
        ("lock", "codex-anywhere", "operator"), ("unlock", "codex-anywhere", "operator")]
    assert all(r["address"] for r in records)


def test_lockdown_on_and_off(managed, audit):
    client, _, switches = managed
    _act(client, action="off", id="codex-anywhere")
    assert _act(client, action="lockdown-on").status_code == 303
    assert load_switches(switches).lockdown is True
    assert _act(client, action="lockdown-off").status_code == 303
    assert load_switches(switches) == load_switches(switches).__class__(lockdown=False,
                                                                        disabled=frozenset({"codex-anywhere"}))
    assert [(r["action"], r["target"]) for r in _ui_records(audit)][1:] == [("lock", "all"), ("unlock", "all")]


def test_issuing_shows_the_value_once_and_it_works_at_once(managed, audit, db):
    """ADR-0006 verification 9 and ADR-0014 verification 1: no file of
    nervus's edited, no restart."""
    client, tokens, _ = managed
    response = _act(client, action="issue", id="laptop", client="claude-code", project="laptop",
                    hosts=["node-a", "hv"])
    assert response.status_code == 200, response.text
    value = re.search(r"<pre><code>([A-Za-z0-9_-]{43})</code></pre>", response.text).group(1)
    token = tokens.get(value)
    assert (token.id, sorted(token.hosts)) == ("laptop", ["hv", "node-a"])
    record, = _ui_records(audit, "issue_token")
    assert (record["target"], record["hosts"], record["client"]) == ("laptop", ["hv", "node-a"], "claude-code")
    assert value not in audit.path.read_text()


@pytest.mark.parametrize("fields, why", [
    ({"hosts": ["hv-root"]}, "hv-root is never issued"),
    ({"hosts": ["node-a", "elsewhere"]}, "elsewhere"),
    ({"hosts": []}, "host"),
    ({"id": "codex-anywhere"}, "already"),
    ({"id": "Bad Id"}, "id"),
])
def test_a_token_that_cannot_be_issued_is_refused_and_says_why(managed, db, fields, why):
    client, _, _ = managed
    data = {"action": "issue", "id": "laptop", "client": "c", "project": "p", "hosts": ["node-a"], **fields}
    response = _act(client, **data)
    assert response.status_code == 400 and why in response.text
    assert db.issued_tokens() == []


def test_revoking_needs_the_id_typed_and_then_the_token_is_refused(managed, audit, db):
    """ADR-0014 decision E and verification 2."""
    client, tokens, _ = managed
    value = db.issue_token("laptop", "c", "p", ["node-a"], taken=tokens.file_ids())
    for typed in ("", "LAPTOP", "laptop "):
        response = _act(client, action="revoke", id="laptop", confirm=typed)
        assert response.status_code == 400 and "type" in response.text
        assert tokens.get(value) is not None
    assert _act(client, action="revoke", id="laptop", confirm="laptop").status_code == 303
    assert tokens.get(value) is None
    assert [r["target"] for r in _ui_records(audit, "revoke_token")] == ["laptop"]
    response = _act(client, action="revoke", id="codex-anywhere", confirm="codex-anywhere")
    assert response.status_code == 400  # a token in the file is not the UI's to revoke


def test_a_change_without_nervuss_own_form_changes_nothing(managed):
    client, _, switches = managed
    real = _hidden(client.get("/clients").text, "form_token")
    for headers, data in [({"Origin": ORIGIN}, {"action": "lockdown-on"}),
                          ({"Origin": ORIGIN}, {"action": "lockdown-on", "form_token": "forged"}),
                          ({"Origin": "https://evil.example"}, {"action": "lockdown-on"}),
                          # even with the real token, from another site's page
                          ({"Origin": "https://evil.example"}, {"action": "lockdown-on", "form_token": real})]:
        assert client.post("/clients", data=data, headers=headers).status_code == 403
    assert load_switches(switches).lockdown is False


@pytest.mark.parametrize("fields", [{"action": "off", "id": "nobody"}, {"action": "on", "id": "codex-anywhere"},
                                    {"action": "explode"}])
def test_an_action_that_does_not_apply_changes_nothing(managed, fields):
    client, _, switches = managed
    before = switches.read_text()
    assert _act(client, **fields).status_code == 400
    assert switches.read_text() == before


def test_an_unreadable_switch_file_is_said_and_left_alone(managed):
    client, _, switches = managed
    switches.write_text("lockdown: [\n")
    response = _act(client, action="off", id="codex-anywhere")
    assert response.status_code == 409 and "unreadable" in response.text
    assert switches.read_text() == "lockdown: [\n"


def test_without_its_audit_record_only_taking_access_away_stands(managed, audit, db, capsys):
    """ADR-0001 s10, as ADR-0012 applied it to sign-in and sign-out: what cannot
    be audited does not happen, except taking access away."""
    client, tokens, switches = managed
    _act(client, action="off", id="codex-anywhere")
    audit.path.unlink()
    audit.path.mkdir()  # every write to the audit log now fails
    assert _act(client, action="on", id="codex-anywhere").status_code == 500
    assert load_switches(switches).disabled == {"codex-anywhere"}  # switched back off
    assert _act(client, action="lockdown-on").status_code == 303
    assert load_switches(switches).lockdown is True  # stands
    assert _act(client, action="lockdown-off").status_code == 500
    assert load_switches(switches).lockdown is True
    response = _act(client, action="issue", id="laptop", client="c", project="p", hosts=["node-a"])
    assert response.status_code == 500 and "<pre><code>" not in response.text
    assert db.issued_tokens() == []
    assert "not audited" in capsys.readouterr().err


def test_the_clients_pages_carry_the_protections(managed):
    client, _, _ = managed
    for response in (client.get("/clients"), _act(client, action="issue", id="laptop", client="c", project="p",
                                                  hosts=["node-a"])):
        for name, value in SECURITY_HEADERS.items():
            assert response.headers.get(name) == value, name
