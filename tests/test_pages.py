"""The UI's pages (ADR-0012 decision 2): HTML nervus makes itself, with every
value escaped unless nervus marked it as its own markup. The audit log, which
the UI will show, holds text an attacker chooses, so this is a security
property, tested by pushing hostile text through every page."""

import inspect
import json
import re
import time
import unicodedata
from html.parser import HTMLParser

import pytest

import nervus
from nervus import pages
from nervus.audit_view import Cursor, Entry, Query, Row
from nervus.clients import ClientRow, ClientsView
from nervus.enrolled_hosts import EnrolledHost
from nervus.enrollment_codes import EnrollmentCode
from nervus.exposure import Declared
from nervus.host_login import LoginRun
from nervus.restore import BackupFile
from nervus.pages import PAGES, STYLESHEET, Markup, Standing, escape, join, render

T0 = 1_800_000_000.0

HOSTILE = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "' autofocus onfocus='alert(1)",
    "</form><form action=https://evil.example><button>",
    "<!-- --><style>body{display:none}</style>",
    "javascript:alert(1)",
    "&lt;already escaped&gt; &amp; &#60;",
    "{form_token} {link} {0}",  # a value is never read as part of the template
    "  ﻿",
    # ADR-0013 decision D: text that hides or reorders what it says
    "rm -rf /tmp/x\u202e/etc/passwd",
    "same\u200bname\u2060twice",
    "\x1b[31mred\x1b[0m\r\x00\x7f",
    "private \ue000 unassigned \u0378",
]

HIDDEN_CATEGORIES = {"Cc", "Cf", "Zl", "Zp", "Co", "Cn"}


def _shown(text):
    """`text` as a page shows it: every character that hides or reorders text
    as a visible code (ADR-0013 decision D), newline and tab as they are."""
    return "".join(f"\u27e8U+{ord(c):04X}\u27e9" if unicodedata.category(c) in HIDDEN_CATEGORIES
                   and c not in "\n\t" else c for c in text)


def _unmarked(page):
    """The page without the marks nervus puts round a hidden character's code.
    Hostile text cannot make one: its < is escaped."""
    return page.replace("<mark>", "").replace("</mark>", "")


class Parsed(HTMLParser):
    """What a browser would build from a page: the tags with their
    attributes, and the text."""

    def __init__(self, page: str):
        super().__init__(convert_charrefs=True)
        self.tags: list[tuple[str, list[tuple[str, str | None]]]] = []
        self.ends: list[str] = []
        self.text: list[str] = []
        self.comments: list[str] = []
        self.feed(page)
        self.close()

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, attrs))

    def handle_startendtag(self, tag, attrs):
        self.tags.append((tag, attrs))

    def handle_endtag(self, tag):
        self.ends.append(tag)

    def handle_data(self, data):
        self.text.append(data)

    def handle_comment(self, data):
        self.comments.append(data)

    def structure(self):
        """Tags and attribute names, in order: what an injection would change."""
        return [(tag, sorted(name for name, _ in attrs)) for tag, attrs in self.tags], self.ends, self.comments

    def values(self) -> str:
        return "\n".join(self.text + [v or "" for _, attrs in self.tags for _, v in attrs])


def _row(*records, offset=0):
    """A row of the audit viewer, from records as nervus writes them, or from
    bytes for a line that holds none."""
    entries = []
    for record in records:
        raw = record if isinstance(record, bytes) else json.dumps(record, sort_keys=True).encode()
        entries.append(Entry(offset, raw, None if isinstance(record, bytes) else record))
        offset += len(raw) + 1
    return Row(tuple(entries))


def _hostile_rows(text):
    """A row of every kind the log holds, with `text` in every field an agent,
    a client, a hand edit or a damaged file could fill (ADR-0013
    consequence 2)."""
    who = {"token_id": text, "client": text, "project": text}
    return [
        _row({"id": text, "phase": "intent", "ts": T0, "tool": text, **who, "host": text, "user": text,
              "cwd": text, "command": text},
             {"id": text, "phase": "result", "ts": T0, "tool": text, "exit_code": 0, "duration_s": 1.5,
              "output_bytes": 3, "truncated": False, "timed_out": False, "log_path": text}),
        _row({"id": text, "phase": "intent", "ts": T0, "tool": "proxmox", **who, "host": text, "method": text,
              "path": text, "params": {text: text}},
             {"id": text, "phase": "result", "ts": T0, "tool": "proxmox", "status": 403, "reason": text}),
        _row({"id": text, "phase": "intent", "ts": T0, "tool": "put", **who, "host": text, "local_path": text,
              "remote_path": text}),
        _row({"id": text, "phase": "intent", "ts": T0, "tool": "job", **who, "host": text, "job_id": text,
              "action": text}),
        _row({"id": text, "phase": "result", "ts": T0, "tool": "hosts", "count": 1, "hosts": [text]}),
        _row({"id": text, "phase": "refused", "ts": T0, "tool": text, **who, "reason": text, "local_path": text}),
        _row({"id": text, "phase": "operator", "ts": T0, "tool": "ui", "actor": "operator", "action": text,
              "target": text, "outcome": [text], "address": text}),
        _row({"id": text, "phase": text, "ts": text, text: text}),
        _row(text.encode("utf-8", "surrogatepass")),
    ]


def _arguments(page, text):
    """Every parameter of a page: text where it takes text, a time where it
    takes one, and for the audit viewer, rows and filters full of it."""
    rows = _hostile_rows(text)
    made = {
        "float": T0,
        "bool": True,
        "list[Row]": rows,
        "Row | None": rows[0],
        "Query": Query(client=text, host=text, tool=text, kind=text, text=text),
        "Cursor | None": Cursor(before=10, horizon=20),
        "list[str]": [text, "hv-root"],
        "ClientsView": ClientsView(rows=[
            ClientRow(id=text, client=text, project=text, hosts=(text,), issued=True, off=True, last_call=T0),
            ClientRow(id=text, client=text, project=text, hosts=(text,), issued=False, off=False,
                      last_call=None),
        ], lockdown=True, unreadable=text),
        "list[EnrolledHost]": [EnrolledHost(name=text, address=text, level=text, host_keys=(text,),
                                            machine_id=text, enrolled_at=T0, enrolled_by=text)],
        "list[EnrollmentCode]": [
            EnrollmentCode(id=text, name=text, address=text, level=text, made_at=T0, expires_at=T0 + 900,
                           made_by=text, used_at=T0 + 60, outcome=text),
            EnrollmentCode(id=text, name=text, address="", level=text, made_at=T0, expires_at=T0 + 900,
                           made_by=text, used_at=None, outcome=None),
        ],
        # A run that has ended, so its outcome and the way on from it are on the page as well.
        "LoginRun": LoginRun(code_id=text, name=text, address=text, level=text, login=text, fingerprint=text,
                             started_at=T0, lines=[text, text], finished_at=T0 + 5, enrolled=False, outcome=text),
        "Standing": Standing(tier=2, warning=text, notes=(text, text)),
        "int | None": 2,
        "list[Declared]": [Declared(network=text, by=text, on=text)],
        "list[BackupFile]": [BackupFile(name=text, size=12_100_000, made_at=T0)],
    }
    return {name: made.get(param.annotation, text) for name, param in inspect.signature(page).parameters.items()}


def _hostile_row_pages(text):
    """The audit viewer's own page for every kind of row."""
    return [(f"page_audit_row {i}", pages.page_audit_row(row=row, until=T0, form_token="tok"))
            for i, row in enumerate(_hostile_rows(text))]


def _every_page(text="benign"):
    return [(page.__name__, page(**_arguments(page, text))) for page in PAGES] + _hostile_row_pages(text)


# --- the builder --------------------------------------------------------------------


def test_escape_shows_characters_that_hide_or_reorder_text_as_marked_codes():
    """ADR-0013 decision D: a direction control, an invisible character or a
    control character would make text read as something it is not. Each is
    shown as its code, marked; other text, in any script, is left alone."""
    for c in ("\u202e", "\u2066", "\u200b", "\u2060", "\ufeff", "\u2028", "\u2029", "\x1b", "\r",
              "\x00", "\x7f", "\x85", "\ue000", "\u0378", "\U000e0041"):
        assert escape(f"a{c}b") == f"a<mark>\u27e8U+{ord(c):04X}\u27e9</mark>b", repr(c)
    for text in ("line\nnext\ttab", "em \u2014 dash", "caf\u00e9", "\u65e5\u672c\u8a9e", "\u03a9",
                 "non\u00a0breaking"):
        assert escape(text) == text
    assert escape("<\u202e>") == "&lt;<mark>\u27e8U+202E\u27e9</mark>&gt;"
    assert escape(Markup("\u202e")) == "\u202e"


def test_escape_makes_text_inert_and_leaves_markup_alone():
    assert escape("<a href='x' title=\"y\">&") == "&lt;a href=&#x27;x&#x27; title=&quot;y&quot;&gt;&amp;"
    assert escape(Markup("<b>")) == "<b>"
    assert isinstance(escape("x"), Markup)
    assert escape(42) == "42"


def test_render_escapes_every_value_and_never_reads_one_as_template():
    assert render("<p>{x}</p>", x="<i>") == "<p>&lt;i&gt;</p>"
    assert render("<p>{x}</p>", x=Markup("<i>")) == "<p><i></p>"
    assert render("<p>{x}</p>", x="{x}{y}") == "<p>{x}{y}</p>"
    assert isinstance(render("<p></p>"), Markup)


def test_join_escapes_each_piece():
    assert join(["<a>", Markup("<b>"), 1]) == "&lt;a&gt;<b>1"


# --- every page -----------------------------------------------------------------


@pytest.mark.parametrize("hostile", HOSTILE)
def test_hostile_text_in_every_page_comes_out_as_text(hostile):
    """ADR-0012 verification 1 and ADR-0013 verification 4. Every text
    parameter of every page gets the hostile value. The page must have exactly
    the tags and attributes it has with harmless text, apart from the marks on
    hidden characters, and show the hostile text as it was given, with each
    hidden character as its code."""
    for (name, benign), (_, attacked) in zip(_every_page(), _every_page(hostile)):
        assert Parsed(_unmarked(attacked)).structure() == Parsed(benign).structure(), name
        assert _shown(hostile) in Parsed(_unmarked(attacked)).values(), name
        assert ("<mark>" in attacked) == (_shown(hostile) != hostile), name


def test_every_page_is_tested():
    """A page left out of PAGES would escape the hostile-text test."""
    made = {f for _, f in inspect.getmembers(pages, inspect.isfunction)
            if f.__name__.startswith("page_") and f.__module__ == pages.__name__}
    assert made == set(PAGES)
    assert all(inspect.signature(p).return_annotation == "Markup" for p in PAGES)


def test_no_page_runs_a_script_or_loads_anything_from_elsewhere():
    """ADR-0012 verification 1, and what the UI's content security policy will
    hold every page to (step 5): no script, no inline style, nothing from
    another address. Links are relative, so the UI works under a path too."""
    for name, page in _every_page():
        parsed = Parsed(page)
        for tag, attrs in parsed.tags:
            assert tag not in ("script", "style", "iframe", "object", "embed", "img"), name
            for attr, value in attrs:
                assert not attr.startswith("on") and attr != "style", (name, tag, attr)
                if attr in ("href", "src", "action", "formaction"):
                    assert not re.match(r"^(?:[a-z][a-z0-9+.-]*:|//|/)", value or "", re.I), (name, attr, value)
        assert page.startswith("<!doctype html>"), name
        assert '<meta charset="utf-8">' in page, name
    assert "url(" not in STYLESHEET and "@import" not in STYLESHEET


def _forms(page):
    parsed = Parsed(page)
    forms, current = [], None
    for tag, attrs in parsed.tags:
        a = dict(attrs)
        if tag == "form":
            current = {"method": a.get("method"), "action": a.get("action"), "fields": {}, "buttons": 0}
            forms.append(current)
        elif tag == "input" and current is not None:
            current["fields"][a.get("name")] = (a.get("type"), a.get("value"))
        elif tag == "button" and current is not None:
            current["buttons"] += 1
    return forms


def test_signed_out_shows_only_how_to_sign_in():
    """ADR-0011 verification 5: without a session, the UI shows nothing but how
    to sign in."""
    page = pages.page_signed_out(notice="")
    assert "nervus-ctl signin" in page
    assert _forms(page) == []
    assert "Sign out" not in page
    assert "That link" in pages.page_signed_out(notice="That link cannot be used.")


def test_signin_has_one_button_that_posts_the_link():
    """ADR-0012 decision 4: opening the link shows this page; only pressing the
    button uses the link, so a preview or a fetch ahead cannot."""
    page = pages.page_signin(link="abc-123_XYZ")
    assert _forms(page) == [{"method": "post", "action": "signin",
                             "fields": {"link": ("hidden", "abc-123_XYZ")}, "buttons": 1}]


def test_home_has_sign_out_and_says_when_the_session_ends():
    page = pages.page_home(until=T0, form_token="tok")
    assert _forms(page) == [{"method": "post", "action": "signout",
                             "fields": {"form_token": ("hidden", "tok")}, "buttons": 1}]
    assert time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(T0)) in page
    assert 'role="alert"' not in page


def test_home_carries_a_standing_banner_when_given_one():
    """Room for ADR-0007 decision 4's banner, which no page can hide."""
    page = pages.page_home(until=T0, form_token="tok", standing=Standing(warning="This nervus has a public address."))
    parsed = Parsed(page)
    assert ("div", [("class", "banner"), ("role", "alert")]) in parsed.tags
    assert "This nervus has a public address." in parsed.values()


# --- first-run setup: ADR-0015 -------------------------------------------------------


def _framed():
    """Every page a signed-in browser sees, with the arguments the hostile test uses."""
    return [page for page in PAGES if "standing" in inspect.signature(page).parameters]


def test_every_signed_in_page_can_carry_the_standing_lines():
    assert {p.__name__ for p in PAGES} - {p.__name__ for p in _framed()} == {"page_signed_out", "page_signin"}


@pytest.mark.parametrize("page", _framed(), ids=lambda p: p.__name__)
def test_every_signed_in_page_shows_the_tier_the_warning_and_each_note(page):
    # ADR-0015 decisions C and E; ADR-0007 decision 4: no page can leave them out.
    standing = Standing(tier=3, warning="public, undeclared", notes=("noted one", "noted two"))
    parsed = Parsed(page(**{**_arguments(page, "benign"), "standing": standing}))
    assert ("div", [("class", "banner"), ("role", "alert")]) in parsed.tags
    assert [t for t in parsed.tags if t == ("div", [("class", "note"), ("role", "status")])] == [
        ("div", [("class", "note"), ("role", "status")])] * 2
    text = parsed.values()
    assert "public, undeclared" in text and "noted one" in text and "noted two" in text
    assert "Tier 3" in text
    assert ("a", [("class", "tier"), ("href", "setup")]) in parsed.tags


@pytest.mark.parametrize("page", _framed(), ids=lambda p: p.__name__)
def test_with_nothing_to_say_a_page_has_no_banner_and_says_no_tier_is_chosen(page):
    args = _arguments(page, "benign")
    args.pop("standing")
    page_text = page(**args)
    assert 'class="banner" role="alert"' not in page_text and 'class="note"' not in page_text
    assert "Tier not chosen" in Parsed(page_text).values()


def test_a_note_never_wears_the_warnings_colours():
    # ADR-0015 C: reduced to a standing note, never nothing, and not the full banner.
    page = pages.page_home(until=T0, form_token="tok", standing=Standing(notes=("declared",)))
    assert 'role="alert"' not in page and 'class="note" role="status"' in page


def _setup(**given):
    args = {"tier": None, "declared": [], "public": [], "until": T0, "form_token": "tok", **given}
    return pages.page_setup(**args)


def test_setup_states_the_non_goals_in_plain_words():
    # ADR-0007 decisions 9 and 10, verification 1; ADR-0015 verification 5.
    text = " ".join(Parsed(_setup()).values().split())
    for words in ("What nervus does not defend against", "Programs running as you",
                  "anyone with root on its machine", "unlocked computer",
                  "can do anything you could there", "its own data",
                  "one trust domain", "share all of it", "containment and accountability",
                  "Losing the recovery key, or giving it away", "A compromised nervus, by restoring it"):
        assert words in text, words


def test_setup_offers_the_three_tiers_in_adr_0023s_words():
    # ADR-0015 decision F: by which computer hosts nervus.
    page = _setup()
    radios = [dict(a) for t, a in Parsed(page).tags if t == "input" and dict(a).get("name") == "tier"]
    assert [r["value"] for r in radios] == ["1", "2", "3"]
    assert not any("checked" in r for r in radios)
    text = " ".join(Parsed(page).values().split())
    assert "different physical computer from your everyday one" in text
    assert "under an account of its own" in text
    assert "in a VM your everyday computer hosts" in text
    assert "Set up nervus" in text


def test_setup_marks_the_tier_already_chosen():
    radios = [dict(a) for t, a in Parsed(_setup(tier=2)).tags if t == "input" and dict(a).get("name") == "tier"]
    assert ["checked" in r for r in radios] == [False, True, False]


def test_setup_says_never_to_forward_a_port_whatever_the_check_found():
    # ADR-0015 decision C, as kept on 2026-10-20.
    for page in (_setup(), _setup(public=["1.2.3.4"])):
        text = " ".join(Parsed(page).values().split())
        assert "Never forward a port on your router to nervus" in text
        assert "overlay network" in text


def test_setup_names_the_addresses_that_look_public_or_says_there_are_none():
    assert "1.2.3.4, 5.6.7.8" in Parsed(_setup(public=["1.2.3.4", "5.6.7.8"])).values()
    assert "none that look public" in " ".join(Parsed(_setup()).values().split())


def test_setup_has_the_tier_form_the_declare_form_and_a_withdraw_for_each_range():
    declared = [Declared("1.2.3.0/24", by="operator", on="2026-10-20")]
    forms = _forms(_setup(tier=1, declared=declared))
    posted = [f for f in forms if f["action"] == "setup"]
    # In the page's order: the tier, each range's withdrawal in the table, then declaring one.
    assert [(f["method"], f["fields"]["action"]) for f in posted] == [
        ("post", ("hidden", "tier")), ("post", ("hidden", "withdraw")), ("post", ("hidden", "declare"))]
    assert all(f["fields"]["form_token"] == ("hidden", "tok") and f["buttons"] == 1 for f in posted)
    assert posted[1]["fields"]["network"] == ("hidden", "1.2.3.0/24")
    assert posted[2]["fields"]["network"][0] == "text"
    text = Parsed(_setup(declared=declared)).values()
    assert "1.2.3.0/24" in text and "operator" in text and "2026-10-20" in text


# --- the audit viewer: ADR-0013 ------------------------------------------------------


def _call_row(command="echo hi", offset=0):
    return _row({"id": "r1", "phase": "intent", "ts": T0, "tool": "exec", "token_id": "codex-anywhere",
                 "host": "node-b", "command": command},
                {"id": "r1", "phase": "result", "ts": T0 + 2, "tool": "exec", "exit_code": 0, "duration_s": 2.0},
                offset=offset)


def _links(page):
    return [dict(attrs).get("href") for tag, attrs in Parsed(page).tags if tag == "a"]


def test_every_signed_in_page_links_to_the_audit_log():
    """ADR-0013 decision I: the viewer is at `audit`, linked from every
    signed-in page's header."""
    signed_in = [(name, page) for name, page in _every_page() if "Sign out" in page]
    assert len(signed_in) == len(_every_page()) - 2  # all but signed out and a link's page
    for name, page in signed_in:
        assert "audit" in _links(page.split("</header>")[0]), name
    assert "audit" in _links(pages.page_home(until=T0, form_token="tok").split("</header>")[1])


def test_the_list_shows_one_row_per_call_and_opens_each():
    row = _call_row(offset=4096)
    page = pages.page_audit(rows=[row], query=Query(), older=None, paged=False, until=T0, form_token="tok")
    text = "".join(Parsed(page).text)
    for shown in (time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(T0)), "codex-anywhere", "exec", "node-b",
                  "echo hi", "exit 0 · 2.0 s"):
        assert shown in text, shown
    assert row.at > 4096 and f"audit?at={row.at}" in _links(page)  # where its result is
    assert "audit?client=codex-anywhere" in _links(page)
    assert "audit?host=node-b" in _links(page) and "audit?tool=exec" in _links(page)


def test_the_list_cuts_a_long_value_and_says_how_much_is_hidden():
    """ADR-0013 decision C."""
    page = pages.page_audit(rows=[_call_row("printf " + "A" * 32850 + "\nsecond line")], query=Query(),
                            older=None, paged=False, until=T0, form_token="tok")
    assert "A" * 153 in page and "A" * 154 not in page
    assert "second line" not in page
    assert "… 32,869 characters, 2 lines" in page


def test_the_filter_form_keeps_what_was_asked_and_changes_nothing():
    """ADR-0013 decision E: filters are in the address, so a view can be kept;
    the form is a GET, carrying no token, because it changes nothing."""
    page = pages.page_audit(rows=[], query=Query(client="c", host="h", tool="t", kind="refused", text="rm -rf"),
                            older=None, paged=False, until=T0, form_token="tok")
    forms = _forms(page)
    assert forms[1]["method"] == "get" and forms[1]["action"] == "audit"
    assert {k: v for k, (_, v) in forms[1]["fields"].items()} == {"client": "c", "host": "h", "tool": "t", "q": "rm -rf"}
    assert [dict(attrs) for tag, attrs in Parsed(page).tags if tag == "option" and ("selected", None) in attrs] \
        == [{"value": "refused", "selected": None}]
    assert "No records match." in page


def test_older_and_newest_links_carry_the_filters_and_the_position():
    query = Query(client="a b", kind="call")
    page = pages.page_audit(rows=[_call_row()], query=query, older=Cursor(before=120, horizon=900), paged=True,
                            until=T0, form_token="tok")
    links = _links(page)
    assert "audit?client=a+b&kind=call&before=120&upto=900" in links
    assert "audit?client=a+b&kind=call" in links
    first = pages.page_audit(rows=[_call_row()], query=Query(), older=None, paged=False, until=T0, form_token="tok")
    assert not any(link and "before=" in link for link in _links(first))
    assert "Older" not in first and "Newest" not in first


def test_a_rows_own_page_shows_every_field_of_every_record_in_full():
    """ADR-0013 decisions B and C: nothing is cut here."""
    command = "printf '%s' '" + "QUJD" * 8214 + "'\nsecond line"
    row = _call_row(command, offset=4096)
    page = pages.page_audit_row(row=row, until=T0, form_token="tok")
    values = "".join(Parsed(page).text)
    assert command in values
    for field in ("id", "phase", "ts", "tool", "token_id", "host", "command", "exit_code", "duration_s"):
        assert field in values, field
    assert "4096" in values and str(row.entries[1].offset) in values
    assert time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(T0)) in values


def test_a_rows_own_page_shows_objects_and_unreadable_lines_as_they_are():
    params = _row({"id": "p", "phase": "intent", "ts": T0, "tool": "proxmox", "params": {"node": "hv", "n": 2}})
    assert '"node": "hv"' in "".join(Parsed(pages.page_audit_row(row=params, until=T0, form_token="t")).text)
    broken = _row(b'{"phase": "intent", \xff garbled', offset=77)
    values = "".join(Parsed(pages.page_audit_row(row=broken, until=T0, form_token="t")).text)
    assert '{"phase": "intent", \\xff garbled' in values and "77" in values


def test_a_position_with_no_record_says_so():
    page = pages.page_audit_row(row=None, until=T0, form_token="tok")
    assert "No record starts there." in page


# --- client management: ADR-0014 ---------------------------------------------------


def _view(rows=(), lockdown=False, unreadable=""):
    return ClientsView(rows=list(rows), lockdown=lockdown, unreadable=unreadable)


FROM_FILE = ClientRow(id="codex-anywhere", client="codex", project="unscoped", hosts=("node-a", "node-b"),
                      issued=False, off=False, last_call=T0)
ISSUED_OFF = ClientRow(id="laptop", client="claude-code", project="laptop", hosts=("hv",), issued=True,
                       off=True, last_call=None)


def _clients(view, hosts=("node-a", "node-b", "hv")):
    return pages.page_clients(view=view, hosts=list(hosts), until=T0, form_token="tok")


def test_every_signed_in_page_links_to_the_clients_page():
    for name, page in _every_page():
        if "Sign out" in page:
            assert "clients" in _links(page.split("</header>")[0]), name


def test_each_token_shows_where_it_lives_its_state_its_last_call_and_its_label():
    """ADR-0014 decision G and ADR-0006 decision 7: unconfined, everywhere."""
    page = _clients(_view([FROM_FILE, ISSUED_OFF]))
    text = " ".join(" ".join(Parsed(page).text).split())
    for shown in ("codex-anywhere", "codex / unscoped", "node-a, node-b", "token file", "on",
                  time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(T0)),
                  "laptop", "claude-code / laptop", "issued in the UI", "OFF", "no call yet"):
        assert shown in text, shown
    assert text.count("unconfined: static token") == 2


def test_each_token_has_one_switch_and_only_issued_ones_can_be_revoked():
    """ADR-0014 decisions D and E: switching is one button; revoking asks for
    the id to be typed."""
    forms = _forms(_clients(_view([FROM_FILE, ISSUED_OFF])))
    actions = [(f["fields"].get("action", (None, None))[1], f["fields"].get("id", (None, None))[1])
               for f in forms if f["action"] == "clients"]
    assert ("off", "codex-anywhere") in actions and ("on", "laptop") in actions
    assert ("revoke", "laptop") in actions and ("revoke", "codex-anywhere") not in actions
    revoke = next(f for f in forms if f["fields"].get("action") == ("hidden", "revoke"))
    assert revoke["method"] == "post" and revoke["fields"]["confirm"] == ("text", None)
    assert all(f["fields"]["form_token"] == ("hidden", "tok") for f in forms)


def test_lockdown_is_one_button_that_says_what_it_does():
    off = _forms(_clients(_view(lockdown=False)))
    on_page = _clients(_view(lockdown=True))
    assert ("hidden", "lockdown-on") in [f["fields"].get("action") for f in off]
    assert ("hidden", "lockdown-off") in [f["fields"].get("action") for f in _forms(on_page)]
    assert "Lockdown is on" in on_page


def test_issuing_offers_the_hosts_it_is_given():
    """The page offers what it is given; leaving out an entry marked
    `issue: never` is the UI's (ADR-0019 decision D, tested in test_ui)."""
    page = _clients(_view())
    issue = next(f for f in _forms(page) if f["fields"].get("action") == ("hidden", "issue"))
    assert {"id", "client", "project"} <= set(issue["fields"])
    boxes = [dict(attrs) for tag, attrs in Parsed(page).tags if tag == "input" and dict(attrs).get("type") == "checkbox"]
    assert [b["value"] for b in boxes] == ["node-a", "node-b", "hv"]
    assert all(b["name"] == "hosts" for b in boxes)


def test_the_page_says_switching_off_does_not_stop_work_and_how_to():
    """ADR-0014 decision B and verification 8."""
    page = _clients(_view([FROM_FILE]))
    assert "nervus-ctl lock &lt;id&gt; --kill-work" in page or "nervus-ctl lock <id> --kill-work" in page


def test_an_unreadable_switch_file_is_said_at_the_top():
    page = _clients(_view([FROM_FILE], unreadable="cannot read /x: gone"))
    assert "every client is refused" in page and "cannot read /x: gone" in page


def test_an_issued_tokens_value_is_shown_once_and_never_in_a_form():
    page = pages.page_token_issued(token_id="laptop", value="V" * 43, until=T0, form_token="tok")
    assert ("V" * 43) in "".join(Parsed(page).text)
    assert all(("V" * 43) not in str(f) for f in _forms(page))
    assert "only time" in page
    assert "your password manager" in page  # names no product (ADR-0019)
    assert "clients" in _links(page)


def test_under_lockdown_a_client_on_says_so_and_still_offers_switch_off():
    page = _clients(_view([FROM_FILE], lockdown=True))
    assert "OFF (lockdown)" in page
    assert ("hidden", "off") in [f["fields"].get("action") for f in _forms(page)]


# --- which release runs: ADR-0029 ----------------------------------------------------

# Stands in for the package's own number, so a page showing any other, such as one written into pages.py, fails.
# Escaping changes its <, > and &, so a page that put it in unescaped fails too.
RELEASE = "0.0.0+<i>sentinel</i>&"


@pytest.mark.parametrize("page", _framed(), ids=lambda p: p.__name__)
def test_every_signed_in_page_says_which_release_runs(page, monkeypatch):
    # ADR-0029 question 2a: an installed nervus knows its own release, and says it in every signed-in page's header,
    # just after the name, escaped like every value.
    monkeypatch.setattr(nervus, "__version__", RELEASE)
    header = page(**_arguments(page, "benign")).split("</header>")[0]
    assert '<a class="name" href="./">nervus</a>\n<span class="release">' + escape(RELEASE) + "</span>" in header
    assert RELEASE in Parsed(header).text


@pytest.mark.parametrize("page", [p for p in PAGES if p not in _framed()], ids=lambda p: p.__name__)
def test_a_page_without_a_session_does_not_say_which_release_runs(page, monkeypatch):
    # ADR-0011 verification 5: without a session, the UI shows nothing but how to sign in. The number is looked for in
    # the page as sent, comments and all, and as installed as well: a page that read it other than at render time
    # would show that one, not the sentinel.
    installed = nervus.__version__
    monkeypatch.setattr(nervus, "__version__", RELEASE)
    page_text = page(**_arguments(page, "benign"))
    parsed = Parsed(page_text)
    for number in (RELEASE, escape(RELEASE), installed):
        assert number not in page_text and number not in parsed.values(), number
    assert not [attrs for _, attrs in parsed.tags if ("class", "release") in attrs]
