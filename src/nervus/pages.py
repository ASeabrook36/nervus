"""The UI's pages: plain HTML that nervus makes itself (ADR-0012 decision 2).

The UI will show text an attacker can choose: the audit log holds what agents
ran and what came back, and an agent can be steered by what it reads (ADR-0007,
adversary A). Text put into a page unescaped would run as code in the
operator's signed-in browser. So the only way to put a value into a page is
render(), which escapes it, unless the value is Markup: HTML nervus itself
wrote. Nothing that came from outside nervus is ever Markup.

Escaping stops text running; it does not stop text misleading. A direction
control makes a browser draw the text after it reversed, and invisible and
control characters make two different strings look alike, so a command could
read on screen as something other than what ran. escape() therefore also shows
each such character as its code, marked, on every page (ADR-0013 decision D).

Every page is a page_* function, listed in PAGES, and tests/test_pages.py
pushes hostile text through every text parameter of each one. No page runs a
script or loads anything from another address, and every link is relative,
so the UI also works under a path. The one thing a page does on its own is
reload itself, with a <meta> refresh, which the content security policy does
not govern: the progress page of an enrollment by login (ADR-0026).
"""

from __future__ import annotations

import html
import json
import re
import time
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import urlencode

import nervus
from nervus.audit_view import PAGE_ROWS, Cursor, Entry, Query, Row, cut
from nervus.clients import ClientRow, ClientsView
from nervus.database import LINK_SECONDS
from nervus.accounts import READONLY, READWRITE, MachineAccount
from nervus.enrolled_hosts import EnrolledHost
from nervus.enrollment_codes import EnrollmentCode
from nervus.exposure import Declared
from nervus.first_run import TIER_WORDS
from nervus.host_login import LoginRun
from nervus.restore import BackupFile


class Markup(str):
    """HTML nervus wrote, put into a page as it is. Everything else is escaped."""


# What Unicode classes as a control, a format character (direction controls
# and zero-width characters among them), a line or paragraph separator,
# private use, or unassigned: characters that show as nothing, or change how
# the text around them is drawn. Newline and tab are left as they are.
_HIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp", "Co", "Cn"})
# Every character but newline, tab and printable ASCII: the only ones worth
# asking unicodedata about.
_CANDIDATES = re.compile("[\x00-\x08\x0b-\x1f\x7f-\U0010ffff]")


def _mark_hidden(match: re.Match[str]) -> str:
    c = match.group()
    if unicodedata.category(c) not in _HIDDEN_CATEGORIES:
        return c
    # No quote in the mark, so in a quoted attribute it stays inside the value.
    return f"<mark>\u27e8U+{ord(c):04X}\u27e9</mark>"


def escape(value: object) -> Markup:
    """`value` as text a browser shows and never runs: &, <, >, " and ' made
    into character references, so it can stand in an element or a quoted
    attribute; and every character that hides or reorders text shown as its
    code, marked. Markup is left as it is."""
    if isinstance(value, Markup):
        return value
    return Markup(_CANDIDATES.sub(_mark_hidden, html.escape(str(value), quote=True)))


def render(template: str, **values: object) -> Markup:
    """Fill `template`, which is nervus's own, with `values`, each escaped.

    Only the template's {name} fields are read; a value is put in whole and
    never read for fields of its own. Templates hold no braces of their own:
    the stylesheet, the one place braces belong, is served apart.
    """
    return Markup(template.format_map({name: escape(value) for name, value in values.items()}))


def join(pieces: Iterable[object]) -> Markup:
    """Pieces one after another, each escaped unless it is Markup."""
    return Markup("".join(escape(piece) for piece in pieces))


def _when(timestamp: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(timestamp))


def _second(timestamp: float | None) -> str:
    """A time in the audit viewer: UTC, to the second (ADR-0013 decision I)."""
    return "\u2014" if timestamp is None else time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(timestamp))


_DOCUMENT = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
{refresh}<title>{title}</title>
<link rel="stylesheet" href="nervus.css">
</head>
<body>
{body}
</body>
</html>
"""


def _document(title: str, body: Markup, refresh_seconds: int | None = None) -> Markup:
    """`refresh_seconds`, given, makes the browser reload the page by itself
    that often: how a page shows progress where no script may run."""
    refresh = Markup(f'<meta http-equiv="refresh" content="{int(refresh_seconds)}">\n'
                     if refresh_seconds is not None else "")
    return render(_DOCUMENT, title=title, body=body, refresh=refresh)


def page_signed_out(notice: str = "") -> Markup:
    """What anyone without a session sees, and all they see (ADR-0011
    verification 5): how to sign in. `notice` says why they are here, such as a
    link that could not be used; never which reason it was (ADR-0012)."""
    return _document("nervus: sign in", render(
        """<main>
<h1>nervus</h1>
{notice}<p>To sign in, run this on the nervus machine, as root:</p>
<pre><code>nervus-ctl signin</code></pre>
<p>It prints a link that works once, within {minutes} minutes, and the certificate fingerprint
to check your browser&#x27;s warning against.</p>
</main>""",
        notice=render('<p class="notice">{notice}</p>\n', notice=notice) if notice else Markup(""),
        minutes=LINK_SECONDS // 60,
    ))


def page_signin(link: str) -> Markup:
    """What a sign-in link opens (ADR-0012 decision 4). Opening it uses
    nothing; pressing the button does, so a chat app's preview, or a browser
    fetching ahead, cannot spend the link. `link` comes from the address, which
    anyone can write, so it is escaped like everything else."""
    return _document("nervus: sign in", render(
        """<main>
<h1>Sign in to nervus</h1>
<p>This link works once. Press Sign in to use it.</p>
<form method="post" action="signin">
<input type="hidden" name="link" value="{link}">
<button type="submit">Sign in</button>
</form>
</main>""",
        link=link,
    ))


@dataclass(frozen=True)
class Standing:
    """What stands on every signed-in page, which no page can leave out: the
    tier declared at setup (ADR-0015 decision E), and the warning ADR-0007
    decision 4 requires while nervus listens on an address public in form and
    in no declared range, or for each declared one the note that replaces it
    (ADR-0015 decision C); and, where nervus makes backups, the warning a day
    without a new one gives (ADR-0027 question 4)."""
    tier: int | None = None
    warning: str = ""
    notes: tuple[str, ...] = ()
    backup_warning: str = ""


NO_STANDING = Standing()



def _frame(title: str, content: Markup, until: float, form_token: str, standing: Standing,
           wide: bool = False, refresh_seconds: int | None = None) -> Markup:
    """Every page of a signed-in browser: which release of nervus runs
    (ADR-0029 question 2a), the way to the audit log, when its session ends,
    Sign out, the tier, and the standing warning or notes, which no page can
    leave out."""
    return _document(title, render(
        """<header>
<a class="name" href="./">nervus</a>
<span class="release">{release}</span>
<a href="audit">Audit log</a>
<a href="clients">Clients</a>
<a href="machines">Machines</a>
<a href="backups">Backups</a>
<a class="tier" href="setup">{tier}</a>
<span class="session">Signed in until {until}</span>
<form method="post" action="signout">
<input type="hidden" name="form_token" value="{form_token}">
<button type="submit">Sign out</button>
</form>
</header>
{banner}{backup}{notes}<main{wide}>
{content}
</main>""",
        release=nervus.__version__,
        tier=TIER_WORDS.get(standing.tier, "Tier not chosen"),
        until=_when(until),
        form_token=form_token,
        banner=(render('<div class="banner" role="alert">{warning}</div>\n', warning=standing.warning)
                if standing.warning else Markup("")),
        notes=join(render('<div class="note" role="status">{note}</div>\n', note=note) for note in standing.notes),
        backup=(render('<div class="banner" role="alert">{warning} <a href="backups">Backups</a></div>\n',
                       warning=standing.backup_warning) if standing.backup_warning else Markup("")),
        wide=Markup(' class="wide"' if wide else ""),
        content=content,
    ), refresh_seconds)


def page_home(until: float, form_token: str, standing: Standing = NO_STANDING) -> Markup:
    """The page a browser lands on once signed in."""
    return _frame("nervus", render(
        """<h1>Signed in</h1>
<p>Your session ends at {until}.</p>
<p><a href="audit">Read the audit log</a>: every call agents made through nervus, every
refusal, and everything done as operator.</p>""",
        until=_when(until),
    ), until, form_token, standing)


# --- the audit log viewer (ADR-0013) ------------------------------------------------
#
# Everything a row shows came from the log, and so may have been written by an
# agent steered by hostile text (ADR-0007, adversary A). It goes into the page
# through render() like any other value, so it is escaped, and any character
# that hides or reorders text is shown as its code (decision D).

_KIND_NAMES = {"call": "Calls", "refused": "Refusals", "operator": "Operator actions"}


def _address(**values: object) -> str:
    """A relative address in the viewer, keeping only the values given."""
    kept = {name: value for name, value in values.items() if value not in ("", None)}
    return "audit?" + urlencode(kept) if kept else "audit"


def _filters(query: Query) -> dict[str, str]:
    return {"client": query.client, "host": query.host, "tool": query.tool, "kind": query.kind, "q": query.text}


def _filter_link(name: str, value: str) -> Markup:
    if not value:
        return Markup("")
    return render('<a href="{href}">{value}</a>', href=_address(**{name: value}), value=value)


def _list_row(row: Row) -> Markup:
    shown, left_out = cut(row.subject)
    return render(
        """<tr class="{kind}">
<td class="when"><a href="{href}">{when}</a></td>
<td>{client}</td>
<td>{tool}</td>
<td>{host}</td>
<td class="subject"><code>{shown}</code>{left_out}</td>
<td class="outcome">{outcome}</td>
</tr>
""",
        kind=row.kind,
        href=_address(at=row.at),
        when=_second(row.when),
        client=_filter_link("client", row.client),
        tool=_filter_link("tool", row.tool),
        # Each machine the row is about, a link to its own filter; each is Markup, made by render().
        host=join((Markup(" · ".join(_filter_link("host", name) for name in row.machines)),
                   render(' <span class="muted">({level})</span>', level=row.level) if row.level else Markup(""))),
        shown=shown,
        left_out=render(' <span class="left-out">{note}</span>', note=left_out) if left_out else Markup(""),
        outcome=row.outcome,
    )


def page_audit(rows: list[Row], query: Query, older: Cursor | None, paged: bool,
               until: float, form_token: str, standing: Standing = NO_STANDING, notice: str = "") -> Markup:
    """The audit log, most recent first, one row per call (ADR-0013 decisions
    B, C, E). `older` is where the next page starts, if anything is older;
    `paged` says this is not the most recent page. `notice` says why there are
    no rows, such as a log nervus could not read."""
    filters = _filters(query)
    kinds = join(
        render('<option value="{value}"{selected}>{name}</option>\n', value=value, name=name,
               selected=Markup(" selected" if value == query.kind else ""))
        for value, name in _KIND_NAMES.items()
    )
    links = []
    if paged:
        links.append(render('<a href="{href}">Most recent</a>', href=_address(**filters)))
    if older is not None:
        links.append(render('<a href="{href}">Older</a>',
                            href=_address(**filters, before=older.before, upto=older.horizon)))
    if notice:
        empty = render('<p class="notice">{notice}</p>\n', notice=notice)
    elif not rows:
        empty = Markup("<p>No records match.</p>\n")
    else:
        empty = Markup("")
    return _frame("nervus: audit log", render(
        """<h1>Audit log</h1>
<form method="get" action="audit" class="filters">
<label>Client <input type="text" name="client" value="{client}"></label>
<label>Host <input type="text" name="host" value="{host}"></label>
<label>Tool <input type="text" name="tool" value="{tool}"></label>
<label>Kind <select name="kind">
<option value="">Any</option>
{kinds}</select></label>
<label>Search <input type="search" name="q" value="{text}"></label>
<button type="submit">Show</button>
<a href="audit">Clear</a>
</form>
<p class="muted">Most recent first, {per_page} rows a page. Times are UTC.</p>
<div class="table">
<table>
<thead><tr><th>Time</th><th>Client</th><th>Tool</th><th>Host</th><th>What</th><th>Outcome</th></tr></thead>
<tbody>
{rows}</tbody>
</table>
</div>
{empty}<nav class="pages">{links}</nav>""",
        client=query.client, host=query.host, tool=query.tool, text=query.text, kinds=kinds,
        per_page=PAGE_ROWS, rows=join(_list_row(row) for row in rows), empty=empty,
        links=Markup(" ".join(links)),  # each is Markup, made by render()
    ), until, form_token, standing, wide=True)


def _value(name: str, value: object) -> Markup:
    if isinstance(value, str):
        text = value
    else:
        text = json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True)
    if name == "ts" and isinstance(value, (int, float)) and not isinstance(value, bool):
        text += f"  ({_second(value)} UTC)"
    return render('<pre class="value">{text}</pre>', text=text)


def _entry(entry: Entry) -> Markup:
    if entry.record is None:
        return render(
            """<section>
<h2>Unreadable line, at byte {offset}</h2>
<pre class="value">{text}</pre>
</section>
""", offset=entry.offset, text=entry.text())
    return render(
        """<section>
<h2>{phase}, at byte {offset}</h2>
<dl>
{fields}</dl>
</section>
""",
        phase=str(entry.phase) if entry.phase is not None else "record",
        offset=entry.offset,
        fields=join(render("<dt>{name}</dt>\n<dd>{value}</dd>\n", name=name, value=_value(name, value))
                    for name, value in sorted(entry.record.items())),
    )


def page_audit_row(row: Row | None, until: float, form_token: str, standing: Standing = NO_STANDING) -> Markup:
    """One row of the audit log, every record it came from, every field in
    full (ADR-0013 decisions B and C). None: no record starts where the
    address said."""
    if row is None:
        content = Markup('<h1>Audit log</h1>\n<p>No record starts there.</p>\n<p><a href="audit">Back to the audit log</a></p>')
    else:
        content = render(
            """<h1>{title}</h1>
<p><a href="audit">Back to the audit log</a></p>
<p>{outcome}</p>
{entries}""",
            title={"call": "Call", "refused": "Refused call", "operator": "Operator action",
                   "unreadable": "Unreadable record"}.get(row.kind, "Record"),
            outcome=row.outcome,
            entries=join(_entry(entry) for entry in row.entries),
        )
    return _frame("nervus: audit log", content, until, form_token, standing, wide=True)


# --- client management (ADR-0014) ---------------------------------------------------
#
# Every form posts to `clients` with the session's form token and an action.
# Switching off and on, and lockdown, are one button each: reversible, and in
# a bad moment speed matters. Revoking cannot be undone, so it asks for the id
# to be typed (decision E).

UNCONFINED = "unconfined: static token"


def _action(action: str, form_token: str, label: str, token_id: str = "", extra: Markup = Markup("")) -> Markup:
    return render(
        """<form method="post" action="clients" class="inline">
<input type="hidden" name="form_token" value="{form_token}">
<input type="hidden" name="action" value="{action}">
{id}{extra}<button type="submit">{label}</button>
</form>""",
        form_token=form_token, action=action, label=label, extra=extra,
        id=render('<input type="hidden" name="id" value="{id}">\n', id=token_id) if token_id else Markup(""),
    )


def _client_row(row: ClientRow, view: ClientsView, form_token: str) -> Markup:
    if view.unreadable:
        state = "refused: the switch file is unreadable"
    elif row.off:
        state = "OFF"
    elif view.lockdown:
        state = "OFF (lockdown)"
    else:
        state = "on"
    switch = (_action("on", form_token, "Switch on", row.id) if row.off
              else _action("off", form_token, "Switch off", row.id))
    revoke = _action("revoke", form_token, "Revoke", row.id, extra=Markup(
        '<input type="text" name="confirm" placeholder="type its id to revoke" autocomplete="off">\n'
    )) if row.issued else Markup("")
    return render(
        """<tr>
<td><code>{id}</code><br><span class="muted">{label}</span></td>
<td>{client} / {project}</td>
<td>{hosts}</td>
<td>{where}</td>
<td class="state">{state}</td>
<td>{last_call}</td>
<td class="actions">{switch}{revoke}</td>
</tr>
""",
        id=row.id, label=UNCONFINED, client=row.client, project=row.project,
        hosts=", ".join(f"{h} (read-only)" if h in row.readonly else h for h in row.hosts),
        where="issued in the UI" if row.issued else "token file", state=state,
        last_call="no call yet" if row.last_call is None else _second(row.last_call),
        switch=switch, revoke=revoke,
    )


def page_clients(view: ClientsView, hosts: list[str], until: float, form_token: str,
                 standing: Standing = NO_STANDING, notice: str = "", both: frozenset[str] = frozenset()) -> Markup:
    """Every client: on or off, lockdown, issuing a fallback token, and revoking
    one issued here (ADR-0014). `hosts` is the inventory's entries a token may
    be issued for: an entry marked `issue: never` is not among them (ADR-0009
    decision 3, ADR-0019 decision D). `notice` says why an action did not happen."""
    if view.lockdown:
        lockdown = render("""<div class="banner" role="status">Lockdown is on: every client is refused.</div>
{button}""", button=_action("lockdown-off", form_token, "Lift lockdown"))
    else:
        lockdown = render("""<p>Lockdown refuses every client at once, until it is lifted.</p>
{button}""", button=_action("lockdown-on", form_token, "Lockdown: refuse every client"))
    unreadable = render(
        '<p class="notice">The switch file is unreadable, so every client is refused: {why}. '
        'Fix it by hand on the nervus machine.</p>\n', why=view.unreadable) if view.unreadable else Markup("")
    # ADR-0031: a machine with both accounts asks for an explicit pick, nothing chosen beforehand.
    boxes = join(render('<label class="host"><input type="checkbox" name="hosts" value="{host}"> {host}</label>\n',
                        host=host) for host in hosts if host not in both)
    picks = join(render(
        """<fieldset class="pick"><legend>{host}</legend>
<label><input type="radio" name="level-{host}" value="none"> not on this token</label>
<label><input type="radio" name="level-{host}" value="read-only"> read-only</label>
<label><input type="radio" name="level-{host}" value="read-write"> read-write</label>
</fieldset>
""", host=host) for host in hosts if host in both)
    return _frame("nervus: clients", render(
        """<h1>Clients</h1>
{notice}{unreadable}<section>
<h2>Lockdown</h2>
{lockdown}
</section>
<section>
<h2>Tokens</h2>
<p class="muted">Every token here is a static token: whatever can read where a client keeps it can use
it. Switching a client off refuses its next call; work it already has running carries on. To stop that
too, run <code>nervus-ctl lock &lt;id&gt; --kill-work</code> on the nervus machine, as root.</p>
<div class="table">
<table>
<thead><tr><th>Token</th><th>Client / project</th><th>Hosts</th><th>Where</th><th>State</th><th>Last call</th><th></th></tr></thead>
<tbody>
{rows}</tbody>
</table>
</div>
</section>
<section>
<h2>Issue a token</h2>
<form method="post" action="clients" class="issue">
<input type="hidden" name="form_token" value="{form_token}">
<input type="hidden" name="action" value="issue">
<label>Id <input type="text" name="id" placeholder="laptop-codex" autocomplete="off"></label>
<label>Client <input type="text" name="client" placeholder="codex"></label>
<label>Project <input type="text" name="project" placeholder="laptop"></label>
<fieldset><legend>Hosts</legend>
{boxes}</fieldset>
{picks_note}{picks}<button type="submit">Issue</button>
</form>
<p class="muted">Its value is shown once, on the next page. Its hosts, and its level on each, cannot be changed
later: issue another and revoke this one.</p>
</section>""",
        notice=render('<p class="notice">{notice}</p>\n', notice=notice) if notice else Markup(""),
        unreadable=unreadable, lockdown=lockdown, form_token=form_token, boxes=boxes, picks=picks,
        picks_note=Markup('<p class="muted">Each machine below has a read-only account beside its read-write one: '
                          'choose for each whether this token is on it, and if so read-only or read-write.</p>\n')
        if picks else Markup(""),
        rows=join(_client_row(row, view, form_token) for row in view.rows),
    ), until, form_token, standing, wide=True)


def page_token_issued(token_id: str, value: str, until: float, form_token: str, standing: Standing = NO_STANDING) -> Markup:
    """A newly issued token's value, shown this once (ADR-0006 decision 7).
    nervus keeps only its hash; nothing can show it again."""
    return _frame("nervus: token issued", render(
        """<h1>Token issued: {id}</h1>
<p>This is the only time its value is shown. Put it in your password manager now, then give it to the client
through that client's own setting for a header or an environment variable.</p>
<pre><code>{value}</code></pre>
<p>It is a static token, unconfined: whatever can read where the client keeps it can use it.</p>
<p><a href="clients">Back to clients</a></p>""",
        id=token_id, value=value,
    ), until, form_token, standing)


# --- machines: enrolling and removing (ADR-0024) -------------------------------------
#
# Every form posts to `machines` with the session's form token and an action.
# Making a code and changing an address are one button each; removing cannot be
# undone from here, so it asks for the name to be typed, as revoking does.

LEVEL_WORDS = {
    "read-only": "read-only: nervus can read and run programs, but cannot change any file outside its own "
                 "folder ~/.nervus. The machine's kernel enforces it (bubblewrap).",
    "standard": "standard: nervus can change only what its own account owns. No sudo.",
    # ADR-0025 question 3a: asked where full access is chosen, since nervus cannot tell.
    "full": "full: nervus can do anything, with sudo and no password. Never for the machine nervus runs on. "
            "Does nervus run on this machine, as a VM or container? Then a client given full access here can "
            "rewrite nervus's audit log.",
}
PLAIN_HTTP = ("This nervus serves MCP over plain HTTP, so it cannot enroll a machine: the machine checks "
              "nervus's key before it runs anything nervus sends, and there is no key without HTTPS. Serve MCP "
              "over HTTPS first (docs/install.md).")


def _level_radios(chosen: str) -> Markup:
    """The three levels as radio buttons, `chosen` already chosen (read-only
    first, ADR-0005 decision 5)."""
    return join(render('<label class="level"><input type="radio" name="level" value="{level}"{checked}> {words}'
                       '</label>\n', level=level, words=words, checked=Markup(" checked" if level == chosen else ""))
                for level, words in LEVEL_WORDS.items())


def account_boxes(readwrite: str, readonly: str) -> Markup:
    """The two accounts' names (ADR-0031 question 8), filled in with nervus's."""
    return render(
        """<fieldset><legend>Accounts nervus makes there</legend>
<label>Read-write, at standard or full <input type="text" name="readwrite" value="{readwrite}" autocomplete="off"
 autocapitalize="none" spellcheck="false"></label>
<label>Read-only, always <input type="text" name="readonly" value="{readonly}" autocomplete="off"
 autocapitalize="none" spellcheck="false"></label>
</fieldset>
""", readwrite=readwrite, readonly=readonly)


def names_hidden(readwrite: str, readonly: str, typed_readwrite: str = "", typed_readonly: str = "") -> Markup:
    """The accounts' names, carried by a page that asks something else first."""
    return render(
        """<input type="hidden" name="readwrite" value="{readwrite}">
<input type="hidden" name="readonly" value="{readonly}">
<input type="hidden" name="typed_readwrite" value="{typed_readwrite}">
<input type="hidden" name="typed_readonly" value="{typed_readonly}">
""", readwrite=readwrite, readonly=readonly, typed_readwrite=typed_readwrite, typed_readonly=typed_readonly)


def page_names_confirm(name: str, names: list[tuple[str, str]], fields: dict[str, str], action: str, until: float,
                       form_token: str, standing: Standing = NO_STANDING) -> Markup:
    """Before a code whose accounts are not nervus's own names (ADR-0031
    question 8, as the operator added): what happens to an account that is
    there already, and each such name typed again to go on. `fields` is
    what the form asked for, carried."""
    carried = join(render('<input type="hidden" name="{k}" value="{v}">\n', k=k, v=v) for k, v in fields.items())
    typed = join(render('<label>Type {n} to go on <input type="text" name="{field}" autocomplete="off" '
                        'autocapitalize="none" spellcheck="false"></label>\n', n=n, field=field)
                 for n, field in names)
    return _frame("nervus: add a machine", render(
        """<h1>Use {accounts} on {name}?</h1>
<p class="notice">If {accounts} is already an account on {name}, nervus uses it as it is, and its own SSH keys are
replaced by nervus&#x27;s line alone: whoever logs in to it with a key, you too, can no longer. nervus never uses
root or one of the machine&#x27;s own system accounts.</p>
<p>To keep nervus&#x27;s own names, go back and leave the boxes as they were filled in.</p>
<form method="post" action="machines" class="enroll">
<input type="hidden" name="form_token" value="{form_token}">
<input type="hidden" name="action" value="{action}">
{carried}{typed}<button type="submit">Go on</button>
</form>
<p><a href="machines">Back to machines</a></p>""",
        name=name, accounts=" and ".join(n for n, _ in names), form_token=form_token, action=action,
        carried=carried, typed=typed,
    ), until, form_token, standing)


def _machine_action(action: str, form_token: str, label: str, name: str, extra: Markup = Markup("")) -> Markup:
    return render(
        """<form method="post" action="machines" class="inline">
<input type="hidden" name="form_token" value="{form_token}">
<input type="hidden" name="action" value="{action}">
<input type="hidden" name="name" value="{name}">
{extra}<button type="submit">{label}</button>
</form>""",
        form_token=form_token, action=action, name=name, label=label, extra=extra,
    )


def _accounts_cell(row: EnrolledHost, kept) -> str:
    """Its accounts, as nervus checked them (ADR-0031): the read-write one, and
    the read-only one with its groups, or why it has none."""
    if kept is None or kept.enrolled_at != row.enrolled_at:
        return "agent (added before read-only accounts)"
    parts = [kept.readwrite] if kept.readwrite else []
    if kept.readonly:
        parts.append(f"{kept.readonly}, read-only" + (f", in {', '.join(kept.groups)}" if kept.groups else ""))
    else:
        parts.append(f"no read-only account: {kept.why_none}")
    return "; ".join(parts)


def _machine_row(row: EnrolledHost, form_token: str, kept=None) -> Markup:
    move = _machine_action("move", form_token, "Change address", row.name, extra=render(
        '<input type="text" name="address" value="{address}" autocomplete="off" aria-label="new address">\n',
        address=row.address))
    remove = _machine_action("remove", form_token, "Remove", row.name, extra=Markup(
        '<input type="text" name="confirm" placeholder="type its name to remove" autocomplete="off">\n'))
    return render(
        """<tr>
<td><code>{name}</code></td>
<td>{address}</td>
<td>{level}<br><span class="muted">{accounts}</span></td>
<td><code>{machine_id}</code></td>
<td>{when}<br><span class="muted">by {by}</span></td>
<td class="actions">{move}{remove}</td>
</tr>
""",
        name=row.name, address=row.address, level=row.level, machine_id=row.machine_id[:12],
        accounts=_accounts_cell(row, kept),
        when=_second(row.enrolled_at), by=row.enrolled_by, move=move, remove=remove,
    )


def _code_state(code: EnrollmentCode, now: float) -> str:
    # What became of a code, once it did. A run by login (ADR-0026) can end before the route sees a report, with
    # the code cancelled and never used, and it is that outcome the owner needs to read.
    if code.outcome:
        return code.outcome
    if code.used_at is not None:
        return "used; nervus is checking the machine"
    if code.expires_at <= now:
        return "expired, unused"
    return f"waiting for the machine, until {_second(code.expires_at)}"


def page_machines(machines: list[EnrolledHost], codes: list[EnrollmentCode], by_hand: list[str], can_enroll: bool, now: float, until: float,
                  form_token: str, standing: Standing = NO_STANDING, notice: str = "",
                  can_login: bool = False, restored: str = "",
                  described: list[tuple[str, str, str | None]] | None = None,
                  accounts: dict[str, MachineAccount] | None = None) -> Markup:
    """Machines enrolled from here, each removable and its address changeable;
    the codes made lately and what became of each; and the form that adds a
    machine, or gives one already here a new level (ADR-0024 decisions 2 to 5):
    Connect, which logs in once with an admin account (ADR-0026), where
    `can_login`, and Advanced, the two lines to run on the machine. `by_hand`
    names hosts.yaml's machines, which are not changed here. `can_enroll` is
    false when MCP serves plain HTTP. `restored`, after a restore until the
    next backup, says what the backup cannot have (ADR-0027 question 6)."""
    rows = join(_machine_row(row, form_token, (accounts or {}).get(row.name)) for row in machines) if machines else Markup(
        '<tr><td colspan="6" class="muted">None yet.</td></tr>\n')
    code_rows = join(render("<tr><td><code>{name}</code></td><td>{level}</td><td>{address}</td><td>{made}</td>"
                            "<td>{state}</td></tr>\n", name=c.name, level=c.level,
                            address=c.address or "where its report comes from", made=_second(c.made_at),
                            state=_code_state(c, now)) for c in codes)
    if can_enroll:
        # Connect first: Enter in a field presses the first button of its form.
        connect = Markup('<button type="submit" name="action" value="connect">Connect</button>\n' if can_login else "")
        blank = ("the address blank to use the one the machine reaches nervus from; give a name or a reserved "
                 "address if that can change.")
        how = (render('<p class="muted">Connect shows the key the machine answers with, then asks once for an admin '
                      'login, root or an account that can use sudo, and does the rest, keeping no password. Advanced '
                      'gives two lines to run as root on the machine instead; they work once, within 15 minutes. '
                      'In Advanced, leave {blank}', blank=blank) if can_login else
               render('<p class="muted">The next page shows two lines to run as root on the machine; they work '
                      'once, within 15 minutes. Leave {blank}', blank=blank))
        add = render(
            """<form method="post" action="machines" class="enroll">
<input type="hidden" name="form_token" value="{form_token}">
<label>Name <input type="text" name="name" placeholder="nas" autocomplete="off"></label>
<label>A name or address nervus can reach <input type="text" name="address" placeholder="required for Connect"
 autocomplete="off"></label>
<fieldset><legend>Level</legend>
{levels}</fieldset>
{boxes}{connect}<button type="submit" name="action" value="add" class="secondary">Advanced: two lines to run on the machine yourself</button>
</form>
{how} To change a machine&#x27;s level, add it again under its name. To reinstall a
machine, add it again under its name too, without removing it: the tokens that name it keep reaching
it.</p>""",
            form_token=form_token, levels=_level_radios("read-only"), connect=connect, how=how,
            boxes=account_boxes(READWRITE, READONLY))
    else:
        add = render('<p class="notice">{why}</p>\n', why=PLAIN_HTTP)
    hand = render('<p class="muted">Also reached, described by hand in hosts.yaml and not changed here: {names}.</p>\n',
                  names=", ".join(by_hand)) if by_hand else Markup("")
    if described and can_enroll:
        # ADR-0031 question 4: a machine described by hand gains a read-only account by two lines.
        hand = join((hand, render(
            """<h3>A read-only account on a machine described by hand</h3>
<p class="muted">Two lines to run as root on it make one account, read-only, beside the one it is described with,
which stays as it is; nervus then checks it and records it. Once it has one, a token can be read-only there.</p>
<div class="table">
<table>
<thead><tr><th>Name</th><th>Described with</th><th>Read-only account</th><th></th></tr></thead>
<tbody>
{rows}</tbody>
</table>
</div>
""", rows=join(render(
                """<tr><td><code>{name}</code></td><td><code>{account}</code></td><td>{has}</td>
<td class="actions">{action}</td></tr>
""", name=d_name, account=d_account, has=render("<code>{r}</code>", r=d_readonly) if d_readonly else "none",
                action=(_machine_action("forget-readonly", form_token, "Forget it", d_name) if d_readonly else
                        _machine_action("readonly-account", form_token, "Two lines to add one", d_name, extra=render(
                            '<input type="text" name="readonly" value="{ro}" autocomplete="off" '
                            'aria-label="the read-only account\'s name">\n', ro=READONLY))))
                for d_name, d_account, d_readonly in described))))
    return _frame("nervus: machines", render(
        """<h1>Machines</h1>
{restored}{notice}<section>
<h2>Enrolled</h2>
<div class="table">
<table>
<thead><tr><th>Name</th><th>Address</th><th>Level</th><th>Machine id</th><th>Enrolled</th><th></th></tr></thead>
<tbody>
{rows}</tbody>
</table>
</div>
{hand}</section>
<section>
<h2>Add a machine</h2>
{add}</section>
<section>
<h2>Codes made lately</h2>
<div class="table">
<table>
<thead><tr><th>Name</th><th>Level</th><th>Address</th><th>Made</th><th>What became of it</th></tr></thead>
<tbody>
{codes}</tbody>
</table>
</div>
</section>""",
        notice=render('<p class="notice">{notice}</p>\n', notice=notice) if notice else Markup(""),
        restored=render('<p class="notice">{restored} Add any such machine again below.</p>\n',
                        restored=restored) if restored else Markup(""),
        rows=rows, hand=hand, add=add,
        codes=code_rows or Markup('<tr><td colspan="5" class="muted">None in the last day.</td></tr>\n'),
    ), until, form_token, standing, wide=True)


def page_enroll_confirm(name: str, level: str, address: str, reason: str, tokens: list[str], until: float,
                        form_token: str, standing: Standing = NO_STANDING, action: str = "add",
                        carried: Markup = Markup("")) -> Markup:
    """Before a code for a reused name or a raised level (ADR-0024 question
    8): which tokens reach what this changes, and the name typed to go on.
    The form carries what was asked for, so only the name is typed again, and
    goes on with `action`: `add`, the two lines, or `connect`, which shows the
    machine's key and asks for the login again (ADR-0026)."""
    return _frame("nervus: add a machine", render(
        """<h1>Add {name}?</h1>
<p>{reason}:</p>
<p><code>{tokens}</code></p>
<p>If that is what you want, type the name to make the commands. If not, revoke those tokens in
<a href="clients">Clients</a> first, or choose another name.</p>
<form method="post" action="machines" class="enroll">
<input type="hidden" name="form_token" value="{form_token}">
<input type="hidden" name="action" value="{action}">
<input type="hidden" name="name" value="{name}">
<input type="hidden" name="address" value="{address}">
<input type="hidden" name="level" value="{level}">
{carried}<label>Type {name} to go on <input type="text" name="confirm" autocomplete="off"></label>
<button type="submit">{button}</button>
</form>
<p><a href="machines">Back to machines</a></p>""",
        name=name, level=level, address=address, reason=reason, tokens=", ".join(tokens), form_token=form_token,
        action=action, button="Connect" if action == "connect" else "Make the commands", carried=carried,
    ), until, form_token, standing)


def page_enroll_lines(name: str, level: str, lines: str, nervus_host: str, until: float, form_token: str,
                      standing: Standing = NO_STANDING) -> Markup:
    """The two lines for one code, shown this once: nervus keeps only the
    code's hash (ADR-0024 decision 2)."""
    return _frame("nervus: add a machine", render(
        """<h1>Add {name}, {level}</h1>
<p>On {name}, in a root shell, run these two lines. The first fetches nervus&#x27;s script and checks it
came from this nervus, by its key. The second shows you the script; read it, quit with q, and it runs.</p>
<pre class="lines"><code>{lines}</code></pre>
<p>They work once, within 15 minutes, and are shown only now. Not in a root shell? Put <code>sudo</code>
before <code>sh</code>.</p>
<p>If {name} reaches nervus by an address other than <code>{host}</code>, put that one in the first line
instead.</p>
<p>The script ends by saying whether {name} was enrolled; <a href="machines">Machines</a> shows it too.</p>""",
        name=name, level=level, lines=lines, host=nervus_host,
    ), until, form_token, standing)


def page_enroll_login(name: str, address: str, level: str, host_key: str, fingerprint: str, confirm: str,
                      until: float, form_token: str, standing: Standing = NO_STANDING,
                      notice: str = "", confirmed_level: str = "",
                      key_file: str = "/etc/ssh/ssh_host_ed25519_key.pub", carried: Markup = Markup("")) -> Markup:
    """What Connect shows (ADR-0026 question 2): the key the machine's SSH
    server answered with and how to check it, then the admin login. The form
    sends the login only with `host_key`, which nervus pins the login to, and
    `confirm`, the name typed for ADR-0024's question 8, if it was, with
    `confirmed_level`, the level it was typed at: a higher one is asked about
    again (ADR-0026 question 7). `key_file` is where the machine keeps the key
    shown, which the owner checks there (question 9). The page
    never holds a password: a refused form comes back with the field empty."""
    return _frame("nervus: log in to a machine", render(
        """<h1>Log in to {name}</h1>
<p>nervus reached {address}. Its SSH server answered with this key:</p>
<pre class="lines"><code>{fingerprint}</code></pre>
<p>If you have logged in to {name} before, check it matches: on that computer,
<code>ssh-keygen -lF {address}</code>; on {name} itself,
<code>ssh-keygen -lf {key_file}</code>. nervus sends the login below only to the machine
holding this key. If it does not match, stop: something else may be answering at {address}.</p>
{notice}<form method="post" action="machines" class="enroll">
<input type="hidden" name="form_token" value="{form_token}">
<input type="hidden" name="action" value="login">
<input type="hidden" name="name" value="{name}">
<input type="hidden" name="address" value="{address}">
<input type="hidden" name="host_key" value="{host_key}">
<input type="hidden" name="confirm" value="{confirm}">
<input type="hidden" name="confirmed_level" value="{confirmed_level}">
{carried}<fieldset><legend>Level</legend>
{levels}</fieldset>
<label>Admin account (root, or one that can use sudo) <input type="text" name="login" autocomplete="off"
 autocapitalize="none" spellcheck="false"></label>
<label>Password <input type="password" name="password" autocomplete="off"></label>
<button type="submit">Enroll</button>
</form>
<p class="muted">nervus logs in once, becomes root, directly or with sudo and this password, and runs its
enrollment script: it makes nervus&#x27;s accounts with nervus&#x27;s key and sets up the level. nervus keeps no
password. Whoever controls this nervus right now could see it; if you would rather nervus never saw it, or you do
not trust this network, use the two lines.</p>
<form method="post" action="machines" class="enroll">
<input type="hidden" name="form_token" value="{form_token}">
<input type="hidden" name="action" value="add">
<input type="hidden" name="name" value="{name}">
<input type="hidden" name="address" value="{address}">
<input type="hidden" name="level" value="{level}">
<input type="hidden" name="confirm" value="{confirm}">
{carried}<button type="submit" class="secondary">Advanced: two lines to run on the machine yourself instead</button>
</form>
<p><a href="machines">Back to machines</a></p>""",
        name=name, address=address, fingerprint=fingerprint, host_key=host_key, confirm=confirm,
        confirmed_level=confirmed_level, key_file=key_file, form_token=form_token, level=level, levels=_level_radios(level),
        carried=carried,
        notice=render('<p class="notice">{notice}</p>\n', notice=notice) if notice else Markup(""),
    ), until, form_token, standing)


# How often the progress page of a run still going reloads itself.
ENROLLING_REFRESH_SECONDS = 2


def page_enrolling(run: LoginRun, until: float, form_token: str, standing: Standing = NO_STANDING) -> Markup:
    """An enrollment by login (ADR-0026 question 6): each step so far, and while
    the run goes on, a page that reloads itself, since no script may run here.
    Leaving it does not stop the run; Machines shows what became of its code."""
    if run.done:
        head = render("<p><strong>{what}</strong></p>\n", what=(f"{run.name} is enrolled, {run.level}" if run.enrolled
                                                              else f"{run.name} was not enrolled"))
        after = (Markup('<p>In <a href="clients">Clients</a>, give a token this machine to let a client use '
                        'it.</p>\n') if run.enrolled else render(
            """<form method="post" action="machines" class="enroll">
<input type="hidden" name="form_token" value="{form_token}">
<input type="hidden" name="action" value="add">
<input type="hidden" name="name" value="{name}">
<input type="hidden" name="address" value="{address}">
<input type="hidden" name="level" value="{level}">
<button type="submit" class="secondary">Advanced: two lines to run on the machine yourself</button>
</form>
<p><a href="machines">Try again</a>, from Machines, with the key and login asked for afresh.</p>
""", form_token=form_token, name=run.name, address=run.address, level=run.level))
        outcome = render('<p class="notice">{outcome}</p>\n', outcome=run.outcome)
    else:
        head = render("<p>nervus is working on {name}. This page reloads itself every {seconds} seconds; leaving it "
                      "does not stop the enrollment.</p>\n", name=run.name, seconds=ENROLLING_REFRESH_SECONDS)
        after = outcome = Markup("")
    steps = join(render("<li>{line}</li>\n", line=line) for line in run.lines)
    return _frame("nervus: enrolling a machine", render(
        """<h1>Enrolling {name}</h1>
{head}<p class="muted">{detail}</p>
<ol class="steps">
{steps}</ol>
{outcome}{after}<p><a href="machines">Back to machines</a></p>""",
        name=run.name, head=head, steps=steps, outcome=outcome, after=after,
        detail=(f"{run.login + ' at ' if run.login else ''}{run.address}, {run.level}"
                f"{', trusting only the key ' + run.fingerprint if run.fingerprint else ''}."),
    ), until, form_token, standing, refresh_seconds=None if run.done else ENROLLING_REFRESH_SECONDS)


def page_machine_removed(name: str, commands: str, tokens: list[str], until: float, form_token: str,
                         standing: Standing = NO_STANDING) -> Markup:
    """A machine forgotten, and what takes nervus off it (ADR-0024 decision
    5a). `tokens` are the ids of tokens whose allowlist still names it."""
    naming = render(
        """<p>These tokens still name {name}: {ids}. They would reach a machine enrolled as {name} later.
Revoke them in <a href="clients">Clients</a> if that is not what you want.</p>
""", name=name, ids=", ".join(tokens)) if tokens else Markup("")
    return _frame("nervus: machine removed", render(
        """<h1>{name} is forgotten</h1>
<p>nervus no longer reaches {name}. To take nervus&#x27;s accounts and key off it, run this on {name} as
root:</p>
<pre class="lines"><code>{commands}</code></pre>
{naming}<p><a href="machines">Back to machines</a></p>""",
        name=name, commands=commands, naming=naming,
    ), until, form_token, standing)


# --- first-run setup (ADR-0015) -------------------------------------------------------
#
# Every form posts to `setup` with the session's form token and an action:
# choosing the tier, declaring a range internal, withdrawing a declaration.

# ADR-0007 decisions 9 and 10, in plain words (ADR-0015 "Settled already"), and
# ADR-0027's two on backups. The README says the setup page says the same, and
# its test holds each list to the other (procedure 054, finding 5).
NON_GOALS = (
    "Programs running as you on a computer where a client runs: they can read the token that client uses.",
    "Whoever runs this nervus: anyone with root on its machine can read its key and tokens, rewrite its "
    "audit log, and see a password you type to add a machine.",
    "A client with full access to the machine underneath nervus: if nervus runs there as a VM or container, "
    "that client can stop nervus and rewrite its audit log. nervus refuses full access to its own machine, but "
    "cannot tell which machine hosts it, so the Machines page asks you.",
    "Someone at an unlocked computer where a client runs, or where you are signed in to nervus's web UI.",
    "What you ask for: an agent with full access to a machine can do anything you could there, destroying it "
    "included. nervus records it; it does not prevent it.",
    "A machine attacking its own data.",
    "Losing the recovery key, or giving it away. nervus's backups hold its keys, locked to a recovery key only "
    "you hold: whoever has that key and a backup can open every secret nervus has, and without it no backup can "
    "be opened, nervus's own included.",
    "A compromised nervus, by restoring it. A backup brings back the same keys, and so whatever an attacker took "
    "with them; recovering from that is new keys, and every machine and client enrolled again.",
    "Separate people. One nervus is one trust domain: everyone who can sign in here reads every client's audit "
    "log, issues and revokes every token, and adds every machine. People sharing a nervus share all of it.",
)

# The tiers by which computer hosts nervus, as ADR-0023 words them (ADR-0015
# decision F). Your everyday computer is the one where your clients run.
TIERS = (
    (1, "Tier 1, recommended: nervus runs on a different physical computer from your everyday one, the one "
        "where your clients run. Nothing on your everyday computer can get into nervus except through its front "
        "door. A VM or a container counts only when a separate computer hosts it."),
    (2, "Tier 2: nervus runs on your everyday computer, under an account of its own. Your programs cannot read "
        "its files without admin rights."),
    (3, "Tier 3: nervus runs on your everyday computer, and your own account can get into it: run as you, in "
        "Docker Desktop or rootless Podman, or in a VM your everyday computer hosts. Any program you run could "
        "read nervus's key and audit log, or act as nervus."),
)


def _setup_action(action: str, form_token: str, label: str, fields: Markup) -> Markup:
    return render(
        """<form method="post" action="setup" class="setup">
<input type="hidden" name="form_token" value="{form_token}">
<input type="hidden" name="action" value="{action}">
{fields}<button type="submit">{label}</button>
</form>""",
        form_token=form_token, action=action, fields=fields, label=label,
    )


def page_setup(tier: int | None, declared: list[Declared], public: list[str], until: float, form_token: str,
               standing: Standing = NO_STANDING, notice: str = "") -> Markup:
    """First-run setup, and where the tier and the declared ranges change later
    (ADR-0015 decisions A to C): what nervus does not defend against, the
    tier, and the addresses the internet might reach. `tier` is the one
    chosen, or None before setup; `public` the addresses nervus listens on
    that look public, as the check at start found them."""
    tiers = join(render('<label class="tier"><input type="radio" name="tier" value="{value}"{checked}> {words}'
                        '</label>\n', value=value, words=words,
                        checked=Markup(" checked" if value == tier else ""))
                 for value, words in TIERS)
    rows = join(render("<tr><td><code>{network}</code></td><td>{on}</td><td>{by}</td><td>{withdraw}</td></tr>\n",
                       network=d.network, on=d.on, by=d.by,
                       withdraw=_setup_action("withdraw", form_token, "Withdraw",
                                              render('<input type="hidden" name="network" value="{network}">\n',
                                                     network=d.network)))
                for d in declared) if declared else Markup('<tr><td colspan="4" class="muted">None.</td></tr>\n')
    found = (render("<p>At its last start it found these, which look public: {addresses}.</p>\n",
                    addresses=", ".join(public)) if public
             else Markup("<p>At its last start it found none that look public.</p>\n"))
    return _frame("nervus: setup", render(
        """<h1>{title}</h1>
{notice}<section>
<h2>What nervus does not defend against</h2>
<p>What nervus gives you is containment and accountability: each client reaches only the machines its token
names, at the level each machine allows; you can switch any client off at once; and every call is in the audit
log. It does not defend against:</p>
<ul>
{non_goals}</ul>
</section>
<section>
<h2>Where nervus runs: its tier</h2>
<p>nervus takes your word for it, and shows the tier at the top of every page. If you move nervus, change it
here.</p>
{tier_form}
</section>
<section>
<h2>Addresses the internet might reach</h2>
<p>At every start nervus checks the addresses it listens on. One outside the private ranges home routers hand
out is warned about at the top of every page: reaching nervus from the internet is not supported.</p>
{found}<p><strong>Never forward a port on your router to nervus.</strong> nervus cannot see a forwarded port, so
no warning here can tell you about one. To reach nervus from outside, use an overlay network such as Tailscale
or WireGuard.</p>
<p>If your network uses addresses that look public but the internet cannot reach them, declare their range
here. The warning then becomes a note naming your declaration, on every page; an address outside every declared
range is still warned about.</p>
<div class="table">
<table>
<thead><tr><th>Range declared internal</th><th>On</th><th>By</th><th></th></tr></thead>
<tbody>
{rows}</tbody>
</table>
</div>
{declare_form}
</section>""",
        title="Set up nervus" if tier is None else "Setup",
        notice=render('<p class="notice">{notice}</p>\n', notice=notice) if notice else Markup(""),
        non_goals=join(render("<li>{goal}</li>\n", goal=goal) for goal in NON_GOALS),
        tier_form=_setup_action("tier", form_token, "Choose this tier",
                                render('<fieldset><legend>Tier</legend>\n{tiers}</fieldset>\n', tiers=tiers)),
        found=found, rows=rows,
        declare_form=_setup_action("declare", form_token, "Declare internal", Markup(
            '<label>Range <input type="text" name="network" placeholder="192.0.2.0/24" autocomplete="off">'
            '</label>\n')),
    ), until, form_token, standing, wide=True)


# --- backups (ADR-0027) ---------------------------------------------------------------

# Where copies go, by the tier declared at setup (ADR-0027 question 3, ADR-0023).
_COPIES = {
    1: ("nervus runs on a computer of its own, so a copy on your everyday computer survives losing it. "
        "Each backup is locked to the recovery key, so a copy there gives nothing away."),
    2: ("nervus runs on your everyday computer, so a backup here does not survive losing that computer. "
        "Keep copies on another disk, or storage elsewhere; each is locked to the recovery key."),
    3: ("nervus runs on your everyday computer, so a backup here does not survive losing that computer. "
        "Keep copies on another disk, or storage elsewhere; each is locked to the recovery key."),
}


def page_backups(backups: list[BackupFile], last_check: str, has_key: bool, tier: int | None, until: float,
                 form_token: str, standing: Standing = NO_STANDING, notice: str = "", restored: str = "") -> Markup:
    """nervus's backups (ADR-0027 questions 3, 4 and 7a): each one, newest
    first, to download; a button that makes one now; when a check last passed,
    and the command that makes one, which needs the recovery key and so is
    never done here; and where copies go for the tier declared."""
    rows = join(render('<tr><td><code>{name}</code>{kept}</td><td>{made}</td><td>{size}</td>'
                       '<td><a href="backups?{query}">Download</a></td></tr>\n',
                       name=b.name, made=_when(b.made_at), size=f"{b.size / 1e6:.1f} MB",
                       kept=render('<br><span class="muted">made before the upgrade to {release}, and kept until '
                                   'the next upgrade</span>', release=b.kept_before) if b.kept_before else Markup(""),
                       query=urlencode({"download": b.name})) for b in backups) if backups else Markup(
        '<tr><td colspan="4" class="muted">None yet.</td></tr>\n')
    make = render("""<form method="post" action="backups">
<input type="hidden" name="form_token" value="{form_token}">
<button type="submit" name="action" value="make">Make a backup now</button>
</form>
""", form_token=form_token) if has_key else render(
        '<p class="notice">There is no recovery key, so no backup can be made. On nervus&#x27;s machine, as root: '
        '<code>nervus-ctl recovery-key</code></p>\n')
    check = (render("<p>The last check that passed: {last}.</p>\n", last=last_check) if last_check else
             render('<p class="notice">No backup has been checked yet.</p>\n'))
    return _frame("nervus: backups", render(
        """<h1>Backups</h1>
{restored}{notice}<section>
<p>nervus backs itself up once a day, keeping a backup a day for a week, one a week for a month and
one a month for a year, and the one made before the last upgrade until the next. Each is locked to
the recovery key, whose private half only you hold: nervus cannot open its own backups.</p>
{make}<div class="table">
<table>
<thead><tr><th>Backup</th><th>Made</th><th>Size</th><th></th></tr></thead>
<tbody>
{rows}</tbody>
</table>
</div>
</section>
<section>
<h2>Checking that the recovery key opens them</h2>
{check}<p class="muted">A backup nobody can open is the usual way backups fail. Check the newest once after
installing and after each upgrade, on nervus&#x27;s machine, as root, with the recovery key to hand:
<code>nervus-ctl backup --check &lt;file&gt;</code>. It changes nothing.</p>
</section>
<section>
<h2>Where to keep copies</h2>
<p>{copies}</p>
</section>""",
        restored=render('<p class="notice">{restored}</p>\n', restored=restored) if restored else Markup(""),
        notice=render('<p class="notice">{notice}</p>\n', notice=notice) if notice else Markup(""),
        make=make, rows=rows, check=check,
        copies=_COPIES.get(tier, "Choose nervus's tier at setup, and this says where copies go."),
    ), until, form_token, standing)


PAGES = (page_signed_out, page_signin, page_home, page_audit, page_audit_row, page_clients, page_token_issued,
         page_machines, page_enroll_confirm, page_names_confirm, page_enroll_login, page_enrolling, page_enroll_lines,
         page_machine_removed, page_setup, page_backups)


STYLESHEET = """\
:root {
  color-scheme: light dark;
  --fg: #1d1d1f; --bg: #ffffff; --muted: #6e6e73; --line: #d2d2d7;
  --alert-fg: #7a3e00; --alert-bg: #fff4e5;
}
@media (prefers-color-scheme: dark) {
  :root {
    --fg: #f5f5f7; --bg: #1c1c1e; --muted: #a1a1a6; --line: #3a3a3c;
    --alert-fg: #ffd8a8; --alert-bg: #3d2a12;
  }
}
body { margin: 0; font: 16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; color: var(--fg); background: var(--bg); }
main { max-width: 40rem; margin: 0 auto; padding: 1.5rem 1rem; }
main.wide { max-width: 80rem; }
header { display: flex; flex-wrap: wrap; align-items: center; gap: 0.5rem 1rem; padding: 0.75rem 1rem; border-bottom: 1px solid var(--line); }
header .name { font-weight: 600; }
header a { color: inherit; }
header .session { margin-left: auto; color: var(--muted); font-size: 0.9rem; }
header form { margin: 0; }
h1 { font-size: 1.5rem; margin: 0 0 1rem; }
pre { padding: 0.75rem 1rem; border: 1px solid var(--line); border-radius: 6px; overflow-x: auto; }
button { font: inherit; padding: 0.4rem 1rem; border: 1px solid var(--line); border-radius: 6px; background: transparent; color: inherit; cursor: pointer; }
.banner { padding: 0.75rem 1rem; color: var(--alert-fg); background: var(--alert-bg); font-weight: 600; }
.note { padding: 0.5rem 1rem; border-bottom: 1px solid var(--line); color: var(--muted); font-size: 0.9rem; }
header .tier { color: var(--muted); font-size: 0.9rem; }
header .release { color: var(--muted); font-size: 0.9rem; }
form.setup { display: flex; flex-wrap: wrap; align-items: end; gap: 0.5rem 1rem; margin: 0.5rem 0; }
form.setup fieldset { flex-direction: column; }
form.setup label { display: flex; flex-direction: column; font-size: 0.9rem; color: var(--muted); }
form.setup label.tier { display: block; color: var(--fg); font-size: 1rem; }
.notice { padding: 0.5rem 1rem; border-left: 3px solid var(--muted); }
.muted { color: var(--muted); font-size: 0.9rem; }
.filters { display: flex; flex-wrap: wrap; align-items: end; gap: 0.5rem 1rem; margin-bottom: 1rem; }
.filters label { display: flex; flex-direction: column; font-size: 0.9rem; color: var(--muted); }
input, select { font: inherit; padding: 0.3rem 0.5rem; border: 1px solid var(--line); border-radius: 6px; background: transparent; color: inherit; }
.table { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 0.9rem; }
th, td { text-align: left; vertical-align: top; padding: 0.35rem 0.5rem; border-bottom: 1px solid var(--line); }
td.when { white-space: nowrap; }
td.subject code { overflow-wrap: anywhere; }
tr.refused td.outcome { color: var(--alert-fg); }
.left-out { color: var(--muted); white-space: nowrap; }
.pages { display: flex; gap: 1rem; margin-top: 1rem; }
pre.value { white-space: pre-wrap; overflow-wrap: anywhere; margin: 0; }
dl { display: grid; grid-template-columns: minmax(6rem, max-content) 1fr; gap: 0.5rem 1rem; }
dt { font-weight: 600; }
dd { margin: 0; min-width: 0; }
h2 { font-size: 1.1rem; margin: 1.5rem 0 0.5rem; }
form.inline { display: inline-flex; gap: 0.4rem; margin: 0 0.4rem 0.4rem 0; }
form.issue { display: flex; flex-wrap: wrap; align-items: end; gap: 0.5rem 1rem; }
form.issue label { display: flex; flex-direction: column; font-size: 0.9rem; color: var(--muted); }
fieldset { border: 1px solid var(--line); border-radius: 6px; display: flex; flex-wrap: wrap; gap: 0.25rem 1rem; }
label.host { color: var(--fg); }
form.enroll { display: flex; flex-direction: column; align-items: start; gap: 0.75rem; }
form.enroll label { display: flex; flex-direction: column; font-size: 0.9rem; color: var(--muted); }
form.enroll fieldset { flex-direction: column; }
form.enroll label.level { display: block; color: var(--fg); font-size: 1rem; }
form.enroll input[type="text"], form.enroll input[type="password"] { width: min(24rem, 80vw); }
button.secondary { color: var(--muted); }
ol.steps { padding-left: 1.5rem; }
pre.lines { white-space: pre-wrap; overflow-wrap: anywhere; }
td.actions { white-space: nowrap; }
mark { padding: 0 0.15em; border-radius: 3px; color: var(--alert-fg); background: var(--alert-bg); font-weight: 600; }
"""
