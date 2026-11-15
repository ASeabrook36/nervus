"""The UI's web application: the operator signs in with a link from
`nervus-ctl signin`, and a browser session lasts 12 hours (ADR-0011 question
A, ADR-0012). Later pieces add the rest of its screens.

    GET  /            the home page, or how to sign in
    GET  /audit       the audit log, filtered and paged by the address; with
                      ?at=, one row's own page (ADR-0013)
    GET  /clients     every client, lockdown, and issuing a token (ADR-0014)
    POST /clients     switch a client off or on, lockdown on or off, issue a
                      token, or revoke one issued here
    GET  /machines    machines enrolled here, codes made lately, and adding
                      a machine (ADR-0024)
    POST /machines    connect to a machine and ask for its admin login, enroll
                      it with that login, make a code and show its two lines,
                      change a machine's address, or remove one and show what
                      takes nervus off it (ADR-0026)
    GET  /enrolling   the progress of an enrollment by login, by its code's id
    GET  /backups     nervus's backups, the last check that passed, and where
                      copies go (ADR-0027); with ?download=, one backup
    POST /backups     make a backup now
    GET  /setup       first-run setup: the non-goals, the tier, and the ranges
                      declared internal (ADR-0015)
    POST /setup       choose the tier, declare a range internal, or withdraw
                      a declaration
    GET  /signin      what a link opens: one button
    POST /signin      the button: spend the link, start a session
    POST /signout     end this browser's session
    GET  /nervus.css  the stylesheet

What protects it, beyond the link itself:
- The session cookie goes only to this host, only over HTTPS, never to a
  script, and never with a request another site starts (SameSite=Strict).
- A form posted from another origin is refused, and Sign out also needs a
  token only nervus's own page carries, derived from the session.
- Every response carries SECURITY_HEADERS: no script runs, nothing loads from
  elsewhere, no other site can frame a page, nothing is cached, and no
  address, such as the sign-in page's, is sent to another site as a referrer.
- Sign-ins, refused links and sign-outs are audited, actor "operator", with
  the browser's address and the link and session by their audit ids
  (decision 6). A sign-in whose record cannot be written is undone.
- Connect is audited the same way before nervus contacts the machine: the
  name, the address it reaches out to and the level. Without that record it
  contacts nothing (ADR-0001 section 10).
- A backup is downloaded only once its download is audited, and only by a
  name the backup folder holds; a path is never taken from the address. No
  page opens a backup: that needs the recovery key, which never comes here
  (ADR-0027 question 5).

Until a tier is chosen, every signed-in page but setup sends the browser to
setup, and every other form changes nothing (ADR-0015 decision A). MCP is
not held back meanwhile.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import anyio.to_thread
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import FileResponse, HTMLResponse, PlainTextResponse, RedirectResponse, Response
from starlette.routing import Route

from nervus.audit import AuditError, AuditLog
from nervus import restore
from nervus.audit_view import Cursor, Query, read_page, read_row
from nervus.backup import made_at as backup_made_at
from nervus.config import ConfigError
from nervus.auth import Tokens
from nervus.clients import clients_view
from nervus.database import Database, DatabaseUnusable, LinkRefused, Session, TokenRefused, audit_id
from nervus.enrolled_hosts import LEVELS, EnrolledHostStore, HostRefused, check
from nervus.enrollment_codes import LOGIN, EnrollmentCodes
from nervus.enrollments import EnrollmentRefused, host_keys
from nervus.exposure import Exposure
from nervus.first_run import FirstRun, SetupRefused
from nervus.host_enrollment import REMOVE_COMMANDS, enroll_lines, enroll_url
from nervus.host_login import LoginEnrollment, LoginRefused, LoginRun, fingerprint, key_file
from nervus.pages import (
    PLAIN_HTTP,
    STYLESHEET,
    Markup,
    Standing,
    page_audit,
    page_audit_row,
    page_backups,
    page_clients,
    page_enroll_confirm,
    page_enroll_lines,
    page_enroll_login,
    page_enrolling,
    page_home,
    page_machine_removed,
    page_machines,
    page_setup,
    page_signed_out,
    page_signin,
    page_token_issued,
)
from nervus.switches import Switches, SwitchesSwapped, SwitchesUnreadable, change_switches

# Never Strict-Transport-Security. With a certificate nobody vouches for, as
# nervus's own is, a browser that has seen it refuses to let the operator past
# its certificate warning at all.
SECURITY_HEADERS = {
    "content-security-policy": (
        "default-src 'none'; style-src 'self'; form-action 'self'; "
        "frame-ancestors 'none'; base-uri 'none'"
    ),
    "x-content-type-options": "nosniff",
    # same-origin, not no-referrer: under no-referrer a browser sends
    # "Origin: null" with a page's own form posts (the Fetch standard), which
    # the origin check must refuse. Found in a browser, 2026-10-07. A page here
    # links to no other site and may load nothing from one, so the sign-in
    # page's address, which holds its link, still goes nowhere but nervus.
    "referrer-policy": "same-origin",
    "cache-control": "no-store",
    "x-frame-options": "DENY",
    "cross-origin-opener-policy": "same-origin",
}

# Forms here hold a link or a token; anything larger is not a form of nervus's.
MAX_BODY_BYTES = 64 * 1024

REFUSED_LINK = "That link cannot be used. A link works once, within 5 minutes; make another with nervus-ctl signin."


def _position(text: str | None) -> int | None:
    """A position in the audit log, from the address: plain decimal digits, or
    nothing. The reader checks that it fits the file."""
    return int(text) if text is not None and re.fullmatch(r"[0-9]{1,20}", text) else None


@dataclass(frozen=True)
class Management:
    """What the clients page works with (ADR-0014): every token nervus
    accepts, the switch file nervus re-reads on every request, the
    inventory's host names, from which a token's hosts are chosen, and those
    of them marked `issue: never`, which are neither offered nor issued
    (ADR-0019 decision D)."""

    tokens: Tokens
    switches: Path
    hosts: list[str]
    never_issued: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Machines:
    """What the machines page works with (ADR-0024): the enrollment codes and
    the enrolled-host store; nervus's key as curl pins it, read at each page,
    None while MCP serves plain HTTP; MCP's port; the names hosts.yaml has,
    which are not enrolled here; the host a machine reaches nervus at, from
    --ui-url, or "" for the one the browser used; and, where nervus can log in
    to a machine with an admin login given once, what does it (ADR-0026)."""

    codes: EnrollmentCodes
    store: EnrolledHostStore
    pin: Callable[[], str | None]
    port: int
    by_hand: list[str]
    nervus_host: str = ""
    login: LoginEnrollment | None = None


@dataclass(frozen=True)
class Setup:
    """What first-run setup works with (ADR-0015): the store of the tier and
    the ranges declared internal, and what the address check found at start,
    matched again with the declared ranges at every page (decision D, as
    clarified on 2026-10-20)."""

    store: FirstRun
    exposure: Exposure


@dataclass(frozen=True)
class Backups:
    """What the backups page works with (ADR-0027): the folder nervus keeps
    them in, the recovery key's public half, and what makes one now, as
    `nervus-ctl backup` does, its record the UI's."""

    folder: Path
    recovery_key: Path
    make: Callable[[], object]


class _Refused(Exception):
    """An action that does not apply, and why, for the operator: 400."""


def form_token(session_value: str) -> str:
    """The token nervus's own pages put in their forms, for one session.

    A page on another site can make the operator's browser post a form here,
    with the session cookie if SameSite ever failed, but cannot read nervus's
    page to learn this. It is a hash of the session's value, so it needs no
    storage and tells nothing of the value.
    """
    return hashlib.sha256(b"nervus form token\0" + session_value.encode()).hexdigest()


class _SecurityHeaders:
    """Put SECURITY_HEADERS on every response, the router's own 404 and 405
    included, in place of any the application set."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = [(k, v) for k, v in message.get("headers", [])
                           if k.decode("latin-1").lower() not in SECURITY_HEADERS]
                headers += [(k.encode("latin-1"), v.encode("latin-1")) for k, v in SECURITY_HEADERS.items()]
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)


def build_ui(database: Database, audit: AuditLog, secure: bool, management: Management | None = None,
             machines: Machines | None = None, setup: Setup | None = None,
             backups: Backups | None = None) -> Starlette:
    """The UI as an ASGI application.

    `secure`: the UI is served over HTTPS, so its cookie is Secure and named
    __Host-, which binds it to this host and path /. Off loopback it always is
    (ADR-0011 question B); plain HTTP on loopback cannot carry a Secure cookie.
    `setup`: first-run setup (ADR-0015), which also gives every signed-in page
    its tier and its warning or notes. nervus always gives it; without it, as
    in tests of other pages, there is no setup page and no page is held back.
    `backups`: the backups page, and the warning on every page a day without
    a new backup gives (ADR-0027 question 4).
    """
    cookie = "__Host-nervus-session" if secure else "nervus-session"

    def page(markup: Markup, status: int = 200) -> HTMLResponse:
        return HTMLResponse(str(markup), status_code=status)

    def address(request: Request) -> str | None:
        return request.client.host if request.client else None

    def same_origin(request: Request) -> bool:
        """A browser names the origin of the page a form was posted from. It
        must be this one: the scheme and the host the browser asked for."""
        origin = request.headers.get("origin")
        if origin is None:
            return True  # not a browser's cross-site post; the link or the token still decides
        return origin == f"{request.url.scheme}://{request.headers.get('host', '')}"

    def refused() -> PlainTextResponse:
        return PlainTextResponse("Refused: this request did not come from nervus's own page.", status_code=403)

    async def session_of(request: Request) -> tuple[str, Session] | None:
        value = request.cookies.get(cookie)
        if not value:
            return None
        found = await anyio.to_thread.run_sync(database.session, value)
        return None if found is None else (value, found)

    def read_standing() -> Standing:
        backup_warning = restore.stale(restore.listing(backups.folder)) if backups is not None else ""
        if setup is None:
            return Standing(backup_warning=backup_warning)
        tier = setup.store.tier()
        exposure = setup.exposure.with_declared(setup.store.declared())
        return Standing(tier=None if tier is None else tier.tier, warning=exposure.warning(),
                        notes=tuple(exposure.notes()), backup_warning=backup_warning)

    def restored_note() -> str:
        """After a restore, until the next backup (ADR-0027 question 6)."""
        if backups is None:
            return ""
        try:
            return restore.restored_note(restore.events(database))
        except DatabaseUnusable:
            return ""

    async def standing_now() -> Standing:
        """The tier and the warning or notes, read for each page, so a change
        at setup shows at once."""
        return await anyio.to_thread.run_sync(read_standing)

    async def signed_in(request: Request) -> tuple[str, Session, Standing] | Response:
        """The browser's session and what stands on its pages; or how to sign
        in; or, until a tier is chosen, setup (ADR-0015 decision A)."""
        found = await session_of(request)
        if found is None:
            return page(page_signed_out())
        standing = await standing_now()
        if setup is not None and standing.tier is None:
            return RedirectResponse("setup", status_code=303)
        return (*found, standing)

    async def form_field(request: Request, name: str) -> str:
        value = (await request.form()).get(name)
        return value if isinstance(value, str) else ""

    async def home(request: Request) -> Response:
        found = await signed_in(request)
        if isinstance(found, Response):
            return found
        value, session, standing = found
        return page(page_home(until=session.expires_at, form_token=form_token(value), standing=standing))

    async def signin_page(request: Request) -> Response:
        link = request.query_params.get("link", "")
        return page(page_signin(link=link) if link else page_signed_out())

    async def signin(request: Request) -> Response:
        if not same_origin(request):
            return refused()
        link = await form_field(request, "link")
        where = address(request)
        try:
            value, session = await anyio.to_thread.run_sync(database.use_link, link)
        except LinkRefused as exc:
            audit.record_refusal("ui", {"actor": "operator", "action": "signin", "reason": exc.reason,
                                        "link": audit_id(link), "address": where})
            return page(page_signed_out(notice=REFUSED_LINK), 403)
        try:
            audit.record_operator("signin", {"link": audit_id(link), "session": audit_id(value),
                                             "expires": session.expires_at, "address": where}, tool="ui")
        except AuditError as exc:
            # ADR-0001 section 10: what cannot be audited does not happen.
            await anyio.to_thread.run_sync(database.sign_out, value)
            print(f"nervus: a sign-in was undone: {exc}", file=sys.stderr, flush=True)
            return page(page_signed_out(
                notice="nervus could not write its audit log, so you are not signed in."), 500)
        response = RedirectResponse("./", status_code=303)
        response.set_cookie(cookie, value, max_age=int(session.expires_at - session.signed_in_at),
                            path="/", secure=secure, httponly=True, samesite="strict")
        return response

    async def signout(request: Request) -> Response:
        if not same_origin(request):
            return refused()
        found = await session_of(request)
        token = await form_field(request, "form_token")
        if found is not None:
            value, _ = found
            if not hmac.compare_digest(token, form_token(value)):
                return refused()
            await anyio.to_thread.run_sync(database.sign_out, value)
            try:
                audit.record_operator("signout", {"session": audit_id(value), "address": address(request)},
                                      tool="ui")
            except AuditError as exc:
                # Signing out only takes access away; it stands without its record.
                print(f"nervus: a sign-out was not audited: {exc}", file=sys.stderr, flush=True)
        response = page(page_signed_out(notice="Signed out."))
        response.delete_cookie(cookie, path="/", secure=secure, httponly=True, samesite="strict")
        return response

    async def audit_log(request: Request) -> Response:
        """The audit log, read from the file nervus writes, in a worker thread
        so a long read does not stop nervus answering (ADR-0013). Reading it
        writes nothing: views are not audited (decision G)."""
        found = await signed_in(request)
        if isinstance(found, Response):
            return found
        value, session, standing = found
        framing = {"until": session.expires_at, "form_token": form_token(value), "standing": standing}
        params = request.query_params
        cant_read = "nervus could not read its audit log: {}"
        if "at" in params:
            at = _position(params["at"])
            try:
                row = None if at is None else await anyio.to_thread.run_sync(read_row, audit.path, at)
            except OSError as exc:
                return page(page_audit(rows=[], query=Query(), older=None, paged=False,
                                       notice=cant_read.format(exc), **framing), 500)
            return page(page_audit_row(row=row, **framing), 200 if row is not None else 404)
        query = Query(client=params.get("client", ""), host=params.get("host", ""), tool=params.get("tool", ""),
                      kind=params.get("kind", ""), text=params.get("q", ""))
        before, upto = _position(params.get("before")), _position(params.get("upto"))
        cursor = Cursor(before, upto) if before is not None and upto is not None else None
        try:
            found_page = await anyio.to_thread.run_sync(read_page, audit.path, query, cursor)
        except OSError as exc:
            return page(page_audit(rows=[], query=query, older=None, paged=cursor is not None,
                                   notice=cant_read.format(exc), **framing), 500)
        return page(page_audit(rows=found_page.rows, query=query, older=found_page.older,
                               paged=cursor is not None, **framing))

    # --- client management (ADR-0014) -------------------------------------------------

    async def clients_page(request: Request, value: str, session: Session, notice: str = "",
                           status: int = 200) -> Response:
        assert management is not None
        view = await anyio.to_thread.run_sync(lambda: clients_view(
            management.tokens, database.issued_tokens(), management.switches, audit.path))
        offered = [h for h in await issuable() if h not in management.never_issued]
        return page(page_clients(view=view, hosts=offered, until=session.expires_at,
                                 form_token=form_token(value), standing=await standing_now(), notice=notice), status)

    async def clients(request: Request) -> Response:
        found = await signed_in(request)
        if isinstance(found, Response):
            return found
        if management is None:
            return PlainTextResponse("Client management is not set up in this nervus.", status_code=404)
        return await clients_page(request, *found[:2])

    async def issuable() -> list[str]:
        """The machines a token may name: hosts.yaml's, then those enrolled
        here, read now (ADR-0024 decision 3)."""
        enrolled = [] if machines is None else [m.name for m in await anyio.to_thread.run_sync(machines.store.all)]
        return list(management.hosts) + [m for m in enrolled if m not in management.hosts]

    async def switch(change: Callable[[Switches], Switches]) -> Switches:
        return await anyio.to_thread.run_sync(change_switches, management.switches, change)

    async def recorded(action: str, fields: dict, undo: Callable[[], object] | None = None) -> str | None:
        """Write an action's audit record. If it cannot be written, undo the
        action unless it took access away (`undo` None), which stands. Returns
        the notice to show, or None if the record was written."""
        try:
            audit.record_operator(action, fields, tool="ui")
            return None
        except AuditError as exc:
            if undo is None:
                print(f"nervus: a {action} in the UI stands but was not audited: {exc}", file=sys.stderr, flush=True)
                return None
            await anyio.to_thread.run_sync(undo)
            print(f"nervus: a {action} in the UI was undone, not audited: {exc}", file=sys.stderr, flush=True)
            return "nervus could not write its audit log, so nothing changed."

    async def manage(request: Request) -> Response:
        if not same_origin(request):
            return refused()
        found = await signed_in(request)
        if isinstance(found, RedirectResponse):
            return found  # setup first: nothing here changes (ADR-0015 decision A)
        if isinstance(found, Response) or management is None:
            return refused()
        value, session, standing = found
        form = await request.form()
        if not hmac.compare_digest(str(form.get("form_token", "")), form_token(value)):
            return refused()
        action, token_id = str(form.get("action", "")), str(form.get("id", ""))
        where = {"address": address(request)}
        try:
            if action in ("off", "on"):
                known = management.tokens.file_ids() | {
                    i.token.id for i in await anyio.to_thread.run_sync(database.issued_tokens)}
                if token_id not in known:
                    raise _Refused(f"There is no token {token_id}.")
                if action == "off":
                    await switch(lambda s: Switches(s.lockdown, s.disabled | {token_id}))
                    await recorded("lock", {"target": token_id, "kill_work": False, **where})
                else:
                    def lift(s: Switches) -> Switches:
                        if token_id not in s.disabled:
                            raise _Refused(f"{token_id} is not switched off.")
                        return Switches(s.lockdown, s.disabled - {token_id})
                    await switch(lift)
                    failed = await recorded("unlock", {"target": token_id, **where}, undo=lambda: change_switches(
                        management.switches, lambda s: Switches(s.lockdown, s.disabled | {token_id})))
                    if failed:
                        return await clients_page(request, value, session, failed, 500)
            elif action == "lockdown-on":
                await switch(lambda s: Switches(True, s.disabled))
                await recorded("lock", {"target": "all", "kill_work": False, **where})
            elif action == "lockdown-off":
                await switch(lambda s: Switches(False, s.disabled))
                failed = await recorded("unlock", {"target": "all", **where}, undo=lambda: change_switches(
                    management.switches, lambda s: Switches(True, s.disabled)))
                if failed:
                    return await clients_page(request, value, session, failed, 500)
            elif action == "issue":
                hosts = [str(h) for h in form.getlist("hosts")]
                known = await issuable()
                unknown = [h for h in hosts if h not in known]
                if unknown:
                    raise _Refused(f"Not in the inventory: {', '.join(unknown)}.")
                client, project = str(form.get("client", "")), str(form.get("project", ""))
                try:
                    issued = await anyio.to_thread.run_sync(lambda: database.issue_token(
                        token_id, client, project, hosts, taken=management.tokens.file_ids(),
                        never_issued=management.never_issued))
                except TokenRefused as exc:
                    raise _Refused(f"Not issued: {exc}.") from exc
                failed = await recorded("issue_token", {"target": token_id, "client": client.strip(),
                                                        "project": project.strip(), "hosts": sorted(set(hosts)),
                                                        **where},
                                        undo=lambda: database.revoke_token(token_id))
                if failed:
                    return await clients_page(request, value, session, failed, 500)
                return page(page_token_issued(token_id=token_id, value=issued, until=session.expires_at,
                                              form_token=form_token(value), standing=standing))
            elif action == "revoke":
                ours = {i.token.id for i in await anyio.to_thread.run_sync(database.issued_tokens)}
                if token_id not in ours:
                    raise _Refused(f"{token_id} was not issued here, so it cannot be revoked here.")
                if str(form.get("confirm", "")) != token_id:
                    raise _Refused(f"To revoke {token_id}, type its id exactly. Nothing was revoked.")
                await anyio.to_thread.run_sync(database.revoke_token, token_id)
                await recorded("revoke_token", {"target": token_id, **where})
            else:
                raise _Refused("That is not an action nervus knows.")
        except _Refused as exc:
            return await clients_page(request, value, session, str(exc), 400)
        except SwitchesSwapped as exc:
            return await clients_page(request, value, session, f"Nothing changed: {exc}.", 409)
        except SwitchesUnreadable as exc:
            return await clients_page(request, value, session,
                                      f"Nothing changed: the switch file is unreadable ({exc}).", 409)
        return RedirectResponse("clients", status_code=303)

    # --- machines (ADR-0024) ----------------------------------------------------------

    async def machines_page(value: str, session: Session, notice: str = "", status: int = 200) -> Response:
        assert machines is not None
        rows = await anyio.to_thread.run_sync(machines.store.all)
        codes = await anyio.to_thread.run_sync(machines.codes.recent)
        return page(page_machines(machines=rows, codes=codes, by_hand=list(machines.by_hand),
                                  can_enroll=machines.pin() is not None, now=time.time(), until=session.expires_at,
                                  form_token=form_token(value), standing=await standing_now(), notice=notice,
                                  can_login=machines.login is not None,
                                  restored=await anyio.to_thread.run_sync(restored_note)),
                    status)

    async def machines_view(request: Request) -> Response:
        found = await signed_in(request)
        if isinstance(found, Response):
            return found
        if machines is None:
            return PlainTextResponse("Enrolling machines is not set up in this nervus.", status_code=404)
        return await machines_page(*found[:2])

    async def naming(name: str) -> list[str]:
        """The ids of the tokens whose allowlist names machine `name`."""
        issued = [i.token for i in await anyio.to_thread.run_sync(database.issued_tokens)]
        in_file = management.tokens.in_file() if management is not None else []
        return sorted({t.id for t in [*in_file, *issued] if name in t.hosts})

    async def ask_first(form, *, name: str, level: str, at: str, action: str, value: str, session: Session,
                        standing: Standing, confirmed_level: str | None = None) -> tuple[list[str], Response | None]:
        """ADR-0024 question 8, asked the same way before Connect, the login and
        the two lines: tokens follow the name, so ask before they would reach a
        machine they did not, or a higher level. Returns the tokens shown, and
        the page asking if the name was not typed; `action` is what that page
        goes on with. `confirmed_level`, for a name typed on an earlier page, is
        the level it was typed at: above it, the name typed answers nothing
        (ADR-0026 question 7)."""
        row = await anyio.to_thread.run_sync(machines.store.get, name)
        shown, reason = await naming(name), None
        if shown and row is None:
            reason = (f"No machine has the name {name} now, but these tokens still name it, so they will "
                      f"reach the machine you are adding")
        elif shown and LEVELS.index(level) > LEVELS.index(row.level):
            reason = (f"{name} goes from {row.level} to {level}, so these tokens, which reach it, will "
                      f"reach it at {level}")
        if reason is None:
            return [], None
        typed = str(form.get("confirm", "")) == name
        if typed and confirmed_level is not None:
            typed = confirmed_level in LEVELS and LEVELS.index(level) <= LEVELS.index(confirmed_level)
        if not typed:
            return shown, page(page_enroll_confirm(name=name, level=level, address=at, reason=reason, tokens=shown,
                                                   until=session.expires_at, form_token=form_token(value),
                                                   standing=standing, action=action))
        return shown, None

    def one_host_key(text: str) -> str:
        """The host key as the store keeps it; exactly one, as the login is
        pinned to exactly the key the owner was shown."""
        try:
            keys = host_keys([text])
        except EnrollmentRefused as exc:
            raise _Refused(f"Not connected: {exc.message}") from exc
        if len(keys) != 1 or len(text.strip().splitlines()) != 1:
            raise _Refused("Not connected: give exactly one host key, the one the machine answered with.")
        return keys[0]

    async def manage_machines(request: Request) -> Response:
        if not same_origin(request):
            return refused()
        found = await signed_in(request)
        if isinstance(found, RedirectResponse):
            return found  # setup first: nothing here changes (ADR-0015 decision A)
        if isinstance(found, Response) or machines is None:
            return refused()
        value, session, standing = found
        form = await request.form()
        if not hmac.compare_digest(str(form.get("form_token", "")), form_token(value)):
            return refused()
        action, name = str(form.get("action", "")), str(form.get("name", "")).strip()
        where = {"address": address(request)}
        try:
            if action == "add":
                pin = machines.pin()
                if pin is None:
                    raise _Refused(PLAIN_HTTP)
                at, level = str(form.get("address", "")).strip(), str(form.get("level", ""))
                try:
                    check(name, at, level, machines.by_hand)
                except HostRefused as exc:
                    raise _Refused(f"No commands made: {exc.message}") from exc
                shown, asked = await ask_first(form, name=name, level=level, at=at, action="add", value=value,
                                               session=session, standing=standing)
                if asked is not None:
                    return asked
                try:
                    code_value, code = await anyio.to_thread.run_sync(lambda: machines.codes.make(
                        name=name, address=at, level=level, made_by="operator", reserved=machines.by_hand))
                except HostRefused as exc:
                    raise _Refused(f"No commands made: {exc.message}") from exc
                failed = await recorded("enrollment_code", {
                    "target": code.name, "code_id": code.id, "level": code.level,
                    "tokens_shown": shown,
                    "machine_address": code.address or "where its report comes from", **where},
                    undo=lambda: machines.codes.cancel(code.id))
                if failed:
                    return await machines_page(value, session, failed, 500)
                host = machines.nervus_host or request.url.hostname or ""
                lines = enroll_lines(enroll_url(host, machines.port, code_value), pin)
                return page(page_enroll_lines(name=code.name, level=code.level, lines=lines, nervus_host=host,
                                              until=session.expires_at, form_token=form_token(value),
                                              standing=standing))
            if action in ("connect", "login"):
                return await connect_or_login(request, form, action, name=name, value=value, session=session,
                                              standing=standing, where=where)
            row = await anyio.to_thread.run_sync(machines.store.get, name)
            if row is None:
                raise _Refused(f"There is no machine {name} enrolled here.")
            if action == "move":
                to = str(form.get("address", "")).strip()
                try:
                    await anyio.to_thread.run_sync(machines.store.move, name, to)
                except HostRefused as exc:
                    raise _Refused(f"Not changed: {exc.message}") from exc
                moved = await anyio.to_thread.run_sync(machines.store.get, name)
                failed = await recorded("move_machine", {"target": name, "from": row.address,
                                                         "to": moved.address, **where},
                                        undo=lambda: machines.store.move(name, row.address))
                if failed:
                    return await machines_page(value, session, failed, 500)
            elif action == "remove":
                if str(form.get("confirm", "")) != name:
                    raise _Refused(f"To remove {name}, type its name exactly. Nothing was removed.")
                await anyio.to_thread.run_sync(machines.store.remove, name)
                # Removing takes access away, so it stands without its record.
                await recorded("remove_machine", {"target": name, "machine_address": row.address,
                                                  "level": row.level, "machine_id": row.machine_id, **where})
                return page(page_machine_removed(name=name, commands=REMOVE_COMMANDS, tokens=await naming(name),
                                                 until=session.expires_at, form_token=form_token(value),
                                                 standing=standing))
            else:
                raise _Refused("That is not an action nervus knows.")
        except _Refused as exc:
            return await machines_page(value, session, str(exc), 400)
        return RedirectResponse("machines", status_code=303)

    async def connect_or_login(request: Request, form, action: str, *, name: str, value: str, session: Session,
                               standing: Standing, where: dict) -> Response:
        """ADR-0026: Connect records that nervus is about to contact the address,
        then fetches the machine's host key and shows it, with the login to give;
        the login makes a code with the account and that key, records it, and
        starts the run in the background. The password goes to `start` and
        nowhere else: not a record, not a page, not a refusal's page."""
        assert machines is not None
        login = machines.login
        if login is None:
            raise _Refused("That is not an action nervus knows.")
        pin = machines.pin()
        if pin is None:
            raise _Refused(PLAIN_HTTP)
        if login.locked():
            raise _Refused("nervus is locked down, so it enrolls nothing")
        at, level = str(form.get("address", "")).strip(), str(form.get("level", ""))
        try:
            check(name, at, level, machines.by_hand)
        except HostRefused as exc:
            raise _Refused(f"Not connected: {exc.message}") from exc
        if not at:
            raise _Refused("Give the address nervus should connect to.")
        # A raised level, or a reused name, is asked about before anything is sent; the confirmation
        # goes on through Connect, so the key is shown afresh and the password typed again.
        # On the login, the name typed counts only up to the level it was typed at (ADR-0026 question 7).
        shown, asked = await ask_first(form, name=name, level=level, at=at, action="connect", value=value,
                                       session=session, standing=standing,
                                       confirmed_level=str(form.get("confirmed_level", "")) if action == "login" else None)
        if asked is not None:
            return asked
        framing = {"until": session.expires_at, "form_token": form_token(value), "standing": standing}
        confirm = str(form.get("confirm", ""))
        confirmed_level = (level if action == "connect" else str(form.get("confirmed_level", ""))) if confirm == name else ""
        if action == "connect":
            # ADR-0001 section 10: nervus is about to reach out to an address the operator typed, so its
            # record comes first, and without the record nothing is contacted. The fields are named one by
            # one, never taken from the form, which on the login holds a password.
            try:
                audit.record_operator("connect", {"target": name, "machine_address": at, "level": level, **where},
                                      tool="ui")
            except AuditError as exc:
                print(f"nervus: a connect in the UI was refused, not audited: {exc}", file=sys.stderr, flush=True)
                return await machines_page(
                    value, session, "nervus could not write its audit log, so it connected to nothing.", 500)
            try:
                key = await login.host_key(at)
            except LoginRefused as exc:
                raise _Refused(f"Not connected: {exc.message}") from exc
            return page(page_enroll_login(name=name, address=at, level=level, host_key=key,
                                          fingerprint=fingerprint(key), key_file=key_file(key), confirm=confirm,
                                          confirmed_level=confirmed_level, **framing))
        key = one_host_key(str(form.get("host_key", "")))
        account, password = str(form.get("login", "")).strip(), str(form.get("password", ""))
        again = {"name": name, "address": at, "level": level, "host_key": key, "fingerprint": fingerprint(key),
                 "key_file": key_file(key),
                 "confirm": confirm, "confirmed_level": confirmed_level, **framing}
        if not LOGIN.fullmatch(account):
            return page(page_enroll_login(notice="Give the admin account to log in as: root, or an account that "
                                                 "can use sudo. Nothing was sent.", **again), 400)
        if not password:
            return page(page_enroll_login(notice="Give that account's password. Nothing was sent.", **again), 400)
        try:
            code_value, code = await anyio.to_thread.run_sync(lambda: machines.codes.make(
                name=name, address=at, level=level, made_by="operator", reserved=machines.by_hand, login=account,
                host_key=key))
        except HostRefused as exc:
            raise _Refused(f"No commands made: {exc.message}") from exc
        failed = await recorded("enrollment_code", {
            "target": code.name, "code_id": code.id, "level": code.level, "tokens_shown": shown,
            "machine_address": code.address, "method": "login", "login": account, "host_key": fingerprint(key),
            **where}, undo=lambda: machines.codes.cancel(code.id))
        if failed:
            return await machines_page(value, session, failed, 500)
        host = machines.nervus_host or request.url.hostname or ""
        login.start(code, url=enroll_url(host, machines.port, code_value), pin=pin, host_key=key, login=account,
                    password=password, shown=enroll_url(host, machines.port, "<code>"))
        return RedirectResponse(f"enrolling?id={code.id}", status_code=303)

    async def enrolling_view(request: Request) -> Response:
        """The progress of an enrollment by login: the run nervus has, or, for one
        it no longer runs, what its code's record says (ADR-0026 question 6)."""
        found = await signed_in(request)
        if isinstance(found, Response):
            return found
        if machines is None or machines.login is None:
            return PlainTextResponse("Enrolling by login is not set up in this nervus.", status_code=404)
        value, session, standing = found
        code_id = request.query_params.get("id", "")
        if not re.fullmatch(r"[0-9a-f]{16}", code_id):
            return PlainTextResponse("There is no such enrollment.", status_code=404)
        run = machines.login.get(code_id)
        if run is None:
            code = await anyio.to_thread.run_sync(machines.codes.get, code_id)
            if code is None:
                return PlainTextResponse("There is no such enrollment.", status_code=404)
            run = await anyio.to_thread.run_sync(lambda: from_record(code))
        return page(page_enrolling(run=run, until=session.expires_at, form_token=form_token(value),
                                   standing=standing))

    def from_record(code) -> LoginRun:
        """A finished run, as far as the code's record tells it, for one nervus
        no longer runs: it was restarted, or the run is long forgotten."""
        assert machines is not None
        made = machines.codes.login_of(code.id)
        outcome = code.outcome or ("nervus is no longer running this enrollment, perhaps because it was restarted; "
                                   "Machines shows what became of it")
        return LoginRun(code_id=code.id, name=code.name, address=code.address, level=code.level,
                        login=made.login if made else "", fingerprint=fingerprint(made.host_key) if made else "",
                        started_at=code.made_at, finished_at=code.used_at or code.made_at,
                        enrolled=outcome.startswith("enrolled"), outcome=outcome)

    # --- first-run setup (ADR-0015) ---------------------------------------------------

    async def setup_page(value: str, session: Session, notice: str = "", status: int = 200) -> Response:
        assert setup is not None
        tier = await anyio.to_thread.run_sync(setup.store.tier)
        declared = await anyio.to_thread.run_sync(setup.store.declared)
        return page(page_setup(tier=None if tier is None else tier.tier, declared=declared,
                               public=[str(a) for a in setup.exposure.addresses if a.is_global],
                               until=session.expires_at, form_token=form_token(value),
                               standing=await standing_now(), notice=notice), status)

    async def setup_view(request: Request) -> Response:
        if setup is None:
            return PlainTextResponse("Setup is not part of this nervus.", status_code=404)
        found = await session_of(request)
        if found is None:
            return page(page_signed_out())
        return await setup_page(*found)

    async def manage_setup(request: Request) -> Response:
        """Choose the tier, declare a range internal, or withdraw one, each
        audited (ADR-0015 decisions B and C). A change that would quiet the
        warning, or change the tier, is undone if its record cannot be
        written; a withdrawal only makes the warning louder, so it stands."""
        if not same_origin(request):
            return refused()
        found = await session_of(request)
        if found is None or setup is None:
            return refused()
        value, session = found
        form = await request.form()
        if not hmac.compare_digest(str(form.get("form_token", "")), form_token(value)):
            return refused()
        action, where = str(form.get("action", "")), {"address": address(request)}
        try:
            if action == "tier":
                given = str(form.get("tier", ""))
                tier = int(given) if re.fullmatch(r"[0-9]", given) else given
                previous = await anyio.to_thread.run_sync(lambda: setup.store.choose_tier(tier, by="operator"))
                failed = await recorded("choose_tier", {"tier": tier,
                                                        "from": None if previous is None else previous.tier, **where},
                                        undo=lambda: setup.store.restore_tier(previous))
                if failed:
                    return await setup_page(value, session, failed, 500)
                return RedirectResponse("./" if previous is None else "setup", status_code=303)
            network = str(form.get("network", ""))
            if action == "declare":
                kept = await anyio.to_thread.run_sync(lambda: setup.store.declare(network, by="operator"))
                failed = await recorded("declare_internal", {"target": kept, **where},
                                        undo=lambda: setup.store.withdraw(kept))
                if failed:
                    return await setup_page(value, session, failed, 500)
            elif action == "withdraw":
                if not await anyio.to_thread.run_sync(setup.store.withdraw, network):
                    raise _Refused(f"{network} is not declared internal.")
                await recorded("withdraw_internal",
                               {"target": str(ipaddress.ip_network(network.strip(), strict=False)), **where})
            else:
                raise _Refused("That is not an action nervus knows.")
        except SetupRefused as exc:
            return await setup_page(value, session, str(exc), 400)
        except _Refused as exc:
            return await setup_page(value, session, str(exc), 400)
        return RedirectResponse("setup", status_code=303)

    async def backups_page(value: str, session: Session, standing: Standing, notice: str = "",
                           status: int = 200) -> Response:
        assert backups is not None
        found = await anyio.to_thread.run_sync(restore.listing, backups.folder)
        try:
            checked = [e for e in await anyio.to_thread.run_sync(restore.events, database) if e[0] == "checked"]
        except DatabaseUnusable:
            checked = []
        last = (f"{time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(checked[-1][3]))}, of {checked[-1][1]}"
                if checked else "")
        return page(page_backups(backups=found, last_check=last, has_key=backups.recovery_key.is_file(),
                                 tier=standing.tier, until=session.expires_at, form_token=form_token(value),
                                 standing=standing, notice=notice,
                                 restored=await anyio.to_thread.run_sync(restored_note)), status)

    async def backups_view(request: Request) -> Response:
        found = await signed_in(request)
        if isinstance(found, Response):
            return found
        if backups is None:
            return PlainTextResponse("Backups are not set up in this nervus.", status_code=404)
        value, session, standing = found
        name = request.query_params.get("download")
        if name is None:
            return await backups_page(value, session, standing)
        # Only a name the folder holds: never a path from the address.
        path = backups.folder / name
        if backup_made_at(name) is None or not path.is_file():
            return PlainTextResponse("No such backup.", status_code=404)
        try:
            audit.record_operator("backup_download", {"file": name, "address": address(request)}, tool="ui")
        except AuditError as exc:
            print(f"nervus: a backup download was refused: {exc}", file=sys.stderr, flush=True)
            return await backups_page(value, session, standing,
                                      "nervus could not write its audit log, so nothing was downloaded.", 500)
        try:
            await anyio.to_thread.run_sync(lambda: _downloaded(database, name))
        except DatabaseUnusable as exc:
            print(f"nervus: a backup download was not noted: {exc}", file=sys.stderr, flush=True)
        return FileResponse(path, media_type="application/octet-stream", filename=name)

    async def manage_backups(request: Request) -> Response:
        if not same_origin(request):
            return refused()
        found = await signed_in(request)
        if isinstance(found, RedirectResponse):
            return found  # setup first: nothing here changes (ADR-0015 decision A)
        if isinstance(found, Response) or backups is None:
            return refused()
        value, session, standing = found
        form = await request.form()
        if not hmac.compare_digest(str(form.get("form_token", "")), form_token(value)):
            return refused()
        if str(form.get("action", "")) != "make":
            return await backups_page(value, session, standing, "That is not an action nervus knows.", 400)
        try:
            await anyio.to_thread.run_sync(backups.make)
        except ConfigError as exc:
            return await backups_page(value, session, await standing_now(), f"No backup was made: {exc}", 500)
        return RedirectResponse("backups", status_code=303)

    async def stylesheet(request: Request) -> Response:
        return Response(STYLESHEET, media_type="text/css; charset=utf-8")

    return Starlette(
        routes=[
            Route("/", home, methods=["GET"]),
            Route("/signin", signin_page, methods=["GET"]),
            Route("/signin", signin, methods=["POST"]),
            Route("/signout", signout, methods=["POST"]),
            Route("/audit", audit_log, methods=["GET"]),
            Route("/clients", clients, methods=["GET"]),
            Route("/clients", manage, methods=["POST"]),
            Route("/machines", machines_view, methods=["GET"]),
            Route("/machines", manage_machines, methods=["POST"]),
            Route("/enrolling", enrolling_view, methods=["GET"]),
            Route("/backups", backups_view, methods=["GET"]),
            Route("/backups", manage_backups, methods=["POST"]),
            Route("/setup", setup_view, methods=["GET"]),
            Route("/setup", manage_setup, methods=["POST"]),
            Route("/nervus.css", stylesheet, methods=["GET"]),
        ],
        middleware=[Middleware(_SecurityHeaders)],
        max_body_size=MAX_BODY_BYTES,
    )


def _downloaded(database: Database, name: str) -> None:
    """When a backup was last downloaded, for `status` and this page."""
    with database.transaction() as db:
        db.execute("INSERT INTO backup_event (kind, file, made_at, at) VALUES ('downloaded', ?, ?, ?)",
                   (name, backup_made_at(name).timestamp(), time.time()))
