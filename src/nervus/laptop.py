"""A laptop set up by one line, with no clone (ADR-0032 questions 4, 5, 6 and 11).

The Clients page, issuing a token, shows a line to run on the computer its client runs on, as the
person, not as root: on macOS and Linux

    curl -fsSk --pinnedpubkey 'sha256//<nervus's key>' 'https://<nervus>:8000/laptop/<code>' | sh

and in Windows PowerShell

    iex (curl.exe -fsSk --pinnedpubkey 'sha256//<nervus's key>' 'https://<nervus>:8000/laptop/<code>/windows' | Out-String)

The script it fetches, written here for one code, does tools/nervus-trust's job with the root it
carries, puts the helper a client runs for its headers, fetches the token with the same code and
keeps it in a place of nervus's own, and prints the commands that tell the client to use nervus. It
runs none of them (question 6).

What the scripts hold to:
- **Nothing runs until all of it has arrived** (consequence 4): below its opening comment, each
  script is one group, its values, its body's function and the call, closed only on its last line,
  so a shell given part of it finds the group unfinished and runs none of it, a cut word above the
  body included (procedure 069, step 4's review). The PowerShell line also hands the whole text
  to the parser before any of it runs.
- **They carry nothing secret.** nervus's root and address are public; the code is in the URL the
  person ran. The token comes only by presenting the code (POST), once (nervus.token_codes).
- **The token is never on a screen, in a clipboard, or in a command's arguments** (verification
  6): the shell holds it in a variable and gives it to the keychain on its standard input; on Linux
  it goes into a file only the person can read; on Windows into one encrypted with the person's own
  Windows key (DPAPI). The helper reads it there when the client connects.
- **The helper alone knows the computer** (question 5): the keychain on macOS, a file on Linux,
  DPAPI on Windows. Each client's commands name the helper.

What the route holds to, as the enrollment route does (ADR-0024):
- **Only over HTTPS, and not in lockdown.** Over plain HTTP there is no key to pin.
- **GET (and HEAD) serves the script for a good code and spends nothing**; POST hands the token
  over, once, and spends the code.
- **Every fetch and hand-over is audited** under the code's id and the token's id, never either's
  value; without the audit log nothing happens.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Callable
from pathlib import Path

from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response

from nervus.audit import AuditError
from nervus.token_codes import CLIENTS, CodeRefused, TokenCodes

TARGET = Path(__file__).resolve().parent / "target"
TOOL = "laptop"
HTTPS_ONLY = ("this nervus serves plain HTTP, and a laptop's line needs HTTPS: it checks nervus's key before it "
              "runs anything nervus sends")
LOCKED = "nervus is locked down, so it hands over no token; ask its operator"
UNKNOWN = ("this line's code is unknown, used or expired; on nervus's Clients page, give the token a new line, "
           "or issue another")
# A host as a URL may carry it, and as a file's name does: what the scripts put in a path.
HOST = re.compile(r"[A-Za-z0-9.:-]+")


class Refused(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


def laptop_url(host: str, port: int, code: str, windows: bool = False) -> str:
    """Where a laptop fetches its script: nervus's MCP port at `host`. Port 443 is left out, as curl
    leaves it out of what it asks for, so the script's own URL is the line's."""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"  # an IPv6 address
    return f"https://{host}{'' if port == 443 else f':{port}'}/laptop/{code}" + ("/windows" if windows else "")


def laptop_line(url: str, pin: str) -> str:
    """The macOS and Linux line (question 4 a), run as the person: the script fetched pinned to
    nervus's key, `-k` only stopping curl asking the computer's own authorities, which do not know
    nervus's; `-f`, so an answer that is not the script is never handed to the shell."""
    return f"curl -fsSk --pinnedpubkey {shlex.quote(pin)} {shlex.quote(url)} | sh\n"


def _ps(value: str) -> str:
    """A PowerShell string literal: in single quotes, which expand nothing, a quote doubled."""
    return "'" + value.replace("'", "''") + "'"


def powershell_line(url: str, pin: str) -> str:
    """The Windows line (question 11 a), for PowerShell: curl.exe, which Windows 10 and 11 carry,
    makes the same pinned fetch; Out-String gathers the whole script, and Invoke-Expression parses
    all of it before any of it runs."""
    return f"iex (curl.exe -fsSk --pinnedpubkey {_ps(pin)} {_ps(url)} | Out-String)\n"


def _names(host: str, token_id: str) -> tuple[str, str]:
    """The names the scripts give nervus's files on the laptop: `safe`, the host as tools/nervus-trust
    names its root (`root-<safe>.pem`), and `name`, the token's, `<safe>-<token id>`."""
    bare = host.strip("[]")
    if not HOST.fullmatch(bare):
        raise ValueError(f"not a host a laptop's script can name: {host!r}")
    safe = bare.replace(":", "-")
    return safe, f"{safe}-{token_id}"


def _helper(name: str) -> str:
    return (TARGET / name).read_text()


def laptop_script(*, origin: str, host: str, url: str, pin: str, root_pem: str, token_id: str, client: str) -> str:
    """The macOS and Linux script for one code: nervus at `origin` (https://<host>:<port>), its
    line's `url`, nervus's key as curl pins it, nervus's root, and the token it hands over, for
    `client`, one of CLIENTS."""
    if client not in CLIENTS:
        raise ValueError(f"not a client nervus knows: {client!r}")
    if any(c in text for text in (origin, host, url, pin, token_id) for c in "\r\n\0'\""):
        raise ValueError("a value for the script holds a line break or a quote")
    if "-----BEGIN CERTIFICATE-----" not in root_pem or "'" in root_pem:
        raise ValueError("nervus's root is not a certificate the script can carry")
    safe, name = _names(host, token_id)
    helper = _helper("nervus-headers")
    if not helper.endswith("\n") or "NERVUS_HELPER" in helper.splitlines():
        raise ValueError("the helper cannot be carried in the script as it is")
    words = CLIENTS[client]
    head = f"""#!/bin/sh
# nervus: set this computer up to reach nervus at {origin}, for {words}, with the token {token_id}.
#
# nervus wrote this for the token you issued on its Clients page. Run it as yourself, not as root.
# Nothing runs until all of it has arrived: below this comment, everything is one group, {{ to the
# last line's }}, and the body one function in it. In ~/.config/nervus (or $XDG_CONFIG_HOME/nervus)
# it does exactly this:
#   1. asks nervus whether this line's code is still good, before anything else;
#   2. checks that nervus answers at {host} as its root, carried below, vouches, then saves that
#      root as root-{safe}.pem and gathers every nervus root saved there into roots.pem, as
#      tools/nervus-trust does;
#   3. puts there the helper a client runs for its headers, nervus-headers, carried below;
#   4. fetches the token, once, with this line's code, and keeps it: on a Mac in your login
#      keychain, as the item nervus-{name}, which asks you before each read; on Linux in the file
#      token-{name}, which only you can read. It is never shown and in no command's arguments;
#   5. prints the commands that tell {words} to use nervus. It runs none of them.

{{
set -u
origin={shlex.quote(origin)} host={shlex.quote(host)}
url={shlex.quote(url)}
mcp={shlex.quote(origin + "/mcp")}
pin={shlex.quote(pin)}
token={shlex.quote(token_id)} client={shlex.quote(client)}
safe={shlex.quote(safe)} name={shlex.quote(name)}
root_pem={shlex.quote(root_pem.strip())}

"""
    return head + _helper("laptop.sh").replace("@@HELPER@@", helper)


def laptop_powershell(*, origin: str, host: str, url: str, pin: str, root_pem: str, token_id: str,
                      client: str) -> str:
    """The Windows script for one code (question 11 a), the macOS and Linux one's twin, in
    PowerShell: the token kept in a file encrypted by Windows for this account alone (DPAPI)."""
    if client not in CLIENTS:
        raise ValueError(f"not a client nervus knows: {client!r}")
    if any(c in text for text in (origin, host, url, pin, token_id) for c in "\r\n\0'\"`$"):
        raise ValueError("a value for the script holds a line break, a quote or a character PowerShell expands")
    if "-----BEGIN CERTIFICATE-----" not in root_pem or "'" in root_pem:
        raise ValueError("nervus's root is not a certificate the script can carry")
    safe, name = _names(host, token_id)
    helper = _helper("nervus-headers.ps1")
    if "'@" in helper:
        raise ValueError("the helper cannot be carried in the script as it is")
    words = CLIENTS[client]
    head = f"""# nervus: set this computer up to reach nervus at {origin}, for {words}, with the token {token_id}.
#
# nervus wrote this for the token you issued on its Clients page. Run it in PowerShell as yourself,
# not as an administrator. Nothing runs until all of it has arrived: PowerShell reads the whole of it
# before it runs any, and below this comment everything is one block, & {{ to the last line's }}.
# In the folder .config\\nervus in your home folder it does exactly this:
#   1. asks nervus whether this line's code is still good, before anything else;
#   2. checks that nervus answers at {host} as its root, carried below, vouches, then saves that root
#      as root-{safe}.pem and gathers every nervus root saved there into roots.pem;
#   3. puts there the helper a client runs for its headers, nervus-headers.ps1, carried below;
#   4. fetches the token, once, with this line's code, and keeps it in the file token-{name},
#      encrypted by Windows so that only your Windows account can read it. It is never shown and in
#      no command's arguments;
#   5. prints the commands that tell {words} to use nervus. It runs none of them.

& {{
$nervusOrigin = {_ps(origin)}
$nervusHost = {_ps(host)}
$nervusUrl = {_ps(url)}
$nervusMcp = {_ps(origin + "/mcp")}
$nervusPin = {_ps(pin)}
$nervusToken = {_ps(token_id)}
$nervusClient = {_ps(client)}
$nervusSafe = {_ps(safe)}
$nervusName = {_ps(name)}
$nervusRoot = {_ps(root_pem.strip())}
$nervusHelper = @'
{helper.rstrip()}
'@

"""
    body = _helper("laptop.ps1")
    text = head + body
    if not text.isascii():
        raise ValueError("the PowerShell script must be ASCII: Out-String reads curl.exe's output in the console's "
                         "own code page")
    return text


class LaptopRoute:
    """The laptop route's work. `pin` is nervus's serving key as curl pins it, None where MCP is
    plain HTTP; `root` reads nervus's root certificate, the PEM a client trusts; `locked` says
    whether nervus is locked down. Each is read at every request."""

    def __init__(self, codes: TokenCodes, audit, *, pin: Callable[[], str | None], root: Callable[[], str],
                 locked: Callable[[], bool] = lambda: False):
        self.codes, self.audit, self.pin, self.root, self.locked = codes, audit, pin, root, locked

    def _open(self, value: str, action: str, client: str):
        fields = {"actor": "operator", "action": action, "from": client}
        if self.pin() is None:
            self.audit.record_refusal(TOOL, {**fields, "reason": "plain HTTP"})
            raise Refused(503, HTTPS_ONLY)
        if self.locked():
            self.audit.record_refusal(TOOL, {**fields, "reason": "lockdown"})
            raise Refused(503, LOCKED)
        code = self.codes.find(value) if action == "fetch" else self.codes.known(value)
        if code is None:
            self.audit.record_refusal(TOOL, {**fields, "reason": "unknown, used or expired code"})
            raise Refused(404, UNKNOWN)
        run_id = self.audit.record_intent(TOOL, {**fields, "code_id": code.id, "target": code.token_id,
                                                 "client": code.client})
        return code, run_id

    def script(self, value: str, origin: str, host: str, client: str, windows: bool) -> str:
        code, run_id = self._open(value, "fetch", client)
        url = f"{origin}/laptop/{value}"
        write = laptop_powershell if windows else laptop_script
        try:
            text = write(origin=origin, host=host, url=url, pin=self.pin(), root_pem=self.root(),
                         token_id=code.token_id, client=code.client)
        except (OSError, ValueError) as exc:
            self.audit.record_result(run_id, TOOL, {"failure_message": str(exc)})
            raise Refused(500, f"nervus could not write the script: {exc}") from exc
        self.audit.record_result(run_id, TOOL, {"served": "windows" if windows else "macos-linux"})
        return text

    def hand_over(self, value: str, client: str) -> str:
        code, run_id = self._open(value, "hand_over", client)
        try:
            token_value, _ = self.codes.hand_over(value, client)
        except CodeRefused as exc:
            self.audit.record_result(run_id, TOOL, {"failure_code": exc.reason})
            raise Refused(404 if exc.reason != "revoked" else 410, exc.message) from None
        try:
            self.audit.record_result(run_id, TOOL, {"handed_over": True})
        except AuditError:
            # The token is handed over and its record is not written: it is the person's still, whose run
            # gets it now, and the intent above names it. Said on nervus's own log.
            print(f"nervus: token {code.token_id} handed over to {client}, its result not audited", flush=True)
        return token_value


def laptop_endpoints(route: LaptopRoute):
    """GET and POST /laptop/{code}, GET /laptop/{code}/windows, beside /mcp. Every answer is plain
    text, for the person at the laptop. A HEAD is served as a GET, spending nothing."""

    async def run(request: Request, windows: bool) -> Response:
        value = request.path_params["code"]
        client = request.client.host if request.client else ""
        try:
            if request.method in ("GET", "HEAD"):
                origin = f"{request.url.scheme}://{request.url.netloc}"
                return PlainTextResponse(route.script(value, origin, request.url.hostname or "", client, windows),
                                         headers={"Cache-Control": "no-store"})
            return PlainTextResponse(route.hand_over(value, client) + "\n", headers={"Cache-Control": "no-store"})
        except Refused as exc:
            return PlainTextResponse(f"nervus: {exc.message}\n", status_code=exc.status)
        except AuditError:
            return PlainTextResponse("nervus: cannot write its audit log, so it does nothing\n", status_code=503)

    async def endpoint(request: Request) -> Response:
        return await run(request, windows=False)

    async def windows(request: Request) -> Response:
        return await run(request, windows=True)

    return endpoint, windows
