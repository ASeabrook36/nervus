"""Enrolling a machine with an admin login its owner gives once (ADR-0026).

nervus fetches the machine's SSH host key and shows it (`host_key`). The owner
checks it and types an admin account and its password. This file logs in to the
machine as that account, becomes root there (it is root, or uses `sudo` with
that password), and runs ADR-0024's two lines itself. From the moment the
script runs, everything is ADR-0024's: the same script, report, check and row.

This is the only code that ever holds an owner's admin password.

What it holds to:
- **The password goes only to the key the owner was shown.** The login is
  pinned to exactly that host key, so a server answering with another key is
  refused before authentication begins and is given no password.
- **The key shown is the machine's ed25519 key where it has one** (question
  9), the one the docs tell the owner to check; another type only from a
  machine that has none, and the page names that key's file.
- **nervus offers nothing of its own account.** No key, no SSH agent, nothing
  read from `~/.ssh/config`, no Kerberos or host-based login: only the
  password, by `keyboard-interactive` or `password`.
- **The password is kept nowhere.** It is held in memory for one run. Every
  text that reaches a step line, the tail of output, an outcome, the code's
  record, the audit log or standard error has it replaced by `<password>`
  first, in case the machine echoes it. A line is read in pieces of bounded
  size, so a machine cannot fill nervus's memory with one.
- **Whatever `sudo` leaves unread on standard input reaches nothing the
  script runs.** The script runs with its standard input from `/dev/null`.
- **The code works for nothing once a run ends, however it ends**: after an
  enrollment, a refusal, a timeout, or a failure of nervus's own.
- **The code is not in nervus's journal while it works.** asyncssh logs every
  command a connection runs, and the command nervus runs on the machine holds
  the code in its URL; nervus writes `/enroll/<code>` in its place there, as
  in its request log (found by procedure 041).
- **Nothing is attempted in lockdown, without an HTTPS key to pin, or
  without the audit record of the login:** the intent is written before
  nervus connects to anything.
- **Only the account name is recorded**, with the key's fingerprint; never
  the password.
"""

from __future__ import annotations

import asyncio
import logging
import re
import shlex
import socket
import sys
import time
from collections import deque
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field

import asyncssh

from nervus.audit import AuditError, AuditLog
from nervus.enroller import pinned_known_hosts
from nervus.enrollment_codes import EnrollmentCode, EnrollmentCodes
from nervus.enrollments import host_keys

# The route's tool name, so the audit viewer shows a login and its report together.
TOOL = "enroll"
CONNECT_SECONDS = 10.0
CHECK_SECONDS = 20.0
RUN_SECONDS = 600.0  # installing packages on a slow machine
KEEP_SECONDS = 3600.0  # how long a finished run is kept for its page
MAX_LINES = 200
LINE_CHARS = 500
TAIL_LINES = 20
SUDO_CHECK = "sudo -S -p '' true"
PIN = re.compile(r"sha256//[A-Za-z0-9+/]{43}=")
SCRUBBED = "<password>"
# The server's host key types nervus asks for, in order: ed25519 first (question 9), then every other plain key
# type, so a machine without one still answers. asyncssh's own order puts RSA first.
HOST_KEY_ALGS = ("ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-ed448",
                 "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa")
_KEY_FILE_STEMS = {"ssh-ed25519": "ed25519", "ssh-ed448": "ed448", "ssh-rsa": "rsa", "ssh-dss": "dsa"}
STEP_PREFIXES = ("nervus enrollment: ", "nervus: ")


def fingerprint(host_key: str) -> str:
    """A host key as `ssh-keygen -l` prints it, algorithm then `SHA256:...`."""
    key = asyncssh.import_public_key(host_key)
    return f"{key.get_algorithm()} {key.get_fingerprint('sha256')}"


def key_file(host_key: str) -> str:
    """Where OpenSSH keeps a machine's public host key of this key's type: the
    file the owner checks the fingerprint of on the machine itself."""
    algorithm = asyncssh.import_public_key(host_key).get_algorithm()
    stem = "ecdsa" if algorithm.startswith("ecdsa-") else _KEY_FILE_STEMS.get(algorithm, "*")
    return f"/etc/ssh/ssh_host_{stem}_key.pub"


NO_CURL = ("nervus enrollment: this machine has no curl, which fetches nervus's script, and no apt-get to install "
           "it with: install curl, then add the machine again. Nothing here was changed")
NO_CURL_INSTALLED = ("nervus enrollment: apt-get could not install curl, which fetches nervus's script: install it, "
                     "then add the machine again")
# A machine without curl is given it first (ADR-0026 question 10), as nervus's script gives it tmux: by
# apt-get, the package lists first, nothing asked, said in a step line; nothing of standard input reaches
# apt-get. Without apt-get nothing is changed, and it says what is missing. Before, the fetch below failed
# as an unreachable nervus does, and the owner was told that.
_CURL_FIRST = ("if ! command -v curl >/dev/null 2>&1; then "
               f"command -v apt-get >/dev/null 2>&1 || {{ echo {shlex.quote(NO_CURL)} >&2; exit 1; }}; "
               "echo 'nervus enrollment: installing curl'; "
               "DEBIAN_FRONTEND=noninteractive apt-get update -q </dev/null >/dev/null "
               "&& DEBIAN_FRONTEND=noninteractive apt-get install -y -q curl </dev/null >/dev/null "
               "&& command -v curl >/dev/null 2>&1 "
               f"|| {{ echo {shlex.quote(NO_CURL_INSTALLED)} >&2; exit 1; }}; fi; ")


def root_command(url: str, pin: str, shown: str) -> str:
    """The two lines as nervus runs them as root: fetch the script to a file of
    its own that is removed on every way out, then run it with nothing on its
    standard input. Before them, on a machine that has no curl to fetch with,
    curl is installed (question 10). `shown` is the URL with `<code>` for the
    code, so the code is never shown in a message."""
    if not PIN.fullmatch(pin):
        raise ValueError("a pin is sha256// and a key's hash, so the machine checks it is talking to nervus")
    message = f"nervus enrollment: this machine could not reach nervus at {shown}, so nothing here was changed"
    return (_CURL_FIRST +
            "t=$(mktemp) || exit 1; trap 'rm -f \"$t\"' EXIT; "
            f"curl -fsSk --pinnedpubkey {shlex.quote(pin)} -o \"$t\" {shlex.quote(url)} "
            f"|| {{ echo {shlex.quote(message)} >&2; exit 1; }}; sh \"$t\" </dev/null")


def login_command(root: str, *, sudo: bool) -> str:
    """`root` run as root: directly where the login is root, else by `sudo`
    taking its password from standard input."""
    return f"sudo -S -p '' sh -c {shlex.quote(root)}" if sudo else f"sh -c {shlex.quote(root)}"


class LoginRefused(Exception):
    """A login that cannot be made, in words for the owner."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


@dataclass
class LoginRun:
    """One enrollment by login, for its progress page. It never holds the
    password."""
    code_id: str
    name: str
    address: str
    level: str
    login: str
    fingerprint: str
    started_at: float
    lines: list[str] = field(default_factory=list)
    finished_at: float | None = None
    enrolled: bool = False
    outcome: str = ""

    @property
    def done(self) -> bool:
        return self.finished_at is not None


_ENROLL_CODE = re.compile(r"/enroll/[A-Za-z0-9_-]+")


class HideCodesInSSHLog(logging.Filter):
    """Writes `/enroll/<code>` where a line of asyncssh's log holds a one-time
    enrollment code, as asyncssh's "Command:" line does for the command a run
    sends the machine; every other line as it was. The request log is quieted
    the same way (`__main__._HideEnrollmentCodes`, procedure 037)."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = _ENROLL_CODE.sub("/enroll/<code>", record.msg)
        if isinstance(record.args, tuple):
            record.args = tuple(_ENROLL_CODE.sub("/enroll/<code>", a) if isinstance(a, str) else a
                                for a in record.args)
        return True


def hide_codes_in_ssh_log() -> None:
    """Once per process: asyncssh's own logger names every command it runs."""
    ssh_log = logging.getLogger("asyncssh")
    if not any(isinstance(f, HideCodesInSSHLog) for f in ssh_log.filters):
        ssh_log.addFilter(HideCodesInSSHLog())


def _scrubbed(text: str, password: str) -> str:
    return text.replace(password, SCRUBBED) if password else text


async def _lines(reader, keep: int) -> AsyncIterator[str]:
    """Each line of `reader`, at most `keep` characters of it: what a machine
    prints is read in pieces and cut, never held whole. A line with no end
    that long is given as it stands, and the rest of it dropped."""
    pending, dropping = "", False
    while True:
        data = await reader.read(4096)
        if not data:
            break
        pending += data
        while "\n" in pending:
            head, _, pending = pending.partition("\n")
            if not dropping:
                yield head.rstrip("\r")[:keep]
            dropping = False
        if len(pending) >= keep:
            if not dropping:
                yield pending[:keep]
            pending, dropping = "", True
    if pending and not dropping:
        yield pending.rstrip("\r")[:keep]


class LoginEnrollment:
    """What nervus's page uses to add a machine by an admin login: the host key
    to show, and a run that logs in and enrolls. `locked` is read at each run.
    Runs go on whether or not anyone watches the page."""

    def __init__(self, codes: EnrollmentCodes, audit: AuditLog, *, port: int = 22,
                 locked: Callable[[], bool] = lambda: False, connect_seconds: float = CONNECT_SECONDS,
                 run_seconds: float = RUN_SECONDS):
        self.codes, self.audit, self.port, self.locked = codes, audit, port, locked
        self.connect_seconds, self.run_seconds = connect_seconds, run_seconds
        self._runs: dict[str, LoginRun] = {}
        self._tasks: set[asyncio.Task] = set()
        hide_codes_in_ssh_log()

    async def host_key(self, address: str) -> str:
        """The host key the SSH server at `address` answers with, as the store
        keeps keys. Nothing is sent but the key exchange. Raises LoginRefused,
        saying what is wrong."""
        try:
            key = await asyncio.wait_for(asyncssh.get_server_host_key(
                address, self.port, config=None, server_host_key_algs=list(HOST_KEY_ALGS)), self.connect_seconds)
        except socket.gaierror:
            raise LoginRefused(f"nervus's machine cannot find {address}: its DNS does not know that name. Give the "
                               f"machine's address, or, for a .local name, install avahi-daemon and libnss-mdns on "
                               f"nervus's machine.") from None
        except ConnectionRefusedError:
            raise LoginRefused(f"nothing answers SSH at {address}, port {self.port}: is its SSH server "
                               f"running?") from None
        except TimeoutError:
            raise LoginRefused(f"{address} did not answer within {self.connect_seconds:g} seconds") from None
        except OSError as exc:
            raise LoginRefused(f"cannot reach {address}: {exc}"[:120]) from None
        except asyncssh.Error as exc:
            raise LoginRefused(f"{address} did not answer as an SSH server ({exc.reason})") from None
        if key is None:
            raise LoginRefused(f"{address} showed no host key, so nervus cannot know it is that machine")
        return host_keys([key.export_public_key("openssh").decode()])[0]

    def start(self, code: EnrollmentCode, *, url: str, pin: str, host_key: str, login: str, password: str,
              shown: str) -> LoginRun:
        """Begin the run for `code` in the background and return it. Called
        inside the event loop."""
        now = time.time()
        self._runs = {k: r for k, r in self._runs.items()
                      if r.finished_at is None or now - r.finished_at <= KEEP_SECONDS}
        run = LoginRun(code_id=code.id, name=code.name, address=code.address, level=code.level, login=login,
                       fingerprint=fingerprint(host_key), started_at=now)
        self._runs[code.id] = run
        task = asyncio.create_task(self._run(run, url=url, pin=pin, host_key=host_key, password=password,
                                             shown=shown))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return run

    def get(self, code_id: str) -> LoginRun | None:
        return self._runs.get(code_id)

    async def finished(self) -> None:
        """Wait for every run now going (for tests)."""
        await asyncio.gather(*self._tasks, return_exceptions=True)

    # --- the run -------------------------------------------------------------------

    async def _run(self, run: LoginRun, *, url: str, pin: str, host_key: str, password: str, shown: str) -> None:
        scrub = lambda text: _scrubbed(text, password)  # noqa: E731
        tail: deque[str] = deque(maxlen=TAIL_LINES)
        state = {"run_id": None, "conn": None, "status": None, "last_error_step": None}
        outcome: str | None = None
        try:
            async with asyncio.timeout(self.run_seconds) as limit:
                try:
                    await self._work(run, state, tail, scrub, url=url, pin=pin, host_key=host_key,
                                     password=password, shown=shown)
                except LoginRefused as exc:
                    outcome = exc.message
            if outcome is None:
                outcome = self._outcome(run, state, tail)
        except TimeoutError:
            if limit.expired():
                outcome = (f"did not finish within {int(self.run_seconds // 60)} minutes. nervus stopped waiting, and "
                           f"the code no longer works, so if the script still reaches nervus it takes nervus's key "
                           f"off again")
            else:
                outcome = "nervus failed (TimeoutError)"
        except Exception as exc:  # noqa: BLE001  (nothing a machine does may leave a run unfinished)
            outcome = f"nervus failed ({type(exc).__name__})"
            print(scrub(f"nervus: a login enrollment failed: {type(exc).__name__}: {exc}"), file=sys.stderr,
                  flush=True)
        finally:
            self._end(run, state, scrub(outcome or "nervus stopped before it finished"))
            password = ""  # nothing of it stays beyond the run

    def _outcome(self, run: LoginRun, state: dict, tail: deque) -> str:
        """What became of the run, the route's own word first."""
        code = self.codes.get(run.code_id)
        status = state["status"]
        if code is not None and code.outcome:
            run.enrolled = status == 0 and code.outcome.startswith("enrolled")
            return code.outcome
        if state["last_error_step"]:
            return state["last_error_step"]
        if tail:
            return tail[-1]
        return f"the script ended with status {status}"

    def _end(self, run: LoginRun, state: dict, outcome: str) -> None:
        """However the run ended: close the connection, make the code work for
        nothing more, say what became of it, and write the result."""
        conn = state["conn"]
        if conn is not None:
            conn.close()
        for what, action in (
            ("cancel the code", lambda: self.codes.cancel(run.code_id)),
            ("record the outcome", lambda: self._finish_code(run.code_id, outcome)),
            ("write the result", lambda: self._record_result(run, state, outcome)),
        ):
            try:
                action()
            except Exception as exc:  # noqa: BLE001
                print(f"nervus: a login enrollment could not {what}: {type(exc).__name__}", file=sys.stderr, flush=True)
        run.outcome = outcome
        run.finished_at = time.time()

    def _finish_code(self, code_id: str, outcome: str) -> None:
        code = self.codes.get(code_id)
        if code is not None and not code.outcome:
            self.codes.finish(code_id, outcome)

    def _record_result(self, run: LoginRun, state: dict, outcome: str) -> None:
        if state["run_id"] is not None:
            self.audit.record_result(state["run_id"], TOOL, {"enrolled": run.enrolled, "outcome": outcome,
                                                             "exit_status": state["status"]})

    async def _work(self, run: LoginRun, state: dict, tail: deque, scrub: Callable[[str], str], *, url: str,
                    pin: str, host_key: str, password: str, shown: str) -> None:
        fields = {"actor": "operator", "action": "login", "code_id": run.code_id, "name": run.name,
                  "address": run.address, "level": run.level, "login": run.login}
        if not isinstance(pin, str) or not PIN.fullmatch(pin):
            self._refusal(fields, "plain HTTP")
            raise LoginRefused("this nervus has no HTTPS key to pin, so the machine could not check it is talking "
                               "to nervus: nervus logs in to nothing")
        if self.locked():
            self._refusal(fields, "lockdown")
            raise LoginRefused("nervus is locked down, so it enrolls nothing")
        if re.search(r"[\r\n\0]", password):
            raise LoginRefused("a password cannot hold a line break")
        root_script = root_command(url, pin, shown)
        try:
            state["run_id"] = self.audit.record_intent(TOOL, {**fields, "host_key": run.fingerprint})
        except AuditError:
            raise LoginRefused("nervus cannot write its audit log, so it did nothing") from None

        address, login = run.address, run.login
        self._step(run, f"connecting to {address} as {login}, trusting only the key {run.fingerprint}", scrub)
        conn = await self._login(address, login, host_key, password, scrub)
        state["conn"] = conn
        self._step(run, f"logged in as {login}", scrub)

        root = await self._become_root(conn, login, password, scrub, run)
        self._step(run, f"running nervus's enrollment script for {run.level} as root; the machine fetches it from "
                        f"{shown}", scrub)
        await self._script(conn, run, state, tail, scrub, command=login_command(root_script, sudo=not root),
                           password=password, sudo=not root)

    def _refusal(self, fields: dict, reason: str) -> None:
        try:
            self.audit.record_refusal(TOOL, {**fields, "reason": reason})
        except AuditError:
            pass  # nothing is attempted either way; the run still says why

    def _step(self, run: LoginRun, text: str, scrub: Callable[[str], str]) -> None:
        if len(run.lines) < MAX_LINES:
            run.lines.append(scrub(text)[:LINE_CHARS])

    async def _login(self, address: str, login: str, host_key: str, password: str, scrub) -> asyncssh.SSHClientConnection:
        try:
            return await asyncssh.connect(
                address, self.port, username=login, password=password,
                known_hosts=pinned_known_hosts(address, self.port, (host_key,)), client_keys=None, agent_path=None,
                gss_auth=False, host_based_auth=False, preferred_auth="keyboard-interactive,password", config=None,
                connect_timeout=self.connect_seconds)
        except (asyncssh.HostKeyNotVerifiable, asyncssh.KeyExchangeFailed):
            # Another key of the same type fails the check; one of another type, which asyncssh does not offer
            # once a key is pinned, fails the key exchange first. To the owner both are the same (question 8).
            raise LoginRefused(f"the SSH server at {address} now answers with another key than the one shown, so "
                               f"nervus sent it no password. If the machine was reinstalled since, start again; if "
                               f"not, something else may be answering at that address.") from None
        except asyncssh.PermissionDenied:
            methods = await self._methods(address, login)
            if "password" not in methods and "keyboard-interactive" not in methods:
                raise LoginRefused(f"{address} takes no password for {login}, only keys, so nervus cannot log in. "
                                   f"Add it with the two lines (Advanced).") from None
            if login == "root":
                raise LoginRefused(f"{address} refused root with that password. Most machines refuse root's "
                                   f"password over SSH (PermitRootLogin); use an account that can use "
                                   f"sudo.") from None
            raise LoginRefused(f"{address} refused {login} with that password.") from None
        except Exception as exc:  # noqa: BLE001
            reason = getattr(exc, "reason", "") or str(exc)
            raise LoginRefused(scrub(f"cannot log in to {address} ({type(exc).__name__}: {reason})")[:200]) from None

    async def _methods(self, address: str, login: str) -> list[str]:
        """What the server takes for `login`, asked without sending any
        credential; none if it cannot be asked."""
        try:
            return list(await asyncio.wait_for(
                asyncssh.get_server_auth_methods(address, self.port, login, config=None), self.connect_seconds))
        except Exception:  # noqa: BLE001
            return []

    async def _become_root(self, conn, login: str, password: str, scrub, run: LoginRun) -> bool:
        """True if the login is root; False if it can use `sudo` with its
        password; else LoginRefused."""
        uid = await self._ask(conn, "id -u", None)
        if uid.stdout is not None and str(uid.stdout).strip() == "0":
            self._step(run, f"{login} is root", scrub)
            return True
        found = await self._ask(conn, SUDO_CHECK, password + "\n")
        if found.exit_status == 0:
            self._step(run, f"{login} can use sudo", scrub)
            return False
        said = [line for line in str(found.stderr or "").splitlines() if line.strip()]
        if found.exit_status == 127 or (said and "not found" in said[-1]):
            raise LoginRefused(f"{login} is not root, and this machine has no sudo: give root's login, or add it "
                               f"with the two lines from a root shell")
        raise LoginRefused(scrub(f"{login} cannot use sudo with that password (sudo said: "
                                 f"{said[-1][:LINE_CHARS] if said else 'nothing'})"))

    async def _ask(self, conn, command: str, given: str | None):
        try:
            return await conn.run(command, input=given, check=False, timeout=CHECK_SECONDS)
        except (OSError, asyncssh.Error) as exc:
            raise LoginRefused(f"the machine did not answer `{command.split()[0]}` ({type(exc).__name__})") from None

    async def _script(self, conn, run: LoginRun, state: dict, tail: deque, scrub, *, command: str, password: str,
                      sudo: bool) -> None:
        process = await conn.create_process(command, encoding="utf-8", errors="replace")
        try:
            if sudo:
                process.stdin.write(password + "\n")
            process.stdin.write_eof()
        except (OSError, asyncssh.Error):
            pass  # the machine ended the command already; what it printed says why

        async def read(reader, errors: bool) -> None:
            async for raw in _lines(reader, LINE_CHARS + len(password)):
                line = scrub(raw)[:LINE_CHARS]
                step = next((line[len(p):] for p in STEP_PREFIXES if line.startswith(p)), None)
                if step is None:
                    tail.append(line)
                    continue
                self._step(run, step, scrub)
                if errors:
                    state["last_error_step"] = step

        await asyncio.gather(read(process.stdout, False), read(process.stderr, True))
        done = await process.wait()
        state["status"] = done.exit_status if done.exit_status is not None else -1
