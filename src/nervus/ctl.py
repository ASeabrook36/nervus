"""nervus-ctl: the operator's off switch (ADR-0003), and the operator's way
into the UI (ADR-0012), run on the nervus machine.

    nervus-ctl status
    nervus-ctl lock <token-id> [--kill-work [--yes]]
    nervus-ctl lock --all [--kill-work [--yes]]
    nervus-ctl unlock <token-id>
    nervus-ctl unlock --all
    nervus-ctl signin
    nervus-ctl signout --all
    nervus-ctl backup [--check <file>]
    nervus-ctl restore <file> [--yes]
    nervus-ctl recovery-key [--replace]
    nervus-ctl start-empty
    nervus-ctl accept-keys

It runs as root on the nervus machine (on Proxmox, `pct exec <vmid> -- ...`), and
bypasses token authentication: holding root on the container is the authority
(ADR-0003 decision 5). It is never an MCP tool, so no client can switch another
off.

- Blocking access is reversible: lock and unlock edit the switches file, which
  nervus re-reads on every request.
- Stopping work is not reversible, so it is a separate, explicit choice
  (--kill-work). nervus-ctl lists the jobs first, then asks for confirmation.
- Jobs are looked for on every machine nervus reaches: hosts.yaml's, those
  added from the web UI, and each VM used by its id, shown as `vmid N`. A
  machine that cannot be read is named, never passed over in silence.
- `lock --all` is lockdown; `unlock --all` lifts lockdown and leaves clients
  that were switched off one by one still off.
- Every action is written to the audit log with the actor "operator"
  (decision 6). So is each listing of jobs: every login nervus-ctl makes
  carries a certificate signed by nervus's CA naming `operator` and that
  record (ADR-0025), and a machine enrolled with the CA admits nothing else.
- `signin` prints a link that signs a browser in to the UI once, within 5
  minutes, and the certificate fingerprint to check the browser's warning
  against. Signing in needs the authority every other command here needs
  (ADR-0011 question A). `signout --all` ends every browser's session.

- Backups (ADR-0027): `backup` makes one, as nervus's account, locked to the
  recovery key's public half; `backup --check` opens one with the private
  half, typed and never saved, and changes nothing but its record; `restore`
  puts one in place, checking it first and keeping what it replaces, and
  starts nervus in lockdown; `recovery-key` makes the key pair and prints the
  private half once; `start-empty` and `accept-keys` are the person's way past
  nervus's refusals to start (question 6), each audited.

It takes every path from nervus's own unit file and its drop-ins, the arguments
systemd starts nervus with, so it always acts on the files the running service reads. A lock
written anywhere else would leave the client on while the operator believed it
off.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import dataclasses
import getpass
import json
import os
import pwd
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

import yaml

import nervus
from nervus import certs, identity, jobs, plainfile, restore, ssh
from nervus.backup import kept_name, recipient
from nervus.auth import load_tokens
from nervus.certs import CertificateAuthority
from nervus.config import ConfigError, Host, load_hosts
from nervus.database import LINK_SECONDS, audit_id
from nervus.enroller import AGENT_USER, SSH_CONNECT_SECONDS, pinned_known_hosts
from nervus.first_run import TIER_WORDS
from nervus.switches import Switches, SwitchesSwapped, SwitchesUnreadable, change_switches, load_switches
from nervus.tls import certificate_fingerprint, issuer_key_path, renewal_path, serving_path

UNIT = Path("/etc/systemd/system/nervus.service")
DEFAULT_TLS_KEY_PATH = "/opt/nervus/secrets/tls.key"


@dataclass(frozen=True)
class Service:
    """What nervus runs with, as its unit file says."""

    tokens: Path
    hosts: Path
    switches: Path
    audit_log: Path
    ssh_key: Path
    ssh_ca: Path
    known_hosts: Path
    ssh_port: int
    database: Path
    ui_url: str  # "" when the unit gives none
    tls_cert: Path  # the UI's certificate: the one given, or nervus's own
    tls_renewed: Path  # where nervus writes its renewal, and serves it from (ADR-0021 D1)
    user: str | None  # the unit's User=, the account nervus runs as
    tls_key: Path = Path(DEFAULT_TLS_KEY_PATH)  # the key beside tls_cert
    tls_issuer: Path | None = None  # nervus's own issuer key, if it serves with nervus's own TLS (ADR-0027 question 6)
    proxmox: Path | None = None  # the Proxmox settings, if the unit gives --proxmox
    recovery_key: Path = Path("secrets/recovery.pub")  # the recovery key's public half (ADR-0027 question 2)
    drop_ins: tuple[Path, ...] = ()  # the installation's own flags (ADR-0019)


def unit_files(unit: Path) -> list[Path]:
    """The unit file, then its drop-ins (`<unit>.d/*.conf`) in the order systemd
    reads them: by name. An installation's own flags live in a drop-in
    (ADR-0019), so what nervus runs is the two together."""
    drop_ins = unit.parent / f"{unit.name}.d"
    return [unit, *sorted(drop_ins.glob("*.conf"))] if drop_ins.is_dir() else [unit]


def _effective(unit: Path) -> tuple[list[str], str, str | None]:
    """ExecStart's words, WorkingDirectory and User, from the unit file and its
    drop-ins read as systemd reads them."""
    starts: list[str] = []
    workdir, user = "/", None
    for path in unit_files(unit):
        try:
            text = path.read_text()
        except OSError as exc:
            raise ConfigError(f"cannot read nervus's unit file {path}: {exc}") from exc
        lines = text.replace("\\\n", " ").splitlines()
        if any(line.startswith(("Environment=", "EnvironmentFile=")) for line in lines):
            # nervus's defaults can come from NERVUS_* variables; this cannot see
            # what systemd would pass, so it refuses rather than guess.
            raise ConfigError(f"{path} sets an environment; nervus-ctl cannot tell which files nervus uses")
        for line in lines:
            key, _, value = line.partition("=")
            if key == "ExecStart":
                # As systemd does: an empty ExecStart= clears the ones before it.
                starts = [] if not value.strip() else [*starts, value]
            elif key == "WorkingDirectory":
                workdir = value.strip()
            elif key == "User":
                user = value.strip()
    if len(starts) != 1:
        raise ConfigError(f"{unit} and its drop-ins must leave exactly one ExecStart")
    return shlex.split(starts[0]), workdir, user


def exec_start(unit: Path) -> list[str]:
    """The command line systemd starts nervus with, program first."""
    return _effective(unit)[0]


def read_unit(unit: Path) -> Service:
    """The paths in the ExecStart nervus runs with, its unit file and drop-ins
    read as systemd reads them, resolved against its WorkingDirectory, parsed
    by nervus's own option parser."""
    from nervus.__main__ import parse_args

    argv, workdir, user = _effective(unit)
    saved = {k: os.environ.pop(k) for k in list(os.environ) if k.startswith("NERVUS_")}
    try:
        args = parse_args(argv[1:])
    finally:
        os.environ.update(saved)
    return service_of(args, Path(workdir), user or None, tuple(unit_files(unit)[1:]))


def service_of(args: argparse.Namespace, workdir: Path, user: str | None, drop_ins: tuple[Path, ...]) -> Service:
    """What nervus runs with, from its parsed arguments: for read_unit, and for
    nervus itself, whose UI makes a backup of the same pieces (ADR-0027)."""
    from nervus.__main__ import DEFAULT_TLS_CERT, DEFAULT_TLS_KEY, served_key

    def resolve(value: str) -> Path:
        return Path(workdir, value)  # an absolute value replaces workdir

    return Service(
        tokens=resolve(args.tokens), hosts=resolve(args.hosts), switches=resolve(args.switches),
        audit_log=resolve(args.audit_log), ssh_key=resolve(args.ssh_key), ssh_ca=resolve(args.ssh_ca_key),
        known_hosts=resolve(args.known_hosts), ssh_port=args.ssh_port,
        database=resolve(args.database), ui_url=args.ui_url,
        tls_cert=resolve(args.tls_cert or DEFAULT_TLS_CERT),
        tls_renewed=renewal_path(resolve(args.tls_cert or DEFAULT_TLS_CERT), resolve(args.database).parent),
        user=user,
        tls_key=resolve(args.tls_key or DEFAULT_TLS_KEY),
        tls_issuer=issuer_key_path(resolve(served)) if (served := served_key(args)) else None,
        proxmox=resolve(args.proxmox) if args.proxmox else None,
        recovery_key=resolve(args.recovery_key),
        drop_ins=drop_ins,
    )


def _jobs_by_run(audit_log: Path) -> dict[str, str]:
    """run id -> token id, for every exec_bg the audit log records. A job's id
    is its run id (decision 4): the shared account cannot tell clients apart,
    the audit log can."""
    owners: dict[str, str] = {}
    try:
        lines = plainfile.read_text(audit_log).splitlines()
    except FileNotFoundError:
        return owners
    except OSError as exc:
        raise ConfigError(f"cannot read the audit log: {exc}") from exc
    for line in lines:
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if record.get("tool") == "exec_bg" and record.get("phase") == "intent":
            owners[record["id"]] = record.get("token_id", "?")
    return owners


async def _connect(service: Service, host, authority: CertificateAuthority):
    """A login to one machine, signed for the record certs.acting_for names,
    then with the plain key for a machine not yet moved to the CA. A machine
    added from the web UI, or a VM used by its id, is trusted only with its own
    pinned keys, as nervus trusts it; one of hosts.yaml's, with the known_hosts
    file. A machine that does not answer is given up on after SSH_CONNECT_SECONDS,
    so that one dead machine cannot hold up status or the off switch."""
    return await ssh.connect(
        address=host.address, port=service.ssh_port, username=host.agent_user, client_keys=[service.ssh_key],
        known_hosts=(pinned_known_hosts(host.address, service.ssh_port, host.host_keys) if host.host_keys
                     else service.known_hosts),
        authority=authority, connect_timeout=SSH_CONNECT_SECONDS,
    )


DATABASE_MACHINES = "the machines added from the web UI and the VMs used by id"


def machines(service: Service) -> tuple[dict[str, Host], str | None]:
    """Every machine nervus reaches, by the name nervus-ctl gives it, and why
    any could not be known: hosts.yaml's; those added from the web UI's
    Machines page (ADR-0024, ADR-0026); and each VM used by its id (ADR-0022),
    as `vmid N`, the audit page's name for it. The last two are read from
    nervus's database, as the account nervus runs as; a hand-written entry
    keeps its name over an added one, as nervus has it (enrolled_hosts.merged).

    A VM is asked where nervus last reached it, with the keys nervus pinned:
    nervus-ctl enrolls and repairs nothing, and a VM that moved is not read
    (found 2026-11-19, procedure 066: these two kinds were asked for nothing)."""
    hosts = load_hosts(service.hosts)
    try:
        held = database_change(service, "machines")
    except ConfigError as exc:
        return hosts, str(exc)
    for row in held["hosts"]:
        hosts.setdefault(row["name"], Host(
            name=row["name"], address=row["address"], os="", role=f"enrolled, {row['level']}",
            agent_user=AGENT_USER, status="onboarded", host_keys=tuple(row["host_keys"]), level=row["level"]))
    for row in held["vms"]:
        name = f"vmid {row['vmid']}"
        hosts[name] = Host(name=name, address=row["address"], os="", role="a VM used by its id",
                           agent_user=AGENT_USER, status="onboarded", host_keys=tuple(row["host_keys"]))
    return hosts, None


async def _sessions(service: Service, host, authority: CertificateAuthority) -> list[str]:
    """Job ids of nervus's tmux sessions on one inventory entry. Two entries
    may be one machine with two accounts, and each has its own sessions."""
    conn = await _connect(service, host, authority)
    try:
        result = await conn.run("tmux list-sessions -F '#{session_name}' 2>/dev/null")
    finally:
        conn.close()
    names = str(result.stdout or "").split()
    return [n[len("nervus-"):] for n in names if n.startswith("nervus-")]


async def running_jobs(service: Service) -> tuple[dict[str, list[tuple[str, str]]], list[str]]:
    """(token id -> [(host, job id)], hosts that could not be read). Jobs no
    audit record attributes are listed under "unattributed".

    Its logins are signed for a `list_jobs` record written first, as the
    operator chose on 2026-10-27. Without that record no machine is asked."""
    owners = _jobs_by_run(service.audit_log)
    found: dict[str, list[tuple[str, str]]] = {}
    unreachable: list[str] = []
    hosts, why = machines(service)
    if why is not None:
        unreachable.append(f"{DATABASE_MACHINES}: {why}")
    try:
        authority = CertificateAuthority(service.ssh_ca)
        certs.acting_for(None, operator_record(service, "list_jobs", {"hosts": sorted(hosts)}))
    except ConfigError as exc:
        return found, [f"any machine, so none was asked: {exc}", *unreachable]
    for name, host in sorted(hosts.items()):
        try:
            for job_id in await _sessions(service, host, authority):
                found.setdefault(owners.get(job_id, "unattributed"), []).append((name, job_id))
        except Exception as exc:  # report and go on: one host down must not hide the others
            unreachable.append(f"{name}: {exc}")
    return found, unreachable


async def _kill(service: Service, targets: list[tuple[str, str]], run_id: str) -> list[str]:
    """Kill each (host, job id), its logins signed for the record `run_id`;
    return one line per job saying what happened."""
    hosts, _ = machines(service)
    authority = CertificateAuthority(service.ssh_ca)
    certs.acting_for(None, run_id)
    lines = []
    for name, job_id in targets:
        if name not in hosts:  # listed a moment ago, and removed from nervus since
            lines.append(f"  {name} {job_id}: NOT STOPPED: nervus no longer has this machine")
            continue
        conn = await _connect(service, hosts[name], authority)
        try:
            await jobs.kill_job(conn, job_id)
            still = await conn.run(f"tmux has-session -t nervus-{job_id} 2>/dev/null")
        finally:
            conn.close()
        lines.append(f"  {name} {job_id}: {'STILL RUNNING' if still.exit_status == 0 else 'stopped'}")
    return lines


# Run in a child process by database_change. It prints one JSON object: the
# outcome, or the reason the change failed.
_DATABASE_CHANGE = """
import json, sys
from pathlib import Path
from nervus.database import Database, DatabaseUnusable
db = Database(Path(sys.argv[1]))
try:
    if sys.argv[2] == "make_link":
        value, expires = db.make_link()
        print(json.dumps({"value": value, "expires": expires}))
    elif sys.argv[2] == "sign_out_all":
        print(json.dumps({"ended": db.sign_out_all()}))
    elif sys.argv[2] == "issued_tokens":
        print(json.dumps({"tokens": [{"id": i.token.id, "client": i.token.client, "project": i.token.project}
                                     for i in db.issued_tokens()]}))
    elif sys.argv[2] == "tier":
        from nervus.first_run import FirstRun
        tier = FirstRun(db).tier()
        print(json.dumps({"tier": None if tier is None else tier.tier}))
    elif sys.argv[2] == "make":
        db.open()
        print(json.dumps({}))
    elif sys.argv[2] == "backup_events":
        with db.transaction(write=False) as c:
            rows = c.execute("SELECT kind, file, made_at, at FROM backup_event ORDER BY at").fetchall()
        print(json.dumps({"events": rows}))
    elif sys.argv[2] in ("backup_event", "restored"):
        event = json.loads(sys.argv[3])
        with db.transaction() as c:
            if sys.argv[2] == "restored":
                from nervus.restore import CLEAR_SHORT_LIVED
                for statement in CLEAR_SHORT_LIVED.split(";"):
                    if statement.strip():
                        c.execute(statement)
            c.execute("INSERT INTO backup_event (kind, file, made_at, at) VALUES (?, ?, ?, ?)",
                      (event["kind"], event["file"], event.get("made_at"), event["at"]))
        print(json.dumps({}))
    elif sys.argv[2] == "machines":
        from nervus.enrolled_hosts import EnrolledHostStore
        from nervus.enrollments import EnrollmentStore
        print(json.dumps({
            "hosts": [{"name": h.name, "address": h.address, "level": h.level, "host_keys": list(h.host_keys)}
                      for h in EnrolledHostStore(db).all()],
            "vms": [{"vmid": v.vmid, "address": v.address, "host_keys": list(v.host_keys)}
                    for v in EnrollmentStore(db).all()]}))
    elif sys.argv[2] == "identity":
        with db.transaction(write=False) as c:
            row = c.execute("SELECT ssh_key, ssh_ca_key, tls_issuer FROM identity").fetchone()
        print(json.dumps({"identity": row}))
    elif sys.argv[2] == "accept_keys":
        found = json.loads(sys.argv[3])
        with db.transaction() as c:
            c.execute("INSERT OR REPLACE INTO identity (only, ssh_key, ssh_ca_key, tls_issuer, recorded_at) "
                      "VALUES (1, ?, ?, ?, ?)", (found["ssh_key"], found["ssh_ca_key"], found["tls_issuer"], found["at"]))
        print(json.dumps({}))
except DatabaseUnusable as exc:
    print(json.dumps({"error": str(exc)}))
"""


_AUDIT_APPEND = """
import json, sys
from pathlib import Path
from nervus.audit import AuditError, AuditLog
request = json.loads(sys.stdin.read())
try:
    print(json.dumps({"id": AuditLog(path=Path(sys.argv[1])).record_operator(request["action"], request["fields"])}))
except AuditError as exc:
    print(json.dumps({"error": str(exc)}))
"""


def _as_account(service: Service, code: str, args: list[str], what: str, stdin: str = "") -> dict:
    """Run `code` in a child process that is the account nervus runs as, and
    nothing more: its user, its group, no other groups (ADR-0012 decision 3).
    Its answer is one JSON object on standard output.

    nervus-ctl runs as root. A file made as root, a database's companions or
    the audit log itself when it does not exist yet, would stay root's, and
    nervus could then not write it (the audit log's case found by procedure
    035, on a fresh install). Run by anyone else, the child is that same
    person, so the path is the same. It is isolated (-I) from the environment
    and from the current folder, which the account may not be able to read.
    """
    account = {}
    if os.geteuid() == 0 and service.user:
        try:
            entry = pwd.getpwnam(service.user)
        except KeyError as exc:
            raise ConfigError(f"nervus's unit runs it as {service.user!r}, which is not an account here") from exc
        account = {"user": entry.pw_uid, "group": entry.pw_gid, "extra_groups": []}
    done = subprocess.run(
        [sys.executable, "-I", "-c", code, *args],
        capture_output=True, text=True, cwd="/", input=stdin, **account,
    )
    try:
        outcome = json.loads(done.stdout)
    except ValueError:
        last = (done.stderr.strip().splitlines() or ["no output"])[-1]
        raise ConfigError(f"{what} failed: {last}") from None
    if "error" in outcome:
        raise ConfigError(outcome["error"])
    return outcome


def database_change(service: Service, action: str, *extra: str) -> dict:
    """Make one change to nervus's database, or read it, as the account
    nervus runs as (_as_account). The child never makes the database, but for
    `start-empty`'s "make": nervus does, when it starts."""
    return _as_account(service, _DATABASE_CHANGE, [str(service.database.absolute()), action, *extra],
                       f"the change to {service.database}")


def operator_record(service: Service, action: str, fields: dict) -> str:
    """Write an operator record to nervus's audit log (ADR-0003 decision 6), as
    the account nervus runs as (_as_account), so a log this makes is nervus's.
    Returns the record's id."""
    request = json.dumps({"action": action, "fields": fields})
    return _as_account(service, _AUDIT_APPEND, [str(service.audit_log.absolute())],
                       f"writing to {service.audit_log}", stdin=request)["id"]


def issued_tokens(service: Service) -> tuple[list[dict], str | None]:
    """The tokens issued in the UI (ADR-0014 decision C), or none and why they
    could not be read, such as a database nervus has not made yet."""
    try:
        return database_change(service, "issued_tokens")["tokens"], None
    except ConfigError as exc:
        return [], str(exc)


def tier_line(service: Service) -> str:
    """The tier declared at first-run setup (ADR-0015 decision E), in one
    line, or why it could not be read."""
    try:
        tier = database_change(service, "tier")["tier"]
    except ConfigError as exc:
        return f"tier unknown: {exc}"
    return "tier: not chosen yet; choose it on the web UI's setup page" if tier is None else f"tier: {TIER_WORDS[tier]}"


def signin(service: Service, out) -> int:
    """ADR-0012 decisions 4, 6 and 7a: a link that signs a browser in once,
    within 5 minutes, and what to check the browser's warning against."""
    if not service.ui_url:
        print("nervus-ctl: nervus's unit gives no --ui-url, so there is no address to sign in at. "
              "Add the address browsers use, such as --ui-url https://<name>:8443, to its ExecStart, "
              "in a drop-in of the installation's own",
              file=out)
        return 1
    certificate = None
    if service.ui_url.startswith("https://"):
        # Read before a link exists: with no fingerprint there is nothing to
        # check the browser's warning against, so no link is made.
        # The file nervus serves: its renewal, once there is one (ADR-0021 D1).
        served = serving_path(service.tls_cert, service.tls_renewed)
        try:
            certificate = certificate_fingerprint(plainfile.read_bytes(served))
        except (OSError, ConfigError) as exc:
            print(f"nervus-ctl: cannot read the UI's certificate {served}: {exc}. Without it "
                  "there is nothing to check the browser's warning against, so no link was made. "
                  "nervus also cannot serve the UI without it", file=out)
            return 1
    made = database_change(service, "make_link")
    # A link is printed only once its making is in the audit log. If that write
    # fails, the link exists but nobody has it, and it expires unused.
    operator_record(service, "signin", {"link": audit_id(made["value"]), "expires": made["expires"]})
    until = time.strftime("%H:%M:%S UTC", time.gmtime(made["expires"]))
    print(f"Sign in once, by {until} ({LINK_SECONDS // 60} minutes from now):\n\n"
          f"  {service.ui_url}/signin?link={made['value']}\n", file=out)
    if certificate is not None:
        print("If the browser warns that nobody vouches for nervus's certificate, accept it only if the "
              f"browser shows this fingerprint for it:\n\n  certificate SHA-256 {certificate}\n", file=out)
    return 0


def signout(service: Service, out) -> int:
    """ADR-0012 decision 5: end every browser's session."""
    ended = database_change(service, "sign_out_all")["ended"]
    operator_record(service, "signout", {"target": "all", "ended": ended})
    print(f"ended {ended} session{'' if ended == 1 else 's'}; every browser must sign in again", file=out)
    return 0


def _state(switches: Switches, token_id: str) -> str:
    if switches.lockdown:
        return "OFF (lockdown)"
    return "OFF" if token_id in switches.disabled else "on"


async def status(service: Service, out) -> int:
    tokens = load_tokens(service.tokens)
    # ADR-0029 question 2a: which release is installed, first. nervus-ctl is a
    # script of the venv nervus runs from, so its package's number is the
    # installed release's.
    print(f"release: {nervus.__version__}", file=out)
    try:
        switches = load_switches(service.switches)
        print(f"switches: {service.switches}" + ("  LOCKDOWN: every client is off" if switches.lockdown else ""), file=out)
    except SwitchesUnreadable as exc:
        switches = None
        print(f"switches: UNREADABLE, so every client is refused: {exc}", file=out)
    print(tier_line(service), file=out)
    found, unreachable = await running_jobs(service)
    issued, why = issued_tokens(service)
    every = [(t.id, t.client, t.project, "") for t in tokens.values()]
    every += [(t["id"], t["client"], t["project"], "  issued in the UI") for t in issued]
    for token_id, client, project, where in sorted(every):
        state = "OFF (switches unreadable)" if switches is None else _state(switches, token_id)
        running = found.get(token_id, [])
        print(f"{token_id:30} {state:16} {client}/{project}  jobs: {len(running)}{where}", file=out)
        for host, job_id in running:
            print(f"    {host} {job_id}", file=out)
    if why is not None:
        print(f"issued tokens unknown: {why}", file=out)
    for host, job_id in found.get("unattributed", []):
        print(f"unattributed job: {host} {job_id}", file=out)
    for line in unreachable:
        print(f"could not read jobs on {line}", file=out)
    for line in backup_lines(service):
        print(line, file=out)
    return 0


async def lock(service: Service, target: str | None, kill_work: bool, yes: bool, out, ask) -> int:
    switches = load_switches(service.switches)  # unreadable: refuse, the operator fixes it by hand
    tokens = {t.id for t in load_tokens(service.tokens).values()}
    issued, why = issued_tokens(service) if target is not None and target not in tokens else ([], None)
    tokens |= {t["id"] for t in issued}
    if target is not None and target not in tokens:
        print(f"nervus-ctl: no token {target!r}; tokens are {', '.join(sorted(tokens))}"
              + (f" (issued tokens unknown: {why})" if why else ""), file=out)
        return 1

    to_kill: list[tuple[str, str]] = []
    if kill_work:
        found, unreachable = await running_jobs(service)
        to_kill = [j for owner, js in found.items() if target is None or owner == target for j in js]
        print(f"Stopping work cannot be undone. Jobs to stop: {len(to_kill)}", file=out)
        for host, job_id in to_kill:
            print(f"  {host} {job_id}", file=out)
        for line in unreachable:
            print(f"  could not read jobs on {line}", file=out)
        if to_kill and not yes:
            word = target or "all"
            if ask(f"Type {word!r} to switch off and stop these jobs: ") != word:
                print("nervus-ctl: not confirmed; nothing changed", file=out)
                return 1

    # Changed under the lock the UI also takes (ADR-0014), from the file as it is
    # then, not as it was read above: the UI may have changed it meanwhile.
    change_switches(service.switches, lambda now: (
        Switches(lockdown=True, disabled=now.disabled) if target is None
        else Switches(lockdown=now.lockdown, disabled=now.disabled | {target})))
    locked = operator_record(service, "lock", {"target": target or "all", "kill_work": kill_work})
    print(f"{'lockdown on: every client' if target is None else target} is now refused on its next call", file=out)

    if to_kill:
        lines = await _kill(service, to_kill, locked)  # signed for the lock that asked for it
        print("\n".join(lines), file=out)
        operator_record(service, "kill_work", {"target": target or "all", "jobs": [f"{h}/{j}" for h, j in to_kill],
                                               "outcome": lines, **certs.ssh_ports()})
        print("A process that detached itself from its job's session can survive this. On a host where "
              "nervus's account has sudo, `sudo -n pkill -u <account>` is the blunt instrument.", file=out)
    return 0


async def unlock(service: Service, target: str | None, out) -> int:
    def lifted(now: Switches) -> Switches:
        if target is None:
            return Switches(lockdown=False, disabled=now.disabled)
        if target in now.disabled:
            return Switches(lockdown=now.lockdown, disabled=now.disabled - {target})
        raise _NotOff()

    try:
        new = change_switches(service.switches, lifted)
    except _NotOff:
        print(f"nervus-ctl: {target!r} is not switched off one by one; nothing changed", file=out)
        return 1
    operator_record(service, "unlock", {"target": target or "all"})
    if target is None:
        still = sorted(new.disabled)
        print("lockdown off" + (f"; still off one by one: {', '.join(still)}" if still else ""), file=out)
    else:
        print(f"{target} is on again" + (", but lockdown is on, so it is still refused" if new.lockdown else ""), file=out)
    return 0


class _NotOff(Exception):
    """unlock was given a client that is not switched off; nothing is written."""


# --- backups (ADR-0027) ------------------------------------------------------------

# Run in a child process, as nervus's account, by backup(). It prints one JSON
# object: the backup made, or why none was.
_BACKUP = """
import json, sys, time
from pathlib import Path
from nervus.audit import AuditLog
from nervus.backup import BackupFailed, Pieces, made_at, make_backup
from nervus.database import Database, DatabaseUnusable
request = json.loads(sys.stdin.read())
given = request["pieces"]
pieces = Pieces(**{role: None if path is None else Path(path) for role, path in given.items() if role != "drop_ins"},
                drop_ins=tuple(Path(path) for path in given["drop_ins"]))
try:
    made = make_backup(pieces, request["recipient"], Path(request["folder"]), AuditLog(path=Path(request["audit_log"])))
except BackupFailed as exc:
    print(json.dumps({"error": str(exc)}))
    sys.exit()
outcome = {"file": str(made.path), "size": made.size, "sha256": made.sha256, "removed": made.removed}
try:
    with Database(Path(request["database"])).transaction() as db:
        db.execute("INSERT INTO backup_event (kind, file, made_at, at) VALUES ('made', ?, ?, ?)",
                   (made.path.name, made_at(made.path.name).timestamp(), time.time()))
except DatabaseUnusable as exc:
    outcome["unrecorded"] = str(exc)
print(json.dumps(outcome))
"""

SECRET_PROMPT = "The recovery key's private half (AGE-SECRET-KEY-1…), pasted; it is not shown or saved: "


def read_secret(prompt: str) -> str:
    """The recovery key, read as getpass reads it: from the terminal whenever
    there is one, not shown, even with something piped in (procedure 047,
    finding 2). Where there is none, from standard input, as getpass does then,
    but without its warning that the key "may be echoed": with no terminal there
    is nothing to echo it to, and a person told so would think it had leaked
    (procedure 054, finding 4)."""
    try:
        os.close(os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY))
    except OSError:
        print(prompt, end="", file=sys.stderr, flush=True)
        line = sys.stdin.readline()
        print(file=sys.stderr, flush=True)
        if not line:
            raise EOFError
        return line.removesuffix("\n")
    return getpass.getpass(prompt)


def _owner(service: Service) -> tuple[int, int] | None:
    """(uid, gid) of nervus's account, when nervus-ctl runs as root and can give
    files to it; otherwise None, and files stay the caller's."""
    if os.geteuid() != 0 or not service.user:
        return None
    try:
        entry = pwd.getpwnam(service.user)
    except KeyError as exc:
        raise ConfigError(f"nervus's unit runs it as {service.user!r}, which is not an account here") from exc
    return entry.pw_uid, entry.pw_gid


def _systemctl(*args: str) -> None:
    done = subprocess.run(["systemctl", *args], capture_output=True, text=True)
    if done.returncode != 0:
        raise ConfigError(f"systemctl {' '.join(args)} failed: {(done.stderr or done.stdout).strip()}")


def _when(timestamp: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(timestamp))


def _backup_path(service: Service, file: str) -> Path:
    """A backup named by its path, or by its name in the backup folder."""
    path = Path(file)
    if path.exists() or "/" in file:
        return path.absolute()
    return restore.backups_folder(service) / file


def backup(service: Service, out) -> int:
    """Question 4: one backup, as nervus's account, then the keeping."""
    key = recipient(service.recovery_key)
    pieces = restore.pieces(service)
    request = {
        "pieces": {f.name: (None if (v := getattr(pieces, f.name)) is None else
                            [str(p) for p in v] if f.name == "drop_ins" else str(v))
                   for f in dataclasses.fields(pieces)},
        "recipient": key, "folder": str(restore.backups_folder(service)),
        "audit_log": str(service.audit_log), "database": str(service.database),
    }
    made = _as_account(service, _BACKUP, [], "the backup", stdin=json.dumps(request))
    print(f"made {made['file']} ({made['size'] / 1e6:.1f} MB), locked to the recovery key {key[:16]}…", file=out)
    for name in made["removed"]:
        print(f"  removed {name}, no longer kept", file=out)
    if "unrecorded" in made:
        print(f"  (when it was made is not in nervus's database: {made['unrecorded']})", file=out)
    return 0


def backup_check(service: Service, file: str, out, secret) -> int:
    """Question 7a's check: the recovery key opens the backup, it passes
    question 5's checks, and its audit log is the start of the live one. It
    changes nothing but its own record."""
    path = _backup_path(service, file)
    identity_text = secret(SECRET_PROMPT)
    try:
        opened = restore.open_backup(path, identity_text)
        restore.check_contents(opened)
        if not restore.log_begins_with(service.audit_log, opened.log_size, opened.log_sha256):
            raise restore.BackupRefused(
                f"its audit log is not the start of {service.audit_log}: it is not a backup of this nervus, "
                "or this nervus's log has been changed since it was made")
    except restore.BackupRefused as exc:
        operator_record(service, "backup_check", {"file": path.name, "passed": False, "reason": str(exc)})
        print(f"nervus-ctl: the check FAILED: {exc}", file=out)
        return 1
    operator_record(service, "backup_check", {"file": path.name, "passed": True, "made_at": opened.made_at})
    database_change(service, "backup_event", json.dumps(
        {"kind": "checked", "file": path.name, "made_at": opened.made_at, "at": time.time()}))
    print(f"the check passed: {path.name}, made {_when(opened.made_at)}, opens with this recovery key, is whole, "
          "and its audit log is the start of this nervus's", file=out)
    return 0


def restore_backup(service: Service, file: str, yes: bool, out, ask, secret) -> int:
    """Question 5a: check first, then stop nervus, keep what is replaced, put
    the backup in place, clear what is short-lived, lockdown, start."""
    path = _backup_path(service, file)
    identity_text = secret(SECRET_PROMPT)
    stage = service.audit_log.with_name(f".{service.audit_log.name}.{os.urandom(8).hex()}.restore")
    try:
        opened = restore.open_backup(path, identity_text, stage_log=stage)
        restore.check_contents(opened)
        plan = restore.destinations(opened, service)
        restore.check_places(opened, service)
    except restore.BackupRefused as exc:
        stage.unlink(missing_ok=True)
        print(f"nervus-ctl: {exc}. Nothing changed", file=out)
        return 1
    print(f"Restoring {path.name}, made {_when(opened.made_at)} by nervus {opened.manifest.get('nervus')}.", file=out)
    print("These files are replaced (what is there now is kept in a dated folder beside the database):", file=out)
    for dest in sorted(set(plan.values()) | {service.audit_log}, key=str):
        print(f"  {dest}", file=out)
    print("nervus stops, then starts again in lockdown, acting for no client until you lift it. "
          "Machines enrolled and tokens issued after the backup was made are not in it.", file=out)
    if not yes and ask("Type 'restore' to go ahead: ") != "restore":
        stage.unlink(missing_ok=True)
        print("nervus-ctl: not confirmed; nothing changed", file=out)
        return 1
    try:
        _systemctl("stop", "nervus")
    except ConfigError as exc:
        stage.unlink(missing_ok=True)
        print(f"nervus-ctl: {exc}. Nothing changed", file=out)
        return 1
    try:
        placed = restore.place(opened, service, _owner(service))
    except restore.BackupRefused as exc:
        # Refused while making the folder that keeps what is replaced, before anything moved.
        stage.unlink(missing_ok=True)
        _systemctl("start", "nervus")
        print(f"nervus-ctl: {exc}. Nothing was replaced; nervus is started again", file=out)
        return 1
    database_change(service, "restored", json.dumps(
        {"kind": "restored", "file": path.name, "made_at": opened.made_at, "at": time.time()}))
    operator_record(service, "restored", {"file": path.name, "made_at": opened.made_at,
                                          "nervus": opened.manifest.get("nervus"), "replaced": str(placed.replaced),
                                          "kept_log": placed.kept_log})
    _systemctl("start", "nervus")
    print(f"restored. What it replaced is in {placed.replaced}.", file=out)
    if placed.kept_log:
        print("The audit log here already began with the backup's, so it was kept whole.", file=out)
    for name in placed.drop_ins_differ:
        print(f"This installation's drop-in {name} differs from the backup's, and was kept; the backup's is in "
              f"{placed.replaced / 'backup-drop-ins' / name}.", file=out)
    print("Lockdown is on. Once you have looked, lift it with: nervus-ctl unlock --all", file=out)
    return 0


def recovery_key(service: Service, replace: bool, out) -> int:
    """Question 2a: a recovery key pair. nervus keeps the public half; the
    private half is printed once, here, and never written to a file."""
    path = service.recovery_key
    if path.exists() and not replace:
        print(f"nervus-ctl: there is a recovery key already ({path}). To make a new one, give --replace: backups "
              "already made stay locked to the old key, so keep it as long as you keep them", file=out)
        return 1
    keygen = shutil.which("age-keygen")
    if keygen is None:
        print("nervus-ctl: age is not installed, so no recovery key can be made", file=out)
        return 1
    made = subprocess.run([keygen], capture_output=True, text=True)
    lines = made.stdout.splitlines()
    private = next((line for line in lines if line.startswith("AGE-SECRET-KEY-")), None)
    public = next((line.split(": ", 1)[1] for line in lines if line.startswith("# public key: ")), None)
    if made.returncode != 0 or private is None or public is None:
        print(f"nervus-ctl: age-keygen failed: {made.stderr.strip()}", file=out)
        return 1
    # An unpredictable staging name created with O_EXCL, like restore's writes, so a
    # symlink planted at a guessed name is never followed (procedure 056, C21 sibling).
    fd, staging_name = tempfile.mkstemp(dir=path.parent, prefix="." + path.name + ".", suffix=".new")
    staging = Path(staging_name)
    try:
        os.write(fd, (public + "\n").encode())
        os.fchmod(fd, 0o600)
        if (owner := _owner(service)) is not None:
            os.fchown(fd, *owner)
    finally:
        os.close(fd)
    try:
        operator_record(service, "recovery_key", {"public": public, "replaced": path.exists()})
    except ConfigError:
        staging.unlink(missing_ok=True)
        raise
    os.replace(staging, path)
    print(f"A new recovery key. nervus keeps its public half, {public}, in {path}, and locks every backup to it.\n\n"
          "Its private half opens every backup, and nothing else does. It is shown this once and kept nowhere on "
          "this machine. Keep it in a password manager or on paper, never on this machine or one a client reaches:\n\n"
          f"  {private}\n", file=out)
    if replace:
        print("Backups made before this stay locked to the old key.", file=out)
    return 0


def start_empty(service: Service, out, ask) -> int:
    """Question 6: start with an empty database, or a new audit log, on
    purpose, where nervus refuses to start without one."""
    if not service.database.exists() and identity.has_records(service.audit_log):
        made, what = "database", f"an empty database at {service.database}: every machine and every token issued " \
                                 "in the UI is forgotten"
    elif service.database.exists() and not identity.has_records(service.audit_log) \
            and identity.recorded(service.database):
        made, what = "audit_log", f"a new audit log at {service.audit_log}: the record of everything before is gone"
    else:
        print("nervus-ctl: nothing is missing, so nervus can start as it is; nothing changed", file=out)
        return 1
    print(f"This starts {what}. Restoring a backup (nervus-ctl restore) is the other way.", file=out)
    if ask("Type 'start-empty' to go ahead: ") != "start-empty":
        print("nervus-ctl: not confirmed; nothing changed", file=out)
        return 1
    # The record first: of the new log, its first.
    operator_record(service, "start_empty", {"made": made})
    if made == "database":
        database_change(service, "make")
    print(f"done. nervus starts at its next try, or now with: systemctl restart nervus", file=out)
    return 0


def accept_keys(service: Service, out, ask) -> int:
    """Question 6, as the operator added it: a key replaced on purpose,
    accepted as nervus's own."""
    issuer = service.tls_issuer if service.tls_issuer is not None and service.tls_issuer.exists() else None
    found = identity.fingerprints(identity.Keys(ssh_key=service.ssh_key, ssh_ca_key=service.ssh_ca, tls_issuer=issuer))
    row = database_change(service, "identity")["identity"]
    if row is None:
        print("nervus has not recorded its keys yet; it does at its next start. Nothing changed", file=out)
        return 0
    was = dict(zip(identity.ROLES, row))
    differ = [role for role in identity.ROLES
              if was[role] != found[role] and not (role == "tls_issuer" and was[role] is None)]
    if not differ:
        print("every key is the one nervus recorded; nothing changed", file=out)
        return 0
    for role in differ:
        print(f"{identity.WORDS[role]}: recorded {was[role]}, now {found[role] or 'missing'}.\n"
              f"  Replacing it {identity.COST[role]}.", file=out)
    typed = ask(f"Type the name of each key replaced on purpose ({' '.join(differ)}): ").split()
    if sorted(typed) != sorted(differ):
        print("nervus-ctl: not confirmed; nothing changed", file=out)
        return 1
    operator_record(service, "accept_keys", {role: {"was": was[role], "now": found[role]} for role in differ})
    database_change(service, "accept_keys", json.dumps({**found, "at": time.time()}))
    print("recorded: nervus starts with these keys", file=out)
    return 0


# What an upgrade records, and a release's name as its folder has it (ADR-0029 question 3a).
# "down": the run ended with nervus up on neither release. The first three are every release's; "down"
# came after them, and an installer writes each record with the nervus-ctl of the release current at
# that moment, so it is ready to have the word refused by an older one (install.sh, record_down).
UPGRADE_STAGES = ("begin", "up", "back", "down")
RELEASE_NAME = re.compile(r"(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*)){2}-[0-9a-f]{12}")


def upgrade_record(service: Service, stage: str, was: str, now: str, why: str | None, out) -> int:
    """ADR-0029, "Settled already": an upgrade's start, its end and its going
    back are operator records, and an upgrade whose first record cannot be
    written does not begin (ADR-0001 s10). install.sh --upgrade writes each
    with the nervus-ctl of the release running then, so a later release's
    installer calls an earlier release's: its arguments keep this shape.
    Its end with nervus down on both releases is one too, written with
    nervus stopped, as each of these can be."""
    for release in (was, now):
        if not RELEASE_NAME.fullmatch(release):
            print(f"nervus-ctl: {release!r} is not a release's name, such as 0.0.0-42c0b5a132ef; nothing recorded",
                  file=out)
            return 1
    operator_record(service, "upgrade", {"stage": stage, "from": was, "to": now, **({"why": why} if why else {})})
    print(f"recorded: the upgrade from {was} to {now}, {stage}", file=out)
    return 0


# Run in a child process by upgrade_backup, as nervus's account, whose folder the backups are in. It
# prints one JSON object: what was kept or removed, or why not.
_KEPT_BACKUP = """
import json, sys
from pathlib import Path
from nervus.backup import BackupFailed, drop_kept_for, keep_for_upgrade, only_kept_for
request = json.loads(sys.stdin.read())
folder = Path(request["folder"])
try:
    if request["stage"] == "keep":
        kept_as = keep_for_upgrade(folder, request["file"], request["release"]).name
        # What an earlier try at this upgrade kept is superseded by this one.
        print(json.dumps({"kept_as": kept_as, "removed": drop_kept_for(folder, request["release"], but=kept_as)}))
    elif request["stage"] == "only":
        print(json.dumps({"removed": only_kept_for(folder, request["release"])}))
    else:
        print(json.dumps({"removed": drop_kept_for(folder, request["release"])}))
except (BackupFailed, OSError) as exc:
    print(json.dumps({"error": str(exc)}))
"""

KEPT_STAGES = ("keep", "only", "drop")


def upgrade_backup(service: Service, stage: str, release: str, file: str | None, out) -> int:
    """ADR-0029 step 7: the backup made before an upgrade to `release`, kept
    apart from the daily keeping until the next upgrade comes up. install.sh
    --upgrade asks for each stage, with the nervus-ctl of the release it has
    built: `keep`, before nervus is stopped, gives that backup a second name
    the daily keeping never removes; `only`, once nervus is up on the release,
    removes the backups kept for earlier upgrades; `drop`, when the upgrade
    went back, removes the one kept for it. Each is done as nervus's account,
    and is an operator record: a keeping whose record cannot be written does
    not happen (ADR-0001 s10); what was removed is recorded after."""
    folder = restore.backups_folder(service)
    if not RELEASE_NAME.fullmatch(release):
        print(f"nervus-ctl: {release!r} is not a release's name, such as 0.0.0-42c0b5a132ef; nothing changed", file=out)
        return 1
    request = {"stage": stage, "release": release, "folder": str(folder)}
    if stage != "keep":
        if file is not None:
            print(f"nervus-ctl: upgrade-backup {stage} takes a release alone; nothing changed", file=out)
            return 1
        removed = _as_account(service, _KEPT_BACKUP, [], "removing kept backups", stdin=json.dumps(request))["removed"]
        if removed:
            operator_record(service, "upgrade_backup", {"stage": stage, "before": release, "removed": removed})
        for name in removed:
            print(f"removed {name}, kept for another upgrade", file=out)
        return 0
    if file is None:
        print("nervus-ctl: keep needs the backup to keep: upgrade-backup keep <release> <backup>; nothing changed",
              file=out)
        return 1
    name = Path(file).name
    if "/" in file and os.path.realpath(Path(file).parent) != os.path.realpath(folder):
        print(f"nervus-ctl: {file} is not in nervus's backup folder, {folder}; nothing changed", file=out)
        return 1
    kept_as = kept_name(name, release)
    record = operator_record(service, "upgrade_backup", {"stage": "keep", "before": release, "file": name,
                                                         "kept_as": kept_as})
    try:
        done = _as_account(service, _KEPT_BACKUP, [], "keeping the backup", stdin=json.dumps({**request, "file": name}))
    except ConfigError as exc:
        with contextlib.suppress(ConfigError):
            operator_record(service, "upgrade_backup", {"stage": "keep_failed", "before": release, "file": name,
                                                        "keep_record": record, "reason": str(exc)})
        raise
    print(f"kept {name} as {kept_as}, until the upgrade after the one to {release}", file=out)
    if done["removed"]:
        operator_record(service, "upgrade_backup", {"stage": "superseded", "before": release, "removed": done["removed"]})
    for gone in done["removed"]:
        print(f"removed {gone}, kept by an earlier try at this upgrade", file=out)
    return 0


def backup_lines(service: Service) -> list[str]:
    """What `status` says of backups (question 4 and 7a)."""
    folder = restore.backups_folder(service)
    listed = restore.listing(folder)
    backups = [b for b in listed if b.kept_before is None]
    lines = []
    if not service.recovery_key.exists():
        lines.append("WARNING: no recovery key, so no backup can be made: nervus-ctl recovery-key")
    if backups:
        hours = (time.time() - backups[0].made_at) / 3600
        lines.append(f"backups: {len(backups)} in {folder}, {sum(b.size for b in backups) / 1e6:.1f} MB; "
                     f"newest {backups[0].name}, {hours:.0f} hours old")
    for b in listed:
        if b.kept_before is not None:
            lines.append(f"kept from before the upgrade to {b.kept_before}, until the next: {b.name}")
    if warning := restore.stale(listed):
        lines.append(f"WARNING: {warning} Make one: nervus-ctl backup")
    try:
        events = database_change(service, "backup_events")["events"]
    except ConfigError as exc:
        return [*lines, f"backup checks unknown: {exc}"]
    lines.append(_last_check(events))
    if note := restore.restored_note(events):
        lines.append(note)
    return lines


def _last_check(events: list) -> str:
    checked = [e for e in events if e[0] == "checked"]
    return (f"last check passed {_when(checked[-1][3])}, of {checked[-1][1]}" if checked else
            "no backup has been checked: nervus-ctl backup --check <file>, with the recovery key")


def last_check(service: Service, out) -> int:
    """`backup --last-check`: when the recovery key last opened a backup, as
    status says it, and nothing more. install.sh --upgrade's plan says it
    (ADR-0029 question 4a) without status's asking every machine for its jobs.
    It changes nothing."""
    try:
        events = database_change(service, "backup_events")["events"]
    except ConfigError as exc:
        print(f"backup checks unknown: {exc}", file=out)
        return 1
    print(_last_check(events), file=out)
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nervus-ctl", description="nervus's off switch (ADR-0003), and signing in to its UI (ADR-0012).")
    parser.add_argument("--unit", type=Path, default=UNIT, help=f"nervus's unit file (default {UNIT})")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status", help="which release is installed, and every client: on or off, and its running jobs")
    for name in ("lock", "unlock"):
        p = sub.add_parser(name)
        which = p.add_mutually_exclusive_group(required=True)
        which.add_argument("token_id", nargs="?")
        which.add_argument("--all", action="store_true")
        if name == "lock":
            p.add_argument("--kill-work", action="store_true", help="also stop the jobs it has running")
            p.add_argument("--yes", action="store_true", help="do not ask before stopping jobs")
    sub.add_parser("signin", help="print a link that signs a browser in to the UI, once, within 5 minutes")
    p = sub.add_parser("signout", help="end every browser's UI session")
    p.add_argument("--all", action="store_true", required=True)
    p = sub.add_parser("backup", help="make a backup now, or check one with the recovery key")
    which = p.add_mutually_exclusive_group()
    which.add_argument("--check", metavar="FILE", help="open FILE with the recovery key and check it; changes nothing")
    which.add_argument("--last-check", action="store_true",
                       help="say when the recovery key last opened a backup; changes nothing")
    p = sub.add_parser("restore", help="put a backup in place, keeping what it replaces, and start in lockdown")
    p.add_argument("file")
    p.add_argument("--yes", action="store_true", help="do not ask before going ahead")
    p = sub.add_parser("recovery-key", help="make the recovery key pair; its private half is printed once")
    p.add_argument("--replace", action="store_true", help="replace the recovery key there is")
    sub.add_parser("start-empty", help="start with an empty database, or a new audit log, on purpose")
    sub.add_parser("accept-keys", help="accept a key of nervus's replaced on purpose")
    p = sub.add_parser("upgrade-record", help="record an upgrade's start, its end, its going back, or that it "
                                              "left nervus down (install.sh --upgrade does)")
    p.add_argument("stage", choices=UPGRADE_STAGES)
    p.add_argument("was", metavar="FROM", help="the release upgraded from, as its folder is named")
    p.add_argument("now", metavar="TO", help="the release upgraded to")
    p.add_argument("--why", help="why it went back, or is down")
    p = sub.add_parser("upgrade-backup", help="keep the backup made before an upgrade until the next one, or remove "
                                              "those kept for other upgrades (install.sh --upgrade does)")
    p.add_argument("stage", choices=KEPT_STAGES)
    p.add_argument("release", metavar="RELEASE", help="the release upgraded to, as its folder is named")
    p.add_argument("file", metavar="BACKUP", nargs="?", help="for keep: the backup made before the upgrade")
    return parser


async def run(argv: list[str], out=sys.stdout, ask=input, secret=read_secret) -> int:
    args = _parser().parse_args(argv)
    try:
        service = read_unit(args.unit)
        if args.command == "status":
            return await status(service, out)
        if args.command == "backup":
            if args.last_check:
                return last_check(service, out)
            return backup_check(service, args.check, out, secret) if args.check else backup(service, out)
        if args.command == "restore":
            return restore_backup(service, args.file, args.yes, out, ask, secret)
        if args.command == "recovery-key":
            return recovery_key(service, args.replace, out)
        if args.command == "start-empty":
            return start_empty(service, out, ask)
        if args.command == "accept-keys":
            return accept_keys(service, out, ask)
        if args.command == "upgrade-record":
            return upgrade_record(service, args.stage, args.was, args.now, args.why, out)
        if args.command == "upgrade-backup":
            return upgrade_backup(service, args.stage, args.release, args.file, out)
        if args.command == "signin":
            return signin(service, out)
        if args.command == "signout":
            return signout(service, out)
        target = None if args.all else args.token_id
        if args.command == "lock":
            if args.kill_work and not args.yes and not sys.stdin.isatty() and ask is input:
                print("nervus-ctl: --kill-work without a terminal needs --yes", file=out)
                return 1
            return await lock(service, target, args.kill_work, args.yes, out, ask)
        return await unlock(service, target, out)
    except SwitchesSwapped as exc:
        print(f"nervus-ctl: {exc}", file=out)
        return 1
    except SwitchesUnreadable as exc:
        print(f"nervus-ctl: the switches file is unreadable, so every client is refused: {exc}\n"
              "Fix it by hand; a valid file is:\n  lockdown: false\n  disabled: []", file=out)
        return 1
    except ConfigError as exc:
        print(f"nervus-ctl: {exc}", file=out)
        return 1


def main() -> int:
    return asyncio.run(run(sys.argv[1:]))
