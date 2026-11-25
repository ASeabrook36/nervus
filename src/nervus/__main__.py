from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import os
import re
import signal
import sys
import urllib.parse
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

import anyio
import uvicorn
from uvicorn.protocols.http.auto import AutoHTTPProtocol

from nervus import ctl, identity, plainfile, restore
from nervus.audit import AuditLog
from nervus.auth import Tokens, load_tokens
from nervus.certs import CertificateAuthority
from nervus.config import ConfigError, Settings, hypervisor_host, load_hosts, never_issued, require_private_file
from nervus.database import Database, DatabaseUnusable
from nervus.enroller import Enroller, ssh_connector
from nervus.ssh import public_words
from nervus.enrollments import EnrollmentStore
from nervus.accounts import MachineAccounts, accounts_at, described
from nervus.enrolled_hosts import EnrolledHostStore, merged
from nervus.enrollment_codes import EnrollmentCodes
from nervus.host_enrollment import HostEnrollment, own_machine_id
from nervus.laptop import LaptopRoute
from nervus.host_login import LoginEnrollment
from nervus.export_sources import VM_RESPONSE_BYTES
from nervus.exporter import Exporter
from nervus.exposure import check as check_exposure
from nervus.first_run import TIER_WORDS, FirstRun
from nervus.exports import ExportStore
from nervus.upload_targets import Deliveries, HostDelivery, VMDelivery
from nervus.uploader import Uploader
from nervus.uploads import UploadStore
from nervus.vm_targets import VMTargets
from nervus.proxmox import ProxmoxClient, load_config
from nervus.server import build_server, connect_host
from nervus.switches import SwitchesUnreadable, load_switches, locked
from nervus.token_codes import TokenCodes
from nervus.tls import (
    ServingCertificate,
    add_addresses,
    issuer_key_path,
    machine_addresses,
    certificate_name,
    certificate_fingerprint,
    default_names,
    generate_own_authority,
    renewal_path,
    root_cert_path,
    upgrade_to_own_authority,
    is_loopback,
    key_file_fingerprint,
    key_file_pin,
    key_pin,
)
from nervus.ui import Backups, Machines, Management, Setup, build_ui


# How long a stop waits for open connections before closing them itself.
# Without a limit, one connection that never finishes holds nervus up until
# systemd kills it: the 2026-09-30 deploy waited 90 seconds on six such
# connections, then ended in SIGKILL (procedures/014).
SHUTDOWN_GRACE_SECONDS = 5
# Bound idle keep-alive and concurrent connections so a LAN peer (the unit binds
# every address) cannot hold the process's file descriptors open and deny both
# ports (procedure 056, C22). A home fleet never needs hundreds at once; beyond
# the cap uvicorn answers 503 and closes, rather than exhausting descriptors.
KEEP_ALIVE_SECONDS = 5
MAX_CONCURRENCY = 256


# nervus's own key and certificate: where `nervus tls-init` puts them, and
# where an off-loopback start looks for them, unless told otherwise. Beside
# the other secrets, as --tokens and --ssh-key default to.
DEFAULT_TLS_CERT = "secrets/tls.crt"
DEFAULT_TLS_KEY = "secrets/tls.key"


def uvicorn_config(
    mcp_server, host: str, port: int, certificate: ServingCertificate | None = None
) -> uvicorn.Config:
    """The web server MCPServer.run(transport="streamable-http") builds, plus a
    limit on how long a shutdown waits for connections.

    The library builds the same app and Config but offers no way to set
    timeout_graceful_shutdown, so this builds them itself. Every other setting
    is the library's default, as run_streamable_http_async passes it.

    Given a certificate, uvicorn serves HTTPS with the context nervus built
    from it (nervus.tls), through uvicorn's ssl_context_factory, which needs
    uvicorn 0.47 or later. Without one, nothing here differs from plain HTTP.
    """
    return _web_server_config(
        mcp_server.streamable_http_app(host=host), host, port, certificate,
        log_level=mcp_server.settings.log_level.lower(),
    )


def ui_uvicorn_config(
    app, host: str, port: int, certificate: ServingCertificate | None = None
) -> uvicorn.Config:
    """The UI's web server: as MCP's, with the same stop limit, but keeping no
    access log. A sign-in page's address holds its link, and the journal is no
    place for one (ADR-0012 decision 4). The audit records of decision 6 take
    the access log's place."""
    return _web_server_config(app, host, port, certificate, http=_NoAccessLog)


class _NoAccessLog(AutoHTTPProtocol):
    """uvicorn's own HTTP protocol, writing no access log line for its requests.

    uvicorn's access_log=False cannot do this: it empties the access logger
    every server in the process shares, so it would silence MCP's access log
    in the journal too. Each connection's protocol decides for itself, so the
    UI's server is given one that never logs.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.access_log = False


class _HideEnrollmentCodes(logging.Filter):
    """Writes `/enroll/<code>` in MCP's request log where a request's path
    held a one-time enrollment code, `/laptop/<code>` where it held a laptop's
    (ADR-0032: its line's GET is logged before its POST hands the token over,
    so a run stopped between them would leave a working code there), and
    every other line as it was.

    uvicorn logs each request line to the journal, and a code in it could be
    used by anyone who reads the journal before the machine reports
    (procedure 037, step 12). The audit records name a code by its id
    (ADR-0024). uvicorn's access logger passes the path as the third
    argument of its message.

    Whatever follows the code goes with it, a query as always and a slash or
    a further path too: `/enroll/<code>/`, which Starlette redirects to the
    path without the slash, once wrote the code whole (procedure 056)."""

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and len(args) >= 3 and isinstance(args[2], str):
            hidden = _CODE_PATH.sub(lambda found: f"/{found.group(1)}/<code>", args[2])
            if hidden != args[2]:
                record.args = (*args[:2], hidden, *args[3:])
        return True


_CODE_PATH = re.compile(r"^/(enroll|laptop)/.*", re.DOTALL)


def _web_server_config(
    app, host: str, port: int, certificate: ServingCertificate | None,
    log_level: str = "info", http: type | str = "auto",
) -> uvicorn.Config:
    tls = {}
    if certificate is not None:
        tls["ssl_context_factory"] = lambda config, default: certificate.listening_context()
    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level=log_level,
        http=http,
        timeout_graceful_shutdown=SHUTDOWN_GRACE_SECONDS,
        timeout_keep_alive=KEEP_ALIVE_SECONDS,
        limit_concurrency=MAX_CONCURRENCY,
        # nervus serves TLS itself, behind no proxy (ADR-0006), so no header names a request's address or
        # scheme. uvicorn believes X-Forwarded-For and -Proto from loopback unless told not to, which let a
        # local process choose the address the audit records (procedure 056).
        proxy_headers=False,
        **tls,
    )
    # After Config, which sets up uvicorn's loggers; once, for every server.
    access = logging.getLogger("uvicorn.access")
    if not any(isinstance(f, _HideEnrollmentCodes) for f in access.filters):
        access.addFilter(_HideEnrollmentCodes())
    return config


@dataclass(frozen=True)
class Listener:
    """One web server in the nervus process: MCP's, or the UI's, on a port of
    its own at the same address (ADR-0012 decision 1). Its configuration is
    built by serve(), so making a Listener loads and binds nothing."""

    name: str
    host: str
    port: int
    certificate: ServingCertificate | None
    config: Callable[[], uvicorn.Config]


class _Server(uvicorn.Server):
    """uvicorn's server, leaving stop signals to serve().

    Each uvicorn server takes SIGTERM and SIGINT for itself while it runs, and
    puts back what it found on its way out. Of two in one process, the second
    to start takes them from the first, so a stop reaches one server directly
    and the other only second-hand, and a second Ctrl-C forces only one to
    stop. serve() takes the signals once, for every server.
    """

    @contextlib.contextmanager
    def capture_signals(self):
        yield


def _console(line: str) -> None:
    print(f"nervus: {line}", file=sys.stderr, flush=True)


def serve(listeners: list[Listener], background: list[Callable[[], Awaitable[None]]] = ()) -> None:
    """Run every listener in this one process until it is told to stop, then
    stop them together, each within SHUTDOWN_GRACE_SECONDS. Work in
    `background`, such as the hourly sweep of expired exports, runs beside them
    and is cancelled when they stop.

    - SIGTERM or SIGINT asks every server to stop; a second asks them to stop
      at once. nervus then exits with status 0.
    - If one server stops by itself, the others are asked to stop too: nervus
      is one service, not two that share a process.
    - SIGHUP checks every certificate served now, instead of the signal's
      default, which stops the process. Daemons conventionally reload on
      SIGHUP, and certificate tools' renewal hooks send it (ADR-0010 decision 5).
    - Each certificate served is watched for a replacement (ADR-0006
      consequence 8), once, however many listeners serve it. The watches end
      when the servers do.
    - A start that cannot bind ends as uvicorn ends it, with exit status 3.
    """
    servers = [_Server(listener.config()) for listener in listeners]
    certificates = list({id(l.certificate): l.certificate for l in listeners if l.certificate}.values())

    def stop() -> None:
        for server in servers:
            if server.should_exit:
                server.force_exit = True
            server.should_exit = True

    def check_now() -> None:
        if not certificates:
            _console("on SIGHUP: serving plain HTTP, no certificate to check")
        for certificate in certificates:
            for line in certificate.check_now():
                _console(f"on SIGHUP: {line}")

    # uvicorn ends a start it cannot make, as when its port is taken, with
    # sys.exit(3). Caught here, so that the other servers stop in their own
    # time rather than being torn down mid-start, and raised once they have.
    failed: list[SystemExit] = []

    async def run_one(server: _Server) -> None:
        try:
            await server.serve()
        except SystemExit as exc:
            failed.append(exc)
        for other in servers:
            other.should_exit = True

    async def run() -> None:
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGHUP, check_now)
        for stop_signal in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(stop_signal, stop)
        async with anyio.create_task_group() as tasks:
            for certificate in certificates:
                tasks.start_soon(certificate.watch, _console)
            for work in background:
                tasks.start_soon(work)
            async with anyio.create_task_group() as serving:
                for server in servers:
                    serving.start_soon(run_one, server)
            tasks.cancel_scope.cancel()

    try:
        anyio.run(run)
    except BaseExceptionGroup as group:
        # anyio wraps whatever leaves a task group. Unwrap a lone exception,
        # such as uvicorn's sys.exit(3) when it cannot bind, so that a start
        # fails as one server's would.
        exc = group
        while isinstance(exc, BaseExceptionGroup) and len(exc.exceptions) == 1:
            exc = exc.exceptions[0]
        if isinstance(exc, BaseExceptionGroup):
            raise
        raise exc from None
    if failed:
        raise failed[0]


def _default(env_var: str, fallback: str) -> str:
    return os.environ.get(env_var, fallback)


def _pull_url(text: str) -> str:
    """--upload-pull-url: where a VM fetches an upload from nervus (ADR-0020
    decision E): nervus's MCP port as the VM reaches it, ending /upload-pull.
    Plain HTTP is allowed, as for MCP itself: what crosses is one file and a
    secret good for one fetch of it."""
    if not text:
        return ""
    parts = urllib.parse.urlsplit(text)
    try:
        parts.port
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{text!r}: {exc}") from exc
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise argparse.ArgumentTypeError(f"{text!r} is not an http:// or https:// address")
    if parts.query or parts.fragment or parts.username or parts.password:
        raise argparse.ArgumentTypeError(f"{text!r} has more than a scheme, host, port and path")
    if parts.path != "/upload-pull":
        raise argparse.ArgumentTypeError(f"{text!r} must end with nervus's pull route, /upload-pull")
    return text


def _ui_url(text: str) -> str:
    """--ui-url: the address browsers reach the UI at, which every sign-in link
    nervus-ctl prints points to (ADR-0012 decision 1).

    HTTPS, or plain HTTP on loopback only: off loopback the UI is never served
    over plain HTTP (ADR-0011 question B), so a link there would lead nowhere,
    or to whatever answers in its place. No query or fragment, since a link is
    this address followed by its own path, and no user name or password.
    """
    if not text:
        return ""
    parts = urllib.parse.urlsplit(text)
    try:
        parts.port  # raises for a port that is not one
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"{text!r}: {exc}") from exc
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise argparse.ArgumentTypeError(f"{text!r} is not an http:// or https:// address")
    if parts.query or parts.fragment or parts.username or parts.password:
        raise argparse.ArgumentTypeError(f"{text!r} has more than a scheme, host, port and path")
    if parts.scheme == "http" and not is_loopback(parts.hostname):
        raise argparse.ArgumentTypeError(
            f"{text!r}: off loopback the UI is reached only over HTTPS (ADR-0011 question B)"
        )
    return text.rstrip("/")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="nervus", description="MCP bastion for the operator's home fleet"
    )
    parser.add_argument(
        "--hosts", default=_default("NERVUS_HOSTS", "hosts.yaml"), help="Path to hosts.yaml"
    )
    parser.add_argument(
        "--tokens",
        default=_default("NERVUS_TOKENS", "secrets/tokens.yaml"),
        help="Path to the tokens file (must be 0600)",
    )
    parser.add_argument(
        "--known-hosts",
        default=_default("NERVUS_KNOWN_HOSTS", "secrets/known_hosts"),
        help="Path to the pinned known_hosts file",
    )
    parser.add_argument(
        "--ssh-key",
        default=_default("NERVUS_SSH_KEY", "secrets/nervus_ed25519"),
        help="Path to the agent SSH private key (must be 0600)",
    )
    parser.add_argument(
        "--ssh-ca-key",
        default=_default("NERVUS_SSH_CA_KEY", "secrets/nervus_ca_ed25519"),
        help=(
            "Path to nervus's SSH certificate authority key (must be 0600), which signs a "
            "certificate naming the client and the run for each connection (ADR-0025)"
        ),
    )
    parser.add_argument(
        "--audit-log",
        default=_default("NERVUS_AUDIT_LOG", "audit.jsonl"),
        help="Path to the append-only audit log",
    )
    parser.add_argument(
        "--switches",
        default=_default("NERVUS_SWITCHES", "secrets/switches.yaml"),
        help=(
            "Path to the off switch (ADR-0003): lockdown and disabled token ids, re-read "
            "on every request. Missing or malformed refuses every client."
        ),
    )
    parser.add_argument(
        "--database",
        default=_default("NERVUS_DATABASE", "nervus.db"),
        help=(
            "Path to nervus's database: what it writes while it runs, such as the "
            "operator's sign-in links and sessions (ADR-0011 decision 1, ADR-0012 decision 3)"
        ),
    )
    parser.add_argument(
        "--exports-dir",
        default=_default("NERVUS_EXPORTS_DIR", ""),
        help=(
            "Where exports wait to be downloaded (ADR-0016 decision E). Default: `exports` "
            "beside the database, which in the systemd unit is /var/lib/nervus/exports"
        ),
    )
    parser.add_argument(
        "--uploads-dir",
        default=_default("NERVUS_UPLOADS_DIR", ""),
        help=(
            "Where uploads wait to be delivered (ADR-0020 decision F). Default: `uploads` "
            "beside the database, which in the systemd unit is /var/lib/nervus/uploads"
        ),
    )
    parser.add_argument(
        "--upload-pull-url",
        type=_pull_url,
        default=_default("NERVUS_UPLOAD_PULL_URL", ""),
        help=(
            "The address a VM fetches an upload from, such as http://nervus.example:8000/upload-pull "
            "(ADR-0020 decision E). Without it, files are pushed into VMs through the guest agent, "
            "slowly and at most 32 MiB"
        ),
    )
    parser.add_argument(
        "--ui-url",
        type=_ui_url,
        default=_default("NERVUS_UI_URL", ""),  # argparse checks a string default with type, too
        help=(
            "The address browsers reach the UI at, such as https://nervus.example:8443. "
            "Sign-in links from `nervus-ctl signin` point here. HTTPS, or plain HTTP on "
            "loopback only"
        ),
    )
    parser.add_argument(
        "--transfer-dir",
        default=_default("NERVUS_TRANSFER_DIR", "transfer"),
        help="Directory put/get may read and write. Transfers outside it are refused.",
    )
    parser.add_argument(
        "--proxmox",
        default=_default("NERVUS_PROXMOX", ""),
        help=(
            "Path to the Proxmox API settings (must be 0600). Without it the "
            "proxmox tool is not offered (ADR-0009 decision 2)."
        ),
    )
    parser.add_argument(
        "--bind-host",
        default=_default("NERVUS_BIND_HOST", "127.0.0.1"),
        help="Address to bind the Streamable HTTP endpoint to",
    )
    parser.add_argument(
        "--bind-port",
        type=int,
        default=int(_default("NERVUS_BIND_PORT", "8000")),
        help="Port to bind the Streamable HTTP endpoint to",
    )
    parser.add_argument(
        "--ui-port",
        type=int,
        default=int(_default("NERVUS_UI_PORT", "8443")),
        help=(
            "Port the UI listens on, at the same address as MCP (ADR-0012 decision 1). "
            "Off loopback it serves only HTTPS, even with --insecure-plain-http"
        ),
    )
    parser.add_argument(
        "--tls-cert",
        default=_default("NERVUS_TLS_CERT", ""),
        help=(
            "Path to a TLS certificate, PEM, any chain after it, given with --tls-key. "
            "Off loopback, nervus serves HTTPS with these, or else with its own "
            f"({DEFAULT_TLS_CERT}, made once by `nervus tls-init`). On loopback, "
            "HTTPS only if these are given (ADR-0010 decision 1)."
        ),
    )
    parser.add_argument(
        "--tls-key",
        default=_default("NERVUS_TLS_KEY", ""),
        help="Path to the TLS certificate's private key (must be 0600)",
    )
    parser.add_argument(
        "--insecure-plain-http",
        action="store_true",
        help=(
            "Serve plain HTTP even off loopback, so that bearer tokens and every request "
            "cross the network unencrypted. Logged as a warning at every start "
            "(ADR-0010 decision 1)."
        ),
    )
    parser.add_argument(
        "--recovery-key",
        default=_default("NERVUS_RECOVERY_KEY", "secrets/recovery.pub"),
        help=(
            "Path to the recovery key's public half, which every backup is locked to "
            "(ADR-0027 question 2). nervus never holds the private half"
        ),
    )
    parser.add_argument(
        "--ssh-port",
        type=int,
        default=int(_default("NERVUS_SSH_PORT", "22")),
        help="SSH port used to reach every host",
    )
    return parser.parse_args(argv)


def tls_certificate(args: argparse.Namespace) -> ServingCertificate | None:
    """The certificate to serve HTTPS with, or None to serve plain HTTP.

    ADR-0010 decision 1: secure by default, insecure only by a named choice.
    - On loopback, plain HTTP unless --tls-cert and --tls-key are given.
    - Off loopback, HTTPS: with the files given, or else with nervus's own,
      made once by `nervus tls-init`. Without either, nervus refuses to start.
    - Plain HTTP off loopback only with --insecure-plain-http, which main()
      warns about at every start. The operator's instance runs that way on its
      LAN until it has a certificate (ADR-0006 decision 6), and its unit says so.
    """
    given = bool(args.tls_cert or args.tls_key)
    if args.insecure_plain_http:
        if given:
            raise ConfigError(
                "--insecure-plain-http contradicts --tls-cert and --tls-key; give one or the other"
            )
        return None
    if not given:
        if is_loopback(args.bind_host):
            return None
        args.tls_cert, args.tls_key = DEFAULT_TLS_CERT, DEFAULT_TLS_KEY  # nervus's own
    elif not (args.tls_cert and args.tls_key):
        raise ConfigError("give both --tls-cert and --tls-key, or neither")
    cert, key = Path(args.tls_cert), Path(args.tls_key)
    # Starting never makes a key (ADR-0010 decision 4): a missing file is an
    # error, never a sign of a first run. A container recreated without its
    # volume must stop here, not quietly take a new identity.
    missing = [str(p) for p in (cert, key) if not p.exists()]
    if missing:
        raise ConfigError(
            f"no TLS {' or '.join(missing)}. nervus never makes its key when it starts. "
            f"To make a key and certificate once, run: nervus tls-init --tls-cert {cert} "
            f"--tls-key {key}. If they existed before, the volume holding them was lost, "
            "and every connector paired with this nervus must be paired again"
            + ("" if given else
               f". Off loopback ({args.bind_host}) nervus serves only HTTPS unless started "
               "with --insecure-plain-http")
        )
    certificate = ServingCertificate(cert, key, _renewal(args, cert))
    certificate.load()
    return certificate


def served_key(args: argparse.Namespace) -> str | None:
    """The TLS key nervus serves with, MCP's or else the UI's, as tls_certificate
    and ui_certificate choose it, without reading any file; None when it serves
    plain HTTP alone. Beside it is nervus's own issuer, where it has one
    (ADR-0027 question 6), so nervus-ctl reads the same one nervus does."""
    if not args.insecure_plain_http and (args.tls_cert or args.tls_key):
        return args.tls_key or None
    return None if is_loopback(args.bind_host) else DEFAULT_TLS_KEY


def _renewal(args: argparse.Namespace, cert: Path) -> Path:
    """Where a renewal of `cert` is written, and served from once there:
    beside the database, in the state directory the unit makes writable
    (ADR-0021 D1), as exports are."""
    return renewal_path(cert, Path(args.database).parent)


def ui_certificate(
    args: argparse.Namespace, certificate: ServingCertificate | None
) -> ServingCertificate | None:
    """The certificate the UI serves with, or None to serve it over plain HTTP.

    ADR-0011 question B and ADR-0012 decision 1:
    - When MCP serves HTTPS, the UI serves with the same certificate.
    - On loopback without one, plain HTTP, as for MCP.
    - Off loopback with MCP on plain HTTP, which only --insecure-plain-http
      allows, the UI still serves HTTPS, with nervus's own certificate: the
      flag names what MCP gives up, and the UI never gives it up. Without that
      certificate nervus refuses to start, as it would for MCP.
    """
    if certificate is not None:
        return certificate
    if is_loopback(args.bind_host):
        return None
    cert, key = Path(DEFAULT_TLS_CERT), Path(DEFAULT_TLS_KEY)
    missing = [str(p) for p in (cert, key) if not p.exists()]
    if missing:
        raise ConfigError(
            f"no TLS {' or '.join(missing)} for the UI. Off loopback the UI is served only over "
            "HTTPS, even with --insecure-plain-http, and nervus never makes its key when it "
            f"starts. To make a key and certificate once, run: nervus tls-init --tls-cert {cert} "
            f"--tls-key {key} --name <the name browsers use>. If they existed before, the "
            "volume holding them was lost"
        )
    own = ServingCertificate(cert, key, _renewal(args, cert))
    own.load()
    return own


def _certificate_name(text: str) -> str:
    try:
        return certificate_name(text)
    except ConfigError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def tls_init(argv: list[str]) -> int:
    """`nervus tls-init`: make nervus's own certificate authority and nervus's
    key and certificate under it, once (ADR-0021 A1).

    The deliberate act ADR-0010 decision 4 requires: starting nervus never
    makes a key, so replacing one, which invalidates every pairing, can only
    happen on purpose. Refuses if any of its files exists.

    The certificate names this machine's hostname, the loopback addresses, its
    own stable addresses (ADR-0022 10a), a specific bind address, and each --name: the names clients and browsers use
    to reach nervus (ADR-0012 decision 7b), never `localhost` (ADR-0021 B1). They
    cannot be added later, since the issuer is limited to them. It prints the
    root's fingerprint, which a user compares before a client trusts the root.

    With --upgrade (ADR-0021 G1) it puts a certificate it made before, self-
    signed, under a new authority of nervus's own, keeping the key: the names
    are the old certificate's, without `localhost`, plus each --name.
    """
    parser = argparse.ArgumentParser(
        prog="nervus tls-init",
        description="Make nervus's own TLS certificate authority, key and certificate, once (ADR-0021).",
    )
    parser.add_argument("--tls-cert", default=_default("NERVUS_TLS_CERT", DEFAULT_TLS_CERT))
    parser.add_argument("--tls-key", default=_default("NERVUS_TLS_KEY", DEFAULT_TLS_KEY))
    parser.add_argument(
        "--bind-host",
        default=_default("NERVUS_BIND_HOST", "127.0.0.1"),
        help="The address nervus will bind; named in the certificate if it is a specific one",
    )
    parser.add_argument(
        "--name",
        action="append",
        type=_certificate_name,
        help=(
            "A name clients and browsers use to reach nervus, such as its DNS name, added to "
            "the certificate; repeat for more. Fixed once made: nervus's issuer is limited to them"
        ),
    )
    parser.add_argument(
        "--upgrade",
        action="store_true",
        help=(
            "Put a certificate tls-init made before, self-signed, under nervus's own authority, "
            "keeping its key (ADR-0021). Its names, without localhost, plus each --name"
        ),
    )
    args = parser.parse_args(argv)
    cert, key = Path(args.tls_cert), Path(args.tls_key)
    if args.upgrade:
        return _tls_upgrade(cert, key, args.name or [])
    # And this machine's own addresses, so a client or a VM can reach nervus
    # by address where no name resolves (ADR-0022 10a).
    names = list(dict.fromkeys(default_names(args.bind_host) + machine_addresses() + (args.name or [])))
    try:
        named = generate_own_authority(cert, key, names)
        certificate = ServingCertificate(cert, key)
        certificate.load()
        root = root_cert_path(cert)
        root_fp = certificate_fingerprint(plainfile.read_bytes(root))
    except ConfigError as exc:
        print(
            f"nervus: {exc}. tls-init makes a key once and never replaces one: a new key "
            "invalidates every pairing made against the old. If that is what you intend, "
            "delete its files first.",
            file=sys.stderr,
        )
        return 1
    _console(
        f"made a TLS key {key} and certificate {cert}, under nervus's own certificate authority, "
        f"for {', '.join(named)}: {certificate.describe()}"
    )
    _console_root(root, root_fp)
    return 0


def _console_root(root: Path, root_fp: str) -> None:
    _console(
        f"clients trust nervus by its root, {root}: root certificate SHA-256 {root_fp}. "
        "Keep this value with your tokens: it is what a user compares before trusting the root"
    )


def _tls_upgrade(cert: Path, key: Path, names: list[str]) -> int:
    """`nervus tls-init --upgrade` (ADR-0021 G1)."""
    try:
        named = upgrade_to_own_authority(cert, key, names)
        certificate = ServingCertificate(cert, key)
        certificate.load()
        root = root_cert_path(cert)
        root_fp = certificate_fingerprint(plainfile.read_bytes(root))
    except ConfigError as exc:
        print(f"nervus: {exc}. Nothing was changed.", file=sys.stderr)
        return 1
    _console(
        f"upgraded the TLS certificate {cert} to nervus's own certificate authority, keeping its "
        f"key, for {', '.join(named)}: {certificate.describe()}. A browser that accepted the old "
        "certificate asks once more; a running nervus loads the new one within seconds"
    )
    _console_root(root, root_fp)
    return 0


def tls_fingerprint(argv: list[str]) -> int:
    """`nervus tls-fingerprint`: print nervus's public-key fingerprint, on demand.

    Run on the nervus machine, this is one of the two references a user
    compares a connector's fingerprint with (ADR-0010 decision 6); the other is
    the console line at every start. A journal line from months ago is hard to
    find on the day of pairing. It reads the key, the identity itself, so it is
    right whatever certificate currently carries that key.

    Where nervus has its own authority (ADR-0021), it also prints the root's
    certificate fingerprint, labelled apart: the reference a user compares
    tools/nervus-trust's value with before a client trusts the root (E2).

    And the same key as curl pins it, labelled "public key pin" (ADR-0032
    question 4): `sha256//` and base64, the form each line nervus gives a
    person to run carries it, so that the line refuses any server but nervus.
    The page showing a line reaches the person through a browser whose view of
    nervus nothing has checked, so it could show a line carrying someone
    else's key. The Machines and Clients pages show the key above each line,
    and the person checks it is this one, which the installer prints too,
    before running the line.
    """
    parser = argparse.ArgumentParser(
        prog="nervus tls-fingerprint",
        description="Print nervus's TLS public-key fingerprint (ADR-0010 decision 6).",
    )
    parser.add_argument("--tls-cert", default=_default("NERVUS_TLS_CERT", DEFAULT_TLS_CERT))
    parser.add_argument("--tls-key", default=_default("NERVUS_TLS_KEY", DEFAULT_TLS_KEY))
    args = parser.parse_args(argv)
    root = root_cert_path(Path(args.tls_cert))
    try:
        found = key_file_fingerprint(Path(args.tls_key))
        pin = key_file_pin(Path(args.tls_key))
        root_fp = certificate_fingerprint(plainfile.read_bytes(root)) if root.exists() else None
    except (ConfigError, OSError) as exc:
        print(f"nervus: {exc}", file=sys.stderr)
        return 1
    print(f"{args.tls_key}: public key SHA-256 {found}")
    print(f"{args.tls_key}: public key pin {pin}")
    if root_fp is not None:
        print(f"{root}: root certificate SHA-256 {root_fp}")
    return 0


def tls_reissue(argv: list[str]) -> int:
    """`nervus tls-reissue --name <address>`: nervus's certificate again, from
    the same issuer, with an address added (ADR-0022 10a), for when nervus's
    address moves. Clients keep the root they saved; a browser asks once more.
    Run as the nervus user, as tls-init is."""
    parser = argparse.ArgumentParser(
        prog="nervus tls-reissue",
        description="Add an address to nervus's TLS certificate, from the same issuer (ADR-0022).",
    )
    parser.add_argument("--tls-cert", default=_default("NERVUS_TLS_CERT", DEFAULT_TLS_CERT))
    parser.add_argument("--tls-key", default=_default("NERVUS_TLS_KEY", DEFAULT_TLS_KEY))
    parser.add_argument("--name", action="append", required=True,
                        help="An address to add to nervus's certificate; repeat for more")
    args = parser.parse_args(argv)
    cert, key = Path(args.tls_cert), Path(args.tls_key)
    try:
        named = add_addresses(cert, issuer_key_path(key), args.name)
        certificate = ServingCertificate(cert, key)
        certificate.load()
    except (ConfigError, OSError, ValueError) as exc:
        print(f"nervus: {exc}", file=sys.stderr)
        return 1
    _console(
        f"re-issued the TLS certificate {cert} from nervus's own issuer, for {', '.join(named)}: "
        f"{certificate.describe()}. Clients keep the root they saved; a browser asks once more; a running "
        "nervus loads it within seconds"
    )
    return 0


TLS_COMMANDS = {"tls-init": tls_init, "tls-fingerprint": tls_fingerprint, "tls-reissue": tls_reissue}


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] in TLS_COMMANDS:
        return TLS_COMMANDS[argv[0]](argv[1:])
    args = parse_args(argv)

    try:
        hosts = load_hosts(Path(args.hosts))
        tokens = load_tokens(Path(args.tokens))
        require_private_file(Path(args.ssh_key))
        # Read once, here, and kept as the SSH key is (ADR-0025 question 1a).
        ssh_ca = CertificateAuthority(Path(args.ssh_ca_key))
        proxmox = ProxmoxClient(load_config(Path(args.proxmox))) if args.proxmox else None
        if args.ui_port == args.bind_port:
            raise ConfigError(
                f"--ui-port and --bind-port are both {args.bind_port}; the UI has a port of its own "
                "(ADR-0012 decision 1)"
            )
        certificate = tls_certificate(args)
        ui_cert = ui_certificate(args, certificate)
        # Last, so that a start refused for anything else makes no database.
        database = Database(Path(args.database))
        # ADR-0027 question 6: never an empty database where nervus has run,
        # and never a database beside keys it was not made with.
        identity.check_history(database.path, Path(args.audit_log))
        database.open()
        served = certificate or ui_cert
        issuer = issuer_key_path(served.key_path) if served is not None else None
        identity.check(database, identity.Keys(ssh_key=Path(args.ssh_key), ssh_ca_key=Path(args.ssh_ca_key),
                                               tls_issuer=issuer if issuer is not None and issuer.exists() else None),
                       AuditLog(path=Path(args.audit_log)))
        issued_ids = {issued.token.id for issued in database.issued_tokens()}
        export_store = ExportStore(database, Path(args.exports_dir or Path(args.database).parent / "exports"))
        export_store.open()
        upload_store = UploadStore(database, Path(args.uploads_dir or Path(args.database).parent / "uploads"))
        interrupted = upload_store.open()
    except ConfigError as exc:
        print(f"nervus: {exc}", file=sys.stderr)
        return 1

    settings = Settings(
        hosts=hosts,
        tokens_path=Path(args.tokens),
        known_hosts_path=Path(args.known_hosts),
        ssh_key_path=Path(args.ssh_key),
        audit_log_path=Path(args.audit_log),
        transfer_dir=Path(args.transfer_dir),
        bind_host=args.bind_host,
        bind_port=args.bind_port,
        ssh_port=args.ssh_port,
        switches_path=Path(args.switches),
        ssh_ca=ssh_ca,
    )
    try:
        load_switches(settings.switches_path)
    except SwitchesUnreadable as exc:
        # Not a refusal to start: refusing every client is the safe state, and
        # fixing the file restores service without a restart (ADR-0003, A).
        _console(f"WARNING: every client is refused until the off switch is fixed: {exc}")
    if proxmox is not None and hypervisor_host(hosts) is None:
        # Not a refusal to start: the other tools work, and the proxmox tool
        # refuses each call with this reason (ADR-0019 decision D).
        _console("WARNING: --proxmox is set, but no inventory entry is marked `hypervisor: proxmox`, "
                 "so every proxmox call and VM export is refused")
    audit = AuditLog(path=settings.audit_log_path)
    # The token file's tokens, and those issued in the UI, looked up in the
    # database on every request (ADR-0014 decision C). An id names one token:
    # the UI refuses one the file has, but the file is edited by hand.
    both = sorted(issued_ids & {t.id for t in tokens.values()})
    if both:
        _console(f"WARNING: these ids are in both the token file and the database, so the audit log "
                 f"cannot tell their calls apart: {', '.join(both)}. Revoke one in the UI.")
    tokens = Tokens(tokens, database.token)
    # VMs named by id, enrolled through the guest agent on first use, over
    # nervus's own key with the host keys their guest agents report (ADR-0022).
    # Machines enrolled from the UI, read at every call beside hosts.yaml (ADR-0024).
    enrolled = EnrolledHostStore(database)
    # What each machine's accounts are, read-only and read-write (ADR-0031).
    machine_accounts = MachineAccounts(database)
    vms = None
    if proxmox is not None:
        enrollments = EnrollmentStore(database)
        key = Path(settings.ssh_key_path)
        # Enrolling writes the CA's line, not the key's (ADR-0025 decision 4).
        vms = VMTargets(enrollments, Enroller(enrollments, ssh_ca.public_key,
                                             ssh_connector(key, settings.ssh_port, authority=ssh_ca)),
                        proxmox)
    # Exports read a VM in answers of up to VM_RESPONSE_BYTES, with a client of
    # their own; the proxmox tool keeps its 256 KiB limit (ADR-0016, step 0).
    # Over SFTP where the VM can be enrolled (ADR-0022 7a).
    exporter = Exporter(
        export_store, audit, connect=lambda host: connect_host(settings, host),
        vm_api=ProxmoxClient(proxmox.config, max_response_bytes=VM_RESPONSE_BYTES) if proxmox else None,
        vm_connect=vms.connect if vms else None,
    )
    uploader = Uploader(upload_store, audit, deliver=Deliveries(
        HostDelivery(upload_store, lambda: merged(hosts, enrolled, machine_accounts), lambda host: connect_host(settings, host)),
        # The root beside the certificate MCP serves, handed to a VM with each
        # pull so its curl can check nervus (ADR-0022 8a). Read at each pull.
        VMDelivery(upload_store, exporter.vm_api, args.upload_pull_url or None,
                   pull_root=root_cert_path(certificate.cert_path) if certificate else None,
                   vm_connect=vms.connect if vms else None),
    ))
    # Machines enrolled with one line run on them (ADR-0024, ADR-0032): the script and
    # the report back on MCP's port, only over HTTPS, pinned to the key MCP
    # serves now; never full access to the machine nervus runs on.
    ssh_key = Path(settings.ssh_key_path)
    codes = EnrollmentCodes(database)
    pin = lambda: key_pin(certificate.certificate.public_key()) if certificate else None  # noqa: E731
    enrollment = HostEnrollment(
        codes, enrolled, audit,
        key=ssh_ca.public_key, connect=ssh_connector(ssh_key, settings.ssh_port, authority=ssh_ca),
        pin=pin, own_machine_id=own_machine_id(), reserved=lambda: hosts.keys(),
        locked=lambda: locked(settings.switches_path),
        # ADR-0031: what each machine's accounts are, and the machines described by hand that can be
        # given a read-only account from the Machines page (question 4).
        machine_accounts=machine_accounts, described=lambda: described(hosts),
        connect_described=lambda host: connect_host(settings, host),
        # nervus's own key, which a machine enrolled before ADR-0025 holds (procedure 068, section 12).
        nervus_key=lambda: public_words(ssh_key),
        # The accounts every hosts.yaml entry at a machine's address is described with (procedure 068, section 12).
        taken=lambda name: accounts_at(hosts, name),
    )
    # A laptop set up by one line (ADR-0032): its script and its token on MCP's port, only over HTTPS, pinned to
    # the key MCP serves now, the root it carries read at each fetch; the token handed over once, by its code.
    token_codes = TokenCodes(database)
    laptop = LaptopRoute(token_codes, audit, pin=pin,
                         root=lambda: plainfile.read_bytes(root_cert_path(certificate.cert_path)).decode(),
                         locked=lambda: locked(settings.switches_path))
    mcp_server = build_server(settings=settings, tokens=tokens, audit=audit, proxmox=proxmox, exporter=exporter,
                              uploader=uploader, vms=vms, enrolled=enrolled, enrollment=enrollment,
                              machine_accounts=machine_accounts, laptop=laptop)
    # At every start: the tier declared at setup, and whether nervus listens on
    # an address public in form, with the ranges declared internal (ADR-0007
    # decision 4, ADR-0015 decisions C to E). It only reads, and is never a
    # refusal: what cannot be read is said, and ranges that cannot be read are
    # left out, which makes the line louder, never quieter. The UI keeps the
    # addresses found here and matches them again at every page.
    first_run = FirstRun(database)
    try:
        tier = first_run.tier()
        _console("tier: not chosen yet; sign in to the web UI to choose it" if tier is None
                 else f"tier: {TIER_WORDS[tier.tier]}")
    except DatabaseUnusable as exc:
        _console(f"WARNING: could not read the tier: {exc}")
    try:
        declared = first_run.declared()
    except DatabaseUnusable as exc:
        _console(f"WARNING: could not read the ranges declared internal, so none is applied: {exc}")
        declared = []
    exposure = check_exposure(settings.bind_host, declared)
    for line in exposure.lines():
        _console(line)
    # The backups page's button makes the backup `nervus-ctl backup` makes,
    # of the pieces nervus's unit and its drop-ins name (ADR-0027).
    service = ctl.service_of(args, Path.cwd(), None,
                             tuple(ctl.unit_files(ctl.UNIT)[1:]) if ctl.UNIT.exists() else ())
    backups = Backups(folder=restore.backups_folder(service), recovery_key=service.recovery_key,
                      make=lambda: restore.backup_now(service, database, audit, tool="ui"))
    ui_app = build_ui(database, audit, secure=ui_cert is not None, setup=Setup(first_run, exposure), backups=backups,
                      # Each token issued with the line that hands it to its laptop, naming nervus as
                      # --ui-url does (ADR-0032 question 5).
                      management=Management(tokens, Path(args.switches), sorted(hosts), never_issued(hosts),
                                            codes=token_codes, pin=pin, port=settings.bind_port,
                                            nervus_host=urllib.parse.urlsplit(args.ui_url).hostname or ""
                                            if args.ui_url else ""),
                      # Added from the page, the line naming nervus as --ui-url does (ADR-0024).
                      machines=Machines(codes, enrolled, pin, settings.bind_port, sorted(hosts),
                                        urllib.parse.urlsplit(args.ui_url).hostname or "" if args.ui_url else "",
                                        # Added by an admin login given once, the machine's key shown first (ADR-0026).
                                        login=LoginEnrollment(codes, audit, port=settings.ssh_port,
                                                              locked=lambda: locked(settings.switches_path)),
                                        # ADR-0031: each machine's accounts, and question 4's machines.
                                        accounts=machine_accounts, described=described(hosts),
                                        taken={n: accounts_at(hosts, n) for n in described(hosts)},
                                        # nervus's key words, for the removal commands (ADR-0031 question 9).
                                        key_words=lambda: tuple(w for w in (
                                            " ".join(ssh_ca.public_key().split()[:2]), public_words(ssh_key)) if w),
                                        # The script each line fetches, shown beneath it (ADR-0032 question 7).
                                        shown=enrollment.shown))
    host = settings.bind_host

    for served in {id(c): c for c in (certificate, ui_cert) if c}.values():
        renewal = served.renew_if_due()  # ADR-0010 decision 3; daily after this
        if renewal is not None:
            _console(renewal)
    if certificate is None:
        if not is_loopback(host):
            # At every start, while the condition holds (ADR-0007 decision 4's pattern).
            _console(
                f"WARNING: serving plain HTTP on {host}:{settings.bind_port}, which "
                "is not loopback (--insecure-plain-http). Bearer tokens and every request and "
                "response cross the network unencrypted."
            )
    else:
        # At every start: this is what a user compares when pairing (ADR-0008).
        _console(f"serving HTTPS with {certificate.serving}: {certificate.describe()}")
    if ui_cert is None:
        _console(f"serving the UI on {host}:{args.ui_port} over plain HTTP, on loopback")
    elif ui_cert is certificate:
        _console(f"serving the UI on {host}:{args.ui_port} over HTTPS, with the same certificate")
    else:
        _console(f"serving the UI on {host}:{args.ui_port} over HTTPS with {ui_cert.serving}: "
                 f"{ui_cert.describe()}")

    serve([
        Listener("MCP", host, settings.bind_port, certificate,
                 lambda: uvicorn_config(mcp_server, host, settings.bind_port, certificate)),
        Listener("UI", host, args.ui_port, ui_cert,
                 lambda: ui_uvicorn_config(ui_app, host, args.ui_port, ui_cert)),
    ], background=[exporter.sweep_forever, uploader.sweep_forever, lambda: uploader.tidy(interrupted)])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
