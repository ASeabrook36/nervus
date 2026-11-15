from __future__ import annotations

import asyncio
import contextlib
import functools
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import asyncssh
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from nervus import certs, jobs, sftp, ssh
from nervus.proxmox import ProxmoxClient, ProxmoxError, check_request
from nervus.audit import AuditError, AuditLog
from nervus.auth import (
    AuthError,
    BearerAuthMiddleware,
    Token,
    Tokens,
    attribution,
    require_host_allowed,
    require_token,
)
from nervus.config import Host, Settings, hypervisor_host
from nervus.download import download_endpoint
from nervus.host_enrollment import HostEnrollment, enroll_endpoint
from nervus.upload_route import upload_endpoints
from nervus.uploader import Uploader
from nervus.exporter import DEFAULT_WAIT_SECONDS, MEASURING, Exporter, HostRequest, Status, VMRequest, export_fields
from nervus.exports import ExportRefused
from nervus.enroller import AGENT_USER, EnrollmentFailed, pinned_known_hosts
from nervus.enrolled_hosts import EnrolledHostStore, merged
from nervus.enrollments import EnrollmentRefused, valid_vmid
from nervus.guest import GuestError
from nervus.vm_targets import VMTargets


def _require_host(hosts: dict[str, Host], name: str) -> Host:
    host = hosts.get(name)
    if host is None:
        raise ValueError(f"unknown host {name!r} (not in nervus's inventory)")
    return host


def _authorized_host(
    *,
    audit: AuditLog,
    tool: str,
    token: Token,
    host: str,
    hosts: dict[str, Host],
) -> Host:
    """Resolve `host` for `token`, recording a refusal if it is not allowed.

    Authorization has to happen before the intent record, because that
    record's `user` field comes from the resolved host -- and a host that
    was denied, or that is not in the inventory, never resolves. That
    ordering is exactly why refusals used to write nothing at all: they
    raised before reaching record_intent, leaving only a journal traceback.

    ADR-0001 section 10 says every tool call appends a record, and the
    Consequences section calls the audit log mandatory precisely because a
    standing credential replaced per-session approval. A denied attempt is
    the case that most needs to be visible, so it gets its own record here
    before the exception propagates.
    """
    try:
        require_host_allowed(token, host)
        return _require_host(hosts, host)
    except (AuthError, ValueError) as exc:
        audit.record_refusal(
            tool,
            {
                **attribution(token),
                "host": host,
                "reason": str(exc),
            },
        )
        raise


def _transfer_path(
    *,
    audit: AuditLog,
    tool: str,
    token: Token,
    host: str,
    transfer_dir: Path,
    local_path: str,
) -> Path:
    """Confine a transfer's local path, recording a refusal if it escapes.

    `put` reads this path from nervus's own filesystem and sends it to a
    host; `get` writes to it. Unconfined, that made the fleet private key
    and the token file exfiltrable by any authenticated client, and made the
    audit log overwritable. Both are refusals worth a record of their own --
    an attempt to read a path outside the transfer directory is exactly the
    kind of thing the log exists to show.
    """
    try:
        return sftp.resolve_transfer_path(transfer_dir, local_path)
    except sftp.TransferPathError as exc:
        audit.record_refusal(
            tool,
            {
                **attribution(token),
                "host": host,
                "local_path": local_path,
                "reason": str(exc),
            },
        )
        raise


REDACTED = "<redacted>"
# ADR-0019 decision D: the Proxmox host is the inventory entry marked
# `hypervisor: proxmox`, whatever it is called. Without one, every call that
# needs it is refused, with this reason.
NO_PROXMOX_HOST = "no inventory entry is marked `hypervisor: proxmox`, so this nervus has no Proxmox host"

# Refusals, and failures reaching a target, whose text is meant for the client
# and holds no secret: ProxmoxError never carries the token's secret, and
# asyncssh's errors carry no key. The MCP library hides the text of any other
# exception, as a crash inside nervus, and it stays hidden.
_REFUSALS = (AuthError, ValueError, sftp.TransferPathError, ProxmoxError, jobs.JobError, AuditError,
             EnrollmentFailed, GuestError)
_FAILURES = (asyncssh.Error, OSError)


def told(exc: BaseException) -> str:
    """What a client is told of an error, and so all the audit log records of
    it: a refusal's own words; a failure's type and words; of anything else, a
    fault in nervus whose text may carry its internals, its type alone. The
    client is told less still of that: only that the tool failed."""
    if isinstance(exc, _REFUSALS):
        return str(exc)
    if isinstance(exc, _FAILURES):
        return f"{type(exc).__name__}: {exc}"
    return type(exc).__name__


def with_reasons(func):
    """Let a tool's refusals and failures reach the client with their reason.

    The MCP library passes a ToolError's text to the client and replaces any
    other exception's with "Error executing tool <name>". Until 2026-10-14
    every refusal raised a plain exception, so a client refused a host, or
    whose file did not exist, was told nothing it could act on. Only the
    switched-off client is meant to learn nothing (ADR-0003 question B), and
    that refusal is the authentication middleware's, before any tool runs.
    """

    @functools.wraps(func)
    async def tool(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except ToolError:
            raise
        except _REFUSALS + _FAILURES as exc:
            raise ToolError(told(exc)) from exc

    return tool


def redact_params(params: dict | None) -> dict:
    """Parameters as the audit log records them (ADR-0009 decision 2).

    Everything is kept, as exec keeps the whole command, except a value
    whose name contains "password" (cipassword, for example). The log is
    copied to the operator's Mac, where agents can read it, and a password
    there would outlive the thing it protects. The key stays, so the record
    still shows that one was set.
    """
    return {
        k: (REDACTED if "password" in k.lower() else v) for k, v in (params or {}).items()
    }


def require_proxmox_host(token: Token, host: str | None) -> None:
    """Refuse a token whose allowlist does not name the Proxmox host, or any
    token at all when the inventory marks no entry `hypervisor: proxmox`."""
    if host is None:
        raise ProxmoxError(NO_PROXMOX_HOST)
    require_host_allowed(token, host)


def _authorized_proxmox(
    *,
    audit: AuditLog,
    token: Token,
    host: str | None,
    method: str,
    path: str,
    params: dict | None,
) -> str:
    """Check a proxmox call before anything is recorded as intended.

    A token may use the tool if the Proxmox host, the entry marked
    `hypervisor: proxmox`, is in its allowlist (ADR-0009 decisions 2 and 7,
    ADR-0019 decision D). The API has no SSH inventory entry of its own, so
    this checks the allowlist directly rather than going through
    _authorized_host. A request nervus will not send -- a bad method or a
    path that tries to leave the API -- is refused here too, and like a
    denied host it gets a record of its own. Returns the upper-cased method.
    """
    try:
        require_proxmox_host(token, host)
        return check_request(method, path, params)
    except (AuthError, ProxmoxError) as exc:
        audit.record_refusal(
            "proxmox",
            {
                **attribution(token),
                "host": host,
                "method": method,
                "path": path,
                "params": redact_params(params),
                "reason": str(exc),
            },
        )
        raise


def connect_host(settings: Settings, host: Host):
    """nervus's one way to open SSH to a host: its own key, the pinned host keys,
    from the known_hosts file or, for a machine enrolled from the UI, its own
    (ADR-0024); with a certificate naming the call when nervus has its CA
    (ADR-0025)."""
    return ssh.connect(
        address=host.address,
        port=settings.ssh_port,
        username=host.agent_user,
        client_keys=[settings.ssh_key_path],
        known_hosts=(pinned_known_hosts(host.address, settings.ssh_port, host.host_keys) if host.host_keys
                     else settings.known_hosts_path),
        authority=settings.ssh_ca,
    )


def _noted(note: str | None) -> dict:
    """`vm_note`, when a VM was enrolled or repaired on the way (ADR-0022 5a)."""
    return {"vm_note": note} if note else {}


def _utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).isoformat(timespec="seconds")


def export_response(status: Status, request_key: str, run_id: str, route: str | None = None) -> dict:
    """What `export` tells the client: never a token, never a path on nervus.
    `route` is how the copy is read, "sftp" or "guest-agent" (ADR-0022 7a)."""
    result: dict = {"run_id": run_id, "request_key": request_key, "state": status.state}
    export = status.export
    if export is not None:
        result.update(export_id=export.id, source=export.source, filename=export.filename,
                      bytes_copied=export.bytes_written)
        if route is not None:
            result["route"] = route
        if export.size is not None:
            result.update(size=export.size, sha256=export.sha256)
        if export.state == "ready":
            result.update(expires_at=_utc(export.expires_at), download_path=f"/exports/{export.id}")
        if export.failure_code is not None:
            result["failure"] = {"code": export.failure_code, "message": export.failure_message}
    if status.state in (MEASURING, "staging"):
        result["next"] = "call export again with the same request_key to wait for it"
    return result


def build_server(
    *,
    settings: Settings,
    tokens: Tokens | dict[str, Token],
    audit: AuditLog,
    proxmox: ProxmoxClient | None = None,
    exporter: Exporter | None = None,
    uploader: Uploader | None = None,
    vms: VMTargets | None = None,
    enrolled: EnrolledHostStore | None = None,
    enrollment: HostEnrollment | None = None,
) -> MCPServer:
    """Build the nervus MCP server: tool surface, audit, and the one
    authorization check this layer performs beyond token validity --
    the per-host allowlist (ADR-0001 sections 6 and 9).

    Every tool opens its own SSH connection and closes it when done.
    There is no connection pool: v1 doesn't need one, and ADR-0001
    section "Consequences" already accepts that concurrency across
    callers is unmanaged in v1.
    """
    proxmox_host = hypervisor_host(settings.hosts)

    def hosts_now() -> dict[str, Host]:
        """hosts.yaml's machines and those enrolled from the UI, read at every
        call, so enrolling needs no restart (ADR-0024 decision 3)."""
        return merged(settings.hosts, enrolled)

    mcp_server: MCPServer = MCPServer(
        name="nervus",
        instructions=(
            "MCP bastion giving programmatic SSH access to the operator's "
            "home fleet. See decisions/0001-mcp-bastion.md."
        ),
        middleware=[BearerAuthMiddleware(tokens, settings.switches_path, audit)],
    )

    def tool(**kwargs):
        """Every tool is registered through this, so none can miss with_reasons."""
        return lambda func: mcp_server.tool(**kwargs)(with_reasons(func))

    async def _connect(host: Host) -> asyncssh.SSHClientConnection:
        return await connect_host(settings, host)

    def _target(tool_name: str, token: Token, host: str | None, vmid: int | None) -> tuple[Host | None, dict]:
        """Authorize a host, or a VM by id (ADR-0022 4a), recording a refusal
        as _authorized_host does. A VM may be named by any token whose
        allowlist holds the hypervisor's entry, and no other (6a): those are
        root in it through the guest agent already. Returns the host's
        record, or None for a VM, and the fields naming it in the audit log."""
        if host is not None and vmid is None:
            return _authorized_host(audit=audit, tool=tool_name, token=token, host=host, hosts=hosts_now()), \
                {"host": host}
        try:
            if host is not None:
                raise ValueError("give a host or a vmid, not both")
            if vmid is None:
                raise ValueError("give a host, or a VM's id as vmid")
            if vms is None:
                raise ValueError("VMs need nervus's Proxmox settings (--proxmox)")
            require_proxmox_host(token, proxmox_host)
            valid_vmid(vmid)
        except (AuthError, ProxmoxError, ValueError) as exc:
            audit.record_refusal(tool_name, {**attribution(token), "host": host, "vmid": vmid, "reason": str(exc)})
            raise
        return None, {"vmid": vmid}

    def _no_nul(tool_name: str, token: Token, named: dict, **given: str) -> None:
        """Refuse, with a record, a string bound for a machine that holds a NUL byte (procedure 056). bash
        drops one from the script nervus sends it, so `echo cu<NUL>rl` ran as `echo curl` while the audit log
        held the NUL, and a search of the log for what ran missed it; elsewhere one cuts a path short or is
        refused with no record. No command or path has a use for one; an upload's destination was refused
        one already (upload_route.parse_destination)."""
        for name, value in given.items():
            if "\x00" in value:
                reason = (f"`{name}` holds a NUL byte, which nervus sends to no machine: it would be dropped or "
                          "cut the string short there, and the audit log would not say what was done")
                audit.record_refusal(tool_name, {**attribution(token), **named, **given, "reason": reason})
                raise ValueError(reason)

    def _user(host_record: Host | None) -> str:
        return AGENT_USER if host_record is None else host_record.agent_user

    async def _open(host_record: Host | None, vmid: int | None, token: Token,
                    run_id: str) -> tuple[asyncssh.SSHClientConnection, str | None]:
        """SSH to the target, for the call `run_id` (ADR-0025: the certificate
        names it, and the result record the port). For a VM, enrolled or
        repaired first if it needs it; the note says what changed, for the
        answer and the log."""
        certs.acting_for(token.id, run_id)
        if host_record is not None:
            return await _connect(host_record), None
        assert vms is not None and vmid is not None
        return await vms.connect(vmid, token.id)

    @contextlib.contextmanager
    def _failure_recorded(run_id: str, tool_name: str):
        """A call that fails once its intent is written still gets a result:
        `error`, what its client is told (`told`), how long it ran and the SSH
        ports it used, as the proxmox tool's result always had. Without it a
        write the machine refused showed as "no result recorded", as a call
        still running does (procedure 054, finding 3). The success's own result
        is written after this, so no call gets two.

        It carries `vm_note` too, read from the call as its ports are: a call
        by vmid that enrolled or repaired the VM and then failed changed the VM
        all the same, so the record says so (ADR-0001 section 10; procedure 056)."""
        start = time.monotonic()
        try:
            yield
        except (Exception, asyncio.CancelledError) as exc:
            audit.record_result(run_id, tool_name, {"error": told(exc), "duration_s": time.monotonic() - start,
                                                    **certs.vm_note(), **certs.ssh_ports()})
            raise

    @tool()
    async def hosts(ctx: Context) -> dict:
        """List the hosts this token is allowed to reach, and, for a token
        that reaches the Proxmox host, the VMs nervus has enrolled: each by
        `vmid`, which every tool that takes `host` also takes."""
        token = require_token(ctx.headers, tokens)
        run_id = audit.record_intent(
            "hosts",
            {
                **attribution(token),
            },
        )
        visible = [
            {
                "name": h.name,
                "address": h.address,
                "role": h.role,
                "status": h.status,
                # read-only, standard or full, for a machine enrolled from the UI (ADR-0024)
                **({"level": h.level} if h.level else {}),
            }
            for h in hosts_now().values()
            if h.name in token.hosts
        ]
        answer: dict = {"hosts": visible}
        recorded: dict = {"count": len(visible), "hosts": sorted(h["name"] for h in visible)}
        if vms is not None and proxmox_host is not None and proxmox_host in token.hosts:
            try:
                answer["vms"] = await vms.listing()
                recorded["vms"] = [vm["vmid"] for vm in answer["vms"]]
            except GuestError as exc:  # nothing forgotten; the hosts still listed
                answer["vms_error"] = recorded["vms_error"] = exc.message
        audit.record_result(run_id, "hosts", recorded)
        return answer

    @tool()
    async def exec(  # noqa: A001 - tool name is fixed by ADR-0001 section 9
        ctx: Context,
        command: str,
        host: str | None = None,
        vmid: int | None = None,
        cwd: str = "~",
        timeout: float = 60.0,
    ) -> dict:
        """Run a command on a host, or in a VM given as `vmid`. Returns exit
        code and bounded output; the full output is always written to the
        target's disk.

        A VM made through the proxmox tool needs nothing set up: the first
        call naming it enrolls it through its guest agent, which takes a few
        seconds, and later calls repair what has changed. `vm_note` in the
        answer says when that happened.

        Commands run as the host's agent account, not as root. Nothing can
        answer a prompt, so privileged commands need `sudo -n` where the
        account has sudo: `sudo -n systemctl reboot` works, a bare `reboot`
        is refused by polkit."""
        token = require_token(ctx.headers, tokens)
        host_record, named = _target("exec", token, host, vmid)
        _no_nul("exec", token, named, command=command, cwd=cwd)

        run_id = audit.record_intent(
            "exec",
            {
                **attribution(token),
                **named,
                "user": _user(host_record),
                "cwd": cwd,
                "command": command,
            },
        )

        start = time.monotonic()
        with _failure_recorded(run_id, "exec"):
            conn, note = await _open(host_record, vmid, token, run_id)
            try:
                result = await ssh.exec_command(
                    conn, cwd=cwd, command=command, timeout=timeout, run_id=run_id, label=certs.label()
                )
            finally:
                conn.close()
        duration_s = time.monotonic() - start

        audit.record_result(
            run_id,
            "exec",
            {
                "exit_code": result.exit_code,
                "duration_s": duration_s,
                "output_bytes": result.total_bytes,
                "truncated": result.truncated,
                "timed_out": result.timed_out,
                "log_path": result.remote_output_path,
                **_noted(note),
                **certs.ssh_ports(),
            },
        )

        return {
            **_noted(note),
            "run_id": run_id,
            "exit_code": result.exit_code,
            "output": result.output,
            "truncated": result.truncated,
            "total_bytes": result.total_bytes,
            "timed_out": result.timed_out,
            "remote_output_path": result.remote_output_path,
        }

    @tool()
    async def exec_bg(ctx: Context, command: str, host: str | None = None, vmid: int | None = None,
                      cwd: str = "~") -> dict:
        """Start a detached job on a host, or in a VM given as `vmid`.
        Survives client disconnects and nervus restarts; check on it later
        with the job tool, naming the same host or vmid.

        Runs as the host's agent account, not as root; privileged commands
        need `sudo -n`, as with exec."""
        token = require_token(ctx.headers, tokens)
        host_record, named = _target("exec_bg", token, host, vmid)
        _no_nul("exec_bg", token, named, command=command, cwd=cwd)

        run_id = audit.record_intent(
            "exec_bg",
            {
                **attribution(token),
                **named,
                "user": _user(host_record),
                "cwd": cwd,
                "command": command,
            },
        )

        with _failure_recorded(run_id, "exec_bg"):
            conn, note = await _open(host_record, vmid, token, run_id)
            try:
                handle = await jobs.start_job(conn, cwd=cwd, command=command, job_id=run_id, label=certs.label())
            finally:
                conn.close()

        audit.record_result(
            run_id,
            "exec_bg",
            {"session_name": handle.session_name, "log_path": handle.log_path, **_noted(note), **certs.ssh_ports()},
        )

        return {
            **_noted(note),
            "job_id": handle.job_id,
            **named,
            "session_name": handle.session_name,
            "log_path": handle.log_path,
        }

    @tool()
    async def job(
        ctx: Context,
        job_id: str,
        action: Literal["status", "logs", "kill"],
        host: str | None = None,
        vmid: int | None = None,
        tail: int | None = None,
        offset: int = 0,
        length: int | None = None,
    ) -> dict:
        """Check status, read logs, or kill a job started by exec_bg, on the
        host or in the VM (`vmid`) it was started on."""
        token = require_token(ctx.headers, tokens)
        host_record, named = _target("job", token, host, vmid)

        run_id = audit.record_intent(
            "job",
            {
                **attribution(token),
                **named,
                "job_id": job_id,
                "action": action,
            },
        )

        with _failure_recorded(run_id, "job"):
            conn, note = await _open(host_record, vmid, token, run_id)
            try:
                if action == "status":
                    status = await jobs.job_status(conn, job_id)
                    result: dict = {
                        "job_id": status.job_id,
                        "running": status.running,
                        "exit_code": status.exit_code,
                    }
                elif action == "logs":
                    text = await jobs.job_logs(conn, job_id, tail=tail, offset=offset, length=length)
                    result = {"job_id": job_id, "logs": text}
                else:
                    await jobs.kill_job(conn, job_id)
                    result = {"job_id": job_id, "killed": True}
            finally:
                conn.close()

        result.update(_noted(note))
        audit.record_result(
            run_id, "job", {"action": action, **{k: v for k, v in result.items() if k != "logs"}, **certs.ssh_ports()}
        )
        return result

    @tool()
    async def put(ctx: Context, local_path: str, remote_path: str, host: str | None = None,
                  vmid: int | None = None) -> dict:
        """Copy a file from nervus's transfer directory, where `get` left it,
        to a host, or a VM given as `vmid`, over SFTP. It is written beside `remote_path`, then renamed
        into place.

        To send a file from your own machine to a host or a VM, do not paste
        it into `exec`: send it from your shell in one command, `curl -T` to
        PUT /uploads on this server with your own token, the destination and
        the file's SHA-256. The bytes never pass through the model. The
        command is in nervus's client instructions, "Send a file from your
        machine"."""
        token = require_token(ctx.headers, tokens)
        host_record, named = _target("put", token, host, vmid)
        _no_nul("put", token, named, local_path=local_path, remote_path=remote_path)
        resolved = _transfer_path(
            audit=audit,
            tool="put",
            token=token,
            host=host,
            transfer_dir=settings.transfer_dir,
            local_path=local_path,
        )

        run_id = audit.record_intent(
            "put",
            {
                **attribution(token),
                **named,
                "local_path": local_path,
                "remote_path": remote_path,
            },
        )
        with _failure_recorded(run_id, "put"):
            conn, note = await _open(host_record, vmid, token, run_id)
            try:
                await sftp.put_file(conn, resolved, remote_path, transfer_dir=settings.transfer_dir)
            finally:
                conn.close()
        audit.record_result(run_id, "put", {"ok": True, **_noted(note), **certs.ssh_ports()})
        return {"ok": True, **_noted(note)}

    @tool()
    async def get(ctx: Context, remote_path: str, local_path: str, host: str | None = None,
                  vmid: int | None = None) -> dict:
        """Copy a file from a host, or a VM given as `vmid`, to nervus's own
        filesystem over SFTP."""
        token = require_token(ctx.headers, tokens)
        host_record, named = _target("get", token, host, vmid)
        _no_nul("get", token, named, remote_path=remote_path, local_path=local_path)
        resolved = _transfer_path(
            audit=audit,
            tool="get",
            token=token,
            host=host,
            transfer_dir=settings.transfer_dir,
            local_path=local_path,
        )

        run_id = audit.record_intent(
            "get",
            {
                **attribution(token),
                **named,
                "remote_path": remote_path,
                "local_path": local_path,
            },
        )
        with _failure_recorded(run_id, "get"):
            conn, note = await _open(host_record, vmid, token, run_id)
            try:
                await sftp.get_file(conn, remote_path, resolved, transfer_dir=settings.transfer_dir)
            finally:
                conn.close()
        audit.record_result(run_id, "get", {"ok": True, **_noted(note), **certs.ssh_ports()})
        return {"ok": True, **_noted(note)}

    # Unconfigured means absent (ADR-0009 decision 2): a client never sees a
    # tool that cannot work.
    if proxmox is not None:
        api = proxmox

        @tool(name="proxmox")
        async def proxmox_call(
            ctx: Context,
            method: Literal["GET", "POST", "PUT", "DELETE"],
            path: str,
            params: dict[str, str | int | float | bool] | None = None,
            timeout: float = 60.0,
        ) -> dict:
            """Call the Proxmox VE API on nervus's Proxmox host. `path` is
            relative to /api2/json, e.g. "/cluster/resources" or
            "/nodes/{node}/qemu/100/status/start", where {node} is a node name
            from GET /nodes;
            `params` is a flat mapping, sent as the query for GET and DELETE
            and as the form body for POST and PUT.

            What is allowed is decided by Proxmox's permissions for nervus's API
            token, with one exception nervus makes itself: the whole-node bulk
            actions (startall, stopall, suspendall, migrateall) are refused
            before anything is sent, because Proxmox would let them reach every
            guest, nervus's own container included. Proxmox's refusal comes back
            as a response with status 403 and Proxmox's reason; it is not a
            nervus error.
            Long-running actions return a task id (UPID); poll
            /nodes/{node}/tasks/{upid}/status. Responses over 256 KiB are refused,
            not cut short: narrow the request."""
            token = require_token(ctx.headers, tokens)
            verb = _authorized_proxmox(
                audit=audit, token=token, host=proxmox_host, method=method, path=path, params=params
            )

            run_id = audit.record_intent(
                "proxmox",
                {
                    **attribution(token),
                    "host": proxmox_host,
                    "user": api.config.token_id,
                    "method": verb,
                    "path": path,
                    "params": redact_params(params),
                },
            )

            start = time.monotonic()
            try:
                resp = await api.request(verb, path, params, timeout=timeout)
            except ProxmoxError as exc:
                audit.record_result(
                    run_id,
                    "proxmox",
                    {"error": str(exc), "duration_s": time.monotonic() - start},
                )
                raise
            audit.record_result(
                run_id,
                "proxmox",
                {
                    "status": resp.status,
                    "reason": resp.reason,
                    "body_bytes": resp.body_bytes,
                    "duration_s": time.monotonic() - start,
                },
            )

            result: dict = {
                "run_id": run_id,
                "status": resp.status,
                "reason": resp.reason,
                "data": resp.data,
            }
            if resp.errors is not None:
                result["errors"] = resp.errors
            if resp.text is not None:
                result["text"] = resp.text
            return result

    if uploader is not None:
        # Beside /mcp on the same port (ADR-0020 decision A).
        send, status, pull = upload_endpoints(uploader, settings, tokens, audit, hosts_now)
        mcp_server.custom_route("/uploads", methods=["PUT"], include_in_schema=False)(send)
        mcp_server.custom_route("/upload-pull", methods=["GET"], include_in_schema=False)(pull)
        mcp_server.custom_route("/uploads/{request_key}", methods=["GET"], include_in_schema=False)(status)

    if enrollment is not None:
        # Beside /mcp on the same port, unauthenticated but for the one-time
        # code, so a machine can fetch its script and report back (ADR-0024 2a).
        mcp_server.custom_route("/enroll/{code}", methods=["GET", "POST"], include_in_schema=False)(
            enroll_endpoint(enrollment)
        )

    if exporter is not None:
        exports = exporter
        # Beside /mcp on the same port (ADR-0016 decision A). Starlette answers
        # HEAD on a GET route.
        mcp_server.custom_route("/exports/{export_id}", methods=["GET"], include_in_schema=False)(
            download_endpoint(exporter.store, tokens, audit, settings.switches_path)
        )

        @tool(name="export")
        async def export_tool(
            ctx: Context,
            request_key: str,
            host: str | None = None,
            remote_path: str | None = None,
            vmid: int | None = None,
            path: str | None = None,
            wait: float = DEFAULT_WAIT_SECONDS,
            action: Literal["create", "delete"] = "create",
            export_id: str | None = None,
        ) -> dict:
            """Copy one file from a host or a VM into nervus, for you to download
            to your own machine. Give either `host` and `remote_path` (read over
            SFTP, where your token may reach the host) or `vmid` and `path`
            (where your token may reach the Proxmox host: read over SFTP, the VM
            enrolled first if it is not yet, or through Proxmox's guest agent,
            much more slowly, if it cannot be). `route` in the answer says which.
            `request_key` is yours to choose, letters, digits, '.', '_', ':' or '-':
            calling again with the same key returns the same export, to wait for
            it or to retry, and never copies twice. A new file needs a new key.

            The call waits up to `wait` seconds (at most 55). The answer's
            `state` is `measuring` or `staging` (call again), `ready` (download
            it), or `failed` (see `failure`). A ready export has `size`, `sha256`,
            `download_path` and `expires_at`, 24 hours on. Download it with your
            own token in the Authorization header, never in the URL, from
            http://<nervus>:8000<download_path>; `curl -C -` resumes a download
            that was cut off. Check the file's SHA-256 against `sha256` before
            using it. One file is at most 256 MiB; archive a directory first.
            `action: "delete"` with `export_id` deletes one of yours early."""
            token = require_token(ctx.headers, tokens)

            if action == "delete":
                run_id = audit.record_intent("export", {**attribution(token), "action": "delete",
                                                        "export_id": export_id})
                deleted = exports.delete(token.id, export_id or "")
                audit.record_result(run_id, "export", {"deleted": deleted})
                return {"run_id": run_id, "export_id": export_id, "deleted": deleted}

            def refuse(reason: str, **fields) -> None:
                audit.record_refusal("export", {**attribution(token), "request_key": request_key,
                                                **fields, "reason": reason})
                raise ToolError(reason)

            if host is not None and vmid is None and path is None and remote_path:
                request = HostRequest(
                    _authorized_host(audit=audit, tool="export", token=token, host=host,
                                     hosts=hosts_now()),
                    remote_path,
                )
            elif vmid is not None and path and host is None and remote_path is None:
                try:
                    require_proxmox_host(token, proxmox_host)
                except (AuthError, ProxmoxError) as exc:
                    refuse(str(exc), host=proxmox_host, vmid=vmid, path=path)
                if not exports.vms:
                    refuse("VM exports need nervus's Proxmox settings, which this nervus does not have",
                           vmid=vmid, path=path)
                request = VMRequest(vmid, path)
            else:
                refuse("give either host and remote_path, or vmid and path",
                       host=host, remote_path=remote_path, vmid=vmid, path=path)
            try:
                exports.check(token.id, request_key, request)
            except ExportRefused as exc:
                refuse(exc.message, source=request.describe())

            run_id = audit.record_intent("export", {**attribution(token), "request_key": request_key,
                                                    "source": request.describe()})
            # The copy runs as a task of its own and carries this call (ADR-0025).
            certs.acting_for(token.id, run_id)
            status = await exports.export(token.id, request_key, request, run_id, wait)
            if not status.created:
                audit.record_result(run_id, "export", export_fields(status.export) if status.export
                                    else {"state": MEASURING})
            return export_response(status, request_key, run_id,
                                   exports.store.route(status.export.id) if status.export else None)

    return mcp_server
