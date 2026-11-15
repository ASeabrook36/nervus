"""Where an upload's file goes (ADR-0020 decisions B, C, D and E): the
deliverers the upload route hands a received, checked file to.

Every delivery has the same three parts, whatever the target:

1. **Check first**, before any byte moves: the directory exists, and the
   destination is either absent or, with `replace=1`, a regular file
   (decision C). Done again at the end, since the target may change meanwhile.
2. **Write under a temporary name in the same directory**,
   `.nervus-upload-<upload id>.part`, so the name says whose it is and a
   rename can put it in place atomically.
3. **Hash it there, then rename it**, in one script run on the target: the
   file is put in place only if the target's own SHA-256 of what it wrote is
   the one the client declared (decision B). Without `replace=1`, a hard link
   puts it in place, which fails rather than replace a file that appeared
   meanwhile. The script prints the size and hash, which the store checks
   again before recording the upload delivered.

A host is written to over SFTP as its agent account (decision D). With
`root=1` the file goes first to the agent account's own temporary file, then
one fixed script run with `sudo -n` installs it beside the destination, hashes
it and renames it. The host's sudo decides, as for `exec`.

The destination path is the target's business (ADR-0016 G1). nervus never
puts it in a command line: every script is fixed, and paths reach it as
arguments, quoted for the shell that runs it.
"""

from __future__ import annotations

import asyncio
import base64
import functools
import posixpath
import re
import shlex
import sys
from collections.abc import Awaitable, Callable
from pathlib import Path

import anyio
import asyncssh

from nervus import certs, plainfile
from nervus.config import Host
from nervus.enroller import EnrollmentFailed
from nervus.uploads import Upload, UploadRefused, UploadStore

MiB = 1024 * 1024
WRITE_BYTES = 1 * MiB
PROGRESS_EVERY = 8 * MiB
# How long a target may take to hash and rename: 256 MiB is seconds.
SCRIPT_TIMEOUT = 300.0

CHECK_SCRIPT = (
    'dest=$1 replace=$2 writable=$3\n'
    'dir=$(dirname -- "$dest")\n'
    '[ -d "$dir" ] || { echo "no such directory: $dir" >&2; exit 3; }\n'
    'if [ -e "$dest" ] || [ -L "$dest" ]; then\n'
    '  [ "$replace" = 1 ] || { echo "$dest exists" >&2; exit 4; }\n'
    '  { [ -f "$dest" ] && [ ! -L "$dest" ]; } || { echo "$dest is not a regular file" >&2; exit 5; }\n'
    'fi\n'
    'if [ "$writable" = 1 ] && [ ! -w "$dir" ]; then echo "cannot write in $dir as $(id -un)" >&2; exit 8; fi\n'
    'exit 0\n'
)

FINISH_SCRIPT = (
    'tmp=$1 dest=$2 mode=$3 replace=$4 expected=$5 src=$6\n'
    'fail() { rm -f "$tmp"; [ -z "$src" ] || rm -f "$src"; echo "$2" >&2; exit "$1"; }\n'
    'if [ -n "$src" ]; then\n'
    '  install -m "${mode:-0644}" "$src" "$tmp" || fail 9 "could not write $tmp"\n'
    '  rm -f "$src"\n'
    'elif [ -n "$mode" ]; then\n'
    '  chmod "$mode" "$tmp" || fail 9 "could not set mode $mode"\n'
    'fi\n'
    'size=$(wc -c < "$tmp") || fail 10 "cannot read $tmp"\n'
    'hash=$(sha256sum < "$tmp") || fail 10 "cannot hash $tmp"\n'
    'hash=${hash%% *}\n'
    '[ "$hash" = "$expected" ] || fail 6 "what was written hashes to $hash, not $expected"\n'
    'if [ "$replace" = 1 ]; then\n'
    '  if [ -e "$dest" ] || [ -L "$dest" ]; then\n'
    '    { [ -f "$dest" ] && [ ! -L "$dest" ]; } || fail 5 "$dest is not a regular file"\n'
    '  fi\n'
    '  mv -f "$tmp" "$dest" || fail 11 "could not rename $tmp to $dest"\n'
    'else\n'
    '  if ! ln "$tmp" "$dest"; then\n'
    '    if [ -e "$dest" ] || [ -L "$dest" ]; then fail 4 "$dest exists"; fi\n'
    '    fail 11 "could not put $tmp in place as $dest"\n'
    '  fi\n'
    '  rm -f "$tmp"\n'
    'fi\n'
    'echo "$size $hash"\n'
)

# What each script's exit status means, for the client.
CODES = {
    3: ("no_directory", ""),
    4: ("exists", "; send replace=1 to replace it"),
    5: ("not_a_file", ""),
    6: ("destination_hash", "; nothing was left in place"),
    8: ("not_writable", "; send root=1 to write it as root"),
    9: ("cannot_write", ""),
    10: ("cannot_hash", "; nervus puts a file in place only once the target has hashed it"),
    11: ("cannot_rename", ""),
}
_DONE = re.compile(r"\s*(\d+)\s+([0-9a-f]{64})\s*$")


def _console(line: str) -> None:
    print(f"nervus: {line}", file=sys.stderr, flush=True)


def temp_path(dest: str, upload_id: str) -> str:
    """The temporary name beside the destination."""
    return posixpath.join(posixpath.dirname(dest), f".nervus-upload-{upload_id}.part")


def agent_temp_path(upload_id: str) -> str:
    """Where the agent account writes a file that root then installs."""
    return f"/tmp/.nervus-upload-{upload_id}.part"


def flag(value: bool) -> str:
    return "1" if value else "0"


# A machine enrolled below full has no sudo for nervus (ADR-0024 decision 1),
# so a refused write there says its level, never to send root=1.
LEVEL_HINTS = {
    "read-only": "; {host} is read-only: its owner chose that nervus changes nothing there",
    "standard": "; {host} is standard: nervus writes only where agent may, and has no sudo for root=1",
}


def script_failure(code: int | None, err: str, where: str, *, root: bool = False, level: str | None = None,
                   host: str = "this machine") -> UploadRefused:
    """A script's exit status as a refusal the client can act on. `level` is
    an enrolled machine's, None for one described by hand."""
    detail = (err or "").strip()[:500]
    below_full = LEVEL_HINTS.get(level or "", "").format(host=host)
    if code in CODES:
        name, hint = CODES[code]
        if name == "not_writable" and below_full:
            hint = below_full
        return UploadRefused(name, f"{where}: {detail}{hint}")
    if root and "sudo" in detail:
        return UploadRefused("sudo_refused", f"{where}: {detail}" + (
            below_full or "; this host's agent account cannot write as root"))
    return UploadRefused("destination_error", f"{where}: exit {code}: {detail}")


def parse_done(out: str, where: str) -> str:
    """The SHA-256 the finishing script printed."""
    match = _DONE.match(out or "")
    if match is None:
        raise UploadRefused("destination_error", f"{where}: the target did not report what it wrote: {out[:200]!r}")
    return match.group(2)


# --- a host, over SSH -------------------------------------------------------------


class HostDelivery:
    """Puts an upload in place on a host, as its agent account, or as root
    through sudo with `root=1`."""

    # How root is asked for. Tests replace it, having no sudo to run.
    SUDO: tuple[str, ...] = ("sudo", "-n")

    def __init__(self, store: UploadStore, hosts: dict[str, Host] | Callable[[], dict[str, Host]],
                 connect: Callable[[Host], Awaitable[asyncssh.SSHClientConnection]]):
        self.store = store
        # The inventory now, enrolled machines included (ADR-0024): a dict, or
        # something that returns one at each delivery.
        self.hosts = hosts
        self.connect = connect

    def _host(self, upload: Upload) -> Host:
        host = (self.hosts() if callable(self.hosts) else self.hosts).get(upload.destination["host"])
        if host is None:
            raise UploadRefused("not_allowed", f"host {upload.destination['host']!r} is no longer in the inventory")
        return host

    @staticmethod
    def _paths(upload: Upload, root: bool) -> tuple[str, str | None]:
        """The temporary file beside the destination, and, as root, the
        agent account's own temporary file it is installed from."""
        return temp_path(upload.destination["path"], upload.id), (agent_temp_path(upload.id) if root else None)

    async def _run(self, conn, script: str, args: list[str], root: bool):
        command = shlex.join([*(self.SUDO if root else ()), "sh", "-c", script, "sh", *args])
        try:
            return await conn.run(command, timeout=SCRIPT_TIMEOUT)
        except asyncssh.TimeoutError as exc:
            raise UploadRefused("destination_error", f"the target took over {SCRIPT_TIMEOUT:.0f} s") from exc

    async def __call__(self, upload: Upload) -> tuple[str, str]:
        host = self._host(upload)
        conn = await self.connect(host)
        try:
            return await self.deliver(conn, upload, f"{host.name}:{upload.destination['path']}",
                                      upload.destination["root"], level=host.level, host=host.name)
        finally:
            conn.close()

    async def deliver(self, conn, upload: Upload, where: str, root: bool, *, level: str | None = None,
                      host: str = "this machine") -> tuple[str, str]:
        """Check, send over SFTP, hash and rename, over an open connection: a
        host's, or an enrolled VM's, which is always written as root, as its
        guest agent writes (ADR-0022 7a). Returns the route and the hash.
        `level` is an enrolled host's (ADR-0024), for what a refusal says."""
        d = upload.destination
        tmp, source = self._paths(upload, root)
        refused = functools.partial(script_failure, where=where, root=root, level=level, host=host)
        checked = await self._run(conn, CHECK_SCRIPT, [d["path"], flag(d["replace"]), flag(not root)], root)
        if checked.exit_status != 0:
            raise refused(checked.exit_status, str(checked.stderr or ""))
        try:
            try:
                await self._send(conn, upload, source or tmp)
            except asyncssh.SFTPPermissionDenied as exc:
                # A read-only machine's SFTP server refuses every write (-R).
                raise refused(8, f"the machine refused the write: {exc.reason}") from None
            done = await self._run(conn, FINISH_SCRIPT, [tmp, d["path"], d["mode"] or "", flag(d["replace"]),
                                                         upload.sha256, source or ""], root)
        except BaseException:
            await self._remove(conn, upload, root)
            raise
        if done.exit_status != 0:
            raise refused(done.exit_status, str(done.stderr or ""))
        return ("sftp+sudo" if root else "sftp"), parse_done(str(done.stdout or ""), where)

    async def _send(self, conn, upload: Upload, remote: str) -> None:
        staged = self.store.open_staged(upload)
        sent = reported = 0
        try:
            async with conn.start_sftp_client() as sftp:
                # "x": created here, never an existing file; 0600 so no other local user
                # reads a secret during the write, before FINISH sets the asked-for mode
                # (procedure 056, C34).
                async with sftp.open(remote, "xb", attrs=asyncssh.SFTPAttrs(permissions=0o600)) as out:
                    while chunk := await anyio.to_thread.run_sync(staged.read, WRITE_BYTES):
                        await out.write(chunk)
                        sent += len(chunk)
                        if sent - reported >= PROGRESS_EVERY:
                            self.store.delivery_progress(upload.id, sent)
                            reported = sent
        finally:
            staged.close()

    async def _remove(self, conn, upload: Upload, root: bool) -> None:
        """Best effort: take away what a delivery that did not finish left."""
        tmp, source = self._paths(upload, root)
        try:
            with anyio.CancelScope(shield=True), anyio.move_on_after(30):
                await self._run(conn, 'rm -f "$1"', [tmp], root)
                if source:
                    await self._run(conn, 'rm -f "$1"', [source], False)
        except Exception as exc:
            _console(f"WARNING: could not remove upload {upload.id}'s temporary file: {exc}")

    async def cleanup(self, upload: Upload) -> None:
        """After a stop: remove what this upload's delivery may have left."""
        conn = await self.connect(self._host(upload))
        try:
            await self._remove(conn, upload, upload.destination["root"])
        finally:
            conn.close()


# --- a VM, through Proxmox's guest agent (decision E) --------------------------------

# Fetch the staged file from nervus into the temporary name. The one-time
# secret arrives on standard input, never as an argument. With $3 = 1,
# nervus's root follows it there (ADR-0022 8a): written to a temporary file
# for curl to check nervus's certificate against, and removed on every way
# out, so nothing of it stays in the VM. Exit 20: no curl; 21: the fetch
# failed. Either way nervus falls back to pushing the file.
PULL_SCRIPT = (
    'url=$1 tmp=$2 root=$3\n'
    'command -v curl >/dev/null 2>&1 || { echo "the VM has no curl" >&2; exit 20; }\n'
    'IFS= read -r secret || { echo "no secret on standard input" >&2; exit 21; }\n'
    'set --\n'
    'if [ "$root" = 1 ]; then\n'
    '  ca=$(mktemp "${TMPDIR:-/tmp}/nervus-root.XXXXXX") || { echo "cannot make a file for nervus\'s root" >&2; exit 21; }\n'
    '  trap \'rm -f "$ca"\' EXIT\n'
    '  cat > "$ca" || { echo "cannot write nervus\'s root" >&2; exit 21; }\n'
    '  set -- --cacert "$ca"\n'
    'fi\n'
    'set -C\n'
    ': > "$tmp" || { echo "cannot create $tmp" >&2; exit 9; }\n'
    'printf "X-Nervus-Upload-Secret: %s\\n" "$secret" | curl -fsS --connect-timeout 10 "$@" -H @- -o "$tmp" "$url" '
    '|| { rm -f "$tmp"; exit 21; }\n'
)
CREATE_SCRIPT = 'set -C\n: > "$1" || { echo "cannot create $1" >&2; exit 9; }\n'
APPEND_SCRIPT = 'base64 -d >> "$1" || exit 9\n'
REMOVE_SCRIPT = 'rm -f "$1"\n'
NO_CURL, FETCH_FAILED = 20, 21

# Through the guest agent: Proxmox takes at most 64 KiB of input-data a call,
# which is 48,000 bytes as base64 (procedure 026: about 0.17 MB/s).
PUSH_BYTES = 48_000
# Decision F: at that speed, 32 MiB is about 3 minutes.
MAX_PUSH_BYTES = 32 * MiB
# Waiting for a guest command: at once, then a little longer each time.
FIRST_POLL, MAX_POLL = 0.05, 0.5
# The whole of a pull: 256 MiB at the measured 36 MB/s is seconds.
PULL_TIMEOUT = 600.0


class VMDelivery:
    """Puts an upload in place in a VM, through the guest agent, which runs as
    root there. `api` is a ProxmoxClient, or anything with its `request`.
    `pull_url` is where a VM fetches a staged file from nervus, such as
    http://nervus.example:8000/upload-pull; without it, files are pushed.
    `pull_root` is the file holding nervus's root (ADR-0021), handed to the VM
    with each pull so it can check nervus's certificate (ADR-0022 8a). It is
    read at each pull, so a root `tls-init --upgrade` makes while nervus runs
    is used; while there is no such file, the VM's own trust store is."""

    def __init__(self, store: UploadStore, api, pull_url: str | None, *, pull_root: Path | None = None,
                 vm_connect=None, poll: float = FIRST_POLL, max_poll: float = MAX_POLL):
        self.store = store
        self.api = api
        self.pull_url = pull_url or None
        self.pull_root = pull_root
        # SSH to a VM by id for a token, enrolling it first if it needs it
        # (vm_targets.VMTargets.connect); without it, no SFTP route.
        self.vm_connect = vm_connect
        self.ssh = HostDelivery(store, {}, connect=None)
        self.poll = poll
        self.max_poll = max_poll

    async def _call(self, method: str, path: str, params: dict, where: str):
        resp = await self.api.request(method, path, params)
        if resp.status != 200:
            reason = f"{resp.reason} {resp.errors}" if resp.errors else resp.reason
            raise UploadRefused("destination_error", f"{where}: Proxmox answered {resp.status} {reason}")
        return resp.data

    async def _agent(self, vmid: int, where: str) -> str:
        """The VM's guest-agent path. A guest the token cannot see, or that is
        not a QEMU VM (a container has no guest agent), is refused."""
        guests = await self._call("GET", "/cluster/resources", {"type": "vm"}, where) or []
        match = [g for g in guests if isinstance(g, dict) and g.get("vmid") == vmid]
        if not match or match[0].get("type") != "qemu":
            raise UploadRefused("no_such_vm", f"no QEMU VM {vmid} that nervus's Proxmox token can see")
        return f"/nodes/{match[0]['node']}/qemu/{vmid}/agent"

    async def _sh(self, agent: str, where: str, script: str, args: list[str], *, stdin: str | None = None,
                  timeout: float = SCRIPT_TIMEOUT) -> tuple[int | None, str, str]:
        params: dict = {"command": ["sh", "-c", script, "sh", *args]}
        if stdin is not None:
            params["input-data"] = stdin
        started = await self._call("POST", f"{agent}/exec", params, where)
        pid = started.get("pid") if isinstance(started, dict) else None
        if not isinstance(pid, int):
            raise UploadRefused("destination_error", f"{where}: the guest agent started no command: {started!r}")
        waited, pause = 0.0, 0.0
        while True:
            if pause:
                await asyncio.sleep(pause)
                waited += pause
            status = await self._call("GET", f"{agent}/exec-status", {"pid": pid}, where)
            if isinstance(status, dict) and status.get("exited"):
                return status.get("exitcode"), str(status.get("out-data", "")), str(status.get("err-data", ""))
            if waited >= timeout:
                raise UploadRefused("destination_error", f"{where}: the guest command took over {timeout:.0f} s")
            pause = min(max(pause * 2, self.poll), self.max_poll)

    async def __call__(self, upload: Upload) -> tuple[str, str]:
        """The fastest route nervus has (ADR-0022 7a): the VM fetches the file
        from nervus; if it cannot, SFTP, the VM enrolled first if it needs it;
        if that cannot be either, pushed through the guest agent. Returns the
        route and the destination's own hash."""
        d = upload.destination
        where = f"VM {d['vmid']}:{d['path']}"
        if self.api is None:
            raise UploadRefused("no_proxmox", "VM uploads need nervus's Proxmox settings (--proxmox)")
        agent = await self._agent(d["vmid"], where)
        code, _, err = await self._sh(agent, where, CHECK_SCRIPT, [d["path"], flag(d["replace"]), "0"])
        if code != 0:
            raise script_failure(code, err, where)
        tmp = temp_path(d["path"], upload.id)
        why = "nervus has no address set for VMs to fetch from (--upload-pull-url)"
        if self.pull_url is not None:
            why = await self._guarded(agent, where, tmp, self._fetch(upload, agent, where, tmp))
            if why is None:
                return "pull", await self._finish(upload, agent, where, tmp)
        if self.vm_connect is not None:
            try:
                conn, _ = await self.vm_connect(d["vmid"], upload.token_id)
            except EnrollmentFailed as exc:
                if exc.code == "vm_gone":
                    raise UploadRefused("vm_gone", exc.message) from None
                # The attempt may have run the enrollment script in the VM, as root: it goes in
                # this upload's audit result, as an enrollment does (vm_targets.connect).
                certs.note(f"VM {d['vmid']} could not be enrolled or reached over SSH: {exc.message}")
                why = f"{why}; and not over SSH: {exc.message}"
            else:
                try:
                    return await self.ssh.deliver(conn, upload, where, root=True)
                finally:
                    conn.close()
        if upload.size > MAX_PUSH_BYTES:
            raise UploadRefused(
                "too_large_to_push",
                f"{where}: the VM could not fetch the file from nervus ({why}), and through the guest agent "
                f"at most {MAX_PUSH_BYTES} bytes are sent; give the VM a route to nervus, or a smaller file",
            )
        _console(f"upload {upload.id}: pushing through the guest agent: {why}")
        await self._guarded(agent, where, tmp, self._push(upload, agent, where, tmp))
        return "guest-agent", await self._finish(upload, agent, where, tmp)

    async def _guarded(self, agent: str, where: str, tmp: str, work):
        """Run `work`, removing the temporary file if it fails."""
        try:
            return await work
        except BaseException:
            await self._remove(agent, where, tmp)
            raise

    async def _finish(self, upload: Upload, agent: str, where: str, tmp: str) -> str:
        d = upload.destination
        code, out, err = await self._guarded(agent, where, tmp, self._sh(
            agent, where, FINISH_SCRIPT, [tmp, d["path"], d["mode"] or "", flag(d["replace"]), upload.sha256, ""]))
        if code != 0:
            raise script_failure(code, err, where)
        return parse_done(out, where)

    async def _fetch(self, upload: Upload, agent: str, where: str, tmp: str) -> str | None:
        """Have the VM fetch the file from nervus. None if it did; why not if
        it could not, so another route is tried."""
        root = self._root()
        secret = self.store.issue_pull_secret(upload)
        code, _, err = await self._sh(agent, where, PULL_SCRIPT, [self.pull_url, tmp, flag(root is not None)],
                                      stdin=secret + "\n" + (root or ""), timeout=PULL_TIMEOUT)
        if code == 0:
            self.store.delivery_progress(upload.id, upload.size)
            return None
        if code not in (NO_CURL, FETCH_FAILED):
            raise script_failure(code, err, where)
        return (err or "").strip()[:300] or f"exit {code}"

    def _root(self) -> str | None:
        """nervus's root as PEM text, or None while there is no such file."""
        if self.pull_root is None:
            return None
        try:
            return plainfile.read_text(self.pull_root)
        except FileNotFoundError:
            return None

    async def _push(self, upload: Upload, agent: str, where: str, tmp: str) -> None:
        code, _, err = await self._sh(agent, where, CREATE_SCRIPT, [tmp])
        if code != 0:
            raise script_failure(code, err, where)
        staged = self.store.open_staged(upload)
        sent = reported = 0
        try:
            while chunk := await anyio.to_thread.run_sync(staged.read, PUSH_BYTES):
                code, _, err = await self._sh(agent, where, APPEND_SCRIPT, [tmp],
                                              stdin=base64.b64encode(chunk).decode())
                if code != 0:
                    raise script_failure(code, err, where)
                sent += len(chunk)
                if sent - reported >= MiB:
                    self.store.delivery_progress(upload.id, sent)
                    reported = sent
        finally:
            staged.close()

    async def _remove(self, agent: str, where: str, tmp: str) -> None:
        try:
            with anyio.CancelScope(shield=True), anyio.move_on_after(30):
                await self._sh(agent, where, REMOVE_SCRIPT, [tmp])
        except Exception as exc:
            _console(f"WARNING: could not remove {where}'s temporary file {tmp}: {exc}")

    async def cleanup(self, upload: Upload) -> None:
        d = upload.destination
        where = f"VM {d['vmid']}:{d['path']}"
        if self.api is not None:
            agent = await self._agent(d["vmid"], where)
            await self._remove(agent, where, temp_path(d["path"], upload.id))
            await self._remove(agent, where, agent_temp_path(upload.id))  # SFTP's, as root installs it


# --- either ------------------------------------------------------------------------


class Deliveries:
    """The deliverer the uploader is given: hosts to one, VMs to the other."""

    def __init__(self, host: HostDelivery, vm: VMDelivery):
        self.host = host
        self.vm = vm

    def _for(self, upload: Upload):
        return self.host if upload.destination["kind"] == "host" else self.vm

    async def __call__(self, upload: Upload) -> tuple[str, str]:
        return await self._for(upload)(upload)

    async def cleanup(self, upload: Upload) -> None:
        await self._for(upload).cleanup(upload)
