"""Enrolling a VM through its guest agent (ADR-0022 decision 3a, step 2).

The guest agent is the trust anchor, as a person at the console is for a host.
Through it, as root in the VM, one fixed script:

- creates `agent` if it is missing, with exactly nervus's public key in its
  `authorized_keys`, and a sudoers file giving it passwordless `sudo`, checked
  by `visudo` before it is put in place (ADR-0001 s4);
- makes sure the SSH server is running, and waits for its host keys;
- prints the host public keys.

nervus then tries each address the guest agent reports, by SSH with strict
checking against those keys, **as the guest agent reported them, never as the
network offers them**, running `id -un; sudo -n id -un` and removing, through
`sudo`, a challenge the script left inside the VM (ADR-0022, amendment
2026-11-13). Only an address that answers `agent` then `root` and removes the
challenge is kept, and only then is the VM enrolled, pinned to the one host key
the server presented there. A server at a reported address with any other key
fails before nervus offers its own key (asyncssh verifies the server first). A
machine that is not this VM -- one whose keys the VM reported, at an address
the VM reported or behind a forwarder the VM runs -- cannot remove the
challenge, so a VM that reports another machine's keys or address gains
nothing; and a key the VM merely listed is never pinned, so it cannot later
forward its SSH port to that machine either.

The script changes nothing nervus relies on if it fails part-way: each file is
written beside its place and renamed in, and the sudoers line is checked first.
Run again, it does the same, so a retry (ADR-0022, question 3's note) is safe.

Nothing here is remembered on failure: the next call tries again.
"""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import Awaitable, Callable
from pathlib import Path

import asyncssh

from nervus import ssh
from nervus.certs import CertificateAuthority
from nervus.enrollments import EnrolledVM, EnrollmentRefused, EnrollmentStore, host_keys, reachable
from nervus.guest import Guest, GuestError

# ADR-0001 s4: the account nervus authenticates as, on every target.
AGENT_USER = "agent"
CHECK_COMMAND = "id -un; sudo -n id -un"
# The challenge's file, under the VM's /run, and the word the check says once it
# has removed it (ADR-0022, amendment 2026-11-13).
CHALLENGE_PREFIX = "nervus-enroll-"
CHALLENGE_HELD = "challenge-held"


def challenge_command(path: str) -> str:
    """The check, then the proof that the machine answering is this VM: removing,
    as root, the file the guest agent left in it. Only the machine holding it can;
    `rm` without -f fails where it is missing, and nothing is echoed."""
    return f"{CHECK_COMMAND}; sudo -n rm -- {path} && echo {CHALLENGE_HELD}"
# One address that does not answer costs this much, then the next is tried.
SSH_CONNECT_SECONDS = 10.0
CHECK_SECONDS = 20.0
# A VM that has just booted may not have made its host keys yet.
HOST_KEY_WAIT_SECONDS = 30
SCRIPT_TIMEOUT = 90.0
MARKER = "nervus-host-keys"

# $1 nervus's CA public key, one line, written after `cert-authority` (ADR-0025
# decision 4: agent trusts certificates nervus signs); $2 the sudoers directory; $3 the SSH
# server's directory; $4 how many seconds to wait for its host keys; $5 the directory
# for the challenge, root's alone (/run); $6 the challenge, 32 hex digits nervus chose.
# Exits 30 to 35 name what is missing; nervus passes the message on.
ENROLL_SCRIPT = r'''key=$1 sudoers=$2 ssh_dir=$3 wait=$4 run_dir=$5 challenge=$6
fail() { code=$1; shift; echo "$*" >&2; exit "$code"; }
umask 077
if ! id -u agent >/dev/null 2>&1; then
  command -v useradd >/dev/null 2>&1 || fail 30 "the VM has no agent account and no useradd to make one"
  useradd -m -s /bin/sh agent || fail 30 "useradd could not make the agent account"
fi
home=$(getent passwd agent | cut -d: -f6)
[ -n "$home" ] && [ -d "$home" ] || fail 30 "the agent account has no home directory"
mkdir -p "$home/.ssh" || fail 31 "cannot make $home/.ssh"
tmp="$home/.ssh/.authorized_keys.nervus"
# Written under `set -C` (noclobber), so a symlink the agent account may plant at this
# staging name is never followed: the write fails closed (procedure 056, C32).
rm -f "$tmp"
( set -C; printf 'cert-authority %s\n' "$key" > "$tmp" ) || fail 31 "cannot write agent's authorized_keys"
chown agent: "$home/.ssh" "$tmp" && chmod 700 "$home/.ssh" && chmod 600 "$tmp" \
  || { rm -f "$tmp"; fail 31 "cannot give agent its authorized_keys"; }
mv -f "$tmp" "$home/.ssh/authorized_keys" || { rm -f "$tmp"; fail 31 "cannot put agent's authorized_keys in place"; }
command -v sudo >/dev/null 2>&1 && command -v visudo >/dev/null 2>&1 || fail 32 "the VM has no sudo"
[ -d "$sudoers" ] || fail 32 "the VM has no $sudoers"
tmp="$sudoers/.nervus-agent"
rm -f "$tmp"
printf 'agent ALL=(ALL) NOPASSWD: ALL\n' > "$tmp" && chmod 440 "$tmp" || { rm -f "$tmp"; fail 32 "cannot write the sudoers line"; }
visudo -cqf "$tmp" || { rm -f "$tmp"; fail 32 "visudo refused the sudoers line"; }
mv -f "$tmp" "$sudoers/nervus-agent" || { rm -f "$tmp"; fail 32 "cannot put the sudoers line in place"; }
if command -v systemctl >/dev/null 2>&1; then
  systemctl is-active --quiet ssh || systemctl is-active --quiet sshd \
    || systemctl start ssh 2>/dev/null || systemctl start sshd 2>/dev/null \
    || fail 33 "cannot start the SSH server"
fi
i=0
while ! ls "$ssh_dir"/ssh_host_*_key.pub >/dev/null 2>&1; do
  [ "$i" -ge "$wait" ] && fail 34 "the SSH server has no host keys in $ssh_dir"
  sleep 1
  i=$((i + 1))
done
# The challenge (ADR-0022, amendment 2026-11-13): an empty root-only file named for it, made
# exclusively, so nothing already at that name is followed or reused. The SSH check removes it
# through sudo; a machine that is not this VM cannot, whatever host keys it shows.
case $challenge in *[!0-9a-f]*|'') fail 35 "the challenge is not one nervus makes" ;; esac
[ "${#challenge}" -eq 32 ] || fail 35 "the challenge is not one nervus makes"
[ -d "$run_dir" ] || fail 35 "the VM has no $run_dir for the challenge"
( set -C; : > "$run_dir/nervus-enroll-$challenge" ) || fail 35 "cannot leave the challenge in $run_dir"
echo nervus-host-keys
cat "$ssh_dir"/ssh_host_*_key.pub
'''


class EnrollmentFailed(Exception):
    """A VM that could not be enrolled, and why. The guest agent stays usable."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


# Opens SSH to `address` as agent, trusting only `host_keys`.
Connect = Callable[[str, tuple[str, ...]], Awaitable[asyncssh.SSHClientConnection]]


def known_hosts_lines(address: str, port: int, keys: tuple[str, ...]) -> str:
    """known_hosts text naming only `address` and only `keys`."""
    where = address if port == 22 else f"[{address}]:{port}"
    return "".join(f"{where} {key}\n" for key in keys)


def pinned_known_hosts(address: str, port: int, keys: tuple[str, ...]) -> asyncssh.SSHKnownHosts:
    return asyncssh.import_known_hosts(known_hosts_lines(address, port, keys))


def ssh_connector(key_path: Path, port: int = 22, timeout: float = SSH_CONNECT_SECONDS,
                  authority: CertificateAuthority | None = None) -> Connect:
    """The Connect nervus uses: its own key, the pinned keys, strict checking;
    with a certificate naming the call, on a client's call, when nervus has its
    CA (ADR-0025)."""
    def connect(address: str, keys: tuple[str, ...]):
        return ssh.connect(address=address, port=port, username=AGENT_USER, client_keys=[key_path],
                           known_hosts=pinned_known_hosts(address, port, keys), connect_timeout=timeout,
                           authority=authority)
    return connect


def parse_host_keys(out: str, where: str) -> tuple[str, ...]:
    """The keys printed after the marker, as the store keeps them."""
    lines = out.splitlines()
    if MARKER not in lines:
        raise EnrollmentFailed("cannot_enroll", f"{where}: the enrollment script printed no host keys")
    try:
        return host_keys([line for line in lines[lines.index(MARKER) + 1:] if line.strip()])
    except EnrollmentRefused as exc:
        raise EnrollmentFailed("cannot_enroll", f"{where}: {exc.message}") from None


class Enroller:
    def __init__(self, store: EnrollmentStore, public_key: str | Callable[[], str], connect: Connect, *,
                 sudoers_dir: str = "/etc/sudoers.d", ssh_dir: str = "/etc/ssh", run_dir: str = "/run",
                 host_key_wait: int = HOST_KEY_WAIT_SECONDS):
        self.store = store
        self.public_key = public_key
        self.connect = connect
        self.sudoers_dir = sudoers_dir
        self.ssh_dir = ssh_dir
        self.run_dir = run_dir
        self.host_key_wait = host_key_wait

    async def enroll(self, guest: Guest, token_id: str,
                     now: float | None = None) -> tuple[EnrolledVM, EnrolledVM | None]:
        """Enroll the VM: the script, the pin, the check, then the row.
        Returns the row and the one it replaced, or raises EnrollmentFailed."""
        where = f"VM {guest.vmid}"
        # Read when a VM is first enrolled, not at start: a key nervus cannot
        # read fails SSH everywhere, as it always did, without stopping nervus.
        try:
            key = self.public_key() if callable(self.public_key) else self.public_key
        except (OSError, asyncssh.KeyImportError) as exc:
            raise EnrollmentFailed("cannot_enroll", f"{where}: nervus cannot read its own SSH key: {exc}") from None
        # A fresh challenge each time, so two enrollments of one VM never share one.
        challenge = secrets.token_hex(16)
        try:
            code, out, err = await guest.sh(
                ENROLL_SCRIPT, [key, self.sudoers_dir, self.ssh_dir, str(self.host_key_wait), self.run_dir, challenge],
                timeout=SCRIPT_TIMEOUT,
            )
        except GuestError as exc:
            raise EnrollmentFailed(exc.code, exc.message) from None
        if code != 0:
            reason = (err or "").strip()[:300] or f"exit {code}"
            raise EnrollmentFailed("cannot_enroll", f"{where}: {reason}")
        keys = parse_host_keys(out, where)
        address, proven = await self._reach(guest, keys, challenge)
        # Only the key proven to be this VM's: one it merely listed is never trusted.
        return self.store.enroll(guest.vmid, address, (proven,), token_id, now=now)

    async def reach(self, guest: Guest, keys: tuple[str, ...]) -> str:
        """The first address the guest agent reports at which SSH answers with
        one of `keys` and the check passes: how a VM whose address moved is found.
        `keys` are an enrolled VM's pinned keys, proven to be its own when it was
        enrolled, so no new challenge is needed. Raises EnrollmentFailed, saying
        what each address did, if none does."""
        address, _ = await self._reach(guest, keys, None)
        return address

    async def _reach(self, guest: Guest, keys: tuple[str, ...], challenge: str | None) -> tuple[str, str]:
        """reach(), with the challenge when enrolling: the address, and the key
        the server presented there."""
        where = f"VM {guest.vmid}"
        try:
            candidates = [a for a in await guest.addresses() if reachable(a)]
        except GuestError as exc:
            raise EnrollmentFailed(exc.code, exc.message) from None
        if not candidates:
            raise EnrollmentFailed("unreachable", f"{where}: its guest agent reports no address nervus can reach")
        tried = []
        for address in candidates:
            why, presented = await self._check(address, keys, challenge, where)
            if why is None:
                return address, presented
            tried.append(f"{address}: {why}")
        raise EnrollmentFailed("unreachable", f"{where}: no address answered as it should ({'; '.join(tried)})")

    async def _check(self, address: str, keys: tuple[str, ...], challenge: str | None,
                     where: str) -> tuple[str | None, str]:
        """(None, the host key the server presented) if `address` is this VM: agent
        with root by sudo, and, given a challenge, holding it. Else (why not, "")."""
        try:
            conn = await self.connect(address, keys)
        except asyncssh.HostKeyNotVerifiable:
            return "another machine's host key", ""
        except asyncssh.PermissionDenied:
            return "it refused nervus's key", ""
        except (OSError, asyncio.TimeoutError, asyncssh.Error) as exc:
            return f"no SSH ({type(exc).__name__}: {str(exc)[:120]})", ""
        command = (CHECK_COMMAND if challenge is None
                   else challenge_command(f"{self.run_dir}/{CHALLENGE_PREFIX}{challenge}"))
        try:
            presented = _key_line(conn.get_server_host_key())
            result = await conn.run(command, check=False, timeout=CHECK_SECONDS)
        except (OSError, asyncio.TimeoutError, asyncssh.Error) as exc:
            return f"the check did not finish ({type(exc).__name__})", ""
        finally:
            conn.close()
        answered = str(result.stdout).split()
        if answered[:2] != [AGENT_USER, "root"]:
            return f"the check answered {answered[:2]!r}, not agent then root", ""
        if challenge is not None and (result.exit_status != 0 or answered[2:] != [CHALLENGE_HELD]):
            return (f"it answered as agent with root by sudo, but could not remove the challenge {where}'s "
                    "guest agent left in it, so it is not this VM"), ""
        if result.exit_status != 0 or (challenge is None and answered[2:]):
            return f"the check answered {answered!r}, exit {result.exit_status}, not agent then root", ""
        if presented not in keys:  # asyncssh accepts only a pinned key; never trust one it did not
            return "the host key it presented is not one its guest agent reported", ""
        return None, presented


def _key_line(key) -> str:
    """A host key as the store keeps it, "type base64"; for a certificate, its key."""
    if key is None:
        return ""
    if isinstance(key, asyncssh.SSHCertificate):
        key = key.key
    return " ".join(key.export_public_key().decode().split()[:2])
