"""The SSH certificate nervus signs for each connection (ADR-0025).

Every machine sees nervus as one account and one key, so its own `sshd`
journal cannot tell clients apart. A certificate carries a free-text key ID,
which `sshd` writes into the journal at login, before any command runs:

    Accepted publickey for agent from ... ED25519-CERT SHA256:... ID token=<id> run=<run> (serial <n>) CA ...

So nervus signs one for every connection it makes on a client's call, naming
the token and the run the audit log has just recorded (decision 1). A command
cannot forge that line; only whoever holds the CA key can.

The certificate carries no forced command and no permissions (decision 1):
what a machine allows stays in its own `authorized_keys` line. nervus only
ever runs a command or SFTP, neither of which needs a terminal, forwarding or
`~/.ssh/rc`. It is valid from five minutes before signing to five after
(question 2a): OpenSSH checks the window only at login, so a long command is
unaffected, and a machine whose clock is a little behind still accepts it.

nervus offers its plain key after the certificate (question 1a), so a machine
not yet moved to a `cert-authority` line still accepts nervus, as before.

Which call a connection belongs to is set once, by `acting_for`, right after
the call's intent record, and read by `nervus.ssh.connect`. It is a context
variable, so the background work a call starts (an export's copy, an upload's
delivery) carries the call that started it, and two calls at once never see
each other's.

The same variable carries to the call's result record what nervus did to a VM
on the call's way that the call did not ask for: enrolled it on first use, or
repaired its enrollment (ADR-0022 decisions 2a and 5a). Whoever does it says so
with `note`, and the result record reads `vm_note`, as it reads `ssh_ports`. So
the enrollment is in the audit log under the run that caused it whatever then
becomes of the call, and for work that answers its client before it ends
(ADR-0001 section 10; procedure 056).
"""

from __future__ import annotations

import secrets
import time
import urllib.parse
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path

import asyncssh

from nervus import plainfile
from nervus.config import ConfigError, require_private_file

# Question 2a: five minutes either side of signing.
WINDOW_SECONDS = 5 * 60

# Decision 1: the key ID is nervus-made and of a fixed alphabet, so no client
# can put text of its own into a machine's log. A run id is a uuid4 nervus
# made; a token id is the operator's, from the UI (database.TOKEN_ID) or the
# token file, which checks none. Anything outside this alphabet is
# percent-encoded, so the id stays readable and the line stays one of nervus's.
_SAFE = "._-"


def _word(value: str) -> str:
    return urllib.parse.quote(value, safe=_SAFE)


@dataclass
class Caller:
    """The call a connection is made for: the token and the run that the audit
    log's intent record names. `ports` collects the local port of each SSH
    connection made for it (decision 3), for the call's result record; `notes`
    what nervus did to a VM on its way, for the same record.

    No token is nervus's own work for its operator, which the audit record
    attributes to `actor: operator`: checking a machine just added from its
    page. Its key ID says `operator`, as the operator chose on 2026-10-27; a
    client's always says `token=`, so the two cannot be confused."""

    token_id: str | None
    run_id: str
    ports: list[int] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def key_id(self) -> str:
        """`token=<id> run=<run>`, the words decision 2's label line uses too;
        `operator run=<run>` for nervus's own work for its operator."""
        who = "operator" if self.token_id is None else f"token={_word(self.token_id)}"
        return f"{who} run={_word(self.run_id)}"


_caller: ContextVar[Caller | None] = ContextVar("nervus_caller", default=None)


def acting_for(token_id: str | None, run_id: str) -> Caller:
    """Mark everything this task does from here on, and every task it starts,
    as done for this call; `token_id` None for the operator's. Returns the
    Caller, whose `ports` the result record reads."""
    caller = Caller(token_id, run_id)
    _caller.set(caller)
    return caller


def current() -> Caller | None:
    return _caller.get()


def label() -> str | None:
    """The words of decision 2's label line for this call, the certificate's
    key ID; None outside a call."""
    caller = current()
    return caller.key_id() if caller is not None else None


def ssh_ports() -> dict:
    """`ssh_ports` for a result record: the local port of every SSH connection
    this call made, in order (decision 3). Nothing when it made none."""
    caller = current()
    return {"ssh_ports": list(caller.ports)} if caller is not None and caller.ports else {}


def note(text: str | None) -> None:
    """Keep, for this call's result record, what nervus did to a VM on the
    call's way. Nothing to keep, or no call to keep it for, keeps nothing."""
    caller = current()
    if text and caller is not None:
        caller.notes.append(text)


def vm_note() -> dict:
    """`vm_note` for a result record: what was noted for this call, in order.
    Nothing when nothing was."""
    caller = current()
    return {"vm_note": "; ".join(caller.notes)} if caller is not None and caller.notes else {}


class CertificateAuthority:
    """nervus's CA key, read once at start-up (question 1a): made by the
    installer beside nervus's SSH key and kept as it is, `0600` and readable by
    nervus alone. No tool, page or transfer path reads it (ADR-0007
    decision 7); it lives with the other secrets."""

    def __init__(self, path: Path):
        require_private_file(path)
        try:
            self._key = asyncssh.import_private_key(plainfile.read_bytes(path))
        except (OSError, asyncssh.KeyImportError) as exc:
            raise ConfigError(f"cannot read nervus's SSH certificate authority key {path}: {exc}") from exc
        self.path = path

    def public_key(self) -> str:
        """The CA's public key as an `authorized_keys` line takes it after
        `cert-authority` and the level's options (decision 4)."""
        return " ".join(self._key.export_public_key("openssh").decode().split()[:2]) + " nervus-ca"

    def sign(self, key: asyncssh.SSHKey, username: str, caller: Caller,
             now: float | None = None) -> asyncssh.SSHCertificate:
        """A certificate for `key`, naming `username` and `caller`, valid from
        WINDOW_SECONDS before `now` to WINDOW_SECONDS after."""
        signed = int(time.time() if now is None else now)
        return self._key.generate_user_certificate(
            key, caller.key_id(),
            principals=[username],
            serial=secrets.randbits(63),
            valid_after=signed - WINDOW_SECONDS,
            valid_before=signed + WINDOW_SECONDS,
            force_command=None,
            source_address=None,
            permit_x11_forwarding=False,
            permit_agent_forwarding=False,
            permit_port_forwarding=False,
            permit_pty=False,
            permit_user_rc=False,
        )
