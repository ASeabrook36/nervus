"""The off switch: which clients nervus refuses, re-read on every request.

ADR-0003, with the operator's answers of 2026-09-11, and ADR-0011 decision 2.
A plain file with no secrets in it:

    lockdown: false
    disabled:
      - codex-laptop

- lockdown: true refuses every client.
- disabled lists token ids refused one by one.
- It is read on every request, so a change applies to a client's next call,
  mid-session included, with no restart.
- A missing or malformed file refuses everything (ADR-0003, question A): a
  lock once set must never be undone by the file going missing.
  So does anything at its name that is not a file: a pipe put there is refused
  like any other unreadable file, and never waited on (nervus.plainfile).
- A refused client learns nothing about why (question B). The reason goes only
  to the audit log, which is where the operator reads it.
- The UI and nervus-ctl both change it, with change_switches(), one at a time
  (ADR-0014). Since 2026-10-12 it lives in nervus's state directory,
  /var/lib/nervus/switches.yaml, where nervus may write it (decision A).
"""

from __future__ import annotations

import contextlib
import fcntl
import os
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import yaml

from nervus import plainfile


@dataclass(frozen=True)
class Switches:
    lockdown: bool
    disabled: frozenset[str]


class SwitchesUnreadable(Exception):
    """The switches file is missing or malformed. Treat as: refuse everything."""


class SwitchesSwapped(SwitchesUnreadable):
    """The new copy of the switches file was swapped for something else while it
    was being written, so nothing was changed. The file's folder is nervus's
    account's, and nervus-ctl writes there as root: only a process of that
    account can do this."""


def load_switches(path: Path) -> Switches:
    """Read the switches file, or raise SwitchesUnreadable.

    Strict on purpose: only the two keys, lockdown a true/false value, disabled
    a list of token ids. Anything else means the file is not what the operator
    meant, and the safe reading of an uncertain lock is "locked". One leniency:
    `disabled:` left empty, as after deleting its last line, means no client is
    disabled, because "re-enabling is deleting a line" (ADR-0003 decision 3).
    """
    try:
        raw = yaml.safe_load(plainfile.read_text(path))
    except OSError as exc:
        raise SwitchesUnreadable(f"cannot read {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise SwitchesUnreadable(f"{path} is not valid YAML: {exc}") from exc
    if not isinstance(raw, dict) or set(raw) != {"lockdown", "disabled"}:
        raise SwitchesUnreadable(f"{path} must have exactly the keys lockdown and disabled")
    lockdown, disabled = raw["lockdown"], raw["disabled"]
    if not isinstance(lockdown, bool):
        raise SwitchesUnreadable(f"{path}: lockdown must be true or false, not {lockdown!r}")
    if disabled is None:
        disabled = []
    if not isinstance(disabled, list) or not all(isinstance(i, str) for i in disabled):
        raise SwitchesUnreadable(f"{path}: disabled must be a list of token ids")
    return Switches(lockdown=lockdown, disabled=frozenset(disabled))


def refusal(path: Path, token_id: str) -> str | None:
    """Why the switches refuse this token now, or None if they let it through."""
    try:
        switches = load_switches(path)
    except SwitchesUnreadable as exc:
        return f"switches unreadable, so everything is refused: {exc}"
    if switches.lockdown:
        return "lockdown"
    if token_id in switches.disabled:
        return "disabled"
    return None


def locked(path: Path) -> bool:
    """Whether nervus is locked down now: an unreadable file is a lock, as it is
    for clients. What refuses enrollment (ADR-0024 step 3)."""
    try:
        return load_switches(path).lockdown
    except SwitchesUnreadable:
        return True


def change_switches(path: Path, change: Callable[[Switches], Switches]) -> Switches:
    """Read the switches file, apply `change`, and write the result, as one
    step no other writer can come between (ADR-0014). Returns what was written.

    The UI and nervus-ctl are separate processes that both change the file.
    Each holds a lock on the file's folder from reading to writing, so one
    waits for the other and neither loses the other's change. The folder, not
    the file: the file is replaced on each write, and a lock on the old one
    would not stop a writer that opened the new one. Someone editing it by
    hand takes no lock, and needs none to be safe from nervus, which writes
    the whole file in one step.

    An unreadable file raises SwitchesUnreadable and is not changed: the
    operator fixes it by hand (ADR-0003, question A).
    """
    folder = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(folder, fcntl.LOCK_EX)
        new = change(load_switches(path))
        _write(path, new)
        return new
    finally:
        os.close(folder)  # and with it, the lock


def _write(path: Path, switches: Switches) -> None:
    """Replace the file in one step, keeping its owner and mode, so nervus never
    reads half a file.

    The new copy's owner and mode are set through its handle, and it is renamed
    only while its name still means it. The folder is nervus's account's and
    nervus-ctl writes here as root: a process of that account can swap the name
    for a link while root writes, and the name must never carry root's chmod and
    chown to what the link names (procedure 058)."""
    text = yaml.safe_dump({"lockdown": switches.lockdown, "disabled": sorted(switches.disabled)}, sort_keys=False)
    old = path.stat()
    fd, staging = tempfile.mkstemp(dir=path.parent, prefix=".switches.")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            with contextlib.suppress(PermissionError):  # only root can give a file away
                os.fchown(fd, old.st_uid, old.st_gid)
            os.fchmod(fd, old.st_mode & 0o777)
            os.fsync(fd)
            made = os.fstat(fd)
            try:
                named = os.lstat(staging)
            except FileNotFoundError:
                named = None
            if named is None or (named.st_dev, named.st_ino) != (made.st_dev, made.st_ino):
                raise SwitchesSwapped(
                    f"the new copy of {path} was swapped for something else while it was written, so nothing was "
                    f"changed; only a process running as the account that owns {path.parent} can do that")
            os.replace(staging, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(staging)
        raise
