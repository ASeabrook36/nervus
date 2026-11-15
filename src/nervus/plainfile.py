"""Opening one of nervus's files: a plain file, or a refusal that names what is
there instead. Never a wait.

nervus's settings, its secrets, the off switch and the audit log sit in folders
that nervus's own account owns. nervus-ctl reads the same names as root.
Whoever owns a folder can put a named pipe where a file was, and a plain open
of a pipe waits for the other end, which never comes: a command the operator
ran would sit there saying nothing. Opened to write, a pipe somebody is reading
takes what was meant for the file.

So nervus's own code opens these names here. The name is opened without
waiting, and what was opened is looked at before a byte is read or written: a
pipe, a folder, a socket or a device is refused as NotAFile, an OSError like
any other file that cannot be read, so each caller says it the way it says
those.

A link is followed, as before: an installation may keep a file elsewhere. What
is checked is what was opened, not its name, so a link to a pipe is a pipe.

Another program handed one of these names opens it itself, and waits as nervus
would have. So where that program will take the file's contents, or the file
already open, nervus reads or opens it here and hands that over: its SSH keys
and known_hosts, the Proxmox CA, a backup for age. The TLS library takes its
certificate and key by name only; both are looked at first (procedure 062).

What this is not: a defence against the account that owns the folder, which
can stop nervus in plainer ways. It makes the answer a sentence instead of a
silence (procedures 058 and 060).
"""

from __future__ import annotations

import errno
import os
import stat
from typing import IO

# Without waiting for a pipe's other end; and never taking a terminal a link
# might lead to as this process's own.
_NO_WAIT = os.O_NONBLOCK | os.O_NOCTTY | os.O_CLOEXEC


class NotAFile(OSError):
    """What is at a file's name is not a plain file."""


def kind(mode: int) -> str:
    """The word for what a mode says is there, when it is not a file."""
    for test, kind in ((stat.S_ISFIFO, "pipe"), (stat.S_ISDIR, "folder"), (stat.S_ISSOCK, "socket")):
        if test(mode):
            return kind
    return "device"


def _opened(path: str | os.PathLike, flags: int, how: str, **text) -> IO:
    try:
        fd = os.open(path, flags | _NO_WAIT, 0o666)
    except OSError as exc:
        if exc.errno != errno.ENXIO:
            raise
        # What open says of a socket, and of a pipe nobody reads that was to be written to.
        try:
            mode = os.stat(path).st_mode
        except OSError:
            raise exc from None
        if stat.S_ISREG(mode):  # it changed meanwhile: say what open said
            raise
        raise NotAFile(f"{os.fspath(path)} is a {kind(mode)}, not a file") from None
    try:
        mode = os.fstat(fd).st_mode
    except BaseException:
        os.close(fd)
        raise
    if not stat.S_ISREG(mode):
        os.close(fd)
        raise NotAFile(f"{os.fspath(path)} is a {kind(mode)}, not a file")
    return os.fdopen(fd, how, **text)


def open_file(path: str | os.PathLike) -> IO[bytes]:
    """The file at `path`, open to read its bytes."""
    return _opened(path, os.O_RDONLY, "rb")


def read_bytes(path: str | os.PathLike) -> bytes:
    with open_file(path) as f:
        return f.read()


def read_text(path: str | os.PathLike) -> str:
    """The file's text, read as pathlib's read_text() reads it."""
    with _opened(path, os.O_RDONLY, "r") as f:
        return f.read()


def open_to_append(path: str | os.PathLike, encoding: str = "utf-8") -> IO[str]:
    """The file at `path`, open to add text at its end, made if it is not there.
    A pipe nobody reads is refused by open itself; one somebody reads is opened,
    and refused here before anything is written to it."""
    return _opened(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, "a", encoding=encoding)
