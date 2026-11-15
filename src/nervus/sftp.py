from __future__ import annotations

import errno
import os
import posixpath
import secrets
import stat
from pathlib import Path

import asyncssh

# Read and written this much at a time between nervus's file and the machine's. asyncssh splits
# each into parallel requests of its own, so a transfer keeps many in flight.
_CHUNK = 8 * 1024 * 1024


class TransferPathError(Exception):
    """A transfer named a path outside the configured transfer directory, or one nervus will not
    open there: a symbolic link at any step below it, or something other than a regular file."""


def resolve_transfer_path(transfer_dir: Path, local_path: str) -> Path:
    """Resolve `local_path` inside `transfer_dir`, refusing anything outside.

    Without this, `put` took an arbitrary path on nervus's own filesystem and
    sent that file to a target host -- which made the fleet private key and
    the token file exfiltrable by any authenticated client, directly against
    ADR-0001 section 2's "No agent ever holds an SSH key". `get` was the
    mirror image: an arbitrary write, and the audit log is the one path the
    hardened unit leaves writable.

    Containment is checked on where the path *lands*, not on how it was
    spelled. Both sides are fully resolved first, so a symlink inside the
    transfer directory pointing at ``/opt/nervus/secrets`` escapes nothing --
    resolution follows it and the result fails the check. String checks like
    rejecting ``..`` would not: they miss symlinks entirely.

    A relative path is taken as relative to the transfer directory. An
    absolute path is allowed only if it already lands inside it.
    """
    base = Path(transfer_dir).resolve()
    given = Path(local_path)
    candidate = (given if given.is_absolute() else base / given).resolve()
    if candidate != base and base not in candidate.parents:
        raise TransferPathError(
            f"local path {local_path!r} resolves outside the transfer directory "
            f"{str(base)!r}; file transfer is confined to that directory"
        )
    return candidate


# What open(2) gives for a symbolic link under O_NOFOLLOW: ELOOP on Linux and macOS, EMLINK on
# FreeBSD, and ENOTDIR where the step is opened as a folder (O_DIRECTORY).
_LINK_ERRNOS = frozenset({errno.ELOOP, errno.EMLINK, errno.ENOTDIR})


def _step(name: str, flags: int, folder: int | None, shown: str, mode: int = 0o666) -> int:
    """Open one step of a path, relative to the folder before it, following no symbolic link
    there; a link refused is named as one, not as the error number open gave."""
    try:
        return os.open(name, flags | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=folder)
    except OSError as exc:
        if exc.errno in _LINK_ERRNOS:
            try:
                is_link = stat.S_ISLNK(os.stat(name, dir_fd=folder, follow_symlinks=False).st_mode)
            except OSError:
                is_link = False
            if is_link:
                raise TransferPathError(f"{shown} is a symbolic link, and nervus follows none in its transfer "
                                        "directory; nothing was transferred") from None
        raise


def open_in_transfer_dir(transfer_dir: Path, path: Path, flags: int, mode: int = 0o666) -> int:
    """Open `path`, which resolve_transfer_path found inside `transfer_dir`, and return its
    descriptor.

    The check resolves every symbolic link to see where the path lands, and the file is opened
    later. A link swapped in between, at the file's own name or at any folder above it, would be
    followed by a plain open, so `put` could read, and `get` write, a file outside the transfer
    directory: seen on the Mac with each of the four (procedure 056, C4). So this opens the transfer
    directory, then each step below it in turn, each relative to the one before and none following
    a symbolic link. A link swapped in anywhere below the transfer directory is refused, not
    followed. Only a process running as nervus can swap one in, and such a process holds nervus's
    keys already (ADR-0007 decisions 2 and 9), so this is defence in depth.

    The file must be a regular one, opened without waiting (O_NONBLOCK) so that a named pipe at the
    name is refused rather than holding the call until something writes to it.
    """
    base = Path(transfer_dir).resolve()
    try:
        parts = Path(path).relative_to(base).parts
    except ValueError:
        raise TransferPathError(f"{str(path)!r} is not inside the transfer directory {str(base)!r}") from None
    if not parts:
        raise TransferPathError(f"{str(path)!r} is the transfer directory itself, not a file in it")
    folder = _step(str(base), os.O_RDONLY | os.O_DIRECTORY, None, f"the transfer directory {str(base)!r}")
    try:
        for depth, name in enumerate(parts[:-1], start=1):
            inner = _step(name, os.O_RDONLY | os.O_DIRECTORY, folder, repr("/".join(parts[:depth])))
            os.close(folder)
            folder = inner
        fd = _step(parts[-1], flags | os.O_NONBLOCK, folder, repr("/".join(parts)), mode)
    finally:
        os.close(folder)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise TransferPathError(f"{'/'.join(parts)!r} in the transfer directory is not a regular file")
    return fd


async def put_file(
    conn: asyncssh.SSHClientConnection,
    local_path: str | Path,
    remote_path: str,
    *,
    transfer_dir: Path,
) -> None:
    """Copy a file from nervus's transfer directory to the target over SFTP, so the destination
    holds either the old file or the whole new one, never part of one (ADR-0020 decision I):
    written under a temporary name beside it, then renamed over it. A copy that fails leaves the
    temporary file removed. nervus's file is opened by open_in_transfer_dir, following no link."""
    temporary = posixpath.join(posixpath.dirname(remote_path), f".nervus-put-{secrets.token_hex(8)}.part")
    with os.fdopen(open_in_transfer_dir(transfer_dir, Path(local_path), os.O_RDONLY), "rb") as source:
        async with conn.start_sftp_client() as sftp:
            try:
                async with sftp.open(temporary, "wb") as target:
                    while chunk := source.read(_CHUNK):
                        await target.write(chunk)
                await sftp.posix_rename(temporary, remote_path)
            except BaseException:
                try:
                    await sftp.remove(temporary)
                except (asyncssh.Error, OSError):
                    pass
                raise


async def get_file(
    conn: asyncssh.SSHClientConnection,
    remote_path: str,
    local_path: str | Path,
    *,
    transfer_dir: Path,
) -> None:
    """Copy a file from the target to nervus's transfer directory over SFTP. The machine's file is
    opened and checked first, so one that is not a regular file leaves nervus's untouched; a link
    there is the machine's own to follow, so its file's bytes arrive, never a link. nervus's file is
    opened by open_in_transfer_dir, following no link."""
    async with conn.start_sftp_client() as sftp:
        async with sftp.open(remote_path, "rb") as source:
            permissions = (await source.stat()).permissions
            if permissions is not None and not stat.S_ISREG(permissions):
                raise asyncssh.SFTPFailure(f"{remote_path!r} on the machine is not a regular file")
            fd = open_in_transfer_dir(transfer_dir, Path(local_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
            with os.fdopen(fd, "wb") as target:
                while chunk := await source.read(_CHUNK):
                    target.write(chunk)
