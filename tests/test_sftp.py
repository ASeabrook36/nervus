from pathlib import Path

from nervus.sftp import get_file, put_file
from nervus.ssh import connect


async def _connect(ssh_server):
    return await connect(
        address=ssh_server.host,
        port=ssh_server.port,
        username=ssh_server.username,
        client_keys=[ssh_server.client_key_path],
        known_hosts=ssh_server.known_hosts_path,
    )


async def test_put_then_get_round_trips_file_contents(ssh_server, tmp_path):
    local_src = tmp_path / "src.txt"
    local_src.write_text("hello from nervus\n")
    remote_path = str(tmp_path / "remote-copy.txt")
    local_dst = tmp_path / "dst.txt"

    conn = await _connect(ssh_server)
    try:
        await put_file(conn, local_src, remote_path, transfer_dir=tmp_path)
        await get_file(conn, remote_path, local_dst, transfer_dir=tmp_path)
    finally:
        conn.close()

    assert local_dst.read_text() == "hello from nervus\n"


async def test_put_creates_file_with_exact_bytes(ssh_server, tmp_path):
    local_src = tmp_path / "bin.dat"
    payload = bytes(range(256)) * 4
    local_src.write_bytes(payload)
    remote_path = str(tmp_path / "remote-bin.dat")

    conn = await _connect(ssh_server)
    try:
        await put_file(conn, local_src, remote_path, transfer_dir=tmp_path)
    finally:
        conn.close()

    assert Path(remote_path).read_bytes() == payload


# --- transfer paths are confined to the transfer directory -----------------
# Before this, put() read any path on nervus's own filesystem and sent it to a
# host, which made the fleet private key and the token file exfiltrable by any
# authenticated client (ADR-0001 s2: "No agent ever holds an SSH key"). get()
# was the mirror image -- an arbitrary write, with the audit log the one path
# the hardened unit leaves writable.

import pytest

from nervus.sftp import TransferPathError, resolve_transfer_path


def test_relative_path_resolves_inside_the_transfer_dir(tmp_path):
    base = tmp_path / "transfer"
    base.mkdir()
    assert resolve_transfer_path(base, "report.txt") == (base / "report.txt").resolve()


def test_absolute_path_inside_the_transfer_dir_is_allowed(tmp_path):
    base = tmp_path / "transfer"
    base.mkdir()
    inside = base / "sub" / "report.txt"
    assert resolve_transfer_path(base, str(inside)) == inside.resolve()


def test_absolute_path_outside_is_refused(tmp_path):
    base = tmp_path / "transfer"
    base.mkdir()
    with pytest.raises(TransferPathError):
        resolve_transfer_path(base, "/opt/nervus/secrets/nervus_ed25519")


def test_dot_dot_escape_is_refused(tmp_path):
    base = tmp_path / "transfer"
    base.mkdir()
    (tmp_path / "secrets").mkdir()
    with pytest.raises(TransferPathError):
        resolve_transfer_path(base, "../secrets/key")


def test_a_symlink_pointing_outside_is_refused(tmp_path):
    """The case a string check on '..' would miss entirely.

    Containment is checked on where the path lands after resolution, not on
    how it was spelled, so a symlink planted inside the transfer directory
    cannot be used to read the secrets directory.
    """
    base = tmp_path / "transfer"
    base.mkdir()
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    (secrets / "key").write_text("not really a key")
    (base / "escape").symlink_to(secrets)

    assert ".." not in "escape/key"  # nothing suspicious about the spelling
    with pytest.raises(TransferPathError):
        resolve_transfer_path(base, "escape/key")


def test_the_transfer_dir_itself_is_allowed(tmp_path):
    base = tmp_path / "transfer"
    base.mkdir()
    assert resolve_transfer_path(base, str(base)) == base.resolve()


# --- put writes beside the destination, then renames (ADR-0020 decision I) ----------


async def test_put_replaces_a_file_whole_by_rename_and_leaves_nothing_beside_it(ssh_server, tmp_path):
    local_src = tmp_path / "new.txt"
    local_src.write_text("new\n")
    remote = tmp_path / "remote" / "config.txt"
    remote.parent.mkdir()
    remote.write_text("old\n")
    before = remote.stat().st_ino
    conn = await _connect(ssh_server)
    try:
        await put_file(conn, local_src, str(remote), transfer_dir=tmp_path)
    finally:
        conn.close()
    assert remote.read_text() == "new\n"
    assert remote.stat().st_ino != before
    assert sorted(p.name for p in remote.parent.iterdir()) == ["config.txt"]


async def test_a_put_that_fails_part_way_leaves_the_old_file_and_nothing_else(ssh_server, tmp_path, monkeypatch):
    import asyncssh

    async def broken(self, oldpath, newpath):
        raise asyncssh.SFTPFailure("the connection dropped")

    monkeypatch.setattr(asyncssh.SFTPClient, "posix_rename", broken)
    local_src = tmp_path / "new.txt"
    local_src.write_text("new\n")
    remote = tmp_path / "remote" / "config.txt"
    remote.parent.mkdir()
    remote.write_text("old\n")
    conn = await _connect(ssh_server)
    try:
        with pytest.raises(asyncssh.SFTPFailure):
            await put_file(conn, local_src, str(remote), transfer_dir=tmp_path)
    finally:
        conn.close()
    assert remote.read_text() == "old\n"
    assert sorted(p.name for p in remote.parent.iterdir()) == ["config.txt"]
