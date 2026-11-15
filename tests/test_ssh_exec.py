import asyncio
import os
import tempfile

import pytest

from nervus.ssh import bound_output, cd_target, connect, exec_command


async def _connect(ssh_server):
    return await connect(
        address=ssh_server.host,
        port=ssh_server.port,
        username=ssh_server.username,
        client_keys=[ssh_server.client_key_path],
        known_hosts=ssh_server.known_hosts_path,
    )


async def test_exec_returns_exit_code_and_output(ssh_server):
    conn = await _connect(ssh_server)
    try:
        result = await exec_command(conn, cwd="/tmp", command="echo hello", timeout=10)
    finally:
        conn.close()

    assert result.exit_code == 0
    assert "hello" in result.output
    assert not result.truncated
    assert not result.timed_out


async def test_exec_returns_nonzero_exit_code(ssh_server):
    conn = await _connect(ssh_server)
    try:
        result = await exec_command(conn, cwd="/tmp", command="exit 7", timeout=10)
    finally:
        conn.close()

    assert result.exit_code == 7


async def test_exec_uses_cwd(ssh_server):
    conn = await _connect(ssh_server)
    try:
        result = await exec_command(conn, cwd="/", command="pwd", timeout=10)
    finally:
        conn.close()

    assert result.output.strip().endswith("/")


async def test_exec_reports_pipeline_exit_status_not_tees(ssh_server):
    """The exit code must be the user command's, not tee's, even though
    output is piped through tee to land on disk."""
    conn = await _connect(ssh_server)
    try:
        result = await exec_command(conn, cwd="/tmp", command="false", timeout=10)
    finally:
        conn.close()

    assert result.exit_code == 1


async def test_exec_writes_full_output_to_target_disk(ssh_server, tmp_path):
    conn = await _connect(ssh_server)
    try:
        result = await exec_command(conn, cwd="/tmp", command="echo on-disk", timeout=10)
        assert result.remote_output_path.startswith("$HOME/.nervus/runs/")

        readback = await exec_command(
            conn, cwd="/tmp", command=f"cat {result.remote_output_path}", timeout=10
        )
    finally:
        conn.close()

    assert "on-disk" in readback.output


async def test_exec_truncates_large_output_with_marker_and_total(ssh_server):
    conn = await _connect(ssh_server)
    try:
        # Print well over the 32 KiB bound.
        result = await exec_command(
            conn, cwd="/tmp", command="yes x | head -c 200000", timeout=10
        )
    finally:
        conn.close()

    assert result.truncated
    assert result.total_bytes >= 200000
    assert result.output.startswith("[... truncated, showing last")
    assert str(result.total_bytes) in result.output


async def test_exec_times_out_on_long_running_command(ssh_server):
    conn = await _connect(ssh_server)
    try:
        result = await exec_command(conn, cwd="/tmp", command="sleep 5", timeout=0.2)
    finally:
        conn.close()

    assert result.timed_out
    assert result.exit_code is None


# --- connect() uses nothing of the running account's ssh setup --------------
# asyncssh reads ~/.ssh/config and SSH_AUTH_SOCK by default. Either would let
# something other than nervus's own key and the pinned host keys shape a
# connection: a ProxyCommand changes where it goes, an agent offers other keys.


async def test_connect_ignores_the_accounts_ssh_config(ssh_server, tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    marker = tmp_path / "proxy-ran"
    (home / ".ssh" / "config").write_text(
        f"Host *\n    ProxyCommand sh -c 'echo ran > {marker}; exit 1'\n"
    )
    monkeypatch.setenv("HOME", str(home))

    conn = await _connect(ssh_server)
    try:
        result = await exec_command(conn, cwd="/tmp", command="echo direct", timeout=10)
    finally:
        conn.close()

    assert not marker.exists(), "~/.ssh/config was read: its ProxyCommand ran"
    assert "direct" in result.output


async def test_connect_never_talks_to_an_ssh_agent(ssh_server, tmp_path, monkeypatch):
    """A listener stands in for the agent; it must never be spoken to.

    HOME is emptied so the machine's own ~/.ssh/config (an IdentityAgent line
    there outranks SSH_AUTH_SOCK) cannot decide what this test exercises.
    """
    (tmp_path / "home").mkdir()
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    asked = []

    async def note(reader, writer):
        asked.append(1)
        writer.close()

    # Unix socket paths are short-limited on macOS, so not tmp_path.
    with tempfile.TemporaryDirectory(dir="/tmp") as short:
        sock = os.path.join(short, "agent")
        agent = await asyncio.start_unix_server(note, sock)
        monkeypatch.setenv("SSH_AUTH_SOCK", sock)
        try:
            conn = await _connect(ssh_server)
            try:
                result = await exec_command(conn, cwd="/tmp", command="echo keyed", timeout=10)
            finally:
                conn.close()
        finally:
            agent.close()
            await agent.wait_closed()

    assert not asked, "the agent named by SSH_AUTH_SOCK was contacted"
    assert "keyed" in result.output


def test_bound_output_leaves_short_output_untouched():
    output, total, truncated = bound_output("hello", limit=32)
    assert output == "hello"
    assert total == 5
    assert not truncated


def test_bound_output_truncates_and_reports_total():
    output, total, truncated = bound_output("x" * 100, limit=10)
    assert truncated
    assert total == 100
    assert output.endswith("x" * 10)
    assert "100" in output


# --- defect C: the default cwd is "~", and quoting a tilde breaks it -------
# Every test above passes cwd="/tmp" explicitly, which is exactly why the
# suite stayed green while exec was broken for every caller that relied on
# the default. See procedures/003-onboard-agent-account.md.


def test_cd_target_leaves_bare_tilde_unquoted():
    # shlex.quote("~") would give "'~'", which bash treats as a literal
    # directory name rather than $HOME.
    assert cd_target("~") == "~"


def test_cd_target_keeps_the_slash_unquoted_and_quotes_the_rest():
    # bash only expands a tilde when the slash ending the tilde-prefix is
    # itself unquoted, so "~'/sub'" fails just as "'~'" does. shlex.quote is
    # minimal, so a tail needing no quoting is left bare -- what matters is
    # that the tilde and its slash are never inside quotes.
    assert cd_target("~/sub") == "~/sub"
    assert cd_target("~/sub dir") == "~/'sub dir'"


def test_cd_target_handles_tilde_user():
    assert cd_target("~agent") == "~agent"
    assert cd_target("~agent/work") == "~agent/work"


def test_cd_target_passes_absolute_paths_through_shlex_quote():
    assert cd_target("/tmp") == "/tmp"
    assert cd_target("/var/tmp/a b") == "'/var/tmp/a b'"


def test_cd_target_does_not_treat_a_non_leading_tilde_as_a_prefix():
    # A tilde anywhere but the start carries no special meaning, and must
    # stay quoted so the shell cannot expand it.
    assert cd_target("/home/~odd") == "'/home/~odd'"
    assert not cd_target("relative/path").startswith("~")


def test_cd_target_leaves_no_room_for_injection_after_the_prefix():
    assert cd_target("~/; rm -rf /") == "~/'; rm -rf /'"


def test_cd_target_renderings_actually_work_in_real_bash(tmp_path):
    """The assertion that matters: bash accepts what we render.

    The first attempted fix for defect C quoted the tail as ~'/sub', which
    is just as broken as '~' and would have passed a string-shaped test.
    Only running it through bash caught that.
    """
    import subprocess

    spaced = tmp_path / "a b"
    spaced.mkdir()
    cases = {
        "~": os.path.expanduser("~"),
        "~/": os.path.expanduser("~"),
        str(tmp_path): str(tmp_path),
        str(spaced): str(spaced),
    }
    for cwd, expected in cases.items():
        done = subprocess.run(
            ["bash", "-c", f"cd {cd_target(cwd)} && pwd"], capture_output=True, text=True
        )
        assert done.returncode == 0, f"{cwd!r} rendered {cd_target(cwd)!r}: {done.stderr}"
        assert os.path.realpath(done.stdout.strip()) == os.path.realpath(expected)


def test_the_old_broken_rendering_really_does_fail_in_bash():
    """Guards the premise of the fix, not the fix itself."""
    import shlex
    import subprocess

    done = subprocess.run(
        ["bash", "-c", f"cd {shlex.quote('~')} && pwd"], capture_output=True, text=True
    )
    assert done.returncode != 0


async def test_exec_works_with_the_default_cwd(ssh_server):
    """The regression test for defect C.

    exec's default cwd is "~". Before the fix this exited 97 with empty
    output, which reads to a client as a command that simply produced
    nothing.
    """
    conn = await _connect(ssh_server)
    try:
        result = await exec_command(conn, cwd="~", command="pwd", timeout=10)
    finally:
        conn.close()

    assert result.exit_code == 0
    assert result.output.strip() == os.path.expanduser("~")


async def test_exec_reports_an_unusable_cwd_instead_of_failing_silently(ssh_server):
    """A bad cwd must say so in the captured output.

    exec_command bounds completed.stdout only, so a bare `cd ... || exit 97`
    wrote its diagnosis to stderr and discarded it -- the caller saw exit 97
    and an empty string, with isError unset.
    """
    conn = await _connect(ssh_server)
    try:
        result = await exec_command(
            conn, cwd="/definitely/not/a/directory", command="echo hi", timeout=10
        )
    finally:
        conn.close()

    assert result.exit_code == 97
    assert "cannot change to working directory" in result.output
    assert "/definitely/not/a/directory" in result.output
