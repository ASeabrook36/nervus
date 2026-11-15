"""The test SSH servers' shell: each command run by a real local shell,
standard input, output and error piped through. Shared by conftest's
ssh_server and the VM stand-ins in test_enroller; a module of its own, since
`conftest` names two modules in this repository (tests/, deployment/tests/)."""

import asyncio
import contextlib

import asyncssh


async def _handle_process(process: asyncssh.SSHServerProcess) -> None:
    """Actually run the command with a real local shell, piping stdio through.

    This makes tests exercise real bash (and, where used, real tmux)
    rather than a mocked SSH layer -- a fake server that just returned
    canned output would not catch a wrong pipefail/quoting bug in
    nervus.ssh.build_exec_script.
    """
    proc = await asyncio.create_subprocess_shell(
        process.command or "",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    async def pump_stdin() -> None:
        try:
            while True:
                data = await process.stdin.read(65536)
                if not data:
                    break
                raw = data.encode() if isinstance(data, str) else data
                proc.stdin.write(raw)
                await proc.stdin.drain()
        except asyncio.CancelledError:
            pass
        finally:
            if proc.stdin is not None and not proc.stdin.is_closing():
                proc.stdin.close()

    async def pump(reader: asyncio.StreamReader, writer) -> None:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            # process.stdout/stderr are str-typed channels by default;
            # the subprocess pipes give bytes.
            writer.write(data.decode(errors="replace"))

    # Completion is driven by the subprocess's own stdout/stderr EOF and
    # exit, not by the client closing stdin -- a command that never reads
    # stdin (e.g. `tmux has-session`) would otherwise hang forever
    # waiting for an EOF a client without `input=` never sends. A real
    # sshd doesn't wait on that either.
    stdin_task = asyncio.ensure_future(pump_stdin())
    await asyncio.gather(pump(proc.stdout, process.stdout), pump(proc.stderr, process.stderr))
    returncode = await proc.wait()
    stdin_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await stdin_task
    process.exit(returncode)
