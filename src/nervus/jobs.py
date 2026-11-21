from __future__ import annotations

import re
import shlex
import uuid
from dataclasses import dataclass

import asyncssh

from nervus.ssh import cd_target, label_line, private_folder


class JobError(Exception):
    """A job could not be started, or the target's tmux/job state was unreadable."""


# A client may supply the job id. It is interpolated into the target's tmux session
# name and its job paths under ~/.nervus/jobs, so it must match a safe shape: a shell
# metacharacter or a slash would otherwise inject or escape the jobs directory. The
# caller already has exec on that host, so this is defence in depth, not a boundary
# (procedure 056, C6). nervus's own default is a uuid4, which matches.
_JOB_ID = re.compile(r"[A-Za-z0-9_-]{1,64}")


def _valid_job_id(job_id: str) -> str:
    if not isinstance(job_id, str) or _JOB_ID.fullmatch(job_id) is None:
        raise JobError(f"a job id is 1 to 64 characters of letters, digits, '-' or '_': {job_id!r}")
    return job_id


@dataclass(frozen=True)
class JobHandle:
    job_id: str
    session_name: str
    log_path: str
    exit_path: str


@dataclass(frozen=True)
class JobStatus:
    job_id: str
    running: bool
    exit_code: int | None


def _session_name(job_id: str) -> str:
    return f"nervus-{_valid_job_id(job_id)}"


def _job_paths(job_id: str) -> tuple[str, str, str]:
    """Returns (job_dir, log_path, exit_path). See ssh.build_exec_script's
    docstring for why these use unquoted $HOME rather than `~`."""
    job_dir = f"$HOME/.nervus/jobs/{_valid_job_id(job_id)}"
    return job_dir, f"{job_dir}/log", f"{job_dir}/exit"


def build_job_script(job_id: str, cwd: str, command: str, label: str | None = None) -> tuple[str, JobHandle]:
    """A detached tmux session that outlives this SSH connection.

    tmux is given the pane command as separate exec-style argv
    (`bash -c <script>` as two tokens after the session name), not one
    string -- that way it execs bash directly rather than depending on
    whatever the target account's default shell happens to be.
    """
    session_name = _session_name(job_id)
    job_dir, log_path, exit_path = _job_paths(job_id)

    cd_failed = shlex.quote(f"nervus: cannot change to working directory: {cwd}")
    inner = (
        "set -o pipefail\n"
        f"cd {cd_target(cwd)} || {{ echo {cd_failed} | tee {log_path}; exit 97; }}\n"
        "{\n"
        f"{command}\n"
        "} 2>&1 | tee " + log_path + "\n"
        "ec=$?\n"
        f'echo "$ec" > {exit_path}\n'
    )

    # The label as the job starts, beside the tmux session (ADR-0025 decision 2).
    script = (
        label_line(label)
        + private_folder(job_dir)
        + f"tmux new-session -d -s {shlex.quote(session_name)} bash -c {shlex.quote(inner)}\n"
    )
    return script, JobHandle(job_id=job_id, session_name=session_name, log_path=log_path, exit_path=exit_path)


async def start_job(
    conn: asyncssh.SSHClientConnection,
    *,
    cwd: str,
    command: str,
    job_id: str | None = None,
    label: str | None = None,
) -> JobHandle:
    job_id = job_id or str(uuid.uuid4())
    script, handle = build_job_script(job_id, cwd, command, label)

    completed = await conn.run("bash -s", input=script, timeout=30)
    if completed.exit_status != 0:
        raise JobError(
            f"failed to start job {job_id}: {(completed.stdout or '') + (completed.stderr or '')}"
        )
    return handle


async def job_status(conn: asyncssh.SSHClientConnection, job_id: str) -> JobStatus:
    session_name = _session_name(job_id)
    _, _, exit_path = _job_paths(job_id)

    has_session = await conn.run(f"tmux has-session -t {shlex.quote(session_name)} 2>/dev/null")
    running = has_session.exit_status == 0

    exit_code = None
    if not running:
        cat = await conn.run(f"cat {exit_path} 2>/dev/null")
        text = (cat.stdout or "").strip()
        if text and (text.lstrip("-")).isdigit():
            exit_code = int(text)

    return JobStatus(job_id=job_id, running=running, exit_code=exit_code)


async def job_logs(
    conn: asyncssh.SSHClientConnection,
    job_id: str,
    *,
    tail: int | None = None,
    offset: int = 0,
    length: int | None = None,
) -> str:
    """Read the job's log. `tail` (bytes from the end) and `offset`/`length`
    (a byte range from the start) are mutually exclusive; with neither,
    the whole log is returned."""
    _, log_path, _ = _job_paths(job_id)

    if tail is not None:
        command = f"tail -c {int(tail)} {log_path}"
    elif length is not None:
        command = f"tail -c +{int(offset) + 1} {log_path} | head -c {int(length)}"
    else:
        command = f"cat {log_path}"

    completed = await conn.run(command)
    return completed.stdout or ""


async def kill_job(conn: asyncssh.SSHClientConnection, job_id: str) -> None:
    session_name = _session_name(job_id)
    await conn.run(f"tmux kill-session -t {shlex.quote(session_name)} 2>/dev/null")
