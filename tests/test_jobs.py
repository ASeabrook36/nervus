import asyncio
import os
import shutil

import pytest

from nervus.jobs import JobError, job_logs, job_status, kill_job, start_job
from nervus.ssh import connect

pytestmark = pytest.mark.skipif(
    shutil.which("tmux") is None,
    reason="tmux not available in this sandbox; job lifecycle is untested here (see CURRENT_STATE.md)",
)


async def _connect(ssh_server):
    return await connect(
        address=ssh_server.host,
        port=ssh_server.port,
        username=ssh_server.username,
        client_keys=[ssh_server.client_key_path],
        known_hosts=ssh_server.known_hosts_path,
    )


async def _wait_until_finished(conn, job_id, timeout=5.0):
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        status = await job_status(conn, job_id)
        if not status.running:
            return status
        await asyncio.sleep(0.1)
    raise AssertionError(f"job {job_id} did not finish within {timeout}s")


async def test_job_runs_to_completion_and_reports_exit_code(ssh_server):
    conn = await _connect(ssh_server)
    try:
        handle = await start_job(conn, cwd="/tmp", command="echo job-output; exit 5")
        status = await _wait_until_finished(conn, handle.job_id)
    finally:
        conn.close()

    assert status.exit_code == 5
    assert not status.running


async def test_job_status_reports_running_while_in_flight(ssh_server):
    conn = await _connect(ssh_server)
    try:
        handle = await start_job(conn, cwd="/tmp", command="sleep 2")
        status = await job_status(conn, handle.job_id)
        assert status.running
        assert status.exit_code is None

        await _wait_until_finished(conn, handle.job_id, timeout=5)
    finally:
        conn.close()


async def test_job_logs_are_tee_d_to_target_disk(ssh_server):
    conn = await _connect(ssh_server)
    try:
        handle = await start_job(conn, cwd="/tmp", command="echo hello-from-job")
        await _wait_until_finished(conn, handle.job_id)

        logs = await job_logs(conn, handle.job_id)
    finally:
        conn.close()

    assert "hello-from-job" in logs


async def test_job_logs_tail_returns_only_last_bytes(ssh_server):
    conn = await _connect(ssh_server)
    try:
        handle = await start_job(conn, cwd="/tmp", command="printf 'aaaaaaaaaabbbbb'")
        await _wait_until_finished(conn, handle.job_id)

        tail = await job_logs(conn, handle.job_id, tail=5)
    finally:
        conn.close()

    assert tail == "bbbbb"


async def test_job_logs_range_returns_requested_slice(ssh_server):
    conn = await _connect(ssh_server)
    try:
        handle = await start_job(conn, cwd="/tmp", command="printf '0123456789'")
        await _wait_until_finished(conn, handle.job_id)

        middle = await job_logs(conn, handle.job_id, offset=3, length=4)
    finally:
        conn.close()

    assert middle == "3456"


async def test_kill_job_stops_a_running_job(ssh_server):
    conn = await _connect(ssh_server)
    try:
        handle = await start_job(conn, cwd="/tmp", command="sleep 30")
        status = await job_status(conn, handle.job_id)
        assert status.running

        await kill_job(conn, handle.job_id)
        await asyncio.sleep(0.3)

        status = await job_status(conn, handle.job_id)
        assert not status.running
    finally:
        conn.close()


async def test_job_survives_being_forgotten_by_the_client(ssh_server):
    """A detached tmux job must keep running even if nothing is polling it --
    that's the whole point of exec_bg over plain exec (ADR-0001 section 9)."""
    conn = await _connect(ssh_server)
    try:
        handle = await start_job(conn, cwd="/tmp", command="sleep 0.5; echo survived")
        # Deliberately don't touch the job for a bit.
        await asyncio.sleep(0.8)

        status = await job_status(conn, handle.job_id)
        logs = await job_logs(conn, handle.job_id)
    finally:
        conn.close()

    assert not status.running
    assert status.exit_code == 0
    assert "survived" in logs


async def test_start_job_raises_job_error_on_duplicate_session(ssh_server):
    """tmux refuses to create a session whose name already exists; that's
    the simplest reliable way to make the wrapper script itself fail,
    as opposed to the job's own command failing later inside the pane."""
    conn = await _connect(ssh_server)
    job_id = "duplicate-job-id"
    try:
        await start_job(conn, cwd="/tmp", command="sleep 5", job_id=job_id)

        with pytest.raises(JobError):
            await start_job(conn, cwd="/tmp", command="sleep 5", job_id=job_id)
    finally:
        await kill_job(conn, job_id)
        conn.close()


async def test_job_works_with_the_default_cwd(ssh_server):
    """Regression test for defect C in exec_bg's half of the fix.

    exec_bg defaults to cwd="~". Before the fix the tmux pane exited 97
    immediately, so the job "completed" having run nothing.
    """
    conn = await _connect(ssh_server)
    try:
        handle = await start_job(conn, cwd="~", command="pwd")
        status = await _wait_until_finished(conn, handle.job_id)
        logs = await job_logs(conn, handle.job_id)
    finally:
        conn.close()

    assert status.exit_code == 0
    assert logs.strip().endswith(os.path.expanduser("~"))
