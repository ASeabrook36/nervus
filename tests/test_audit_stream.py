"""Tests for tools/nervus-audit-stream, run as sshd would run it: a separate
process, the log's path on its command line, the copy's machine's request in
SSH_ORIGINAL_COMMAND."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "tools" / "nervus-audit-stream"

LINES = [b'{"id": "a", "phase": "intent"}\n', b'{"id": "a", "phase": "result"}\n',
         b'{"id": "b", "phase": "intent"}\n']


def run(log: Path, request: str | None, *extra_args: str, timeout: float = 30) -> tuple[int, bytes]:
    env = {k: v for k, v in os.environ.items() if k != "SSH_ORIGINAL_COMMAND"}
    if request is not None:
        env["SSH_ORIGINAL_COMMAND"] = request
    args = [sys.executable, str(SCRIPT)] + ([str(log)] if log else []) + list(extra_args)
    p = subprocess.run(args, env=env, capture_output=True, timeout=timeout)
    return p.returncode, p.stdout


def parse(out: bytes) -> tuple[str, bytes]:
    header, _, data = out.partition(b"\n")
    return header.decode(), data


@pytest.fixture
def log(tmp_path) -> Path:
    p = tmp_path / "audit.jsonl"
    p.write_bytes(b"".join(LINES))
    p.chmod(0o600)
    return p


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def test_from_zero_sends_everything_with_the_empty_prefix_hash(log):
    code, out = run(log, "0")
    header, data = parse(out)
    whole = b"".join(LINES)
    assert code == 0
    assert header == f"OK 0 {len(whole)} {sha(b'')}"
    assert data == whole


def test_from_an_offset_sends_the_rest_and_hashes_the_prefix(log):
    held = LINES[0]
    code, out = run(log, str(len(held)))
    header, data = parse(out)
    assert code == 0
    assert header == f"OK {len(held)} {len(b''.join(LINES))} {sha(held)}"
    assert data == b"".join(LINES[1:])


def test_up_to_date_sends_nothing(log):
    size = log.stat().st_size
    code, out = run(log, str(size))
    assert (code, out) == (0, f"OK {size} {size} {sha(log.read_bytes())}\n".encode())


def test_a_half_written_record_waits_for_the_next_pull(log):
    whole = log.read_bytes()
    with log.open("ab") as f:
        f.write(b'{"id": "c", "pha')  # nervus mid-write
    code, out = run(log, "0")
    header, data = parse(out)
    assert header == f"OK 0 {len(whole)} {sha(b'')}"
    assert data == whole


def test_an_edited_log_changes_the_prefix_hash(log):
    held = b"".join(LINES[:2])
    log.write_bytes(held.replace(b'"a"', b'"x"') + LINES[2])  # same length, different bytes
    code, out = run(log, str(len(held)))
    header, _ = parse(out)
    assert code == 0
    assert header.split()[3] != sha(held)  # the copy's machine will see this and raise the alarm


def test_a_shorter_log_is_reported(log):
    code, out = run(log, str(log.stat().st_size + 10))
    assert (code, out) == (3, f"SHRUNK {log.stat().st_size}\n".encode())


@pytest.mark.parametrize(
    "request_",
    ["", "abc", "-1", "10 20", "10; cat /etc/passwd", "../../etc/shadow", "1" * 16, "0x10"],
)
def test_anything_but_one_offset_is_refused(log, request_):
    code, out = run(log, request_)
    assert code == 2
    assert out.startswith(b"ERR ")
    assert b"phase" not in out  # no log content leaks with a refusal


def test_no_request_at_all_is_refused(log):
    code, out = run(log, None)
    assert code == 2 and out.startswith(b"ERR ")


def test_the_path_comes_only_from_the_command_line(log):
    code, out = run(None, "0")  # forced command without a path
    assert code == 2 and out.startswith(b"ERR ")


def test_an_unreadable_log_is_an_error_not_a_traceback(tmp_path):
    code, out = run(tmp_path / "missing.jsonl", "0")
    assert code == 2 and out.startswith(b"ERR cannot open the log")


@pytest.mark.parametrize("what", ["pipe", "folder"])
def test_what_is_not_a_file_at_the_logs_name_is_said_and_never_waited_on(tmp_path, what):
    """nervus's account owns the log's folder and can put either there. Waiting on
    a pipe held the copy's machine's connection open with nothing said, and a
    folder ended in a traceback it reads as "not reachable": either way the copy
    stopped growing and no alarm was raised. An ERR line raises it."""
    log = tmp_path / "audit.jsonl"
    os.mkfifo(log, 0o600) if what == "pipe" else log.mkdir()
    assert run(log, "0", timeout=5) == (2, f"ERR the log is a {what}, not a file\n".encode())


def test_a_large_log_is_sent_in_whole_line_chunks(tmp_path):
    line = b'{"pad": "' + b"x" * 1000 + b'"}\n'
    p = tmp_path / "big.jsonl"
    p.write_bytes(line * 10000)  # about 10 MB, more than one 8 MiB chunk
    held = 0
    copy = b""
    for _ in range(5):
        code, out = run(p, str(held))
        header, data = parse(out)
        _, start, end, digest = header.split()
        assert code == 0 and int(start) == held and digest == sha(copy)
        assert data == b"" or data.endswith(b"\n")
        copy += data
        held = int(end)
        if held == p.stat().st_size:
            break
    assert copy == p.read_bytes()
