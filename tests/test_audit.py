import hashlib
import json
import os

import pytest

from nervus.audit import AuditError, AuditLog, AuditRefused


def test_record_intent_then_result_appends_two_lines(tmp_path):
    log = AuditLog(path=tmp_path / "audit.jsonl")

    run_id = log.record_intent(
        "exec",
        {
            "token_id": "claude-code-project-a",
            "client": "claude-code",
            "project": "project-a",
            "host": "node-a",
            "user": "agent",
            "cwd": "/home/agent",
            "command": "uptime",
        },
    )
    log.record_result(
        run_id,
        "exec",
        {"exit_code": 0, "duration_s": 0.42, "output_bytes": 123, "log_path": "~/.nervus/runs/x/output"},
    )

    lines = log.path.read_text().splitlines()
    assert len(lines) == 2

    intent = json.loads(lines[0])
    result = json.loads(lines[1])

    assert intent["id"] == run_id
    assert intent["phase"] == "intent"
    assert intent["tool"] == "exec"
    assert intent["host"] == "node-a"
    assert intent["command"] == "uptime"

    assert result["id"] == run_id
    assert result["phase"] == "result"
    assert result["exit_code"] == 0
    assert result["output_bytes"] == 123


def test_record_intent_returns_distinct_ids(tmp_path):
    log = AuditLog(path=tmp_path / "audit.jsonl")

    first = log.record_intent("exec", {"command": "a"})
    second = log.record_intent("exec", {"command": "b"})

    assert first != second


def test_record_intent_raises_audit_error_when_unwritable(tmp_path):
    missing_dir = tmp_path / "does-not-exist" / "audit.jsonl"
    log = AuditLog(path=missing_dir)

    with pytest.raises(AuditError):
        log.record_intent("exec", {"command": "a"})


def test_audit_log_is_append_only_across_instances(tmp_path):
    path = tmp_path / "audit.jsonl"
    AuditLog(path=path).record_intent("exec", {"command": "first"})
    AuditLog(path=path).record_intent("exec", {"command": "second"})

    lines = path.read_text().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["command"] == "first"
    assert json.loads(lines[1])["command"] == "second"


def test_an_intent_too_large_to_record_whole_is_refused_and_the_log_stays_bounded(tmp_path):
    # A client sends a huge command with non-BMP characters that inflate ~12x once
    # JSON-escaped. One record must not become an unbounded line (procedure 056,
    # finding 3), and an intent cut to fit would let a long call hide its end, so
    # the call is refused before it runs (ADR-0013, amendment 2026-11-13).
    log = AuditLog(path=tmp_path / "audit.jsonl")
    fields = {"command": "\U0001f600" * 1_000_000, "host": "node-a"}
    with pytest.raises(AuditRefused) as refused:
        log.record_intent("exec", fields)
    assert isinstance(refused.value, AuditError)  # every caller already stops on this
    assert "nothing was done" in str(refused.value) and "too large" in str(refused.value)
    lines = log.path.read_text().splitlines()
    assert len(lines) == 1 and len(lines[0].encode("utf-8")) <= 300_000
    record = json.loads(lines[0])
    assert record["phase"] == "refused" and record["tool"] == "exec" and record["refused"] == "too_large_to_record"
    assert record["host"] == "node-a"            # a short client field is left as-is
    assert "truncated" in record["command"]      # the refusal's copy is cut, and says so
    assert record["arguments_sha256"] == hashlib.sha256(json.dumps(fields, sort_keys=True).encode()).hexdigest()


def test_a_padded_command_cannot_hide_its_end_from_the_record(tmp_path):
    log = AuditLog(path=tmp_path / "audit.jsonl")
    command = ":" + " " * 50_000 + "; rm -rf /srv/important"
    run_id = log.record_intent("exec", {"command": command, "host": "node-a"})
    record = json.loads(log.path.read_text().splitlines()[0])
    assert record["id"] == run_id and record["phase"] == "intent"
    assert record["command"] == command          # whole, end included


def test_a_result_is_still_cut_so_its_line_stays_bounded(tmp_path):
    log = AuditLog(path=tmp_path / "audit.jsonl")
    run_id = log.record_intent("exec", {"command": "true", "host": "node-a"})
    log.record_result(run_id, "exec", {"error": "x" * 1_000_000})
    line = log.path.read_text().splitlines()[1]
    assert len(line.encode("utf-8")) <= 300_000 and "truncated" in json.loads(line)["error"]
