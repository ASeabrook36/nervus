"""tools/compare-refusals: ADR-0003 item 8 on the machine. A switched-off client's
refusal against a wrong token's, against a real nervus process, run as the
operator runs it (`python -` with the script on standard input)."""

import importlib.machinery
import importlib.util
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import asyncssh
import pytest

from nervus.switches import load_switches

TOOL = Path(__file__).parent.parent / "tools" / "compare-refusals"
ON = "lockdown: false\ndisabled: []\n"


def _module():
    loader = importlib.machinery.SourceFileLoader("compare_refusals", str(TOOL))
    spec = importlib.util.spec_from_loader("compare_refusals", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def nervus(tmp_path):
    """A real nervus, and a unit file naming its files and port as a deployed nervus's does."""
    root = tmp_path / "opt"
    (root / "secrets").mkdir(parents=True)
    (root / "hosts.yaml").write_text(
        "hosts:\n  - {name: host-a, address: host-a.invalid, os: x, role: x, agent_user: agent, status: onboarded}\n")
    tokens = root / "secrets" / "tokens.yaml"
    tokens.write_text("tokens:\n"
                      f"  - {{token: {'a' * 43}, id: t1, client: claude-code, project: p, hosts: [host-a]}}\n"
                      f"  - {{token: {'b' * 43}, id: t2, client: codex, project: q, hosts: [host-a]}}\n")
    os.chmod(tokens, 0o600)
    key = root / "secrets" / "key"
    key.write_bytes(asyncssh.generate_private_key("ssh-ed25519").export_private_key())  # read at every start
    os.chmod(key, 0o600)
    switches = root / "secrets" / "switches.yaml"
    switches.write_text(ON)
    port = _free_port()
    args = ["--hosts", "hosts.yaml", "--tokens", "secrets/tokens.yaml", "--ssh-key", "secrets/key",
            "--switches", "secrets/switches.yaml", "--audit-log", str(tmp_path / "audit.jsonl"),
            "--transfer-dir", str(tmp_path), "--bind-host", "127.0.0.1", "--bind-port", str(port),
            "--ui-port", str(_free_port())]
    unit = tmp_path / "nervus.service"
    unit.write_text("[Service]\n"
                    f"WorkingDirectory={root}\n"
                    "ExecStart=/opt/nervus/.venv/bin/nervus \\\n    " + " \\\n    ".join(args) + "\n")
    with open(tmp_path / "console.log", "wb") as out:
        proc = subprocess.Popen([sys.executable, "-m", "nervus", *args], cwd=root, stdout=out, stderr=subprocess.STDOUT)
    try:
        deadline = time.monotonic() + 20
        while True:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=1).close()
                break
            except OSError:
                assert proc.poll() is None and time.monotonic() < deadline, (tmp_path / "console.log").read_text()
                time.sleep(0.1)
        yield unit, switches, tmp_path / "audit.jsonl"
    finally:
        proc.terminate()
        proc.wait(timeout=15)


def _run(unit, token_id, pairs=20):
    with TOOL.open() as script:
        done = subprocess.run([sys.executable, "-", "--unit", str(unit), "--pairs", str(pairs), token_id],
                              stdin=script, capture_output=True, text=True, timeout=120)
    return done.returncode, done.stdout + done.stderr


def _records(audit):
    return [json.loads(line) for line in audit.read_text().splitlines()] if audit.exists() else []


def test_a_switched_off_client_is_refused_exactly_as_a_wrong_token_is(nervus):
    unit, switches, audit = nervus
    code, out = _run(unit, "t1")
    assert code == 0, out
    for name in ("initialize, a connection request", "tools/list, inside the session",
                 "tools/call hosts, inside the session"):
        assert out.count(f"{name}, ") == 2, out  # its pair, and its control pair
    assert "identical except the session id's value" in out  # the connection request
    assert "identical, byte for byte" in out  # inside the session
    assert "timing, 20 connection requests each: switched off median" in out
    assert "every comparison equal; t1 is on again" in out
    assert "a" * 43 not in out  # the token itself is never shown
    assert load_switches(switches).disabled == frozenset()
    records = _records(audit)
    assert [(r["action"], r["target"]) for r in records if r["phase"] == "operator" and r["tool"] == "nervus-ctl"] == [("lock", "t1"), ("unlock", "t1")]
    refused = {(r["tool"], r["reason"]) for r in records if r["phase"] == "refused"}
    assert refused == {("initialize", "switches: disabled"), ("tools/list", "switches: disabled"),
                       ("tools/call", "switches: disabled")}


def test_it_will_not_start_on_a_client_already_switched_off(nervus):
    unit, switches, audit = nervus
    switches.write_text("lockdown: false\ndisabled: [t1]\n")
    before = switches.read_bytes()
    code, out = _run(unit, "t1")
    assert code == 2, out
    assert "t1 is refused already (disabled)" in out and "nothing changed" in out
    assert switches.read_bytes() == before
    assert not [r for r in _records(audit) if r["phase"] == "operator" and r["tool"] == "nervus-ctl"]


def test_an_unknown_token_id_stops_it_before_anything_changes(nervus):
    unit, switches, audit = nervus
    code, out = _run(unit, "nobody")
    assert code == 2, out
    assert "no token 'nobody'; tokens are t1, t2" in out
    assert switches.read_text() == ON
    assert not [r for r in _records(audit) if r["phase"] == "operator" and r["tool"] == "nervus-ctl"]


def test_the_client_is_switched_back_on_when_a_comparison_cannot_finish(nervus, monkeypatch, capsys):
    unit, switches, audit = nervus
    module = _module()

    def broken(*_args, **_kwargs):
        assert load_switches(switches).disabled == {"t1"}  # it really was off at this point
        raise module.Stop("nervus went away")

    monkeypatch.setattr(module, "three", broken)
    assert module.main(["--unit", str(unit), "t1"]) == 1
    out = capsys.readouterr().out
    assert "could not finish: nervus went away" in out
    assert load_switches(switches).disabled == frozenset()
    assert [r["action"] for r in _records(audit) if r["phase"] == "operator" and r["tool"] == "nervus-ctl"] == ["lock", "unlock"]


def test_it_reaches_a_nervus_listening_on_every_interface_through_loopback(tmp_path):
    unit = tmp_path / "nervus.service"
    unit.write_text("[Service]\nExecStart=/opt/nervus/.venv/bin/nervus --bind-host 0.0.0.0 --bind-port 8000 \\\n"
                    "    --insecure-plain-http\n")
    assert _module().address(unit) == ("127.0.0.1", 8000)


REFUSAL = (b"HTTP/1.1 200 OK\r\ndate: Mon, 05 Oct 2026 21:35:09 GMT\r\nserver: uvicorn\r\n"
           b"content-type: text/event-stream\r\nmcp-session-id: %s\r\n\r\n"
           b'data: {"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"unauthorized"}}\r\n')


def _refusal(session=b"0" * 32, extra=b""):
    return (REFUSAL % session).replace(b"server: uvicorn\r\n", b"server: uvicorn\r\n" + extra)


def test_a_header_only_the_switched_off_client_gets_is_reported():
    compare = _module().compare
    found, wrong = compare("initialize", [_refusal(b"1" * 32, b"x-off: yes\r\n"), _refusal(b"2" * 32),
                                          _refusal(b"3" * 32)], mask=True)
    assert len(wrong) == 1 and "switched off / made up: DIFFERENT" in wrong[0] and "x-off: yes" in wrong[0]
    assert found == ["initialize, made up / made up (control): identical except the session id's value, "
                     "the same form in both"]


def test_a_session_id_of_another_form_is_not_masked_and_is_reported():
    compare = _module().compare
    _, wrong = compare("initialize", [_refusal(b"t1-session"), _refusal(b"2" * 32), _refusal(b"3" * 32)], mask=True)
    assert len(wrong) == 1 and "t1-session" in wrong[0]


def test_inside_a_session_nothing_is_masked():
    compare = _module().compare
    found, wrong = compare("tools/list", [_refusal(b"1" * 32), _refusal(b"1" * 32), _refusal(b"2" * 32)], mask=False)
    assert found == ["tools/list, switched off / made up: identical, byte for byte"]
    assert len(wrong) == 1 and "made up / made up (control): DIFFERENT" in wrong[0]


def test_a_switched_off_client_that_was_served_is_reported():
    compare = _module().compare
    served = _refusal().replace(b'"error":{"code":-32001,"message":"unauthorized"}', b'"result":{}')
    _, wrong = compare("tools/list", [served, _refusal(), _refusal()], mask=False)
    assert "tools/list: the switched-off client was not refused" in wrong


def test_only_the_connection_request_has_its_session_id_masked(monkeypatch):
    module = _module()

    def three(_where, message, _tokens, session):
        if session is None:  # a connection request: a fresh id on each response
            return [_refusal(b"1" * 32), _refusal(b"2" * 32), _refusal(b"3" * 32)]
        return [_refusal(b"1" * 32), _refusal(b"2" * 32), _refusal(b"2" * 32)]

    monkeypatch.setattr(module, "three", three)
    found, wrong, _ = module.comparisons(("127.0.0.1", 1), "a", ["b", "c"], "s")
    assert [w.split(":")[0] for w in wrong] == ["tools/list, inside the session, switched off / made up",
                                                "tools/call hosts, inside the session, switched off / made up"]
    assert sum("initialize" in f for f in found) == 2


def test_timing_that_matches_a_coin_flip_passes():
    found, wrong = _module().judge_timing([53.0, 53.2, 52.9, 53.1] * 50, [53.1, 53.0, 53.0, 53.0] * 50)
    assert wrong == [] and "switched off slower in 100 of 200 pairs" in found


def test_a_switched_off_refusal_that_is_reliably_slower_is_reported():
    # As before decision D: about 0.45 ms slower, in most pairs (measured locally).
    off = [2.6 + (i % 7) * 0.05 for i in range(200)]
    other = [2.2 + (i % 5) * 0.05 for i in range(200)]
    _, wrong = _module().judge_timing(off, other)
    assert any("under 50 ms" in w for w in wrong)
    assert any("tells it apart" in w for w in wrong)


def test_a_reliably_slower_refusal_is_reported_even_above_the_minimum():
    off = [53.4 + (i % 3) * 0.1 for i in range(200)]
    other = [53.0 + (i % 3) * 0.1 for i in range(200)]
    _, wrong = _module().judge_timing(off, other)
    assert wrong == ["timing: switched off slower in 200 of 200 pairs, more than four standard deviations "
                     "from a coin flip, so its timing tells it apart"]
