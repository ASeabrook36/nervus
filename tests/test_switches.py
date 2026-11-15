"""The off switch (ADR-0003, ADR-0011 decision 2): the file, read strictly and
failing closed, and the middleware that consults it on every request."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from nervus.audit import AuditLog
from nervus.auth import BearerAuthMiddleware, Token
from nervus.switches import Switches, SwitchesUnreadable, load_switches, refusal

ON = "lockdown: false\ndisabled: []\n"


def _file(tmp_path, text):
    path = tmp_path / "switches.yaml"
    path.write_text(text)
    return path


def test_nothing_off(tmp_path):
    assert load_switches(_file(tmp_path, ON)) == Switches(lockdown=False, disabled=frozenset())
    assert refusal(_file(tmp_path, ON), "t1") is None


def test_one_client_off(tmp_path):
    path = _file(tmp_path, "lockdown: false\ndisabled:\n  - t1\n")
    assert refusal(path, "t1") == "disabled"
    assert refusal(path, "t2") is None


def test_lockdown_refuses_everyone(tmp_path):
    path = _file(tmp_path, "lockdown: true\ndisabled: []\n")
    assert refusal(path, "t1") == "lockdown"
    assert refusal(path, "t2") == "lockdown"


def test_an_emptied_disabled_list_means_nobody_is_off(tmp_path):
    # "Re-enabling is deleting a line" (ADR-0003 decision 3), so deleting the
    # last one must not lock everybody out.
    assert refusal(_file(tmp_path, "lockdown: false\ndisabled:\n"), "t1") is None


@pytest.mark.parametrize("text", [
    "lockdown: false\ndisabled: [\n",                      # not YAML
    "",                                                    # empty
    "lockdown: false\n",                                   # a key missing
    "lockdown: false\ndisabled: []\nextra: 1\n",           # a key too many
    "lockdown: \"no\"\ndisabled: []\n",                    # not true or false
    "lockdown: false\ndisabled: t1\n",                     # not a list
    "lockdown: false\ndisabled: [1]\n",                    # not token ids
    "- lockdown\n",                                        # not a mapping
])
def test_a_malformed_file_refuses_everyone(tmp_path, text):
    path = _file(tmp_path, text)
    with pytest.raises(SwitchesUnreadable):
        load_switches(path)
    assert refusal(path, "t1").startswith("switches unreadable")


def test_a_missing_file_refuses_everyone(tmp_path):
    assert refusal(tmp_path / "absent.yaml", "t1").startswith("switches unreadable")


# --- the middleware -----------------------------------------------------------

TOKENS = {"good": Token(id="t1", client="claude-code", project="p", hosts=frozenset({"node-a"}))}


def _ctx(token="good", request_id=7, method="tools/call", params=None):
    headers = {"authorization": f"Bearer {token}"} if token else {}
    return SimpleNamespace(request=SimpleNamespace(headers=headers), request_id=request_id,
                           method=method, params=params if params is not None else {"name": "hosts"})


async def _refusal_message(middleware, ctx):
    from mcp.shared.exceptions import MCPError

    async def call_next(_ctx):
        raise AssertionError("call_next must not run for a refused client")

    with pytest.raises(MCPError) as caught:
        await middleware(ctx, call_next)
    return caught.value


async def test_a_switched_off_client_gets_exactly_what_an_invalid_token_gets(tmp_path):
    middleware = BearerAuthMiddleware(TOKENS, _file(tmp_path, "lockdown: false\ndisabled: [t1]\n"),
                                      AuditLog(path=tmp_path / "audit.jsonl"))
    off = await _refusal_message(middleware, _ctx())
    invalid = await _refusal_message(middleware, _ctx(token="bad"))
    assert (off.code, str(off)) == (invalid.code, str(invalid))


async def test_the_refusal_is_audited_with_its_reason(tmp_path):
    import json

    audit = AuditLog(path=tmp_path / "audit.jsonl")
    middleware = BearerAuthMiddleware(TOKENS, _file(tmp_path, "lockdown: true\ndisabled: []\n"), audit)
    await _refusal_message(middleware, _ctx(params={"name": "exec", "arguments": {}}))
    records = [json.loads(line) for line in audit.path.read_text().splitlines()]
    assert len(records) == 1
    record = records[0]
    assert (record["phase"], record["tool"], record["name"]) == ("refused", "tools/call", "exec")
    assert (record["token_id"], record["reason"]) == ("t1", "switches: lockdown")
    assert "good" not in audit.path.read_text()  # the token itself is never written


async def test_a_refused_notification_is_not_written(tmp_path):
    audit = AuditLog(path=tmp_path / "audit.jsonl")
    middleware = BearerAuthMiddleware(TOKENS, _file(tmp_path, "lockdown: true\ndisabled: []\n"), audit)
    await _refusal_message(middleware, _ctx(request_id=None, method="notifications/initialized"))
    assert not audit.path.exists()


async def test_a_change_applies_on_the_next_call(tmp_path):
    path = _file(tmp_path, ON)
    middleware = BearerAuthMiddleware(TOKENS, path, AuditLog(path=tmp_path / "audit.jsonl"))

    async def call_next(_ctx):
        return "ran"

    assert await middleware(_ctx(), call_next) == "ran"
    path.write_text("lockdown: false\ndisabled: [t1]\n")
    await _refusal_message(middleware, _ctx())
    path.write_text(ON)
    assert await middleware(_ctx(), call_next) == "ran"


async def test_a_missing_file_refuses_a_valid_token(tmp_path):
    middleware = BearerAuthMiddleware(TOKENS, tmp_path / "absent.yaml", AuditLog(path=tmp_path / "a.jsonl"))
    await _refusal_message(middleware, _ctx())


@pytest.mark.parametrize("why, token, text", [
    ("invalid token", "bad", ON),
    ("missing token", None, ON),
    ("switched off", "good", "lockdown: false\ndisabled: [t1]\n"),
    ("lockdown", "good", "lockdown: true\ndisabled: []\n"),
    ("unreadable switches", "good", "lockdown: maybe\n"),
])
async def test_no_refusal_is_answered_sooner_than_the_minimum(tmp_path, why, token, text):
    # ADR-0003 decision D: how long a refusal takes says nothing about why.
    import time

    from nervus.auth import REFUSAL_SECONDS

    middleware = BearerAuthMiddleware(TOKENS, _file(tmp_path, text), AuditLog(path=tmp_path / "audit.jsonl"))
    began = time.monotonic()
    await _refusal_message(middleware, _ctx(token=token))
    assert time.monotonic() - began >= REFUSAL_SECONDS, why


async def test_a_served_request_is_not_held(tmp_path):
    import time

    from nervus.auth import REFUSAL_SECONDS

    middleware = BearerAuthMiddleware(TOKENS, _file(tmp_path, ON), AuditLog(path=tmp_path / "audit.jsonl"))

    async def call_next(_ctx):
        return "ran"

    began = time.monotonic()
    assert await middleware(_ctx(), call_next) == "ran"
    assert time.monotonic() - began < REFUSAL_SECONDS / 2


async def test_work_done_before_the_wait_does_not_show_in_its_length():
    # The reason for _hold's last 2 ms: a plain sleep for the remainder is rounded
    # up to a whole millisecond from when it starts, which carries the work done
    # before it straight through (measured: 0.26 ms went through unchanged).
    import statistics
    import time

    from nervus.auth import REFUSAL_SECONDS, _hold

    async def refusal(work):
        began = time.monotonic()
        while time.monotonic() < began + work:
            pass
        await _hold(began)
        return time.monotonic() - began

    little = statistics.median([await refusal(0.00005) for _ in range(9)])
    more = statistics.median([await refusal(0.0006) for _ in range(9)])
    assert little >= REFUSAL_SECONDS and more >= REFUSAL_SECONDS
    assert abs(more - little) < 0.0002


# --- changing the file: the UI and nervus-ctl, one at a time (ADR-0014) ----------------

import os  # noqa: E402
import stat  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402

from nervus.switches import change_switches  # noqa: E402


def test_a_change_is_written_whole_keeping_mode_and_leaving_nothing_behind(tmp_path):
    path = _file(tmp_path, ON)
    os.chmod(path, 0o640)
    new = change_switches(path, lambda s: Switches(lockdown=s.lockdown, disabled=s.disabled | {"t1"}))
    assert new == load_switches(path) == Switches(lockdown=False, disabled=frozenset({"t1"}))
    assert stat.S_IMODE(path.stat().st_mode) == 0o640
    assert [p.name for p in tmp_path.iterdir()] == ["switches.yaml"]


def test_an_unreadable_file_is_not_changed(tmp_path):
    path = _file(tmp_path, "lockdown: [\n")
    with pytest.raises(SwitchesUnreadable):
        change_switches(path, lambda s: s)
    assert path.read_text() == "lockdown: [\n"


def test_two_writers_at_the_same_moment_both_land(tmp_path):
    """ADR-0014 verification 4. Each writer reads, changes and writes; with a
    pause between reading and writing, two writers without the lock would
    lose each other's changes."""
    path = _file(tmp_path, ON)

    def writer(prefix):
        for i in range(8):
            def add(s, name=f"{prefix}{i}"):
                time.sleep(0.005)
                return Switches(lockdown=s.lockdown, disabled=s.disabled | {name})
            change_switches(path, add)

    threads = [threading.Thread(target=writer, args=(p,)) for p in ("ui-", "ctl-")]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert load_switches(path).disabled == {f"{p}{i}" for p in ("ui-", "ctl-") for i in range(8)}


# --- written through its handle (procedure 058) --------------------------------------------


def test_a_new_copy_swapped_for_a_link_carries_no_chmod_or_chown_to_what_it_names(tmp_path, monkeypatch):
    # The switches file's folder is nervus's account's, and nervus-ctl writes the file as root. A
    # process of that account can swap the new copy's name for a link while root writes it; the
    # name must not then carry root's chmod and chown to whatever the link names.
    import os
    import stat

    from nervus import switches
    path = tmp_path / "switches.yaml"
    path.write_text(ON)
    path.chmod(0o600)
    outside = tmp_path / "root-file"
    outside.write_text("root's\n")
    outside.chmod(0o644)
    real_fsync = os.fsync

    def swap(fd):
        real_fsync(fd)
        new = next(p for p in tmp_path.iterdir() if p.name.startswith(".switches."))
        new.unlink()
        new.symlink_to(outside)
    monkeypatch.setattr(switches.os, "fsync", swap)
    with pytest.raises(SwitchesUnreadable) as refused:
        switches.change_switches(path, lambda now: Switches(lockdown=True, disabled=now.disabled))
    assert "swapped" in str(refused.value)
    assert stat.S_IMODE(outside.stat().st_mode) == 0o644 and outside.read_text() == "root's\n"
    assert not path.is_symlink() and load_switches(path).lockdown is False  # not changed
    assert sorted(p.name for p in tmp_path.iterdir()) == ["root-file", "switches.yaml"]
