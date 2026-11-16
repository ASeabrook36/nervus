"""Reading the audit log for the viewer (ADR-0013 decisions A, B, E and H).

The logs here are written by nervus's own AuditLog, so their records have the
shapes the real one has, as read off a deployed nervus on 2026-10-12. No real record is
used: a command can hold anything (rule 7)."""

import json

import pytest

from nervus import audit_view
from nervus.audit import AuditLog
from nervus.audit_view import Cursor, Query, cut, read_page, read_row


@pytest.fixture
def log(tmp_path):
    return AuditLog(path=tmp_path / "audit.jsonl")


def _call(log, command="echo hi", token="claude-code-ops", host="node-a", exit_code=0, result=True):
    run_id = log.record_intent("exec", {"token_id": token, "client": "claude-code", "project": "nervus",
                                        "host": host, "user": "agent", "cwd": "~", "command": command})
    if result:
        log.record_result(run_id, "exec", {"exit_code": exit_code, "duration_s": 0.25, "output_bytes": 3,
                                           "truncated": False, "timed_out": False, "log_path": "x"})
    return run_id


def _ids(page_or_rows):
    rows = page_or_rows.rows if hasattr(page_or_rows, "rows") else page_or_rows
    return [tuple((e.record or {}).get("phase") for e in row.entries) for row in rows]


def _all_pages(path, query=Query(), limit=3, between=None):
    """Every page, oldest last, following the Older cursor as the viewer does."""
    pages, cursor = [], None
    while True:
        page = read_page(path, query, cursor, limit=limit)
        pages.append(page)
        if page.older is None:
            return pages
        cursor = page.older
        if between:
            between()


# --- rows: decision B ------------------------------------------------------------------


def test_newest_first_one_row_per_call(log):
    first = _call(log, "first")
    log.record_refusal("exec", {"token_id": "t", "reason": "token 't' is not allowed to reach host 'node-b'"})
    log.record_operator("lock", {"target": "all", "kill_work": False})
    last = _call(log, "last", exit_code=2)
    page = read_page(log.path)
    assert [r.kind for r in page.rows] == ["call", "operator", "refused", "call"]
    assert _ids(page) == [("intent", "result"), ("operator",), ("refused",), ("intent", "result")]
    assert [r.entries[0].record["id"] for r in (page.rows[0], page.rows[3])] == [last, first]
    assert page.rows[0].subject == "last" and page.rows[0].outcome == "exit 2 · 0.2 s"
    assert page.rows[1].client == "operator" and page.rows[1].subject == "lock all"
    assert page.rows[2].outcome == "refused" and "node-b" in page.rows[2].subject
    assert page.rows[3].client == "claude-code-ops" and page.rows[3].host == "node-a"
    assert page.older is None


def test_a_call_is_one_row_with_other_records_between_its_intent_and_result(log):
    """Two calls at once: their records interleave."""
    a = log.record_intent("exec", {"token_id": "a", "host": "node-a", "command": "slow"})
    b = _call(log, "fast", token="b")
    log.record_refusal("initialize", {"token_id": "c", "reason": "switches: disabled"})
    log.record_result(a, "exec", {"exit_code": 0, "duration_s": 9.0})
    rows = read_page(log.path).rows
    assert [(r.kind, r.client) for r in rows] == [("call", "a"), ("refused", "c"), ("call", "b")]
    assert [e.record["id"] for e in rows[0].entries] == [a, a]
    assert [e.record["id"] for e in rows[2].entries] == [b, b]


def test_a_page_ending_between_intent_and_result_keeps_the_call_whole(log):
    a = log.record_intent("exec", {"token_id": "a", "command": "slow"})
    for i in range(3):
        log.record_refusal("initialize", {"token_id": "c", "reason": f"r{i}"})
    log.record_result(a, "exec", {"exit_code": 0})
    pages = _all_pages(log.path, limit=2)
    assert [_ids(p) for p in pages[:2]] == [[("intent", "result"), ("refused",)], [("refused",), ("refused",)]]
    # A full page cannot know nothing older matches without reading on, so
    # Older may lead to an empty page; here, past the intent already shown.
    assert [p.rows for p in pages[2:]] == [[]]


def test_an_intent_without_a_result_says_so_and_does_not_say_failed(log):
    _call(log, "done")
    _call(log, "running", result=False)
    rows = read_page(log.path).rows
    assert _ids(rows) == [("intent",), ("intent", "result")]
    assert rows[0].outcome == "no result recorded"


def test_a_result_whose_intent_is_missing_is_still_shown(log):
    log.record_result("lost-intent", "exec", {"exit_code": 1, "duration_s": 1.0})
    _call(log)
    rows = read_page(log.path).rows
    assert _ids(rows) == [("intent", "result"), ("result",)]
    assert rows[1].kind == "call" and rows[1].outcome == "exit 1 · 1.0 s"


def test_what_a_row_shows_for_each_tool(log):
    r = log.record_intent("proxmox", {"token_id": "t", "host": "hv", "method": "GET",
                                      "path": "/cluster/resources", "params": {"type": "vm"}})
    log.record_result(r, "proxmox", {"status": 200, "reason": "OK", "body_bytes": 9, "duration_s": 0.1})
    r = log.record_intent("job", {"token_id": "t", "host": "node-b", "job_id": "j1", "action": "status"})
    log.record_result(r, "job", {"action": "status", "job_id": "j1", "running": True, "exit_code": None})
    log.record_refusal("get", {"token_id": "t", "host": "node-b", "local_path": "/etc/x", "reason": "outside"})
    r = log.record_intent("put", {"token_id": "t", "host": "node-b", "local_path": "a", "remote_path": "b"})
    log.record_result(r, "put", {"ok": True})
    r = log.record_intent("exec", {"token_id": "t", "host": "node-b", "command": "sleep 99"})
    log.record_result(r, "exec", {"exit_code": None, "timed_out": True, "truncated": True, "duration_s": 60.0})
    shown = [(row.tool, row.subject, row.outcome) for row in read_page(log.path).rows]
    assert shown == [
        ("exec", "sleep 99", "done · timed out · output cut · 60.0 s"),
        ("put", "a → b", "done"),
        ("get", "outside", "refused"),
        ("job", "status j1", "done"),
        ("proxmox", "GET /cluster/resources", "HTTP 200 · 0.1 s"),
    ]


# --- unreadable lines: decision H --------------------------------------------------------


def test_a_line_that_is_not_a_record_is_a_row_with_its_position(log):
    _call(log)
    with log.path.open("ab") as f:
        bad_at = f.tell()
        f.write(b'{"phase": "intent", "id": \xff broken\n')
        f.write(b"[1, 2]\n")  # JSON, but not a record
    _call(log)
    rows = read_page(log.path).rows
    assert [r.kind for r in rows] == ["call", "unreadable", "unreadable", "call"]
    assert rows[2].at == bad_at and rows[2].outcome == "unreadable record"
    assert rows[2].subject == '{"phase": "intent", "id": \\xff broken'
    assert rows[1].subject == "[1, 2]"


def test_a_last_line_still_being_written_is_left_out_until_complete(log):
    _call(log)
    with log.path.open("ab") as f:
        f.write(b'{"id": "x", "phase": "refused", "tool": "exec"')
    assert _ids(read_page(log.path)) == [("intent", "result")]
    with log.path.open("ab") as f:
        f.write(b', "reason": "r"}\n')
    assert _ids(read_page(log.path)) == [("refused",), ("intent", "result")]


def test_an_empty_or_missing_log(log):
    log.path.write_bytes(b"")
    assert read_page(log.path).rows == []
    log.path.unlink()
    with pytest.raises(FileNotFoundError):
        read_page(log.path)


# --- paging: decisions A and E -------------------------------------------------------------


def _mixed(log, calls=12):
    held = log.record_intent("exec", {"token_id": "held", "command": "slow"})
    for i in range(calls):
        _call(log, f"c{i}", token=f"t{i % 3}", host=("node-a", "node-b")[i % 2])
        if i % 4 == 0:
            log.record_refusal("initialize", {"token_id": "off", "reason": "switches: disabled"})
        if i == 5:
            log.record_result(held, "exec", {"exit_code": 0})
    _call(log, "running", result=False)
    with log.path.open("ab") as f:
        f.write(b"not json\n")


def test_paging_back_shows_every_row_once(log):
    _mixed(log)
    everything = read_page(log.path, limit=1000).rows
    for limit in (1, 2, 3, 7):
        paged = [row for page in _all_pages(log.path, limit=limit) for row in page.rows]
        assert [r.at for r in paged] == [r.at for r in everything], limit
    assert len(everything) == 1 + 12 + 3 + 1 + 1


def test_records_appended_while_paging_back_change_nothing_on_older_pages(log):
    """The pages after the first read the log as it was when the first was
    read. Here a call that was running then, on an older page, finishes while
    the operator pages back: it is still shown, once, as it was."""
    running = _call(log, "running", result=False)
    for i in range(4):
        _call(log, f"c{i}")
    everything = read_page(log.path, limit=1000).rows
    assert [r.outcome for r in everything][-1] == "no result recorded"

    def append():
        if read_page(log.path, Query(text="finished")).rows == []:
            log.record_result(running, "exec", {"exit_code": 0, "log_path": "finished"})
        _call(log, "new")

    paged = [row for page in _all_pages(log.path, limit=2, between=append) for row in page.rows]
    assert [r.at for r in paged] == [r.at for r in everything]
    assert paged[-1].outcome == "no result recorded"
    assert read_page(log.path).rows[0].subject == "new"


@pytest.mark.parametrize("cursor", [
    lambda size: Cursor(before=5, horizon=size),            # not at the start of a line
    lambda size: Cursor(before=size + 1, horizon=size),     # beyond the horizon
    lambda size: Cursor(before=10, horizon=size + 100),     # beyond the file
    lambda size: Cursor(before=0, horizon=size),            # nothing is older than the start
    lambda size: Cursor(before=-1, horizon=size),
])
def test_a_cursor_that_does_not_fit_the_file_is_ignored(log, cursor):
    _mixed(log)
    newest = read_page(log.path, limit=4)
    assert read_page(log.path, cursor=cursor(log.path.stat().st_size), limit=4) == newest


def test_the_newest_page_reads_only_the_end_of_a_large_log(log, monkeypatch):
    """Decision A: the first page costs the same however large the log."""
    with log.path.open("w") as f:
        for i in range(5000):
            for phase in ("intent", "result"):
                f.write(json.dumps({"id": f"{i:036d}", "phase": phase, "tool": "exec", "ts": i,
                                    "command": "x" * 200}) + "\n")
    parsed = []
    real = audit_view._parse
    monkeypatch.setattr(audit_view, "_parse", lambda raw: parsed.append(raw) or real(raw))
    page = read_page(log.path)
    assert len(page.rows) == 100 and page.older is not None
    assert len(parsed) <= 2 * 100 + 2


# --- filters and search: decision E --------------------------------------------------------


def test_each_filter_shows_exactly_the_rows_that_match(log):
    _mixed(log)
    everything = read_page(log.path, limit=1000).rows
    for query, keep in [
        (Query(client="t1"), lambda r: r.client == "t1"),
        (Query(host="node-b"), lambda r: r.host == "node-b"),
        (Query(tool="initialize"), lambda r: r.tool == "initialize"),
        (Query(kind="refused"), lambda r: r.kind == "refused"),
        (Query(kind="call", client="t0", host="node-a"), lambda r: (r.kind, r.client, r.host) == ("call", "t0", "node-a")),
        (Query(client="nobody"), lambda r: False),
    ]:
        expected = [r.at for r in everything if keep(r)]
        assert expected or query.client == "nobody"
        for limit in (2, 1000):
            got = [r.at for page in _all_pages(log.path, query, limit=limit) for r in page.rows]
            assert got == expected, (query, limit)


# --- the machine a row is about, whatever its record calls it (decision E, the Host filter) --------


def _vm_call(log, vmid, command):
    run_id = log.record_intent("exec", {"token_id": "claude-code-ops", "client": "claude-code", "project": "nervus",
                                        "vmid": vmid, "user": "agent", "cwd": "~", "command": command})
    log.record_result(run_id, "exec", {"exit_code": 0, "duration_s": 0.1, "vm_note": "enrolled"})


def _found(log, host):
    return [r.subject for r in read_page(log.path, Query(host=host)).rows]


def test_a_call_that_names_a_vm_by_its_id_shows_it_and_is_found_by_it(log):
    # ADR-0022: a call may name a VM by `vmid`, and its records then name no host. The viewer's Host
    # column was empty for such a call, and no machine filter found it (procedure 034).
    _call(log, "on a host", host="node-a")
    _vm_call(log, 104, "in a vm")
    _vm_call(log, 1040, "in another vm")
    row, = read_page(log.path, Query(host="vmid 104")).rows
    assert row.subject == "in a vm" and row.host == "vmid 104" and row.machines == ("vmid 104",)
    assert _found(log, "104") == ["in a vm"]  # its id alone, as a person would type it
    assert _found(log, "vmid 10") == [] and _found(log, "10") == []  # a whole id, never its beginning
    assert _found(log, "node-a") == ["on a host"] and _found(log, "vmid node-a") == []


def test_a_refused_call_that_named_a_vm_is_found_by_it(log):
    log.record_refusal("exec", {"token_id": "t", "host": None, "vmid": 104,
                                "reason": "VMs need nervus's Proxmox settings (--proxmox)"})
    row, = read_page(log.path, Query(host="vmid 104")).rows
    assert row.kind == "refused" and row.machines == ("vmid 104",)


def test_a_call_through_the_hypervisor_for_a_vm_is_found_by_either(log):
    # An export of a VM's file names the hypervisor's entry and the VM; an upload gives the id as text.
    log.record_intent("export", {"token_id": "t", "request_key": "k1", "host": "hv", "vmid": 104, "path": "/var/log/x"})
    log.record_intent("upload", {"token_id": "t", "request_key": "k2", "vmid": "104",
                                 "destination": {"vmid": "104", "path": "/root/x"}})
    export, upload = reversed(read_page(log.path).rows)
    assert export.machines == ("hv", "vmid 104") and export.host == "hv" and upload.machines == ("vmid 104",)
    assert len(read_page(log.path, Query(host="vmid 104")).rows) == 2
    assert [r.tool for r in read_page(log.path, Query(host="hv")).rows] == ["export"]


@pytest.mark.parametrize("vmid", [True, None, "", "abc", "1" * 40, 1.5, [104], {"id": 104}])
def test_what_is_not_a_vms_id_names_no_machine(log, vmid):
    log.record_refusal("exec", {"token_id": "t", "host": None, "vmid": vmid, "reason": "not a VM id"})
    row, = read_page(log.path).rows
    assert row.machines == () and row.host == ""


def test_enrolling_a_machine_and_an_operators_work_on_it_are_found_by_its_name(log):
    # Their records name the machine as `name` or as `target`, not as `host`. A token's actions use
    # `target` too, and a token may bear a machine's name: those are not about the machine.
    run_id = log.record_intent("enroll", {"actor": "operator", "action": "login", "code_id": "c0de", "name": "web",
                                          "address": "192.0.2.9", "level": "standard", "login": "alice"})
    log.record_result(run_id, "enroll", {"enrolled": True, "outcome": "enrolled web, standard", "exit_status": 0})
    log.record_operator("connect", {"target": "web", "machine_address": "192.0.2.9", "level": "standard"}, tool="ui")
    log.record_operator("enrollment_code", {"target": "web", "code_id": "c0de", "level": "standard"}, tool="ui")
    log.record_operator("move_machine", {"target": "web", "from": "192.0.2.9", "to": "192.0.2.10"}, tool="ui")
    log.record_operator("remove_machine", {"target": "web", "level": "standard"}, tool="ui")
    log.record_refusal("ui", {"actor": "operator", "page": "machines", "action": "connect", "target": "web",
                              "reason": "nervus is locked down, so it enrolls nothing"})
    log.record_operator("lock", {"target": "web", "kill_work": False}, tool="ui")
    log.record_operator("lock", {"target": "web", "kill_work": False})  # nervus-ctl's
    log.record_refusal("ui", {"actor": "operator", "page": "clients", "action": "off", "target": "web",
                              "reason": "There is no token web."})
    rows = read_page(log.path, Query(host="web")).rows
    assert [(r.kind, r.tool, (r.entries[0].record or {}).get("action")) for r in rows] == [
        ("refused", "ui", "connect"), ("operator", "ui", "remove_machine"), ("operator", "ui", "move_machine"),
        ("operator", "ui", "enrollment_code"), ("operator", "ui", "connect"), ("call", "enroll", "login")]
    assert all(r.machines == ("web",) for r in rows)


def test_search_looks_in_every_field_ignoring_case(log):
    _call(log, "rm -rf /tmp/Build — done")
    r = log.record_intent("proxmox", {"token_id": "t", "method": "POST", "path": "/x", "params": {"node": "Hv"}})
    log.record_result(r, "proxmox", {"status": 403, "reason": "Permission check failed"})
    _call(log, "true")
    with log.path.open("ab") as f:
        f.write(b"garbled RM -RF line\n")

    def found(text):
        return [r.subject for r in read_page(log.path, Query(text=text)).rows]

    assert found("RM -rf") == ["garbled RM -RF line", "rm -rf /tmp/Build — done"]
    assert found("— DONE") == ["rm -rf /tmp/Build — done"]
    assert found('"node": "hv"') == ["POST /x"]  # inside an object
    assert found("permission check") == ["POST /x"]  # in the result
    assert found("nothing like it") == []


def test_an_unreadable_line_is_found_by_search_or_no_filter_only(log):
    with log.path.open("ab") as f:
        f.write(b"garbage\n")
    assert [r.kind for r in read_page(log.path).rows] == ["unreadable"]
    assert [r.kind for r in read_page(log.path, Query(text="garb")).rows] == ["unreadable"]
    for query in (Query(client="operator"), Query(kind="call"), Query(host="node-a"), Query(tool="exec")):
        assert read_page(log.path, query).rows == []


# --- one row's own page ------------------------------------------------------------------


def test_read_row_finds_a_call_whole_from_where_it_sits(log):
    _call(log, "before")
    a = log.record_intent("exec", {"token_id": "a", "command": "slow"})
    _call(log, "between")
    log.record_result(a, "exec", {"exit_code": 0})
    rows = read_page(log.path).rows
    row = read_row(log.path, rows[0].at)
    assert [e.record["id"] for e in row.entries] == [a, a] and row.at == rows[0].at
    intent_only = read_row(log.path, row.entries[0].offset)
    assert [e.offset for e in intent_only.entries] == [e.offset for e in row.entries]


def test_read_row_refuses_a_position_that_is_not_a_record(log):
    _call(log)
    size = log.path.stat().st_size
    assert read_row(log.path, 3) is None
    assert read_row(log.path, size) is None
    assert read_row(log.path, size + 10) is None
    assert read_row(log.path, -1) is None
    assert read_row(log.path, 0).kind == "call"


# --- what the list shows of a value: decision C ------------------------------------------


def test_cut_keeps_the_first_line_and_says_what_is_left_out():
    assert cut("short") == ("short", "")
    assert cut("x" * 160) == ("x" * 160, "")
    assert cut("x" * 32857) == ("x" * 160, "… 32,857 characters")
    assert cut("one\ntwo\nthree") == ("one", "… 13 characters, 3 lines")
    assert cut("") == ("", "")


def test_pairing_is_bounded_so_a_far_apart_pair_does_not_scan_the_whole_log(log):
    # intent, then a flood of unrelated records, then the matching result far away.
    run_id = log.record_intent("exec", {"token_id": "t", "client": "c", "project": "p",
                                        "host": "h", "user": "agent", "cwd": "~", "command": "x"})
    for _ in range(audit_view._PAIR_SCAN_LIMIT + 5):
        log.record_operator("noise", {})
    log.record_result(run_id, "exec", {"exit_code": 0, "duration_s": 0.1, "output_bytes": 0,
                                       "truncated": False, "timed_out": False, "log_path": "x"})
    # Reading the intent's row must not scan the whole flood forward to pair it:
    # beyond the bound it is shown on its own (procedure 056, finding 3).
    row = read_row(log.path, 0)
    assert len(row.entries) == 1 and row.entries[0].phase == "intent"
