"""Reading the audit log for the UI's viewer (ADR-0013).

The viewer reads the log file itself at each request; there is no copy of it
anywhere else (decision A). The newest records are read from the end of the
file backwards, so the first page costs the same however large the log grows;
a filter or a search reads further back, until it fills a page or reaches the
start.

One row is one call (decision B): an intent and its result, matched by id; a
refusal; an operator action; or a line that is not a readable record, which is
shown, never skipped (decision H). A row sits where its newest record is, so a
page is one stretch of the file, and a result looks back for its intent, which
is almost always the line just before it. An intent with no result says "no
result recorded": the log cannot tell a call still running from one that never
finished.

A line without its newline is a record still being written, and is left out
until it is complete. Paging carries two positions in the file: where the next
page starts, and how long the file was when the first page was read. Every page
after the first reads the log as it was then, so records appended while the
operator pages back change nothing they see until they return to the newest.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

from nervus import plainfile

PAGE_ROWS = 100
CUT_CHARACTERS = 160
_CHUNK = 64 * 1024


def _parse(raw: bytes) -> dict[str, Any] | None:
    """A line as a record, or None if it is not one."""
    try:
        record = json.loads(raw)
    except ValueError:  # bad JSON, and bad UTF-8 too
        return None
    return record if isinstance(record, dict) else None


@dataclass(frozen=True)
class Entry:
    """One line of the log: where it starts, its bytes without the newline, and
    the record it holds, or None if it holds none."""

    offset: int
    raw: bytes
    record: dict[str, Any] | None

    @property
    def end(self) -> int:
        return self.offset + len(self.raw) + 1

    @property
    def phase(self) -> object:
        return self.record.get("phase") if self.record is not None else None

    def text(self) -> str:
        """The line as text, whatever its bytes: undecodable ones as \\x.. escapes."""
        return self.raw.decode("utf-8", "backslashreplace")


_KINDS = {"intent": "call", "result": "call", "refused": "refused", "operator": "operator"}

# The operator's actions in the UI whose `target` is a machine (ADR-0024, ADR-0026). Every other
# action's target is a token, which may bear a machine's name and is not one.
_MACHINE_ACTIONS = frozenset({"connect", "enrollment_code", "move_machine", "remove_machine"})


def _vm(value: object) -> str:
    """A VM named by its id, as the viewer shows and finds it: `vmid 104`. "" for what is not an
    id: a call's record holds one as a number, an upload's as the digits it was sent."""
    if isinstance(value, bool):
        return ""
    if isinstance(value, str) and value.isascii() and value.isdigit() and len(value) <= 10:
        value = int(value)
    return f"vmid {value}" if isinstance(value, int) else ""


def cut(text: str, limit: int = CUT_CHARACTERS) -> tuple[str, str]:
    """What the list shows of a value (decision C): its first line, at most
    `limit` characters, and a note saying how much is left out, or "" if
    nothing is."""
    lines = text.split("\n")
    shown = lines[0][:limit]
    if shown == text:
        return shown, ""
    note = f"… {len(text):,} characters"
    if len(lines) > 1:
        note += f", {len(lines):,} lines"
    return shown, note


@dataclass(frozen=True)
class Row:
    """One row of the viewer: the entries it came from, oldest first."""

    entries: tuple[Entry, ...]

    @property
    def at(self) -> int:
        """Where the row sits in the file: its newest entry, which is also how
        the row's own page is found."""
        return self.entries[-1].offset

    @property
    def kind(self) -> str:
        if self.entries[0].record is None:
            return "unreadable"
        return _KINDS.get(self.entries[0].phase, "other")  # type: ignore[arg-type]

    def _first(self) -> dict[str, Any]:
        return self.entries[0].record or {}

    def _get(self, name: str) -> str:
        value = self._first().get(name)
        return value if isinstance(value, str) else ""

    @property
    def intent(self) -> Entry | None:
        return next((e for e in self.entries if e.phase == "intent"), None)

    @property
    def result(self) -> Entry | None:
        return next((e for e in self.entries if e.phase == "result"), None)

    @property
    def when(self) -> float | None:
        ts = self._first().get("ts")
        return float(ts) if isinstance(ts, (int, float)) and not isinstance(ts, bool) else None

    @property
    def client(self) -> str:
        """The token that made the call, or the actor, `operator`."""
        return self._get("token_id") or self._get("actor")

    @property
    def machines(self) -> tuple[str, ...]:
        """Every machine the row is about, as the Host column shows them and
        its filter finds them, whatever the record calls it: the `host` a call
        names; a VM a call names by its id instead (ADR-0022), as `vmid 104`;
        the machine an enrollment is of; and the machine the operator's action
        in the UI, or a form the Machines page refused, was about."""
        first = self._first()
        found = [self._get("host"), _vm(first.get("vmid"))]
        if self.tool == "enroll":
            found.append(self._get("name"))
        if self.tool == "ui" and (first.get("page") == "machines" if self.kind == "refused"
                                  else self._get("action") in _MACHINE_ACTIONS):
            found.append(self._get("target"))
        return tuple(dict.fromkeys(name for name in found if name))

    @property
    def host(self) -> str:
        """The first of `machines`, or "" for a row about none."""
        return next(iter(self.machines), "")

    @property
    def tool(self) -> str:
        return self._get("tool")

    @property
    def subject(self) -> str:
        """What the call was about: its command, path or reason."""
        if self.kind == "unreadable":
            return self.entries[0].text()
        r = self._first()
        if self.kind == "refused":
            return self._get("reason")
        if self.kind == "operator":
            return " ".join(v for v in (self._get("action"), self._get("target")) if v)
        if "command" in r:
            return self._get("command")
        if "path" in r:
            return " ".join(v for v in (self._get("method"), self._get("path")) if v)
        if "job_id" in r:
            return " ".join(v for v in (self._get("action"), self._get("job_id")) if v)
        if "local_path" in r and "remote_path" in r:
            ends = (self._get("local_path"), self._get("remote_path"))
            return " → ".join(ends if self.tool == "put" else ends[::-1])
        return ""

    @property
    def outcome(self) -> str:
        if self.kind == "unreadable":
            return "unreadable record"
        if self.kind == "refused":
            return "refused"
        if self.kind != "call":
            return ""
        result = self.result
        if result is None:
            return "no result recorded"
        r = result.record or {}
        parts = []
        if r.get("exit_code") is not None:
            parts.append(f"exit {r['exit_code']}")
        elif r.get("status") is not None:
            parts.append(f"HTTP {r['status']}")
        elif "error" in r:
            parts.append("error")
        else:
            parts.append("done")
        if r.get("timed_out") is True:
            parts.append("timed out")
        if r.get("truncated") is True:
            parts.append("output cut")
        duration = r.get("duration_s")
        if isinstance(duration, (int, float)) and not isinstance(duration, bool):
            parts.append(f"{duration:.1f} s")
        return " · ".join(parts)

    def texts(self) -> Iterator[str]:
        """Every value in the row, as text, for the search (decision E)."""
        for entry in self.entries:
            if entry.record is None:
                yield entry.text()
                continue
            for value in entry.record.values():
                yield value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)


@dataclass(frozen=True)
class Query:
    """The viewer's filters and search (decision E). Empty means any."""

    client: str = ""
    host: str = ""
    tool: str = ""
    kind: str = ""
    text: str = ""

    def matches(self, row: Row) -> bool:
        for name in ("client", "tool", "kind"):
            wanted = getattr(self, name)
            if wanted and getattr(row, name) != wanted:
                return False
        # A machine by any name the row has for it; a VM also by its id alone, as a person types it.
        if self.host and self.host not in row.machines and (_vm(self.host) or None) not in row.machines:
            return False
        if self.text:
            needle = self.text.casefold()
            return any(needle in value.casefold() for value in row.texts())
        return True


@dataclass(frozen=True)
class Cursor:
    """Where an older page starts, and the length of the log it reads."""

    before: int
    horizon: int


@dataclass(frozen=True)
class Page:
    rows: list[Row]
    older: Cursor | None  # None: this page reaches the start of the log


class _Log:
    """The log file as it is at `size` bytes: only lines that end before it,
    with their newline, are read."""

    def __init__(self, f: BinaryIO, horizon: int | None = None):
        self.f = f
        actual = os.fstat(f.fileno()).st_size
        self.size = actual if horizon is None else min(horizon, actual)

    def starts_line(self, offset: int) -> bool:
        if not 0 <= offset <= self.size:
            return False
        if offset == 0:
            return True
        self.f.seek(offset - 1)
        return self.f.read(1) == b"\n"

    def backward(self, end: int) -> Iterator[tuple[int, bytes]]:
        """(offset, line) for every complete line before `end`, newest first."""
        pos, buf, found_end = end, b"", False
        while True:
            # buf is the file from pos; once found_end, it ends with a newline.
            if not found_end:
                last = buf.rfind(b"\n")
                if last != -1:
                    buf, found_end = buf[: last + 1], True
            if found_end:
                while (start := buf.rfind(b"\n", 0, len(buf) - 1)) != -1:
                    yield pos + start + 1, buf[start + 1 : -1]
                    buf = buf[: start + 1]
                if pos == 0:
                    yield 0, buf[:-1]
                    return
            elif pos == 0:
                return
            n = min(_CHUNK, pos)
            pos -= n
            self.f.seek(pos)
            chunk = self.f.read(n)
            if len(chunk) != n:
                return  # the file shrank under us; show what was read
            buf = chunk + buf

    def forward(self, start: int) -> Iterator[tuple[int, bytes]]:
        """(offset, line) for every complete line from `start`, oldest first."""
        self.f.seek(start)
        offset = start
        while offset < self.size:
            line = self.f.readline()
            if not line.endswith(b"\n") or offset + len(line) > self.size:
                return
            yield offset, line[:-1]
            offset += len(line)

    def entry_at(self, offset: int) -> Entry | None:
        if not self.starts_line(offset):
            return None
        for start, raw in self.forward(offset):
            return Entry(start, raw, _parse(raw))
        return None


def _match(offset: int, raw: bytes, run_id: str, phase: str) -> Entry | None:
    """The entry, if this line is the `phase` record of call `run_id`. A cheap
    look at the bytes first, so a search for one call parses almost nothing."""
    if run_id.encode() not in raw:
        return None
    record = _parse(raw)
    if record is not None and record.get("id") == run_id and record.get("phase") == phase:
        return Entry(offset, raw, record)
    return None


# Pairing an intent with its result normally looks only a few records away. The
# search is bounded so a flood of records written between a pair cannot make the
# whole-log scan quadratic (procedure 056, finding 3); beyond the bound the two
# are shown as separate rows rather than scanned for without limit.
_PAIR_SCAN_LIMIT = 2000


def _find_intent(log: _Log, result: Entry) -> Entry | None:
    run_id = (result.record or {}).get("id")
    if not isinstance(run_id, str):
        return None
    for scanned, (offset, raw) in enumerate(log.backward(result.offset)):
        if scanned >= _PAIR_SCAN_LIMIT:
            return None
        if (found := _match(offset, raw, run_id, "intent")) is not None:
            return found
    return None


def _find_result(log: _Log, intent: Entry) -> Entry | None:
    run_id = (intent.record or {}).get("id")
    if not isinstance(run_id, str):
        return None
    for scanned, (offset, raw) in enumerate(log.forward(intent.end)):
        if scanned >= _PAIR_SCAN_LIMIT:
            return None
        if (found := _match(offset, raw, run_id, "result")) is not None:
            return found
    return None


def _rows(log: _Log, end: int) -> Iterator[tuple[Row, int]]:
    """Every row whose newest entry is before `end`, newest first, each with
    the position the scan has reached: where the next page would start."""
    lines = log.backward(end)
    pending: tuple[int, bytes] | None = None
    shown: set[int] = set()  # intents already shown with a result in this scan
    while True:
        if pending is not None:
            (offset, raw), pending = pending, None
        elif (line := next(lines, None)) is not None:
            offset, raw = line
        else:
            return
        entry = Entry(offset, raw, _parse(raw))
        scanned = offset
        if entry.phase == "result" and isinstance(run_id := entry.record.get("id"), str):  # type: ignore[union-attr]
            intent = None
            following = next(lines, None)
            if following is not None:
                intent = _match(*following, run_id, "intent")
                if intent is None:
                    pending = following
                else:
                    scanned = intent.offset
            if intent is None:
                intent = _find_intent(log, entry)
                if intent is not None:
                    shown.add(intent.offset)
            yield Row((intent, entry) if intent else (entry,)), scanned
        elif entry.phase == "intent":
            if entry.offset in shown or _find_result(log, entry) is not None:
                continue  # shown with its result, which is newer
            yield Row((entry,)), scanned
        else:
            yield Row((entry,)), scanned


def read_page(path: Path, query: Query = Query(), cursor: Cursor | None = None,
              limit: int = PAGE_ROWS) -> Page:
    """Up to `limit` rows matching `query`, newest first: from the end of the
    log, or from `cursor`. A cursor that does not fit the file, which an
    address can carry, is ignored, and the page starts from the newest.

    A full page offers older rows without looking for one: knowing that none
    matches could mean reading the rest of the file. So the last Older may
    lead to an empty page."""
    with plainfile.open_file(path) as f:
        log = _Log(f)
        if cursor is not None:
            within = _Log(f, cursor.horizon)
            if (cursor.horizon <= log.size and log.starts_line(cursor.horizon)
                    and 0 < cursor.before <= cursor.horizon and within.starts_line(cursor.before)):
                log = within
            else:
                cursor = None
        rows: list[Row] = []
        for row, scanned in _rows(log, cursor.before if cursor else log.size):
            if query.matches(row):
                rows.append(row)
                if len(rows) == limit:
                    return Page(rows, Cursor(scanned, log.size) if scanned > 0 else None)
        return Page(rows, None)


def read_row(path: Path, at: int) -> Row | None:
    """The row whose newest entry starts at `at`, with every entry it came
    from, for the row's own page; None if no complete line starts there."""
    with plainfile.open_file(path) as f:
        log = _Log(f)
        entry = log.entry_at(at)
        if entry is None:
            return None
        if entry.phase == "result":
            intent = _find_intent(log, entry)
            return Row((intent, entry) if intent else (entry,))
        if entry.phase == "intent":
            result = _find_result(log, entry)
            return Row((entry, result) if result else (entry,))
        return Row((entry,))
