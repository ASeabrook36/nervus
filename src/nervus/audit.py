from __future__ import annotations

import hashlib
import json
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nervus import plainfile


class AuditError(Exception):
    """The audit log could not be written. Per ADR-0001 section 10, the call this
    record belongs to must be refused, not merely logged as best-effort."""


class AuditRefused(AuditError):
    """A call whose intent is too large to record whole. Cut to fit, the record
    would keep only the start of what the call asked for, and a long call could
    hide its end; so the call is refused, and a bounded refusal recorded in its
    place (ADR-0013, amendment 2026-11-13)."""


# A client supplies some record fields (a command, a path, proxmox params). Left
# unbounded, one call could write a line of many megabytes -- a non-BMP character
# becomes 12 bytes once JSON-escaped -- which wedges the off-box audit copy (the
# puller refuses a line over 8 MiB) and bloats the operator's audit viewer. Each
# string is capped and marked; a pathological record falls back to nervus's own
# fields (procedure 056, finding 3). The intent-before-effect record still exists
# (ADR-0001 s10); only over-long client text is shortened.
_STRING_CAP = 4096          # characters kept per string value in a record
_LINE_CAP = 256 * 1024      # bytes; a record still larger keeps only nervus's own fields
_OWN_FIELDS = frozenset({"id", "phase", "ts", "tool", "actor", "action"})


def _clamp(value: Any) -> Any:
    if isinstance(value, str) and len(value) > _STRING_CAP:
        return value[:_STRING_CAP] + f"…[+{len(value) - _STRING_CAP} chars truncated]"
    if isinstance(value, Mapping):
        return {k: _clamp(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_clamp(v) for v in value]
    return value


def _bounded(record: dict[str, Any]) -> dict[str, Any]:
    clamped = {k: (v if k in _OWN_FIELDS else _clamp(v)) for k, v in record.items()}
    if len(json.dumps(clamped, sort_keys=True).encode("utf-8")) <= _LINE_CAP:
        return clamped
    kept = {k: v for k, v in clamped.items() if k in _OWN_FIELDS}
    kept["truncated"] = f"client fields over {_LINE_CAP} bytes were dropped from this record"
    return kept


@dataclass(frozen=True)
class AuditLog:
    """Append-only JSONL audit log.

    Every tool call writes an "intent" record before doing anything, and a
    "result" record after. If the intent record can't be written, the
    caller must not proceed -- see record_intent's docstring.
    """

    path: Path

    def record_intent(self, tool: str, fields: Mapping[str, Any]) -> str:
        """Write the intent record for a call about to happen.

        Returns the run id that ties this intent to its later result.
        Raises AuditError if the record could not be written -- the caller
        must treat that as a refusal to perform the call at all, per
        ADR-0001 section 10. An intent is written whole, never cut to fit:
        one too large for a line raises AuditRefused, an AuditError, after
        recording a bounded refusal that carries the arguments' hash.
        """
        run_id = str(uuid.uuid4())
        line = json.dumps({"id": run_id, "phase": "intent", "ts": time.time(), "tool": tool, **fields},
                          sort_keys=True)
        size = len(line.encode("utf-8"))
        if size > _LINE_CAP:
            self.record_refusal(tool, {
                **fields,
                "refused": "too_large_to_record",
                "reason": f"the call's record would be {size} bytes; the audit log keeps one whole only up to "
                          f"{_LINE_CAP}",
                "arguments_sha256": hashlib.sha256(json.dumps(dict(fields), sort_keys=True).encode()).hexdigest(),
            })
            raise AuditRefused(f"nothing was done: this call's arguments are too large for the audit log to keep "
                               f"whole ({size} bytes as recorded; at most {_LINE_CAP}). Send large content as "
                               "an upload, then work on the file")
        self._write(line)
        return run_id

    def record_result(self, run_id: str, tool: str, fields: Mapping[str, Any]) -> None:
        """Write the result record for a call whose intent was already recorded."""
        self._append(
            {
                "id": run_id,
                "phase": "result",
                "ts": time.time(),
                "tool": tool,
                **fields,
            }
        )

    def record_refusal(self, tool: str, fields: Mapping[str, Any]) -> str:
        """Write a record for a call that was refused before it ran.

        ADR-0001 section 10 requires every tool call to append a record, and
        a refused call is still a call -- arguably the most interesting kind,
        since the audit log is the only place an attempted access violation
        appears at all. Before this existed, a token denied a host raised
        before reaching record_intent and left nothing behind but a traceback
        in the journal.

        A refusal has no result to pair with, so it is a phase of its own
        rather than an intent left permanently dangling. Dangling intents
        mean something different -- a call that started and never finished.
        """
        run_id = str(uuid.uuid4())
        self._append(
            {
                "id": run_id,
                "phase": "refused",
                "ts": time.time(),
                "tool": tool,
                **fields,
            }
        )
        return run_id

    def record_operator(self, action: str, fields: Mapping[str, Any], tool: str = "nervus-ctl") -> str:
        """Write a record of something the operator did, with nervus-ctl or, as
        `tool="ui"`, in the UI.

        ADR-0003 decision 6: a kill switch whose use leaves no trace would be a
        strange thing in a system whose audit log is mandatory. The actor is
        "operator" where a client's record has a token id. ADR-0012 decision 6
        records the UI's sign-ins the same way.
        """
        run_id = str(uuid.uuid4())
        self._append(
            {
                "id": run_id,
                "phase": "operator",
                "ts": time.time(),
                "tool": tool,
                "actor": "operator",
                "action": action,
                **fields,
            }
        )
        return run_id

    def _append(self, record: dict[str, Any]) -> None:
        """A result, refusal or operator record, cut to keep its line bounded."""
        self._write(json.dumps(_bounded(record), sort_keys=True))

    def _write(self, line: str) -> None:
        try:
            with plainfile.open_to_append(self.path) as f:
                f.write(line + "\n")
                f.flush()
        except OSError as exc:
            raise AuditError(f"could not write audit record to {self.path}: {exc}") from exc
