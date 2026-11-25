"""What the UI's clients page shows (ADR-0014 decision G): every token nervus
accepts, from the token file and issued in the UI, whether it is switched
off, and its last call, read from the audit log as the viewer reads it
(ADR-0013). The page itself is pages.page_clients; ui.py makes the changes.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from nervus.audit_view import Query, read_page
from nervus.auth import Token, Tokens
from nervus.database import IssuedToken
from nervus.switches import SwitchesUnreadable, load_switches
from nervus.token_codes import TokenCode


@dataclass(frozen=True)
class ClientRow:
    id: str
    client: str
    project: str
    hosts: tuple[str, ...]
    issued: bool  # issued in the UI, and so revocable there; else from the token file
    off: bool  # switched off one by one; lockdown and an unreadable file are the view's
    last_call: float | None  # when its newest call began; None if the log has none
    readonly: tuple[str, ...] = ()  # ADR-0031: the hosts it is read-only on
    # ADR-0032 question 5: the token's latest line, for a token issued to wait for one; None for one issued
    # before, whose value was shown.
    line: TokenCode | None = None


@dataclass(frozen=True)
class ClientsView:
    rows: list[ClientRow]
    lockdown: bool
    unreadable: str  # why the switch file cannot be read, so every client is refused; "" if it can


def _last_call(audit_log: Path, token_id: str) -> float | None:
    """The newest call by this token: a call, not a refusal, which a switched
    off client makes on every attempt. Read from the end of the log, so a
    token in use costs little; one never used reads it all."""
    try:
        rows = read_page(audit_log, Query(client=token_id, kind="call"), limit=1).rows
    except OSError:
        return None
    return rows[0].when if rows else None


def clients_view(tokens: Tokens, issued: Iterable[IssuedToken], switches: Path, audit_log: Path,
                 lines: dict[str, TokenCode] | None = None) -> ClientsView:
    try:
        state = load_switches(switches)
        lockdown, disabled, unreadable = state.lockdown, state.disabled, ""
    except SwitchesUnreadable as exc:
        lockdown, disabled, unreadable = False, frozenset(), str(exc)

    def row(token: Token, from_ui: bool) -> ClientRow:
        return ClientRow(id=token.id, client=token.client, project=token.project, hosts=tuple(sorted(token.hosts)),
                         issued=from_ui, off=token.id in disabled,
                         last_call=_last_call(audit_log, token.id), readonly=tuple(sorted(token.readonly)),
                         line=(lines or {}).get(token.id) if from_ui else None)

    rows = [row(t, False) for t in tokens.in_file()] + [row(i.token, True) for i in issued]
    return ClientsView(rows=sorted(rows, key=lambda r: r.id), lockdown=lockdown, unreadable=unreadable)
