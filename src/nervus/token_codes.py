"""One-time codes that hand a token to the computer its client runs on (ADR-0032 question 5 a).

Issuing a token on the Clients page makes, beside it, a code that works once, within 15 minutes,
as a machine's enrollment code does. The page shows a line with the code in it; the person runs
it on their laptop, and the script it fetches (nervus.laptop) presents the code once more to be
handed the token. The token is never on a screen, in a clipboard, or in a command's arguments.

What it holds to:
- **A token issued with a code has no value until its code is used.** It is kept under the hash
  of a value made and thrown away at once, which nothing can present, so until then it lets no
  one in. When the code is used, nervus makes the token's value, keeps its hash in place of that
  one, and hands the value over, once, in the same transaction. Nothing secret is kept while it
  waits: a copy of the database hands over no token.
- **Only a hash of the code is kept** (ADR-0012), as for every code; the page and the audit log
  name a code by its id.
- **A code is used once.** Of two runs that present it at once, one is handed the token and the
  other is told the code was used, which is how a person learns someone got there first; they
  then revoke the token on the Clients page (question 5, "Which computer gets the token").
- **The code knows the client application the token is for**, chosen from a list when it is
  issued: Claude Code, Codex, or other. The script learns it from nervus, by the code.
- **A token whose code expired unused may be given a new one**; one whose value was handed over
  never gets another, nor does a token revoked meanwhile.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass

from nervus.database import TOKEN_BYTES, Database

CODE_SECONDS = 15 * 60
CODE_BYTES = 24  # 192 random bits, in a URL
ID_BYTES = 8
# ADR-0032 question 5: the client applications a token is issued for, the value each is kept
# as, and the words the page and the script use for it.
CLIENTS = {"claude-code": "Claude Code", "codex": "Codex", "other": "another client"}


@dataclass(frozen=True)
class TokenCode:
    id: str
    token_id: str
    client: str  # one of CLIENTS
    made_at: float
    expires_at: float
    used_at: float | None
    used_from: str | None

    def waiting(self, now: float) -> bool:
        return self.used_at is None and self.expires_at > now


class CodeRefused(Exception):
    """A code that hands over nothing, and why: `reason` for the audit log, the message for the person."""

    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason, self.message = reason, message


_COLUMNS = "id, token_id, client, made_at, expires_at, used_at, used_from"


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _now(now: float | None) -> float:
    return time.time() if now is None else now


class TokenCodes:
    def __init__(self, database: Database):
        self.database = database

    @staticmethod
    def _get(db, column: str, value: str) -> TokenCode | None:
        row = db.execute(f"SELECT {_COLUMNS} FROM token_code WHERE {column} = ?", (value,)).fetchone()
        return TokenCode(*row) if row else None

    def _insert(self, db, token_id: str, client: str, now: float) -> tuple[str, str]:
        value, code_id = secrets.token_urlsafe(CODE_BYTES), secrets.token_hex(ID_BYTES)
        db.execute("INSERT INTO token_code (id, hash, token_id, client, made_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
                   (code_id, _hash(value), token_id, client, now, now + CODE_SECONDS))
        return value, code_id

    def issue(self, id: str, client_kind: str, client: str, project: str, hosts: list[str], now: float | None = None,
              **issued) -> tuple[str, TokenCode]:
        """Issue a token that waits for its code, and that code, in one transaction: the code's
        value, which exists only in what the caller shows, and its record. `client_kind` is one of
        CLIENTS; `client` the name the token is kept with, as the audit log says it. The rest is
        Database.issue_token's, which raises TokenRefused."""
        if client_kind not in CLIENTS:
            raise ValueError(f"not a client nervus knows: {client_kind!r}")
        now = _now(now)
        made: list[tuple[str, str]] = []

        def waiting(db) -> None:
            # A code left from an earlier token of this id never reaches this one (Database.revoke_token).
            db.execute("DELETE FROM token_code WHERE token_id = ?", (id,))
            made.append(self._insert(db, id, client_kind, now))
        self.database.issue_token(id, client, project, hosts, now=now, waiting=waiting, **issued)
        value, code_id = made[0]
        with self.database.transaction(write=False) as db:
            return value, self._get(db, "id", code_id)

    def again(self, token_id: str, now: float | None = None) -> tuple[str, TokenCode]:
        """A new code for a token whose last expired unused (ValueError otherwise): only a token
        issued to wait has codes, and one whose value was handed over never gets another."""
        now = _now(now)
        with self.database.transaction() as db:
            before = [TokenCode(*row) for row in db.execute(
                f"SELECT {_COLUMNS} FROM token_code WHERE token_id = ? ORDER BY made_at, id", (token_id,)).fetchall()]
            if not before or not _token_exists(db, token_id):
                raise ValueError(f"{token_id} is not a token issued here to wait for its line")
            if any(code.used_at is not None for code in before):
                raise ValueError(f"{token_id}'s value was handed over already, by its line; a token is handed over "
                                 f"once")
            if any(code.waiting(now) for code in before):
                raise ValueError(f"{token_id}'s line still works")
            value, code_id = self._insert(db, token_id, before[-1].client, now)
            return value, self._get(db, "id", code_id)

    def find(self, value: str, now: float | None = None) -> TokenCode | None:
        """The code, if it is unused and in time, and its token is still issued; otherwise None."""
        now = _now(now)
        with self.database.transaction(write=False) as db:
            code = self._get(db, "hash", _hash(value))
            if code is None or not code.waiting(now) or not _token_exists(db, code.token_id):
                return None
            return code

    def known(self, value: str) -> TokenCode | None:
        """The code's record whatever became of it, for saying why it hands over nothing."""
        with self.database.transaction(write=False) as db:
            return self._get(db, "hash", _hash(value))

    def hand_over(self, value: str, used_from: str, now: float | None = None) -> tuple[str, TokenCode]:
        """The token's value, made now, its hash put in place, and the code spent, in one
        transaction: or CodeRefused, saying why, with nothing changed. A token is handed over
        once: if any code of it was used already, this one hands over nothing."""
        now = _now(now)
        token_value = secrets.token_urlsafe(TOKEN_BYTES)
        with self.database.transaction() as db:
            code = self._get(db, "hash", _hash(value))
            if code is None:
                raise CodeRefused("unknown", "this line's code is unknown: make a new one on nervus's Clients page")
            spent = db.execute("UPDATE token_code SET used_at = ?, used_from = ? WHERE id = ? AND used_at IS NULL "
                               "AND expires_at > ?", (now, used_from, code.id, now)).rowcount
            if not spent:
                if code.used_at is not None:
                    raise CodeRefused("used", "this line's code was used already, so the token went to whatever "
                                              "ran it first. If that was not you, revoke the token on nervus's "
                                              "Clients page, and issue another")
                raise CodeRefused("expired", "this line's code has expired: on nervus's Clients page, give the "
                                             "token a new line, or issue another")
            if db.execute("SELECT 1 FROM token_code WHERE token_id = ? AND id != ? AND used_at IS NOT NULL",
                          (code.token_id, code.id)).fetchone():
                raise CodeRefused("used", f"the token {code.token_id} was handed over already, by another of its "
                                          "lines, so this one hands over nothing")
            changed = sum(db.execute(f"UPDATE {table} SET hash = ? WHERE id = ?",
                                     (_hash(token_value), code.token_id)).rowcount
                          for table in ("issued_token", "assigned_token"))
            if changed != 1:
                raise CodeRefused("revoked", f"the token {code.token_id} was revoked, so this line hands over "
                                             "nothing: issue another on nervus's Clients page")
            return token_value, self._get(db, "id", code.id)

    def of_tokens(self) -> dict[str, TokenCode]:
        """Each token's latest code, by token id, for the Clients page."""
        with self.database.transaction(write=False) as db:
            rows = db.execute(f"SELECT {_COLUMNS} FROM token_code ORDER BY made_at, id").fetchall()
        return {code.token_id: code for code in map(lambda row: TokenCode(*row), rows)}

    def cancel(self, code_id: str, now: float | None = None) -> None:
        """The code expires now, unused: what the UI does when the record of its making cannot be written."""
        with self.database.transaction() as db:
            db.execute("UPDATE token_code SET expires_at = MIN(expires_at, ?) WHERE id = ?", (_now(now), code_id))


def _token_exists(db, token_id: str) -> bool:
    return db.execute("SELECT 1 FROM issued_token WHERE id = ? UNION SELECT 1 FROM assigned_token WHERE id = ?",
                      (token_id, token_id)).fetchone() is not None
