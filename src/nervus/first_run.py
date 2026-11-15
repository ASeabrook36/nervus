"""First-run setup's choices (ADR-0015 consequence 1.2), kept in the database
(ADR-0011 decision 1) in tables added without changing its version (ADR-0014
decision F).

- **The tier** the operator declares (ADR-0007 decision 2, worded as ADR-0023
  words it): 1, 2 or 3, with who chose it and when. One at a time; changing it
  replaces it (ADR-0015 decision B). Its history is the audit log's, written
  by the caller.
- **Ranges declared internal** (ADR-0015 decision C): each a network, kept in
  one spelling, with who declared it and when. A range is never everything, so
  `/0` is refused. exposure.py turns the warning for an address in one into a
  note naming the declaration.

Every change is one transaction (database.py).
"""

from __future__ import annotations

import datetime
import ipaddress
import time
from dataclasses import dataclass

from nervus.database import Database
from nervus.exposure import Declared

TIERS = (1, 2, 3)
# The tier in a few words, wherever the installation is described: the UI's
# header, the line at every start, nervus-ctl status (ADR-0015 decision E).
# The setup page says each in full (ADR-0023's wording, decision F).
TIER_WORDS = {
    1: "Tier 1: a separate computer",
    2: "Tier 2: your everyday computer, nervus's own account",
    3: "Tier 3: your everyday computer, your account can get in",
}


class SetupRefused(ValueError):
    """A choice that cannot be kept, and why, in words for the operator."""


@dataclass(frozen=True)
class Tier:
    tier: int
    chosen_at: float
    chosen_by: str


def _now(now: float | None) -> float:
    return time.time() if now is None else now


def _network(given) -> str:
    """A range in one spelling: the network an address or range is in."""
    if not isinstance(given, str):
        raise SetupRefused(f"{given!r} is not an address range, such as 192.0.2.0/24")
    try:
        network = ipaddress.ip_network(given.strip(), strict=False)
    except ValueError:
        raise SetupRefused(f"{given!r} is not an address range, such as 192.0.2.0/24") from None
    if network.prefixlen == 0:
        raise SetupRefused(f"{network} is every address: a declaration names a range, never everything")
    return str(network)


@dataclass(frozen=True)
class FirstRun:
    database: Database

    def tier(self) -> Tier | None:
        """The tier declared, or None until setup has chosen one."""
        with self.database.transaction(write=False) as db:
            row = db.execute("SELECT tier, chosen_at, chosen_by FROM setup_tier").fetchone()
        return None if row is None else Tier(*row)

    def choose_tier(self, tier, by: str, now: float | None = None) -> Tier | None:
        """Keep `tier`, and return the one it replaced, if any."""
        if type(tier) is not int or tier not in TIERS:
            raise SetupRefused(f"{tier!r} is not a tier: 1, 2 or 3")
        now = _now(now)
        with self.database.transaction() as db:
            row = db.execute("SELECT tier, chosen_at, chosen_by FROM setup_tier").fetchone()
            db.execute("INSERT OR REPLACE INTO setup_tier (only, tier, chosen_at, chosen_by) VALUES (1, ?, ?, ?)",
                       (tier, now, by))
        return None if row is None else Tier(*row)

    def restore_tier(self, previous: Tier | None) -> None:
        """Put the tier back exactly as `previous` was, or none: undoing a
        change whose audit record could not be written."""
        with self.database.transaction() as db:
            db.execute("DELETE FROM setup_tier")
            if previous is not None:
                db.execute("INSERT INTO setup_tier (only, tier, chosen_at, chosen_by) VALUES (1, ?, ?, ?)",
                           (previous.tier, previous.chosen_at, previous.chosen_by))

    def declared(self) -> list[Declared]:
        """Every range declared internal, in the order declared, each with the
        day it was declared, in UTC as the UI shows times (ADR-0013)."""
        with self.database.transaction(write=False) as db:
            rows = db.execute(
                "SELECT network, declared_by, declared_at FROM declared_range ORDER BY declared_at, network"
            ).fetchall()
        return [Declared(network, by=by, on=datetime.datetime.fromtimestamp(at, datetime.timezone.utc).date().isoformat())
                for network, by, at in rows]

    def declare(self, given, by: str, now: float | None = None) -> str:
        """Declare a range internal; returns it as kept. A range already
        declared is refused, keeping the first declaration."""
        network = _network(given)
        now = _now(now)
        with self.database.transaction() as db:
            if db.execute("SELECT 1 FROM declared_range WHERE network = ?", (network,)).fetchone():
                raise SetupRefused(f"{network} is already declared internal")
            db.execute("INSERT INTO declared_range (network, declared_at, declared_by) VALUES (?, ?, ?)",
                       (network, now, by))
        return network

    def withdraw(self, given) -> bool:
        """Withdraw a declaration. False if that range had none."""
        network = _network(given)
        with self.database.transaction() as db:
            return db.execute("DELETE FROM declared_range WHERE network = ?", (network,)).rowcount > 0
