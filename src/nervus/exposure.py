"""Whether nervus listens on an address someone on the internet could reach
(ADR-0007 decision 4; ADR-0015 decisions C and D).

Nothing on a machine can tell that for certain, so this checks the form of
each address nervus listens on: Python's standard library says whether it is
global, outside every private and reserved range. A range the operator has
declared internal turns the warning for the addresses in it into a note that
names the declaration, never nothing. Checked once, at every start.

What it cannot see: a port forwarded to nervus on a router, since the machine
keeps its private address. The line for a private machine says so.

It only reads. It never refuses a start or a client, and a check that cannot
read says it could not tell (ADR-0015 C, as kept on 2026-10-20).
"""

from __future__ import annotations

import ipaddress
import json
import socket
import subprocess
from dataclasses import dataclass
from typing import Callable, Iterable

from nervus.tls import is_loopback

Address = ipaddress.IPv4Address | ipaddress.IPv6Address


@dataclass(frozen=True)
class Declared:
    """A range declared internal: who declared it, and on which day."""
    network: str
    by: str
    on: str

    def covers(self, address: Address) -> bool:
        return address in ipaddress.ip_network(self.network, strict=False)  # never across families

    @property
    def width(self) -> int:
        return ipaddress.ip_network(self.network, strict=False).num_addresses


@dataclass(frozen=True)
class Exposure:
    bind_host: str
    addresses: tuple[Address, ...] = ()
    declared_for: tuple[tuple[Address, Declared], ...] = ()
    unreadable: str | None = None

    @property
    def public(self) -> list[Address]:
        """Public in form, and in no declared range: the full warning."""
        noted = {address for address, _ in self.declared_for}
        return [a for a in self.addresses if a.is_global and a not in noted]

    @property
    def state(self) -> str:
        if is_loopback(self.bind_host):
            return "loopback"
        if self.unreadable is not None:
            return "unknown"
        if self.public:
            return "public"
        return "noted" if self.declared_for else "private"

    def with_declared(self, declared: Iterable[Declared]) -> Exposure:
        """The same addresses, matched against `declared` now: what each page
        shows, so a declaration made or withdrawn counts at once, while the
        addresses themselves are read only at start (ADR-0015 decision D, as
        clarified on 2026-10-20)."""
        if self.unreadable is not None or is_loopback(self.bind_host):
            return self
        return Exposure(self.bind_host, self.addresses, _match(self.addresses, declared))

    def warning(self) -> str:
        """The warning, in words for a page's banner, or "" if there is none."""
        state = self.state
        if state == "unknown":
            return (f"could not read the addresses nervus listens on ({self.unreadable}), so whether any is "
                    f"public in form is unknown")
        if state != "public":
            return ""
        named = ", ".join(str(a) for a in self.public)
        return (f"nervus listens on {named}, public in form and in no range declared internal: if the internet "
                f"can reach it, it can reach nervus's sign-in and MCP. Public exposure is not supported "
                f"(ADR-0007 decision 4): reach nervus from outside through an overlay network. If this network is "
                f"not reachable from the internet, declare its range internal at setup.")

    def notes(self) -> list[str]:
        """For each address a declared range covers, the note that stands in
        for the warning: never nothing (ADR-0015 decision C)."""
        return [f"{address} is public in form; declared internal by {d.by} on {d.on} ({d.network})"
                for address, d in self.declared_for]

    def lines(self) -> list[str]:
        """What is logged at every start: the warning, the notes, or one line
        saying nothing listened on is public in form."""
        state = self.state
        if state == "loopback":
            return [f"listening on loopback only ({self.bind_host}): not reachable from other machines"]
        lines = [f"WARNING: {self.warning()}"] if self.warning() else []
        lines += [f"note: {note}" for note in self.notes()]
        if state == "private":
            lines.append(
                f"none of the {len(self.addresses)} addresses nervus listens on is public in form. A port "
                f"forwarded to nervus on a router cannot be seen from here: never forward one; reach nervus "
                f"from outside through an overlay network (ADR-0007 decision 4)")
        return lines


def read_interface_addresses(run: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> list[str]:
    """Every address on every interface, from `ip -j address` (Linux's
    iproute2), temporary IPv6 addresses included: they are reachable while
    they last. An answer that cannot be read raises OSError, never an empty
    list, so a machine is never taken for one with no public address."""
    done = run(["ip", "-j", "address", "show"], capture_output=True, text=True, timeout=10)
    if done.returncode != 0:
        raise OSError(f"`ip -j address show` exited {done.returncode}")
    try:
        interfaces = json.loads(done.stdout)
    except ValueError as exc:
        raise OSError(f"`ip -j address show` printed what is not JSON: {exc}") from exc
    if not isinstance(interfaces, list):
        raise OSError("`ip -j address show` printed no list of interfaces")
    found = []
    for interface in interfaces:
        for entry in (interface.get("addr_info") or []) if isinstance(interface, dict) else []:
            if not isinstance(entry, dict):
                continue
            try:
                found.append(str(ipaddress.ip_address(entry.get("local", ""))))
            except ValueError:
                continue
    return found


def resolve_ipv4(name: str) -> list[str]:
    """What a bind name means to nervus's web server, which binds a name as
    IPv4 (uvicorn's `Config.bind_socket`)."""
    return [info[4][0] for info in socket.getaddrinfo(name, None, socket.AF_INET, socket.SOCK_STREAM)]


def _listened_on(bind_host: str, interfaces: Callable[[], list[str]],
                 resolve: Callable[[str], list[str]]) -> list[Address]:
    try:
        bound = ipaddress.ip_address(bind_host)
    except ValueError:
        candidates = resolve(bind_host)
    else:
        if not bound.is_unspecified:
            return [bound]
        # 0.0.0.0 is every IPv4 address; :: is every IPv6 and, as Linux binds
        # it by default, every IPv4 address too.
        candidates = [a for a in interfaces() if bound.version == 6 or ipaddress.ip_address(a).version == 4]
    addresses = []
    for text in candidates:
        try:
            addresses.append(ipaddress.ip_address(text.split("%")[0]))
        except ValueError:
            continue
    return list(dict.fromkeys(addresses))


def _match(addresses: Iterable[Address], declared: Iterable[Declared]) -> tuple[tuple[Address, Declared], ...]:
    """Each address public in form, with the narrowest declared range it is in."""
    ranges = sorted(declared, key=lambda d: d.width)
    found = []
    for address in addresses:
        if address.is_global:
            covering = next((d for d in ranges if d.covers(address)), None)
            if covering is not None:
                found.append((address, covering))
    return tuple(found)


def check(bind_host: str, declared: Iterable[Declared] = (), *,
          interfaces: Callable[[], list[str]] = read_interface_addresses,
          resolve: Callable[[str], list[str]] = resolve_ipv4) -> Exposure:
    """What nervus listens on, judged by form, with the declared ranges each
    public address falls in (the narrowest named). Never raises."""
    if is_loopback(bind_host):
        return Exposure(bind_host)
    try:
        addresses = _listened_on(bind_host, interfaces, resolve)
        if not addresses:
            return Exposure(bind_host, unreadable="no address found")
        return Exposure(bind_host, tuple(addresses), _match(addresses, declared))
    except Exception as exc:  # noqa: BLE001 - the check never stops a start (ADR-0015 C)
        return Exposure(bind_host, unreadable=str(exc) or type(exc).__name__)
