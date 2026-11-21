from __future__ import annotations

import stat
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from nervus import plainfile

if TYPE_CHECKING:
    from nervus.certs import CertificateAuthority


class ConfigError(Exception):
    """A configuration file is missing, malformed, or insecurely permissioned."""


# What `hypervisor:` may say in the inventory (ADR-0019 decision D). One value
# today; another platform adds a value and the code for its API.
HYPERVISORS = ("proxmox",)


@dataclass(frozen=True)
class Host:
    name: str
    address: str
    os: str
    role: str
    agent_user: str
    status: str
    # ADR-0019 decision D: what a host is for comes from the inventory, never
    # from its name. `hypervisor` names the platform whose API this entry's
    # allowlist gates; `never_issued` is `issue: never`, an entry the UI never
    # issues a token for.
    hypervisor: str | None = None
    never_issued: bool = False
    # ADR-0024: a machine enrolled from the UI carries its own pinned host keys
    # ("type base64"), used in place of the known_hosts file, and the level its
    # owner chose. A hand-written entry has neither.
    host_keys: tuple[str, ...] = ()
    level: str | None = None
    # ADR-0031: the machine's read-only account, where it has one: one added from
    # the UI since, the read-only account its enrollment made; one added before,
    # at read-only, `agent`; one described by hand, the one its owner added from
    # the Machines page. `agent_user` is then the read-write account, or at
    # read-only alone the read-only one. nervus.accounts chooses between them.
    readonly_user: str | None = None


@dataclass(frozen=True)
class Settings:
    hosts: dict[str, Host]
    tokens_path: Path
    known_hosts_path: Path
    ssh_key_path: Path
    audit_log_path: Path
    transfer_dir: Path
    bind_host: str
    bind_port: int
    ssh_port: int = 22
    # The off switch (ADR-0003). nervus's entrypoint always sets it.
    switches_path: Path | None = None
    # nervus's SSH certificate authority (ADR-0025), which signs a certificate
    # for each connection made on a client's call. nervus's entrypoint always
    # sets it; without it, nervus offers its plain key alone, as before.
    ssh_ca: CertificateAuthority | None = None


def load_hosts(path: Path) -> dict[str, Host]:
    """Load the fleet inventory from hosts.yaml.

    Returns hosts keyed by name. Does not contact any host -- values are
    only as good as their provenance in the file itself (see hosts.yaml's
    header comment and CLAUDE.md rule 2).
    """
    try:
        raw = yaml.safe_load(plainfile.read_text(path))
    except FileNotFoundError as exc:
        raise ConfigError(f"hosts file not found: {path}") from exc
    except OSError as exc:
        raise ConfigError(f"cannot read the hosts file: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"hosts file is not valid YAML: {path}: {exc}") from exc

    if not isinstance(raw, dict) or not isinstance(raw.get("hosts"), list):
        raise ConfigError(f"hosts file must have a top-level 'hosts' list: {path}")

    hosts: dict[str, Host] = {}
    required_fields = ("name", "address", "os", "role", "agent_user", "status")
    for entry in raw["hosts"]:
        if not isinstance(entry, dict):
            raise ConfigError(f"hosts file entry is not a mapping: {entry!r}")
        missing = [f for f in required_fields if f not in entry]
        if missing:
            raise ConfigError(f"hosts file entry missing fields {missing}: {entry!r}")
        host = Host(
            name=entry["name"],
            address=entry["address"] or "",
            os=entry["os"],
            role=entry["role"],
            agent_user=entry["agent_user"],
            status=entry["status"],
            hypervisor=_hypervisor(entry),
            never_issued=_never_issued(entry),
        )
        if host.name in hosts:
            raise ConfigError(f"duplicate host name in hosts file: {host.name}")
        hosts[host.name] = host

    for kind in HYPERVISORS:
        marked = sorted(h.name for h in hosts.values() if h.hypervisor == kind)
        if len(marked) > 1:
            raise ConfigError(
                f"hosts file marks more than one entry `hypervisor: {kind}` ({', '.join(marked)}); "
                "nervus works with one (ADR-0019 decision D)"
            )
    return hosts


def _hypervisor(entry: dict) -> str | None:
    value = entry.get("hypervisor")
    if value is None or value in HYPERVISORS:
        return value
    raise ConfigError(
        f"hosts file entry {entry['name']!r} has `hypervisor: {value}`; nervus knows only "
        f"{', '.join(HYPERVISORS)}"
    )


def _never_issued(entry: dict) -> bool:
    value = entry.get("issue")
    if value is None:
        return False
    if value == "never":
        return True
    raise ConfigError(
        f"hosts file entry {entry['name']!r} has `issue: {value}`; the only value is `never`"
    )


def hypervisor_host(hosts: dict[str, Host], kind: str = "proxmox") -> str | None:
    """The name of the entry marked `hypervisor: <kind>`, or None if none is."""
    return next((h.name for h in hosts.values() if h.hypervisor == kind), None)


def never_issued(hosts: dict[str, Host]) -> frozenset[str]:
    """The entries marked `issue: never`."""
    return frozenset(h.name for h in hosts.values() if h.never_issued)


def require_private_file(path: Path) -> None:
    """Refuse to proceed if path is not a regular file readable only by its owner.

    Applies to the tokens file and known_hosts (rule 7: secrets never enter
    the repository, and never get read from a world- or group-readable
    file once deployed).
    """
    try:
        status = path.stat()
    except FileNotFoundError as exc:
        raise ConfigError(f"required file not found: {path}") from exc
    if not stat.S_ISREG(status.st_mode):
        # A pipe made 0600 passed the check below, and whatever read it next waited for ever.
        raise ConfigError(f"refusing to use {path}: it is a {plainfile.kind(status.st_mode)}, not a file")
    mode = stat.S_IMODE(status.st_mode)

    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ConfigError(
            f"refusing to use {path}: mode {oct(mode)} is readable or writable "
            "by group or other; it must be 0600"
        )
