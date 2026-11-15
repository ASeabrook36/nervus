import os

import pytest

from nervus.config import ConfigError, Host, hypervisor_host, load_hosts, never_issued, require_private_file


HOSTS_YAML = """
hosts:
  - name: node-a
    address: node-a.home.example.net
    os: Ubuntu 26.04 LTS
    role: application host
    agent_user: agent
    status: not-onboarded
  - name: node-b
    address: ""
    os: Ubuntu 26.04 LTS
    role: inference appliance
    agent_user: agent
    status: not-onboarded
"""


def test_load_hosts_parses_all_entries(tmp_path):
    path = tmp_path / "hosts.yaml"
    path.write_text(HOSTS_YAML)

    hosts = load_hosts(path)

    assert set(hosts) == {"node-a", "node-b"}
    assert hosts["node-a"] == Host(
        name="node-a",
        address="node-a.home.example.net",
        os="Ubuntu 26.04 LTS",
        role="application host",
        agent_user="agent",
        status="not-onboarded",
    )
    assert hosts["node-b"].address == ""


def test_load_hosts_missing_file(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_hosts(tmp_path / "does-not-exist.yaml")


def test_load_hosts_rejects_missing_fields(tmp_path):
    path = tmp_path / "hosts.yaml"
    path.write_text("hosts:\n  - name: node-a\n")

    with pytest.raises(ConfigError, match="missing fields"):
        load_hosts(path)


def test_load_hosts_rejects_duplicate_names(tmp_path):
    path = tmp_path / "hosts.yaml"
    path.write_text(
        """
hosts:
  - name: node-a
    address: a
    os: a
    role: a
    agent_user: agent
    status: not-onboarded
  - name: node-a
    address: b
    os: b
    role: b
    agent_user: agent
    status: not-onboarded
"""
    )

    with pytest.raises(ConfigError, match="duplicate"):
        load_hosts(path)


def test_load_hosts_rejects_malformed_yaml(tmp_path):
    path = tmp_path / "hosts.yaml"
    path.write_text("hosts: [this is not: valid: yaml")

    with pytest.raises(ConfigError, match="not valid YAML"):
        load_hosts(path)


# --- what a host is for comes from the inventory (ADR-0019 decision D) --------

def _entry(name: str, extra: str = "") -> str:
    return (f"  - name: {name}\n    address: {name}.example.net\n    os: test\n    role: test\n"
            f"    agent_user: agent\n    status: onboarded\n{extra}")


def _load(tmp_path, *entries: str):
    path = tmp_path / "hosts.yaml"
    path.write_text("hosts:\n" + "".join(entries))
    return load_hosts(path)


def test_the_proxmox_host_is_the_entry_marked_so_whatever_its_name(tmp_path):
    hosts = _load(tmp_path, _entry("node-a"), _entry("hv", "    hypervisor: proxmox\n"),
                  _entry("hv-root", "    issue: never\n"))
    assert hypervisor_host(hosts) == "hv"
    assert never_issued(hosts) == {"hv-root"}
    assert (hosts["node-a"].hypervisor, hosts["node-a"].never_issued) == (None, False)


def test_no_entry_is_the_proxmox_host_by_its_name(tmp_path):
    hosts = _load(tmp_path, _entry("hv"), _entry("hv-root"))
    assert hypervisor_host(hosts) is None
    assert never_issued(hosts) == frozenset()


def test_an_unknown_hypervisor_is_refused_with_what_is_known(tmp_path):
    with pytest.raises(ConfigError, match="`hypervisor: esxi`; nervus knows only proxmox"):
        _load(tmp_path, _entry("hv", "    hypervisor: esxi\n"))


def test_two_proxmox_hosts_are_refused(tmp_path):
    with pytest.raises(ConfigError, match=r"more than one entry `hypervisor: proxmox` \(a, b\)"):
        _load(tmp_path, _entry("a", "    hypervisor: proxmox\n"), _entry("b", "    hypervisor: proxmox\n"))


@pytest.mark.parametrize("value", ["always", "yes", "true"])
def test_issue_takes_only_never(tmp_path, value):
    # YAML reads yes and true as booleans; refused all the same.
    with pytest.raises(ConfigError, match="the only value is `never`"):
        _load(tmp_path, _entry("hv-root", f"    issue: {value}\n"))


def test_require_private_file_accepts_0600(tmp_path):
    path = tmp_path / "tokens"
    path.write_text("secret")
    os.chmod(path, 0o600)

    require_private_file(path)  # must not raise


def test_require_private_file_rejects_group_readable(tmp_path):
    path = tmp_path / "tokens"
    path.write_text("secret")
    os.chmod(path, 0o640)

    with pytest.raises(ConfigError, match="0600"):
        require_private_file(path)


def test_require_private_file_rejects_world_readable(tmp_path):
    path = tmp_path / "tokens"
    path.write_text("secret")
    os.chmod(path, 0o604)

    with pytest.raises(ConfigError, match="0600"):
        require_private_file(path)


def test_require_private_file_missing(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        require_private_file(tmp_path / "missing")


def test_the_example_inventory_in_docs_loads_as_written():
    """docs/hosts.example.yaml is what docs/install.md tells people to copy: it must stay
    something nervus accepts, with its Proxmox host and its never-issued entry marked."""
    from pathlib import Path

    hosts = load_hosts(Path(__file__).resolve().parent.parent / "docs" / "hosts.example.yaml")
    assert hypervisor_host(hosts) == "hv"
    assert never_issued(hosts) == {"hv-root"}
