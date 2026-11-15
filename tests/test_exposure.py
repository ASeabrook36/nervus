"""Whether nervus listens on an address public in form (ADR-0015 decisions C
and D, ADR-0007 decision 4): which addresses it listens on, which of them are
public in form, which a declared range covers, and the line logged at every
start. The check only reads; it never refuses a start (ADR-0015 C, 2026-10-20)."""

import json
import subprocess

import pytest

from nervus.exposure import Declared, check, read_interface_addresses

PRIVATE_V4 = ["127.0.0.1", "192.168.1.10", "10.0.0.5"]
PUBLIC_V4 = "1.2.3.4"
PUBLIC_V6 = "2a01:4f8::10"


def _interfaces(*addresses):
    return lambda: list(addresses)


def _never(*_a, **_k):
    raise AssertionError("not to be read")


def _warnings(exposure):
    return [line for line in exposure.lines() if line.startswith("WARNING")]


@pytest.mark.parametrize("host", ["localhost", "::1"])
def test_loopback_by_name_or_address_reads_nothing(host):
    read = []
    exposure = check(host, interfaces=lambda: read.append("interfaces") or [],
                     resolve=lambda name: read.append(name) or [])
    assert read == []
    assert exposure.state == "loopback"


def test_loopback_says_so():
    exposure = check("127.0.0.1")
    assert exposure.lines() == ["listening on loopback only (127.0.0.1): not reachable from other machines"]


def test_private_addresses_only_are_not_public_and_the_line_names_what_it_cannot_see():
    exposure = check("0.0.0.0", interfaces=_interfaces(*PRIVATE_V4))
    assert exposure.state == "private"
    assert not _warnings(exposure)
    [line] = exposure.lines()
    assert "3 addresses" in line and "none" in line
    assert "port forwarded" in line and "overlay network" in line


def test_an_overlay_networks_shared_range_is_not_public():
    exposure = check("0.0.0.0", interfaces=_interfaces("100.100.1.1", "192.168.1.10"))
    assert exposure.state == "private"


def test_a_public_ipv4_address_undeclared_is_warned_about_by_name():
    exposure = check("0.0.0.0", interfaces=_interfaces(*PRIVATE_V4, PUBLIC_V4))
    assert exposure.state == "public"
    [warning] = _warnings(exposure)
    assert PUBLIC_V4 in warning
    assert "192.168.1.10" not in warning
    assert "declare its range internal" in warning and "overlay network" in warning


def test_ipv6_is_not_listened_on_under_the_ipv4_wildcard():
    exposure = check("0.0.0.0", interfaces=_interfaces("192.168.1.10", PUBLIC_V6))
    assert exposure.state == "private"
    assert PUBLIC_V6 not in " ".join(exposure.lines())


def test_ipv6_and_ipv4_are_both_listened_on_under_the_ipv6_wildcard():
    exposure = check("::", interfaces=_interfaces("192.168.1.10", "fd00::5", PUBLIC_V6, PUBLIC_V4))
    assert exposure.state == "public"
    [warning] = _warnings(exposure)
    assert PUBLIC_V6 in warning and PUBLIC_V4 in warning


def test_a_declared_range_turns_the_warning_into_a_note_naming_it():
    declared = [Declared("1.2.3.0/24", by="operator", on="2026-10-20")]
    exposure = check("0.0.0.0", declared, interfaces=_interfaces(*PRIVATE_V4, PUBLIC_V4))
    assert exposure.state == "noted"
    assert not _warnings(exposure)
    [note] = exposure.lines()
    assert note == "note: 1.2.3.4 is public in form; declared internal by operator on 2026-10-20 (1.2.3.0/24)"


def test_an_address_outside_every_declared_range_still_gets_the_full_warning():
    declared = [Declared("1.2.3.0/24", by="operator", on="2026-10-20")]
    exposure = check("0.0.0.0", declared, interfaces=_interfaces(PUBLIC_V4, "5.6.7.8"))
    assert exposure.state == "public"
    [warning] = _warnings(exposure)
    assert "5.6.7.8" in warning and PUBLIC_V4 not in warning
    assert any(line.startswith("note: 1.2.3.4 ") for line in exposure.lines())


def test_a_range_of_the_other_family_covers_nothing():
    declared = [Declared("2a01:4f8::/32", by="operator", on="2026-10-20")]
    exposure = check("0.0.0.0", declared, interfaces=_interfaces(PUBLIC_V4))
    assert exposure.state == "public"


def test_the_narrowest_declared_range_is_the_one_named():
    declared = [Declared("1.0.0.0/8", by="operator", on="2026-10-01"),
                Declared("1.2.3.0/24", by="operator", on="2026-10-20")]
    exposure = check("0.0.0.0", declared, interfaces=_interfaces(PUBLIC_V4))
    [note] = exposure.lines()
    assert "(1.2.3.0/24)" in note and "2026-10-20" in note


def test_a_bind_to_one_address_checks_that_address_only():
    assert check("192.168.1.10", interfaces=_never).state == "private"
    assert check(PUBLIC_V4, interfaces=_never).state == "public"


def test_a_bind_to_a_name_checks_what_it_resolves_to():
    exposure = check("nervus.example", interfaces=_never, resolve=lambda name: [PUBLIC_V4])
    assert exposure.state == "public"
    assert check("nervus.example", interfaces=_never, resolve=lambda name: ["10.0.0.5"]).state == "private"


def _raises(exc):
    def run(*_a, **_k):
        raise exc
    return run


@pytest.mark.parametrize("failure", [OSError("no ip"), RuntimeError("anything at all"), ValueError("bad")])
def test_a_check_that_cannot_read_says_it_cannot_tell_and_never_raises(failure):
    exposure = check("0.0.0.0", interfaces=_raises(failure))
    assert exposure.state == "unknown"
    [warning] = _warnings(exposure)
    assert "could not read" in warning and "unknown" in warning


def test_a_name_that_does_not_resolve_is_unknown_not_private():
    exposure = check("nervus.example", resolve=_raises(OSError("no such name")))
    assert exposure.state == "unknown"


def test_no_address_at_all_is_unknown_not_private():
    assert check("0.0.0.0", interfaces=_interfaces()).state == "unknown"


# `ip -j address show` as iproute2 prints it, cut to what is read.
IP_JSON = [
    {"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1", "scope": "host"}]},
    {"ifname": "eth0", "addr_info": [
        {"family": "inet", "local": "192.168.1.10", "scope": "global", "dynamic": True},
        {"family": "inet6", "local": "2a01:4f8::10", "scope": "global", "mngtmpaddr": True},
        {"family": "inet6", "local": "2a01:4f8::abcd", "scope": "global", "temporary": True},
        {"family": "inet6", "local": "fe80::5054:ff:fe12:3456", "scope": "link"},
        {"family": "inet6", "scope": "global"},
        {"family": "inet", "local": "not an address", "scope": "global"},
    ]},
    {"ifname": "odd"},
    "junk",
]


def _ran(stdout="", returncode=0):
    return lambda *a, **k: subprocess.CompletedProcess(a, returncode, stdout=stdout, stderr="")


def test_every_address_on_every_interface_is_read_temporary_ones_included():
    # A temporary IPv6 address is reachable while it lasts, so it counts here,
    # unlike in nervus's certificate (tls.machine_addresses).
    assert read_interface_addresses(_ran(json.dumps(IP_JSON))) == [
        "127.0.0.1", "192.168.1.10", "2a01:4f8::10", "2a01:4f8::abcd", "fe80::5054:ff:fe12:3456"]


@pytest.mark.parametrize("run", [_ran("", returncode=1), _ran("not json"), _ran('{"not": "a list"}')])
def test_an_unreadable_answer_from_ip_is_an_error_not_an_empty_machine(run):
    with pytest.raises(OSError):
        read_interface_addresses(run)


# --- for every page: the same addresses, matched again (ADR-0015 D, clarified) -----


def test_the_addresses_from_start_are_matched_again_with_new_declarations():
    found = check("0.0.0.0", interfaces=_interfaces("192.168.1.10", PUBLIC_V4))
    assert found.state == "public"
    declared = found.with_declared([Declared("1.2.3.0/24", by="operator", on="2026-10-20")])
    assert declared.state == "noted" and declared.addresses == found.addresses
    assert declared.with_declared([]).state == "public"
    assert found.state == "public"  # the one from start is kept as it was


def test_the_banners_words_are_the_lines_without_their_labels():
    found = check("0.0.0.0", interfaces=_interfaces(PUBLIC_V4, "5.6.7.8"))
    exposure = found.with_declared([Declared("5.6.7.0/24", by="operator", on="2026-10-20")])
    assert exposure.warning().startswith("nervus listens on 1.2.3.4, public in form")
    assert exposure.notes() == ["5.6.7.8 is public in form; declared internal by operator on 2026-10-20 (5.6.7.0/24)"]
    assert exposure.lines() == ["WARNING: " + exposure.warning(), "note: " + exposure.notes()[0]]


@pytest.mark.parametrize("exposure", [check("127.0.0.1"), check("0.0.0.0", interfaces=_interfaces("10.0.0.5"))])
def test_nothing_public_puts_nothing_on_a_page(exposure):
    assert exposure.warning() == "" and exposure.notes() == []


def test_a_check_that_could_not_read_is_a_warning_on_a_page_too():
    exposure = check("0.0.0.0", interfaces=_raises(OSError("no ip")))
    assert exposure.warning().startswith("could not read the addresses nervus listens on (no ip)")
    assert exposure.with_declared([Declared("1.2.3.0/24", by="operator", on="2026-10-20")]).state == "unknown"
