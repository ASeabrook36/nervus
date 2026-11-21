"""Machines enrolled from the web UI, used by nervus's tools (ADR-0024 step 2):
read at every call beside hosts.yaml, so enrolling needs no restart; reached
as `agent` with the host keys their own row pins, not the known_hosts file;
listed by `hosts` with their level; reached only by a token whose allowlist
names them. A real SSH server on loopback plays the machine."""

import dataclasses
import json

import asyncssh
import pytest

from nervus.audit import AuditLog
from nervus.auth import Token
from nervus.config import Host
from nervus.database import Database
from nervus.enrolled_hosts import EnrolledHostStore, merged
from nervus.server import build_server
from nervus.upload_route import authorize
from nervus.upload_targets import HostDelivery
from nervus.uploads import UploadRefused
from test_server import GOOD_TOKEN, _call_tool, _content, _settings

MACHINE = "0123456789abcdef0123456789abcdef"
WEB_TOKEN = "sekret-web"


@pytest.fixture
def world(tmp_path, ssh_server):
    """nervus with hosts.yaml's `testhost`, an empty known_hosts file, and an
    enrolled-host store with nothing in it yet."""
    empty = tmp_path / "known_hosts.empty"
    empty.write_text("")
    settings = dataclasses.replace(_settings(tmp_path, ssh_server), known_hosts_path=empty)
    db = Database(tmp_path / "nervus.db")
    db.open()
    store = EnrolledHostStore(db)
    tokens = {
        GOOD_TOKEN: Token(id="t-good", client="claude-code", project="p", hosts=frozenset({"testhost"})),
        WEB_TOKEN: Token(id="t-web", client="claude-code", project="p", hosts=frozenset({"web"})),
    }
    audit = AuditLog(path=settings.audit_log_path)
    server = build_server(settings=settings, tokens=tokens, audit=audit, enrolled=store)
    host_key = open(ssh_server.known_hosts_path).read().split(" ", 1)[1].strip()  # as the machine reported it
    return server, store, settings, host_key


def _enroll(store, host_key, name="web", level="standard"):
    # Standard: a read-only call needs nervus's certificate authority (ADR-0031), which this
    # nervus has not got, and these tests are of how the machine is reached, not of its level.
    store.add(name, address="127.0.0.1", level=level, host_keys=[host_key], machine_id=MACHINE,
              enrolled_by="operator")


async def test_a_machine_enrolled_after_start_is_reached_at_the_next_call(world):
    server, store, _, host_key = world
    refused = await _call_tool(server, WEB_TOKEN, "exec", {"host": "web", "command": "echo hi"})
    assert refused.is_error and "web" in refused.content[0].text
    _enroll(store, host_key)  # after nervus started: no restart
    done = await _call_tool(server, WEB_TOKEN, "exec", {"host": "web", "command": "echo hi"})
    assert not done.is_error, done.content[0].text
    assert _content(done)["output"].strip() == "hi"


async def test_it_is_reached_with_its_own_pinned_keys_not_the_known_hosts_file(world):
    """The known_hosts file is empty here, so only the row's keys can let
    nervus in; a row naming another key is refused before any command runs."""
    server, store, _, _ = world
    other = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode().strip()
    _enroll(store, other)
    done = await _call_tool(server, WEB_TOKEN, "exec", {"host": "web", "command": "echo hi"})
    assert done.is_error and "Host key" in done.content[0].text


async def test_a_token_whose_allowlist_does_not_name_it_is_refused(world):
    server, store, _, host_key = world
    _enroll(store, host_key)
    done = await _call_tool(server, GOOD_TOKEN, "exec", {"host": "web", "command": "echo hi"})
    assert done.is_error and "not allowed" in done.content[0].text


async def test_hosts_lists_it_with_its_level_beside_hosts_yaml(world):
    server, store, _, host_key = world
    _enroll(store, host_key, level="standard")
    hosts = _content(await _call_tool(server, WEB_TOKEN, "hosts", {}))["hosts"]
    assert hosts == [{"name": "web", "address": "127.0.0.1", "role": "enrolled, standard", "status": "onboarded",
                      "level": "standard"}]
    mine = _content(await _call_tool(server, GOOD_TOKEN, "hosts", {}))["hosts"]
    # ADR-0031: every machine with the client's level there; one described by hand, whose level
    # nervus does not know, read-write.
    assert [h["name"] for h in mine] == ["testhost"] and mine[0]["level"] == "read-write"


async def test_once_forgotten_it_is_refused_at_the_next_call(world):
    server, store, _, host_key = world
    _enroll(store, host_key)
    assert not (await _call_tool(server, WEB_TOKEN, "exec", {"host": "web", "command": "true"})).is_error
    store.remove("web")
    assert (await _call_tool(server, WEB_TOKEN, "exec", {"host": "web", "command": "true"})).is_error


def test_hosts_yaml_keeps_a_name_enrolled_before_the_file_gained_it(world):
    _, store, settings, host_key = world
    _enroll(store, host_key, name="testhost-2")
    file_hosts = {**settings.hosts, "testhost-2": dataclasses.replace(settings.hosts["testhost"], name="testhost-2")}
    both = merged(file_hosts, store)
    assert both["testhost-2"].host_keys == () and both["testhost-2"].level is None  # the file's own entry


def test_uploads_may_go_to_it(world):
    _, store, settings, host_key = world
    _enroll(store, host_key)
    token = Token(id="t-web", client="c", project="p", hosts=frozenset({"web"}))
    destination = {"kind": "host", "host": "web"}
    with pytest.raises(UploadRefused):
        authorize(token, destination, settings)  # hosts.yaml alone does not know it
    authorize(token, destination, settings, merged(settings.hosts, store))


def test_a_delivery_finds_a_machine_enrolled_after_it_was_made(world, tmp_path):
    _, store, settings, host_key = world
    delivery = HostDelivery(None, lambda: merged(settings.hosts, store), connect=None)
    upload = type("U", (), {"destination": {"host": "web"}})()
    with pytest.raises(UploadRefused):
        delivery._host(upload)
    _enroll(store, host_key)
    assert delivery._host(upload).host_keys
