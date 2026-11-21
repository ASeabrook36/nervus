"""A VM named by its id in nervus's tools (ADR-0022 step 3; decisions 2a, 4a,
5a, 6a): enrolled on the first call that names it, checked at every use,
repaired when its address moves or its key changes, forgotten when it is
gone; reached by every token whose allowlist holds the hypervisor's entry and
no other; listed by `hosts`.

The VM is played as in test_enroller: its script in a real `sh`, its guest
agent faked, its SSH a real server on loopback standing in for the address
the guest agent reports."""

import asyncio
import json

import asyncssh
import pytest

from nervus import accounts, certs, jobs, sftp, ssh
from nervus.audit import AuditLog
from nervus.auth import Token
from nervus.config import Host, Settings
from nervus.database import Database
from nervus.enroller import ENROLL_SCRIPT, EnrollmentFailed
from nervus.enrollments import EnrollmentStore
from nervus.guest import GuestError
from nervus.proxmox import ProxmoxResponse
from nervus.server import build_server
from nervus.vm_targets import VMTargets
from test_enroller import OTHER_ADDRESS, T0, VM, VM_ADDRESS, FakeGuestAgent, _connector, _enroller, _in_a_call, servers  # noqa: F401
from test_server import _call_tool, _content

HV, HV_TOKEN, HOST_TOKEN = "hv", "sekret-hv", "sekret-host"


class World:
    """One VM, its guest agent, the servers standing in for its addresses,
    and nervus's VM targets over them."""

    def __init__(self, tmp_path, servers, server):
        self.tmp_path = tmp_path
        self.servers = servers
        self.vm = VM(tmp_path / "vm", [server.host_key_line])
        self.agent = FakeGuestAgent(self.vm)
        self.standing_in = {VM_ADDRESS: server}
        self.tried = []
        db = Database(tmp_path / "nervus.db")
        db.open()
        self.store = EnrollmentStore(db)
        self.targets = VMTargets(self.store, _enroller(self.store, servers.key_path, self.standing_in, self.vm,
                                                       self.tried), self.agent, poll=0)

    async def visit(self, token_id="t"):
        """One call's connection, closed: the note it brought."""
        conn, note = await self.targets.connect(123, token_id)
        conn.close()
        return note

    def scripts_run(self):
        return sum(1 for _, path, p in self.agent.calls if path.endswith("/exec") and ENROLL_SCRIPT in p["command"])

    def report(self, *addresses):
        """The VM's interfaces now carry these addresses."""
        self.agent.interfaces = [{"name": "eth0", "ip-addresses": [
            {"ip-address-type": "ipv4", "ip-address": a} for a in addresses]}]

    def rebuild(self, server):
        """The VM rebuilt under the same id: a new host key."""
        for f in self.vm.ssh.iterdir():
            f.unlink()
        (self.vm.ssh / "ssh_host_0_key.pub").write_text(server.host_key_line + "\n")


# The VM's own sshd trusts what its agent's authorized_keys holds, at each attempt.
AUTHORIZED = ("vm", "home", "agent", ".ssh", "authorized_keys")


@pytest.fixture
async def world(tmp_path, servers):
    return World(tmp_path, servers, await servers(keys_file=tmp_path.joinpath(*AUTHORIZED), root=tmp_path / "vm"))


async def _whoami(conn):
    result = await conn.run("echo reached", check=False)
    conn.close()
    return result.stdout.strip()


# --- enrolled on first use, checked at every use ------------------------------------


async def test_the_first_call_naming_a_vm_enrolls_it_and_says_so(world):
    conn, note = await world.targets.connect(123, "client-a")
    assert await _whoami(conn) == "reached"
    assert note == f"VM 123 enrolled, at {VM_ADDRESS}"
    assert world.store.get(123).enrolled_by == "client-a"
    assert world.scripts_run() == 1


async def test_later_calls_use_the_row_and_touch_no_guest_agent(world):
    await world.visit()
    before = len(world.agent.calls)
    conn, note = await world.targets.connect(123, "t")
    assert await _whoami(conn) == "reached" and note is None
    assert len(world.agent.calls) == before


async def test_two_first_calls_at_once_enroll_it_once(world):
    await asyncio.gather(world.visit(), world.visit())
    assert world.scripts_run() == 1


async def test_a_vm_that_cannot_be_enrolled_is_tried_again_on_the_next_call(world):
    (world.vm.bin / "sudo").unlink()
    with pytest.raises(EnrollmentFailed):
        await world.visit()
    world.vm.shim("sudo", "exit 0")  # fixed meanwhile
    note = await world.visit()
    assert note.startswith("VM 123 enrolled") and world.scripts_run() == 2


async def test_what_a_connection_changed_is_noted_on_the_call_it_was_made_for(world):
    """The note also goes with the call (certs.note), so a call whose own answer has no place for it, or
    that fails after the VM was enrolled, still has it for its audit result (ADR-0001 section 10)."""
    first = certs.acting_for("t", "0b9f4c2e-5d1a-4e8b-9c3f-7a6d2e1b0c94")
    certs.take(accounts.vm_route(123))
    note = await world.visit()
    assert note == f"VM 123 enrolled, at {VM_ADDRESS}" and first.notes == [note]
    later = certs.acting_for("t", "7d1c9a53-2f4e-4b6a-8e0d-3c5b7a9f1e24")
    certs.take(accounts.vm_route(123))
    assert await world.visit() is None and later.notes == [] and first.notes == [note]


async def test_an_enrollment_is_noted_even_if_the_connection_after_it_fails(world):
    """The VM is changed and its row kept before nervus connects for the call itself."""
    caller = certs.acting_for("t", "0b9f4c2e-5d1a-4e8b-9c3f-7a6d2e1b0c94")
    certs.take(accounts.vm_route(123))
    connect, calls = world.targets.enroller.connect, []

    async def dropped_after_the_check(address, keys, machine=None):
        calls.append(address)
        if len(calls) == 1:
            return await connect(address, keys, machine=machine)  # the enrollment's own check
        raise asyncssh.ConnectionLost("the VM went away")

    world.targets.enroller.connect = dropped_after_the_check
    with pytest.raises(asyncssh.ConnectionLost):
        await world.targets.connect(123, "t")
    assert calls == [VM_ADDRESS, VM_ADDRESS] and world.store.get(123) is not None
    assert caller.notes == [f"VM 123 enrolled, at {VM_ADDRESS}"]


# --- repaired ------------------------------------------------------------------------


async def test_a_moved_address_is_found_with_the_same_keys_without_enrolling_again(world):
    await world.visit()
    keys = world.store.get(123).host_keys
    world.standing_in[OTHER_ADDRESS] = world.standing_in.pop(VM_ADDRESS)
    world.report(OTHER_ADDRESS)
    conn, note = await world.targets.connect(123, "t")
    assert await _whoami(conn) == "reached"
    assert note == f"VM 123 moved from {VM_ADDRESS} to {OTHER_ADDRESS}"
    row = world.store.get(123)
    assert (row.address, row.host_keys) == (OTHER_ADDRESS, keys)
    assert world.scripts_run() == 1


async def test_a_changed_host_key_is_taken_only_from_the_guest_agent(world, servers):
    await world.visit()
    old = world.store.get(123)
    rebuilt = await servers(keys_file=world.vm.authorized_keys, root=world.vm.root)
    world.standing_in[VM_ADDRESS] = rebuilt
    world.rebuild(rebuilt)
    conn, note = await world.targets.connect(123, "t")
    assert await _whoami(conn) == "reached"
    assert note == "VM 123's host key changed, as its guest agent reports; enrolled again"
    assert world.store.get(123).host_keys != old.host_keys
    assert world.scripts_run() == 2


async def test_another_machine_at_the_address_is_never_trusted(world, servers):
    """The id's address now answers with another key, and the guest agent
    still reports the old one: the VM moved, and something else took its
    address. nervus pins nothing from the network and finds the VM."""
    await world.visit()
    impostor = await servers()
    world.standing_in[OTHER_ADDRESS] = world.standing_in[VM_ADDRESS]
    world.standing_in[VM_ADDRESS] = impostor
    world.report(VM_ADDRESS, OTHER_ADDRESS)
    conn, note = await world.targets.connect(123, "t")
    assert await _whoami(conn) == "reached"
    assert world.store.get(123).address == OTHER_ADDRESS
    assert impostor.auths == []
    assert "moved" in note


async def test_a_vm_that_moved_and_was_rebuilt_is_enrolled_again(world, servers):
    await world.visit()
    rebuilt = await servers(keys_file=world.vm.authorized_keys, root=world.vm.root)
    world.standing_in = {OTHER_ADDRESS: rebuilt}
    world.targets.enroller.connect = _connector(world.servers.key_path, world.standing_in, world.tried)
    world.report(OTHER_ADDRESS)
    world.rebuild(rebuilt)
    note = await world.visit()
    assert note == "VM 123's host key changed, as its guest agent reports; enrolled again"
    assert world.store.get(123).address == OTHER_ADDRESS


async def test_access_taken_away_inside_the_vm_is_repaired(world):
    """Someone in the VM emptied agent's authorized_keys: its sshd refuses
    nervus's key. The guest agent puts it back."""
    await world.visit()
    world.vm.authorized_keys.write_text("")
    assert await world.visit() == "VM 123 enrolled again: nervus's access to it was repaired"
    assert world.scripts_run() == 2
    assert await world.visit() is None


async def test_a_gone_vm_is_forgotten_and_the_call_says_so(world):
    await world.visit()
    world.standing_in.clear()  # nothing answers at its address
    world.agent.guests = [g for g in world.agent.guests if g["vmid"] != 123]
    with pytest.raises(EnrollmentFailed) as failed:
        await world.visit()
    assert failed.value.code == "vm_gone" and "VM 123 is gone" in failed.value.message
    assert world.store.get(123) is None


# --- listed ----------------------------------------------------------------------------


async def test_the_listing_names_enrolled_vms_proxmox_still_has_and_forgets_the_rest(world):
    await world.visit()
    # A second enrolled VM, with its own host key: reusing VM 123's keys is now refused
    # as aliasing (procedure 056, finding 2), and keep_only here does not depend on them.
    other_key = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode().strip()
    world.store.enroll(200, "192.0.2.200", [other_key], "t", now=T0)
    listed = await world.targets.listing()
    assert [(vm["vmid"], vm["name"], vm["address"]) for vm in listed] == [(123, "agent-vm", VM_ADDRESS)]
    assert world.store.get(200) is None


async def test_a_listing_proxmox_cannot_give_forgets_nothing(world):
    await world.visit()
    real = world.agent.request

    async def failing(method, path, params=None, **kw):
        if path == "/cluster/resources":
            return ProxmoxResponse(status=500, reason="busy", data=None, errors=None, body_bytes=0)
        return await real(method, path, params, **kw)

    world.agent.request = failing
    with pytest.raises(GuestError):
        await world.targets.listing()
    assert world.store.get(123) is not None


# --- through the tools ---------------------------------------------------------------


def _server(tmp_path, world, *, with_vms=True, hypervisor=True):
    hv = Host(name=HV, address="192.0.2.1", os="test", role="test", agent_user="observer",
              status="onboarded", hypervisor="proxmox" if hypervisor else None)
    other = Host(name="web", address="192.0.2.2", os="test", role="test", agent_user="agent", status="onboarded")
    transfer = tmp_path / "transfer"
    transfer.mkdir(exist_ok=True)
    settings = Settings(hosts={HV: hv, "web": other}, tokens_path=tmp_path / "t", known_hosts_path=tmp_path / "k",
                        ssh_key_path=world.servers.key_path, audit_log_path=tmp_path / "audit.jsonl",
                        transfer_dir=transfer, bind_host="127.0.0.1", bind_port=0)
    tokens = {HV_TOKEN: Token(id="t-hv", client="codex", project="p", hosts=frozenset({HV})),
              HOST_TOKEN: Token(id="t-host", client="codex", project="p", hosts=frozenset({"web"}))}
    audit = AuditLog(path=settings.audit_log_path)
    return build_server(settings=settings, tokens=tokens, audit=audit,
                        vms=world.targets if with_vms else None), audit


def _records(audit):
    return [json.loads(line) for line in audit.path.read_text().splitlines() if line.strip()]


async def test_exec_by_vmid_enrolls_runs_and_records_it_under_the_call(tmp_path, world):
    mcp_server, audit = _server(tmp_path, world)
    result = await _call_tool(mcp_server, HV_TOKEN, "exec", {"vmid": 123, "command": "echo hello", "cwd": "/"})
    assert not result.is_error, result.content[0].text
    answer = _content(result)
    assert answer["exit_code"] == 0 and answer["output"].strip() == "hello"
    assert answer["vm_note"] == f"VM 123 enrolled, at {VM_ADDRESS}"
    intent, done = [r for r in _records(audit) if r.get("tool") == "exec"]
    assert intent["vmid"] == 123 and intent["user"] == "agent" and "host" not in intent
    assert done["id"] == intent["id"] == answer["run_id"] and done["vm_note"] == answer["vm_note"]
    assert intent["token_id"] == "t-hv"


async def test_every_ssh_tool_takes_a_vmid(tmp_path, world):
    mcp_server, _ = _server(tmp_path, world)
    (tmp_path / "transfer" / "out.txt").write_text("from nervus")
    dest = tmp_path / "in-the-vm.txt"
    put = await _call_tool(mcp_server, HV_TOKEN, "put", {"vmid": 123, "local_path": "out.txt",
                                                         "remote_path": str(dest)})
    assert not put.is_error, put.content[0].text
    assert dest.read_text() == "from nervus"
    got = await _call_tool(mcp_server, HV_TOKEN, "get", {"vmid": 123, "remote_path": str(dest),
                                                         "local_path": "back.txt"})
    assert not got.is_error and (tmp_path / "transfer" / "back.txt").read_text() == "from nervus"
    if __import__("shutil").which("tmux"):
        started = _content(await _call_tool(mcp_server, HV_TOKEN, "exec_bg", {"vmid": 123, "command": "true"}))
        assert started["vmid"] == 123
        status = await _call_tool(mcp_server, HV_TOKEN, "job", {"vmid": 123, "job_id": started["job_id"],
                                                                "action": "status"})
        assert not status.is_error, status.content[0].text


async def test_a_put_that_enrolls_the_vm_and_then_fails_records_the_enrollment(tmp_path, world):
    """Procedure 056, as it was seen: a put to a folder the VM does not have leaves the VM enrolled,
    and the call's audit result must say so beside its error. The VM was changed under this call
    whatever became of the call (ADR-0001 section 10)."""
    mcp_server, audit = _server(tmp_path, world)
    (tmp_path / "transfer" / "out.txt").write_text("from nervus")
    result = await _call_tool(mcp_server, HV_TOKEN, "put", {"vmid": 123, "local_path": "out.txt",
                                                            "remote_path": str(tmp_path / "no-such-folder" / "x")})
    assert result.is_error
    assert world.store.get(123) is not None
    intent, done = [r for r in _records(audit) if r.get("tool") == "put"]
    assert done["id"] == intent["id"] and "error" in done
    assert done["vm_note"] == f"VM 123 enrolled, at {VM_ADDRESS}"


# Each SSH tool by vmid, failing after its connection: what it calls once connected, and its arguments.
_ONCE_CONNECTED = {
    "exec": (ssh, "exec_command", {"command": "true"}),
    "exec_bg": (jobs, "start_job", {"command": "true"}),
    "job": (jobs, "job_status", {"job_id": "a-job", "action": "status"}),
    "put": (sftp, "put_file", {"local_path": "out.txt", "remote_path": "/x"}),
    "get": (sftp, "get_file", {"remote_path": "/x", "local_path": "back.txt"}),
}


@pytest.mark.parametrize("tool", sorted(_ONCE_CONNECTED))
async def test_every_ssh_tool_records_an_enrollment_even_when_the_call_then_fails(tmp_path, world, monkeypatch,
                                                                                  tool):
    """The failed call's result reads the note from the call (certs.vm_note), as it reads its SSH
    ports, so no tool's failure can drop it."""
    module, name, args = _ONCE_CONNECTED[tool]

    async def refused(*_args, **_kwargs):
        raise OSError("the machine refused")

    monkeypatch.setattr(module, name, refused)
    mcp_server, audit = _server(tmp_path, world)
    (tmp_path / "transfer" / "out.txt").write_text("from nervus")
    result = await _call_tool(mcp_server, HV_TOKEN, tool, {"vmid": 123, **args})
    assert result.is_error
    intent, done = [r for r in _records(audit) if r.get("tool") == tool]
    assert done["id"] == intent["id"] and done["error"]
    assert done["vm_note"] == f"VM 123 enrolled, at {VM_ADDRESS}"


async def test_a_token_without_the_hypervisor_entry_is_refused_a_vmid_before_anything_is_asked(tmp_path, world):
    mcp_server, audit = _server(tmp_path, world)
    for tool, args in [("exec", {"command": "x"}), ("exec_bg", {"command": "x"}),
                       ("job", {"job_id": "j", "action": "status"}),
                       ("put", {"local_path": "a", "remote_path": "/b"}),
                       ("get", {"remote_path": "/b", "local_path": "a"})]:
        result = await _call_tool(mcp_server, HOST_TOKEN, tool, {"vmid": 123, **args})
        assert result.is_error, tool
    refusals = [r for r in _records(audit) if r["phase"] == "refused"]
    assert [r["tool"] for r in refusals] == ["exec", "exec_bg", "job", "put", "get"]
    assert all(r["vmid"] == 123 for r in refusals)
    assert world.agent.calls == []


@pytest.mark.parametrize("args, reason", [
    ({"vmid": 123, "host": HV}, "not both"),
    ({}, "give a host, or a VM's id"),
    ({"vmid": 99}, "not a Proxmox VM id"),
])
async def test_a_call_naming_its_target_wrongly_is_refused_and_says_why(tmp_path, world, args, reason):
    mcp_server, audit = _server(tmp_path, world)
    result = await _call_tool(mcp_server, HV_TOKEN, "exec", {"command": "x", **args})
    assert result.is_error and reason in result.content[0].text
    assert [r["phase"] for r in _records(audit)] == ["refused"]
    assert world.agent.calls == []


async def test_without_proxmox_settings_a_vmid_is_refused_with_the_reason(tmp_path, world):
    mcp_server, _ = _server(tmp_path, world, with_vms=False)
    result = await _call_tool(mcp_server, HV_TOKEN, "exec", {"vmid": 123, "command": "x"})
    assert result.is_error and "--proxmox" in result.content[0].text


async def test_without_a_hypervisor_entry_a_vmid_is_refused(tmp_path, world):
    mcp_server, _ = _server(tmp_path, world, hypervisor=False)
    result = await _call_tool(mcp_server, HV_TOKEN, "exec", {"vmid": 123, "command": "x"})
    assert result.is_error and "hypervisor: proxmox" in result.content[0].text
    assert world.agent.calls == []


async def test_a_vm_that_cannot_be_enrolled_says_why(tmp_path, world):
    (world.vm.bin / "sudo").unlink()
    mcp_server, _ = _server(tmp_path, world)
    result = await _call_tool(mcp_server, HV_TOKEN, "exec", {"vmid": 123, "command": "x"})
    assert result.is_error and "the VM has no sudo" in result.content[0].text


async def test_hosts_lists_enrolled_vms_to_a_token_that_reaches_the_hypervisor_only(tmp_path, world):
    await world.visit()
    mcp_server, audit = _server(tmp_path, world)
    answer = _content(await _call_tool(mcp_server, HV_TOKEN, "hosts", {}))
    assert [vm["vmid"] for vm in answer["vms"]] == [123] and answer["vms"][0]["name"] == "agent-vm"
    assert _records(audit)[-1]["vms"] == [123]
    other = _content(await _call_tool(mcp_server, HOST_TOKEN, "hosts", {}))
    assert "vms" not in other and [h["name"] for h in other["hosts"]] == ["web"]


async def test_hosts_still_lists_hosts_when_proxmox_cannot_list_vms(tmp_path, world):
    await world.visit()
    real = world.agent.request

    async def failing(method, path, params=None, **kw):
        if path == "/cluster/resources":
            return ProxmoxResponse(status=500, reason="busy", data=None, errors=None, body_bytes=0)
        return await real(method, path, params, **kw)

    world.agent.request = failing
    mcp_server, _ = _server(tmp_path, world)
    answer = _content(await _call_tool(mcp_server, HV_TOKEN, "hosts", {}))
    assert [h["name"] for h in answer["hosts"]] == [HV] and "cannot list VMs" in answer["vms_error"]
    assert world.store.get(123) is not None


async def test_every_tool_the_vm_recipe_names_takes_a_vmid(tmp_path, world):
    """docs/clients.md, "Make a VM", step 5, as written."""
    import re
    from pathlib import Path
    text = (Path(__file__).resolve().parent.parent / "docs" / "clients.md").read_text()
    step = text[text.index("**5. Use it by its id.**"):text.index("**The guest agent**")]
    named = re.findall(r"`(exec|exec_bg|job|put|get|export)`", step.split("Commands run as")[0])
    assert set(named) >= {"exec", "exec_bg", "job", "put", "get", "export"}
    from nervus.exporter import Exporter
    from nervus.exports import ExportStore
    db = Database(tmp_path / "e.db")
    db.open()
    store = ExportStore(db, tmp_path / "exports", free_bytes=lambda: 100 * 1024**3)
    store.open()
    hv = Host(name=HV, address="192.0.2.1", os="test", role="test", agent_user="observer", status="onboarded",
              hypervisor="proxmox")
    settings = Settings(hosts={HV: hv}, tokens_path=tmp_path / "t", known_hosts_path=tmp_path / "k",
                        ssh_key_path=world.servers.key_path, audit_log_path=tmp_path / "a.jsonl",
                        transfer_dir=tmp_path, bind_host="127.0.0.1", bind_port=0)
    full = build_server(settings=settings, tokens={}, audit=AuditLog(path=tmp_path / "a.jsonl"),
                        exporter=Exporter(store, AuditLog(path=tmp_path / "a.jsonl"), connect=None,
                                          vm_api=world.agent), vms=world.targets)
    schemas = {t.name: t.input_schema for t in await full.list_tools()}
    for tool in set(named):
        assert "vmid" in schemas[tool]["properties"], tool
