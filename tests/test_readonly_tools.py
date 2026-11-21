"""ADR-0031 step 4: what a read-only client may call (question 2a).

`exec`, `exec_bg`, `job`, `get` and `export` work where a client is read-only.
`put` and uploads to that machine are refused by nervus before anything is
sent, and where it is read-only on the Proxmox host, the `proxmox` tool and a
VM named by its id are refused too; each refusal with its record and its
reason. Another client on the same machine is unchanged. `hosts` gives the
client's level on each machine, and lists no VMs to one read-only on the
Proxmox host.
"""

import json

import pytest

from nervus.audit import AuditLog
from nervus.auth import Token
from nervus.config import Host, Settings
from nervus.server import build_server

from test_accounts import _no_caller, ca, offered  # noqa: F401  the fixtures
from test_server import _call_tool, _content

LIMITED, PLAIN = "sekret-limited", "sekret-plain"
VMID_TOOLS = [
    ("exec", {"command": "true"}),
    ("exec_bg", {"command": "true"}),
    ("job", {"job_id": "j1", "action": "status"}),
    ("put", {"local_path": "f.txt", "remote_path": "/tmp/x"}),
    ("get", {"remote_path": "/etc/hostname", "local_path": "g.txt"}),
]


class StandInVMs:
    def __init__(self):
        self.asked = []

    async def connect(self, vmid, token_id):
        self.asked.append(vmid)
        raise OSError("the test's stand-in reaches no VM")

    async def listing(self):
        return [{"vmid": 123, "name": "vm", "address": "192.0.2.9", "enrolled_at": "2026-11-20T00:00:00+00:00"}]


class StandInProxmox:
    class config:
        token_id = "nervus@pve!nervus"

    def __init__(self):
        self.asked = []

    async def request(self, method, path, params, timeout=60):
        self.asked.append((method, path))

        class Response:
            status, reason, body_bytes, data, errors, text = 200, "OK", 2, [], None, None
        return Response()


@pytest.fixture
def built(tmp_path, ca):
    web = Host(name="web", address="192.0.2.2", os="", role="r", agent_user="nervusagent", status="onboarded",
               level="full", readonly_user="nervusagent-readonly", host_keys=())
    hv = Host(name="hv", address="192.0.2.1", os="", role="r", agent_user="observer", status="onboarded",
              hypervisor="proxmox", readonly_user="nervusagent-readonly")
    transfer = tmp_path / "transfer"
    transfer.mkdir()
    (transfer / "f.txt").write_text("x")
    known = tmp_path / "known"
    known.write_text("")
    key = tmp_path / "k"
    key.write_bytes(__import__("asyncssh").generate_private_key("ssh-ed25519").export_private_key())
    settings = Settings(hosts={"web": web, "hv": hv}, tokens_path=tmp_path / "t", known_hosts_path=known,
                        ssh_key_path=tmp_path / "k", audit_log_path=tmp_path / "audit.jsonl", transfer_dir=transfer,
                        bind_host="127.0.0.1", bind_port=0, ssh_ca=ca)
    tokens = {LIMITED: Token(id="t-limited", client="c", project="p", hosts=frozenset({"web", "hv"}),
                             readonly=frozenset({"web", "hv"})),
              PLAIN: Token(id="t-plain", client="c", project="p", hosts=frozenset({"web", "hv"}))}
    audit = AuditLog(path=settings.audit_log_path)
    vms, api = StandInVMs(), StandInProxmox()
    server = build_server(settings=settings, tokens=tokens, audit=audit, vms=vms, proxmox=api)

    class Built:
        pass

    b = Built()
    b.server, b.settings, b.vms, b.api = server, settings, vms, api
    b.records = lambda: [json.loads(l) for l in settings.audit_log_path.read_text().splitlines()]
    return b


async def test_put_is_refused_where_the_client_is_read_only_and_nothing_is_sent(built, offered):
    result = await _call_tool(built.server, LIMITED, "put", {"host": "web", "local_path": "f.txt",
                                                            "remote_path": "/tmp/x"})
    assert result.is_error and "read-only on web" in result.content[0].text
    assert "username" not in offered
    put = [r for r in built.records() if r["tool"] == "put"]
    assert [r["phase"] for r in put] == ["refused"] and put[0]["level"] == "read-only"
    assert "nothing was sent" in put[0]["reason"]


async def test_another_client_read_write_on_the_same_machine_may_still_put(built, offered):
    await _call_tool(built.server, PLAIN, "put", {"host": "web", "local_path": "f.txt", "remote_path": "/tmp/x"})
    assert offered["username"] == "nervusagent"  # it went on to connect, as its read-write account


@pytest.mark.parametrize("tool,arguments", VMID_TOOLS)
async def test_a_vm_by_its_id_is_refused_where_the_client_is_read_only_on_the_proxmox_host(built, tool, arguments):
    result = await _call_tool(built.server, LIMITED, tool, {"vmid": 123, **arguments})
    assert result.is_error and "read-only on hv, the Proxmox host" in result.content[0].text
    assert built.vms.asked == []
    records = [r for r in built.records() if r["tool"] == tool]
    assert [r["phase"] for r in records] == ["refused"] and records[0]["vmid"] == 123


@pytest.mark.parametrize("tool,arguments", VMID_TOOLS)
async def test_a_read_write_client_still_reaches_the_vm(built, tool, arguments):
    await _call_tool(built.server, PLAIN, tool, {"vmid": 123, **arguments})
    assert built.vms.asked == [123]


async def test_the_proxmox_tool_is_refused_where_the_client_is_read_only_there(built):
    result = await _call_tool(built.server, LIMITED, "proxmox", {"method": "GET", "path": "/cluster/resources"})
    assert result.is_error and "Proxmox API" in result.content[0].text
    assert built.api.asked == []
    records = [r for r in built.records() if r["tool"] == "proxmox"]
    assert [r["phase"] for r in records] == ["refused"]
    plain = await _call_tool(built.server, PLAIN, "proxmox", {"method": "GET", "path": "/cluster/resources"})
    assert not plain.is_error and built.api.asked == [("GET", "/cluster/resources")]


async def test_hosts_gives_the_client_its_level_on_each_machine(built):
    limited = _content(await _call_tool(built.server, LIMITED, "hosts", {}))
    plain = _content(await _call_tool(built.server, PLAIN, "hosts", {}))
    assert {h["name"]: h["level"] for h in limited["hosts"]} == {"web": "read-only", "hv": "read-only"}
    assert {h["name"]: h["level"] for h in plain["hosts"]} == {"web": "full", "hv": "read-write"}


async def test_hosts_lists_no_vms_to_a_client_read_only_on_the_proxmox_host(built):
    limited = _content(await _call_tool(built.server, LIMITED, "hosts", {}))
    plain = _content(await _call_tool(built.server, PLAIN, "hosts", {}))
    assert "vms" not in limited
    assert [vm["vmid"] for vm in plain["vms"]] == [123]


async def test_exec_and_get_still_work_where_the_client_is_read_only(built, offered):
    for tool, arguments in (("exec", {"command": "true"}),
                            ("get", {"remote_path": "/etc/hostname", "local_path": "g.txt"})):
        offered.pop("username", None)
        await _call_tool(built.server, LIMITED, tool, {"host": "web", **arguments})
        assert offered["username"] == "nervusagent-readonly", tool
