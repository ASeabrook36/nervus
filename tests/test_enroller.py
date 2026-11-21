"""Enrolling a VM through its guest agent (ADR-0022 step 2, decision 3a): the
script, the host-key pin, the SSH check, then the row.

The script runs here in a real `sh`, through a fake guest agent, with only the
commands that need root stood in for (`id`, `useradd`, `getent`, `chown`,
`visudo`, `systemctl`, `sudo`), on real files in a temporary directory. The SSH
check runs against real SSH servers on loopback: the VM, and an impostor with
another host key. Loopback is never an address nervus keeps, so the test's
connector takes the address the guest agent reported and connects to the
server standing in for it, pinned exactly as nervus pins."""

import asyncio
import base64
import itertools
import os
import re
import secrets
import shutil
import stat
import subprocess
from pathlib import Path

import asyncssh
import pytest
from sshd_shell import _handle_process

from nervus import accounts, certs
from nervus.certs import CertificateAuthority
from nervus.database import Database
from nervus.enroller import (
    CHECK_COMMAND,
    ENROLL_SCRIPT,
    MARKER,
    known_hosts_lines,
    Enroller,
    EnrollmentFailed,
    ssh_connector,
)
from nervus.enrollments import EnrollmentStore
from nervus.guest import Guest
from nervus.proxmox import ProxmoxResponse

T0 = 1_800_000_000.0
LOOPBACK, LINK_LOCAL = "127.0.0.1", "fe80::5054:ff:fe12:3456"
VM_ADDRESS, OTHER_ADDRESS = "192.0.2.10", "192.0.2.11"


# --- a VM, played by this machine --------------------------------------------------

SHIMS = {
    # Only `id -u agent` is asked.
    "id": '[ -e "$FAKE/agent-exists" ]',
    "useradd": 'echo "useradd $*" >> "$FAKE/log"; mkdir -p "$FAKE/home/agent"; : > "$FAKE/agent-exists"',
    "getent": '[ -e "$FAKE/agent-exists" ] && echo "agent:x:1001:1001::$FAKE/home/agent:/bin/sh"',
    "chown": 'echo "chown $*" >> "$FAKE/log"',
    # visudo -cqf <file>: refuses on request, and anything but the one line.
    "visudo": '[ ! -e "$FAKE/visudo-refuses" ] && [ "$(cat "$2")" = "agent ALL=(ALL) NOPASSWD: ALL" ]',
    "systemctl": 'echo "systemctl $*" >> "$FAKE/log"',
    "sudo": "exit 0",
}


class VM:
    """The guest's files and commands: its home directories, /etc/sudoers.d
    and /etc/ssh under one temporary directory."""

    def __init__(self, root: Path, host_keys: list[str]):
        self.root = root
        root.mkdir(parents=True, exist_ok=True)
        self.bin = root / "bin"
        self.bin.mkdir()
        for name, body in SHIMS.items():
            self.shim(name, body)
        os.symlink(shutil.which("cut"), self.bin / "cut")
        self.sudoers = root / "etc" / "sudoers.d"
        self.sudoers.mkdir(parents=True)
        self.ssh = root / "etc" / "ssh"
        self.ssh.mkdir()
        for n, line in enumerate(host_keys):
            (self.ssh / f"ssh_host_{n}_key.pub").write_text(line + "\n")
        (root / "home").mkdir()
        self.run = root / "run"
        self.run.mkdir()

    def shim(self, name, body):
        path = self.bin / name
        path.write_text(f"#!/bin/sh\n{body}\n")
        path.chmod(0o755)

    def env(self):
        return {"PATH": f"{self.bin}:/bin", "FAKE": str(self.root)}

    @property
    def log(self):
        path = self.root / "log"
        return path.read_text().splitlines() if path.exists() else []

    @property
    def authorized_keys(self):
        return self.root / "home" / "agent" / ".ssh" / "authorized_keys"


class FakeGuestAgent:
    """Proxmox's guest-agent calls as Proxmox answers them, for VM 123 on node
    hv; `exec` runs the command here, in the VM's environment."""

    def __init__(self, vm: VM, interfaces=None):
        self.vm = vm
        self.interfaces = interfaces if interfaces is not None else [
            {"name": "lo", "ip-addresses": [{"ip-address-type": "ipv4", "ip-address": LOOPBACK, "prefix": 8},
                                            {"ip-address-type": "ipv6", "ip-address": "::1", "prefix": 128}]},
            {"name": "eth0", "ip-addresses": [{"ip-address-type": "ipv6", "ip-address": LINK_LOCAL, "prefix": 64},
                                              {"ip-address-type": "ipv4", "ip-address": VM_ADDRESS, "prefix": 24}]},
        ]
        self.guests = [{"vmid": 123, "type": "qemu", "node": "hv", "name": "agent-vm"},
                       {"vmid": 124, "type": "lxc", "node": "hv", "name": "a-container"}]
        self.calls = []
        self._runs = {}
        self._pids = itertools.count(1000)

    async def request(self, method, path, params=None, *, timeout=60.0):
        params = params or {}
        self.calls.append((method, path, params))
        if path == "/cluster/resources":
            return self._ok(self.guests)
        if path == "/nodes/hv/qemu/123/agent/exec":
            # The enrollment script sees only the VM's commands; anything else
            # (an export's hashing, an upload's scripts) this machine's.
            env = self.vm.env() if ENROLL_SCRIPT in params["command"] else None
            done = await asyncio.to_thread(subprocess.run, params["command"], input=params.get("input-data", ""),
                                           capture_output=True, text=True, env=env)
            pid = next(self._pids)
            self._runs[pid] = done
            return self._ok({"pid": pid})
        if path == "/nodes/hv/qemu/123/agent/exec-status":
            done = self._runs[params["pid"]]
            return self._ok({"exited": 1, "exitcode": done.returncode, "out-data": done.stdout,
                             "err-data": done.stderr})
        if path == "/nodes/hv/qemu/123/agent/network-get-interfaces":
            return self._ok({"result": self.interfaces})
        if path == "/nodes/hv/qemu/123/agent/file-read":  # unpadded; test_export_sources has Proxmox's quirk
            data = Path(params["file"]).read_bytes()
            piece = data[params["offset"]:params["offset"] + params["count"]]
            return self._ok({"content": base64.b64encode(piece).decode(), "bytes-read": len(piece),
                             "truncated": params["offset"] + len(piece) < len(data)})
        return ProxmoxResponse(status=501, reason="not in the fake", data=None, errors=None, body_bytes=0)

    @staticmethod
    def _ok(data):
        return ProxmoxResponse(status=200, reason="OK", data=data, errors=None, body_bytes=0)


# --- SSH servers standing in for addresses ------------------------------------------


class _Counting(asyncssh.SSHServer):
    """Counts every authentication a client begins. Given `keys_file`, it
    accepts exactly the keys in it, read at each attempt, as sshd reads a
    user's authorized_keys."""

    def __init__(self, auths, keys_file=None):
        self.auths = auths
        self.keys_file = keys_file

    def begin_auth(self, username):
        self.auths.append(username)
        return True

    def public_key_auth_supported(self):
        return True

    def validate_public_key(self, username, key):
        return self._listed(key, ca=False)

    def validate_ca_key(self, username, key):
        """A `cert-authority` line, as enrollment writes since ADR-0025."""
        return self._listed(key, ca=True)

    def _listed(self, key, ca):
        if self.keys_file is None:
            return False
        try:
            listed = asyncssh.import_authorized_keys(self.keys_file.read_text())
        except (OSError, ValueError):
            return False
        return listed.validate(key, "127.0.0.1", "127.0.0.1", ca=ca) is not None


class Server:
    def __init__(self, port, host_key, auths, answer):
        self.port, self.host_key, self.auths, self.answer = port, host_key, auths, answer

    @property
    def host_key_line(self):
        return self.host_key.export_public_key().decode().strip()


@pytest.fixture
async def servers(tmp_path):
    """Make SSH servers that accept only nervus's key and answer the check
    with `answer`, counting every authentication a client begins."""
    nervus_key = asyncssh.generate_private_key("ssh-ed25519")
    key_path = tmp_path / "nervus_ed25519"
    key_path.write_bytes(nervus_key.export_private_key())
    key_path.chmod(0o600)
    # nervus's CA beside its key, as the installer makes it (ADR-0025).
    ca_path = _ca_path(key_path)
    ca_path.write_bytes(asyncssh.generate_private_key("ssh-ed25519").export_private_key())
    ca_path.chmod(0o600)
    authorized = tmp_path / "nervus.pub"
    authorized.write_bytes(nervus_key.export_public_key())
    running = []

    async def make(answer="agent\nroot\n", exit_status=0, keys_file=None, root=None):
        """`root` is the machine this server is: it holds only the files under it,
        so it can remove a VM's challenge only if it stands in for that VM."""
        host_key = asyncssh.generate_private_key("ssh-ed25519")
        auths = []

        async def handle(process):
            command = process.command or ""
            challenge = re.fullmatch(re.escape(CHECK_COMMAND) + r"; sudo -n rm -- (\S+) && echo (\S+)", command)
            if command == CHECK_COMMAND:
                process.stdout.write(answer)
                process.exit(exit_status)
            elif challenge:
                path, word = Path(challenge[1]), challenge[2]
                held = root is not None and path.is_relative_to(root) and path.is_file()
                if held:
                    path.unlink()
                process.stdout.write(answer + (word + "\n" if held else ""))
                process.exit(exit_status if held else 1)
            else:  # anything else runs here, as the test SSH server does
                await _handle_process(process)

        trust = {} if keys_file else {"authorized_client_keys": str(authorized)}
        server = await asyncssh.listen("127.0.0.1", 0, server_factory=lambda: _Counting(auths, keys_file),
                                       server_host_keys=[host_key], process_factory=handle, sftp_factory=True,
                                       **trust)
        running.append(server)
        return Server(server.sockets[0].getsockname()[1], host_key, auths, answer)

    make.key_path = key_path
    yield make
    for server in running:
        server.close()
        await server.wait_closed()


def _ca_path(key_path):
    return key_path.with_name("nervus_ca_ed25519")


def _ca(key_path):
    """nervus's CA beside `key_path`, where `servers` puts it; None without one."""
    return CertificateAuthority(_ca_path(key_path)) if _ca_path(key_path).exists() else None


@pytest.fixture(autouse=True)
def _in_a_call():
    """nervus enrolls a VM only on a client's call: the certificate names it;
    and, as the server does for every call by vmid, the call chose `agent`
    there (ADR-0031, accounts.vm_route)."""
    token = certs._caller.set(certs.Caller("t", "0b9f4c2e-5d1a-4e8b-9c3f-7a6d2e1b0c94",
                                           route=accounts.vm_route(123)))
    yield
    certs._caller.reset(token)


def _connector(key_path, standing_in, tried):
    """nervus's own connector, pointed at the server standing in for each
    reported address, and pinned under loopback exactly as nervus pins."""
    async def connect(address, keys, machine=None):
        tried.append(address)
        if address not in standing_in:
            raise OSError("no route to host")
        return await ssh_connector(key_path, port=standing_in[address].port, timeout=5,
                                   authority=_ca(key_path))(LOOPBACK, keys, machine=machine)
    return connect


@pytest.fixture
def store(tmp_path):
    db = Database(tmp_path / "nervus.db")
    db.open()
    return EnrollmentStore(db)


def _enroller(store, key_path, standing_in, vm, tried, **options):
    return Enroller(store, _ca(key_path).public_key(), _connector(key_path, standing_in, tried),
                    sudoers_dir=str(vm.sudoers), ssh_dir=str(vm.ssh), run_dir=str(vm.run), host_key_wait=0,
                    **options)


# --- the script ------------------------------------------------------------------------

KEY_LINE = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFu8fA3dl0g5nNnZ3cJ+r2mbe8yqk9fXqNw0TQ0Q3l2X nervus"
HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK3wq0q8p1m8w1s0yHcZ8Jm7z3vQwz0p8m2v1pQ7Tn1e root@vm"


def _run(vm, key=KEY_LINE, wait="0", challenge=None):
    """The script as nervus runs it: a fresh challenge each time, as nervus makes one."""
    challenge = secrets.token_hex(16) if challenge is None else challenge
    return subprocess.run(["sh", "-c", ENROLL_SCRIPT, "sh", key, str(vm.sudoers), str(vm.ssh), wait,
                           str(vm.run), challenge],
                          capture_output=True, text=True, env=vm.env(), timeout=30)


def _mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def test_the_script_makes_the_account_its_key_and_its_sudo_and_prints_the_host_keys(tmp_path):
    vm = VM(tmp_path, [HOST_KEY])
    done = _run(vm)
    assert done.returncode == 0, done.stderr
    assert any(line.startswith("useradd ") for line in vm.log)
    assert vm.authorized_keys.read_text() == f"cert-authority {KEY_LINE}\n"
    assert _mode(vm.authorized_keys) == 0o600 and _mode(vm.authorized_keys.parent) == 0o700
    assert (vm.sudoers / "nervus-agent").read_text() == "agent ALL=(ALL) NOPASSWD: ALL\n"
    assert _mode(vm.sudoers / "nervus-agent") == 0o440
    assert sorted(p.name for p in vm.sudoers.iterdir()) == ["nervus-agent"]
    assert sorted(p.name for p in vm.authorized_keys.parent.iterdir()) == ["authorized_keys"]
    lines = done.stdout.splitlines()
    assert lines[lines.index(MARKER) + 1:] == [HOST_KEY]


def test_the_script_leaves_the_challenge_as_a_root_only_file_named_for_it(tmp_path):
    vm = VM(tmp_path, [HOST_KEY])
    challenge = secrets.token_hex(16)
    done = _run(vm, challenge=challenge)
    assert done.returncode == 0, done.stderr
    left = vm.run / f"nervus-enroll-{challenge}"
    assert [p.name for p in vm.run.iterdir()] == [left.name]
    assert left.read_text() == "" and _mode(left) == 0o600


@pytest.mark.parametrize("challenge", ["", "0" * 31, "0" * 33, "A" * 32, "../" + "0" * 29, "0" * 31 + ";"])
def test_a_challenge_nervus_does_not_make_is_refused_and_nothing_is_left(tmp_path, challenge):
    vm = VM(tmp_path, [HOST_KEY])
    done = _run(vm, challenge=challenge)
    assert done.returncode == 35 and "challenge" in done.stderr
    assert list(vm.run.iterdir()) == [] and MARKER not in done.stdout


def test_a_challenge_already_present_is_never_reused(tmp_path):
    vm = VM(tmp_path, [HOST_KEY])
    challenge = secrets.token_hex(16)
    (vm.run / f"nervus-enroll-{challenge}").symlink_to(tmp_path / "elsewhere")
    done = _run(vm, challenge=challenge)
    assert done.returncode == 35 and not (tmp_path / "elsewhere").exists()


def test_an_existing_agent_keeps_its_account_and_gets_exactly_nervus_key(tmp_path):
    vm = VM(tmp_path, [HOST_KEY])
    (tmp_path / "agent-exists").touch()
    vm.authorized_keys.parent.mkdir(parents=True)
    vm.authorized_keys.write_text("ssh-ed25519 AAAAsomeoneelse someone@else\n")
    done = _run(vm)
    assert done.returncode == 0, done.stderr
    assert not any(line.startswith("useradd ") for line in vm.log)
    assert vm.authorized_keys.read_text() == f"cert-authority {KEY_LINE}\n"


def test_running_it_again_changes_nothing_more(tmp_path):
    vm = VM(tmp_path, [HOST_KEY])
    first = _run(vm)
    second = _run(vm)
    assert (first.returncode, second.returncode) == (0, 0)
    assert first.stdout == second.stdout
    assert sum(line.startswith("useradd ") for line in vm.log) == 1
    assert vm.authorized_keys.read_text() == f"cert-authority {KEY_LINE}\n"


def test_a_sudoers_line_visudo_refuses_is_never_put_in_place(tmp_path):
    vm = VM(tmp_path, [HOST_KEY])
    (tmp_path / "visudo-refuses").touch()
    done = _run(vm)
    assert done.returncode == 32 and "visudo refused" in done.stderr
    assert list(vm.sudoers.iterdir()) == []


@pytest.mark.parametrize("missing", ["sudo", "visudo"])
def test_a_vm_without_sudo_is_refused_with_the_reason(tmp_path, missing):
    vm = VM(tmp_path, [HOST_KEY])
    (vm.bin / missing).unlink()
    done = _run(vm)
    assert done.returncode == 32 and "no sudo" in done.stderr
    assert list(vm.sudoers.iterdir()) == []


def test_a_vm_without_useradd_and_no_agent_is_refused(tmp_path):
    vm = VM(tmp_path, [HOST_KEY])
    (vm.bin / "useradd").unlink()
    done = _run(vm)
    assert done.returncode == 30 and "no useradd" in done.stderr
    assert list(vm.sudoers.iterdir()) == []


def test_an_ssh_server_without_host_keys_is_refused(tmp_path):
    vm = VM(tmp_path, [])
    done = _run(vm)
    assert done.returncode == 34 and "no host keys" in done.stderr
    assert MARKER not in done.stdout


def test_it_waits_for_host_keys_a_booting_vm_has_not_made_yet(tmp_path):
    vm = VM(tmp_path, [])
    later = subprocess.Popen(["sh", "-c", f'sleep 1; printf "%s\\n" "{HOST_KEY}" > "{vm.ssh}/ssh_host_0_key.pub"'])
    done = _run(vm, wait="5")
    later.wait()
    assert done.returncode == 0, done.stderr
    assert done.stdout.splitlines()[-1] == HOST_KEY


def test_the_key_is_only_ever_text(tmp_path):
    vm = VM(tmp_path, [HOST_KEY])
    hostile = f'ssh-ed25519 AAAA $(touch {tmp_path}/ran) `touch {tmp_path}/ran`; touch {tmp_path}/ran'
    done = _run(vm, key=hostile)
    assert done.returncode == 0, done.stderr
    assert not (tmp_path / "ran").exists()
    assert vm.authorized_keys.read_text() == f"cert-authority {hostile}\n"


def test_the_ssh_server_is_started_if_it_is_not_running(tmp_path):
    vm = VM(tmp_path, [HOST_KEY])
    vm.shim("systemctl", 'echo "systemctl $*" >> "$FAKE/log"; [ "$1" != is-active ]')
    done = _run(vm)
    assert done.returncode == 0, done.stderr
    assert "systemctl start ssh" in vm.log


# --- the whole step ------------------------------------------------------------------


async def test_a_vm_is_enrolled_at_its_reported_address_pinned_to_its_reported_key(store, servers, tmp_path):
    server = await servers(root=tmp_path / "vm")
    vm = VM(tmp_path / "vm", [server.host_key_line])
    tried = []
    enroller = _enroller(store, servers.key_path, {VM_ADDRESS: server}, vm, tried)
    row, replaced = await enroller.enroll(Guest(FakeGuestAgent(vm), 123, poll=0), "client-a", now=T0)
    assert replaced is None
    assert (row.vmid, row.address, row.enrolled_by, row.enrolled_at) == (123, VM_ADDRESS, "client-a", T0)
    assert row.host_keys == (" ".join(server.host_key_line.split()[:2]),)
    assert store.get(123) == row
    assert tried == [VM_ADDRESS]  # never loopback, never link-local
    # The CA's line, not the key's (ADR-0025 decision 4).
    assert vm.authorized_keys.read_text() == f"cert-authority {_ca(servers.key_path).public_key()}\n"
    assert server.auths == ["agent"]


async def test_a_server_with_another_key_is_refused_before_nervus_offers_its_own(store, servers, tmp_path):
    vm_server, impostor = await servers(), await servers()
    vm = VM(tmp_path / "vm", [vm_server.host_key_line])
    tried = []
    enroller = _enroller(store, servers.key_path, {VM_ADDRESS: impostor}, vm, tried)
    with pytest.raises(EnrollmentFailed) as failed:
        await enroller.enroll(Guest(FakeGuestAgent(vm), 123, poll=0), "t", now=T0)
    assert failed.value.code == "unreachable"
    assert f"{VM_ADDRESS}: another machine's host key" in failed.value.message
    assert impostor.auths == []  # nervus never began to authenticate to it
    assert store.get(123) is None


async def test_the_next_address_is_tried_when_one_is_another_machine(store, servers, tmp_path):
    vm_server, impostor = await servers(root=tmp_path / "vm"), await servers()
    vm = VM(tmp_path / "vm", [vm_server.host_key_line])
    agent = FakeGuestAgent(vm)
    agent.interfaces.append({"name": "eth1", "ip-addresses": [{"ip-address-type": "ipv4", "ip-address": OTHER_ADDRESS}]})
    tried = []
    enroller = _enroller(store, servers.key_path, {VM_ADDRESS: impostor, OTHER_ADDRESS: vm_server}, vm, tried)
    row, _ = await enroller.enroll(Guest(agent, 123, poll=0), "t", now=T0)
    assert row.address == OTHER_ADDRESS and tried == [VM_ADDRESS, OTHER_ADDRESS]
    assert impostor.auths == []


@pytest.mark.parametrize("answer, exit_status", [("agent\nagent\n", 0), ("agent\n", 1), ("root\nroot\n", 0)])
async def test_a_vm_where_agent_is_not_root_by_sudo_is_not_enrolled(store, servers, tmp_path, answer, exit_status):
    server = await servers(answer=answer, exit_status=exit_status)
    vm = VM(tmp_path / "vm", [server.host_key_line])
    enroller = _enroller(store, servers.key_path, {VM_ADDRESS: server}, vm, [])
    with pytest.raises(EnrollmentFailed) as failed:
        await enroller.enroll(Guest(FakeGuestAgent(vm), 123, poll=0), "t", now=T0)
    assert failed.value.code == "unreachable" and "not agent then root" in failed.value.message
    assert store.get(123) is None


async def test_a_vm_nervus_cannot_reach_says_so_and_is_not_enrolled(store, servers, tmp_path):
    server = await servers()
    vm = VM(tmp_path / "vm", [server.host_key_line])
    enroller = _enroller(store, servers.key_path, {}, vm, [])
    with pytest.raises(EnrollmentFailed) as failed:
        await enroller.enroll(Guest(FakeGuestAgent(vm), 123, poll=0), "t", now=T0)
    assert f"{VM_ADDRESS}: no SSH" in failed.value.message
    assert store.get(123) is None


async def test_a_vm_reporting_no_address_nervus_can_reach_is_refused_without_trying(store, servers, tmp_path):
    server = await servers()
    vm = VM(tmp_path / "vm", [server.host_key_line])
    agent = FakeGuestAgent(vm, interfaces=[
        {"name": "lo", "ip-addresses": [{"ip-address-type": "ipv4", "ip-address": LOOPBACK}]},
        {"name": "eth0", "ip-addresses": [{"ip-address-type": "ipv6", "ip-address": LINK_LOCAL}]},
    ])
    tried = []
    with pytest.raises(EnrollmentFailed) as failed:
        await _enroller(store, servers.key_path, {LOOPBACK: server}, vm, tried).enroll(Guest(agent, 123, poll=0), "t")
    assert failed.value.code == "unreachable" and "no address nervus can reach" in failed.value.message
    assert tried == []


async def test_a_script_failure_is_reported_with_its_reason_and_nothing_else_is_tried(store, servers, tmp_path):
    server = await servers()
    vm = VM(tmp_path / "vm", [server.host_key_line])
    (vm.bin / "sudo").unlink()
    agent = FakeGuestAgent(vm)
    tried = []
    with pytest.raises(EnrollmentFailed) as failed:
        await _enroller(store, servers.key_path, {VM_ADDRESS: server}, vm, tried).enroll(Guest(agent, 123, poll=0), "t")
    assert failed.value.code == "cannot_enroll" and "the VM has no sudo" in failed.value.message
    assert tried == [] and not any(path.endswith("network-get-interfaces") for _, path, _ in agent.calls)
    assert store.get(123) is None


@pytest.mark.parametrize("vmid", [124, 999])
async def test_a_guest_that_is_not_a_visible_vm_is_refused(store, servers, tmp_path, vmid):
    vm = VM(tmp_path / "vm", [HOST_KEY])
    with pytest.raises(EnrollmentFailed) as failed:
        await _enroller(store, servers.key_path, {}, vm, []).enroll(Guest(FakeGuestAgent(vm), vmid, poll=0), "t")
    assert failed.value.code == "no_such_vm"


async def test_enrolling_again_replaces_the_row_and_says_what_it_replaced(store, servers, tmp_path):
    old, new = await servers(root=tmp_path / "vm"), await servers(root=tmp_path / "vm")
    vm = VM(tmp_path / "vm", [old.host_key_line])
    first, _ = await _enroller(store, servers.key_path, {VM_ADDRESS: old}, vm, []).enroll(
        Guest(FakeGuestAgent(vm), 123, poll=0), "t", now=T0)
    (vm.ssh / "ssh_host_0_key.pub").write_text(new.host_key_line + "\n")  # rebuilt, same id
    second, replaced = await _enroller(store, servers.key_path, {VM_ADDRESS: new}, vm, []).enroll(
        Guest(FakeGuestAgent(vm), 123, poll=0), "t", now=T0 + 60)
    assert replaced == first and second.host_keys != first.host_keys


# --- the challenge: the machine reached must be this VM (ADR-0022, amendment 2026-11-13) ----


async def test_a_machine_that_cannot_remove_the_challenge_is_not_this_vm_whatever_keys_it_shows(
        store, servers, tmp_path):
    # A root-compromised VM reports another machine's real host key, and an address
    # that reaches that machine. Nothing nervus knows shares the key -- the machine is
    # in hosts.yaml, or not enrolled yet -- so only the challenge can tell.
    other = await servers(root=tmp_path / "other")
    vm = VM(tmp_path / "vm", [other.host_key_line])
    with pytest.raises(EnrollmentFailed) as failed:
        await _enroller(store, servers.key_path, {VM_ADDRESS: other}, vm, []).enroll(
            Guest(FakeGuestAgent(vm), 123, poll=0), "t", now=T0)
    assert failed.value.code == "unreachable"
    assert f"{VM_ADDRESS}: " in failed.value.message and "challenge" in failed.value.message
    assert store.get(123) is None
    assert [p.name for p in vm.run.iterdir()] != []  # left in the VM, never removed by the other machine


async def test_only_the_key_the_vm_presented_is_pinned_not_one_it_merely_listed(store, servers, tmp_path):
    # The VM lists another machine's public key beside its own. Its own passes the
    # check; were the other pinned too, the VM could later forward its SSH port to
    # that machine and every call naming it would land there.
    vm_server, other = await servers(root=tmp_path / "vm"), await servers(root=tmp_path / "other")
    vm = VM(tmp_path / "vm", [vm_server.host_key_line, other.host_key_line])
    row, _ = await _enroller(store, servers.key_path, {VM_ADDRESS: vm_server}, vm, []).enroll(
        Guest(FakeGuestAgent(vm), 123, poll=0), "t", now=T0)
    assert row.host_keys == (" ".join(vm_server.host_key_line.split()[:2]),)
    forwarded = _connector(servers.key_path, {VM_ADDRESS: other}, [])
    with pytest.raises(asyncssh.HostKeyNotVerifiable):
        await forwarded(VM_ADDRESS, row.host_keys, machine=accounts.vm_name(123))
    assert other.auths == []


async def test_the_challenge_is_removed_by_the_check_and_each_enrollment_has_its_own(store, servers, tmp_path):
    server = await servers(root=tmp_path / "vm")
    vm = VM(tmp_path / "vm", [server.host_key_line])
    agent = FakeGuestAgent(vm)
    for n in range(2):
        await _enroller(store, servers.key_path, {VM_ADDRESS: server}, vm, []).enroll(
            Guest(agent, 123, poll=0), "t", now=T0 + n)
        assert list(vm.run.iterdir()) == []
    scripts = [params["command"] for _, path, params in agent.calls if path.endswith("/agent/exec")]
    assert len(scripts) == 2 and scripts[0] != scripts[1]


# --- the pieces --------------------------------------------------------------------


def test_the_pin_names_one_address_and_only_the_keys_given():
    line = " ".join(HOST_KEY.split()[:2])
    assert known_hosts_lines("192.0.2.10", 22, (line,)) == f"192.0.2.10 {line}\n"
    assert known_hosts_lines("192.0.2.10", 2222, (line,)) == f"[192.0.2.10]:2222 {line}\n"
    assert known_hosts_lines("2001:db8::1", 22, (line, line)) == f"2001:db8::1 {line}\n" * 2
    assert known_hosts_lines("2001:db8::1", 2222, (line,)) == f"[2001:db8::1]:2222 {line}\n"


async def test_the_guest_agent_reports_ipv4_first_once_each(tmp_path):
    vm = VM(tmp_path / "vm", [HOST_KEY])
    agent = FakeGuestAgent(vm, interfaces=[
        {"name": "lo", "ip-addresses": [{"ip-address-type": "ipv4", "ip-address": LOOPBACK}]},
        {"name": "eth0", "ip-addresses": [{"ip-address-type": "ipv6", "ip-address": "2001:db8::10"},
                                          {"ip-address-type": "ipv4", "ip-address": VM_ADDRESS},
                                          {"ip-address-type": "ipv4", "ip-address": VM_ADDRESS},
                                          {"ip-address-type": "ipv4"}, "junk"]},
        "junk", {"name": "eth1"},
    ])
    assert await Guest(agent, 123, poll=0).addresses() == [LOOPBACK, VM_ADDRESS, "2001:db8::10"]


async def test_a_key_nervus_cannot_read_fails_the_enrollment_and_runs_nothing(store, tmp_path):
    vm = VM(tmp_path / "vm", [HOST_KEY])
    agent = FakeGuestAgent(vm)
    unreadable = tmp_path / "not-a-key"
    unreadable.write_text("fake key material")
    enroller = Enroller(store, lambda: asyncssh.read_private_key(str(unreadable)), _connector(unreadable, {}, []),
                        sudoers_dir=str(vm.sudoers), ssh_dir=str(vm.ssh), host_key_wait=0)
    with pytest.raises(EnrollmentFailed) as failed:
        await enroller.enroll(Guest(agent, 123, poll=0), "t")
    assert failed.value.code == "cannot_enroll" and "cannot read its own SSH key" in failed.value.message
    assert agent.calls == []
