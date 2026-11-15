"""Where an upload's file goes (ADR-0020 decisions B, C, D and E): the check
before anything moves, the temporary name beside the destination, the
target's own hash before the rename, and nothing left behind when it fails.

The scripts run here in a real shell on real files. Host deliveries run over a
real SSH and SFTP server on loopback (conftest), as this machine's user; the
one thing a test cannot do is sudo, so `root=1` is tested with sudo stood in
for, and once against the real sudo, which refuses without a password."""

import hashlib
import os
import shutil
import stat
import subprocess

import pytest

from nervus.config import Host
from nervus.database import Database
from nervus.ssh import connect
from nervus.upload_targets import CHECK_SCRIPT, FINISH_SCRIPT, HostDelivery, temp_path
from nervus.uploads import DELIVERING, UploadRefused, UploadStore

DATA = b"#!/bin/sh\necho hello\n"
SHA = hashlib.sha256(DATA).hexdigest()
ID = "0123456789abcdef0123456789abcdef"


@pytest.fixture
def store(tmp_path):
    db = Database(tmp_path / "nervus.db")
    db.open()
    s = UploadStore(db, tmp_path / "uploads", free_bytes=lambda: 100 * 1024**3)
    s.open()
    return s


def _delivering(store, dest, data=DATA, key="k1", **options):
    destination = {"kind": "host", "host": "web", "path": str(dest), "replace": False, "root": False,
                   "mode": None, **options}
    upload, _ = store.begin("t", key, destination, len(data), hashlib.sha256(data).hexdigest())
    receiver = store.receiver(upload)
    receiver.write(data)
    upload = store.received(upload, receiver)
    assert upload.state == DELIVERING
    return upload


def _sh(script, *args):
    done = subprocess.run(["sh", "-c", script, "sh", *map(str, args)], capture_output=True, text=True)
    return done.returncode, done.stdout, done.stderr


def _leftovers(directory):
    return sorted(p.name for p in directory.iterdir() if p.name.startswith(".nervus-upload-"))


# --- the check before anything moves (decision C) ---------------------------------------


def test_the_check_passes_a_new_file_in_an_existing_directory(tmp_path):
    assert _sh(CHECK_SCRIPT, tmp_path / "new", "0", "1")[0] == 0


def test_the_check_refuses_a_missing_directory(tmp_path):
    assert _sh(CHECK_SCRIPT, tmp_path / "nope" / "new", "0", "1")[0] == 3


def test_the_check_refuses_an_existing_file_without_replace(tmp_path):
    (tmp_path / "f").write_text("old")
    assert _sh(CHECK_SCRIPT, tmp_path / "f", "0", "1")[0] == 4
    assert _sh(CHECK_SCRIPT, tmp_path / "f", "1", "1")[0] == 0


@pytest.mark.parametrize("make", ["dir", "link"])
def test_the_check_never_replaces_anything_but_a_regular_file(tmp_path, make):
    dest = tmp_path / "x"
    if make == "dir":
        dest.mkdir()
    else:
        (tmp_path / "target").write_text("t")
        dest.symlink_to(tmp_path / "target")
    assert _sh(CHECK_SCRIPT, dest, "1", "1")[0] == 5


@pytest.mark.skipif(os.geteuid() == 0, reason="root can write anywhere")
def test_the_check_refuses_a_directory_the_account_cannot_write(tmp_path):
    locked = tmp_path / "locked"
    locked.mkdir(mode=0o555)
    try:
        assert _sh(CHECK_SCRIPT, locked / "new", "0", "1")[0] == 8
        assert _sh(CHECK_SCRIPT, locked / "new", "0", "0")[0] == 0  # as root, the next step decides
    finally:
        locked.chmod(0o755)


# --- hash, then rename (decisions B and C) ------------------------------------------


def _finish(tmp_path, dest, data=DATA, expected=SHA, mode="", replace="0", src=""):
    tmp = temp_path(str(dest), ID)
    if not src:
        open(tmp, "wb").write(data)
    return tmp, _sh(FINISH_SCRIPT, tmp, dest, mode, replace, expected, src)


def test_a_file_with_the_declared_hash_is_put_in_place(tmp_path):
    dest = tmp_path / "run.sh"
    tmp, (code, out, err) = _finish(tmp_path, dest)
    assert code == 0, err
    assert out.split() == [str(len(DATA)), SHA]
    assert dest.read_bytes() == DATA
    assert not os.path.exists(tmp)


def test_a_file_with_another_hash_is_never_put_in_place(tmp_path):
    dest = tmp_path / "run.sh"
    dest.write_text("old")
    tmp, (code, _, err) = _finish(tmp_path, dest, expected="0" * 64, replace="1")
    assert code == 6
    assert dest.read_text() == "old"
    assert _leftovers(tmp_path) == []


def test_a_file_that_appeared_meanwhile_is_not_replaced(tmp_path):
    dest = tmp_path / "run.sh"
    dest.write_text("theirs")
    _, (code, _, _) = _finish(tmp_path, dest)
    assert code == 4
    assert dest.read_text() == "theirs"
    assert _leftovers(tmp_path) == []


def test_replace_swaps_the_whole_file_by_rename(tmp_path):
    dest = tmp_path / "run.sh"
    dest.write_text("old")
    before = dest.stat().st_ino
    _, (code, _, err) = _finish(tmp_path, dest, replace="1")
    assert code == 0, err
    assert dest.read_bytes() == DATA
    assert dest.stat().st_ino != before  # a new file renamed over it, not the old one rewritten


def test_the_mode_is_set_before_it_is_in_place(tmp_path):
    dest = tmp_path / "run.sh"
    _, (code, _, err) = _finish(tmp_path, dest, mode="0750")
    assert code == 0, err
    assert stat.S_IMODE(dest.stat().st_mode) == 0o750


def test_as_root_the_file_is_installed_from_the_accounts_own_copy(tmp_path):
    src = tmp_path / "own.part"
    src.write_bytes(DATA)
    dest = tmp_path / "run.sh"
    _, (code, _, err) = _finish(tmp_path, dest, src=str(src))
    assert code == 0, err
    assert dest.read_bytes() == DATA
    assert stat.S_IMODE(dest.stat().st_mode) == 0o644
    assert not src.exists()


@pytest.mark.parametrize("name", ["a file", "-n", "it's", "$(touch pwned)", "new\nline", "*"])
def test_a_hostile_file_name_is_only_ever_a_name(tmp_path, name):
    dest = tmp_path / name
    _, (code, _, err) = _finish(tmp_path, dest)
    assert code == 0, err
    assert dest.read_bytes() == DATA
    assert not (tmp_path / "pwned").exists()


# --- a whole delivery to a host, over real SSH (decision D) ---------------------------


@pytest.fixture
def host_delivery(ssh_server, store):
    host = Host(name="web", address=ssh_server.host, os="debian", role="test", agent_user=ssh_server.username,
                status="active")

    async def _connect(_host):
        return await connect(address=ssh_server.host, port=ssh_server.port, username=ssh_server.username,
                             client_keys=[ssh_server.client_key_path], known_hosts=ssh_server.known_hosts_path)

    return HostDelivery(store, {"web": host}, _connect)


async def test_a_host_upload_is_written_hashed_and_renamed(host_delivery, store, tmp_path):
    dest = tmp_path / "srv" / "run.sh"
    dest.parent.mkdir()
    upload = _delivering(store, dest)
    route, sha = await host_delivery(upload)
    assert (route, sha) == ("sftp", SHA)
    assert dest.read_bytes() == DATA
    assert _leftovers(dest.parent) == []


async def test_a_large_host_upload_arrives_whole(host_delivery, store, tmp_path):
    data = os.urandom(5 * 1024 * 1024 + 3)
    dest = tmp_path / "big.bin"
    upload = _delivering(store, dest, data=data)
    route, sha = await host_delivery(upload)
    assert sha == hashlib.sha256(data).hexdigest()
    assert dest.read_bytes() == data


async def test_an_existing_file_is_refused_before_anything_is_sent(host_delivery, store, tmp_path):
    dest = tmp_path / "run.sh"
    dest.write_text("old")
    upload = _delivering(store, dest)
    with pytest.raises(UploadRefused) as refused:
        await host_delivery(upload)
    assert refused.value.code == "exists"
    assert "replace=1" in refused.value.message
    assert dest.read_text() == "old"
    assert _leftovers(tmp_path) == []


async def test_a_missing_directory_is_refused(host_delivery, store, tmp_path):
    upload = _delivering(store, tmp_path / "nope" / "run.sh")
    with pytest.raises(UploadRefused) as refused:
        await host_delivery(upload)
    assert refused.value.code == "no_directory"


async def test_a_temporary_file_in_the_way_leaves_nothing_and_changes_nothing(host_delivery, store, tmp_path):
    """The SFTP open is exclusive: a file already at the temporary name, say a
    link someone planted, is never written through."""
    dest = tmp_path / "run.sh"
    upload = _delivering(store, dest)
    target = tmp_path / "elsewhere"
    os.symlink(target, temp_path(str(dest), upload.id))
    with pytest.raises(Exception):
        await host_delivery(upload)
    assert not target.exists()
    assert not dest.exists()
    assert _leftovers(tmp_path) == []  # what was at the temporary name is removed, not followed


async def test_as_root_through_sudo_it_is_installed(host_delivery, store, tmp_path, monkeypatch):
    monkeypatch.setattr(HostDelivery, "SUDO", ())  # stands in for sudo -n: runs the same script, as this user
    dest = tmp_path / "run.sh"
    upload = _delivering(store, dest, root=True, mode="0700")
    route, sha = await host_delivery(upload)
    assert (route, sha) == ("sftp+sudo", SHA)
    assert stat.S_IMODE(dest.stat().st_mode) == 0o700
    assert not os.path.exists(f"/tmp/.nervus-upload-{upload.id}.part")


@pytest.mark.skipif(shutil.which("sudo") is None or subprocess.run(["sudo", "-n", "true"], capture_output=True)
                    .returncode == 0, reason="needs a sudo that asks for a password")
async def test_as_root_where_sudo_asks_for_a_password_it_is_refused_with_sudos_reason(host_delivery, store,
                                                                                       tmp_path):
    dest = tmp_path / "run.sh"
    upload = _delivering(store, dest, root=True)
    with pytest.raises(UploadRefused) as refused:
        await host_delivery(upload)
    assert refused.value.code == "sudo_refused"
    assert not dest.exists()
    assert not os.path.exists(f"/tmp/.nervus-upload-{upload.id}.part")


async def test_cleanup_removes_what_an_interrupted_delivery_left(host_delivery, store, tmp_path):
    dest = tmp_path / "run.sh"
    upload = _delivering(store, dest)
    leftover = temp_path(str(dest), upload.id)
    open(leftover, "wb").write(b"part")
    await host_delivery.cleanup(upload)
    assert not os.path.exists(leftover)


# --- a VM, through a guest agent that runs the scripts here (decision E) -------------

import asyncio
import itertools
import json
import re
import shlex
import socket
import threading
import time

import uvicorn
from pathlib import Path

from nervus.audit import AuditLog
from nervus.auth import Token
from nervus.config import Settings
from nervus.proxmox import ProxmoxResponse
from nervus.server import build_server
from nervus.upload_targets import MAX_PUSH_BYTES, Deliveries, VMDelivery
from nervus.tls import generate_own_authority, root_cert_path
from nervus.uploader import Uploader
from nervus import upload_targets


class FakeAgent:
    """Proxmox's guest-agent calls as the deployed Proxmox answers them, with
    the guest's shell played by this machine's: `command` runs here, and
    `input-data` is its standard input."""

    def __init__(self, guests=None, refuse=None):
        self.guests = guests if guests is not None else [{"vmid": 123, "type": "qemu", "node": "hv"},
                                                         {"vmid": 124, "type": "lxc", "node": "hv"}]
        self.refuse = refuse or {}
        self.calls = []
        self._runs = {}
        self._pids = itertools.count(1000)

    async def request(self, method, path, params=None, *, timeout=60.0):
        params = params or {}
        self.calls.append((method, path, params))
        for suffix, (status, reason) in self.refuse.items():
            if path.endswith(suffix):
                return ProxmoxResponse(status=status, reason=reason, data=None, errors=None, body_bytes=0)
        if path == "/cluster/resources":
            return self._ok(self.guests)
        if path == "/nodes/hv/qemu/123/agent/exec":
            done = await asyncio.to_thread(subprocess.run, params["command"], input=params.get("input-data", ""),
                                           capture_output=True, text=True)
            pid = next(self._pids)
            self._runs[pid] = done
            return self._ok({"pid": pid})
        if path == "/nodes/hv/qemu/123/agent/exec-status":
            done = self._runs[params["pid"]]
            return self._ok({"exited": 1, "exitcode": done.returncode, "out-data": done.stdout,
                             "err-data": done.stderr})
        return ProxmoxResponse(status=501, reason="not in the fake", data=None, errors=None, body_bytes=0)

    @staticmethod
    def _ok(data):
        return ProxmoxResponse(status=200, reason="OK", data=data, errors=None, body_bytes=0)


def _vm_upload(store, dest, data=DATA, key="v1", **options):
    destination = {"kind": "vm", "vmid": 123, "path": str(dest), "replace": False, "root": False, "mode": None,
                   **options}
    upload, _ = store.begin("t", key, destination, len(data), hashlib.sha256(data).hexdigest())
    receiver = store.receiver(upload)
    receiver.write(data)
    return store.received(upload, receiver)


def _serve_nervus(store, tmp_path, **tls):
    """nervus's MCP app, with the pull route, under uvicorn on loopback; over
    HTTPS when given uvicorn's ssl_certfile and ssl_keyfile."""
    audit = AuditLog(path=tmp_path / "audit.jsonl")
    settings = Settings(hosts={}, tokens_path=tmp_path / "t", known_hosts_path=tmp_path / "k",
                        ssh_key_path=tmp_path / "s", audit_log_path=tmp_path / "audit.jsonl", transfer_dir=tmp_path,
                        bind_host="127.0.0.1", bind_port=0, switches_path=None)
    uploader = Uploader(store, audit, deliver=None)
    app = build_server(settings=settings, tokens={"x": Token(id="t", client="c", project="p", hosts=frozenset())},
                       audit=audit, uploader=uploader).streamable_http_app()
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error", **tls))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(200):
        if server.started:
            break
        time.sleep(0.01)
    yield f"{'https' if tls else 'http'}://127.0.0.1:{port}", audit.path
    server.should_exit = True
    thread.join(timeout=10)


@pytest.fixture
def nervus(store, tmp_path):
    yield from _serve_nervus(store, tmp_path)


@pytest.fixture
def nervus_tls(store, tmp_path):
    """The same over HTTPS, as ADR-0021 serves it: a certificate under nervus's
    own authority, naming the address the VM is given (ADR-0022 8a). Yields
    the address, the audit log, and the root's file."""
    cert, key = tmp_path / "tls" / "tls.crt", tmp_path / "tls" / "tls.key"
    cert.parent.mkdir()
    generate_own_authority(cert, key, ["127.0.0.1", "nervus.test"])
    for base, audit_path in _serve_nervus(store, tmp_path, ssl_certfile=str(cert), ssl_keyfile=str(key)):
        yield base, audit_path, root_cert_path(cert)


def _closed_port_url():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return f"http://127.0.0.1:{s.getsockname()[1]}/upload-pull"


curl = pytest.mark.skipif(shutil.which("curl") is None, reason="curl is not installed")


@curl
async def test_a_vm_fetches_its_upload_from_nervus(store, nervus, tmp_path):
    base, audit_path = nervus
    agent = FakeAgent()
    data = os.urandom(3 * 1024 * 1024 + 5)
    dest = tmp_path / "vm" / "app.tar"
    dest.parent.mkdir()
    upload = _vm_upload(store, dest, data=data)
    route, sha = await VMDelivery(store, agent, base + "/upload-pull", poll=0)(upload)
    assert (route, sha) == ("pull", hashlib.sha256(data).hexdigest())
    assert dest.read_bytes() == data
    assert _leftovers(dest.parent) == []
    records = [json.loads(line) for line in audit_path.read_text().splitlines()]
    pulls = [r for r in records if r.get("action") == "pull"]
    assert [r["phase"] for r in pulls] == ["intent", "result"]
    assert pulls[1]["bytes_sent"] == len(data) and pulls[1]["all_sent"]


@curl
async def test_the_secret_reaches_the_vm_on_standard_input_only(store, nervus, tmp_path):
    base, audit_path = nervus
    agent = FakeAgent()
    upload = _vm_upload(store, tmp_path / "app.sh")
    await VMDelivery(store, agent, base + "/upload-pull", poll=0)(upload)
    (pull,) = [p for _, path, p in agent.calls if path.endswith("/exec") and "input-data" in p]
    secret = pull["input-data"].strip()
    assert len(secret) >= 43
    assert all(secret not in str(arg) for arg in pull["command"])
    assert secret not in audit_path.read_text()
    assert store.claim_pull_secret(secret) is None  # spent


@curl
async def test_a_vm_fetches_its_upload_from_an_https_nervus_trusting_its_root(store, nervus_tls, tmp_path,
                                                                             monkeypatch):
    """ADR-0022 8a: the VM checks nervus's certificate against nervus's root,
    handed to it with the secret, and keeps nothing of it afterwards."""
    base, _, root = nervus_tls
    vm_tmp = tmp_path / "vm-tmp"  # the VM's own temporary directory
    vm_tmp.mkdir()
    monkeypatch.setenv("TMPDIR", str(vm_tmp))
    data = os.urandom(1024 * 1024 + 3)
    dest = tmp_path / "vm" / "app.tar"
    dest.parent.mkdir()
    upload = _vm_upload(store, dest, data=data)
    route, sha = await VMDelivery(store, FakeAgent(), base + "/upload-pull", pull_root=root, poll=0)(upload)
    assert (route, sha) == ("pull", hashlib.sha256(data).hexdigest())
    assert dest.read_bytes() == data
    assert _leftovers(dest.parent) == []
    assert list(vm_tmp.iterdir()) == []  # nervus's root is not left in the VM


@curl
async def test_the_root_reaches_the_vm_on_standard_input_only(store, nervus_tls, tmp_path):
    base, audit_path, root = nervus_tls
    agent = FakeAgent()
    upload = _vm_upload(store, tmp_path / "app.sh")
    await VMDelivery(store, agent, base + "/upload-pull", pull_root=root, poll=0)(upload)
    (pull,) = [p for _, path, p in agent.calls if path.endswith("/exec") and "input-data" in p]
    pem = root.read_text()
    assert pem in pull["input-data"]
    assert all("BEGIN CERTIFICATE" not in str(arg) for arg in pull["command"])
    secret = pull["input-data"].split("\n", 1)[0]
    assert len(secret) >= 43 and store.claim_pull_secret(secret) is None  # first line, and spent


@curl
@pytest.mark.parametrize("given", ["none", "missing"])
async def test_without_nervus_root_an_https_pull_is_refused_and_the_file_pushed(store, nervus_tls, tmp_path, given):
    """What ADR-0022 finding 1 saw: the VM's curl refuses a certificate it
    cannot check, so the file goes the slow way. A root file that is not
    there (nervus serving another authority's certificate) is no root."""
    base, _, _ = nervus_tls
    dest = tmp_path / "app.sh"
    upload = _vm_upload(store, dest)
    root = None if given == "none" else tmp_path / "no-such-root.crt"
    route, _ = await VMDelivery(store, FakeAgent(), base + "/upload-pull", pull_root=root, poll=0)(upload)
    assert route == "guest-agent"
    assert dest.read_bytes() == DATA


@curl
async def test_a_failed_pull_leaves_no_copy_of_nervus_root(store, tmp_path, monkeypatch):
    root = tmp_path / "tls" / "tls-root.crt"
    root.parent.mkdir()
    generate_own_authority(tmp_path / "tls" / "tls.crt", tmp_path / "tls" / "tls.key", ["nervus.test"])
    vm_tmp = tmp_path / "vm-tmp"
    vm_tmp.mkdir()
    monkeypatch.setenv("TMPDIR", str(vm_tmp))
    dest = tmp_path / "app.sh"
    upload = _vm_upload(store, dest)
    route, _ = await VMDelivery(store, FakeAgent(), _closed_port_url().replace("http:", "https:"),
                                pull_root=root, poll=0)(upload)
    assert route == "guest-agent" and dest.read_bytes() == DATA
    assert list(vm_tmp.iterdir()) == []


INSTALL = Path(__file__).resolve().parent.parent / "docs" / "install.md"
# Where the doc says <nervus's address>: a documentation address nothing
# answers at. The VM's curl is pointed at loopback while checking nervus's
# certificate against this, since loopback is always in the certificate.
ADDRESS = "192.0.2.9"


def _installed(name):
    text = INSTALL.read_text()
    match = re.search(rf"<!-- install:{name} -->\n```[a-z]*\n(.*?)\n```", text, re.S)
    assert match, f"docs/install.md has no install:{name} block"
    return match.group(1).replace("<nervus's name>", "nervus.test").replace("<nervus's address>", ADDRESS)


@curl
async def test_the_install_docs_pull_address_works_with_the_certificate_they_make(store, tmp_path, monkeypatch):
    """ADR-0022 step 0b: tls-init as step 7 has it, and the drop-in's flags as
    "A Proxmox host" has them; a VM then pulls an upload over HTTPS, by
    nervus's address, with no name and its certificate checked."""
    from nervus.__main__ import main, parse_args

    words = shlex.split(_installed("tls-init"))
    cert, key = tmp_path / "tls" / "tls.crt", tmp_path / "tls" / "tls.key"
    cert.parent.mkdir(mode=0o700)
    assert main(["tls-init", *words[words.index("tls-init") + 1:], "--tls-cert", str(cert),
                 "--tls-key", str(key)]) == 0
    flags = parse_args(shlex.split(_installed("proxmox-flags").replace("\\\n", " ")))
    assert flags.proxmox == "/opt/nervus/secrets/proxmox.yaml"
    assert flags.upload_pull_url.startswith(f"https://{ADDRESS}:8000/")
    shim = tmp_path / "bin" / "curl"
    shim.parent.mkdir()
    shim.write_text(f'#!/bin/sh\nexec {shutil.which("curl")} --connect-to ::127.0.0.1: "$@"\n')
    shim.chmod(0o755)
    monkeypatch.setenv("PATH", f"{shim.parent}{os.pathsep}{os.environ['PATH']}")
    dest = tmp_path / "app.sh"
    upload = _vm_upload(store, dest)
    for base, _ in _serve_nervus(store, tmp_path, ssl_certfile=str(cert), ssl_keyfile=str(key)):
        url = flags.upload_pull_url.replace(":8000/", f":{base.rsplit(':', 1)[1]}/")
        route, _ = await VMDelivery(store, FakeAgent(), url, pull_root=root_cert_path(cert), poll=0)(upload)
    assert route == "pull" and dest.read_bytes() == DATA


async def test_without_a_pull_address_the_file_is_pushed_through_the_guest_agent(store, tmp_path):
    data = os.urandom(150_001)  # four pushes
    dest = tmp_path / "app.bin"
    upload = _vm_upload(store, dest, data=data)
    route, sha = await VMDelivery(store, FakeAgent(), None, poll=0)(upload)
    assert route == "guest-agent"
    assert dest.read_bytes() == data


@curl
async def test_a_vm_that_cannot_reach_nervus_gets_the_file_pushed(store, tmp_path):
    dest = tmp_path / "app.sh"
    upload = _vm_upload(store, dest)
    route, _ = await VMDelivery(store, FakeAgent(), _closed_port_url(), poll=0)(upload)
    assert route == "guest-agent"
    assert dest.read_bytes() == DATA


@curl
async def test_a_file_too_large_to_push_is_refused_when_the_vm_cannot_fetch_it(store, tmp_path, monkeypatch):
    monkeypatch.setattr(upload_targets, "MAX_PUSH_BYTES", 10)
    dest = tmp_path / "app.sh"
    upload = _vm_upload(store, dest)
    with pytest.raises(UploadRefused) as refused:
        await VMDelivery(store, FakeAgent(), _closed_port_url(), poll=0)(upload)
    assert refused.value.code == "too_large_to_push"
    assert not dest.exists()
    assert _leftovers(tmp_path) == []


async def test_an_existing_file_in_a_vm_is_refused_before_anything_is_sent(store, tmp_path):
    dest = tmp_path / "app.sh"
    dest.write_text("old")
    agent = FakeAgent()
    upload = _vm_upload(store, dest)
    with pytest.raises(UploadRefused) as refused:
        await VMDelivery(store, agent, None, poll=0)(upload)
    assert refused.value.code == "exists"
    assert dest.read_text() == "old"
    assert not any("input-data" in p for _, _, p in agent.calls)


@pytest.mark.parametrize("vmid", [999, 124])
async def test_a_guest_that_is_not_a_visible_vm_is_refused(store, tmp_path, vmid):
    upload = _vm_upload(store, tmp_path / "app.sh")
    upload = upload.__class__(**{**upload.__dict__, "destination": {**upload.destination, "vmid": vmid}})
    with pytest.raises(UploadRefused) as refused:
        await VMDelivery(store, FakeAgent(), None, poll=0)(upload)
    assert refused.value.code == "no_such_vm"


async def test_a_proxmox_refusal_is_reported_with_its_reason(store, tmp_path):
    upload = _vm_upload(store, tmp_path / "app.sh")
    agent = FakeAgent(refuse={"/agent/exec": (403, "Permission check failed (VM.GuestAgent.Unrestricted)")})
    with pytest.raises(UploadRefused) as refused:
        await VMDelivery(store, agent, None, poll=0)(upload)
    assert refused.value.code == "destination_error"
    assert "VM.GuestAgent.Unrestricted" in refused.value.message


async def test_a_vm_upload_with_a_mode_and_replace(store, tmp_path):
    dest = tmp_path / "app.sh"
    dest.write_text("old")
    upload = _vm_upload(store, dest, replace=True, mode="0755")
    await VMDelivery(store, FakeAgent(), None, poll=0)(upload)
    assert dest.read_bytes() == DATA
    assert stat.S_IMODE(dest.stat().st_mode) == 0o755


async def test_vm_cleanup_removes_what_an_interrupted_delivery_left(store, tmp_path):
    dest = tmp_path / "app.sh"
    upload = _vm_upload(store, dest)
    leftover = temp_path(str(dest), upload.id)
    open(leftover, "wb").write(b"part")
    await VMDelivery(store, FakeAgent(), None, poll=0).cleanup(upload)
    assert not os.path.exists(leftover)


async def test_the_dispatcher_sends_hosts_and_vms_each_to_their_own(store, tmp_path):
    seen = []

    class One:
        def __init__(self, name):
            self.name = name

        async def __call__(self, upload):
            seen.append(self.name)
            return self.name, upload.sha256

    deliveries = Deliveries(One("host"), One("vm"))
    await deliveries(_delivering(store, tmp_path / "a"))
    await deliveries(_vm_upload(store, tmp_path / "b"))
    assert seen == ["host", "vm"]


async def test_a_push_that_fails_part_way_leaves_nothing_in_the_vm(store, tmp_path, monkeypatch):
    # The guest takes two pieces, then refuses the third, as a full disk would.
    monkeypatch.setattr(upload_targets, "APPEND_SCRIPT",
                        'base64 -d >> "$1" || exit 9\n[ "$(wc -c < "$1")" -lt 100000 ] || exit 9\n')
    dest = tmp_path / "app.bin"
    upload = _vm_upload(store, dest, data=os.urandom(150_001))
    with pytest.raises(UploadRefused) as refused:
        await VMDelivery(store, FakeAgent(), None, poll=0)(upload)
    assert refused.value.code == "cannot_write"
    assert not dest.exists()
    assert _leftovers(tmp_path) == []


# --- a refusal says what the machine's level allows (ADR-0024) -------------------------

import asyncssh  # noqa: E402

from nervus.upload_targets import script_failure  # noqa: E402


@pytest.mark.parametrize("level", [None, "full"])
def test_where_sudo_may_help_a_write_refused_hints_root_1(level):
    refused = script_failure(8, "cannot write in /srv as agent", "web:/srv/x", level=level)
    assert refused.code == "not_writable" and refused.message.endswith("; send root=1 to write it as root")


@pytest.mark.parametrize("level, says", [
    ("read-only", "web is read-only: its owner chose that nervus changes nothing there"),
    ("standard", "web is standard: nervus writes only where agent may, and has no sudo"),
])
def test_below_full_a_write_refused_says_the_level_and_never_hints_root_1(level, says):
    refused = script_failure(8, "cannot write in /srv as agent", "web:/srv/x", level=level, host="web")
    assert refused.code == "not_writable" and says in refused.message and "send root=1" not in refused.message


def test_below_full_root_1_refused_by_sudo_says_the_level():
    refused = script_failure(1, "sudo: a password is required", "web:/srv/x", root=True, level="standard",
                             host="web")
    assert refused.code == "sudo_refused" and "web is standard" in refused.message


def _at_level(host_delivery, level):
    host = host_delivery.hosts["web"]
    host_delivery.hosts["web"] = Host(name=host.name, address=host.address, os=host.os, role=host.role,
                                      agent_user=host.agent_user, status=host.status, level=level)


async def test_a_standard_machine_refuses_a_folder_agent_cannot_write_saying_so(host_delivery, store, tmp_path):
    _at_level(host_delivery, "standard")
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o500)
    try:
        with pytest.raises(UploadRefused) as refused:
            await host_delivery(_delivering(store, locked / "run.sh"))
    finally:
        locked.chmod(0o700)
    assert refused.value.code == "not_writable" and "web is standard" in refused.value.message
    assert "send root=1" not in refused.value.message


async def test_a_read_only_machine_refusing_the_sftp_write_is_said_plainly(host_delivery, store, tmp_path,
                                                                            monkeypatch):
    """Its SFTP server runs with -R, so even ~/.nervus refuses a write there."""
    _at_level(host_delivery, "read-only")

    async def refuse(self, conn, upload, remote):
        raise asyncssh.SFTPPermissionDenied("Permission denied")

    monkeypatch.setattr(HostDelivery, "_send", refuse)
    dest = tmp_path / "run.sh"
    with pytest.raises(UploadRefused) as refused:
        await host_delivery(_delivering(store, dest))
    assert refused.value.code == "not_writable"
    assert "Permission denied" in refused.value.message and "web is read-only" in refused.value.message
    assert not dest.exists() and _leftovers(tmp_path) == []
