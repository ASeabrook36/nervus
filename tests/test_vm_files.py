"""Files to and from a VM by the fastest route nervus has (ADR-0022 step 4,
decision 7a), and the answer naming it.

- An export from a VM is read over SFTP, the VM enrolled first if it is not
  yet, and through the guest agent only if it cannot be enrolled.
- An upload into a VM is fetched by the VM itself first; if it cannot, it goes
  over SFTP, enrolling the VM, which lifts the guest agent's 32 MiB limit;
  only if neither works is it pushed through the guest agent.

The VM is played as in test_vm_targets."""

import hashlib
import json
import os

import pytest

from nervus import certs
from nervus.audit import AuditLog
from nervus.database import Database
from nervus.exporter import Exporter, VMRequest
from nervus.exports import ExportStore
from nervus.server import export_response
from nervus.upload_targets import HostDelivery, VMDelivery, agent_temp_path
from nervus.uploader import Uploader
from nervus.uploads import UploadRefused
from nervus import upload_targets
from test_enroller import VM_ADDRESS, _in_a_call, servers  # noqa: F401
from test_upload_targets import DATA, _closed_port_url, _leftovers, _vm_upload, nervus, store  # noqa: F401
from test_vm_targets import world  # noqa: F401


def _break_enrollment(world):
    (world.vm.bin / "sudo").unlink()


def _guest_reads(world):
    return [p for _, p, _ in world.agent.calls if p.endswith("/file-read")]


# --- exports ------------------------------------------------------------------------


@pytest.fixture
def exporter(tmp_path, world):
    db = Database(tmp_path / "exports.db")
    db.open()
    exports = ExportStore(db, tmp_path / "exports", free_bytes=lambda: 100 * 1024**3)
    exports.open()
    return Exporter(exports, AuditLog(path=tmp_path / "audit.jsonl"), connect=None, vm_api=world.agent,
                    vm_connect=world.targets.connect)


async def _export(exporter, path, key="k"):
    run_id = exporter.audit.record_intent("export", {"token_id": "t"})
    status = await exporter.export("t", key, VMRequest(123, str(path)), run_id, wait=30)
    return status.export, exporter.store.route(status.export.id)


async def test_an_export_from_a_vm_goes_over_sftp_enrolling_it_first(tmp_path, world, exporter):
    data = os.urandom(3 * 1024 * 1024 + 7)
    source = tmp_path / "in-the-vm.bin"
    source.write_bytes(data)
    export, route = await _export(exporter, source)
    assert export.state == "ready" and export.sha256 == hashlib.sha256(data).hexdigest()
    assert route == "sftp"
    assert _guest_reads(world) == []
    assert world.store.get(123).enrolled_by == "t"


async def test_an_export_from_a_vm_that_cannot_be_enrolled_goes_through_the_guest_agent(tmp_path, world, exporter):
    _break_enrollment(world)
    source = tmp_path / "in-the-vm.bin"
    source.write_bytes(DATA)
    export, route = await _export(exporter, source)
    assert export.state == "ready" and export.sha256 == hashlib.sha256(DATA).hexdigest()
    assert route == "guest-agent" and _guest_reads(world)
    assert world.store.get(123) is None


async def test_an_export_from_a_gone_vm_says_so(tmp_path, world, exporter):
    await world.visit()
    world.standing_in.clear()
    world.agent.guests = [g for g in world.agent.guests if g["vmid"] != 123]
    export, route = await _export(exporter, tmp_path / "whatever")
    assert (export.state, export.failure_code) == ("failed", "vm_gone")
    assert route is None


async def test_a_spent_exports_route_is_forgotten_with_it(tmp_path, world, exporter):
    source = tmp_path / "in-the-vm.bin"
    source.write_bytes(DATA)
    export, route = await _export(exporter, source)
    assert route == "sftp"
    exporter.store.sweep(now=export.expires_at + 10 * 24 * 3600)
    assert exporter.store.route(export.id) is None


# What enrolling the VM on the way did is in the audit result of the call that caused it
# (ADR-0001 section 10; ADR-0022 verification 1), whatever then became of the copy.


def _result(audit, run_id):
    records = [json.loads(line) for line in audit.path.read_text().splitlines()]
    done, = [r for r in records if r["id"] == run_id and r["phase"] == "result"]
    return done


async def _exported(exporter, path, key="k"):
    """One call, as the export tool makes it: its result record, and the export."""
    run_id = exporter.audit.record_intent("export", {"token_id": "t"})
    certs.acting_for("t", run_id)
    status = await exporter.export("t", key, VMRequest(123, str(path)), run_id, wait=30)
    return _result(exporter.audit, run_id), status.export


async def test_an_export_that_enrolls_the_vm_says_so_in_its_audit_result(tmp_path, world, exporter):
    source = tmp_path / "in-the-vm.bin"
    source.write_bytes(DATA)
    done, export = await _exported(exporter, source)
    assert export.state == "ready" and done["state"] == "ready"
    assert done["vm_note"] == f"VM 123 enrolled, at {VM_ADDRESS}"
    later, _ = await _exported(exporter, source, key="k2")  # enrolled already: nothing to say
    assert later["state"] == "ready" and "vm_note" not in later


async def test_an_export_that_fails_after_enrolling_the_vm_still_says_it_was_enrolled(tmp_path, world, exporter):
    done, export = await _exported(exporter, tmp_path / "no-such-file")
    assert export.state == "failed" and done["state"] == "failed"
    assert world.store.get(123) is not None and done["vm_note"] == f"VM 123 enrolled, at {VM_ADDRESS}"


async def test_an_export_through_the_guest_agent_says_the_vm_could_not_be_enrolled(tmp_path, world, exporter):
    """The enrollment script ran in the VM as root, so the attempt leaves its trace too."""
    _break_enrollment(world)
    source = tmp_path / "in-the-vm.bin"
    source.write_bytes(DATA)
    done, export = await _exported(exporter, source)
    assert export.state == "ready" and world.scripts_run() == 1
    assert done["vm_note"].startswith("VM 123 could not be enrolled or reached over SSH: ")
    assert "the VM has no sudo" in done["vm_note"]


def test_the_answer_names_the_route():
    class Done:
        state = "ready"
        export = type("E", (), dict(id="e1", source={}, filename="f", bytes_written=1, size=1, sha256="0" * 64,
                                    state="ready", expires_at=0.0, failure_code=None))()
    assert export_response(Done(), "k", "r", "sftp")["route"] == "sftp"
    assert "route" not in export_response(Done(), "k", "r")


# --- uploads ----------------------------------------------------------------------


@pytest.fixture
def as_root(monkeypatch):
    monkeypatch.setattr(HostDelivery, "SUDO", ())  # stands in for sudo -n, as in test_upload_targets


def _vm_delivery(store, world, pull_url=None):
    return VMDelivery(store, world.agent, pull_url, vm_connect=world.targets.connect, poll=0)


@pytest.mark.usefixtures("as_root")
async def test_an_upload_the_vm_cannot_fetch_goes_over_sftp_as_root(store, world, tmp_path):
    dest = tmp_path / "dest" / "app.sh"
    dest.parent.mkdir()
    upload = _vm_upload(store, dest)
    route, sha = await _vm_delivery(store, world, _closed_port_url())(upload)
    assert (route, sha) == ("sftp+sudo", hashlib.sha256(DATA).hexdigest())
    assert dest.read_bytes() == DATA
    assert _leftovers(dest.parent) == [] and not os.path.exists(agent_temp_path(upload.id))
    assert world.store.get(123) is not None  # enrolled on the way


@pytest.mark.usefixtures("as_root")
async def test_over_sftp_the_guest_agents_limit_does_not_apply(store, world, tmp_path, monkeypatch):
    monkeypatch.setattr(upload_targets, "MAX_PUSH_BYTES", 10)
    dest = tmp_path / "big.bin"
    data = os.urandom(5 * 1024 * 1024)
    upload = _vm_upload(store, dest, data=data)
    route, _ = await _vm_delivery(store, world)(upload)
    assert route == "sftp+sudo" and dest.read_bytes() == data


async def test_a_vm_that_cannot_be_enrolled_gets_the_file_pushed(store, world, tmp_path):
    _break_enrollment(world)
    dest = tmp_path / "app.sh"
    upload = _vm_upload(store, dest)
    route, _ = await _vm_delivery(store, world)(upload)
    assert route == "guest-agent" and dest.read_bytes() == DATA


async def test_too_large_to_push_names_every_route_that_failed(store, world, tmp_path, monkeypatch):
    monkeypatch.setattr(upload_targets, "MAX_PUSH_BYTES", 10)
    _break_enrollment(world)
    dest = tmp_path / "app.sh"
    upload = _vm_upload(store, dest)
    with pytest.raises(UploadRefused) as refused:
        await _vm_delivery(store, world)(upload)
    assert refused.value.code == "too_large_to_push"
    assert "--upload-pull-url" in refused.value.message and "the VM has no sudo" in refused.value.message
    assert not dest.exists() and _leftovers(tmp_path) == []


@pytest.mark.skipif(__import__("shutil").which("curl") is None, reason="curl is not installed")
async def test_a_vm_that_can_fetch_its_file_is_never_enrolled_for_it(store, nervus, world, tmp_path):
    base, _ = nervus
    dest = tmp_path / "app.sh"
    upload = _vm_upload(store, dest)
    route, _ = await _vm_delivery(store, world, base + "/upload-pull")(upload)
    assert route == "pull" and world.store.get(123) is None


async def _delivered(store, world, upload, tmp_path):
    """One upload's delivery, as the upload route starts it: its result record, and the upload."""
    audit = AuditLog(path=tmp_path / "audit.jsonl")
    uploader = Uploader(store, audit, deliver=_vm_delivery(store, world))
    run_id = audit.record_intent("upload", {"token_id": "t"})
    certs.acting_for("t", run_id)
    uploader.start(upload, run_id)
    await uploader.wait(upload.id, 30)
    return _result(audit, run_id), store.get("t", upload.id)


@pytest.mark.usefixtures("as_root")
async def test_an_upload_that_enrolls_the_vm_says_so_in_its_audit_result(store, world, tmp_path):
    done, upload = await _delivered(store, world, _vm_upload(store, tmp_path / "app.sh"), tmp_path)
    assert (upload.state, done["state"], done["route"]) == ("delivered", "delivered", "sftp+sudo")
    assert done["vm_note"] == f"VM 123 enrolled, at {VM_ADDRESS}"
    later, _ = await _delivered(store, world, _vm_upload(store, tmp_path / "again.sh", key="v2"), tmp_path)
    assert later["state"] == "delivered" and "vm_note" not in later  # enrolled already: nothing to say


async def test_an_upload_that_fails_after_enrolling_the_vm_still_says_it_was_enrolled(store, world, tmp_path,
                                                                                    monkeypatch):
    async def refused(self, conn, upload, where, root, **named):
        raise UploadRefused("not_writable", f"{where}: the VM refused the write")

    monkeypatch.setattr(HostDelivery, "deliver", refused)
    done, upload = await _delivered(store, world, _vm_upload(store, tmp_path / "app.sh"), tmp_path)
    assert (upload.state, done["failure_code"]) == ("failed", "not_writable")
    assert world.store.get(123) is not None and done["vm_note"] == f"VM 123 enrolled, at {VM_ADDRESS}"


async def test_an_upload_pushed_through_the_guest_agent_says_the_vm_could_not_be_enrolled(store, world, tmp_path):
    _break_enrollment(world)
    done, upload = await _delivered(store, world, _vm_upload(store, tmp_path / "app.sh"), tmp_path)
    assert (upload.state, done["route"]) == ("delivered", "guest-agent") and world.scripts_run() == 1
    assert done["vm_note"].startswith("VM 123 could not be enrolled or reached over SSH: ")
    assert "the VM has no sudo" in done["vm_note"]


async def test_an_upload_to_a_gone_vm_says_so(store, world, tmp_path):
    await world.visit()
    world.standing_in.clear()
    real = world.agent.request
    calls = {"n": 0}

    async def vanishing(method, path, params=None, **kw):
        # Proxmox still has it for the guest-agent check, then not.
        if path == "/cluster/resources":
            calls["n"] += 1
            if calls["n"] > 1:
                world.agent.guests = [g for g in world.agent.guests if g["vmid"] != 123]
        return await real(method, path, params, **kw)

    world.agent.request = vanishing
    upload = _vm_upload(store, tmp_path / "app.sh")
    with pytest.raises(UploadRefused) as refused:
        await _vm_delivery(store, world)(upload)
    assert refused.value.code == "vm_gone"


async def test_cleanup_after_a_stop_removes_what_sftp_may_have_left(store, world, tmp_path):
    upload = _vm_upload(store, tmp_path / "app.sh")
    left = agent_temp_path(upload.id)
    with open(left, "w") as f:
        f.write("partial")
    try:
        await _vm_delivery(store, world).cleanup(upload)
        assert not os.path.exists(left)
    finally:
        if os.path.exists(left):
            os.unlink(left)
