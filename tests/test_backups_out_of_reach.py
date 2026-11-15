"""ADR-0027 verification 9: no MCP tool, and no client's token, reaches a backup.

A client's token opens nervus's MCP tools and the routes beside /mcp. The one place nervus hands a
backup out is the UI's backups page, the operator's, behind a sign-in no token is
(test_ui_backups.py: a download needs a session). Of the tools, only `put` and `get` name a file on
nervus's own machine, and only in the transfer folder; the routes name a file only by an id nervus
made. So a backup stays out of reach while:
- the backups folder and each folder a client's call can name hold none of each other, as installed;
- `put` and `get` refuse a backup however its path is spelled;
- no tool, parameter or route arrives without being looked at here.

A client may also hold an account on nervus's own machine, added from the UI: never at full
(test_host_enrollment_route.py), so never root, and the backups folder is nervus's alone
(test_backup.py: 0700, each backup 0600). Observed with a token that does not hold ADR-0009's full
level, which is root on nervus's machine and reaches every file there, as its decision 3 accepts and
as its exceptions say of the audit log's like verifications."""

import dataclasses
import os
from datetime import datetime, timezone

import pytest

from nervus import restore
from nervus.audit import AuditLog
from nervus.backup import backup_name
from nervus.database import Database
from nervus.exporter import Exporter
from nervus.exports import ExportStore
from nervus.host_enrollment import HostEnrollment
from nervus.proxmox import ProxmoxClient, ProxmoxConfig
from nervus.server import build_server
from nervus.uploader import Uploader
from nervus.uploads import UploadStore
from test_install_doc import _installed, _passing
from test_server import GOOD_TOKEN, _audit_records, _call_tool, _hypervisor_entry, _settings, _tokens

# Every tool a client's token can call, and its parameters. Of these, only put's and get's
# `local_path` names a file on nervus's own machine, inside the transfer folder; every other path is
# the machine's, the VM's or the Proxmox API's, and `export_id` names one of the client's own exports.
TOOLS = {
    "hosts": set(),
    "exec": {"host", "vmid", "command", "cwd", "timeout"},
    "exec_bg": {"host", "vmid", "command", "cwd"},
    "job": {"host", "vmid", "job_id", "action", "offset", "length", "tail"},
    "put": {"host", "vmid", "local_path", "remote_path"},
    "get": {"host", "vmid", "remote_path", "local_path"},
    "proxmox": {"method", "path", "params", "timeout"},
    "export": {"host", "vmid", "remote_path", "path", "request_key", "wait", "action", "export_id"},
}
# Every route on the same port. A file one serves or takes is named by an id nervus made (an export,
# an upload, a one-time secret or code), never by a path.
ROUTES = {"/mcp", "/uploads", "/uploads/{request_key}", "/upload-pull", "/enroll/{code}", "/exports/{export_id}"}


async def test_a_client_can_call_these_tools_and_routes_and_no_other(tmp_path, ssh_server, pki):
    """With every part configured. A new tool, parameter or route fails here until it is added
    above, with what of nervus's own machine it can name."""
    settings = _settings(tmp_path, ssh_server)
    settings = dataclasses.replace(settings, hosts={**settings.hosts, "hv": _hypervisor_entry()})
    audit = AuditLog(path=settings.audit_log_path)
    db = Database(tmp_path / "nervus.db")
    db.open()
    exports = ExportStore(db, tmp_path / "exports", free_bytes=lambda: 1 << 40)
    exports.open()
    uploads = UploadStore(db, tmp_path / "uploads", free_bytes=lambda: 1 << 40)
    uploads.open()
    server = build_server(
        settings=settings, tokens=_tokens(), audit=audit,
        proxmox=ProxmoxClient(ProxmoxConfig(host="localhost", port=8006, token_id="nervus@pve!nervus",
                                            ca_file=pki["ca"], secret="unused")),
        exporter=Exporter(exports, audit, connect=None, vm_api=None),
        uploader=Uploader(uploads, audit, deliver=None),
        enrollment=HostEnrollment(None, None, audit, key=lambda: "", connect=None, pin=lambda: None,
                                  own_machine_id=None, reserved=lambda: ()))
    assert {tool.name: set(tool.input_schema["properties"]) for tool in await server.list_tools()} == TOOLS
    assert {route.path for route in server.streamable_http_app().routes} == ROUTES


def test_as_installed_no_folder_a_client_names_holds_the_backups_folder_or_lies_in_it(tmp_path):
    """The transfer folder, and the exports and uploads stores, where the shipped unit and nervus's
    own defaults put them (test_install_doc.py reads them from there), against where nervus keeps its
    backups: neither is in the other, so no path in one is a path in the other."""
    service = _installed(tmp_path)
    backups = restore.backups_folder(service)
    for folder in _passing(service):
        assert backups != folder and folder not in backups.parents and backups not in folder.parents, folder


NAME = backup_name(datetime(2026, 11, 1, tzinfo=timezone.utc))
LOCKED = b"age-encryption.org/v1\n-> X25519 a backup, locked\n"
SPELLINGS = ["its path", "climbing out", "a link to it", "a link to its folder"]


class Machine:
    """nervus's transfer folder and backups folder, laid out under a test folder as the shipped unit
    lays them out, one backup in it, and two links in the transfer folder as if something had left
    them there."""

    def __init__(self, tmp_path):
        self.transfer = tmp_path / "opt" / "nervus" / "transfer"
        self.backups = tmp_path / "var" / "lib" / "nervus" / "backups"
        self.transfer.mkdir(parents=True)
        self.backups.mkdir(parents=True, mode=0o700)
        self.backup = self.backups / NAME
        self.backup.write_bytes(LOCKED)
        (self.transfer / "a-link").symlink_to(self.backup)
        (self.transfer / "a-folder-link").symlink_to(self.backups)

    def spelled(self, how):
        return {"its path": str(self.backup), "climbing out": os.path.relpath(self.backup, self.transfer),
                "a link to it": "a-link", "a link to its folder": f"a-folder-link/{NAME}"}[how]


def _server(tmp_path, ssh_server, machine):
    settings = dataclasses.replace(_settings(tmp_path, ssh_server), transfer_dir=machine.transfer)
    return build_server(settings=settings, tokens=_tokens(), audit=AuditLog(path=settings.audit_log_path)), settings


@pytest.mark.parametrize("how", SPELLINGS)
async def test_put_will_not_send_a_backup_anywhere(tmp_path, ssh_server, how):
    machine = Machine(tmp_path)
    server, settings = _server(tmp_path, ssh_server, machine)
    arrived = tmp_path / "on-the-machine"
    result = await _call_tool(server, GOOD_TOKEN, "put",
                              {"host": "testhost", "local_path": machine.spelled(how), "remote_path": str(arrived)})
    assert result.is_error and "transfer directory" in result.content[0].text
    assert not arrived.exists()
    assert [record["phase"] for record in _audit_records(settings)] == ["refused"]


@pytest.mark.parametrize("how", SPELLINGS)
async def test_get_will_not_write_over_a_backup_or_beside_it(tmp_path, ssh_server, how):
    machine = Machine(tmp_path)
    server, settings = _server(tmp_path, ssh_server, machine)
    on_the_machine = tmp_path / "on-the-machine"
    on_the_machine.write_bytes(b"not a backup")
    result = await _call_tool(server, GOOD_TOKEN, "get", {"host": "testhost", "remote_path": str(on_the_machine),
                                                          "local_path": machine.spelled(how)})
    assert result.is_error and "transfer directory" in result.content[0].text
    assert machine.backup.read_bytes() == LOCKED and os.listdir(machine.backups) == [NAME]
    assert [record["phase"] for record in _audit_records(settings)] == ["refused"]
