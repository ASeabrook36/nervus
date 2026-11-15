"""Tests for nervus.proxmox against a real local HTTPS server (conftest's
`hv` and `impostor`).

Like conftest's real SSH server, the point is to exercise the real thing:
TLS verification is only tested by a handshake that can fail. Each test
server gets a certificate from a throwaway CA made with the openssl CLI; a
second, unrelated CA stands in for anyone who is not hv.
"""

from __future__ import annotations

import json
import shutil
import ssl
from pathlib import Path

import pytest

from nervus.config import ConfigError
from nervus.proxmox import (
    ProxmoxClient,
    ProxmoxConfig,
    ProxmoxError,
    api_path,
    check_request,
    encode_params,
    load_config,
)

SECRET = "00000000-test-secret-0000-000000000000"
TOKEN_ID = "nervus@pve!nervus"


def _client(pki, port: int, host: str = "localhost", **kw) -> ProxmoxClient:
    cfg = ProxmoxConfig(host=host, port=port, token_id=TOKEN_ID, ca_file=pki["ca"], secret=SECRET)
    return ProxmoxClient(cfg, **kw)


# --- configuration ----------------------------------------------------------


def _write_config(d: Path, ca: Path, **overrides) -> Path:
    fields = {"url": "https://hv.home.example.net:8006", "token_id": TOKEN_ID,
              "secret": SECRET, "ca_file": str(ca), **overrides}
    p = d / "proxmox.yaml"
    p.write_text("".join(f"{k}: {json.dumps(v)}\n" for k, v in fields.items()))
    p.chmod(0o600)
    return p


def test_load_config_reads_a_good_file(tmp_path, pki):
    cfg = load_config(_write_config(tmp_path, pki["ca"]))
    assert (cfg.host, cfg.port, cfg.token_id, cfg.ca_file) == (
        "hv.home.example.net", 8006, TOKEN_ID, pki["ca"])
    assert cfg.secret == SECRET


def test_load_config_defaults_port_and_resolves_a_relative_ca(tmp_path, pki):
    shutil.copy(pki["ca"], tmp_path / "pve-root-ca.pem")
    cfg = load_config(_write_config(tmp_path, Path("pve-root-ca.pem"), url="https://hv"))
    assert cfg.port == 8006
    assert cfg.ca_file == tmp_path / "pve-root-ca.pem"


def test_config_repr_never_shows_the_secret(tmp_path, pki):
    cfg = load_config(_write_config(tmp_path, pki["ca"]))
    assert SECRET not in repr(cfg)


def test_load_config_refuses_a_readable_file(tmp_path, pki):
    p = _write_config(tmp_path, pki["ca"])
    p.chmod(0o644)
    with pytest.raises(ConfigError, match="0600"):
        load_config(p)


@pytest.mark.parametrize(
    "overrides, match",
    [
        ({"url": "http://hv:8006"}, "https"),
        ({"url": "https://hv:8006/api2/json"}, "only https"),
        ({"token_id": "nervus@pve"}, "user@realm!name"),
        ({"token_id": "nervus!token"}, "user@realm!name"),
        ({"secret": ""}, "missing"),
        ({"ca_file": "/nonexistent/ca.pem"}, "not found"),
    ],
)
def test_load_config_refuses_bad_values(tmp_path, pki, overrides, match):
    with pytest.raises(ConfigError, match=match):
        load_config(_write_config(tmp_path, pki["ca"], **overrides))


def test_a_ca_file_that_is_not_a_certificate_is_refused(tmp_path):
    bad = tmp_path / "bad.pem"
    bad.write_text("not a certificate\n")
    cfg = ProxmoxConfig(host="hv", port=8006, token_id=TOKEN_ID, ca_file=bad, secret=SECRET)
    with pytest.raises(ConfigError, match="not a usable certificate"):
        ProxmoxClient(cfg)


# --- paths and parameters ---------------------------------------------------


@pytest.mark.parametrize(
    "path, target",
    [
        ("/", "/api2/json/"),
        ("/version", "/api2/json/version"),
        ("/nodes/hv/qemu/", "/api2/json/nodes/hv/qemu"),
        ("/access/users/nervus@pve/token/t1", "/api2/json/access/users/nervus@pve/token/t1"),
        ("/nodes/hv/tasks/UPID:hv:0001:0002:0003:qmstart:100:nervus@pve!t:/status",
         "/api2/json/nodes/hv/tasks/UPID:hv:0001:0002:0003:qmstart:100:nervus@pve!t:/status"),
        ("/storage/a b", "/api2/json/storage/a%20b"),
        ("/storage/100%", "/api2/json/storage/100%25"),
    ],
)
def test_api_path_encodes_what_it_checked(path, target):
    assert api_path(path) == target


@pytest.mark.parametrize(
    "path",
    ["version", "/../../pve2/ext6/pvemanagerlib.js", "/nodes/../access", "/nodes/./hv",
     "/nodes//hv", "/version?x=1", "/version#frag", "/nodes\\hv", "/nodes/\nprox"],
)
def test_api_path_refuses_escapes(path):
    with pytest.raises(ProxmoxError):
        api_path(path)


def test_a_list_of_strings_is_the_key_repeated():
    """How Proxmox takes an array: the guest agent's command and its arguments."""
    assert encode_params({"command": ["sh", "-c", "a b", "sh", "/tmp/x y"]}) == (
        "command=sh&command=-c&command=a+b&command=sh&command=%2Ftmp%2Fx+y"
    )


@pytest.mark.parametrize("value", [[], [1, 2], ["a", {"b": 1}], [["a"]]])
def test_other_lists_are_refused(value):
    with pytest.raises(ProxmoxError):
        encode_params({"command": value})


def test_encode_params():
    assert encode_params({"vmid": 105, "start": True, "force": False, "name": "a b"}) == (
        "vmid=105&start=1&force=0&name=a+b")
    assert encode_params(None) == ""
    with pytest.raises(ProxmoxError, match="'net0'"):
        encode_params({"net0": {"bridge": "vmbr0"}})


# --- requests against the fake API ------------------------------------------


async def test_get_sends_the_token_and_query(pki, fake_api):
    resp = await _client(pki, fake_api.port).request("GET", "/nodes/hv/qemu", {"full": True})
    assert (resp.status, resp.data) == (200, {"echo": "/api2/json/nodes/hv/qemu"})
    [req] = fake_api.requests
    assert req["method"] == "GET"
    assert req["path"] == "/api2/json/nodes/hv/qemu?full=1"
    assert req["authorization"] == f"PVEAPIToken={TOKEN_ID}={SECRET}"
    assert req["body"] == ""


async def test_post_sends_a_form_body(pki, fake_api):
    await _client(pki, fake_api.port).request(
        "post", "/nodes/hv/qemu/105/snapshot", {"snapname": "before", "vmstate": False})
    [req] = fake_api.requests
    assert (req["method"], req["path"]) == ("POST", "/api2/json/nodes/hv/qemu/105/snapshot")
    assert req["content_type"] == "application/x-www-form-urlencoded"
    assert req["body"] == "snapname=before&vmstate=0"


async def test_a_permission_refusal_is_a_response_with_its_reason(pki, fake_api):
    resp = await _client(pki, fake_api.port).request("GET", "/denied")
    assert resp.status == 403
    assert resp.reason == "Permission check failed (/vms/123, VM.Audit)"
    assert resp.data is None


async def test_parameter_errors_are_returned(pki, fake_api):
    resp = await _client(pki, fake_api.port).request("POST", "/invalid", {"vmid": 1})
    assert resp.status == 400
    assert resp.errors == {"vmid": "value must be >= 100"}


async def test_a_body_that_is_not_json_comes_back_as_text(pki, fake_api):
    resp = await _client(pki, fake_api.port).request("GET", "/text")
    assert (resp.status, resp.data, resp.text) == (500, None, "<html>not json</html>")


async def test_an_oversized_response_is_refused_not_truncated(pki, fake_api):
    size = len('{"data":"') + 2000 + len('"}')  # 2011 bytes
    with pytest.raises(ProxmoxError, match=f"larger than {size - 1} bytes"):
        await _client(pki, fake_api.port, max_response_bytes=size - 1).request("GET", "/big")
    resp = await _client(pki, fake_api.port, max_response_bytes=size).request("GET", "/big")
    assert resp.body_bytes == size and len(resp.data) == 2000


async def test_a_bad_method_or_path_never_opens_a_connection(pki, fake_api):
    client = _client(pki, fake_api.port)
    with pytest.raises(ProxmoxError, match="method"):
        await client.request("PATCH", "/version")
    with pytest.raises(ProxmoxError, match="segments"):
        await client.request("GET", "/nodes/../access")
    assert fake_api.requests == []


# --- the pin ----------------------------------------------------------------


def test_the_context_trusts_the_pinned_ca_and_nothing_else(pki):
    # A handshake test cannot catch the system trust store being added
    # alongside the pin (the throwaway rogue CA is in no system store), so
    # check the store itself: exactly one CA, and it is the pinned one.
    ctx = _client(pki, 8006)._ctx
    assert ctx.cert_store_stats()["x509_ca"] == 1
    [ca] = ctx.get_ca_certs(binary_form=True)
    assert ca == ssl.PEM_cert_to_DER_cert(pki["ca"].read_text())
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname


async def test_a_server_from_another_ca_is_refused_before_the_token_is_sent(pki, impostor):
    with pytest.raises(ProxmoxError, match="not trusted by the pinned CA") as exc:
        await _client(pki, impostor.port).request("GET", "/version")
    assert SECRET not in str(exc.value)
    assert impostor.requests == []


async def test_a_certificate_for_another_name_is_refused(pki, fake_api):
    # The certificate names only "localhost"; connecting as 127.0.0.1 must fail.
    with pytest.raises(ProxmoxError, match="not trusted by the pinned CA"):
        await _client(pki, fake_api.port, host="127.0.0.1").request("GET", "/version")
    assert fake_api.requests == []


async def test_an_unreachable_api_is_an_error_without_the_secret(pki):
    # Port 1 on localhost: nothing listens, so the connection is refused.
    with pytest.raises(ProxmoxError, match="could not complete") as exc:
        await _client(pki, 1).request("GET", "/version", timeout=2)
    assert SECRET not in str(exc.value)


@pytest.mark.parametrize("path", [
    "/nodes/hv/stopall", "/nodes/hv/startall", "/nodes/hv/suspendall", "/nodes/hv/migrateall",
    "/nodes/hv/stopall/",
])
def test_whole_node_bulk_actions_are_refused(path):
    # These check the privilege on the node, then act on every guest with no per-guest
    # check, so the NoAccess on nervus's own container does not stop them. nervus never
    # acts on all guests at once (procedure 056, finding 4).
    with pytest.raises(ProxmoxError):
        check_request("POST", path, None)


def test_a_specific_guest_action_is_still_allowed():
    assert check_request("POST", "/nodes/hv/qemu/100/status/stop", None) == "POST"
