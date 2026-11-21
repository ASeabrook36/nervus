import os
import sqlite3
from pathlib import Path

import asyncssh
import pytest

from nervus import __main__ as main_module
from nervus.export_sources import VM_RESPONSE_BYTES
from nervus.__main__ import main, parse_args


def test_parse_args_defaults():
    args = parse_args([])
    assert args.hosts == "hosts.yaml"
    assert args.tokens == "secrets/tokens.yaml"
    assert args.bind_host == "127.0.0.1"
    assert args.bind_port == 8000
    assert args.ssh_port == 22


def test_parse_args_overrides():
    args = parse_args(
        ["--hosts", "h.yaml", "--tokens", "t.yaml", "--bind-host", "0.0.0.0", "--bind-port", "9000"]
    )
    assert args.hosts == "h.yaml"
    assert args.tokens == "t.yaml"
    assert args.bind_host == "0.0.0.0"
    assert args.bind_port == 9000


def test_parse_args_reads_env_defaults(monkeypatch):
    monkeypatch.setenv("NERVUS_BIND_PORT", "9999")
    args = parse_args([])
    assert args.bind_port == 9999


def test_the_database_and_the_ui_address_are_settings(monkeypatch):
    """ADR-0012 decisions 1 and 3. nervus-ctl reads both from the unit file."""
    monkeypatch.delenv("NERVUS_DATABASE")  # set by conftest, to keep tests' databases in tmp
    args = parse_args([])
    assert args.database == "nervus.db"
    assert args.ui_url == ""  # not given: nervus-ctl signin says to add it
    args = parse_args(["--database", "/var/lib/nervus/nervus.db", "--ui-url", "https://nervus.example:8443/"])
    assert args.database == "/var/lib/nervus/nervus.db"
    assert args.ui_url == "https://nervus.example:8443"  # one form, so links join cleanly


@pytest.mark.parametrize("good", ["https://nervus.example:8443", "https://192.0.2.7", "http://localhost:8443",
                                  "http://127.0.0.1:8443", "http://[::1]:8443", "https://nervus.example/ui"])
def test_a_ui_url_may_be(good):
    assert parse_args(["--ui-url", good]).ui_url == good


@pytest.mark.parametrize("bad", [
    "http://nervus.example:8443",       # plain HTTP off loopback (ADR-0011 B)
    "nervus.example:8443",              # no scheme
    "ftp://nervus.example",
    "https://",                         # no host
    "https://nervus.example:8443/?x=1",  # a query would end up inside every link
    "https://nervus.example#top",
    "https://user@nervus.example",
    "https://nervus.example:99999",
])
def test_a_ui_url_may_not_be(bad, capsys):
    with pytest.raises(SystemExit):
        parse_args([f"--ui-url={bad}"])
    assert "argument --ui-url" in capsys.readouterr().err


@pytest.mark.parametrize("good", ["http://nervus.example:8000/upload-pull", "https://192.0.2.7:8000/upload-pull"])
def test_an_upload_pull_url_may_be(good):
    assert parse_args(["--upload-pull-url", good]).upload_pull_url == good


@pytest.mark.parametrize("bad", [
    "http://nervus.example:8000",               # not the pull route
    "http://nervus.example:8000/uploads",
    "nervus.example:8000/upload-pull",          # no scheme
    "http://nervus.example:8000/upload-pull?x=1",
    "http://user@nervus.example/upload-pull",
])
def test_an_upload_pull_url_may_not_be(bad, capsys):
    with pytest.raises(SystemExit):
        parse_args([f"--upload-pull-url={bad}"])
    assert "argument --upload-pull-url" in capsys.readouterr().err


def _write_hosts(tmp_path, extra=""):
    path = tmp_path / "hosts.yaml"
    path.write_text(
        "hosts:\n"
        "  - name: node-a\n"
        "    address: node-a.home.example.net\n"
        "    os: Ubuntu\n"
        "    role: app host\n"
        "    agent_user: agent\n"
        "    status: not-onboarded\n" + extra
    )
    return path


def _write_tokens(tmp_path):
    path = tmp_path / "tokens.yaml"
    path.write_text(
        "tokens:\n"
        "  - token: sekret\n"
        "    id: t1\n"
        "    client: claude-code\n"
        "    project: p\n"
        "    hosts: [node-a]\n"
    )
    os.chmod(path, 0o600)
    return path


def _write_key(tmp_path):
    """A real key, the same one at every start in this folder: every start
    compares its fingerprint with the database's (ADR-0027 question 6)."""
    path = tmp_path / "key"
    if path.exists():
        return path
    path.write_bytes(asyncssh.generate_private_key("ssh-ed25519").export_private_key())
    os.chmod(path, 0o600)
    return path


def test_main_refuses_to_start_on_missing_hosts_file(tmp_path, capsys):
    tokens_path = _write_tokens(tmp_path)
    key_path = _write_key(tmp_path)

    rc = main(
        [
            "--hosts",
            str(tmp_path / "does-not-exist.yaml"),
            "--tokens",
            str(tokens_path),
            "--ssh-key",
            str(key_path),
        ]
    )

    assert rc == 1
    assert "not found" in capsys.readouterr().err


def test_main_refuses_to_start_on_group_readable_tokens_file(tmp_path, capsys):
    hosts_path = _write_hosts(tmp_path)
    tokens_path = _write_tokens(tmp_path)
    os.chmod(tokens_path, 0o640)
    key_path = _write_key(tmp_path)

    rc = main(
        ["--hosts", str(hosts_path), "--tokens", str(tokens_path), "--ssh-key", str(key_path)]
    )

    assert rc == 1
    assert "0600" in capsys.readouterr().err


def test_main_builds_and_runs_server_on_valid_config(tmp_path, monkeypatch):
    hosts_path = _write_hosts(tmp_path)
    tokens_path = _write_tokens(tmp_path)
    key_path = _write_key(tmp_path)

    calls = {}
    fake_server = object()

    def fake_build_server(*, settings, tokens, audit, proxmox=None, exporter=None, uploader=None, vms=None,
                          enrolled=None, enrollment=None, machine_accounts=None):
        calls["vms"] = vms
        calls["enrolled"] = enrolled
        calls["enrollment"] = enrollment
        calls["settings"] = settings
        calls["tokens"] = tokens
        calls["proxmox"] = proxmox
        calls["exporter"] = exporter
        calls["uploader"] = uploader
        return fake_server

    def fake_serve(listeners, background=()):
        calls["serve"] = [(l.name, l.host, l.port, l.certificate) for l in listeners]
        calls["background"] = list(background)

    monkeypatch.setattr(main_module, "build_server", fake_build_server)
    monkeypatch.setattr(main_module, "serve", fake_serve)
    real_build_ui = main_module.build_ui

    def capture_ui(*args, **kwargs):
        calls["machines"] = kwargs.get("machines")
        return real_build_ui(*args, **kwargs)

    monkeypatch.setattr(main_module, "build_ui", capture_ui)

    rc = main(
        [
            "--hosts",
            str(hosts_path),
            "--tokens",
            str(tokens_path),
            "--ssh-key",
            str(key_path),
            "--bind-host",
            "127.0.0.1",
            "--bind-port",
            "8123",
            "--ssh-port",
            "2222",
        ]
    )

    assert rc == 0
    assert calls["serve"] == [("MCP", "127.0.0.1", 8123, None), ("UI", "127.0.0.1", 8443, None)]
    assert "node-a" in calls["settings"].hosts
    assert calls["tokens"].get("sekret") is not None  # the file's, beside the database's (ADR-0014 C)
    # Exports are offered, kept beside the database, and swept hourly beside the
    # servers (ADR-0016 decision E). With no --proxmox, only from hosts.
    exporter = calls["exporter"]
    assert exporter is not None and not exporter.vms
    assert exporter.store.directory == Path(os.environ["NERVUS_DATABASE"]).parent / "exports"
    assert exporter.store.directory.is_dir()
    # Uploads too, beside them (ADR-0020 decision F): swept hourly, and what a
    # stop interrupted tidied at start. With no --proxmox and no pull address,
    # VM uploads are refused with that reason.
    uploader = calls["uploader"]
    assert uploader.store.directory == Path(os.environ["NERVUS_DATABASE"]).parent / "uploads"
    assert uploader.store.directory.is_dir()
    assert uploader.deliver.vm.api is None and uploader.deliver.vm.pull_url is None
    assert uploader.deliver.vm.pull_root is None  # plain HTTP: no root to hand a VM
    assert uploader.deliver.vm.vm_connect is None and exporter.vm_connect is None  # no --proxmox
    assert calls["background"][:2] == [exporter.sweep_forever, uploader.sweep_forever]
    assert len(calls["background"]) == 3
    # No --proxmox: the tool is not offered (ADR-0009 decision 2), and no VM
    # can be named by id (ADR-0022).
    assert calls["proxmox"] is None
    assert calls["vms"] is None
    # Machines enrolled from the UI, in the same database (ADR-0024 decision 3).
    assert calls["enrolled"].database.path == Path(os.environ["NERVUS_DATABASE"])
    # Enrolled with two lines on the machine (ADR-0024 step 3): into that
    # store, never under a hosts.yaml name; over plain HTTP, refused.
    enrollment = calls["enrollment"]
    assert enrollment.store is calls["enrolled"] and enrollment.codes.database.path == enrollment.store.database.path
    assert set(enrollment.reserved()) == set(calls["settings"].hosts) and enrollment.pin() is None
    # The UI's machines page makes codes for that route, naming MCP's port.
    machines = calls["machines"]
    assert machines.codes is enrollment.codes and machines.store is enrollment.store
    assert machines.port == 8123 and machines.pin() is None and machines.nervus_host == ""
    assert machines.by_hand == sorted(calls["settings"].hosts)
    # Added by an admin login given once (ADR-0026 step 4): the same codes and audit log, SSH on the port nervus's
    # other connections use, and the same lockdown switch the route reads.
    login = machines.login
    assert login is not None and login.codes is machines.codes and login.audit.path == enrollment.audit.path
    assert login.port == calls["settings"].ssh_port == 2222 and login.locked() == enrollment.locked()


def _write_proxmox(tmp_path, ca_file, mode=0o600):
    path = tmp_path / "proxmox.yaml"
    path.write_text(
        "url: https://hv.home.example.net:8006\n"
        "token_id: nervus@pve!nervus\n"
        "secret: 00000000-test-secret\n"
        f"ca_file: {ca_file}\n"
    )
    os.chmod(path, mode)
    return path


def test_main_refuses_to_start_on_a_readable_proxmox_file(tmp_path, capsys, pki):
    rc = main(
        [
            "--hosts", str(_write_hosts(tmp_path)),
            "--tokens", str(_write_tokens(tmp_path)),
            "--ssh-key", str(_write_key(tmp_path)),
            "--proxmox", str(_write_proxmox(tmp_path, pki["ca"], mode=0o644)),
        ]
    )

    assert rc == 1
    assert "0600" in capsys.readouterr().err


def test_main_passes_a_proxmox_client_when_configured(tmp_path, monkeypatch, pki):
    calls = {}

    def fake_build_server(*, settings, tokens, audit, proxmox=None, exporter=None, uploader=None, vms=None,
                          enrolled=None, enrollment=None, machine_accounts=None):
        calls["proxmox"] = proxmox
        calls["exporter"] = exporter
        calls["vms"] = vms
        return object()

    monkeypatch.setattr(main_module, "build_server", fake_build_server)
    monkeypatch.setattr(main_module, "serve", lambda *args, **kwargs: None)

    rc = main(
        [
            "--hosts", str(_write_hosts(tmp_path)),
            "--tokens", str(_write_tokens(tmp_path)),
            "--ssh-key", str(_write_key(tmp_path)),
            "--proxmox", str(_write_proxmox(tmp_path, pki["ca"])),
        ]
    )

    assert rc == 0
    assert calls["proxmox"].config.token_id == "nervus@pve!nervus"
    assert calls["proxmox"].config.host == "hv.home.example.net"
    # The proxmox tool keeps its 256 KiB limit; VM exports read with a client of
    # their own that takes a 1 MiB read's answer (ADR-0016, step 0).
    assert calls["proxmox"].max_response_bytes == 256 * 1024
    assert calls["exporter"].vms
    assert calls["exporter"].vm_api.max_response_bytes == VM_RESPONSE_BYTES
    assert calls["exporter"].vm_api.config == calls["proxmox"].config
    # VMs named by id go through the proxmox tool's client, and are given
    # nervus's own public key, from its private key (ADR-0022 3a).
    # The key is read when a VM is first enrolled, so a key nervus cannot read
    # does not stop it starting: this test's is not a key.
    vms = calls["vms"]
    assert vms.api is calls["proxmox"]
    assert vms.enroller.store is vms.store
    # Exports and uploads reach VMs over SFTP through the same (ADR-0022 7a).
    assert calls["exporter"].vm_connect == vms.connect
    # Enrolling writes nervus's CA, not its key (ADR-0025 decision 4).
    ca = CertificateAuthority(Path(os.environ["NERVUS_SSH_CA_KEY"]))
    assert vms.enroller.public_key() == ca.public_key()


def test_the_web_server_limits_how_long_a_stop_waits():
    # A real server from build_server, so the app is the one nervus serves.
    from nervus.audit import AuditLog
    from nervus.config import Settings
    from nervus.server import build_server

    settings = Settings(
        hosts={}, tokens_path=Path("t"), known_hosts_path=Path("k"), ssh_key_path=Path("s"),
        audit_log_path=Path("a"), transfer_dir=Path("x"), bind_host="127.0.0.1", bind_port=8123,
    )
    server = build_server(settings=settings, tokens={}, audit=AuditLog(path=Path("a")))
    config = main_module.uvicorn_config(server, "0.0.0.0", 8000)
    assert config.timeout_graceful_shutdown == main_module.SHUTDOWN_GRACE_SECONDS == 5
    assert (config.host, config.port) == ("0.0.0.0", 8000)


def test_a_connection_that_never_finishes_does_not_hold_up_a_stop(tmp_path):
    """The 2026-09-30 hang, reproduced: a request whose body never arrives.
    Before the limit nervus waited on it until killed; now it exits by itself."""
    import json, signal, socket, subprocess, sys, time, urllib.request

    port = 18000 + os.getpid() % 1000
    token = "t" * 43
    tokens = tmp_path / "tokens.yaml"
    tokens.write_text(f"tokens:\n  - token: {token}\n    id: t\n    client: c\n    project: p\n    hosts: [node-a]\n")
    key = _write_key(tmp_path)
    os.chmod(tokens, 0o600)
    proc = subprocess.Popen(
        [sys.executable, "-m", "nervus", "--hosts", str(_write_hosts(tmp_path)), "--tokens", str(tokens),
         "--ssh-key", str(key), "--audit-log", str(tmp_path / "audit.jsonl"), "--transfer-dir", str(tmp_path),
         "--bind-host", "127.0.0.1", "--bind-port", str(port), "--ui-port", str(port + 1)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        url = f"http://127.0.0.1:{port}/mcp"
        headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                   "Authorization": f"Bearer {token}"}
        for _ in range(100):
            try:
                urllib.request.urlopen(url, timeout=1)
            except urllib.error.HTTPError:
                break
            except OSError:
                time.sleep(0.1)
        init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}}
        r = urllib.request.urlopen(urllib.request.Request(url, method="POST", headers=headers,
                                                          data=json.dumps(init).encode()), timeout=10)
        sid = r.headers["mcp-session-id"]
        r.read()
        stuck = socket.create_connection(("127.0.0.1", port))
        stuck.sendall(
            (f"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n"
             f"Authorization: Bearer {token}\r\nmcp-session-id: {sid}\r\nContent-Length: 500\r\n\r\n"
             '{"jsonrpc":"2.0",').encode()
        )
        time.sleep(0.5)
        start = time.monotonic()
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=main_module.SHUTDOWN_GRACE_SECONDS + 10)
        assert time.monotonic() - start < main_module.SHUTDOWN_GRACE_SECONDS + 5
        stuck.close()
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


# --- TLS (ADR-0006 decision 6, ADR-0008 decision 9) ---------------------------
#
# Flag handling in-process; serving against a real nervus process, as the stop
# test above does. Certificates are made at run time in tmp_path (rule 7).

import datetime
import hashlib
import http.client
import json
import re
import signal
import socket
import ssl
import subprocess
import sys
import time

from nervus.certs import CertificateAuthority
from nervus.tls import ServingCertificate, certificate_fingerprint, fingerprint, generate_self_signed

FINGERPRINT = re.compile(r"public key SHA-256 ((?:[0-9A-F]{2}:){31}[0-9A-F]{2})")
ROOT_FINGERPRINT = re.compile(r"root certificate SHA-256 ((?:[0-9A-F]{2}:){31}[0-9A-F]{2})")
TOKEN = "t" * 43
INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}}
MCP_HEADERS = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}


@pytest.fixture
def secrets(tmp_path):
    d = tmp_path / "secrets"
    d.mkdir(mode=0o700)
    return d


@pytest.fixture
def no_serving(monkeypatch):
    """For starts that must be refused: if one is not, fail now rather than
    serve forever inside the test."""
    def refuse(*args):
        raise AssertionError("nervus started serving")
    monkeypatch.setattr(main_module, "serve", refuse)


def _tls_args(secrets):
    return ["--tls-cert", str(secrets / "tls.crt"), "--tls-key", str(secrets / "tls.key")]


def _init(secrets):
    """`nervus tls-init`, in-process: the one-time act that makes the pair."""
    assert main(["tls-init", *_tls_args(secrets)]) == 0


def _write_switches(tmp_path, text="lockdown: false\ndisabled: []\n"):
    """The off switch with nothing off, as a deployment creates it (ADR-0003, A)."""
    path = tmp_path / "switches.yaml"
    path.write_text(text)
    return path


def _config_args(tmp_path):
    return ["--hosts", str(_write_hosts(tmp_path)), "--tokens", str(_write_tokens(tmp_path)),
            "--ssh-key", str(_write_key(tmp_path)), "--switches", str(_write_switches(tmp_path))]


def _colons(digest: bytes) -> str:
    return digest.hex(":").upper()


def _key_fp(der: bytes) -> str:
    """Public-key SHA-256 of a DER certificate, as a pinning client computes it."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    spki = x509.load_der_x509_certificate(der).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return _colons(hashlib.sha256(spki).digest())


def test_tls_needs_both_files_or_neither(tmp_path, capsys, secrets, no_serving):
    rc = main([*_config_args(tmp_path), "--tls-cert", str(secrets / "tls.crt")])
    assert rc == 1
    assert "both --tls-cert and --tls-key" in capsys.readouterr().err


def test_tls_generate_is_gone():
    # ADR-0010 decision 4: a start flag that makes a key is withdrawn.
    with pytest.raises(SystemExit):
        parse_args(["--tls-generate"])


def test_a_start_never_makes_a_key_and_says_how(tmp_path, capsys, secrets, no_serving):
    rc = main([*_config_args(tmp_path), *_tls_args(secrets)])
    assert rc == 1
    err = capsys.readouterr().err
    assert "never makes its key when it starts" in err
    assert f"nervus tls-init --tls-cert {secrets / 'tls.crt'} --tls-key {secrets / 'tls.key'}" in err
    assert "paired again" in err
    assert list(secrets.iterdir()) == []


def test_a_start_with_half_a_pair_makes_nothing(tmp_path, capsys, secrets, no_serving):
    (secrets / "tls.key").write_text("an orphan")
    os.chmod(secrets / "tls.key", 0o600)
    rc = main([*_config_args(tmp_path), *_tls_args(secrets)])
    assert rc == 1
    assert "no TLS " + str(secrets / "tls.crt") in capsys.readouterr().err
    assert sorted(p.name for p in secrets.iterdir()) == ["tls.key"]
    assert (secrets / "tls.key").read_text() == "an orphan"


def test_tls_init_makes_the_pair_once(secrets, capsys):
    _init(secrets)
    made = capsys.readouterr().err
    assert FINGERPRINT.findall(made) == [fingerprint((secrets / "tls.crt").read_bytes())]
    before = {p.name: p.read_bytes() for p in secrets.iterdir()}
    assert sorted(before) == ["tls-issuer.crt", "tls-issuer.key", "tls-root.crt", "tls.crt", "tls.key"]  # ADR-0021: nervus's own authority, no root key
    root = ROOT_FINGERPRINT.findall(made)
    assert root == [certificate_fingerprint((secrets / "tls-root.crt").read_bytes())]

    assert main(["tls-init", *_tls_args(secrets)]) == 1
    assert "never replaces one" in capsys.readouterr().err
    assert {p.name: p.read_bytes() for p in secrets.iterdir()} == before


@pytest.mark.parametrize("existing", ["tls.crt", "tls.key"])
def test_tls_init_refuses_beside_half_a_pair(secrets, capsys, existing):
    (secrets / existing).write_text("an orphan")
    assert main(["tls-init", *_tls_args(secrets)]) == 1
    assert "refusing to replace" in capsys.readouterr().err
    assert sorted(p.name for p in secrets.iterdir()) == [existing]
    assert (secrets / existing).read_text() == "an orphan"


def _names(cert_path):
    """The DNS names and IP addresses a certificate is valid for."""
    from cryptography import x509

    san = x509.load_pem_x509_certificate(cert_path.read_bytes()).extensions.get_extension_for_class(
        x509.SubjectAlternativeName).value
    return san.get_values_for_type(x509.DNSName), [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]


def test_tls_init_adds_the_names_browsers_use(secrets, capsys):
    """ADR-0012 decision 7b: the name a browser goes to is in the certificate,
    so the browser warns only that nobody vouches for it, not about the name.
    ADR-0021 B1: never `localhost`, even when asked."""
    args = ["--name", "Nervus.Example", "--name", "192.0.2.9", "--name", "localhost"]
    assert main(["tls-init", *_tls_args(secrets), *args]) == 0
    dns, ips = _names(secrets / "tls.crt")
    assert "nervus.example" in dns and "localhost" not in dns
    assert "192.0.2.9" in ips and "127.0.0.1" in ips
    assert "nervus.example" in capsys.readouterr().err  # it says what it named


@pytest.mark.parametrize("bad", [
    "https://nervus.example", "nervus example", "", "-nervus.example", "nervus..example",
    "nervus.example.", "n\u00ebrvus.example", "a" * 64 + ".example", "*.example",
])
def test_tls_init_refuses_what_is_not_a_name(secrets, capsys, bad):
    """A name written wrong would match nothing, for as long as the key lasts."""
    with pytest.raises(SystemExit):
        main(["tls-init", *_tls_args(secrets), f"--name={bad}"])  # "=", so "-…" is not an option
    assert "argument --name" in (err := capsys.readouterr().err)
    assert "is not a DNS name or an IP address" in err
    assert list(secrets.iterdir()) == []


def test_tls_init_upgrade_keeps_the_key_and_prints_the_root(secrets, capsys):
    """ADR-0021 G1, from the command line: an install made before ADR-0021."""
    generate_self_signed(secrets / "tls.crt", secrets / "tls.key", ["localhost", "127.0.0.1", "host-a"])
    key_before = (secrets / "tls.key").read_bytes()
    fp = fingerprint((secrets / "tls.crt").read_bytes())
    assert main(["tls-init", "--upgrade", *_tls_args(secrets), "--name", "nervus.example"]) == 0
    err = capsys.readouterr().err
    assert (secrets / "tls.key").read_bytes() == key_before
    assert FINGERPRINT.findall(err) == [fp]
    assert ROOT_FINGERPRINT.findall(err) == [certificate_fingerprint((secrets / "tls-root.crt").read_bytes())]
    assert "upgraded" in err and "nervus.example" in err and "host-a" in err
    assert sorted(p.name for p in secrets.iterdir()) == [
        "tls-issuer.crt", "tls-issuer.key", "tls-root.crt", "tls.crt", "tls.key"]


def test_tls_init_upgrade_refuses_what_it_cannot_upgrade_and_says_why(secrets, capsys):
    assert main(["tls-init", "--upgrade", *_tls_args(secrets)]) == 1    # nothing there
    assert "nervus" in capsys.readouterr().err
    _init(secrets)
    before = {p.name: p.read_bytes() for p in secrets.iterdir()}
    capsys.readouterr()
    assert main(["tls-init", "--upgrade", *_tls_args(secrets)]) == 1    # already upgraded
    assert "refusing to replace" in capsys.readouterr().err
    assert {p.name: p.read_bytes() for p in secrets.iterdir()} == before


def test_tls_fingerprint_prints_what_tls_init_and_every_start_print(secrets, capsys):
    _init(secrets)
    made = FINGERPRINT.findall(capsys.readouterr().err)
    assert main(["tls-fingerprint", "--tls-key", str(secrets / "tls.key")]) == 0
    out = capsys.readouterr().out
    assert FINGERPRINT.findall(out) == made == [fingerprint((secrets / "tls.crt").read_bytes())]


def test_tls_fingerprint_prints_the_roots_beside_the_keys(secrets, capsys):
    """ADR-0021 E2: on nervus's machine, the reference a user compares
    tools/nervus-trust's value with, labelled apart from the key's."""
    _init(secrets)
    made = ROOT_FINGERPRINT.findall(capsys.readouterr().err)
    assert main(["tls-fingerprint", *_tls_args(secrets)]) == 0
    out = capsys.readouterr().out
    assert ROOT_FINGERPRINT.findall(out) == made == [
        certificate_fingerprint((secrets / "tls-root.crt").read_bytes())]
    assert FINGERPRINT.findall(out) == [fingerprint((secrets / "tls.crt").read_bytes())]
    assert f"{secrets / 'tls-root.crt'}: root certificate SHA-256" in out


def test_tls_fingerprint_of_an_install_without_a_root_prints_the_key_alone(secrets, capsys):
    generate_self_signed(secrets / "tls.crt", secrets / "tls.key", ["localhost"])
    assert main(["tls-fingerprint", *_tls_args(secrets)]) == 0
    out = capsys.readouterr().out
    assert len(FINGERPRINT.findall(out)) == 1 and ROOT_FINGERPRINT.findall(out) == []


def test_tls_fingerprint_without_a_key_says_so(tmp_path, capsys):
    assert main(["tls-fingerprint", "--tls-key", str(tmp_path / "absent.key")]) == 1
    assert "cannot read a private key" in capsys.readouterr().err


def test_tls_init_defaults_beside_the_other_secrets(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("NERVUS_TLS_CERT", raising=False)
    monkeypatch.delenv("NERVUS_TLS_KEY", raising=False)
    (tmp_path / "secrets").mkdir(mode=0o700)
    assert main(["tls-init"]) == 0
    assert sorted(p.name for p in (tmp_path / "secrets").iterdir()) == ["tls-issuer.crt", "tls-issuer.key", "tls-root.crt", "tls.crt", "tls.key"]


def test_main_serves_tls_with_the_certificate_and_prints_its_fingerprint(tmp_path, capsys, monkeypatch, secrets):
    calls = {}
    monkeypatch.setattr(main_module, "build_server", lambda **kw: calls.setdefault("built", kw) and "server")
    monkeypatch.setattr(main_module, "serve", lambda listeners, background=(): calls.setdefault("listeners", listeners))

    _init(secrets)
    capsys.readouterr()
    rc = main([*_config_args(tmp_path), *_tls_args(secrets), "--bind-port", "8123"])

    assert rc == 0
    mcp, ui = calls["listeners"]
    assert (mcp.name, mcp.host, mcp.port) == ("MCP", "127.0.0.1", 8123)
    assert mcp.certificate.cert_path == secrets / "tls.crt"
    assert ui.certificate is mcp.certificate  # one certificate, watched once
    certificate = mcp.certificate
    printed = FINGERPRINT.findall(capsys.readouterr().err)
    assert printed == [certificate.fingerprint]
    # A VM's pull is handed the root beside the certificate MCP serves (ADR-0022 8a).
    assert calls["built"]["uploader"].deliver.vm.pull_root == secrets / "tls-root.crt"


def _real_server():
    from nervus.audit import AuditLog
    from nervus.config import Settings
    from nervus.server import build_server

    settings = Settings(
        hosts={}, tokens_path=Path("t"), known_hosts_path=Path("k"), ssh_key_path=Path("s"),
        audit_log_path=Path("a"), transfer_dir=Path("x"), bind_host="127.0.0.1", bind_port=8123,
    )
    return build_server(settings=settings, tokens={}, audit=AuditLog(path=Path("a")))


def test_the_tls_web_server_serves_the_certificate_and_keeps_the_stop_limit(tmp_path):
    generate_self_signed(tmp_path / "c", tmp_path / "k", ["localhost"])
    certificate = ServingCertificate(tmp_path / "c", tmp_path / "k")
    certificate.load()
    config = main_module.uvicorn_config(_real_server(), "0.0.0.0", 8443, certificate)
    config.load()
    assert config.ssl is certificate.context
    assert config.timeout_graceful_shutdown == main_module.SHUTDOWN_GRACE_SECONDS == 5

    plain = main_module.uvicorn_config(_real_server(), "0.0.0.0", 8000)
    plain.load()
    assert plain.ssl is None


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _Nervus:
    """A real nervus process, as `python -m nervus` runs it, its console kept in a file."""

    def __init__(self, tmp_path, *args, umask=-1):
        tokens = tmp_path / "tokens.yaml"
        tokens.write_text(f"tokens:\n  - token: {TOKEN}\n    id: t\n    client: c\n    project: p\n    hosts: [node-a]\n")
        os.chmod(tokens, 0o600)
        self.port = _free_port()
        self.ui_port = _free_port()
        self.database = tmp_path / "nervus.db"
        self.switches = tmp_path / "switches.yaml"
        if not self.switches.exists():
            _write_switches(tmp_path)
        self.console = tmp_path / f"console-{self.port}.log"
        self.args = ["--hosts", str(_write_hosts(tmp_path)), "--tokens", str(tokens),
                     "--ssh-key", str(_write_key(tmp_path)), "--audit-log", str(tmp_path / "audit.jsonl"),
                     "--transfer-dir", str(tmp_path), "--bind-host", "127.0.0.1", "--bind-port", str(self.port),
                     "--switches", str(self.switches), "--ui-port", str(self.ui_port),
                     "--database", str(self.database), *args]
        with open(self.console, "wb") as out:
            self.proc = subprocess.Popen(
                [sys.executable, "-m", "nervus", *self.args],
                stdout=out, stderr=subprocess.STDOUT, umask=umask,
            )

    def wait_listening(self, timeout=20.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise AssertionError(f"nervus exited {self.proc.returncode}:\n{self.text()}")
            try:
                for port in (self.port, self.ui_port):  # MCP's and the UI's
                    socket.create_connection(("127.0.0.1", port), timeout=1).close()
                return
            except OSError:
                time.sleep(0.1)
        raise AssertionError(f"nervus not listening after {timeout} s:\n{self.text()}")

    def text(self) -> str:
        return self.console.read_text(errors="replace")

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()


def _trusting(cafile) -> ssl.SSLContext:
    """A client that trusts this one certificate and nothing else, verifying as
    strictly as Python 3.13 and later do by default."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile)
    context.verify_flags |= ssl.VERIFY_X509_STRICT
    return context


def _post(conn, message, headers):
    conn.request("POST", "/mcp", body=json.dumps(message), headers=headers)
    response = conn.getresponse()
    return response, response.read().decode()


def _jsonrpc(body: str) -> dict:
    # The body is the evidence, not the status (tools/nervus-status): nervus
    # refuses a token with HTTP 200 and a JSON-RPC error in an event stream.
    if body.lstrip().startswith("{"):
        return json.loads(body)
    data = [line[len("data: "):] for line in body.splitlines() if line.startswith("data: ")]
    return json.loads(data[-1])


def test_over_https_a_client_trusting_only_nervuss_own_certificate_gets_the_usual_refusal(tmp_path, secrets):
    _init(secrets)
    nervus = _Nervus(tmp_path, *_tls_args(secrets))
    try:
        nervus.wait_listening()
        conn = http.client.HTTPSConnection("127.0.0.1", nervus.port, context=_trusting(secrets / "tls.crt"), timeout=10)

        response, body = _post(conn, INIT, MCP_HEADERS)
        assert response.status == 200
        error = _jsonrpc(body)["error"]
        assert error["code"] == -32001
        assert error["message"].startswith("unauthorized")

        # The same connection with the token: TLS is all that changed.
        response, body = _post(conn, INIT, {**MCP_HEADERS, "Authorization": f"Bearer {TOKEN}"})
        assert "serverInfo" in _jsonrpc(body)["result"]
        conn.close()

        # Controls. A client that trusts another certificate refuses nervus's...
        other = tmp_path / "other"
        other.mkdir()
        generate_self_signed(other / "tls.crt", other / "tls.key", ["localhost"])
        stranger = http.client.HTTPSConnection("localhost", nervus.port, context=_trusting(other / "tls.crt"), timeout=10)
        with pytest.raises(ssl.SSLCertVerificationError):
            _post(stranger, INIT, MCP_HEADERS)
        # ...and plain HTTP to the same port gets no answer from MCP at all.
        plain = http.client.HTTPConnection("127.0.0.1", nervus.port, timeout=10)
        with pytest.raises((OSError, http.client.HTTPException)):
            _post(plain, INIT, MCP_HEADERS)
    finally:
        nervus.stop()


def test_the_console_shows_the_served_certificates_fingerprint_at_every_start(tmp_path, secrets):
    made = subprocess.run([sys.executable, "-m", "nervus", "tls-init", *_tls_args(secrets)],
                          capture_output=True, text=True, timeout=60)
    assert made.returncode == 0, made.stderr
    first = _Nervus(tmp_path, *_tls_args(secrets))
    try:
        first.wait_listening()
        printed = FINGERPRINT.findall(first.text())
        with _trusting(secrets / "tls.crt").wrap_socket(
            socket.create_connection(("127.0.0.1", first.port)), server_hostname="127.0.0.1"
        ) as s:
            served = s.getpeercert(binary_form=True)
    finally:
        first.stop()
    assert "made a" not in first.text()  # starting never makes a key
    assert printed == [_key_fp(served)] == FINGERPRINT.findall(made.stderr)
    on_disk = (secrets / "tls.crt").read_bytes()
    # The file is nervus's certificate with its chain after it (ADR-0021 E2); the
    # first is the one served. PEM_cert_to_DER_cert reads exactly one.
    first = on_disk.decode().split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n"
    assert printed == [_key_fp(ssl.PEM_cert_to_DER_cert(first))]

    # The second start prints the same.
    second = _Nervus(tmp_path, *_tls_args(secrets))
    try:
        second.wait_listening()
    finally:
        second.stop()
    assert FINGERPRINT.findall(second.text()) == printed
    assert (secrets / "tls.crt").read_bytes() == on_disk

    # And the command a user runs on the nervus machine prints it too.
    shown = subprocess.run([sys.executable, "-m", "nervus", "tls-fingerprint", "--tls-key",
                            str(secrets / "tls.key")], capture_output=True, text=True, timeout=60)
    assert FINGERPRINT.findall(shown.stdout) == printed


def test_the_key_and_certificate_tls_init_makes_are_0600_whatever_its_umask(secrets):
    made = subprocess.run([sys.executable, "-m", "nervus", "tls-init", *_tls_args(secrets)],
                          capture_output=True, text=True, timeout=60, umask=0)
    assert made.returncode == 0, made.stderr
    for name in ("tls.key", "tls.crt"):
        assert oct(os.stat(secrets / name).st_mode & 0o777) == oct(0o600), name


def test_with_tls_a_connection_that_never_finishes_does_not_hold_up_a_stop(tmp_path, secrets):
    """The 2026-09-30 hang over HTTPS: a request whose body never arrives, and
    beside it a connection that never even starts its TLS handshake."""
    _init(secrets)
    nervus = _Nervus(tmp_path, *_tls_args(secrets))
    try:
        nervus.wait_listening()
        client = _trusting(secrets / "tls.crt")
        conn = http.client.HTTPSConnection("127.0.0.1", nervus.port, context=client, timeout=10)
        response, _ = _post(conn, INIT, {**MCP_HEADERS, "Authorization": f"Bearer {TOKEN}"})
        sid = response.headers["mcp-session-id"]
        stuck = client.wrap_socket(socket.create_connection(("127.0.0.1", nervus.port)), server_hostname="127.0.0.1")
        stuck.sendall(
            (f"POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n"
             f"Authorization: Bearer {TOKEN}\r\nmcp-session-id: {sid}\r\nContent-Length: 500\r\n\r\n"
             '{"jsonrpc":"2.0",').encode()
        )
        silent = socket.create_connection(("127.0.0.1", nervus.port))
        time.sleep(0.5)
        start = time.monotonic()
        nervus.proc.send_signal(signal.SIGTERM)
        nervus.proc.wait(timeout=main_module.SHUTDOWN_GRACE_SECONDS + 10)
        assert time.monotonic() - start < main_module.SHUTDOWN_GRACE_SECONDS + 5
        # The stuck request really held the stop until the limit cut it off.
        assert "timeout graceful shutdown exceeded" in nervus.text()
        stuck.close()
        silent.close()
    finally:
        nervus.stop()


def test_a_replaced_certificate_is_served_to_new_connections_while_open_ones_continue(tmp_path, secrets):
    """ADR-0006 consequence 8: a renewal needs no restart. Replace the pair as
    certificate tools do, by renaming new files over the old."""
    from nervus.tls import WATCH_SECONDS, fingerprint

    _init(secrets)
    nervus = _Nervus(tmp_path, *_tls_args(secrets))
    try:
        nervus.wait_listening()
        old_pem = tmp_path / "old.crt"
        old_pem.write_bytes((secrets / "tls.crt").read_bytes())
        before = http.client.HTTPSConnection("127.0.0.1", nervus.port, context=_trusting(old_pem), timeout=10)
        _post(before, INIT, MCP_HEADERS)
        endpoint, old_der = before.sock.getsockname(), before.sock.getpeercert(binary_form=True)

        new = tmp_path / "renewal"
        new.mkdir()
        generate_self_signed(new / "tls.crt", new / "tls.key", ["localhost", "127.0.0.1"])
        os.replace(new / "tls.key", secrets / "tls.key")
        os.replace(new / "tls.crt", secrets / "tls.crt")
        new_fp = fingerprint((secrets / "tls.crt").read_bytes())

        # Wait for nervus to say so, keeping the first connection busy so that
        # it is not closed for idling meanwhile (uvicorn closes an idle one at 5 s).
        deadline = time.monotonic() + WATCH_SECONDS + 10
        while f"reloaded the TLS certificate {secrets / 'tls.crt'}: public key SHA-256 {new_fp}" not in nervus.text():
            assert time.monotonic() < deadline, nervus.text()
            _post(before, INIT, MCP_HEADERS)
            time.sleep(0.5)

        # New handshakes present the new certificate, by name and by address.
        for name in ("localhost", "127.0.0.1"):
            with _trusting(secrets / "tls.crt").wrap_socket(
                socket.create_connection(("127.0.0.1", nervus.port)), server_hostname=name
            ) as s:
                assert _key_fp(s.getpeercert(binary_form=True)) == new_fp
        with pytest.raises(ssl.SSLCertVerificationError):
            _post(http.client.HTTPSConnection("localhost", nervus.port, context=_trusting(old_pem), timeout=10),
                  INIT, MCP_HEADERS)

        # The connection opened before the reload carries on, on its certificate.
        response, body = _post(before, INIT, MCP_HEADERS)
        assert _jsonrpc(body)["error"]["code"] == -32001
        assert before.sock.getsockname() == endpoint  # the same connection, not a new one
        assert before.sock.getpeercert(binary_form=True) == old_der
        before.close()
    finally:
        nervus.stop()


def test_a_tls_start_that_cannot_bind_fails_as_a_plain_one_does(tmp_path, secrets):
    """uvicorn ends a start it cannot bind with exit status 3 and one line.
    With TLS that exit leaves through the certificate watch's task group, which
    must not turn it into a traceback and status 1."""
    tokens = tmp_path / "tokens.yaml"
    tokens.write_text(f"tokens:\n  - token: {TOKEN}\n    id: t\n    client: c\n    project: p\n    hosts: [node-a]\n")
    os.chmod(tokens, 0o600)
    with socket.socket() as taken:
        taken.bind(("127.0.0.1", 0))
        taken.listen()
        base = [sys.executable, "-m", "nervus", "--hosts", str(_write_hosts(tmp_path)), "--tokens", str(tokens),
                "--ssh-key", str(_write_key(tmp_path)), "--audit-log", str(tmp_path / "audit.jsonl"),
                "--transfer-dir", str(tmp_path), "--bind-port", str(taken.getsockname()[1]),
                "--ui-port", str(_free_port())]
        plain = subprocess.run(base, capture_output=True, text=True, timeout=60)
        _init(secrets)
        tls = subprocess.run(base + _tls_args(secrets), capture_output=True, text=True, timeout=60)
    assert plain.returncode == tls.returncode == 3
    assert "address already in use" in tls.stderr
    assert "Traceback" not in plain.stderr and "Traceback" not in tls.stderr


# --- off loopback, HTTPS unless told otherwise (ADR-0010 decision 1) ---------


@pytest.fixture
def served(monkeypatch):
    """Record which way main() would serve, without serving."""
    calls = {}
    monkeypatch.setattr(main_module, "build_server", lambda **kw: "server")
    monkeypatch.setattr(main_module, "serve",
                        lambda listeners, background=(): calls.update({l.name: l.certificate for l in listeners}))
    return calls


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "localhost"])
def test_on_loopback_with_no_certificate_nervus_serves_plain_http_without_a_warning(
        tmp_path, capsys, served, host):
    assert main([*_config_args(tmp_path), "--bind-host", host]) == 0
    assert served == {"MCP": None, "UI": None}
    assert "WARNING" not in capsys.readouterr().err


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.0.2.7", "nervus.example"])
def test_off_loopback_with_no_certificate_nervus_refuses_and_names_both_ways_out(
        tmp_path, monkeypatch, capsys, no_serving, host):
    monkeypatch.chdir(tmp_path)  # nervus's own pair would be ./secrets/tls.*
    assert main([*_config_args(tmp_path), "--bind-host", host]) == 1
    err = capsys.readouterr().err
    assert "nervus tls-init" in err and "--insecure-plain-http" in err
    assert not (tmp_path / "secrets").exists()


def test_off_loopback_nervus_serves_https_with_its_own_certificate(tmp_path, monkeypatch, served):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "secrets").mkdir(mode=0o700)
    assert main(["tls-init"]) == 0
    assert main([*_config_args(tmp_path), "--bind-host", "0.0.0.0"]) == 0
    assert served["MCP"].cert_path == Path(main_module.DEFAULT_TLS_CERT)
    assert served["UI"] is served["MCP"]


def test_off_loopback_nervus_serves_https_with_a_given_certificate(tmp_path, secrets, served):
    _init(secrets)
    assert main([*_config_args(tmp_path), *_tls_args(secrets), "--bind-host", "0.0.0.0"]) == 0
    assert served["MCP"].cert_path == secrets / "tls.crt"
    assert served["UI"] is served["MCP"]


def test_plain_http_off_loopback_needs_the_flag_and_warns(tmp_path, monkeypatch, capsys, served):
    monkeypatch.chdir(tmp_path)  # the UI's certificate is nervus's own, ./secrets/tls.*
    (tmp_path / "secrets").mkdir(mode=0o700)
    assert main(["tls-init"]) == 0
    capsys.readouterr()
    assert main([*_config_args(tmp_path), "--bind-host", "0.0.0.0", "--insecure-plain-http"]) == 0
    assert served["MCP"] is None
    assert served["UI"].cert_path == Path(main_module.DEFAULT_TLS_CERT)  # ADR-0011 question B
    err = capsys.readouterr().err
    assert ("serving the UI on 0.0.0.0:8443 over HTTPS with secrets/tls.crt: public key SHA-256 "
            f"{served['UI'].fingerprint}") in err
    assert "WARNING: serving plain HTTP on 0.0.0.0:8000, which is not loopback" in err
    assert "unencrypted" in err


def test_the_opt_out_and_a_certificate_contradict(tmp_path, capsys, secrets, no_serving):
    _init(secrets)
    capsys.readouterr()
    rc = main([*_config_args(tmp_path), *_tls_args(secrets), "--bind-host", "0.0.0.0",
               "--insecure-plain-http"])
    assert rc == 1
    assert "contradicts" in capsys.readouterr().err


REPO = Path(__file__).resolve().parent.parent
UNIT = REPO / "deploy" / "nervus.service"
# An installation's own flags are in a drop-in of its own; this one's is tested with
# the deployment record, in deployment/tests/ (ADR-0018's amendment).


def _unit_exec_start() -> list[str]:
    """nervus's arguments from the generic unit, read as nervus-ctl reads it."""
    from nervus.ctl import exec_start

    return exec_start(UNIT)[1:]


def test_the_generic_unit_is_secure_by_default_and_names_no_installation():
    """ADR-0019 and ADR-0007: with no drop-in, HTTPS everywhere, no Proxmox tool,
    no sign-in address, and nothing of any one installation in the file."""
    import re

    args = parse_args(_unit_exec_start())
    assert args.bind_host == "0.0.0.0" and not args.insecure_plain_http
    assert (args.proxmox, args.ui_url) == ("", "")
    # Nothing of an installation: no URL, and no address but the two every machine has.
    text = UNIT.read_text()
    assert not re.search(r"https?://", text)
    assert set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)) <= {"0.0.0.0", "127.0.0.1"}


def test_the_unit_names_every_path_and_its_state_directory():
    """ADR-0011 consequence 2 and ADR-0012 decision 3: under ProtectSystem=strict
    nervus can write only where the unit lets it; StateDirectory=nervus is
    /var/lib/nervus, made by systemd, nervus's, and writable."""
    unit = UNIT.read_text()
    assert "\nStateDirectory=nervus\n" in unit
    assert "\nStateDirectoryMode=0700\n" in unit
    args = parse_args(_unit_exec_start())
    assert args.switches == "/var/lib/nervus/switches.yaml"  # where nervus can write it (ADR-0014 A)
    assert Path(args.database).parent == Path("/var/lib/nervus")
    assert args.ui_port == 8443 != args.bind_port


def test_the_unit_needs_its_own_certificate_for_the_ui(tmp_path, monkeypatch):
    """ADR-0012 consequence 3: until `nervus tls-init` has run on the nervus machine,
    nervus refuses to start there, because the UI is never plain HTTP off
    loopback, so a deploy without it rolls back."""
    monkeypatch.chdir(tmp_path)  # no secrets/tls.* here
    args = parse_args(_unit_exec_start())
    with pytest.raises(main_module.ConfigError, match="even with --insecure-plain-http") as refused:
        main_module.ui_certificate(args, None)
    assert "nervus tls-init" in str(refused.value) and "--name" in str(refused.value)


def test_a_start_reissues_its_own_expiring_certificate_and_serves_it(tmp_path, secrets):
    """ADR-0010 decision 3, against a real process: 10 days left at start, so
    nervus re-issues for the same key before serving, and serves the new one.
    ADR-0021 D1: with secrets/ read-only to it, as the unit leaves it, the
    renewal goes beside the database, in the state directory."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    _init(secrets)
    issuer_key = serialization.load_pem_private_key((secrets / "tls-issuer.key").read_bytes(), None)
    _expire_in_ten_days(secrets / "tls.crt", issuer_key)
    before = (secrets / "tls.crt").read_bytes()
    fp = fingerprint(before)
    renewed = tmp_path / "tls" / "tls.crt"  # the real process's database is tmp_path/nervus.db
    secrets.chmod(0o500)
    try:
        nervus = _Nervus(tmp_path, *_tls_args(secrets))
        try:
            nervus.wait_listening()
            with _trusting(secrets / "tls-root.crt").wrap_socket(
                socket.create_connection(("127.0.0.1", nervus.port)), server_hostname="127.0.0.1"
            ) as s:
                served = s.getpeercert(binary_form=True)
        finally:
            nervus.stop()
    finally:
        secrets.chmod(0o700)
    assert f"re-issued the TLS certificate {renewed} for the same key: public key SHA-256 {fp}" in nervus.text()
    assert f"serving HTTPS with {renewed}" in nervus.text()
    assert (secrets / "tls.crt").read_bytes() == before
    assert _key_fp(served) == fp
    left = x509.load_der_x509_certificate(served).not_valid_after_utc - datetime.datetime.now(datetime.timezone.utc)
    assert left.days > 800


# --- SIGHUP checks now, and never stops nervus (ADR-0010 decision 5) ---------


def _sighup_and_wait_for(nervus, text, timeout=10.0):
    nervus.proc.send_signal(signal.SIGHUP)
    deadline = time.monotonic() + timeout
    while text not in nervus.text():
        assert nervus.proc.poll() is None, f"nervus exited {nervus.proc.returncode} on SIGHUP:\n{nervus.text()}"
        assert time.monotonic() < deadline, nervus.text()
        time.sleep(0.1)


def test_sighup_does_not_stop_plain_nervus(tmp_path):
    nervus = _Nervus(tmp_path)
    try:
        nervus.wait_listening()
        _sighup_and_wait_for(nervus, "on SIGHUP: serving plain HTTP, no certificate to check")
        time.sleep(0.5)
        assert nervus.proc.poll() is None
        socket.create_connection(("127.0.0.1", nervus.port), timeout=5).close()
    finally:
        nervus.stop()


def test_sighup_makes_tls_nervus_check_its_certificate_now(tmp_path, secrets):
    _init(secrets)
    nervus = _Nervus(tmp_path, *_tls_args(secrets))
    try:
        nervus.wait_listening()
        fp = fingerprint((secrets / "tls.crt").read_bytes())
        _sighup_and_wait_for(nervus, f"on SIGHUP: certificate files unchanged; serving public key SHA-256 {fp}")
        time.sleep(0.5)
        assert nervus.proc.poll() is None
        with _trusting(secrets / "tls.crt").wrap_socket(
            socket.create_connection(("127.0.0.1", nervus.port)), server_hostname="127.0.0.1"
        ) as s:
            assert _key_fp(s.getpeercert(binary_form=True)) == fp
    finally:
        nervus.stop()


def test_the_unit_reloads_by_sighup():
    unit = UNIT.read_text()
    assert "\nExecReload=/bin/kill -HUP $MAINPID\n" in unit


def _expire_in_ten_days(cert_path, issuer_key):
    """Replace nervus's certificate with the same one, 10 days from expiry,
    issued as nervus issues its own (ADR-0021 A1): by its issuer, with the
    issuer and root after it."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization

    current, *chain = x509.load_pem_x509_certificates(cert_path.read_bytes())
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(current.subject).issuer_name(current.issuer)
               .public_key(current.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(hours=1))
               .not_valid_after(now + datetime.timedelta(days=10)))
    for extension in current.extensions:
        builder = builder.add_extension(extension.value, extension.critical)
    staged = cert_path.with_name("expiring.crt")
    staged.write_bytes(b"".join(c.public_bytes(serialization.Encoding.PEM)
                                for c in [builder.sign(issuer_key, hashes.SHA256()), *chain]))
    staged.chmod(0o600)
    os.replace(staged, cert_path)


def test_a_reissue_while_running_reaches_the_next_handshake(tmp_path, secrets):
    """ADR-0010 verification 3, against a real process and without a restart:
    the certificate is swapped for a 10-day one on the same key, SIGHUP runs
    the check, nervus re-issues, and the next handshake presents the result."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization

    _init(secrets)
    fp = fingerprint((secrets / "tls.crt").read_bytes())
    nervus = _Nervus(tmp_path, *_tls_args(secrets))
    try:
        nervus.wait_listening()
        issuer_key = serialization.load_pem_private_key((secrets / "tls-issuer.key").read_bytes(), None)
        _expire_in_ten_days(secrets / "tls.crt", issuer_key)

        _sighup_and_wait_for(nervus, f"on SIGHUP: re-issued the TLS certificate {tmp_path / 'tls' / 'tls.crt'} for the same key")
        with _trusting(secrets / "tls-root.crt").wrap_socket(
            socket.create_connection(("127.0.0.1", nervus.port)), server_hostname="127.0.0.1"
        ) as s:
            served = s.getpeercert(binary_form=True)
    finally:
        nervus.stop()
    assert _key_fp(served) == fp
    left = x509.load_der_x509_certificate(served).not_valid_after_utc - datetime.datetime.now(datetime.timezone.utc)
    assert left.days > 800


# --- the off switch, against a real process (ADR-0003, ADR-0011 decision 2) ---


def test_a_client_switched_off_mid_session_is_refused_then_restored_without_a_restart(tmp_path):
    nervus = _Nervus(tmp_path)
    try:
        nervus.wait_listening()
        conn = http.client.HTTPConnection("127.0.0.1", nervus.port, timeout=10)
        auth = {**MCP_HEADERS, "Authorization": f"Bearer {TOKEN}"}
        response, body = _post(conn, INIT, auth)
        assert "result" in _jsonrpc(body)
        session = {**auth, "mcp-session-id": response.headers["mcp-session-id"]}
        _post(conn, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}, session)
        call = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "hosts", "arguments": {}}}
        pid = nervus.proc.pid

        _, body = _post(conn, call, session)
        assert "result" in _jsonrpc(body)

        nervus.switches.write_text("lockdown: false\ndisabled: [t]\n")
        _, body = _post(conn, call, session)
        error = _jsonrpc(body)["error"]
        assert (error["code"], error["message"]) == (-32001, "unauthorized: invalid or missing bearer token")

        nervus.switches.write_text("lockdown: false\ndisabled: []\n")
        _, body = _post(conn, call, session)
        assert "result" in _jsonrpc(body)
        assert nervus.proc.pid == pid and nervus.proc.poll() is None
    finally:
        nervus.stop()
    refused = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()
               if '"refused"' in line]
    assert [(r["tool"], r["name"], r["reason"]) for r in refused] == [("tools/call", "hosts", "switches: disabled")]


# --- the UI beside MCP, in one process (ADR-0012 decision 1) -----------------

import uvicorn  # noqa: E402

from nervus.database import Database  # noqa: E402
from nervus.first_run import FirstRun  # noqa: E402
from nervus.ui import SECURITY_HEADERS  # noqa: E402


def _request(port, path, method="GET", body=None, headers=None, tls=None):
    conn = (http.client.HTTPSConnection("127.0.0.1", port, context=tls, timeout=10) if tls
            else http.client.HTTPConnection("127.0.0.1", port, timeout=10))
    conn.request(method, path, body=body, headers=headers or {})
    response = conn.getresponse()
    return response, response.read().decode()


def test_nervus_serves_the_ui_beside_mcp(tmp_path):
    nervus = _Nervus(tmp_path)
    try:
        nervus.wait_listening()
        response, page = _request(nervus.ui_port, "/")
        assert response.status == 200 and "nervus-ctl signin" in page
        assert response.headers["content-security-policy"] == SECURITY_HEADERS["content-security-policy"]
        conn = http.client.HTTPConnection("127.0.0.1", nervus.port, timeout=10)
        assert "result" in _jsonrpc(_post(conn, INIT, {**MCP_HEADERS, "Authorization": f"Bearer {TOKEN}"})[1])
    finally:
        nervus.stop()
    assert f"serving the UI on 127.0.0.1:{nervus.ui_port} over plain HTTP, on loopback" in nervus.text()


def test_a_link_signs_a_browser_in_through_a_running_nervus_and_its_journal_never_holds_it(tmp_path):
    """End to end: the database nervus opened at start, a link made in it as
    nervus-ctl makes one, a browser's three requests, and the audit record.
    The UI keeps no access log, so the link's address never reaches the
    console, where MCP's requests do."""
    nervus = _Nervus(tmp_path)
    try:
        nervus.wait_listening()
        FirstRun(Database(nervus.database)).choose_tier(1, by="operator")  # setup done (ADR-0015 A)
        link, _ = Database(nervus.database).make_link()
        response, page = _request(nervus.ui_port, f"/signin?link={link}")
        assert response.status == 200 and "Sign in" in page
        response, _ = _request(nervus.ui_port, "/signin", method="POST", body=f"link={link}", headers={
            "Content-Type": "application/x-www-form-urlencoded", "Origin": f"http://127.0.0.1:{nervus.ui_port}"})
        assert response.status == 303
        cookie = response.headers["set-cookie"].split(";")[0]
        assert cookie.startswith("nervus-session=")  # plain HTTP, on loopback
        response, page = _request(nervus.ui_port, "/", headers={"Cookie": cookie})
        assert "Sign out" in page
        conn = http.client.HTTPConnection("127.0.0.1", nervus.port, timeout=10)
        _post(conn, INIT, {**MCP_HEADERS, "Authorization": f"Bearer {TOKEN}"})
    finally:
        nervus.stop()
    console = nervus.text()
    assert '"POST /mcp HTTP/1.1"' in console  # access logging is on, for MCP
    assert link not in console and "/signin" not in console
    records = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    assert [(r["tool"], r["action"]) for r in records if r.get("tool") == "ui"] == [("ui", "signin")]


def test_with_a_certificate_the_ui_serves_https_with_it_and_never_plain_http(tmp_path, secrets):
    """ADR-0011 verification 6: over HTTPS the UI presents the certificate
    whose fingerprint nervus prints at start, and it does not answer plain
    HTTP."""
    _init(secrets)
    nervus = _Nervus(tmp_path, *_tls_args(secrets))
    try:
        nervus.wait_listening()
        with _trusting(secrets / "tls.crt").wrap_socket(
            socket.create_connection(("127.0.0.1", nervus.ui_port)), server_hostname="127.0.0.1"
        ) as s:
            served = s.getpeercert(binary_form=True)
        response, page = _request(nervus.ui_port, "/", tls=_trusting(secrets / "tls.crt"))
        assert response.status == 200 and "nervus-ctl signin" in page
        with socket.create_connection(("127.0.0.1", nervus.ui_port), timeout=5) as plain:
            plain.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            try:
                reply = plain.recv(4096)
            except ConnectionResetError:
                reply = b""
        assert not reply.startswith(b"HTTP/")
    finally:
        nervus.stop()
    assert FINGERPRINT.findall(nervus.text()) == [_key_fp(served)]  # printed once, for both
    assert f"serving the UI on 127.0.0.1:{nervus.ui_port} over HTTPS, with the same certificate" in nervus.text()


def test_one_stop_ends_both_listeners_together_within_the_limit(tmp_path):
    """procedures/015's limit, with two servers: a stuck request on each, and
    one SIGTERM. Stopped one after the other, as uvicorn's own signal handling
    would, they would take twice the limit. nervus then exits with status 0."""
    nervus = _Nervus(tmp_path)
    try:
        nervus.wait_listening()
        conn = http.client.HTTPConnection("127.0.0.1", nervus.port, timeout=10)
        response, _ = _post(conn, INIT, {**MCP_HEADERS, "Authorization": f"Bearer {TOKEN}"})
        sid = response.headers["mcp-session-id"]
        stuck_mcp = socket.create_connection(("127.0.0.1", nervus.port))
        stuck_mcp.sendall(
            (f"POST /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n"
             f"Authorization: Bearer {TOKEN}\r\nmcp-session-id: {sid}\r\nContent-Length: 500\r\n\r\n"
             '{"jsonrpc":"2.0",').encode())
        stuck_ui = socket.create_connection(("127.0.0.1", nervus.ui_port))
        stuck_ui.sendall(b"POST /signin HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                         b"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 500\r\n\r\nlink=")
        time.sleep(0.5)
        start = time.monotonic()
        nervus.proc.send_signal(signal.SIGTERM)
        nervus.proc.wait(timeout=2 * main_module.SHUTDOWN_GRACE_SECONDS + 10)
        elapsed = time.monotonic() - start
        stuck_mcp.close()
        stuck_ui.close()
    finally:
        nervus.stop()
    assert elapsed < main_module.SHUTDOWN_GRACE_SECONDS + 3, elapsed
    assert nervus.proc.returncode == 0
    # uvicorn's line as each server cuts its stuck request off: both were held, and both cut off.
    assert nervus.text().count("running task(s), timeout graceful shutdown exceeded") == 2


def test_nervus_not_uvicorn_takes_the_stop_signals():
    """serve() owns SIGTERM and SIGINT for every server at once; uvicorn's
    servers must not take them for themselves while they run."""
    before = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
    server = main_module._Server(uvicorn.Config(app=lambda scope, receive, send: None))
    with server.capture_signals():
        assert {sig: signal.getsignal(sig) for sig in before} == before


def test_the_ui_port_is_its_own(tmp_path, capsys, no_serving):
    assert main([*_config_args(tmp_path), "--bind-port", "8123", "--ui-port", "8123"]) == 1
    assert "a port of its own" in capsys.readouterr().err
    assert not (tmp_path / "nervus.db").exists()


def test_a_start_makes_the_database_and_refuses_one_it_cannot_use(tmp_path, capsys, served):
    assert main(_config_args(tmp_path)) == 0
    made = tmp_path / "nervus.db"
    assert oct(made.stat().st_mode & 0o777) == oct(0o600)
    Database(made).make_link()  # one nervus can use
    bad = tmp_path / "bad.db"
    bad.write_bytes(b"not a database, and long enough for SQLite to look" * 4)
    assert main([*_config_args(tmp_path), "--database", str(bad)]) == 1
    assert "bad.db" in capsys.readouterr().err


def test_off_loopback_the_ui_needs_its_certificate_even_when_mcp_is_plain(tmp_path, monkeypatch, capsys,
                                                                           no_serving):
    """ADR-0011 question B: --insecure-plain-http names what MCP gives up; the
    UI never gives it up. A refused start makes no database."""
    monkeypatch.chdir(tmp_path)
    assert main([*_config_args(tmp_path), "--bind-host", "0.0.0.0", "--insecure-plain-http"]) == 1
    err = capsys.readouterr().err
    assert "even with --insecure-plain-http" in err and "nervus tls-init" in err
    assert not (tmp_path / "nervus.db").exists()


def test_switching_a_client_off_in_the_ui_refuses_its_next_call(tmp_path):
    """ADR-0014 verification 3, end to end: the clients page of a running
    nervus, signed in, switches a client off; the switch file nervus was
    started with says so, and that client's next MCP call is refused."""
    nervus = _Nervus(tmp_path)
    try:
        nervus.wait_listening()
        origin = {"Origin": f"http://127.0.0.1:{nervus.ui_port}"}
        form = {"Content-Type": "application/x-www-form-urlencoded", **origin}
        FirstRun(Database(nervus.database)).choose_tier(1, by="operator")  # setup done (ADR-0015 A)
        link, _ = Database(nervus.database).make_link()
        response, _ = _request(nervus.ui_port, "/signin", method="POST", body=f"link={link}", headers=form)
        cookie = {"Cookie": response.headers["set-cookie"].split(";")[0]}
        response, page = _request(nervus.ui_port, "/clients", headers=cookie)
        assert response.status == 200 and "<code>t</code>" in page and "token file" in page
        token = re.search(r'name="form_token" value="([^"]+)"', page).group(1)
        conn = http.client.HTTPConnection("127.0.0.1", nervus.port, timeout=10)
        auth = {**MCP_HEADERS, "Authorization": f"Bearer {TOKEN}"}
        assert "result" in _jsonrpc(_post(conn, INIT, auth)[1])
        response, _ = _request(nervus.ui_port, "/clients", method="POST",
                               body=f"form_token={token}&action=off&id=t", headers={**form, **cookie})
        assert response.status == 303
        assert "disabled:\n- t" in nervus.switches.read_text()
        assert _jsonrpc(_post(conn, INIT, auth)[1])["error"]["code"] == -32001
    finally:
        nervus.stop()


@pytest.mark.parametrize("extra, warned", [
    ("", True),
    ("  - name: hv\n    address: hv.example.net\n    os: test\n    role: test\n"
     "    agent_user: observer\n    status: onboarded\n    hypervisor: proxmox\n", False),
])
def test_main_warns_when_proxmox_is_set_but_no_entry_is_the_proxmox_host(tmp_path, monkeypatch, pki, capsys,
                                                                          extra, warned):
    """ADR-0019 decision D: not a refusal to start, but said at every start."""
    monkeypatch.setattr(main_module, "build_server", lambda **kwargs: object())
    monkeypatch.setattr(main_module, "serve", lambda *args, **kwargs: None)
    rc = main(["--hosts", str(_write_hosts(tmp_path, extra)), "--tokens", str(_write_tokens(tmp_path)),
               "--ssh-key", str(_write_key(tmp_path)), "--proxmox", str(_write_proxmox(tmp_path, pki["ca"]))])
    assert rc == 0
    assert ("no inventory entry is marked `hypervisor: proxmox`" in capsys.readouterr().err) is warned


def _start(tmp_path, monkeypatch):
    """Start nervus on loopback with the servers stood in for; what serve()
    was handed, or None if it was never reached."""
    served = {}
    monkeypatch.setattr(main_module, "serve", lambda listeners, background=(): served.setdefault("listeners", listeners))
    rc = main(["--hosts", str(_write_hosts(tmp_path)), "--tokens", str(_write_tokens(tmp_path)),
               "--ssh-key", str(_write_key(tmp_path)), "--bind-host", "127.0.0.1", "--bind-port", "8123"])
    return rc, served.get("listeners")


def test_every_start_logs_whether_nervus_listens_on_a_public_address(tmp_path, monkeypatch, capsys):
    # ADR-0007 decision 4, ADR-0015 decision D: at every start.
    rc, listeners = _start(tmp_path, monkeypatch)
    assert rc == 0 and listeners
    assert "nervus: listening on loopback only (127.0.0.1)" in capsys.readouterr().err


def test_a_public_address_is_warned_about_and_nervus_still_starts(tmp_path, monkeypatch, capsys):
    from nervus.exposure import Exposure
    import ipaddress
    checked = []
    public = Exposure("0.0.0.0", (ipaddress.ip_address("1.2.3.4"),))
    monkeypatch.setattr(main_module, "check_exposure", lambda host, declared: checked.append(host) or public)
    rc, listeners = _start(tmp_path, monkeypatch)
    assert checked == ["127.0.0.1"]
    assert rc == 0 and listeners  # warned about, never refused (ADR-0007 decision 4)
    assert "nervus: WARNING: nervus listens on 1.2.3.4, public in form" in capsys.readouterr().err


def test_the_ranges_declared_at_setup_reach_the_check(tmp_path, monkeypatch):
    # ADR-0015 decision C: a declaration turns the warning into a note.
    from nervus.first_run import FirstRun
    database = Database(Path(os.environ["NERVUS_DATABASE"]))
    database.open()
    FirstRun(database).declare("1.2.3.0/24", by="operator", now=1792497600.0)
    checked = []
    real = main_module.check_exposure
    monkeypatch.setattr(main_module, "check_exposure",
                        lambda host, declared: checked.append(list(declared)) or real(host, declared))
    rc, listeners = _start(tmp_path, monkeypatch)
    assert rc == 0 and listeners
    assert [[d.network for d in declared] for declared in checked] == [["1.2.3.0/24"]]


def test_ranges_that_cannot_be_read_are_said_and_nervus_still_starts(tmp_path, monkeypatch, capsys):
    from nervus.database import DatabaseUnusable
    from nervus.first_run import FirstRun

    def unreadable(self):
        raise DatabaseUnusable("the database is locked")

    monkeypatch.setattr(FirstRun, "declared", unreadable)
    checked = []
    real = main_module.check_exposure
    monkeypatch.setattr(main_module, "check_exposure",
                        lambda host, declared: checked.append(list(declared)) or real(host, declared))
    rc, listeners = _start(tmp_path, monkeypatch)
    assert rc == 0 and listeners
    assert checked == [[]]  # none applied: louder, never quieter
    assert "could not read the ranges declared internal, so none is applied: the database is locked" \
        in capsys.readouterr().err


def test_every_start_logs_the_tier_or_that_none_is_chosen(tmp_path, monkeypatch, capsys):
    # ADR-0015 decision E: the console line at every start.
    from nervus.first_run import FirstRun
    rc, _ = _start(tmp_path, monkeypatch)
    assert rc == 0
    assert "nervus: tier: not chosen yet; sign in to the web UI to choose it" in capsys.readouterr().err
    FirstRun(Database(Path(os.environ["NERVUS_DATABASE"]))).choose_tier(1, by="operator")
    rc, _ = _start(tmp_path, monkeypatch)
    assert "nervus: tier: Tier 1: a separate computer" in capsys.readouterr().err


def test_the_ui_is_given_setup_with_the_check_from_start(tmp_path, monkeypatch):
    seen = {}
    real_build_ui = main_module.build_ui
    monkeypatch.setattr(main_module, "build_ui", lambda *a, **k: seen.update(k) or real_build_ui(*a, **k))
    rc, _ = _start(tmp_path, monkeypatch)
    assert rc == 0
    setup = seen["setup"]
    assert setup.exposure.bind_host == "127.0.0.1" and setup.exposure.state == "loopback"
    assert setup.store.database.path == Path(os.environ["NERVUS_DATABASE"])


# --- who nervus is (ADR-0027 question 6, step 2) ------------------------------


def _who(tmp_path) -> tuple:
    with sqlite3.connect(os.environ["NERVUS_DATABASE"]) as db:
        return db.execute("SELECT ssh_key, ssh_ca_key, tls_issuer FROM identity").fetchone()


def test_a_start_records_who_nervus_is_and_the_next_with_the_same_keys_starts(tmp_path, monkeypatch):
    assert _start(tmp_path, monkeypatch)[0] == 0
    first = _who(tmp_path)
    assert first[0].startswith("SHA256:") and first[2] is None  # plain HTTP on loopback: no issuer
    assert _start(tmp_path, monkeypatch)[0] == 0
    assert _who(tmp_path) == first


def test_a_start_with_another_ca_key_is_refused_before_anything_is_served(tmp_path, monkeypatch, capsys):
    assert _start(tmp_path, monkeypatch)[0] == 0
    other = tmp_path / "other_ca"
    other.write_bytes(asyncssh.generate_private_key("ssh-ed25519").export_private_key())
    other.chmod(0o600)
    monkeypatch.setenv("NERVUS_SSH_CA_KEY", str(other))
    capsys.readouterr()
    assert _start(tmp_path, monkeypatch) == (1, None)
    assert "nervus's SSH certificate authority key" in capsys.readouterr().err


def test_a_start_with_no_database_where_nervus_has_run_is_refused_and_makes_none(tmp_path, monkeypatch, capsys):
    assert _start(tmp_path, monkeypatch)[0] == 0
    database = Path(os.environ["NERVUS_DATABASE"])
    for path in database.parent.glob(database.name + "*"):
        path.unlink()
    capsys.readouterr()
    assert _start(tmp_path, monkeypatch) == (1, None)
    assert "nervus has run here before and its database is gone" in capsys.readouterr().err
    assert not database.exists()


def test_a_start_with_nervuss_own_tls_records_its_issuer(tmp_path, monkeypatch, secrets):
    monkeypatch.setattr(main_module, "build_server", lambda **kw: "server")
    monkeypatch.setattr(main_module, "serve", lambda listeners, background=(): None)
    _init(secrets)
    assert main([*_config_args(tmp_path), *_tls_args(secrets), "--bind-port", "8123"]) == 0
    assert _who(tmp_path)[2] is not None
    (secrets / "tls-issuer.key").unlink()
    assert main([*_config_args(tmp_path), *_tls_args(secrets), "--bind-port", "8123"]) == 1


@pytest.mark.parametrize("argv, expected", [
    ([], None),  # loopback, plain HTTP
    (["--bind-host", "0.0.0.0"], "secrets/tls.key"),  # nervus's own
    (["--bind-host", "0.0.0.0", "--insecure-plain-http"], "secrets/tls.key"),  # the UI keeps HTTPS
    (["--insecure-plain-http"], None),
    (["--tls-cert", "a.crt", "--tls-key", "a.key"], "a.key"),  # given
])
def test_the_key_nervus_serves_with_is_named_as_tls_certificate_chooses_it(argv, expected):
    """nervus-ctl reads nervus's issuer beside this key (ADR-0027 step 3), so it
    must be the one main() serves with."""
    assert main_module.served_key(parse_args(argv)) == expected


def test_nervus_gives_its_ui_the_backups_beside_its_database(tmp_path, monkeypatch):
    """ADR-0027 step 5: the backups page reads the folder nervus-ctl writes,
    and its button locks to the recovery key the unit names."""
    given = {}
    real = main_module.build_ui
    monkeypatch.setattr(main_module, "build_ui", lambda *a, **kw: given.update(kw) or real(*a, **kw))
    assert _start(tmp_path, monkeypatch)[0] == 0
    backups = given["backups"]
    assert backups.folder == Path(os.environ["NERVUS_DATABASE"]).parent / "backups"
    assert backups.recovery_key == Path.cwd() / "secrets" / "recovery.pub"
