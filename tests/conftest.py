import asyncio
import contextlib
import json
import shutil
import ssl
import subprocess
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import asyncssh
import pytest
from sshd_shell import _handle_process


@dataclass
class SSHServerFixture:
    host: str
    port: int
    client_key_path: str
    known_hosts_path: str
    username: str


@pytest.fixture
async def ssh_server(tmp_path):
    """A real local SSH server, authenticating exactly one generated keypair,
    that executes commands with a real subprocess shell.
    """
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    client_key = asyncssh.generate_private_key("ssh-ed25519")

    client_key_path = tmp_path / "client_ed25519"
    client_key_path.write_bytes(client_key.export_private_key())
    client_key_path.chmod(0o600)

    authorized_keys_path = tmp_path / "authorized_keys"
    authorized_keys_path.write_bytes(client_key.export_public_key())

    server = await asyncssh.listen(
        "127.0.0.1",
        0,
        server_host_keys=[host_key],
        authorized_client_keys=str(authorized_keys_path),
        process_factory=_handle_process,
        sftp_factory=True,
    )

    port = server.sockets[0].getsockname()[1]

    known_hosts_path = tmp_path / "known_hosts"
    known_hosts_path.write_text(
        f"[127.0.0.1]:{port} {host_key.export_public_key().decode().strip()}\n"
    )

    try:
        yield SSHServerFixture(
            host="127.0.0.1",
            port=port,
            client_key_path=str(client_key_path),
            known_hosts_path=str(known_hosts_path),
            username="testuser",
        )
    finally:
        server.close()
        await server.wait_closed()


@pytest.fixture
async def ca_ssh_server(tmp_path):
    """As ssh_server, and trusting a certificate authority of its own as well,
    as a machine enrolled since ADR-0025 trusts nervus's: a read-only call,
    which offers only a certificate (ADR-0031), can log in to it. `ca_path`
    is the authority's private key."""
    from types import SimpleNamespace
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    client_key = asyncssh.generate_private_key("ssh-ed25519")
    ca_key = asyncssh.generate_private_key("ssh-ed25519")
    folder = tmp_path / "ca-ssh-server"
    folder.mkdir()
    client_key_path, ca_path = folder / "client_ed25519", folder / "ca_ed25519"
    for path, key in ((client_key_path, client_key), (ca_path, ca_key)):
        path.write_bytes(key.export_private_key())
        path.chmod(0o600)
    authorized = folder / "authorized_keys"
    authorized.write_text(client_key.export_public_key().decode().strip() + "\n"
                          + "cert-authority " + ca_key.export_public_key().decode().strip() + "\n")
    server = await asyncssh.listen("127.0.0.1", 0, server_host_keys=[host_key],
                                   authorized_client_keys=str(authorized), process_factory=_handle_process,
                                   sftp_factory=True)
    port = server.sockets[0].getsockname()[1]
    known = folder / "known_hosts"
    known.write_text(f"[127.0.0.1]:{port} {host_key.export_public_key().decode().strip()}\n")
    try:
        yield SimpleNamespace(host="127.0.0.1", port=port, client_key_path=str(client_key_path),
                              known_hosts_path=str(known), username="testuser", ca_path=ca_path)
    finally:
        server.close()
        await server.wait_closed()


# A fake Proxmox API over real TLS, for tests/test_proxmox.py and the
# proxmox tool in tests/test_server.py.


# --- certificates -----------------------------------------------------------


def _openssl(*args: str, cwd: Path) -> None:
    subprocess.run(["openssl", *args], cwd=cwd, check=True, capture_output=True)


def _make_ca(d: Path, name: str) -> tuple[Path, Path]:
    key, pem = d / f"{name}.key", d / f"{name}.pem"
    _openssl(
        "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
        "-keyout", key.name, "-out", pem.name, "-days", "2", "-subj", f"/CN={name}",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        cwd=d,
    )
    return key, pem


def _make_leaf(d: Path, name: str, ca: tuple[Path, Path], dns: str) -> tuple[Path, Path]:
    key, csr, pem, ext = (d / f"{name}{s}" for s in (".key", ".csr", ".pem", ".ext"))
    ext.write_text(
        f"subjectAltName=DNS:{dns}\nbasicConstraints=CA:FALSE\n"
        "keyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n"
    )
    _openssl(
        "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
        "-keyout", key.name, "-out", csr.name, "-subj", f"/CN={dns}", cwd=d,
    )
    _openssl(
        "x509", "-req", "-in", csr.name, "-CA", ca[1].name, "-CAkey", ca[0].name,
        "-CAcreateserial", "-out", pem.name, "-days", "2", "-extfile", ext.name, cwd=d,
    )
    return key, pem


@pytest.fixture(scope="session")
def pki(tmp_path_factory) -> dict[str, Path]:
    """Two throwaway CAs: one stands in for the Proxmox host's own, the other for anyone else."""
    if shutil.which("openssl") is None:
        pytest.skip("needs the openssl CLI")
    d = tmp_path_factory.mktemp("pki")
    pve_ca = _make_ca(d, "pve-ca")
    rogue_ca = _make_ca(d, "rogue-ca")
    good = _make_leaf(d, "good", pve_ca, "localhost")
    rogue = _make_leaf(d, "rogue", rogue_ca, "localhost")
    return {
        "ca": pve_ca[1],
        "good_key": good[0], "good_cert": good[1],
        "rogue_key": rogue[0], "rogue_cert": rogue[1],
    }


# --- a fake Proxmox API -----------------------------------------------------


@dataclass
class FakeAPI:
    port: int
    requests: list[dict] = field(default_factory=list)


def _handler(api: FakeAPI):
    class Handler(BaseHTTPRequestHandler):
        def _serve(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            api.requests.append(
                {
                    "method": self.command,
                    "path": self.path,
                    "authorization": self.headers.get("Authorization"),
                    "content_type": self.headers.get("Content-Type"),
                    "body": self.rfile.read(length).decode() if length else "",
                }
            )
            route = self.path.split("?")[0]
            if route == "/api2/json/denied":
                self._reply(403, b'{"data":null}', "Permission check failed (/vms/123, VM.Audit)")
            elif route == "/api2/json/invalid":
                self._reply(400, b'{"data":null,"errors":{"vmid":"value must be >= 100"}}',
                            "Parameter verification failed.")
            elif route == "/api2/json/big":
                self._reply(200, b'{"data":"' + b"x" * 2000 + b'"}')
            elif route == "/api2/json/text":
                self._reply(500, b"<html>not json</html>")
            else:
                self._reply(200, json.dumps({"data": {"echo": route}}).encode())

        def _reply(self, status: int, body: bytes, reason: str | None = None) -> None:
            self.send_response(status, reason)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST = do_PUT = do_DELETE = _serve

        def log_message(self, *args) -> None:
            pass

    return Handler


def _serve(key: Path, cert: Path):
    api = FakeAPI(port=0)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(api))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    api.port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, api


@pytest.fixture
def fake_api(pki):
    server, api = _serve(pki["good_key"], pki["good_cert"])
    yield api
    server.shutdown()
    server.server_close()


@pytest.fixture
def impostor(pki):
    server, api = _serve(pki["rogue_key"], pki["rogue_cert"])
    yield api
    server.shutdown()
    server.server_close()


@pytest.fixture(autouse=True)
def _database_in_tmp(tmp_path, monkeypatch):
    """nervus's default database is ./nervus.db. Every nervus a test starts, in
    this process or as a child process, keeps it in that test's own folder
    instead of wherever pytest runs, which may be the repository."""
    monkeypatch.setenv("NERVUS_DATABASE", str(tmp_path / "nervus.db"))


@pytest.fixture(autouse=True)
def _audit_log_in_tmp(tmp_path_factory, monkeypatch):
    """nervus's default audit log is ./audit.jsonl, and every start now writes
    to it (ADR-0027 question 6). Every nervus a test starts keeps it in a
    folder of its own, so no test's folder holds an extra file, and no start
    finds another test's log."""
    monkeypatch.setenv("NERVUS_AUDIT_LOG", str(tmp_path_factory.mktemp("audit") / "audit.jsonl"))


@pytest.fixture(scope="session")
def _test_ssh_ca(tmp_path_factory):
    path = tmp_path_factory.mktemp("ssh-ca") / "nervus_ca_ed25519"
    path.write_bytes(asyncssh.generate_private_key("ssh-ed25519").export_private_key())
    path.chmod(0o600)
    return path


@pytest.fixture(autouse=True)
def _ssh_ca_for_every_start(_test_ssh_ca, monkeypatch):
    """nervus refuses to start without its SSH certificate authority, as without
    its SSH key (ADR-0025). Every nervus a test starts has one, made as the
    installer makes it, in a folder of its own so no test's folder holds an
    extra file, unless the test names another."""
    monkeypatch.setenv("NERVUS_SSH_CA_KEY", str(_test_ssh_ca))
