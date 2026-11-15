"""tools/nervus-trust against a real TLS server presenting what tls-init makes
(ADR-0021 E2): nervus's certificate, its issuer and its root. The script reads
the root from the handshake, unchecked by design, prints its SHA-256, and saves
it only once the user has confirmed that value and nervus has been checked
against it, under the name the user gave.

On macOS it is run with both the system's openssl (LibreSSL, what a Mac
without Homebrew has) and any other openssl on PATH."""

import asyncio
import json
import os
import re
import shutil
import ssl
import stat
from pathlib import Path

import pytest

from nervus.tls import ServingCertificate, certificate_fingerprint, generate_own_authority, root_cert_path

TOOL = Path(__file__).resolve().parent.parent / "tools" / "nervus-trust"

pytestmark = pytest.mark.skipif(
    not all(shutil.which(t) for t in ("bash", "curl", "openssl")), reason="needs bash, curl and openssl"
)

OPENSSLS = sorted({os.path.realpath(p) for p in (shutil.which("openssl"), "/usr/bin/openssl") if p and os.path.exists(p)})


@pytest.fixture(params=OPENSSLS, ids=lambda p: "system" if p == "/usr/bin/openssl" else "path")
def openssl_bin(request, tmp_path):
    """A PATH whose openssl is this one."""
    d = tmp_path / "openssl-bin"
    d.mkdir()
    (d / "openssl").symlink_to(request.param)
    return str(d)


async def _answer(reader, writer):
    """An HTTPS server that answers every request, as nervus does, with 404."""
    try:
        await reader.read(4096)
        writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        await writer.drain()
    except (ConnectionError, ssl.SSLError):
        pass
    finally:
        writer.close()


class Server:
    pass


async def _serve(tmp_path, name):
    """A nervus of its own: its own authority, for 127.0.0.1 and `name`."""
    srv = Server()
    d = tmp_path / name
    d.mkdir()
    srv.cert, srv.key = d / "tls.crt", d / "tls.key"
    generate_own_authority(srv.cert, srv.key, ["127.0.0.1", name, "localhost"])
    srv.root = root_cert_path(srv.cert)
    srv.fp = certificate_fingerprint(srv.root.read_bytes())
    served = ServingCertificate(srv.cert, srv.key)
    served.load()
    srv.server = await asyncio.start_server(_answer, "127.0.0.1", 0, ssl=served.context)
    srv.port = srv.server.sockets[0].getsockname()[1]
    srv.url = f"https://127.0.0.1:{srv.port}/mcp"
    srv.by_name = (f"https://{name}:{srv.port}/mcp", "--resolve", f"{name}:{srv.port}:127.0.0.1")
    return srv


@pytest.fixture
async def nervus(tmp_path):
    srv = await _serve(tmp_path, "nervus.test")
    yield srv
    srv.server.close()


@pytest.fixture
async def other(tmp_path):
    """A second nervus, under another root: a friend's, or one restored at another address."""
    srv = await _serve(tmp_path, "other.test")
    yield srv
    srv.server.close()


async def trust(tmp_path, *args, stdin=b"", path=None, **env):
    environment = {"PATH": f"{path}:{os.environ['PATH']}" if path else os.environ["PATH"],
                   "HOME": str(tmp_path / "home"), **env}
    (tmp_path / "home").mkdir(exist_ok=True)
    proc = await asyncio.create_subprocess_exec(
        "bash", str(TOOL), *args, env=environment, stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
    out, _ = await asyncio.wait_for(proc.communicate(stdin), timeout=60)
    return proc.returncode, out.decode()


def saved(tmp_path, host="127.0.0.1"):
    return tmp_path / "home" / ".config" / "nervus" / f"root-{host}.pem"


def bundle(tmp_path):
    """The one file Claude Code is told: every root saved beside it."""
    return tmp_path / "home" / ".config" / "nervus" / "roots.pem"


def _same_certificate(a: Path, b: Path) -> bool:
    der = lambda p: ssl.PEM_cert_to_DER_cert(p.read_text())
    return der(a) == der(b)


def _certificates(path: Path) -> list[bytes]:
    pems = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", path.read_text(), re.S)
    return sorted(ssl.PEM_cert_to_DER_cert(p) for p in pems)


async def test_with_the_right_fingerprint_it_saves_the_root_and_prints_each_setting(nervus, tmp_path, openssl_bin):
    code, out = await trust(tmp_path, nervus.url, "--expect", nervus.fp, path=openssl_bin)
    assert code == 0, out
    assert nervus.fp in out
    path = saved(tmp_path)
    assert _same_certificate(path, nervus.root)
    assert stat.S_IMODE(path.stat().st_mode) == 0o644  # not a secret: anyone may read a root
    assert f'"NODE_EXTRA_CA_CERTS": "{bundle(tmp_path)}"' in out
    assert f"CODEX_CA_CERTIFICATE={path}" in out
    assert f"NERVUS_CACERT={path}" in out
    assert "SSL_CERT_FILE" not in out.replace("not SSL_CERT_FILE", "")


async def test_the_fingerprint_may_be_given_without_colons_and_in_any_case(nervus, tmp_path):
    code, out = await trust(tmp_path, nervus.url, "--expect", nervus.fp.replace(":", "").lower())
    assert code == 0, out
    assert saved(tmp_path).exists()


async def test_a_wrong_fingerprint_saves_nothing(nervus, tmp_path, openssl_bin):
    wrong = "00:" + nervus.fp[3:]
    code, out = await trust(tmp_path, nervus.url, "--expect", wrong, path=openssl_bin)
    assert code == 1, out
    assert "does not match" in out
    assert not saved(tmp_path).exists()


async def test_without_expect_it_asks_and_saves_on_yes(nervus, tmp_path):
    code, out = await trust(tmp_path, nervus.url, stdin=b"yes\n")
    assert code == 0, out
    assert "Does it match" in out
    assert saved(tmp_path).exists()


@pytest.mark.parametrize("answer", [b"", b"no\n", b"y\n"])
async def test_without_expect_anything_but_yes_saves_nothing(nervus, tmp_path, answer):
    code, out = await trust(tmp_path, nervus.url, stdin=answer)
    assert code == 1, out
    assert not saved(tmp_path).exists()


async def test_a_name_nervuss_certificate_is_not_for_saves_nothing(nervus, tmp_path, openssl_bin):
    # tls-init never names localhost (ADR-0021 B1), so this is checked and refused.
    code, out = await trust(tmp_path, f"https://localhost:{nervus.port}/mcp", "--expect", nervus.fp,
                            path=openssl_bin)
    assert code == 1, out
    assert "localhost" in out
    assert not saved(tmp_path, "localhost").exists()


async def test_by_name_it_checks_that_name(nervus, tmp_path, openssl_bin):
    """--resolve, as curl's: the name nervus is trusted by, reached at an address
    given, for a name this machine cannot look up yet."""
    code, out = await trust(tmp_path, f"https://nervus.test:{nervus.port}/mcp", "--expect", nervus.fp,
                            "--resolve", f"nervus.test:{nervus.port}:127.0.0.1", path=openssl_bin)
    assert code == 0, out
    assert saved(tmp_path, "nervus.test").exists()


async def test_a_server_whose_chain_has_no_root_of_its_own_is_refused(tmp_path, pki):
    """A certificate from an authority, presented without its root, as public
    ones are: there is no root to save, and the system's roots may be enough."""
    served = ServingCertificate(pki["good_cert"], pki["good_key"])
    os.chmod(pki["good_key"], 0o600)
    served.load()
    server = await asyncio.start_server(_answer, "127.0.0.1", 0, ssl=served.context)
    port = server.sockets[0].getsockname()[1]
    try:
        code, out = await trust(tmp_path, f"https://127.0.0.1:{port}/mcp", "--expect", "AA")
    finally:
        server.close()
    assert code == 1, out
    assert "root" in out
    assert not saved(tmp_path).exists()


async def test_the_same_root_again_is_already_saved(nervus, tmp_path):
    assert (await trust(tmp_path, nervus.url, "--expect", nervus.fp))[0] == 0
    code, out = await trust(tmp_path, nervus.url, "--expect", nervus.fp)
    assert code == 0, out
    assert "already saved" in out


async def test_a_different_root_is_never_replaced_quietly(nervus, tmp_path):
    path = saved(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text("another nervus's root\n")
    code, out = await trust(tmp_path, nervus.url, "--expect", nervus.fp)
    assert code == 1, out
    assert "--replace" in out
    assert path.read_text() == "another nervus's root\n"
    code, out = await trust(tmp_path, nervus.url, "--expect", nervus.fp, "--replace")
    assert code == 0, out
    assert _same_certificate(path, nervus.root)


async def test_an_existing_node_extra_ca_certs_is_named(nervus, tmp_path):
    code, out = await trust(tmp_path, nervus.url, "--expect", nervus.fp, NODE_EXTRA_CA_CERTS="/etc/corp-ca.pem")
    assert code == 0, out
    assert "/etc/corp-ca.pem" in out and "one file" in out


# --- more than one nervus (procedure 047, finding 1) ---------------------------------------
# Claude Code takes one file of roots (NODE_EXTRA_CA_CERTS), and ~/.claude/settings.json's wins
# over the environment, so trusting a second nervus must not lose the first.

async def test_a_second_nervus_joins_the_first_in_the_one_file_claude_code_reads(nervus, other, tmp_path):
    assert (await trust(tmp_path, *nervus.by_name, "--expect", nervus.fp))[0] == 0
    code, out = await trust(tmp_path, *other.by_name, "--expect", other.fp)
    assert code == 0, out
    assert _certificates(bundle(tmp_path)) == sorted(_certificates(nervus.root) + _certificates(other.root))
    assert stat.S_IMODE(bundle(tmp_path).stat().st_mode) == 0o644
    assert f'"NODE_EXTRA_CA_CERTS": "{bundle(tmp_path)}"' in out
    # Each nervus keeps its own file, for what reaches one nervus at a time.
    assert _same_certificate(saved(tmp_path, "nervus.test"), nervus.root)
    assert f"NERVUS_CACERT={saved(tmp_path, 'other.test')}" in out


async def test_a_root_saved_before_joins_the_file_when_it_is_already_saved(nervus, other, tmp_path):
    """Roots saved by an earlier nervus-trust, which made no such file: running it again makes it."""
    for srv, name in ((nervus, "nervus.test"), (other, "other.test")):
        saved(tmp_path, name).parent.mkdir(parents=True, exist_ok=True)
        saved(tmp_path, name).write_bytes(srv.root.read_bytes())
    code, out = await trust(tmp_path, *nervus.by_name, "--expect", nervus.fp)
    assert code == 0 and "already saved" in out, out
    assert _certificates(bundle(tmp_path)) == sorted(_certificates(nervus.root) + _certificates(other.root))


async def test_a_replaced_root_leaves_the_file_too(nervus, other, tmp_path):
    saved(tmp_path, "nervus.test").parent.mkdir(parents=True)
    saved(tmp_path, "nervus.test").write_bytes(other.root.read_bytes())  # this nervus's old root
    code, out = await trust(tmp_path, *nervus.by_name, "--expect", nervus.fp, "--replace")
    assert code == 0, out
    assert _certificates(bundle(tmp_path)) == _certificates(nervus.root)


async def test_with_out_the_file_given_is_the_one_each_client_is_told(nervus, tmp_path):
    out_file = tmp_path / "elsewhere" / "nervus.pem"
    code, out = await trust(tmp_path, nervus.url, "--expect", nervus.fp, "--out", str(out_file))
    assert code == 0, out
    assert f'"NODE_EXTRA_CA_CERTS": "{out_file}"' in out
    assert not bundle(tmp_path).exists()


def _settings(tmp_path, env: dict) -> Path:
    path = tmp_path / "home" / ".claude" / "settings.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"permissions": {"allow": []}, "env": env}, indent=2))
    return path


async def test_a_settings_file_naming_another_file_is_named(nervus, tmp_path):
    """As docs/clients.md had it: one nervus's own root, in the file that wins."""
    path = _settings(tmp_path, {"NODE_EXTRA_CA_CERTS": "/Users/me/.config/nervus/root-first.pem"})
    code, out = await trust(tmp_path, nervus.url, "--expect", nervus.fp)
    assert code == 0, out
    assert str(path) in out and "/Users/me/.config/nervus/root-first.pem" in out
    assert "wins over the environment" in out and str(bundle(tmp_path)) in out


async def test_one_nervuss_root_saved_here_is_never_added_to(nervus, tmp_path):
    """The environment naming one nervus's own root, as docs/clients.md had it: told to name the
    file of every root instead, never to append the others to that one nervus's file."""
    first = saved(tmp_path, "first.test")
    code, out = await trust(tmp_path, nervus.url, "--expect", nervus.fp, NODE_EXTRA_CA_CERTS=str(first))
    assert code == 0, out
    assert f"set it to {bundle(tmp_path)}" in out and ">>" not in out


async def test_a_settings_file_naming_the_file_already_is_not_warned_of(nervus, tmp_path):
    _settings(tmp_path, {"NODE_EXTRA_CA_CERTS": str(bundle(tmp_path))})
    code, out = await trust(tmp_path, nervus.url, "--expect", nervus.fp)
    assert code == 0, out
    assert "warn" not in out


def test_the_guide_tells_claude_code_the_file_that_holds_every_root():
    guide = (TOOL.parent.parent / "docs" / "clients.md").read_text()
    section = guide[guide.index("**Trusting nervus's root**, either way"):guide.index("## Codex")]
    assert "~/.config/nervus/roots.pem" in section and "every nervus" in section
    assert "~/.config/nervus/roots.pem" in guide[guide.index("## Trust nervus's certificate"):guide.index("## Where the token lives")]


async def test_nothing_listening_is_reported(tmp_path):
    code, out = await trust(tmp_path, "https://127.0.0.1:9/mcp", "--expect", "AA")
    assert code == 1, out
    assert not saved(tmp_path).exists()


async def test_plain_http_is_refused(tmp_path):
    code, out = await trust(tmp_path, "http://127.0.0.1:8000/mcp", "--expect", "AA")
    assert code == 2, out
    assert "https://" in out


def test_it_never_turns_certificate_checking_off():
    text = TOOL.read_text()
    for switch in (r"\s-k\b", r"--insecure\b", r"NODE_TLS_REJECT_UNAUTHORIZED"):
        assert not re.search(switch, text), switch
