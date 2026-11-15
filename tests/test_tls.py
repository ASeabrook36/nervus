"""nervus's TLS module: the certificate it makes for itself, its fingerprint,
and loading a certificate and key to serve with. Every certificate here is
made at run time inside tmp_path; none is committed (rule 7)."""

import asyncio
import datetime
import hashlib
import os
import re
import shutil
import socket
import ssl
import stat
import subprocess
from pathlib import Path

import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from nervus.config import ConfigError
from nervus.tls import (
    SELF_SIGNED_VALIDITY_DAYS,
    ServingCertificate,
    certificate_fingerprint,
    default_names,
    fingerprint,
    generate_self_signed,
)


@pytest.fixture
def pair(tmp_path):
    cert, key = tmp_path / "tls.crt", tmp_path / "tls.key"
    generate_self_signed(cert, key, ["localhost", "127.0.0.1", "::1"])
    return cert, key


def _mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def test_generated_files_are_0600_whatever_the_umask(tmp_path):
    # umask 0 would leave a file created with the usual defaults at 0666.
    old = os.umask(0)
    try:
        generate_self_signed(tmp_path / "tls.crt", tmp_path / "tls.key", ["localhost"])
    finally:
        os.umask(old)
    assert _mode(tmp_path / "tls.key") == 0o600
    assert _mode(tmp_path / "tls.crt") == 0o600


@pytest.mark.parametrize("existing", ["tls.crt", "tls.key"])
def test_generation_never_replaces_a_file(tmp_path, existing):
    (tmp_path / existing).write_text("someone else's")
    with pytest.raises(ConfigError, match="refusing to replace"):
        generate_self_signed(tmp_path / "tls.crt", tmp_path / "tls.key", ["localhost"])
    assert (tmp_path / existing).read_text() == "someone else's"
    assert sorted(p.name for p in tmp_path.iterdir()) == [existing]


def test_generation_does_not_follow_a_symlink(tmp_path):
    target = tmp_path / "elsewhere"
    (tmp_path / "tls.key").symlink_to(target)  # dangling: exists() alone says False
    with pytest.raises(ConfigError, match="refusing to replace"):
        generate_self_signed(tmp_path / "tls.crt", tmp_path / "tls.key", ["localhost"])
    assert not target.exists()


def test_the_generated_certificate(pair):
    cert = x509.load_pem_x509_certificate(pair[0].read_bytes())
    assert isinstance(cert.public_key(), ec.EllipticCurvePublicKey)
    assert cert.public_key().curve.name == "secp256r1"
    assert cert.issuer == cert.subject
    assert cert.not_valid_after_utc - cert.not_valid_before_utc == datetime.timedelta(
        days=SELF_SIGNED_VALIDITY_DAYS
    )
    assert cert.not_valid_before_utc < datetime.datetime.now(datetime.timezone.utc)
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["localhost"]
    assert [str(ip) for ip in san.get_values_for_type(x509.IPAddress)] == ["127.0.0.1", "::1"]
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False


def test_default_names():
    hostname = socket.gethostname()
    assert default_names("0.0.0.0") == list(dict.fromkeys(["localhost", "127.0.0.1", "::1", hostname]))
    assert default_names("::") == default_names("0.0.0.0")
    assert "192.0.2.7" in default_names("192.0.2.7")
    assert "nervus.example" in default_names("nervus.example")


def _openssl_key_fingerprint(cert_path):
    """The certificate's public-key SHA-256, extracted by openssl rather than
    by nervus: `openssl x509 -pubkey | openssl pkey -pubin -outform DER`."""
    pem = subprocess.run(["openssl", "x509", "-noout", "-pubkey", "-in", str(cert_path)],
                         capture_output=True, check=True).stdout
    der = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"],
                         input=pem, capture_output=True, check=True).stdout
    return hashlib.sha256(der).digest().hex(":").upper()


@pytest.mark.skipif(shutil.which("openssl") is None, reason="needs the openssl CLI")
def test_fingerprint_is_the_public_keys_as_openssl_extracts_it(pair):
    assert fingerprint(pair[0].read_bytes()) == _openssl_key_fingerprint(pair[0])


def _same_key_new_certificate(pair, days):
    """Another certificate for the pair's key, with other dates, serial and name."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID

    key = serialization.load_pem_private_key(pair[1].read_bytes(), None)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "re-issued")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=days))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM)


def _openssl_certificate_fingerprint(cert_path):
    """The certificate's SHA-256 fingerprint as openssl prints it, which is the
    number browsers show: `openssl x509 -noout -fingerprint -sha256`."""
    out = subprocess.run(["openssl", "x509", "-noout", "-fingerprint", "-sha256", "-in", str(cert_path)],
                         capture_output=True, check=True, text=True).stdout
    return out.strip().split("=", 1)[1].upper()


@pytest.mark.skipif(shutil.which("openssl") is None, reason="needs the openssl CLI")
def test_certificate_fingerprint_is_the_one_openssl_and_browsers_show(pair):
    assert certificate_fingerprint(pair[0].read_bytes()) == _openssl_certificate_fingerprint(pair[0])


def test_certificate_fingerprint_is_not_the_keys_and_changes_on_reissue(pair):
    """ADR-0012 decision 7a: the number a browser shows is not the one nervus
    pins, and unlike that one it changes when the certificate is re-issued."""
    original = pair[0].read_bytes()
    found = certificate_fingerprint(original)
    assert re.fullmatch(r"(?:[0-9A-F]{2}:){31}[0-9A-F]{2}", found)
    assert found != fingerprint(original)
    reissued = _same_key_new_certificate(pair, days=10)
    assert certificate_fingerprint(reissued) != found
    assert certificate_fingerprint(original + reissued) == found  # the first in the file, as served


def test_certificate_fingerprint_of_something_else_is_an_error():
    with pytest.raises(ConfigError, match="not a PEM certificate"):
        certificate_fingerprint(b"not a certificate")


def test_only_a_new_key_changes_the_fingerprint(tmp_path, pair):
    """ADR-0010 decision 2: re-issuing the certificate for the same key must
    not break a pairing; a new key must."""
    original = pair[0].read_bytes()
    reissued = _same_key_new_certificate(pair, days=10)
    assert reissued != original
    assert fingerprint(reissued) == fingerprint(original)

    other = tmp_path / "other"
    other.mkdir()
    generate_self_signed(other / "tls.crt", other / "tls.key", ["localhost"])
    assert fingerprint((other / "tls.crt").read_bytes()) != fingerprint(original)


async def test_a_client_trusting_only_that_certificate_connects(pair):
    """Served as loaded, by name and by address, and verified strictly, as
    Python 3.13 and later do by default. The fingerprint is the served one's."""
    served = ServingCertificate(*pair)
    served.load()
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0, ssl=served.context)
    port = server.sockets[0].getsockname()[1]

    def handshake(name):
        client = ssl.create_default_context(cafile=str(pair[0]))
        client.verify_flags |= ssl.VERIFY_X509_STRICT
        with client.wrap_socket(socket.create_connection(("127.0.0.1", port)), server_hostname=name) as s:
            return s.getpeercert(binary_form=True)

    try:
        for name in ("localhost", "127.0.0.1"):
            der = await asyncio.get_running_loop().run_in_executor(None, handshake, name)
            assert der == ssl.PEM_cert_to_DER_cert(pair[0].read_text())
            assert served.fingerprint == fingerprint(ssl.DER_cert_to_PEM_cert(der).encode())
    finally:
        server.close()


def test_load_refuses_a_key_others_can_read(pair):
    os.chmod(pair[1], 0o640)
    with pytest.raises(ConfigError, match="0600"):
        ServingCertificate(*pair).load()


def test_a_failed_load_keeps_what_was_loaded(tmp_path, pair):
    served = ServingCertificate(*pair)
    served.load()
    context, found = served.context, served.fingerprint

    other = tmp_path / "other"
    other.mkdir()
    generate_self_signed(other / "tls.crt", other / "tls.key", ["localhost"])
    shutil.copy(other / "tls.crt", pair[0])  # a new certificate, the old key: no match
    with pytest.raises(ConfigError, match="cannot serve TLS"):
        served.load()
    assert (served.context, served.fingerprint) == (context, found)


def test_load_refuses_a_missing_certificate(tmp_path, pair):
    with pytest.raises(ConfigError):
        ServingCertificate(tmp_path / "absent.crt", pair[1]).load()


def test_the_context_is_the_one_uvicorn_builds(pair):
    """nervus builds its own context so it can rebuild it on a reload. It must
    be the one uvicorn would have built from the same files at its defaults."""
    config = uvicorn.Config(lambda *a: None, ssl_certfile=str(pair[0]), ssl_keyfile=str(pair[1]))
    config.load()
    served = ServingCertificate(*pair)
    served.load()
    ours, theirs = served.context, config.ssl

    def shape(c):
        return (
            c.protocol, c.options, c.minimum_version, c.maximum_version, c.verify_mode,
            c.verify_flags, c.check_hostname, sorted(x["name"] for x in c.get_ciphers()),
        )

    assert shape(ours) == shape(theirs)


# --- replacing the certificate while nervus runs (ADR-0006 consequence 8) ----


def _renewal(tmp_path, pair, *, cert=True, key=True):
    """Replace the pair as certificate tools do: write new files elsewhere,
    then rename them over the old. Returns the new certificate's path."""
    import tempfile

    new = Path(tempfile.mkdtemp(dir=tmp_path))
    generate_self_signed(new / "tls.crt", new / "tls.key", ["localhost", "127.0.0.1"])
    if key:
        os.replace(new / "tls.key", pair[1])
    if cert:
        os.replace(new / "tls.crt", pair[0])
    return new


def _loaded(pair):
    served = ServingCertificate(*pair)
    served.load()
    return served


def test_unchanged_files_are_not_reloaded(pair):
    served = _loaded(pair)
    context = served.context
    assert served.reload_if_changed() is None
    assert served.context is context


def test_a_replacement_is_loaded(tmp_path, pair):
    served = _loaded(pair)
    context, old = served.context, served.fingerprint
    _renewal(tmp_path, pair)
    line = served.reload_if_changed()
    assert line.startswith("reloaded the TLS certificate")
    assert served.fingerprint == fingerprint(pair[0].read_bytes()) != old
    assert served.fingerprint in line
    assert served.context is not context
    assert served.reload_if_changed() is None


def test_a_half_written_renewal_keeps_the_old_until_the_other_half_lands(tmp_path, pair):
    served = _loaded(pair)
    context, old = served.context, served.fingerprint
    new = _renewal(tmp_path, pair, key=False)  # the certificate written, the key not yet
    line = served.reload_if_changed()
    assert "cannot be used" in line and old in line
    assert (served.context, served.fingerprint) == (context, old)
    assert served.reload_if_changed() is None  # not retried until the files change
    os.replace(new / "tls.key", pair[1])
    assert served.reload_if_changed().startswith("reloaded")
    assert served.fingerprint == fingerprint(pair[0].read_bytes())


def test_a_replacement_key_others_can_read_is_refused(tmp_path, pair):
    served = _loaded(pair)
    old = served.fingerprint
    _renewal(tmp_path, pair)
    os.chmod(pair[1], 0o644)
    assert "0600" in served.reload_if_changed()
    assert served.fingerprint == old


def test_an_unexpected_error_keeps_the_old(pair, monkeypatch):
    served = _loaded(pair)
    old = served.fingerprint
    os.utime(pair[0])  # a change, so a load is attempted

    def broken():
        raise RuntimeError("something nobody expected")

    monkeypatch.setattr(served, "load", broken)
    assert "something nobody expected" in served.reload_if_changed()
    assert served.fingerprint == old


async def test_new_handshakes_get_the_new_certificate_and_open_connections_keep_theirs(tmp_path, pair):
    served = _loaded(pair)
    old_pem = tmp_path / "old.crt"
    shutil.copy(pair[0], old_pem)

    async def echo(reader, writer):
        while line := await reader.readline():
            writer.write(line)
            await writer.drain()
        writer.close()

    server = await asyncio.start_server(echo, "127.0.0.1", 0, ssl=served.listening_context())
    port = server.sockets[0].getsockname()[1]
    run = asyncio.get_running_loop().run_in_executor

    def connect(cafile, name):
        client = ssl.create_default_context(cafile=str(cafile))
        client.verify_flags |= ssl.VERIFY_X509_STRICT
        return client.wrap_socket(socket.create_connection(("127.0.0.1", port)), server_hostname=name)

    try:
        before = await run(None, connect, old_pem, "localhost")
        _renewal(tmp_path, pair)
        assert served.reload_if_changed().startswith("reloaded")
        new_der = ssl.PEM_cert_to_DER_cert(pair[0].read_text())

        # By name and by address: with a server name in the handshake, and without.
        for name in ("localhost", "127.0.0.1"):
            s = await run(None, connect, pair[0], name)
            assert s.getpeercert(binary_form=True) == new_der
            s.close()
        with pytest.raises(ssl.SSLCertVerificationError):
            await run(None, connect, old_pem, "localhost")

        def still_talking():
            before.sendall(b"still here\n")
            return before.recv(100)

        assert await run(None, still_talking) == b"still here\n"
        assert before.getpeercert(binary_form=True) == ssl.PEM_cert_to_DER_cert(old_pem.read_text())
        before.close()
    finally:
        server.close()


async def test_watch_reloads_and_reports(tmp_path, pair):
    import anyio

    served = _loaded(pair)
    reports = []
    with anyio.fail_after(10):
        async with anyio.create_task_group() as tasks:
            tasks.start_soon(served.watch, reports.append, 0.05)
            await anyio.sleep(0.2)
            assert reports == []
            _renewal(tmp_path, pair)
            while not reports:
                await anyio.sleep(0.05)
            tasks.cancel_scope.cancel()
    assert reports == [f"reloaded the TLS certificate {pair[0]}: {served.describe()}"]


# --- renewing before expiry (ADR-0010 decision 3) ----------------------------


@pytest.fixture
def expiring(tmp_path):
    """nervus's own pair, with a certificate that has 10 days left."""
    cert, key = tmp_path / "own.crt", tmp_path / "own.key"
    generate_self_signed(cert, key, ["localhost", "127.0.0.1"], validity_days=10)
    return cert, key


def test_far_from_expiry_nothing_is_done(pair):
    served = _loaded(pair)
    before = pair[0].read_bytes()
    assert served.renew_if_due() is None
    assert pair[0].read_bytes() == before


def test_its_own_certificate_is_reissued_for_the_same_key(expiring):
    served = _loaded(expiring)
    old_cert = x509.load_pem_x509_certificate(expiring[0].read_bytes())
    old_key, old_fp, context = expiring[1].read_bytes(), served.fingerprint, served.context

    line = served.renew_if_due()

    assert line.startswith("re-issued the TLS certificate") and old_fp in line
    new_cert = x509.load_pem_x509_certificate(expiring[0].read_bytes())
    assert expiring[1].read_bytes() == old_key            # the key is untouched
    assert served.fingerprint == old_fp == fingerprint(expiring[0].read_bytes())
    assert new_cert.serial_number != old_cert.serial_number
    assert new_cert.not_valid_after_utc - new_cert.not_valid_before_utc == datetime.timedelta(
        days=SELF_SIGNED_VALIDITY_DAYS)
    assert new_cert.not_valid_after_utc > datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=800)
    assert new_cert.subject == old_cert.subject
    assert list(new_cert.extensions) == list(old_cert.extensions)  # names, usages, identifiers
    assert served.context is not context                  # in use without a restart
    assert _mode(expiring[0]) == 0o600
    assert sorted(p.name for p in expiring[0].parent.iterdir()) == ["own.crt", "own.key"]
    assert served.renew_if_due() is None                  # 825 days left now


def test_a_certificate_it_did_not_issue_is_warned_about_not_touched(tmp_path, pki):
    # The test CA's certificates live 2 days: issued by someone else, expiring.
    cert, key = tmp_path / "ca-issued.crt", tmp_path / "ca-issued.key"
    shutil.copy(pki["good_cert"], cert)
    shutil.copy(pki["good_key"], key)
    os.chmod(key, 0o600)
    served = _loaded((cert, key))
    before = cert.read_bytes()

    line = served.renew_if_due()

    assert line.startswith(f"WARNING: TLS certificate {cert} expires")
    assert "cannot renew a certificate it did not issue" in line
    assert cert.read_bytes() == before


def test_a_failed_reissue_keeps_serving_the_old_and_says_so(expiring, monkeypatch):
    served = _loaded(expiring)
    before, context = expiring[0].read_bytes(), served.context

    def read_only(path, data):
        raise ConfigError(f"cannot create {path}: [Errno 30] Read-only file system")

    monkeypatch.setattr("nervus.tls._write_new_private_file", read_only)
    line = served.renew_if_due()

    assert "Re-issuing it for the same key failed, and is retried daily" in line
    assert "Read-only file system" in line
    assert expiring[0].read_bytes() == before and served.context is context


async def test_watch_checks_expiry_on_its_schedule(expiring):
    import anyio

    served = _loaded(expiring)
    reports = []
    with anyio.fail_after(10):
        async with anyio.create_task_group() as tasks:
            tasks.start_soon(served.watch, reports.append, 0.05, 0.3)
            while not reports:
                await anyio.sleep(0.05)
            tasks.cancel_scope.cancel()
    assert len(reports) == 1 and reports[0].startswith("re-issued the TLS certificate")


def test_check_now_reloads_a_replacement_at_once(tmp_path, pair):
    """What SIGHUP runs (ADR-0010 decision 5)."""
    served = _loaded(pair)
    assert served.check_now() == [f"certificate files unchanged; serving {served.describe()}"]
    _renewal(tmp_path, pair)
    lines = served.check_now()
    assert len(lines) == 1 and lines[0].startswith("reloaded the TLS certificate")
    assert served.fingerprint == fingerprint(pair[0].read_bytes())


def test_check_now_also_checks_expiry(expiring):
    served = _loaded(expiring)
    lines = served.check_now()
    assert lines[0].startswith("certificate files unchanged")
    assert lines[1].startswith("re-issued the TLS certificate")


def test_a_self_signed_certificate_someone_gave_nervus_is_not_rewritten(tmp_path):
    """ADR-0010 decision 3 re-issues only what nervus made. A self-signed
    certificate made elsewhere, for nervus's key or not, is the giver's."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "made by hand")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=10))
            .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / "hand.crt", tmp_path / "hand.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    os.chmod(key_path, 0o600)
    served = _loaded((cert_path, key_path))
    before = cert_path.read_bytes()

    line = served.renew_if_due()

    assert "cannot renew a certificate it did not issue" in line
    assert cert_path.read_bytes() == before
