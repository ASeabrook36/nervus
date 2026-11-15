"""nervus's own two-layer certificate authority (ADR-0021 A1, B1, C1): a root
whose key is never saved, an issuer limited to nervus's DNS names, and nervus's
certificate under it, which nervus re-issues with the issuer's key.

The checks that matter are made by real TLS clients: Python's own, verifying as
strictly as Python 3.13 does by default, and curl. Procedure 030 showed Claude
Code and Codex agree with them. Every certificate is made in tmp_path."""

import asyncio
import datetime
import ipaddress
import os
import shutil
import socket
import ssl
import stat
import subprocess

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from nervus.config import ConfigError
from nervus.tls import (
    AUTHORITY_VALIDITY_DAYS,
    SELF_SIGNED_VALIDITY_DAYS,
    ServingCertificate,
    certificate_fingerprint,
    fingerprint,
    generate_own_authority,
    issuer_cert_path,
    issuer_key_path,
    key_file_fingerprint,
    renewal_path,
    root_cert_path,
    serving_path,
    upgrade_to_own_authority,
)

NAMES = ["localhost", "127.0.0.1", "::1", "host-a", "nervus.example"]
FILES = ["tls-issuer.crt", "tls-issuer.key", "tls-root.crt", "tls.crt", "tls.key"]


@pytest.fixture
def made(tmp_path):
    cert, key = tmp_path / "tls.crt", tmp_path / "tls.key"
    generate_own_authority(cert, key, NAMES)
    return cert, key


def _chain(path):
    return x509.load_pem_x509_certificates(path.read_bytes())


def _days(cert):
    return (cert.not_valid_after_utc - cert.not_valid_before_utc).days


def _mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def test_it_makes_five_files_and_saves_no_root_key(tmp_path, made):
    assert sorted(p.name for p in tmp_path.iterdir()) == FILES
    assert all(_mode(p) == 0o600 for p in tmp_path.iterdir())
    assert issuer_key_path(made[1]) == tmp_path / "tls-issuer.key"
    assert issuer_cert_path(made[0]) == tmp_path / "tls-issuer.crt"
    assert root_cert_path(made[0]) == tmp_path / "tls-root.crt"
    # Every private key on disk, and none of them is the root's.
    root = x509.load_pem_x509_certificate(root_cert_path(made[0]).read_bytes())
    keys = [serialization.load_pem_private_key(p.read_bytes(), None)
            for p in tmp_path.iterdir() if b"PRIVATE KEY" in p.read_bytes()]
    assert len(keys) == 2
    spki = lambda k: k.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    assert spki(root.public_key()) not in {spki(k.public_key()) for k in keys}


@pytest.mark.parametrize("existing", FILES)
def test_it_never_replaces_a_file_and_leaves_nothing_half_made(tmp_path, existing):
    (tmp_path / existing).write_text("someone else's")
    with pytest.raises(ConfigError, match="refusing to replace"):
        generate_own_authority(tmp_path / "tls.crt", tmp_path / "tls.key", NAMES)
    assert sorted(p.name for p in tmp_path.iterdir()) == [existing]
    assert (tmp_path / existing).read_text() == "someone else's"


def test_the_files_are_0600_whatever_the_umask(tmp_path):
    old = os.umask(0)
    try:
        generate_own_authority(tmp_path / "tls.crt", tmp_path / "tls.key", NAMES)
    finally:
        os.umask(old)
    assert all(_mode(p) == 0o600 for p in tmp_path.iterdir())


def test_the_chain_nervus_presents_ends_with_the_root(made):
    leaf, issuer, root = _chain(made[0])
    assert issuer == x509.load_pem_x509_certificate(issuer_cert_path(made[0]).read_bytes())
    assert root == x509.load_pem_x509_certificate(root_cert_path(made[0]).read_bytes())
    root.verify_directly_issued_by(root)
    issuer.verify_directly_issued_by(root)
    leaf.verify_directly_issued_by(issuer)
    assert fingerprint(made[0].read_bytes()) == key_file_fingerprint(made[1])  # the key is the identity
    for cert in (leaf, issuer, root):
        assert cert.public_key().curve.name == "secp256r1"
        assert cert.not_valid_before_utc < datetime.datetime.now(datetime.timezone.utc)
    assert _days(leaf) == SELF_SIGNED_VALIDITY_DAYS == 825
    assert _days(issuer) == _days(root) == AUTHORITY_VALIDITY_DAYS
    assert AUTHORITY_VALIDITY_DAYS >= 20 * 365
    bc = lambda c: c.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert (bc(root).ca, bc(root).path_length) == (True, 1)
    assert (bc(issuer).ca, bc(issuer).path_length) == (True, 0)
    assert bc(leaf).ca is False
    ku = lambda c: c.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku(root).key_cert_sign and ku(issuer).key_cert_sign and not ku(leaf).key_cert_sign
    assert root.subject != issuer.subject  # each named, so a chain is never ambiguous


def test_two_installations_have_different_roots(tmp_path):
    for d in ("a", "b"):
        (tmp_path / d).mkdir()
        generate_own_authority(tmp_path / d / "tls.crt", tmp_path / d / "tls.key", NAMES)
    a, b = (x509.load_pem_x509_certificate((tmp_path / d / "tls-root.crt").read_bytes()) for d in "ab")
    assert a.subject != b.subject


def test_the_issuer_is_limited_to_the_dns_names_and_never_localhost(made):
    leaf, issuer, _ = _chain(made[0])
    limit = issuer.extensions.get_extension_for_class(x509.NameConstraints)
    assert limit.critical
    assert limit.value.excluded_subtrees is None
    assert sorted(n.value for n in limit.value.permitted_subtrees) == ["host-a", "nervus.example"]
    assert all(isinstance(n, x509.DNSName) for n in limit.value.permitted_subtrees)
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert sorted(san.get_values_for_type(x509.DNSName)) == ["host-a", "nervus.example"]
    assert [str(ip) for ip in san.get_values_for_type(x509.IPAddress)] == ["127.0.0.1", "::1"]
    # A subject that reads as a host name is checked against the limit too, so the
    # certificate's names are only in its alternative names (procedure 030).
    assert not leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)


def test_without_a_dns_name_it_refuses_and_makes_nothing(tmp_path):
    with pytest.raises(ConfigError, match="DNS name"):
        generate_own_authority(tmp_path / "tls.crt", tmp_path / "tls.key", ["localhost", "127.0.0.1"])
    assert list(tmp_path.iterdir()) == []


# --- real clients ---------------------------------------------------------


def _impostor(made, tmp_path, san: x509.GeneralName):
    """A certificate the issuer's key signs for `san`: what a thief holding
    that key, and only that key, could make. Served with nervus's chain."""
    leaf, issuer, root = _chain(made[0])
    issuer_key = serialization.load_pem_private_key(issuer_key_path(made[1]).read_bytes(), None)
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "impostor")]))
            .issuer_name(issuer.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(hours=1)).not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.public_key()), critical=False)
            .sign(issuer_key, hashes.SHA256()))
    d = tmp_path / "impostor"
    d.mkdir(exist_ok=True)
    pem = lambda c: c.public_bytes(serialization.Encoding.PEM)
    (d / "tls.crt").write_bytes(pem(cert) + pem(issuer) + pem(root))
    (d / "tls.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                  serialization.NoEncryption()))
    os.chmod(d / "tls.key", 0o600)
    return d / "tls.crt", d / "tls.key"


async def _serving(pair):
    served = ServingCertificate(*pair)
    served.load()
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0, ssl=served.context)
    return server, server.sockets[0].getsockname()[1]


def _handshake(root, port, name):
    client = ssl.create_default_context(cafile=str(root))  # given a cafile, it trusts that alone
    client.verify_flags |= ssl.VERIFY_X509_STRICT
    with client.wrap_socket(socket.create_connection(("127.0.0.1", port)), server_hostname=name) as s:
        return s.getpeercert(binary_form=True)


async def _python_client(root, port, name):
    return await asyncio.get_running_loop().run_in_executor(None, _handshake, root, port, name)


async def test_a_client_trusting_only_the_root_accepts_nervus_by_name_and_address(made):
    server, port = await _serving(made)
    try:
        for name in ("nervus.example", "host-a", "127.0.0.1"):
            der = await _python_client(root_cert_path(made[0]), port, name)
            assert fingerprint(ssl.DER_cert_to_PEM_cert(der).encode()) == key_file_fingerprint(made[1])
    finally:
        server.close()


async def test_a_client_that_does_not_trust_the_root_refuses_nervus(made, tmp_path):
    (tmp_path / "other").mkdir()
    generate_own_authority(tmp_path / "other" / "tls.crt", tmp_path / "other" / "tls.key", NAMES)
    server, port = await _serving(made)
    try:
        with pytest.raises(ssl.SSLCertVerificationError):
            await _python_client(tmp_path / "other" / "tls-root.crt", port, "nervus.example")
    finally:
        server.close()


@pytest.mark.parametrize("name", ["example.com", "localhost"])
async def test_the_issuer_cannot_vouch_for_another_name(made, tmp_path, name):
    impostor = _impostor(made, tmp_path, x509.DNSName(name))
    server, port = await _serving(impostor)
    try:
        with pytest.raises(ssl.SSLCertVerificationError, match="(?i)name constraint|permitted subtree|subtree"):
            await _python_client(root_cert_path(made[0]), port, name)
    finally:
        server.close()


curl = pytest.mark.skipif(shutil.which("curl") is None, reason="curl is not installed")


async def _curl(root, port, name):
    proc = await asyncio.create_subprocess_exec(
        "curl", "-sS", "-o", "/dev/null", "--max-time", "10", "--cacert", str(root),
        "--resolve", f"{name}:{port}:127.0.0.1", f"https://{name}:{port}/",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    _, err = await proc.communicate()
    return proc.returncode, err.decode()


@curl
async def test_curl_agrees(made, tmp_path):
    """A second library: LibreSSL on macOS, OpenSSL on Debian."""
    server, port = await _serving(made)
    impostor = _impostor(made, tmp_path, x509.DNSName("example.com"))
    other, other_port = await _serving(impostor)
    try:
        code, err = await _curl(root_cert_path(made[0]), port, "nervus.example")
        assert code in (0, 52, 56), err  # TLS passed; the test server then closes without an answer
        code, err = await _curl(root_cert_path(made[0]), other_port, "example.com")
        assert code == 60, err
    finally:
        server.close()
        other.close()


# --- re-issue -------------------------------------------------------------


@pytest.fixture
def expiring(tmp_path):
    cert, key = tmp_path / "tls.crt", tmp_path / "tls.key"
    generate_own_authority(cert, key, NAMES, validity_days=10)
    return cert, key


def test_its_certificate_is_reissued_under_the_issuer_for_the_same_key(expiring):
    served = ServingCertificate(*expiring)
    served.load()
    old_leaf, issuer, root = _chain(expiring[0])
    old_fp, context = served.fingerprint, served.context
    keys = {p: p.read_bytes() for p in (expiring[1], issuer_key_path(expiring[1]))}

    line = served.renew_if_due()

    assert line.startswith("re-issued the TLS certificate") and old_fp in line
    leaf, new_issuer, new_root = _chain(expiring[0])
    assert (new_issuer, new_root) == (issuer, root)        # the chain above is untouched
    leaf.verify_directly_issued_by(issuer)
    assert leaf.serial_number != old_leaf.serial_number
    assert _days(leaf) == SELF_SIGNED_VALIDITY_DAYS
    assert leaf.subject == old_leaf.subject
    assert list(leaf.extensions) != [] and [e.oid for e in leaf.extensions] == [e.oid for e in old_leaf.extensions]
    assert leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName) == \
        old_leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    assert {p: p.read_bytes() for p in keys} == keys       # no key changes
    assert served.fingerprint == old_fp and served.context is not context
    assert served.renew_if_due() is None


async def test_the_reissued_certificate_still_verifies_against_the_root(expiring):
    served = ServingCertificate(*expiring)
    served.load()
    served.renew_if_due()
    server, port = await _serving(expiring)
    try:
        await _python_client(root_cert_path(expiring[0]), port, "nervus.example")
    finally:
        server.close()


def test_without_its_issuer_key_it_is_warned_about_not_touched(expiring):
    issuer_key_path(expiring[1]).unlink()
    served = ServingCertificate(*expiring)
    served.load()
    before = expiring[0].read_bytes()
    line = served.renew_if_due()
    assert "cannot renew a certificate it did not issue" in line
    assert expiring[0].read_bytes() == before


def test_with_another_issuer_key_it_is_warned_about_not_touched(expiring, tmp_path):
    (tmp_path / "x").mkdir()
    generate_own_authority(tmp_path / "x" / "tls.crt", tmp_path / "x" / "tls.key", NAMES)
    shutil.copy(tmp_path / "x" / "tls-issuer.key", issuer_key_path(expiring[1]))
    served = ServingCertificate(*expiring)
    served.load()
    before = expiring[0].read_bytes()
    assert "cannot renew a certificate it did not issue" in served.renew_if_due()
    assert expiring[0].read_bytes() == before


def test_the_roots_fingerprint_is_the_one_a_user_compares(made):
    """What tls-init prints, and what tools/nervus-trust will show: the root
    certificate's SHA-256, as openssl prints it."""
    root = root_cert_path(made[0])
    if shutil.which("openssl") is None:
        pytest.skip("needs the openssl CLI")
    out = subprocess.run(["openssl", "x509", "-in", str(root), "-noout", "-fingerprint", "-sha256"],
                         capture_output=True, text=True, check=True).stdout
    assert out.strip().split("=", 1)[1] == certificate_fingerprint(root.read_bytes())


# --- renewal into the state directory (ADR-0021 D1) -------------------------


@pytest.fixture
def unit_like(tmp_path):
    """As the unit lays nervus out: its certificate in a secrets directory it
    cannot write, its state directory writable, and a certificate 10 days from
    expiry. The secrets directory is made read-only for the test, as
    ProtectSystem=strict makes it for the service."""
    secrets_dir, state = tmp_path / "secrets", tmp_path / "state"
    secrets_dir.mkdir(mode=0o700)
    state.mkdir(mode=0o700)
    cert, key = secrets_dir / "tls.crt", secrets_dir / "tls.key"
    generate_own_authority(cert, key, NAMES, validity_days=10)
    secrets_dir.chmod(0o500)
    yield cert, key, renewal_path(cert, state)
    secrets_dir.chmod(0o700)


def test_the_renewal_lives_in_the_state_directory(unit_like, tmp_path):
    cert, key, renewed = unit_like
    assert renewed == tmp_path / "state" / "tls" / "tls.crt"


def test_a_renewal_is_written_to_the_state_directory_when_secrets_cannot_be(unit_like):
    cert, key, renewed = unit_like
    before = cert.read_bytes()
    served = ServingCertificate(cert, key, renewed)
    served.load()
    old_fp = served.fingerprint

    line = served.renew_if_due()

    assert line == f"re-issued the TLS certificate {renewed} for the same key: {served.describe()}"
    assert cert.read_bytes() == before                       # secrets/ untouched
    assert _mode(renewed) == 0o600 and _mode(renewed.parent) == 0o700
    assert served.serving == renewed and served.fingerprint == old_fp
    leaf, issuer, root = _chain(renewed)
    assert (issuer, root) == tuple(_chain(cert)[1:])
    assert _days(leaf) == SELF_SIGNED_VALIDITY_DAYS
    assert served.renew_if_due() is None


def test_a_restart_serves_the_renewal(unit_like):
    cert, key, renewed = unit_like
    first = ServingCertificate(cert, key, renewed)
    first.load()
    first.renew_if_due()
    again = ServingCertificate(cert, key, renewed)
    again.load()
    assert again.serving == renewed
    assert again.not_after == first.not_after
    assert again.renew_if_due() is None


async def test_a_client_trusting_the_root_accepts_the_renewal(unit_like):
    cert, key, renewed = unit_like
    served = ServingCertificate(cert, key, renewed)
    served.load()
    served.renew_if_due()
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0, ssl=served.context)
    port = server.sockets[0].getsockname()[1]
    try:
        der = await _python_client(root_cert_path(cert), port, "nervus.example")
        assert x509.load_der_x509_certificate(der) == _chain(renewed)[0]
    finally:
        server.close()


def test_the_old_shape_renews_into_the_state_directory_too(tmp_path):
    from nervus.tls import generate_self_signed

    cert, key = tmp_path / "tls.crt", tmp_path / "tls.key"
    generate_self_signed(cert, key, ["localhost", "127.0.0.1"], validity_days=10)
    renewed = renewal_path(cert, tmp_path / "state")
    (tmp_path / "state").mkdir()
    before = cert.read_bytes()
    served = ServingCertificate(cert, key, renewed)
    served.load()
    assert served.renew_if_due().startswith(f"re-issued the TLS certificate {renewed}")
    assert cert.read_bytes() == before and served.serving == renewed


def test_without_a_state_directory_the_renewal_fails_and_says_so(unit_like, tmp_path):
    cert, key, _ = unit_like
    served = ServingCertificate(cert, key, renewal_path(cert, tmp_path / "missing"))
    served.load()
    line = served.renew_if_due()
    assert "Re-issuing it for the same key failed, and is retried daily" in line
    assert served.serving == cert


def _write_cert(path, cert, *chain):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(b"".join(c.public_bytes(serialization.Encoding.PEM) for c in (cert, *chain)))
    path.chmod(0o600)


def _resigned(cert, signing_key, *, days, public_key=None):
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(cert.subject).issuer_name(cert.issuer)
               .public_key(public_key or cert.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(hours=1)).not_valid_after(now + datetime.timedelta(days=days)))
    for e in cert.extensions:
        builder = builder.add_extension(e.value, e.critical)
    return builder.sign(signing_key, hashes.SHA256())


def test_serving_path_takes_the_renewal_only_when_it_renews_the_given_certificate(made, tmp_path):
    cert, key = made
    leaf, issuer, root = _chain(cert)
    issuer_key = serialization.load_pem_private_key(issuer_key_path(key).read_bytes(), None)
    renewed = renewal_path(cert, tmp_path / "state")

    assert serving_path(cert, None) == cert
    assert serving_path(cert, renewed) == cert                       # no renewal yet

    _write_cert(renewed, _resigned(leaf, issuer_key, days=900), issuer, root)
    assert serving_path(cert, renewed) == renewed                    # same key and issuer, longer

    _write_cert(renewed, _resigned(leaf, issuer_key, days=100), issuer, root)
    assert serving_path(cert, renewed) == cert                       # shorter than what was given

    other = ec.generate_private_key(ec.SECP256R1())
    _write_cert(renewed, _resigned(leaf, issuer_key, days=900, public_key=other.public_key()), issuer, root)
    assert serving_path(cert, renewed) == cert                       # another key

    (tmp_path / "x").mkdir()
    generate_own_authority(tmp_path / "x" / "tls.crt", tmp_path / "x" / "tls.key", NAMES)
    foreign_issuer = _chain(tmp_path / "x" / "tls.crt")[1]
    foreign = x509.load_pem_x509_certificate(_resigned(leaf, issuer_key, days=900).public_bytes(
        serialization.Encoding.PEM))
    builder = (x509.CertificateBuilder().subject_name(foreign.subject).issuer_name(foreign_issuer.subject)
               .public_key(foreign.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(foreign.not_valid_before_utc).not_valid_after(foreign.not_valid_after_utc))
    _write_cert(renewed, builder.sign(issuer_key, hashes.SHA256()), foreign_issuer)
    assert serving_path(cert, renewed) == cert                       # another issuer

    renewed.write_text("not a certificate")
    assert serving_path(cert, renewed) == cert


def test_a_changed_renewal_is_reloaded(unit_like):
    """The file watch covers the renewal too, so nervus serves one written by
    another of its processes without a restart."""
    cert, key, renewed = unit_like
    served = ServingCertificate(cert, key, renewed)
    served.load()
    other = ServingCertificate(cert, key, renewed)
    other.load()
    other.renew_if_due()
    line = served.reload_if_changed()
    assert line.startswith(f"reloaded the TLS certificate {renewed}")
    assert served.serving == renewed


# --- tls-init --upgrade (ADR-0021 G1) ---------------------------------------


@pytest.fixture
def old_install(tmp_path):
    """What tls-init made before ADR-0021: a self-signed certificate."""
    from nervus.tls import generate_self_signed

    cert, key = tmp_path / "tls.crt", tmp_path / "tls.key"
    generate_self_signed(cert, key, ["localhost", "127.0.0.1", "::1", "host-a"])
    return cert, key


async def test_an_old_install_is_upgraded_keeping_its_key(old_install, tmp_path):
    cert, key = old_install
    key_before, fp = key.read_bytes(), key_file_fingerprint(key)

    named = upgrade_to_own_authority(cert, key)

    assert named == ["host-a", "127.0.0.1", "::1"]                  # localhost dropped (B1)
    assert key.read_bytes() == key_before and fingerprint(cert.read_bytes()) == fp
    assert sorted(p.name for p in tmp_path.iterdir()) == FILES
    assert all(_mode(p) == 0o600 for p in tmp_path.iterdir())
    leaf, issuer, root = _chain(cert)
    leaf.verify_directly_issued_by(issuer)
    issuer.verify_directly_issued_by(root)
    assert sorted(n.value for n in issuer.extensions.get_extension_for_class(
        x509.NameConstraints).value.permitted_subtrees) == ["host-a"]
    assert _days(leaf) == SELF_SIGNED_VALIDITY_DAYS
    server, port = await _serving(old_install)
    try:
        await _python_client(root_cert_path(cert), port, "host-a")
    finally:
        server.close()


def test_upgrading_can_add_names_since_the_limit_is_set_now(old_install):
    cert, key = old_install
    named = upgrade_to_own_authority(cert, key, ["nervus.example", "192.0.2.9"])
    assert "nervus.example" in named and "192.0.2.9" in named
    issuer = _chain(cert)[1]
    assert "nervus.example" in [n.value for n in issuer.extensions.get_extension_for_class(
        x509.NameConstraints).value.permitted_subtrees]


def test_upgrading_twice_is_refused_and_changes_nothing(old_install, tmp_path):
    upgrade_to_own_authority(*old_install)
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    with pytest.raises(ConfigError, match="refusing to replace"):
        upgrade_to_own_authority(*old_install)
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == before


def test_a_certificate_nervus_did_not_make_is_not_upgraded(tmp_path, pki):
    cert, key = tmp_path / "tls.crt", tmp_path / "tls.key"
    shutil.copy(pki["good_cert"], cert)
    shutil.copy(pki["good_key"], key)
    os.chmod(key, 0o600)
    before = cert.read_bytes()
    with pytest.raises(ConfigError, match="not nervus's to upgrade"):
        upgrade_to_own_authority(cert, key)
    assert cert.read_bytes() == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["tls.crt", "tls.key"]


def test_upgrading_without_a_dns_name_asks_for_one_and_makes_nothing(tmp_path):
    from nervus.tls import generate_self_signed

    cert, key = tmp_path / "tls.crt", tmp_path / "tls.key"
    generate_self_signed(cert, key, ["localhost", "127.0.0.1"])
    before = cert.read_bytes()
    with pytest.raises(ConfigError, match="--name"):
        upgrade_to_own_authority(cert, key)
    assert cert.read_bytes() == before
    assert sorted(p.name for p in tmp_path.iterdir()) == ["tls.crt", "tls.key"]
    assert upgrade_to_own_authority(cert, key, ["nervus.example"])[0] == "nervus.example"


def test_a_failed_upgrade_leaves_the_old_install_as_it_was(old_install, tmp_path, monkeypatch):
    import nervus.tls

    cert, key = old_install
    before = {p.name: p.read_bytes() for p in tmp_path.iterdir()}
    real = nervus.tls._write_new_private_file

    def fail_on_the_root(path, data):
        if path.name == "tls-root.crt":
            raise ConfigError(f"cannot create {path}: [Errno 28] No space left on device")
        real(path, data)

    monkeypatch.setattr(nervus.tls, "_write_new_private_file", fail_on_the_root)
    with pytest.raises(ConfigError, match="No space left"):
        upgrade_to_own_authority(cert, key)
    assert {p.name: p.read_bytes() for p in tmp_path.iterdir()} == before
