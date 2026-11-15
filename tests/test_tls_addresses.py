"""nervus's addresses in its certificate (ADR-0022 step 5, decision 10a):
`tls-init` names the machine's own stable addresses, and `tls-reissue` adds an
address later, from the same issuer, so a client that reaches nervus by
address keeps the root it saved when the address moves."""

import ipaddress
import json
import subprocess

import pytest
from cryptography import x509
from cryptography.x509 import verification

from nervus import __main__ as main_module
from nervus import tls
from nervus.__main__ import main
from nervus.tls import (
    ServingCertificate,
    add_addresses,
    generate_self_signed,
    issuer_key_path,
    machine_addresses,
    reissue_under_issuer,
    renewal_path,
    root_cert_path,
    serving_path,
)

# `ip -j address show` as iproute2 prints it, cut to what is read.
IP_JSON = [
    {"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1", "scope": "host"},
                                   {"family": "inet6", "local": "::1", "scope": "host"}]},
    {"ifname": "eth0", "addr_info": [
        {"family": "inet", "local": "192.0.2.5", "scope": "global", "dynamic": True},
        {"family": "inet6", "local": "2001:db8::5", "scope": "global", "dynamic": True, "mngtmpaddr": True},
        {"family": "inet6", "local": "2001:db8::abcd", "scope": "global", "temporary": True, "dynamic": True},
        {"family": "inet6", "local": "2001:db8::dead", "scope": "global", "deprecated": True},
        {"family": "inet6", "local": "fe80::5054:ff:fe12:3456", "scope": "link"},
    ]},
    {"ifname": "docker0", "addr_info": [{"family": "inet", "local": "172.17.0.1", "scope": "global"}]},
    {"ifname": "odd"},
    "junk",
]


def _ran(stdout="", returncode=0):
    return lambda *a, **k: subprocess.CompletedProcess(a, returncode, stdout=stdout, stderr="")


def test_the_machines_stable_global_addresses_are_named():
    assert machine_addresses(_ran(json.dumps(IP_JSON))) == ["192.0.2.5", "2001:db8::5", "172.17.0.1"]


@pytest.mark.parametrize("run", [_ran("", 1), _ran("not json"), _ran("{}")])
def test_an_answer_that_cannot_be_read_names_none(run):
    assert machine_addresses(run) == []


def test_without_ip_none_are_named():
    def missing(*a, **k):
        raise FileNotFoundError("ip")
    assert machine_addresses(missing) == []


@pytest.fixture
def secrets(tmp_path):
    d = tmp_path / "secrets"
    d.mkdir(mode=0o700)
    return d


def _args(secrets):
    return ["--tls-cert", str(secrets / "tls.crt"), "--tls-key", str(secrets / "tls.key")]


def _addresses(cert_path):
    san = x509.load_pem_x509_certificates(cert_path.read_bytes())[0].extensions.get_extension_for_class(
        x509.SubjectAlternativeName).value
    return [str(a) for a in san.get_values_for_type(x509.IPAddress)]


def _valid_for(cert_path, address):
    """Whether a client trusting only nervus's root accepts nervus's
    certificate for `address`, name constraints and all."""
    chain = x509.load_pem_x509_certificates(cert_path.read_bytes())
    root = x509.load_pem_x509_certificates(root_cert_path(cert_path).read_bytes())[0]
    verifier = verification.PolicyBuilder().store(verification.Store([root])).build_server_verifier(
        verification.IPAddress(ipaddress.ip_address(address)))
    try:
        verifier.verify(chain[0], chain[1:])
    except verification.VerificationError:
        return False
    return True


def test_tls_init_names_the_machines_addresses(secrets, monkeypatch, capsys):
    monkeypatch.setattr(main_module, "machine_addresses", lambda: ["192.0.2.5", "2001:db8::5"])
    assert main(["tls-init", *_args(secrets), "--name", "nervus.example"]) == 0
    assert {"192.0.2.5", "2001:db8::5"} <= set(_addresses(secrets / "tls.crt"))
    assert _valid_for(secrets / "tls.crt", "192.0.2.5")
    assert "192.0.2.5" in capsys.readouterr().err


@pytest.fixture
def made(secrets, monkeypatch):
    monkeypatch.setattr(main_module, "machine_addresses", lambda: ["192.0.2.5"])
    assert main(["tls-init", *_args(secrets), "--name", "nervus.example"]) == 0
    return secrets / "tls.crt", secrets / "tls.key"


def test_reissue_adds_an_address_a_client_with_the_saved_root_accepts(made, secrets, capsys):
    cert, key = made
    before = x509.load_pem_x509_certificates(cert.read_bytes())
    root = root_cert_path(cert).read_bytes()
    assert not _valid_for(cert, "198.51.100.7")
    assert main(["tls-reissue", *_args(secrets), "--name", "198.51.100.7"]) == 0
    after = x509.load_pem_x509_certificates(cert.read_bytes())
    assert _valid_for(cert, "198.51.100.7") and _valid_for(cert, "192.0.2.5")
    assert root_cert_path(cert).read_bytes() == root  # clients keep what they saved
    assert after[0].public_key() == before[0].public_key()  # the identity, untouched
    assert after[0].issuer == before[0].issuer and after[1:] == before[1:]
    san = lambda c: {str(n.value) for n in c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value}
    assert san(after[0]) == san(before[0]) | {"198.51.100.7"}
    assert (cert.stat().st_mode & 0o777) == 0o600
    assert "198.51.100.7" in capsys.readouterr().err


def test_reissue_refuses_a_dns_name_and_changes_nothing(made, secrets, capsys):
    cert, _ = made
    was = cert.read_bytes()
    assert main(["tls-reissue", *_args(secrets), "--name", "other.example"]) == 1
    assert "Only an address can be added" in capsys.readouterr().err
    assert cert.read_bytes() == was


def test_reissue_refuses_a_certificate_not_of_nervus_own_issuer(secrets, capsys):
    cert, key = secrets / "tls.crt", secrets / "tls.key"
    generate_self_signed(cert, key, ["nervus.example"])  # before ADR-0021
    other = secrets / "elsewhere"
    other.mkdir(mode=0o700)
    assert main(["tls-init", "--tls-cert", str(other / "tls.crt"), "--tls-key", str(other / "tls.key"),
                 "--name", "nervus.example"]) == 0
    issuer_key_path(key).write_bytes(issuer_key_path(other / "tls.key").read_bytes())
    issuer_key_path(key).chmod(0o600)
    was = cert.read_bytes()
    assert main(["tls-reissue", *_args(secrets), "--name", "198.51.100.7"]) == 1
    assert "not a certificate of nervus's own issuer" in capsys.readouterr().err
    assert cert.read_bytes() == was


def test_a_running_nervus_serves_the_reissued_certificate(made, secrets):
    cert, key = made
    serving = ServingCertificate(cert, key)
    serving.load()
    first = serving.fingerprint  # the key's, which is the identity
    add_addresses(cert, issuer_key_path(key), ["198.51.100.7"])
    assert serving.reload_if_changed() is not None
    san = serving.certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "198.51.100.7" in [str(a) for a in san.get_values_for_type(x509.IPAddress)]
    assert serving.fingerprint == first  # what a connector pins survives


def test_it_is_served_over_an_earlier_renewal(made, tmp_path, monkeypatch):
    cert, key = made
    with monkeypatch.context() as older:  # the given certificate nearing its end, as when a renewal is due
        older.setattr(tls, "SELF_SIGNED_VALIDITY_DAYS", 20)
        reissue_under_issuer(cert, issuer_key_path(key))
    (tmp_path / "state").mkdir()  # the unit's StateDirectory
    renewed = renewal_path(cert, tmp_path / "state")
    reissue_under_issuer(cert, issuer_key_path(key), dest=renewed)
    assert serving_path(cert, renewed) == renewed
    add_addresses(cert, issuer_key_path(key), ["198.51.100.7"])
    assert serving_path(cert, renewed) == cert


INSTALL = __import__("pathlib").Path(__file__).resolve().parent.parent / "docs" / "install.md"


def test_the_install_docs_reissue_command_works_as_written(made, secrets):
    import re
    import shlex
    block = re.search(r"<!-- install:tls-reissue -->\n```bash\n(.*?)\n```", INSTALL.read_text(), re.S)
    assert block, "docs/install.md has no install:tls-reissue block"
    words = shlex.split(block.group(1).replace("<nervus's new address>", "198.51.100.9"))
    assert words[words.index("runuser"):words.index("runuser") + 3] == ["runuser", "-u", "nervus"]
    cert, _ = made
    assert main([words[words.index("tls-reissue")], *words[words.index("tls-reissue") + 1:], *_args(secrets)]) == 0
    assert _valid_for(cert, "198.51.100.9")
