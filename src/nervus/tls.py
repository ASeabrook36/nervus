"""nervus's own TLS: the certificate it serves, the fingerprint people compare,
the certificate authority it makes for itself, and replacing the certificate
while nervus runs.

ADR-0006 decision 6: given a certificate and a key, nervus serves HTTPS itself,
and does not care where they came from. ADR-0008 decision 9: it can make its
own on first run, and prints the fingerprint a user compares when pairing.
ADR-0006 consequence 8: it watches the files it was given and reloads them when
they change, so a renewed certificate needs no restart. ADR-0021: what tls-init
makes is a small certificate authority of nervus's own, so that a client can be
told to trust it once without trusting nervus's key for every other name.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import subprocess
from pathlib import Path
from typing import Callable

import anyio
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from nervus import plainfile
from nervus.config import ConfigError, require_private_file

# A certificate nervus makes for itself is ECDSA P-256 and valid for 825 days.
# Neither value is settled by an ADR; both are open questions for the operator,
# with the reasons for these choices, in CURRENT_STATE.md (Phase 2, step 2).
SELF_SIGNED_VALIDITY_DAYS = 825
SELF_SIGNED_COMMON_NAME = "nervus"

# ADR-0021 C1: the root and the issuer of nervus's own authority live 20 years,
# so a client saves the root once in that time. nervus's certificate under them
# keeps SELF_SIGNED_VALIDITY_DAYS, the longest Apple's platforms accept for a
# server certificate, and is re-issued as ADR-0010 decision 3 says.
AUTHORITY_VALIDITY_DAYS = 7305

# How often nervus looks at its certificate and key for a replacement: two
# stat calls. A renewal is in use within this many seconds of being written.
WATCH_SECONDS = 5.0

# ADR-0010 decision 3: a certificate nervus issued itself is re-issued for the
# same key once this few days remain; one it did not issue is warned about from
# then on. Checked at every start and then daily. The timing is the one detail
# the operator accepted as adjustable.
RENEW_WITHIN_DAYS = 30
EXPIRY_CHECK_SECONDS = 24 * 3600


def key_fingerprint(public_key) -> str:
    """SHA-256 over a public key's SubjectPublicKeyInfo (DER), as
    colon-separated uppercase hex.

    This is what a user compares and a connector pins (ADR-0010 decision 2):
    the key, not the certificate around it. Re-issuing the certificate for the
    same key leaves it unchanged; only a new key changes it. It is not the
    certificate fingerprint a browser shows, which is why it is always printed
    labelled "public key SHA-256".
    """
    spki = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(spki).digest().hex(":").upper()


def key_pin(public_key) -> str:
    """The same SHA-256 as key_fingerprint, as curl's `--pinnedpubkey` takes it:
    `sha256//` and base64 (ADR-0024 decision 2)."""
    spki = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return "sha256//" + base64.b64encode(hashlib.sha256(spki).digest()).decode()


def _key_file_public(key_path: Path):
    try:
        key = serialization.load_pem_private_key(plainfile.read_bytes(key_path), password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise ConfigError(f"cannot read a private key from {key_path}: {exc}") from exc
    return key.public_key()


def key_file_fingerprint(key_path: Path) -> str:
    """The public-key fingerprint of the private key in `key_path`, which is
    nervus's identity whatever certificate currently carries it."""
    return key_fingerprint(_key_file_public(key_path))


def key_file_pin(key_path: Path) -> str:
    """The same key as key_file_fingerprint, as key_pin gives it: the form the
    lines nervus hands out carry it (ADR-0032 question 4)."""
    return key_pin(_key_file_public(key_path))


def fingerprint(cert_pem: bytes) -> str:
    """The public-key fingerprint (key_fingerprint) of the first certificate in
    `cert_pem`. The first certificate in a file is the one nervus presents; any
    after it are the chain."""
    try:
        cert = x509.load_pem_x509_certificates(cert_pem)[0]
    except ValueError as exc:
        raise ConfigError(f"not a PEM certificate: {exc}") from exc
    return key_fingerprint(cert.public_key())


def certificate_fingerprint(cert_pem: bytes) -> str:
    """SHA-256 over the first certificate in `cert_pem` (DER), as
    colon-separated uppercase hex: the fingerprint a browser shows.

    Not what a user compares when pairing, nor what a connector pins: that is
    the public key's (key_fingerprint), which survives a re-issue. This one
    changes whenever the certificate does. It exists because Safari and
    Firefox show only this one, and the operator compares it before accepting
    the UI's certificate (ADR-0012 decision 7a). Always printed labelled
    "certificate SHA-256", so the two are never mistaken for each other.
    """
    try:
        cert = x509.load_pem_x509_certificates(cert_pem)[0]
    except ValueError as exc:
        raise ConfigError(f"not a PEM certificate: {exc}") from exc
    return cert.fingerprint(hashes.SHA256()).hex(":").upper()


def is_loopback(host: str) -> bool:
    """Whether binding `host` keeps nervus on this machine. Only `localhost`
    and loopback addresses count; any other name might resolve anywhere, so it
    is treated as off loopback."""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def default_names(bind_host: str) -> list[str]:
    """The names a certificate nervus makes for itself is valid for.

    Loopback, this machine's hostname, and the bind address when it is a
    specific one. A client that pins the certificate (ADR-0008) never checks
    them; a client that trusts the certificate as it would a CA's does, and
    can only reach nervus by one of these.
    """
    names = ["localhost", "127.0.0.1", "::1"]
    for name in (socket.gethostname(), bind_host):
        if not name or not name.isascii():
            continue
        try:
            if ipaddress.ip_address(name).is_unspecified:
                continue  # 0.0.0.0 or ::, every address, which no client connects to by that name
        except ValueError:
            pass
        names.append(name)
    return list(dict.fromkeys(names))


def machine_addresses(run: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> list[str]:
    """This machine's own stable addresses, for nervus's certificate (ADR-0022
    10a), so a client or a VM can reach nervus by address where no name
    resolves. Read from `ip -j address` (Linux's iproute2): global ones only,
    never loopback or link-local, and never an IPv6 privacy address, which
    changes by itself. Where there is no `ip`, none: names still work."""
    try:
        done = run(["ip", "-j", "address", "show"], capture_output=True, text=True, timeout=10)
        interfaces = json.loads(done.stdout) if done.returncode == 0 else []
    except (OSError, subprocess.SubprocessError, ValueError):
        return []
    found = []
    for interface in interfaces if isinstance(interfaces, list) else []:
        for entry in (interface.get("addr_info") or []) if isinstance(interface, dict) else []:
            if not isinstance(entry, dict) or entry.get("scope") != "global":
                continue
            if entry.get("temporary") or entry.get("deprecated") or entry.get("tentative") or entry.get("dadfailed"):
                continue
            try:
                ip = ipaddress.ip_address(entry.get("local", ""))
            except ValueError:
                continue
            if not (ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast):
                found.append(str(ip))
    return list(dict.fromkeys(found))


def add_addresses(cert_path: Path, issuer_key: Path, addresses: list[str]) -> list[str]:
    """`nervus tls-reissue` (ADR-0022 10a): nervus's certificate again, from
    the same issuer, for the same key, with `addresses` added to its names, so
    a client keeps the root it saved when nervus's address moves. Only
    addresses: the issuer is limited to the DNS names it was made for, so a
    new name could never be vouched for. Everything else is kept: subject,
    key, the other names and extensions, the issuer and root after it.
    Written beside `cert_path` and renamed over it, so a running nervus loads
    it within seconds. Returns every name the new certificate is for."""
    new: list[str] = []
    for text in addresses:
        try:
            new.append(str(ipaddress.ip_address(text)))
        except ValueError:
            raise ConfigError(
                f"{text!r} is not an address. Only an address can be added: nervus's issuer is limited to "
                f"the DNS names tls-init was given (ADR-0021 B1)"
            ) from None
    require_private_file(issuer_key)
    signing_key = serialization.load_pem_private_key(plainfile.read_bytes(issuer_key), password=None)
    certs = x509.load_pem_x509_certificates(plainfile.read_bytes(cert_path))
    cert = certs[0]
    if len(certs) < 2 or certs[1].subject != cert.issuer or _spki(certs[1].public_key()) != _spki(
            signing_key.public_key()):
        raise ConfigError(f"{cert_path} is not a certificate of nervus's own issuer {issuer_key}; nothing changed")
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    had = [str(n.value) for n in san]
    names = list(dict.fromkeys(had + new))
    not_before = _not_before()
    builder = _builder(cert.subject, cert.issuer, cert.public_key(), not_before,
                       not_before + datetime.timedelta(days=SELF_SIGNED_VALIDITY_DAYS))
    for extension in cert.extensions:
        if isinstance(extension.value, x509.SubjectAlternativeName):
            builder = builder.add_extension(x509.SubjectAlternativeName(_subject_alt_names(names)), extension.critical)
        elif not isinstance(extension.value, x509.SubjectKeyIdentifier):  # _builder adds it
            builder = builder.add_extension(extension.value, extension.critical)
    reissued = builder.sign(signing_key, hashes.SHA256())
    staging = cert_path.with_name(cert_path.name + ".reissue")
    if staging.exists() or staging.is_symlink():
        staging.unlink()  # left by an attempt that died; it is ours alone
    _write_new_private_file(staging, _pem(reissued, *certs[1:]))
    os.replace(staging, cert_path)
    return names


_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def certificate_name(text: str) -> str:
    """`text` as a name for a certificate nervus makes, or ConfigError.

    An IP address, or a DNS name of ASCII letters, digits and hyphens,
    lowercased: the forms a browser compares with the address it was given.
    Anything else, a URL or a name with a space in it, would be written into
    the certificate as given and then match nothing. A certificate's names
    stay as long as its key does, since re-issuing keeps them (ADR-0012
    decision 7b), so a wrong one is refused rather than kept.
    """
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        pass
    name = text.lower()
    if len(name) > 253 or not all(_DNS_LABEL.fullmatch(label) for label in name.split(".")):
        raise ConfigError(f"{text!r} is not a DNS name or an IP address")
    return name


def _subject_alt_names(names: list[str]) -> list[x509.GeneralName]:
    out: list[x509.GeneralName] = []
    for name in names:
        try:
            out.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            out.append(x509.DNSName(name))
    return out


def root_cert_path(cert_path: Path) -> Path:
    """Where tls-init puts the root of nervus's own authority, beside its
    certificate: the one file a client is told to trust (ADR-0021 E2, F1). Not
    a secret, but written 0600 like everything in nervus's secrets."""
    return cert_path.with_name(f"{cert_path.stem}-root{cert_path.suffix}")


def issuer_cert_path(cert_path: Path) -> Path:
    """The issuer's certificate, beside nervus's. It is also in nervus's chain."""
    return cert_path.with_name(f"{cert_path.stem}-issuer{cert_path.suffix}")


def issuer_key_path(key_path: Path) -> Path:
    """The issuer's key, beside nervus's: what nervus re-issues its certificate
    with. Limited to nervus's DNS names, it can vouch for no other name (ADR-0021
    A1), but for any address: the limit cannot name addresses (B1), so whoever
    holds this key could impersonate a site reached by address (procedure 056, C5)."""
    return key_path.with_name(f"{key_path.stem}-issuer{key_path.suffix}")


def renewal_path(cert_path: Path, state_dir: Path) -> Path:
    """Where nervus writes a renewal of the certificate at `cert_path`: under its
    state directory, which the unit makes writable, since it leaves the secrets
    directory read-only to the service (ADR-0021 D1). In the unit that is
    /var/lib/nervus/tls/, beside the database."""
    return state_dir / "tls" / cert_path.name


def serving_path(cert_path: Path, renewed: Path | None) -> Path:
    """The file nervus serves: `renewed` when it renews the certificate at
    `cert_path` (the same key, from the same issuer, and valid for longer),
    and otherwise `cert_path` itself.

    So a renewal is served across restarts, while a certificate someone puts
    in place of the given one later, or a stray file, is never shadowed by an
    old renewal. nervus-ctl reads the same file, so the fingerprint it gives
    for the browser is the one the browser is shown.
    """
    if renewed is None:
        return cert_path
    try:
        given = x509.load_pem_x509_certificates(plainfile.read_bytes(cert_path))[0]
        newer = x509.load_pem_x509_certificates(plainfile.read_bytes(renewed))[0]
    except (OSError, ValueError):
        return cert_path
    if (
        _spki(newer.public_key()) == _spki(given.public_key())
        and newer.issuer == given.issuer
        and newer.not_valid_after_utc > given.not_valid_after_utc
    ):
        return renewed
    return cert_path


def _spki(public_key) -> bytes:
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _key_usage(*, signs_certificates: bool) -> x509.KeyUsage:
    """A CA's usage signs certificates; nervus's own signs TLS handshakes."""
    return x509.KeyUsage(
        digital_signature=not signs_certificates, content_commitment=False, key_encipherment=False,
        data_encipherment=False, key_agreement=False, key_cert_sign=signs_certificates,
        crl_sign=signs_certificates, encipher_only=False, decipher_only=False,
    )


def _pem(*certs: x509.Certificate) -> bytes:
    return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs)


def _private_pem(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def generate_own_authority(
    cert_path: Path, key_path: Path, names: list[str], validity_days: int = SELF_SIGNED_VALIDITY_DAYS
) -> list[str]:
    """Make nervus's own certificate authority and nervus's certificate under it
    (ADR-0021 A1, B1, C1), all written 0600, and return the names it is for.

    - A root, which signs the issuer once. Its key is made here, used for that
      one signature, and never written anywhere, so nothing can ever sign with
      it again. Clients trust the root (root_cert_path).
    - An issuer, limited by a name constraint to nervus's DNS names, whose key
      is kept (issuer_key_path) to re-issue nervus's certificate. A client
      checks the limit, so that key cannot vouch for any other DNS name; for
      addresses, see below.
    - nervus's certificate, for its DNS names and addresses, presented with the
      issuer and the root after it: the root, so tools/nervus-trust can read it
      from the handshake (ADR-0021 E2).

    `localhost` is never named: no client elsewhere reaches nervus by it, and
    allowing it would let the issuer vouch for every client's own local
    services (B1). Addresses go in nervus's certificate but not in the limit,
    which Claude Code's TLS library cannot apply to addresses (procedure 030).
    The names are fixed once made, as ADR-0010 decision 4 says of the key.

    Never replaces any of the five files, and leaves none behind if it fails.
    """
    files = [cert_path, key_path, issuer_cert_path(cert_path), issuer_key_path(key_path), root_cert_path(cert_path)]
    for path in files:
        if path.exists() or path.is_symlink():
            raise ConfigError(f"refusing to replace existing {path}")

    dns, ips = _split_names(names)
    not_before = _not_before()
    root, issuer, issuer_key = _make_authority(dns, not_before)
    key = ec.generate_private_key(ec.SECP256R1())
    cert = _issue(issuer, issuer_key, key.public_key(), dns + ips, not_before, validity_days)
    _write_all([
        (key_path, _private_pem(key)),
        (issuer_key_path(key_path), _private_pem(issuer_key)),
        (root_cert_path(cert_path), _pem(root)),
        (issuer_cert_path(cert_path), _pem(issuer)),
        (cert_path, _pem(cert, issuer, root)),
    ])
    return dns + ips


def upgrade_to_own_authority(cert_path: Path, key_path: Path, names: list[str] = ()) -> list[str]:
    """`tls-init --upgrade` (ADR-0021 G1): put a certificate `tls-init` made
    before ADR-0021, self-signed, under nervus's own authority, keeping its key.

    The key is the identity (ADR-0010 decision 2), so its fingerprint, and
    anything pinned to it, survive; only the certificate around it changes,
    and browsers that accepted the old one are asked once more. The names are
    the old certificate's, without `localhost`, plus `names`: the issuer's
    limit is set now, so this is when names can be added. Makes the issuer and
    root as tls-init does, then replaces the certificate in one rename.

    Refuses a certificate nervus did not make, and refuses if any of the new
    files exists, so it runs once. A failure leaves the old install as it was.
    """
    new_files = [issuer_key_path(key_path), root_cert_path(cert_path), issuer_cert_path(cert_path)]
    for path in new_files:
        if path.exists() or path.is_symlink():
            raise ConfigError(f"refusing to replace existing {path}: is this nervus already upgraded?")
    try:
        old = x509.load_pem_x509_certificates(plainfile.read_bytes(cert_path))[0]
        key = serialization.load_pem_private_key(plainfile.read_bytes(key_path), password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise ConfigError(f"cannot read nervus's certificate {cert_path} and key {key_path}: {exc}") from exc
    own_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, SELF_SIGNED_COMMON_NAME)])
    try:
        old.verify_directly_issued_by(old)
        made_by_nervus = old.subject == own_name and _spki(old.public_key()) == _spki(key.public_key())
    except Exception:
        made_by_nervus = False
    if not made_by_nervus:
        raise ConfigError(
            f"{cert_path} is not a certificate tls-init made for this key, self-signed, so it is "
            "not nervus's to upgrade"
        )
    try:
        san = old.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        had = san.get_values_for_type(x509.DNSName) + [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        had = []
    dns, ips = _split_names([*had, *names])
    not_before = _not_before()
    root, issuer, issuer_key = _make_authority(dns, not_before)
    cert = _issue(issuer, issuer_key, key.public_key(), dns + ips, not_before, SELF_SIGNED_VALIDITY_DAYS)
    written = _write_all([
        (issuer_key_path(key_path), _private_pem(issuer_key)),
        (root_cert_path(cert_path), _pem(root)),
        (issuer_cert_path(cert_path), _pem(issuer)),
    ])
    staging = cert_path.with_name(cert_path.name + ".upgrade")
    try:
        if staging.exists() or staging.is_symlink():
            staging.unlink()  # left by an attempt that died; it is ours alone
        _write_new_private_file(staging, _pem(cert, issuer, root))
        os.replace(staging, cert_path)
    except BaseException:
        for path in [*written, staging]:
            path.unlink(missing_ok=True)
        raise
    return dns + ips


def _split_names(names: list[str]) -> tuple[list[str], list[str]]:
    """The DNS names and the addresses a certificate of nervus's own authority
    is for. Never `localhost` (ADR-0021 B1); at least one DNS name, since the
    issuer is limited to them."""
    dns, ips = [], []
    for name in names:
        try:
            ips.append(str(ipaddress.ip_address(name)))
            continue
        except ValueError:
            pass
        try:
            name = certificate_name(name)
        except ConfigError:
            continue  # a hostname no client could use, such as one with an underscore
        if name != "localhost" and not name.endswith(".localhost"):
            dns.append(name)
    dns, ips = list(dict.fromkeys(dns)), list(dict.fromkeys(ips))
    if not dns:
        raise ConfigError(
            "nervus's certificate needs at least one DNS name for nervus, which its issuer is "
            "limited to (ADR-0021 B1); give one with --name"
        )
    return dns, ips


def _not_before() -> datetime.datetime:
    # An hour early, so a client whose clock runs a little behind the server's
    # does not see a certificate that is not valid yet.
    return datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)


def _builder(subject, issuer, public, not_before, until) -> x509.CertificateBuilder:
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(until)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public), critical=False)
    )


def _make_authority(dns: list[str], not_before: datetime.datetime):
    """A root, used here to sign the issuer and then dropped, never written;
    and an issuer limited to `dns`. Returns the root, the issuer and the
    issuer's key."""
    until = not_before + datetime.timedelta(days=AUTHORITY_VALIDITY_DAYS)
    # Each installation's root and issuer are named apart, so a client that
    # trusts two installations never has two roots of the same name to choose from.
    tag = secrets.token_hex(4)
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"nervus root {tag}")])
    root = (
        _builder(root_name, root_name, root_key.public_key(), not_before, until)
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(_key_usage(signs_certificates=True), critical=True)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False)
        .sign(root_key, hashes.SHA256())
    )
    issuer_key = ec.generate_private_key(ec.SECP256R1())
    issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"nervus issuer {tag}")])
    issuer = (
        _builder(issuer_name, root_name, issuer_key.public_key(), not_before, until)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_key_usage(signs_certificates=True), critical=True)
        .add_extension(
            x509.NameConstraints(permitted_subtrees=[x509.DNSName(n) for n in dns], excluded_subtrees=None),
            critical=True,
        )
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False)
        .sign(root_key, hashes.SHA256())
    )
    del root_key  # its one signature is made; it is never written
    return root, issuer, issuer_key


def _issue(issuer, issuer_key, public_key, names: list[str], not_before, validity_days: int) -> x509.Certificate:
    """nervus's certificate for `public_key`, from its issuer. No common name: a
    subject that reads as a host name is checked against the issuer's limit
    too, so the names live only in the alternative names."""
    own = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, SELF_SIGNED_COMMON_NAME)])
    return (
        _builder(own, issuer.subject, public_key, not_before, not_before + datetime.timedelta(days=validity_days))
        .add_extension(x509.SubjectAlternativeName(_subject_alt_names(names)), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_key_usage(signs_certificates=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
        .sign(issuer_key, hashes.SHA256())
    )


def _write_all(files: list[tuple[Path, bytes]]) -> list[Path]:
    """Write each new file, 0600, never replacing one; if any fails, remove the
    ones this call wrote, so no part of an authority is left behind."""
    written: list[Path] = []
    try:
        for path, data in files:
            _write_new_private_file(path, data)
            written.append(path)
    except BaseException:
        for path in written:
            path.unlink()
        raise
    return written


def _write_new_private_file(path: Path, data: bytes) -> None:
    """Create `path` holding `data`, mode 0600, refusing to replace anything.

    O_EXCL makes "only if it does not exist" one step, so a file, or a
    symlink, that appeared since the caller looked is never overwritten. The
    mode is set again after creation because the umask can remove bits from
    the one passed to open, never add them.
    """
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise ConfigError(f"refusing to replace existing {path}") from exc
    except OSError as exc:
        raise ConfigError(f"cannot create {path}: {exc}") from exc
    with os.fdopen(fd, "wb") as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(data)
        f.flush()
        os.fsync(f.fileno())


def generate_self_signed(
    cert_path: Path, key_path: Path, names: list[str], validity_days: int = SELF_SIGNED_VALIDITY_DAYS
) -> None:
    """Make a new key and a self-signed certificate for `names`, both written 0600.

    Never replaces either file. Replacing nervus's certificate invalidates every
    pairing made against it (ADR-0008 decision 9), so it must never happen by
    accident; deleting both files and starting again is the deliberate way.
    """
    for path in (cert_path, key_path):
        if path.exists() or path.is_symlink():
            raise ConfigError(f"refusing to replace existing {path}")

    key = ec.generate_private_key(ec.SECP256R1())
    public = key.public_key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, SELF_SIGNED_COMMON_NAME)])
    # An hour early, so a client whose clock runs a little behind the server's
    # does not see a certificate that is not valid yet.
    not_before = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(public)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_before + datetime.timedelta(days=validity_days))
        .add_extension(x509.SubjectAlternativeName(_subject_alt_names(names)), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        # RFC 5280 asks for the subject key identifier in end-entity
        # certificates; a self-signed one may omit the authority identifier,
        # which costs nothing to include. tests/test_tls.py verifies with
        # VERIFY_X509_STRICT, the default from Python 3.13.
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(public), critical=False)
        .sign(key, hashes.SHA256())
    )

    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    _write_new_private_file(key_path, key_pem)
    try:
        _write_new_private_file(cert_path, cert.public_bytes(serialization.Encoding.PEM))
    except BaseException:
        key_path.unlink()  # this call created it; leave no half of a pair behind
        raise


def reissue_self_signed(cert_path: Path, key_path: Path, dest: Path | None = None) -> None:
    """Re-issue a self-signed certificate for the same key: the same subject,
    names and extensions, a new serial number and new dates, 825 days from an
    hour ago. The key is untouched, so its fingerprint, and every pairing made
    against it, survive (ADR-0010 decisions 2 and 3). What tls-init made
    before ADR-0021, and test fixtures, still have this shape. Written to
    `dest`, or over `cert_path` when none is given.
    """
    key = serialization.load_pem_private_key(plainfile.read_bytes(key_path), password=None)
    _reissue(cert_path, dest or cert_path, key)


def reissue_under_issuer(cert_path: Path, issuer_key: Path, dest: Path | None = None) -> None:
    """Re-issue nervus's certificate under its own issuer (ADR-0021 A1): the
    same subject, key, names and extensions, signed again by the issuer, and
    presented with the same issuer and root after it. Written to `dest`, or
    over `cert_path` when none is given."""
    require_private_file(issuer_key)
    _reissue(cert_path, dest or cert_path,
             serialization.load_pem_private_key(plainfile.read_bytes(issuer_key), password=None))


def _reissue(source: Path, dest: Path, signing_key) -> None:
    """The first certificate in `source`, re-issued: a new serial number and
    new dates, 825 days from an hour ago, signed by `signing_key`; any chain
    after it kept as it was.

    The new file is written beside `dest`, 0600, and renamed over it, so a
    reader never sees half a file. `dest`'s directory is made, 0700, if it is
    missing, but not its parent: that is the state directory, the unit's to make.
    """
    certs = x509.load_pem_x509_certificates(plainfile.read_bytes(source))
    cert = certs[0]
    not_before = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
    builder = (
        x509.CertificateBuilder()
        .subject_name(cert.subject)
        .issuer_name(cert.issuer)
        .public_key(cert.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_before + datetime.timedelta(days=SELF_SIGNED_VALIDITY_DAYS))
    )
    for extension in cert.extensions:
        builder = builder.add_extension(extension.value, extension.critical)
    renewed = builder.sign(signing_key, cert.signature_hash_algorithm)
    try:
        dest.parent.mkdir(mode=0o700, exist_ok=True)
    except OSError as exc:
        raise ConfigError(f"cannot make {dest.parent}: {exc}") from exc
    staging = dest.with_name(dest.name + ".reissue")
    if staging.exists() or staging.is_symlink():
        staging.unlink()  # left by an attempt that died; it is ours alone
    _write_new_private_file(staging, _pem(renewed, *certs[1:]))
    os.replace(staging, dest)


class ServingCertificate:
    """The certificate and key nervus serves HTTPS with, loaded into an SSLContext,
    and replaceable while nervus runs.

    The context is Python's TLS server defaults plus the certificate and key,
    which is the context uvicorn builds from a certificate and key at its own
    defaults (tests/test_tls.py compares the two).

    uvicorn gives one context to the listening socket at startup, and the
    socket keeps it. Loading a new certificate into that context in place is
    unsafe: OpenSSL takes the certificate and the key in two steps, and a
    failure between them (a key not written yet, a mismatched pair) leaves a
    certificate with no usable key, which fails every handshake after it.

    So each load builds a complete new context, and only one that loaded
    cleanly becomes current. The listening context's sni_callback, which
    OpenSSL calls early in every handshake whether or not the client sent a
    server name, moves the new connection onto the current context. A
    connection already open keeps the one it was made with, so a reload never
    cuts one off.
    """

    def __init__(self, cert_path: Path, key_path: Path, renewed_path: Path | None = None):
        """`renewed_path` is where a renewal is written and, once there, served
        from (serving_path, ADR-0021 D1). Without one, a renewal replaces
        `cert_path` in place."""
        self.cert_path = cert_path
        self.key_path = key_path
        self.renewed_path = renewed_path
        self.serving = cert_path  # the file loaded: cert_path or its renewal
        self.context: ssl.SSLContext | None = None
        self.fingerprint: str | None = None
        self.not_after: datetime.datetime | None = None
        self.certificate: x509.Certificate | None = None
        self._attempted: tuple | None = None

    def _stat(self) -> tuple:
        out = []
        for path in (self.cert_path, self.key_path, *([self.renewed_path] if self.renewed_path else [])):
            try:
                s = os.stat(path)
            except OSError:
                out.append(None)
            else:
                out.append((s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_mode))
        return tuple(out)

    def load(self) -> None:
        """Load the files into a new context. If they cannot be used, raise
        ConfigError and leave what was loaded before untouched.

        The key must be 0600, as every secret nervus reads must be.
        """
        before = self._stat()
        self._attempted = before
        serving = serving_path(self.cert_path, self.renewed_path)
        try:
            require_private_file(self.key_path)
            cert_pem = plainfile.read_bytes(serving)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(serving, self.key_path)
        except OSError as exc:  # ssl.SSLError included: a bad file, or a key that does not match
            raise ConfigError(
                f"cannot serve TLS with certificate {serving} and key {self.key_path}: {exc}"
            ) from exc
        found = fingerprint(cert_pem)
        certificate = x509.load_pem_x509_certificates(cert_pem)[0]
        # The certificate is read twice, once here and once by OpenSSL. If the
        # files changed in between, the fingerprint might not be the
        # certificate's, so nothing is taken from this attempt.
        if self._stat() != before:
            raise ConfigError(f"{serving} or {self.key_path} changed while being read")
        self.context, self.fingerprint, self.certificate = context, found, certificate
        self.serving = serving
        self.not_after = certificate.not_valid_after_utc

    def describe(self) -> str:
        return f"public key SHA-256 {self.fingerprint}, certificate valid until {self.not_after:%Y-%m-%d}"

    def listening_context(self) -> ssl.SSLContext:
        """The context for the listening socket: the one loaded first, moving
        each new handshake onto whichever context is current."""
        listener = self.context

        def select(connection, server_name, context):
            if self.context is not context:
                connection.context = self.context

        listener.sni_callback = select
        return listener

    def reload_if_changed(self) -> str | None:
        """Load the files again if they changed since the last attempt.

        Returns a line for the console, or None when nothing changed. A failed
        attempt is not repeated until the files change again; a renewal tool
        that writes the certificate and then the key changes them twice, so
        the second write is tried.
        """
        if self._stat() == self._attempted:
            return None
        try:
            self.load()
        except Exception as exc:  # whatever happened, keep serving what works
            return (
                f"TLS certificate {self.cert_path} or key {self.key_path} changed but cannot "
                f"be used, so nervus still serves the one with {self.describe()}: {exc}"
            )
        return f"reloaded the TLS certificate {self.serving}: {self.describe()}"

    def _own_signer(self) -> Callable[[], None] | None:
        """How to re-issue this certificate, if it is nervus's own; else None.

        Only nervus's own are its to re-issue (ADR-0010 decision 3):
        - what `nervus tls-init` makes since ADR-0021: signed by the issuer
          next in its chain, whose key nervus holds beside its own;
        - what it made before: self-signed by the key nervus serves with, and
          named as nervus names its own.
        A certificate someone made and gave to nervus, self-signed or under an
        authority, is theirs, so it is warned about and never rewritten.
        """
        cert = self.certificate
        if cert.issuer == cert.subject:
            own_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, SELF_SIGNED_COMMON_NAME)])
            try:
                cert.verify_directly_issued_by(cert)
            except Exception:
                return None
            if cert.subject != own_name:
                return None
            return lambda: reissue_self_signed(self.serving, self.key_path, self._renewal_dest())
        key_path = issuer_key_path(self.key_path)
        try:
            chain = x509.load_pem_x509_certificates(plainfile.read_bytes(self.serving))
            if len(chain) < 2 or chain[0] != cert or not key_path.exists():
                return None
            require_private_file(key_path)
            issuer_key = serialization.load_pem_private_key(plainfile.read_bytes(key_path), password=None)
            if _spki(issuer_key.public_key()) != _spki(chain[1].public_key()):
                return None
            cert.verify_directly_issued_by(chain[1])
        except Exception:
            return None
        return lambda: reissue_under_issuer(self.serving, key_path, self._renewal_dest())

    def _renewal_dest(self) -> Path:
        return self.renewed_path or self.cert_path

    def renew_if_due(self) -> str | None:
        """ADR-0010 decision 3, checked at start and daily. Returns a line for
        the console, or None while more than RENEW_WITHIN_DAYS remain.

        A certificate nervus made is re-issued for the same key, and loaded at
        once. Any other, a self-signed one someone gave nervus included, is not
        nervus's to renew, so it is warned about instead; the file watch loads
        its replacement.
        """
        now = datetime.datetime.now(datetime.timezone.utc)
        left = self.not_after - now
        if left > datetime.timedelta(days=RENEW_WITHIN_DAYS):
            return None
        when = f"{self.not_after:%Y-%m-%d}, in {max(left.days, 0)} days"
        reissue = self._own_signer()
        if reissue is None:
            return (
                f"WARNING: TLS certificate {self.serving} expires {when}. nervus cannot renew "
                "a certificate it did not issue; replace the file, and nervus will load it"
            )
        try:
            reissue()
            self.load()
        except Exception as exc:  # keep serving what works; tried again tomorrow
            return (
                f"WARNING: TLS certificate {self.serving} expires {when}. Re-issuing it for "
                f"the same key failed, and is retried daily: {exc}"
            )
        return f"re-issued the TLS certificate {self.serving} for the same key: {self.describe()}"

    def check_now(self) -> list[str]:
        """What SIGHUP does (ADR-0010 decision 5): the file check and the
        expiry check, at once rather than on their schedules. Always returns at
        least one line, so a signal is never answered with silence."""
        line = self.reload_if_changed()
        lines = [line or f"certificate files unchanged; serving {self.describe()}"]
        renewal = self.renew_if_due()
        if renewal is not None:
            lines.append(renewal)
        return lines

    async def watch(
        self,
        report: Callable[[str], None],
        interval: float = WATCH_SECONDS,
        expiry_every: float = EXPIRY_CHECK_SECONDS,
    ) -> None:
        """Reload the certificate whenever its files change, and check its
        expiry daily, reporting each attempt. Runs until cancelled."""
        checked = anyio.current_time()
        while True:
            await anyio.sleep(interval)
            line = self.reload_if_changed()
            if line is not None:
                report(line)
            if anyio.current_time() - checked >= expiry_every:
                checked = anyio.current_time()
                line = self.renew_if_due()
                if line is not None:
                    report(line)
