"""Who nervus is (ADR-0027 question 6, step 2): the keys recorded at the
first start and compared at every other, and the refusal to start empty where
nervus has run before."""

import json
import sqlite3
from pathlib import Path

import asyncssh
import pytest

from nervus.audit import AuditLog
from nervus.database import Database
from nervus.identity import IdentityRefused, Keys, check, check_history
from nervus.tls import generate_own_authority, issuer_key_path

T0 = 1_800_000_000.0


def _ssh_key(path: Path) -> Path:
    path.write_bytes(asyncssh.generate_private_key("ssh-ed25519").export_private_key())
    path.chmod(0o600)
    return path


def _issuer(folder: Path) -> Path:
    """nervus's own TLS authority, as `nervus tls-init` makes it; its issuer's key."""
    folder.mkdir(exist_ok=True)
    generate_own_authority(folder / "tls.crt", folder / "tls.key", ["nervus.example"])
    return issuer_key_path(folder / "tls.key")


class Nervus:
    def __init__(self, tmp_path: Path):
        self.tmp = tmp_path
        self.database = Database(tmp_path / "nervus.db")
        self.database.open()
        self.audit = AuditLog(tmp_path / "audit.jsonl")
        self.keys = Keys(ssh_key=_ssh_key(tmp_path / "nervus_ed25519"),
                         ssh_ca_key=_ssh_key(tmp_path / "nervus_ca_ed25519"),
                         tls_issuer=_issuer(tmp_path / "tls"))

    def start(self, **keys):
        check(self.database, Keys(**{**self.keys.__dict__, **keys}), self.audit, now=T0)

    def recorded(self):
        with self.database.transaction(write=False) as db:
            return db.execute("SELECT ssh_key, ssh_ca_key, tls_issuer FROM identity").fetchone()

    def records(self):
        return [json.loads(line) for line in self.audit.path.read_text().splitlines()]


@pytest.fixture
def nervus(tmp_path):
    return Nervus(tmp_path)


# --- recorded at the first start, compared at every other ------------------------------


def test_the_first_start_records_who_nervus_is_and_says_so_first(nervus):
    nervus.start()
    ssh, ca, issuer = nervus.recorded()
    assert ssh.startswith("SHA256:") and ca.startswith("SHA256:") and ssh != ca and issuer
    [record] = nervus.records()
    assert record["action"] == "identity_recorded" and record["tool"] == "nervus"
    assert (record["ssh_key"], record["ssh_ca_key"], record["tls_issuer"]) == (ssh, ca, issuer)


def test_a_start_with_the_same_keys_starts_and_writes_nothing(nervus):
    nervus.start()
    before = nervus.audit.path.read_bytes(), nervus.recorded()
    nervus.start()
    assert (nervus.audit.path.read_bytes(), nervus.recorded()) == before


@pytest.mark.parametrize("role, words", [
    ("ssh_ca_key", "nervus's SSH certificate authority key"),
    ("ssh_key", "nervus's SSH key"),
])
def test_an_ssh_key_not_the_databases_refuses_the_start_naming_it(nervus, role, words):
    nervus.start()
    other = _ssh_key(nervus.tmp / "other")
    with pytest.raises(IdentityRefused, match=f"{words} .* is not the one nervus's database was made with") as refused:
        nervus.start(**{role: other})
    assert "nervus-ctl restore" in str(refused.value)


def test_a_tls_issuer_not_the_databases_refuses_the_start(nervus):
    nervus.start()
    with pytest.raises(IdentityRefused, match="nervus's TLS issuer key .* is not the one"):
        nervus.start(tls_issuer=_issuer(nervus.tmp / "other-tls"))


def test_a_tls_issuer_missing_where_one_was_recorded_refuses_the_start(nervus):
    nervus.start()
    with pytest.raises(IdentityRefused, match="nervus's TLS issuer key is missing, but nervus's database was made with one"):
        nervus.start(tls_issuer=None)


def test_a_tls_issuer_where_none_was_is_recorded_not_refused(nervus):
    """`nervus tls-init --upgrade` gives a nervus serving its own certificate an
    issuer: nothing that trusted it stops trusting it."""
    nervus.start(tls_issuer=None)
    assert nervus.recorded()[2] is None
    nervus.start()
    assert nervus.recorded()[2] is not None
    assert [r["action"] for r in nervus.records()] == ["identity_recorded", "identity_issuer_recorded"]


def test_a_database_from_before_this_records_who_nervus_is_at_its_next_start(tmp_path, nervus):
    """An installation's database made before the table existed: it is added
    when opened, empty, and the next start fills it."""
    with sqlite3.connect(nervus.database.path) as db:
        db.execute("DROP TABLE identity")
    nervus.database.open()
    nervus.start()
    assert nervus.recorded() is not None


def test_a_first_start_that_cannot_be_audited_records_nothing(nervus):
    nervus.audit = AuditLog(nervus.tmp / "no/such/folder/audit.jsonl")
    with pytest.raises(IdentityRefused, match="cannot record who nervus is"):
        nervus.start()
    assert nervus.recorded() is None


# --- never an empty database where nervus has run, never a database without its log ---


def _log(path: Path, text: str) -> Path:
    path.write_text(text)
    return path


def test_no_database_beside_a_log_with_records_refuses_and_makes_none(tmp_path):
    log = _log(tmp_path / "audit.jsonl", '{"id": "x"}\n')
    with pytest.raises(IdentityRefused, match="nervus has run here before and its database is gone") as refused:
        check_history(tmp_path / "nervus.db", log)
    assert "nervus-ctl start-empty" in str(refused.value) and "nervus-ctl restore" in str(refused.value)
    assert not (tmp_path / "nervus.db").exists()


@pytest.mark.parametrize("log", [None, ""])
def test_no_database_and_no_records_is_a_new_installation(tmp_path, log):
    path = tmp_path / "audit.jsonl"
    if log is not None:
        _log(path, log)
    check_history(tmp_path / "nervus.db", path)


@pytest.mark.parametrize("log", [None, ""])
def test_a_database_that_knows_who_nervus_is_without_its_log_refuses(nervus, log):
    nervus.start()
    nervus.audit.path.unlink()
    if log is not None:
        _log(nervus.audit.path, log)
    with pytest.raises(IdentityRefused, match="nervus never removes its log") as refused:
        check_history(nervus.database.path, nervus.audit.path)
    assert "nervus-ctl start-empty" in str(refused.value)


def test_a_database_that_has_not_recorded_who_nervus_is_needs_no_log(tmp_path):
    """A database made, then nervus stopped before its first record: nothing
    shows nervus ran, so nothing is refused, and that start records it."""
    Database(tmp_path / "nervus.db").open()
    check_history(tmp_path / "nervus.db", tmp_path / "audit.jsonl")


def test_a_database_with_its_log_starts(nervus):
    nervus.start()
    check_history(nervus.database.path, nervus.audit.path)
