"""Making a backup (ADR-0027 step 1): what it holds, that only the recovery
key opens it, that nothing is written in clear, and what is kept."""

import hashlib
import io
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import tarfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import nervus
from nervus import backup
from nervus.audit import AuditLog
from nervus.backup import BackupFailed, Pieces, backup_name, make_backup, made_at, prune, recipient, to_keep
from nervus.backup import drop_kept_for, keep_for_upgrade, kept, kept_name, only_kept_for
from nervus.database import Database

NOW = datetime(2026, 10, 28, 16, 30, tzinfo=timezone.utc)

needs_age = pytest.mark.skipif(
    shutil.which("age") is None or shutil.which("age-keygen") is None,
    reason="age is not installed here; these tests run it",
)


def _key_pair(path: Path) -> str:
    """A recovery key pair: the private half written to `path`, the public half
    returned."""
    subprocess.run(["age-keygen", "-o", str(path)], check=True, capture_output=True)
    return next(line.split(": ")[1] for line in path.read_text().splitlines() if line.startswith("# public key"))


def _secret(path: Path, text: str, mode=0o600) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(mode)
    return path


class Install:
    """A nervus installation's files, laid out as the unit lays them out."""

    def __init__(self, root: Path):
        self.root = root
        opt, state, log = root / "opt/nervus", root / "var/lib/nervus", root / "var/log/nervus"
        secrets = opt / "secrets"
        state.mkdir(parents=True)
        log.mkdir(parents=True)
        self.database = Database(state / "nervus.db")
        self.database.open()
        self.audit = AuditLog(log / "audit.jsonl")
        self.audit.record_operator("unlock", {"target": "all"})
        dropin = _secret(root / "etc/systemd/system/nervus.service.d/instance.conf", "[Service]\n", 0o644)
        self.pieces = Pieces(
            ssh_key=_secret(secrets / "nervus_ed25519", "SSH KEY SECRET\n"),
            ssh_ca_key=_secret(secrets / "nervus_ca_ed25519", "CA KEY SECRET\n"),
            tokens=_secret(secrets / "tokens.yaml", "tokens: [{token: TOKEN SECRET}]\n"),
            hosts=_secret(opt / "hosts.yaml", "hosts: []\n", 0o644),
            switches=_secret(state / "switches.yaml", "lockdown: false\ndisabled: []\n"),
            database=self.database.path,
            audit_log=self.audit.path,
            ssh_key_pub=_secret(secrets / "nervus_ed25519.pub", "ssh-ed25519 AAAA nervus\n", 0o644),
            ssh_ca_key_pub=_secret(secrets / "nervus_ca_ed25519.pub", "ssh-ed25519 BBBB nervus-ca\n", 0o644),
            known_hosts=_secret(secrets / "known_hosts", "host ssh-ed25519 CCCC\n"),
            tls_cert=_secret(secrets / "tls.crt", "TLS CERT\n"),
            tls_key=_secret(secrets / "tls.key", "TLS KEY SECRET\n"),
            tls_issuer_cert=_secret(secrets / "tls-issuer.crt", "ISSUER CERT\n"),
            tls_issuer_key=_secret(secrets / "tls-issuer.key", "ISSUER KEY SECRET\n"),
            tls_root_cert=_secret(secrets / "tls-root.crt", "ROOT CERT\n"),
            tls_renewed=_secret(state / "tls/tls.crt", "RENEWED CERT\n"),
            proxmox=_secret(secrets / "proxmox.yaml", "secret: PROXMOX SECRET\n"),
            proxmox_ca=_secret(secrets / "pve-root-ca.pem", "PVE CA\n", 0o644),
            drop_ins=(dropin,),
        )
        # What a backup leaves out: clients' files in passing, and code.
        _secret(state / "exports/abc/report.txt", "EXPORTED FILE\n")
        _secret(state / "uploads/def", "UPLOADED FILE\n")
        _secret(opt / "transfer/moved.txt", "TRANSFERRED FILE\n")
        _secret(opt / "src/nervus/__init__.py", "CODE\n")
        self.folder = state / "backups"


@pytest.fixture
def install(tmp_path):
    return Install(tmp_path / "root")


@pytest.fixture
def key(tmp_path):
    """(private half's file, public half)."""
    path = tmp_path / "recovery.key"
    return path, _key_pair(path)


def _open(path: Path, identity: Path) -> dict[str, bytes]:
    """A backup opened with the standard age tool: each member's bytes, by name."""
    done = subprocess.run(["age", "--decrypt", "--identity", str(identity), str(path)], capture_output=True)
    if done.returncode != 0:
        raise RuntimeError(done.stderr.decode())
    with tarfile.open(fileobj=io.BytesIO(done.stdout), mode="r:gz") as archive:
        return {m.name: archive.extractfile(m).read() for m in archive.getmembers() if m.isfile()}


def _records(log: Path) -> list[dict]:
    return [json.loads(line) for line in log.read_text().splitlines()]


# --- what it holds ---------------------------------------------------------------


@needs_age
def test_it_holds_every_listed_piece_and_nothing_it_leaves_out(install, key):
    made = make_backup(install.pieces, key[1], install.folder, install.audit, now=NOW)
    opened = _open(made.path, key[0])
    roles = {role for role, _ in install.pieces.files()} | {"database", "audit_log"}
    assert set(opened) == {"manifest.json"} | {f"pieces/{role}" for role in roles}
    for role, path in install.pieces.files():
        assert opened[f"pieces/{role}"] == path.read_bytes(), role
    every = b"".join(opened.values())
    for left_out in (b"EXPORTED FILE", b"UPLOADED FILE", b"TRANSFERRED FILE", b"CODE"):
        assert left_out not in every


@needs_age
def test_its_manifest_names_each_piece_with_its_path_mode_and_hash(install, key):
    made = make_backup(install.pieces, key[1], install.folder, install.audit, now=NOW)
    opened = _open(made.path, key[0])
    manifest = json.loads(opened["manifest.json"])
    assert manifest["format"] == 1 and manifest["schema_version"] == 1
    assert manifest["made_at"] == NOW.timestamp()
    listed = {p["role"]: p for p in manifest["pieces"]}
    assert set(listed) == {name[len("pieces/"):] for name in opened if name.startswith("pieces/")}
    for role, piece in listed.items():
        assert piece["sha256"] == hashlib.sha256(opened[f"pieces/{role}"]).hexdigest(), role
        assert piece["size"] == len(opened[f"pieces/{role}"])
    assert listed["ssh_ca_key"]["path"] == str(install.pieces.ssh_ca_key)
    assert listed["ssh_ca_key"]["mode"] == 0o600 and listed["hosts"]["mode"] == 0o644


@needs_age
def test_its_manifest_names_the_release_nervus_says_it_is(install, key, monkeypatch):
    # ADR-0029 question 2a: the release, as nervus.__version__ reads it, the one reader of the number. The number
    # is the test's own, so a manifest that read it anywhere else fails whatever the installed number is.
    monkeypatch.setattr(nervus, "__version__", "0.0.0+this-test")
    made = make_backup(install.pieces, key[1], install.folder, install.audit, now=NOW)
    assert json.loads(_open(made.path, key[0])["manifest.json"])["nervus"] == "0.0.0+this-test"


@needs_age
def test_a_piece_the_installation_does_not_have_is_not_in_it(install, key):
    pieces = Pieces(**{**install.pieces.__dict__, "proxmox": None, "proxmox_ca": None, "tls_renewed": None})
    opened = _open(make_backup(pieces, key[1], install.folder, install.audit, now=NOW).path, key[0])
    assert not {"pieces/proxmox", "pieces/proxmox_ca", "pieces/tls_renewed"} & set(opened)


@needs_age
@pytest.mark.parametrize("role", ["ssh_ca_key", "ssh_key", "tokens", "switches", "database", "audit_log",
                                  "tls_issuer_key"])
def test_a_missing_piece_refuses_the_backup_naming_it(install, key, role):
    getattr(install.pieces, role).unlink()
    with pytest.raises(BackupFailed, match=role):
        make_backup(install.pieces, key[1], install.folder, install.audit, now=NOW)
    assert not install.folder.exists() or not list(install.folder.iterdir())


# --- one moment ------------------------------------------------------------------


@needs_age
def test_a_backup_made_while_nervus_writes_holds_every_earlier_write_whole(install, key, tmp_path):
    """Verification 1: SQLite's backup command, not a copy of the file. Another
    connection writes all the while; the backup's database passes SQLite's own
    check and holds every link made before the backup began.

    A connection is held open throughout, as one of nervus's is whenever two
    overlap: then recent changes sit in the write-ahead file, not the main
    one, and a copy of the main file alone would miss them."""
    reader = sqlite3.connect(install.database.path)
    reader.execute("SELECT 1 FROM signin_link").fetchall()
    before = {hashlib.sha256(install.database.make_link()[0].encode()).hexdigest() for _ in range(200)}
    stop = threading.Event()

    def write():
        while not stop.is_set():
            install.database.make_link()

    writer = threading.Thread(target=write)
    writer.start()
    try:
        made = make_backup(install.pieces, key[1], install.folder, install.audit, now=NOW)
    finally:
        stop.set()
        writer.join()
        reader.close()
    restored = tmp_path / "restored.db"
    restored.write_bytes(_open(made.path, key[0])["pieces/database"])
    with sqlite3.connect(restored) as db:
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        hashes = {row[0] for row in db.execute("SELECT hash FROM signin_link")}
    assert before <= hashes


@needs_age
def test_its_audit_log_ends_at_a_whole_record_and_holds_its_own(install, key):
    """Read last, up to its last whole line: a record half-written at that
    moment is left for the next backup, never cut in two."""

    class HalfWriting(AuditLog):
        def record_operator(self, action, fields, tool="nervus-ctl"):
            run_id = super().record_operator(action, fields, tool)
            if action == "backup":
                with self.path.open("a") as log:
                    log.write('{"id": "half')
            return run_id

    audit = HalfWriting(install.audit.path)
    made = make_backup(install.pieces, key[1], install.folder, audit, now=NOW)
    log = _open(made.path, key[0])["pieces/audit_log"]
    assert log.endswith(b"\n") and b'"half' not in log
    records = [json.loads(line) for line in log.splitlines()]
    assert records[-1]["action"] == "backup" and records[-1]["file"] == made.path.name
    assert install.audit.path.read_bytes().startswith(log)


# --- locked to the recovery key -----------------------------------------------------


@needs_age
def test_it_opens_with_the_recovery_key_and_with_no_other(install, key, tmp_path):
    """Verification 2: the standard age tool opens it with the recovery key's
    private half, and another key opens nothing."""
    made = make_backup(install.pieces, key[1], install.folder, install.audit, now=NOW)
    assert _open(made.path, key[0])["pieces/ssh_ca_key"] == b"CA KEY SECRET\n"
    other = tmp_path / "other.key"
    _key_pair(other)
    with pytest.raises(RuntimeError, match="no identity matched"):
        _open(made.path, other)


@needs_age
def test_nothing_in_the_folder_is_in_clear(install, key):
    made = make_backup(install.pieces, key[1], install.folder, install.audit, now=NOW)
    assert [p.name for p in install.folder.iterdir()] == [made.path.name]
    written = made.path.read_bytes()
    assert written.startswith(b"age-encryption.org/v1\n")
    for secret in (b"CA KEY SECRET", b"SSH KEY SECRET", b"TOKEN SECRET", b"signin_link"):
        assert secret not in written


@needs_age
def test_the_folder_is_0700_and_each_backup_0600_whatever_the_umask(install, key):
    install.folder.mkdir(mode=0o755)
    install.folder.chmod(0o755)
    old = os.umask(0)
    try:
        made = make_backup(install.pieces, key[1], install.folder, install.audit, now=NOW)
    finally:
        os.umask(old)
    assert stat.S_IMODE(install.folder.stat().st_mode) == 0o700
    assert stat.S_IMODE(made.path.stat().st_mode) == 0o600


def test_the_recovery_key_file_holds_one_public_key_and_nothing_else(tmp_path):
    good = "age1" + "q" * 58
    assert recipient(_secret(tmp_path / "ok.pub", good + "\n")) == good
    with pytest.raises(BackupFailed, match="not an age public key"):
        recipient(_secret(tmp_path / "private.pub", "AGE-SECRET-KEY-1" + "Q" * 58 + "\n"))
    with pytest.raises(BackupFailed, match="recovery-key"):
        recipient(tmp_path / "missing.pub")


# --- failures ------------------------------------------------------------------------


@needs_age
def test_a_failure_leaves_no_partial_file_and_is_recorded(install, key):
    """age refuses a key with a bad checksum, part-way: nothing is left, and the
    failure is in the audit log after the record that began it."""
    bad = key[1][:-1] + ("q" if key[1][-1] != "q" else "p")
    with pytest.raises(BackupFailed, match="age"):
        make_backup(install.pieces, bad, install.folder, install.audit, now=NOW)
    assert list(install.folder.iterdir()) == []
    begun, failed = _records(install.audit.path)[-2:]
    assert begun["action"] == "backup" and failed["action"] == "backup_failed"
    assert failed["backup_record"] == begun["id"]


def test_without_age_no_backup_is_made(install, monkeypatch):
    monkeypatch.setattr(backup.shutil, "which", lambda name: None)
    with pytest.raises(BackupFailed, match="age is not installed"):
        make_backup(install.pieces, "age1" + "q" * 58, install.folder, install.audit, now=NOW)
    assert not install.folder.exists()


@needs_age
def test_no_record_no_backup(install, key, tmp_path):
    """ADR-0001 s10: a backup whose making cannot be recorded is not made."""
    unwritable = AuditLog(tmp_path / "no/such/folder/audit.jsonl")
    with pytest.raises(BackupFailed, match="record"):
        make_backup(install.pieces, key[1], install.folder, unwritable, now=NOW)
    assert not install.folder.exists()


@needs_age
def test_a_made_backup_is_recorded_with_its_hash(install, key):
    made = make_backup(install.pieces, key[1], install.folder, install.audit, now=NOW)
    begun, done = _records(install.audit.path)[-2:]
    assert (begun["action"], begun["actor"], begun["file"]) == ("backup", "operator", made.path.name)
    assert done["action"] == "backup_made" and done["backup_record"] == begun["id"]
    assert done["sha256"] == hashlib.sha256(made.path.read_bytes()).hexdigest() == made.sha256
    assert done["size"] == made.path.stat().st_size


# --- what is kept --------------------------------------------------------------------


def _daily(days: int, start=NOW) -> list[datetime]:
    """One backup a day, at 04:00, for `days` days up to `start`'s date."""
    first = start.replace(hour=4, minute=0) - timedelta(days=days - 1)
    return [first + timedelta(days=i) for i in range(days)]


def _kept_by_running_daily(days: int) -> set[datetime]:
    """What is left after a backup a day for `days` days, kept as each one is
    made, as nervus keeps them."""
    kept: set[datetime] = set()
    for t in _daily(days):
        kept = to_keep(sorted(kept | {t}), t)
    return kept


def test_the_newest_of_each_of_the_last_seven_days_is_kept():
    many = [t + timedelta(hours=h) for t in _daily(10) for h in (0, 6)]
    kept = to_keep(many, NOW.replace(hour=12))
    last_week = [t for t in kept if NOW - t < timedelta(days=7)]
    assert len(last_week) == 7
    assert all(t.hour == 10 for t in last_week)  # each day's newest


def test_a_year_of_daily_backups_keeps_a_week_daily_a_month_weekly_a_year_monthly():
    kept = _kept_by_running_daily(400)
    newest = max(kept)
    ages = sorted((newest - t).days for t in kept)
    assert ages[:7] == [0, 1, 2, 3, 4, 5, 6]
    assert max(ages) < 365, "nothing older than a year"
    weeks = {t.isocalendar()[:2] for t in kept if newest - t < timedelta(days=31)}
    assert len(weeks) == 5
    months = {(t.year, t.month) for t in kept}
    assert len(months) == 12
    assert len(kept) <= 7 + 5 + 12


def test_nothing_older_than_a_year_is_kept_even_alone():
    assert to_keep([NOW - timedelta(days=366)], NOW) == set()
    assert to_keep([NOW - timedelta(days=300)], NOW) == {NOW - timedelta(days=300)}


def test_a_backups_time_is_read_from_its_name():
    assert made_at(backup_name(NOW)) == NOW
    assert made_at("notes.txt") is None
    assert made_at(backup_name(NOW) + ".partial") is None


def test_prune_never_touches_a_file_that_is_not_a_backup_nor_the_newest(tmp_path):
    for t in _daily(400):
        (tmp_path / backup_name(t)).write_bytes(b"x")
    (tmp_path / "notes.txt").write_bytes(b"mine")
    (tmp_path / (backup_name(NOW) + ".partial")).write_bytes(b"x")
    ancient = tmp_path / backup_name(NOW - timedelta(days=900))
    ancient.write_bytes(b"x")
    removed = prune(tmp_path, NOW + timedelta(days=900), keep=ancient)
    left = {p.name for p in tmp_path.iterdir()}
    assert {"notes.txt", backup_name(NOW) + ".partial", ancient.name} == left
    assert len(removed) == 400


@needs_age
def test_a_made_backup_prunes_and_records_what_it_removed(install, key):
    install.folder.mkdir(mode=0o700)
    old = install.folder / backup_name(NOW - timedelta(days=400))
    old.write_bytes(b"x")
    made = make_backup(install.pieces, key[1], install.folder, install.audit, now=NOW)
    assert not old.exists() and made.removed == [old.name]
    assert _records(install.audit.path)[-1]["removed"] == [old.name]


@needs_age
def test_a_failed_backup_removes_nothing(install, key):
    install.folder.mkdir(mode=0o700)
    old = install.folder / backup_name(NOW - timedelta(days=400))
    old.write_bytes(b"x")
    install.pieces.ssh_ca_key.unlink()
    with pytest.raises(BackupFailed):
        make_backup(install.pieces, key[1], install.folder, install.audit, now=NOW)
    assert old.exists()


@needs_age
def test_a_second_backup_in_the_same_second_is_refused_and_says_why(install, key):
    make_backup(install.pieces, key[1], install.folder, install.audit, now=NOW)
    with pytest.raises(BackupFailed, match="made this same second"):
        make_backup(install.pieces, key[1], install.folder, install.audit, now=NOW)
    assert len(list(install.folder.iterdir())) == 1


# --- the backup made before an upgrade, kept until the next (ADR-0029 step 7) -------------------
#
# Procedure 051, finding 5: the keeping holds a day's newest, so a second backup the same day removed
# the one made before the upgrade. Where that upgrade raised the database's version, it was the only
# backup the release before could read, and going back and the guide send a person to it.

R1, R2 = "0.2.0-42c0b5a132ef", "0.3.0-09bcc2ef1cd8"


def _backup_file(folder: Path, when=NOW, content=b"made before the upgrade") -> Path:
    path = folder / backup_name(when)
    path.write_bytes(content)
    path.chmod(0o600)
    return path


def test_a_kept_backup_has_a_name_of_its_own_which_no_keeping_reads_as_a_backups():
    name = kept_name(backup_name(NOW), R2)
    assert name == "nervus-backup-20261028T163000Z.before-0.3.0-09bcc2ef1cd8.tar.gz.age"
    assert made_at(name) is None  # so the daily keeping, in this release and in every one before it, leaves it
    assert kept(name) == (NOW, R2)
    assert kept(backup_name(NOW)) is None and kept("notes.txt") is None and kept(name + ".partial") is None
    assert kept("nervus-backup-20261301T000000Z.before-0.3.0-09bcc2ef1cd8.tar.gz.age") is None  # no such day


@pytest.mark.parametrize("name, release", [
    (backup_name(NOW), "0.3-09bcc2ef1cd8"), (backup_name(NOW), "0.3.0-09BCC2EF1CD8"), (backup_name(NOW), "../x"),
    (backup_name(NOW), "0.3.0-09bcc2ef1cd8/x"), ("notes.txt", R2), ("../" + backup_name(NOW), R2),
    (kept_name(backup_name(NOW), R1), R2),
])
def test_only_a_backup_and_a_release_by_their_own_names_make_a_kept_name(name, release):
    with pytest.raises(BackupFailed):
        kept_name(name, release)


def test_a_backup_kept_for_an_upgrade_outlives_a_later_backup_the_same_day(tmp_path):
    before = _backup_file(tmp_path)
    kept_path = keep_for_upgrade(tmp_path, before.name, R2)
    assert kept_path == tmp_path / kept_name(before.name, R2)
    later = _backup_file(tmp_path, NOW + timedelta(hours=1), b"made after it")
    assert prune(tmp_path, NOW + timedelta(hours=1), keep=later) == [before.name]  # as ever: not its day's newest
    assert kept_path.read_bytes() == b"made before the upgrade" and stat.S_IMODE(kept_path.stat().st_mode) == 0o600
    # Nor a year of keeping after it.
    for day in range(1, 400):
        prune(tmp_path, NOW + timedelta(days=day), keep=_backup_file(tmp_path, NOW + timedelta(days=day), b"x"))
    assert kept_path.read_bytes() == b"made before the upgrade"


def test_keeping_twice_is_keeping_once(tmp_path):
    before = _backup_file(tmp_path)
    assert keep_for_upgrade(tmp_path, before.name, R2) == keep_for_upgrade(tmp_path, before.name, R2)
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted([before.name, kept_name(before.name, R2)])


@pytest.mark.parametrize("what", ["nothing", "a folder", "a pipe", "a link to a file elsewhere"])
def test_what_is_not_a_backup_in_the_folder_is_not_kept(tmp_path, what):
    folder = tmp_path / "backups"
    folder.mkdir()
    source = folder / backup_name(NOW)
    if what == "a folder":
        source.mkdir()
    elif what == "a pipe":
        os.mkfifo(source)
    elif what == "a link to a file elsewhere":
        (tmp_path / "elsewhere").write_bytes(b"not a backup")
        source.symlink_to(tmp_path / "elsewhere")
    with pytest.raises(BackupFailed):
        keep_for_upgrade(folder, source.name, R2)
    assert not (folder / kept_name(source.name, R2)).exists()


def test_where_a_second_name_cannot_be_given_the_backup_is_copied(tmp_path, monkeypatch):
    # Not every file system gives a file two names.
    def no_links(*args, **kwargs):
        raise OSError(1, "Operation not permitted")
    monkeypatch.setattr(os, "link", no_links)
    before = _backup_file(tmp_path)
    kept_path = keep_for_upgrade(tmp_path, before.name, R2)
    assert kept_path.read_bytes() == before.read_bytes() and stat.S_IMODE(kept_path.stat().st_mode) == 0o600
    assert kept_path.stat().st_ino != before.stat().st_ino


def test_once_an_upgrade_is_up_only_the_backup_kept_for_it_stays(tmp_path):
    first = keep_for_upgrade(tmp_path, _backup_file(tmp_path, NOW - timedelta(days=30)).name, R1)
    second = keep_for_upgrade(tmp_path, _backup_file(tmp_path).name, R2)
    (tmp_path / "notes.txt").write_bytes(b"mine")
    daily = sorted(p.name for p in tmp_path.iterdir() if made_at(p.name))
    assert only_kept_for(tmp_path, R2) == [first.name]
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted([*daily, second.name, "notes.txt"])
    assert only_kept_for(tmp_path, R2) == []


def test_an_upgrade_that_went_back_drops_the_backup_kept_for_it_and_no_other(tmp_path):
    first = keep_for_upgrade(tmp_path, _backup_file(tmp_path, NOW - timedelta(days=30)).name, R1)
    second = keep_for_upgrade(tmp_path, _backup_file(tmp_path).name, R2)
    assert drop_kept_for(tmp_path, R2) == [second.name] and first.exists() and not second.exists()
    assert drop_kept_for(tmp_path, R2) == [] and len(list(tmp_path.iterdir())) == 3


def test_dropping_for_a_release_can_spare_the_one_just_kept(tmp_path):
    # An upgrade tried again makes a new backup: the one kept for the earlier try is superseded.
    earlier = keep_for_upgrade(tmp_path, _backup_file(tmp_path, NOW - timedelta(hours=2)).name, R2)
    again = keep_for_upgrade(tmp_path, _backup_file(tmp_path).name, R2)
    other = keep_for_upgrade(tmp_path, _backup_file(tmp_path, NOW - timedelta(days=30)).name, R1)
    assert drop_kept_for(tmp_path, R2, but=again.name) == [earlier.name]
    assert again.exists() and other.exists() and not earlier.exists()


def test_the_listing_gives_a_kept_backup_with_the_release_it_was_made_before(tmp_path):
    from nervus.restore import listing
    before = _backup_file(tmp_path, NOW - timedelta(days=30))
    kept_path = keep_for_upgrade(tmp_path, before.name, R2)
    before.unlink()  # long since removed by the daily keeping
    newest = _backup_file(tmp_path)
    assert [(b.name, b.kept_before) for b in listing(tmp_path)] == [(newest.name, None), (kept_path.name, R2)]
    assert listing(tmp_path)[1].made_at == (NOW - timedelta(days=30)).timestamp()


def test_made_at_returns_none_for_a_shaped_name_with_an_impossible_date():
    # A name matching the backup pattern but with an impossible date must not raise:
    # the backups folder is nervus-writable, and listing() only caught OSError, so such
    # a file crashed every signed-in UI page (procedure 056, robustness).
    from nervus.backup import made_at
    assert made_at("nervus-backup-20261301T000000Z.tar.gz.age") is None  # month 13


def test_listing_skips_a_backup_name_with_an_impossible_date(tmp_path):
    from nervus.restore import listing
    (tmp_path / "nervus-backup-20261301T000000Z.tar.gz.age").write_bytes(b"x")  # impossible date
    (tmp_path / "nervus-backup-20261101T000000Z.tar.gz.age").write_bytes(b"ok")
    assert [b.name for b in listing(tmp_path)] == ["nervus-backup-20261101T000000Z.tar.gz.age"]
