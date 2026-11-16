"""nervus-ctl's backup commands (ADR-0027 step 3): backup, backup --check,
restore, recovery-key, start-empty and accept-keys, on installations laid out
as a unit names them, with nervus itself stood in for by its start-up checks."""

import asyncio
import hashlib
import io
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import asyncssh
import pytest
import yaml

from nervus import ctl, identity
from nervus.audit import AuditLog
from nervus.backup import backup_name, kept, made_at
from nervus.database import Database
from nervus.tls import generate_own_authority

pytestmark = pytest.mark.skipif(shutil.which("age") is None or shutil.which("age-keygen") is None,
                                reason="age is not installed here; these tests run it")


def _key_pair() -> tuple[str, str]:
    """(private half, public half) of a new recovery key."""
    lines = subprocess.run(["age-keygen"], capture_output=True, text=True, check=True).stdout.splitlines()
    return (next(l for l in lines if l.startswith("AGE-SECRET-KEY-")),
            next(l.split(": ")[1] for l in lines if l.startswith("# public key: ")))


def _ssh_key(path: Path) -> None:
    key = asyncssh.generate_private_key("ssh-ed25519")
    path.write_bytes(key.export_private_key())
    path.chmod(0o600)
    path.with_name(path.name + ".pub").write_bytes(key.export_public_key())


class Installation:
    """One nervus installation: its unit and drop-in, its secrets, its state
    and its log, as the installer lays them out, started once."""

    def __init__(self, root: Path, private: str, public: str, drop_in: str = "Restart=always\n"):
        self.root, self.private = root, private
        opt, self.state, logs = root / "opt", root / "state", root / "log"
        self.secrets = opt / "secrets"
        for folder in (self.secrets, self.state, logs):
            folder.mkdir(parents=True, mode=0o700)
        _ssh_key(self.secrets / "nervus_ed25519")
        _ssh_key(self.secrets / "nervus_ca_ed25519")
        for name, text in (("tokens.yaml", f"tokens: [{{token: {'x' * 43}, id: t1, client: c, project: p, hosts: [h]}}]\n"),
                           ("known_hosts", f"h ssh-ed25519 AAAA{root.name}\n"), ("recovery.pub", public + "\n")):
            (self.secrets / name).write_text(text)
            (self.secrets / name).chmod(0o600)
        (opt / "hosts.yaml").write_text(f"hosts: []  # {root.name}\n")
        generate_own_authority(self.secrets / "tls.crt", self.secrets / "tls.key", [f"{root.name}.example"])
        (self.state / "switches.yaml").write_text("lockdown: false\ndisabled: [t2]\n")
        self.unit = root / "nervus.service"
        self.unit.write_text(
            "[Service]\nUser=\n"
            f"WorkingDirectory={opt}\n"
            "ExecStart=/opt/nervus/.venv/bin/nervus --hosts hosts.yaml --tokens secrets/tokens.yaml "
            "--known-hosts secrets/known_hosts --ssh-key secrets/nervus_ed25519 "
            f"--ssh-ca-key secrets/nervus_ca_ed25519 --audit-log {logs / 'audit.jsonl'} "
            f"--switches {self.state / 'switches.yaml'} --database {self.state / 'nervus.db'} --bind-host 0.0.0.0\n")
        (root / "nervus.service.d").mkdir()
        (root / "nervus.service.d" / "instance.conf").write_text("[Service]\n" + drop_in)
        self.service = ctl.read_unit(self.unit)
        self.database = Database(self.service.database)
        self.audit = AuditLog(self.service.audit_log)
        self.start()

    def start(self):
        """What nervus checks at every start (step 2): raises IdentityRefused."""
        identity.check_history(self.service.database, self.service.audit_log)
        self.database.open()
        identity.check(self.database, identity.Keys(self.service.ssh_key, self.service.ssh_ca, self.service.tls_issuer),
                       self.audit)

    async def ctl(self, *argv, ask=None, secret=None):
        out = io.StringIO()
        rc = await ctl.run(["--unit", str(self.unit), *argv], out=out, ask=ask or (lambda _: ""),
                           secret=secret or (lambda _: self.private))
        return rc, out.getvalue()

    def rows(self, sql):
        with sqlite3.connect(self.service.database) as db:
            return db.execute(sql).fetchall()

    def records(self):
        return [json.loads(line) for line in self.service.audit_log.read_text().splitlines()]

    def backups(self):
        return sorted((self.state / "backups").iterdir())

    def tree(self) -> dict[str, bytes]:
        """Every file under the installation, by path: what "nothing changed"
        is judged against."""
        return {str(p.relative_to(self.root)): p.read_bytes() for p in sorted(self.root.rglob("*")) if p.is_file()}

    def busy(self):
        """A day of use: a signed-in browser, a sign-in link, a token issued in
        the UI, an enrollment code used and one not."""
        link, _ = self.database.make_link()
        self.database.use_link(link)
        self.database.make_link()
        self.database.issue_token("ui-1", "claude", "proj", ["h"])
        with self.database.transaction() as db:
            for code, used in (("used", 1.0), ("unused", None)):
                db.execute("INSERT INTO enrollment_code (id, hash, name, address, level, made_at, expires_at, made_by, "
                           "used_at) VALUES (?, ?, 'm', '10.0.0.9', 'full', 0, 9e9, 'operator', ?)", (code, code, used))
                db.execute("INSERT INTO enrollment_login (code_id, login, host_key) VALUES (?, 'root', 'k')", (code,))
        self.audit.record_operator("lock", {"target": "t2"})


@pytest.fixture
def key():
    return _key_pair()


@pytest.fixture
def systemctl(monkeypatch):
    calls = []
    monkeypatch.setattr(ctl, "_systemctl", lambda *args: calls.append(args))
    return calls


@pytest.fixture
def first(tmp_path, key):
    nervus = Installation(tmp_path / "first", *key)
    nervus.busy()
    return nervus


def _open(nervus: Installation, path: Path) -> dict[str, bytes]:
    import tarfile, io as _io
    plain = subprocess.run(["age", "-d", "-i", "-", str(path)], input=nervus.private.encode(),
                           capture_output=True, check=True).stdout
    with tarfile.open(fileobj=_io.BytesIO(plain), mode="r:gz") as archive:
        return {m.name: archive.extractfile(m).read() for m in archive.getmembers()}


# --- backup ------------------------------------------------------------------------


async def test_backup_holds_every_piece_this_installation_has(first):
    rc, out = await first.ctl("backup")
    assert rc == 0, out
    [made] = first.backups()
    opened = _open(first, made)
    roles = {name[len("pieces/"):] for name in opened if name.startswith("pieces/")}
    assert roles == {"ssh_key", "ssh_key_pub", "ssh_ca_key", "ssh_ca_key_pub", "tokens", "hosts", "known_hosts",
                     "switches", "database", "audit_log", "tls_cert", "tls_key", "tls_issuer_cert", "tls_issuer_key",
                     "tls_root_cert", "recovery_key", "drop_ins/instance.conf"}
    assert opened["pieces/tls_issuer_key"] == (first.secrets / "tls-issuer.key").read_bytes()
    assert [r[0] for r in first.rows("SELECT kind FROM backup_event")] == ["made"]
    assert [r["action"] for r in first.records()][-2:] == ["backup", "backup_made"]


async def test_backup_without_a_recovery_key_says_how_to_make_one_and_makes_nothing(first):
    (first.secrets / "recovery.pub").unlink()
    rc, out = await first.ctl("backup")
    assert rc == 1 and "nervus-ctl recovery-key" in out
    assert not (first.state / "backups").exists()


# --- backup --check ------------------------------------------------------------------


async def test_check_passes_on_a_good_backup_and_changes_nothing_but_its_record(first):
    await first.ctl("backup")
    before = first.tree()
    rc, out = await first.ctl("backup", "--check", first.backups()[0].name)
    assert rc == 0 and "the check passed" in out, out
    after = first.tree()
    changed = {path for path in before.keys() | after.keys() if before.get(path) != after.get(path)}
    assert changed <= {"log/audit.jsonl", "state/nervus.db", "state/nervus.db-wal", "state/nervus.db-shm"}
    assert first.records()[-1]["action"] == "backup_check" and first.records()[-1]["passed"] is True
    assert [r[0] for r in first.rows("SELECT kind FROM backup_event")] == ["made", "checked"]


def _damage(path: Path) -> None:
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 0xFF
    path.write_bytes(bytes(data))


async def test_check_fails_on_a_damaged_backup(first):
    await first.ctl("backup")
    _damage(first.backups()[0])
    rc, out = await first.ctl("backup", "--check", str(first.backups()[0]))
    assert rc == 1 and "FAILED" in out
    assert first.records()[-1]["passed"] is False
    assert [r[0] for r in first.rows("SELECT kind FROM backup_event")] == ["made"]


async def test_check_fails_with_another_key(first):
    await first.ctl("backup")
    rc, out = await first.ctl("backup", "--check", first.backups()[0].name, secret=lambda _: _key_pair()[0])
    assert rc == 1 and "not the one this backup was locked to" in out


async def test_check_fails_on_a_backup_whose_log_is_not_the_start_of_the_live_one(first):
    await first.ctl("backup")
    log = first.service.audit_log
    log.write_text(log.read_text().replace('"lock"', '"LOCK"', 1))
    rc, out = await first.ctl("backup", "--check", first.backups()[0].name)
    assert rc == 1 and "is not the start of" in out


# --- restore -------------------------------------------------------------------------


@pytest.fixture
def second(tmp_path, key):
    """nervus installed afresh on another machine, at the same name, with keys of
    its own, as the installer makes them before `--restore` is built."""
    return Installation(tmp_path / "second", *key, drop_in="Restart=on-failure\n")


async def test_restore_onto_a_new_machine_brings_back_who_nervus_was(first, second, systemctl):
    await first.ctl("backup")
    backup = first.backups()[0]
    was = second.tree()
    rc, out = await second.ctl("restore", str(backup), ask=lambda _: "restore")
    assert rc == 0, out
    assert systemctl == [("stop", "nervus"), ("start", "nervus")]
    # Every piece is first's, where second's unit puts it.
    for name in ("nervus_ed25519", "nervus_ca_ed25519", "tokens.yaml", "known_hosts", "tls.key", "tls-issuer.key",
                 "tls-root.crt"):
        assert (second.secrets / name).read_bytes() == (first.secrets / name).read_bytes(), name
    second.start()  # who nervus is matches: it starts
    # Lockdown, keeping who the backup had switched off.
    assert yaml.safe_load((second.state / "switches.yaml").read_text()) == {"lockdown": True, "disabled": ["t2"]}
    # Nothing short-lived; what lasts is there.
    assert second.rows("SELECT COUNT(*) FROM session") == [(0,)]
    assert second.rows("SELECT COUNT(*) FROM signin_link") == [(0,)]
    assert second.rows("SELECT id FROM enrollment_code") == [("used",)]
    assert second.rows("SELECT code_id FROM enrollment_login") == [("used",)]
    assert second.rows("SELECT id FROM issued_token") == [("ui-1",)]
    assert second.rows("SELECT kind, file FROM backup_event WHERE kind = 'restored'") == [("restored", backup.name)]
    # The log is first's, and its next record names the backup.
    records = second.records()
    assert records[-1]["action"] == "restored" and records[-1]["file"] == backup.name
    assert any(r.get("target") == "t2" for r in records)
    # What it replaced is kept, never deleted.
    [replaced] = second.state.glob("replaced-*")
    for role, path in (("ssh_ca_key", "opt/secrets/nervus_ca_ed25519"), ("database", "state/nervus.db"),
                       ("audit_log", "log/audit.jsonl"), ("tls_issuer_key", "opt/secrets/tls-issuer.key")):
        assert (replaced / "pieces" / role).read_bytes() == was[path], role
    # Second's own drop-in is kept; first's is saved beside, and said to differ.
    assert (second.root / "nervus.service.d/instance.conf").read_text().endswith("on-failure\n")
    assert (replaced / "backup-drop-ins/instance.conf").read_text().endswith("always\n")
    assert "instance.conf differs" in out and "nervus-ctl unlock --all" in out


async def test_restore_on_the_same_machine_keeps_a_log_that_already_begins_with_the_backups(first, systemctl):
    await first.ctl("backup")
    first.audit.record_operator("unlock", {"target": "t2"})  # after the backup
    rc, out = await first.ctl("restore", first.backups()[0].name, ask=lambda _: "restore")
    assert rc == 0, out
    actions = [r["action"] for r in first.records()]
    assert actions[-2:] == ["unlock", "restored"]
    assert "kept whole" in out


@pytest.mark.parametrize("spoil, words", [
    ("damaged", "cannot open"),
    ("another key", "not the one this backup was locked to"),
    ("newer release", "made by a newer release"),
])
async def test_restore_refuses_before_anything_changes(first, second, systemctl, spoil, words):
    if spoil == "newer release":
        with sqlite3.connect(first.service.database) as db:
            db.execute("PRAGMA user_version = 2")
    await first.ctl("backup")
    backup = first.backups()[0]
    if spoil == "damaged":
        _damage(backup)
    secret = (lambda _: _key_pair()[0]) if spoil == "another key" else None
    before = second.tree()
    rc, out = await second.ctl("restore", str(backup), ask=lambda _: "restore", secret=secret)
    assert rc == 1 and words in out and "Nothing changed" in out
    assert systemctl == []
    assert second.tree() == before


async def test_restore_not_confirmed_changes_nothing(first, second, systemctl):
    await first.ctl("backup")
    before = second.tree()
    rc, out = await second.ctl("restore", str(first.backups()[0]), ask=lambda _: "no")
    assert rc == 1 and "not confirmed" in out
    assert systemctl == [] and second.tree() == before


# --- recovery-key --------------------------------------------------------------------


async def test_recovery_key_keeps_the_public_half_and_prints_the_private_half_once(tmp_path, key):
    nervus = Installation(tmp_path / "n", *key)
    (nervus.secrets / "recovery.pub").unlink()
    rc, out = await nervus.ctl("recovery-key")
    assert rc == 0, out
    public = (nervus.secrets / "recovery.pub").read_text().strip()
    assert public.startswith("age1") and public in out
    [private] = [line.strip() for line in out.splitlines() if line.strip().startswith("AGE-SECRET-KEY-")]
    assert not any(private.encode() in data for data in nervus.tree().values())
    assert nervus.records()[-1] == {**nervus.records()[-1], "action": "recovery_key", "public": public}
    # The pair works: a backup locked to the one opens with the other.
    nervus.private = private
    await nervus.ctl("backup")
    assert "pieces/database" in _open(nervus, nervus.backups()[0])


async def test_recovery_key_is_not_replaced_unless_asked(tmp_path, key):
    nervus = Installation(tmp_path / "n", *key)
    rc, out = await nervus.ctl("recovery-key")
    assert rc == 1 and "--replace" in out and (nervus.secrets / "recovery.pub").read_text().strip() == key[1]
    rc, out = await nervus.ctl("recovery-key", "--replace")
    assert rc == 0 and (nervus.secrets / "recovery.pub").read_text().strip() != key[1]
    assert "stay locked to the old key" in out


# --- start-empty ---------------------------------------------------------------------


async def test_start_empty_makes_the_database_on_purpose_and_says_so_first(first):
    for path in first.state.glob("nervus.db*"):
        path.unlink()
    with pytest.raises(identity.IdentityRefused):
        first.start()
    rc, out = await first.ctl("start-empty", ask=lambda _: "start-empty")
    assert rc == 0, out
    assert first.records()[-1]["action"] == "start_empty" and first.records()[-1]["made"] == "database"
    first.start()


async def test_start_empty_starts_a_new_log_whose_first_record_says_so(first):
    first.service.audit_log.unlink()
    with pytest.raises(identity.IdentityRefused):
        first.start()
    rc, out = await first.ctl("start-empty", ask=lambda _: "start-empty")
    assert rc == 0, out
    assert [r["action"] for r in first.records()] == ["start_empty"]
    first.start()


async def test_start_empty_with_nothing_missing_or_not_confirmed_changes_nothing(first):
    before = first.tree()
    assert (await first.ctl("start-empty", ask=lambda _: "start-empty"))[0] == 1
    first.service.audit_log.unlink()
    before = first.tree()
    rc, out = await first.ctl("start-empty", ask=lambda _: "no")
    assert rc == 1 and "not confirmed" in out and first.tree() == before


# --- accept-keys ---------------------------------------------------------------------


async def test_accept_keys_accepts_a_key_replaced_on_purpose_once_named(first):
    _ssh_key(first.secrets / "nervus_ed25519")
    with pytest.raises(identity.IdentityRefused, match="nervus-ctl accept-keys"):
        first.start()
    before = first.tree()
    rc, out = await first.ctl("accept-keys", ask=lambda _: "ssh_ca_key")
    assert rc == 1 and "not confirmed" in out and first.tree() == before
    assert "nervus's SSH key: recorded SHA256:" in out and "costs nothing" in out
    rc, out = await first.ctl("accept-keys", ask=lambda _: "ssh_key")
    assert rc == 0, out
    record = first.records()[-1]
    assert record["action"] == "accept_keys" and set(record) >= {"ssh_key"} and "ssh_ca_key" not in record
    first.start()


async def test_accept_keys_with_nothing_replaced_changes_nothing(first):
    before = first.tree()
    rc, out = await first.ctl("accept-keys", ask=lambda _: "ssh_key")
    assert rc == 0 and "nothing changed" in out and first.tree() == before


# --- the backup made before an upgrade, kept until the next (ADR-0029 step 7) -------------------
#
# install.sh --upgrade asks for each of these, with the nervus-ctl of the release it has just built.

NEXT, AFTER = "0.3.0-09bcc2ef1cd8", "0.4.0-1b2c3d4e5f60"


def _kept_records(nervus):
    return [(r["stage"], r.get("file"), r.get("kept_as"), r.get("removed")) for r in nervus.records()
            if r.get("action") == "upgrade_backup"]


async def test_the_backup_an_upgrade_made_is_kept_and_still_checks_and_restores_by_its_kept_name(first, systemctl):
    from nervus.backup import kept_name
    await first.ctl("backup")
    made, = first.backups()
    rc, out = await first.ctl("upgrade-backup", "keep", NEXT, str(made))  # the path `nervus-ctl backup` printed
    assert rc == 0, out
    kept_path = made.with_name(kept_name(made.name, NEXT))
    assert kept_path.is_file() and f"kept {made.name} as {kept_path.name}" in out
    assert _kept_records(first) == [("keep", made.name, kept_path.name, None)]
    await asyncio.sleep(1.1)  # a backup's name is its second
    rc, out = await first.ctl("backup")  # as the timer, the button or a second upgrade would, the same day
    assert rc == 0 and kept_path.is_file(), out
    rc, out = await first.ctl("backup", "--check", kept_path.name)
    assert rc == 0 and "the check passed" in out, out
    rc, out = await first.ctl("restore", kept_path.name, ask=lambda _: "restore")
    assert rc == 0 and "restored." in out, out


async def test_an_upgrade_that_is_up_leaves_only_its_own_kept_backup_and_one_that_went_back_drops_its_own(first):
    from nervus.backup import kept_name
    await first.ctl("backup")
    made, = first.backups()
    for release in (NEXT, AFTER):
        assert (await first.ctl("upgrade-backup", "keep", release, made.name))[0] == 0
    rc, out = await first.ctl("upgrade-backup", "drop", AFTER)  # that upgrade went back
    assert rc == 0 and {p.name for p in first.backups()} == {made.name, kept_name(made.name, NEXT)}, out
    assert (await first.ctl("upgrade-backup", "keep", AFTER, made.name))[0] == 0
    rc, out = await first.ctl("upgrade-backup", "only", AFTER)  # and tried again, it came up
    assert rc == 0 and {p.name for p in first.backups()} == {made.name, kept_name(made.name, AFTER)}, out
    assert [(stage, removed) for stage, _, _, removed in _kept_records(first) if stage != "keep"] == [
        ("drop", [kept_name(made.name, AFTER)]), ("only", [kept_name(made.name, NEXT)])]
    assert (await first.ctl("upgrade-backup", "only", AFTER))[0] == 0  # nothing more to remove is no failure


async def test_an_upgrade_tried_again_keeps_its_new_backup_in_place_of_the_earlier_tries(first):
    # The first try kept its backup and stopped before nervus was stopped; nothing dropped it.
    from nervus.backup import kept_name
    await first.ctl("backup")
    earlier, = first.backups()
    assert (await first.ctl("upgrade-backup", "keep", NEXT, earlier.name))[0] == 0
    await asyncio.sleep(1.1)  # a backup's name is its second
    await first.ctl("backup")
    again = next(p for p in first.backups() if made_at(p.name) and p != earlier)
    rc, out = await first.ctl("upgrade-backup", "keep", NEXT, again.name)
    assert rc == 0 and f"removed {kept_name(earlier.name, NEXT)}" in out, out
    assert [p.name for p in first.backups() if kept(p.name)] == [kept_name(again.name, NEXT)]
    assert ("superseded", None, None, [kept_name(earlier.name, NEXT)]) in _kept_records(first)


@pytest.mark.parametrize("args, says", [
    (("keep", NEXT), "keep needs the backup"),
    (("keep", "0.3", "nervus-backup-20261028T163000Z.tar.gz.age"), "not a release's name"),
    (("keep", NEXT, "notes.txt"), "not a backup's name"),
    (("keep", NEXT, "nervus-backup-20261028T163000Z.tar.gz.age"), "cannot keep"),  # no such backup here
    (("keep", NEXT, "/etc/nervus-backup-20261028T163000Z.tar.gz.age"), "not in nervus's backup folder"),
    (("only", "0.3"), "not a release's name"),
    (("drop", NEXT, "nervus-backup-20261028T163000Z.tar.gz.age"), "takes a release alone"),
])
async def test_what_cannot_be_kept_is_refused_saying_why_and_nothing_is_made(first, args, says):
    await first.ctl("backup")
    before = first.backups()
    rc, out = await first.ctl("upgrade-backup", *args)
    assert rc == 1 and says in out, out
    assert first.backups() == before


async def test_a_keeping_that_cannot_be_recorded_does_not_happen(first):
    from nervus.backup import kept_name
    await first.ctl("backup")
    made, = first.backups()
    log = first.service.audit_log
    log.rename(log.with_name("audit.kept"))
    log.mkdir()  # a folder where the log should be: every write to it fails
    rc, out = await first.ctl("upgrade-backup", "keep", NEXT, made.name)
    assert rc == 1 and first.backups() == [made], out


async def test_status_names_the_backup_kept_from_before_the_upgrade(first, monkeypatch):
    from nervus.backup import kept_name
    monkeypatch.setattr(ctl, "running_jobs", _no_jobs)
    await first.ctl("backup")
    made, = first.backups()
    await first.ctl("upgrade-backup", "keep", NEXT, made.name)
    _, out = await first.ctl("status")
    assert "backups: 1 in" in out  # the daily ones, counted as before
    assert f"kept from before the upgrade to {NEXT}, until the next: {kept_name(made.name, NEXT)}" in out


# --- status --------------------------------------------------------------------------


async def test_status_says_when_there_is_no_backup_and_when_the_newest_is_old(first, monkeypatch):
    monkeypatch.setattr(ctl, "running_jobs", _no_jobs)
    _, out = await first.ctl("status")
    assert "No backup of nervus has been made yet" in out
    await first.ctl("backup")
    _, out = await first.ctl("status")
    assert "backups: 1" in out and "no backup for more than a day" not in out
    assert "no backup has been checked" in out
    old = first.backups()[0]
    old.rename(old.with_name(backup_name(datetime.now(timezone.utc) - timedelta(hours=27))))
    _, out = await first.ctl("status")
    assert "No backup of nervus for more than a day" in out


async def test_status_says_when_a_check_passed_and_after_a_restore_until_the_next_backup(first, systemctl, monkeypatch):
    monkeypatch.setattr(ctl, "running_jobs", _no_jobs)
    await first.ctl("backup")
    await first.ctl("backup", "--check", first.backups()[0].name)
    _, out = await first.ctl("status")
    assert "last check passed" in out
    await first.ctl("restore", first.backups()[0].name, ask=lambda _: "restore")
    _, out = await first.ctl("status")
    assert "Restored from a backup made" in out
    await asyncio.sleep(1.1)  # a backup's name is its second
    rc, made = await first.ctl("backup")
    assert rc == 0, made
    _, out = await first.ctl("status")
    assert "Restored from a backup made" not in out


async def _no_jobs(service):
    return {}, []


async def _asks_every_machine(service):
    raise AssertionError("asked every machine for its jobs, as status does")


async def test_backup_last_check_says_when_the_recovery_key_last_opened_a_backup_and_changes_nothing(first, monkeypatch):
    # ADR-0029 question 4a: install.sh --upgrade's plan says it, so it must not ask any machine anything.
    monkeypatch.setattr(ctl, "running_jobs", _asks_every_machine)
    await first.ctl("backup")
    before = first.tree()
    rc, out = await first.ctl("backup", "--last-check")
    assert rc == 0 and out.startswith("no backup has been checked") and first.tree() == before, out
    await first.ctl("backup", "--check", first.backups()[0].name)
    rc, out = await first.ctl("backup", "--last-check")
    assert rc == 0 and out.startswith("last check passed") and first.backups()[0].name in out, out


def test_the_unit_names_the_recovery_key_the_issuer_and_the_drop_ins(first):
    svc = first.service
    assert svc.recovery_key == first.secrets / "recovery.pub"
    assert svc.tls_key == first.secrets / "tls.key" and svc.tls_issuer == first.secrets / "tls-issuer.key"
    assert svc.drop_ins == (first.root / "nervus.service.d" / "instance.conf",)
    assert svc.proxmox is None


# --- a backup that opens, but is not whole ----------------------------------------------
#
# The recovery key's public half is not secret: anything can lock a file to it.
# So what opens is still checked, piece by piece.


def _broken_database() -> bytes:
    """A database SQLite opens, whose own integrity check fails."""
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE t (a TEXT)")
    db.execute("CREATE INDEX i ON t (a)")
    db.executemany("INSERT INTO t VALUES (?)", [(str(i) * 20,) for i in range(500)])
    db.commit()
    data = bytearray(db.serialize())
    page = 19 * 4096
    data[page + 4096 - 200:page + 4096 - 100] = b"z" * 100
    return bytes(data)


def _craft(nervus: Installation, path: Path, public: str, change) -> None:
    """Open the backup at `path`, change its members with `change(members,
    manifest)`, and lock it again to `public`, as anyone holding it could."""
    import tarfile, io as _io
    members = _open(nervus, path)
    manifest = json.loads(members.pop("manifest.json"))
    change(members, manifest)
    buffer = _io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, data in [("manifest.json", json.dumps(manifest).encode()), *members.items()]:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, _io.BytesIO(data))
    locked = subprocess.run(["age", "-r", public], input=buffer.getvalue(), capture_output=True, check=True).stdout
    path.write_bytes(locked)


def _listed(manifest, role, data):
    piece = next(p for p in manifest["pieces"] if p["role"] == role)
    piece["sha256"], piece["size"] = hashlib.sha256(data).hexdigest(), len(data)


def _swap_piece(members, manifest):
    members["pieces/tokens"] = b"tokens: []\n"


def _add_piece(members, manifest):
    members["pieces/extra"] = b"not nervus's"


def _break_database(members, manifest):
    members["pieces/database"] = _broken_database()
    _listed(manifest, "database", members["pieces/database"])


def _mismatch_key(members, manifest):
    other = asyncssh.generate_private_key("ssh-ed25519").export_public_key()
    members["pieces/ssh_ca_key_pub"] = other
    _listed(manifest, "ssh_ca_key_pub", other)


@pytest.mark.parametrize("change, words", [
    (_swap_piece, "tokens is not what its manifest says"),
    (_add_piece, "unlisted ['extra']"),
    (_break_database, "fails SQLite's integrity check"),
    (_mismatch_key, "ssh_ca_key does not match its public half"),
])
async def test_a_backup_that_opens_but_is_not_whole_fails_the_check_and_is_never_restored(
        first, second, key, systemctl, change, words):
    await first.ctl("backup")
    backup = first.backups()[0]
    _craft(first, backup, key[1], change)
    rc, out = await first.ctl("backup", "--check", backup.name)
    assert rc == 1 and words in out, out
    before = second.tree()
    rc, out = await second.ctl("restore", str(backup), ask=lambda _: "restore")
    assert rc == 1 and words in out and "Nothing changed" in out
    assert systemctl == [] and second.tree() == before


async def test_the_uis_button_makes_the_backup_nervus_ctl_makes(first):
    """restore.backup_now, which nervus's backups page calls: the same pieces,
    the same row, its record the UI's."""
    from nervus import restore
    await first.ctl("backup")
    by_ctl = _open(first, first.backups()[0])
    for path in first.backups():
        path.unlink()
    made = restore.backup_now(first.service, first.database, first.audit, tool="ui")
    by_ui = _open(first, made.path)
    assert set(by_ui) == set(by_ctl)
    assert [r["tool"] for r in first.records() if r["action"] in ("backup", "backup_made")][-2:] == ["ui", "ui"]
    assert [r[0] for r in first.rows("SELECT kind FROM backup_event")] == ["made", "made"]


# --- restore trusts the backup for nothing but bytes (procedure 056, finding 1) ---------
#
# A backup is authenticated only by decrypting, and the recovery key's public half is not
# secret, so a forged backup can pass the whole-backup check. Restore must therefore take
# where, how and the staging path from this installation, never from the backup.


def _evil_role(outside: Path):
    """A forged piece whose manifest names an absolute path outside the installation."""
    body = b"pwned by restore\n"

    def change(members, manifest):
        members["pieces/evil"] = body
        manifest["pieces"].append({"role": "evil", "path": str(outside), "mode": 0o644,
                                   "sha256": hashlib.sha256(body).hexdigest(), "size": len(body)})
    return change


async def test_restore_refuses_a_backup_that_names_a_role_it_does_not_know(first, second, key, systemctl, tmp_path):
    await first.ctl("backup")
    backup = first.backups()[0]
    outside = tmp_path / "outside" / "pwned"
    outside.parent.mkdir()
    _craft(first, backup, key[1], _evil_role(outside))
    before = second.tree()
    rc, out = await second.ctl("restore", str(backup), ask=lambda _: "restore")
    assert rc == 1 and "Nothing changed" in out, out
    assert not outside.exists(), "restore wrote to a manifest-chosen path outside the installation"
    assert systemctl == [] and second.tree() == before


async def test_restore_does_not_write_through_a_symlink_at_the_staging_name(first, second, key, systemctl, tmp_path):
    await first.ctl("backup")
    backup = first.backups()[0]
    outside = tmp_path / "outside-target"
    outside.write_text("original\n")
    target = second.secrets / "tokens.yaml"
    target.with_name(target.name + ".restore-new").symlink_to(outside)
    rc, out = await second.ctl("restore", str(backup), ask=lambda _: "restore")
    assert rc == 0, out
    assert outside.read_text() == "original\n", "restore wrote through a planted staging symlink"
    assert (second.secrets / "tokens.yaml").read_bytes() == (first.secrets / "tokens.yaml").read_bytes()


async def test_declined_restore_does_not_write_through_the_audit_staging_symlink(first, second, key, systemctl, tmp_path):
    await first.ctl("backup")
    backup = first.backups()[0]
    outside = tmp_path / "audit-target"
    outside.write_text("original\n")
    log = second.service.audit_log
    log.with_name(f".{log.name}.restore").symlink_to(outside)
    rc, out = await second.ctl("restore", str(backup), ask=lambda _: "no")
    assert rc == 1 and "not confirmed" in out
    assert outside.read_text() == "original\n", "staging the audit log wrote through a planted symlink"


async def test_restore_clamps_an_overbroad_mode_from_the_manifest(first, second, key, systemctl):
    await first.ctl("backup")
    backup = first.backups()[0]

    def loosen(members, manifest):
        next(p for p in manifest["pieces"] if p["role"] == "tokens")["mode"] = 0o4777
    _craft(first, backup, key[1], loosen)
    rc, out = await second.ctl("restore", str(backup), ask=lambda _: "restore")
    assert rc == 0, out
    mode = (second.secrets / "tokens.yaml").stat().st_mode & 0o7777
    assert mode & 0o7077 == 0, f"mode not clamped: {oct(mode)}"


def _with_proxmox(nervus: Installation, ca_file: str) -> None:
    """Proxmox settings as tools/proxmox-access writes them, naming the CA as `ca_file`,
    and the unit giving --proxmox, as the installer's drop-in does."""
    (nervus.secrets / "pve-root-ca.pem").write_text(
        f"-----BEGIN CERTIFICATE-----\n{nervus.root.name}\n-----END CERTIFICATE-----\n")
    settings = nervus.secrets / "proxmox.yaml"
    settings.write_text('url: https://hv.example:8006\ntoken_id: "nervus@pve!nervus"\n'
                        'secret: "00000000-0000-0000-0000-000000000000"\n' f"ca_file: {ca_file}\n")
    settings.chmod(0o600)
    nervus.unit.write_text(nervus.unit.read_text().replace(" --bind-host", " --proxmox secrets/proxmox.yaml --bind-host"))
    nervus.service = ctl.read_unit(nervus.unit)


@pytest.mark.parametrize("named", ["absolute", "climbing"])
async def test_restore_refuses_a_proxmox_ca_the_settings_name_outside_the_secrets_folder(
        first, second, key, systemctl, tmp_path, named):
    # The Proxmox settings are nervus's account's to edit. Pointed at a file root reads,
    # the CA's destination must not be honoured: restore would move that file aside and
    # write the CA there, owned by nervus's account (procedure 056, C20).
    _with_proxmox(first, "pve-root-ca.pem")
    await first.ctl("backup")
    backup = first.backups()[0]
    outside = tmp_path / "etc" / "profile.d" / "x.sh"
    outside.parent.mkdir(parents=True)
    outside.write_text("# root's\n")
    _with_proxmox(second, str(outside) if named == "absolute" else os.path.relpath(outside, second.secrets))
    before = second.tree()
    rc, out = await second.ctl("restore", str(backup), ask=lambda _: "restore")
    assert rc == 1 and "Nothing changed" in out and "secrets folder" in out, out
    assert outside.read_text() == "# root's\n", "restore wrote the Proxmox CA where nervus's settings named it"
    assert systemctl == [] and second.tree() == before


async def test_restore_puts_the_proxmox_ca_beside_the_settings(first, second, key, systemctl):
    _with_proxmox(first, "pve-root-ca.pem")
    await first.ctl("backup")
    backup = first.backups()[0]
    _with_proxmox(second, "pve-root-ca.pem")
    rc, out = await second.ctl("restore", str(backup), ask=lambda _: "restore")
    assert rc == 0, out
    assert (second.secrets / "pve-root-ca.pem").read_bytes() == (first.secrets / "pve-root-ca.pem").read_bytes()


def _kept_in(out: str) -> Path:
    return Path(out.split("What it replaced is in ", 1)[1].split(".\n", 1)[0].rstrip("."))


async def test_restore_never_follows_a_link_planted_at_a_replaced_folder_name(first, second, key, systemctl, tmp_path):
    # The folder that keeps what a restore replaces is made beside the database, in a
    # folder nervus's account owns. Named by the second, it could be guessed: a link
    # planted at every name for the next minutes made root create folders in, and chmod,
    # whatever the link named (procedure 058, trial A).
    await first.ctl("backup")
    backup = first.backups()[0]
    outside = tmp_path / "rootdir"
    outside.mkdir(mode=0o755)
    (outside / "marker").write_text("root's\n")
    now = int(time.time())
    for s in range(-5, 120):
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(now + s))
        (second.state / f"replaced-{stamp}").symlink_to(outside)
    rc, out = await second.ctl("restore", str(backup), ask=lambda _: "restore")
    assert rc == 0, out
    assert sorted(p.name for p in outside.iterdir()) == ["marker"], "root made folders through a planted link"
    assert stat.S_IMODE(outside.stat().st_mode) == 0o755, "root changed a planted link's target's mode"
    kept = _kept_in(out)
    assert not kept.is_symlink() and kept.is_dir() and stat.S_IMODE(kept.stat().st_mode) == 0o700
    assert (kept / "pieces" / "tokens").is_file()


async def test_restore_refuses_when_its_kept_folder_is_swapped_for_a_link(first, second, key, systemctl, tmp_path,
                                                                        monkeypatch):
    # nervus's account may also swap the folder for a link between its making and its
    # use. Restore opens it without following a link before anything is moved, so the
    # swap is refused, nothing is replaced, and nervus is started again.
    from nervus import restore
    await first.ctl("backup")
    backup = first.backups()[0]
    outside = tmp_path / "rootdir"
    outside.mkdir(mode=0o755)
    real_mkdtemp = restore.tempfile.mkdtemp

    def swapped(*args, **kwargs):
        made = Path(real_mkdtemp(*args, **kwargs))
        made.rename(made.with_name(made.name + ".moved"))
        made.symlink_to(outside)
        return str(made)
    monkeypatch.setattr(restore.tempfile, "mkdtemp", swapped)
    before = {k: v for k, v in second.tree().items() if "replaced-" not in k}
    rc, out = await second.ctl("restore", str(backup), ask=lambda _: "restore")
    assert rc == 1 and "swapped" in out and "Nothing was replaced" in out, out
    assert list(outside.iterdir()) == [] and stat.S_IMODE(outside.stat().st_mode) == 0o755
    assert {k: v for k, v in second.tree().items() if "replaced-" not in k} == before
    assert systemctl == [("stop", "nervus"), ("start", "nervus")]


# --- root acts through handles, never by path, where another account can change a folder ----
#
# nervus's account owns the folders restore writes into: its secrets, its state, its log's
# folder. Inside them it can make any name a link, or swap one name for another while restore
# waits for the operator. Root must follow none of it (procedure 058; ADR-0027, 2026-11-13).


def _staged(log_dir: Path) -> Path:
    return next(p for p in log_dir.iterdir() if p.name.endswith(".restore"))


async def test_restore_refuses_when_its_staged_audit_log_is_swapped_while_it_waits(first, second, key, systemctl,
                                                                                tmp_path):
    # The audit log is staged beside the log before the operator confirms. Swapped for a link
    # while restore waits, the name would carry root's chmod and chown to whatever it names.
    await first.ctl("backup")
    backup = first.backups()[0]
    outside = tmp_path / "root-file"
    outside.write_text("root's\n")
    outside.chmod(0o400)

    def swap_then_confirm(_prompt):
        staged = _staged(second.service.audit_log.parent)
        staged.unlink()
        staged.symlink_to(outside)
        return "restore"
    before = second.tree()
    rc, out = await second.ctl("restore", str(backup), ask=swap_then_confirm)
    assert rc == 1 and "swapped" in out and "Nothing was replaced" in out, out
    assert stat.S_IMODE(outside.stat().st_mode) == 0o400 and outside.read_text() == "root's\n"
    assert not second.service.audit_log.is_symlink()
    assert systemctl == [("stop", "nervus"), ("start", "nervus")] and second.tree() == before


async def test_restore_refuses_when_its_staged_audit_log_is_removed_while_it_waits(first, second, key, systemctl):
    await first.ctl("backup")
    backup = first.backups()[0]

    def remove_then_confirm(_prompt):
        _staged(second.service.audit_log.parent).unlink()
        return "restore"
    before = second.tree()
    rc, out = await second.ctl("restore", str(backup), ask=remove_then_confirm)
    assert rc == 1 and "Nothing was replaced" in out, out
    assert systemctl == [("stop", "nervus"), ("start", "nervus")] and second.tree() == before


def _with_renewal(nervus: Installation) -> None:
    """A certificate nervus renewed itself: in a folder of its own, beside the database."""
    renewed = nervus.service.tls_renewed
    renewed.parent.mkdir(mode=0o700)
    renewed.write_bytes(nervus.service.tls_cert.read_bytes())


async def test_restore_follows_no_link_in_a_folder_another_account_can_change(first, second, key, systemctl,
                                                                           tmp_path):
    # The renewal's folder sits inside nervus's state folder. A link planted at its name would
    # have root write the renewal, as nervus's own file, into any folder the link names.
    _with_renewal(first)
    await first.ctl("backup")
    backup = first.backups()[0]
    outside = tmp_path / "a-folder-root-reads"
    outside.mkdir()
    second.state.chmod(0o777)  # as /var/lib/nervus is to root: another account can change what it holds
    (second.state / "tls").symlink_to(outside)
    before = second.tree()
    rc, out = await second.ctl("restore", str(backup), ask=lambda _: "restore")
    assert rc == 1 and "Nothing changed" in out and "link" in out, out
    assert list(outside.iterdir()) == [], "root wrote through a link planted where a folder belongs"
    assert systemctl == [] and second.tree() == before


async def test_restore_makes_the_renewals_folder_and_puts_the_renewal_in_it(first, second, key, systemctl):
    _with_renewal(first)
    await first.ctl("backup")
    backup = first.backups()[0]
    second.state.chmod(0o777)
    rc, out = await second.ctl("restore", str(backup), ask=lambda _: "restore")
    assert rc == 0, out
    folder = second.state / "tls"
    assert folder.is_dir() and not folder.is_symlink() and stat.S_IMODE(folder.stat().st_mode) == 0o700
    assert (folder / "tls.crt").read_bytes() == first.service.tls_renewed.read_bytes()


@pytest.mark.parametrize("what", ["folder", "pipe"])
async def test_restore_refuses_a_place_that_holds_something_other_than_a_file(first, second, key, systemctl, what):
    # A folder at the audit log's name crashed the restore half-way, pieces already placed and
    # nervus stopped; a pipe there made root wait on it for ever. Both are refused first.
    await first.ctl("backup")
    backup = first.backups()[0]
    log = second.service.audit_log
    log.rename(log.with_name("audit.jsonl.kept"))
    log.mkdir() if what == "folder" else os.mkfifo(log)
    before = second.tree()
    rc, out = await second.ctl("restore", str(backup), ask=lambda _: "restore")
    assert rc == 1 and "Nothing changed" in out and "not a file" in out, out
    assert systemctl == [] and second.tree() == before


async def test_a_link_where_a_file_belongs_is_kept_as_a_link_and_a_file_put_in_its_place(first, second, key,
                                                                                      systemctl, tmp_path):
    await first.ctl("backup")
    backup = first.backups()[0]
    elsewhere = tmp_path / "elsewhere"
    elsewhere.write_text("lockdown: false\ndisabled: []\n")
    switch = second.service.switches
    switch.unlink()
    switch.symlink_to(elsewhere)
    rc, out = await second.ctl("restore", str(backup), ask=lambda _: "restore")
    assert rc == 0, out
    assert not switch.is_symlink() and "lockdown: true" in switch.read_text()
    assert elsewhere.read_text() == "lockdown: false\ndisabled: []\n"
    assert (_kept_in(out) / "pieces" / "switches").is_symlink()


def test_valid_roles_stay_in_step_with_locations(first):
    from nervus import restore
    assert set(restore.locations(first.service)) == restore.VALID_ROLES


async def test_recovery_key_does_not_write_through_a_symlink_at_the_staging_name(tmp_path, key):
    # recovery-key wrote its staging file at a predictable name; harden it like restore
    # (procedure 056, finding 1's C21 sibling). A planted symlink must not be followed.
    nervus = Installation(tmp_path / "n", *key)
    (nervus.secrets / "recovery.pub").unlink()
    outside = tmp_path / "outside"
    outside.write_text("original\n")
    (nervus.secrets / "recovery.pub.new").symlink_to(outside)
    rc, out = await nervus.ctl("recovery-key")
    assert rc == 0, out
    assert outside.read_text() == "original\n"  # not written through
    assert (nervus.secrets / "recovery.pub").read_text().strip().startswith("age1")
