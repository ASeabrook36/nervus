"""Backups in the UI (ADR-0027 step 5): the warning on every page a day without
a new backup gives; the backups page, its download and its button; and the
note after a restore, until the next backup."""

import json
import time
from datetime import datetime, timedelta, timezone

import pytest
from starlette.testclient import TestClient

from nervus.audit import AuditLog
from nervus.backup import BackupFailed, backup_name
from nervus.database import Database
from nervus.enrolled_hosts import EnrolledHostStore
from nervus.enrollment_codes import EnrollmentCodes
from nervus.exposure import check
from nervus.first_run import FirstRun
from nervus.ui import Backups, Machines, Setup, build_ui

ORIGIN = "https://nervus.example:8443"


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "nervus.db")
    database.open()
    return database


@pytest.fixture
def audit(tmp_path):
    return AuditLog(path=tmp_path / "audit.jsonl")


class Folder:
    """nervus's backup folder, and a stand-in for what makes a backup."""

    def __init__(self, tmp_path, db):
        self.path = tmp_path / "backups"
        self.path.mkdir(mode=0o700)
        self.key = tmp_path / "recovery.pub"
        self.key.write_text("age1" + "q" * 58 + "\n")
        self.db, self.made, self.fails = db, [], None

    def add(self, hours_old: float, data: bytes = b"age-encryption.org/v1\nlocked") -> str:
        name = backup_name(datetime.now(timezone.utc).replace(microsecond=0) - timedelta(hours=hours_old))
        (self.path / name).write_bytes(data)
        return name

    def event(self, kind: str, at: float, made_at: float = 0.0, file: str = "f"):
        with self.db.transaction() as c:
            c.execute("INSERT INTO backup_event (kind, file, made_at, at) VALUES (?, ?, ?, ?)", (kind, file, made_at, at))

    def make(self):
        if self.fails:
            raise BackupFailed(self.fails)
        self.made.append(self.add(0))

    def backups(self):
        return Backups(folder=self.path, recovery_key=self.key, make=self.make)


@pytest.fixture
def folder(tmp_path, db):
    return Folder(tmp_path, db)


def _browser(db, audit, folder, tier=None, machines=None):
    setup = None
    if tier is not None:
        FirstRun(db).choose_tier(tier, by="operator")
        setup = Setup(FirstRun(db), check("127.0.0.1", interfaces=lambda: ["127.0.0.1"]))
    browser = TestClient(build_ui(db, audit, secure=True, backups=folder.backups(), setup=setup, machines=machines),
                         base_url=ORIGIN, follow_redirects=False)
    link, _ = db.make_link()
    assert browser.post("/signin", data={"link": link}, headers={"Origin": ORIGIN}).status_code == 303
    return browser


@pytest.fixture
def browser(db, audit, folder):
    return _browser(db, audit, folder)


def _form_token(browser):
    page = browser.get("/backups").text
    start = page.index('name="form_token" value="') + len('name="form_token" value="')
    return page[start:page.index('"', start)]


def _records(audit, action):
    lines = audit.path.read_text().splitlines() if audit.path.exists() else []
    return [r for r in map(json.loads, lines) if r.get("action") == action]


# --- the warning on every page (question 4) -------------------------------------------


@pytest.mark.parametrize("path", ["/", "/audit", "/backups"])
def test_without_a_backup_every_page_says_so(browser, path):
    page = browser.get(path).text
    assert 'class="banner" role="alert">No backup of nervus has been made yet.' in page


def test_a_backup_made_within_a_day_quiets_the_warning_and_an_older_one_does_not(browser, folder):
    folder.add(hours_old=25)
    assert "No backup of nervus" not in browser.get("/").text
    for path in folder.path.iterdir():
        path.unlink()
    folder.add(hours_old=27)
    assert "No backup of nervus for more than a day" in browser.get("/").text


# --- the page --------------------------------------------------------------------------


def test_the_page_lists_each_backup_newest_first_with_its_download(browser, folder):
    old, new = folder.add(hours_old=48), folder.add(hours_old=1)
    page = browser.get("/backups").text
    assert page.index(new) < page.index(old)
    assert f'href="backups?download={new}"' in page
    assert "No backup has been checked yet." in page and "nervus-ctl backup --check" in page


def test_the_page_says_when_a_check_last_passed(browser, folder):
    folder.event("checked", at=time.time(), file="nervus-backup-20261028T163000Z.tar.gz.age")
    assert "The last check that passed:" in browser.get("/backups").text
    assert "nervus-backup-20261028T163000Z.tar.gz.age" in browser.get("/backups").text


@pytest.mark.parametrize("tier, says", [
    (1, "a copy on your everyday computer survives losing it"),
    (2, "does not survive losing that computer"),
])
def test_the_page_says_where_copies_go_for_the_tier(db, audit, folder, tier, says):
    assert says in _browser(db, audit, folder, tier=tier).get("/backups").text


def test_without_a_recovery_key_there_is_no_button_but_the_command(browser, folder):
    folder.key.unlink()
    page = browser.get("/backups").text
    assert 'value="make"' not in page and "nervus-ctl recovery-key" in page


# --- download ------------------------------------------------------------------------------


def test_a_download_is_recorded_first_and_gives_the_backup(browser, folder, audit, db):
    name = folder.add(hours_old=1, data=b"the locked bytes")
    response = browser.get("/backups", params={"download": name})
    assert response.status_code == 200 and response.content == b"the locked bytes"
    assert f'filename="{name}"' in response.headers["content-disposition"]
    [record] = _records(audit, "backup_download")
    assert record["file"] == name and record["tool"] == "ui" and record["actor"] == "operator"
    with db.transaction(write=False) as c:
        assert c.execute("SELECT kind, file FROM backup_event").fetchall() == [("downloaded", name)]


def test_a_download_needs_a_session(db, audit, folder):
    name = folder.add(hours_old=1, data=b"the locked bytes")
    stranger = TestClient(build_ui(db, audit, secure=True, backups=folder.backups()), base_url=ORIGIN)
    response = stranger.get("/backups", params={"download": name})
    assert b"the locked bytes" not in response.content and not _records(audit, "backup_download")


@pytest.mark.parametrize("name", ["../nervus.db", "nervus.db", "nervus-backup-20261028T163000Z.tar.gz.age",
                                  "/etc/passwd"])
def test_only_a_backup_the_folder_holds_can_be_downloaded(browser, folder, audit, tmp_path, name):
    folder.add(hours_old=1)
    response = browser.get("/backups", params={"download": name})
    assert response.status_code == 404 and not _records(audit, "backup_download")


def test_a_download_that_cannot_be_recorded_does_not_happen(db, folder, tmp_path):
    name = folder.add(hours_old=1, data=b"the locked bytes")
    audit = AuditLog(path=tmp_path / "audit.jsonl")
    browser = _browser(db, audit, folder)
    audit.path.unlink()
    audit.path.mkdir()  # the log cannot be written
    response = browser.get("/backups", params={"download": name})
    assert response.status_code == 500 and b"the locked bytes" not in response.content


# --- the button ----------------------------------------------------------------------------


def test_the_button_makes_a_backup(browser, folder):
    response = browser.post("/backups", data={"form_token": _form_token(browser), "action": "make"},
                            headers={"Origin": ORIGIN})
    assert response.status_code == 303 and response.headers["location"] == "backups"
    assert len(folder.made) == 1


def test_the_button_needs_nervuss_own_page(browser, folder):
    token = _form_token(browser)
    assert browser.post("/backups", data={"form_token": token, "action": "make"},
                        headers={"Origin": "https://elsewhere.example"}).status_code == 403
    assert browser.post("/backups", data={"form_token": "forged", "action": "make"},
                        headers={"Origin": ORIGIN}).status_code == 403
    assert folder.made == []


def test_a_backup_that_fails_says_why(browser, folder):
    folder.fails = "cannot read ssh_ca_key"
    response = browser.post("/backups", data={"form_token": _form_token(browser), "action": "make"},
                            headers={"Origin": ORIGIN})
    assert response.status_code == 500 and "No backup was made: cannot read ssh_ca_key" in response.text


# --- after a restore (question 6) ---------------------------------------------------------


@pytest.fixture
def machines(db):
    return Machines(codes=EnrollmentCodes(db), store=EnrolledHostStore(db), pin=lambda: "sha256//x", port=8000,
                    by_hand=[])


def test_after_a_restore_the_machines_page_says_what_is_not_here_until_the_next_backup(db, audit, folder, machines):
    browser = _browser(db, audit, folder, machines=machines)
    made = datetime(2026, 10, 28, 16, 30, tzinfo=timezone.utc).timestamp()
    folder.event("restored", at=time.time() - 60, made_at=made)
    for path in ("/machines", "/backups"):
        assert "Restored from a backup made 2026-10-28 16:30 UTC" in browser.get(path).text
    folder.event("made", at=time.time())
    for path in ("/machines", "/backups"):
        assert "Restored from a backup made" not in browser.get(path).text
