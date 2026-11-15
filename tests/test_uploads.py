"""The upload store (ADR-0020 step 1; decisions B, E, F, G and H): owner-only
uploads under a request key, space reserved before the body is read and shared
with exports, a staged copy that must match the declared size and SHA-256
before it is delivered, deleted as soon as it is delivered or has failed, a
one-time secret for a VM's pull, and recovery after a stop."""

import hashlib
import importlib.util
import os
import shutil
import signal
import sqlite3
import stat
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from nervus.database import Database
from nervus.exports import ExportStore, Limits
from nervus.exports import STAGING as EXPORT_STAGING
from nervus.uploads import (
    DELIVERED,
    DELIVERING,
    FAILED,
    KEEP_SPENT_SECONDS,
    PULL_SECRET_SECONDS,
    RECEIVING,
    UploadRefused,
    UploadStore,
)

T0 = 1_800_000_000.0
REPO = Path(__file__).resolve().parent.parent
# The release deployed before this one (procedures/028). Its database code is what a
# rollback would run.
PREVIOUS_RELEASE = "2915cd5"
PLENTY = 100 * 1024**3
DATA = b"hello world"
SHA = hashlib.sha256(DATA).hexdigest()
DEST = {"kind": "host", "host": "web", "path": "/srv/a.txt", "root": False, "replace": False}


@pytest.fixture
def database(tmp_path):
    db = Database(tmp_path / "nervus.db")
    db.open()
    return db


def _store(database, tmp_path, limits=Limits(), free=lambda: PLENTY):
    s = UploadStore(database, tmp_path / "uploads", limits=limits, free_bytes=free)
    s.open(now=T0)
    return s


@pytest.fixture
def store(database, tmp_path):
    return _store(database, tmp_path)


def _begin(store, token="codex-anywhere", key="k1", size=len(DATA), sha=SHA, now=T0, dest=DEST):
    return store.begin(token, key, dest, size, sha, now=now)


def _received(store, data=DATA, token="codex-anywhere", key="k1", sha=None, size=None, now=T0):
    upload, _ = _begin(store, token=token, key=key, size=len(data) if size is None else size,
                       sha=hashlib.sha256(data).hexdigest() if sha is None else sha, now=now)
    receiver = store.receiver(upload)
    receiver.write(data)
    return store.received(upload, receiver, now=now)


def _files(store):
    return sorted(p.name for p in store.directory.iterdir())


# --- making one, and a retry (decision G) --------------------------------------------


def test_begin_reserves_and_records_a_receiving_upload(store):
    upload, created = _begin(store)
    assert created
    assert upload.state == RECEIVING
    assert upload.reserved_bytes == len(DATA)
    assert upload.size == len(DATA)
    assert upload.sha256 == SHA
    assert upload.destination == DEST
    assert len(upload.id) == 32


def test_the_same_key_and_hash_returns_the_same_upload(store):
    first, _ = _begin(store)
    again, created = _begin(store, now=T0 + 5)
    assert not created
    assert again.id == first.id


def test_the_same_key_with_another_hash_is_refused(store):
    _begin(store)
    with pytest.raises(UploadRefused) as refused:
        _begin(store, sha="0" * 64)
    assert refused.value.code == "key_reused"


def test_the_same_key_from_another_token_is_another_upload(store):
    first, _ = _begin(store)
    other, created = _begin(store, token="claude-code")
    assert created and other.id != first.id


@pytest.mark.parametrize("key", ["", "a b", "../x", "k" * 129, "ключ"])
def test_a_request_key_must_be_plain(store, key):
    with pytest.raises(UploadRefused) as refused:
        _begin(store, key=key)
    assert refused.value.code == "bad_request_key"


@pytest.mark.parametrize("sha", ["", "abc", "g" * 64, SHA + "0"])
def test_a_declared_hash_must_be_a_sha256(store, sha):
    with pytest.raises(UploadRefused) as refused:
        _begin(store, sha=sha)
    assert refused.value.code == "bad_sha256"


def test_a_declared_hash_in_capitals_is_the_same_hash(store):
    upload, _ = _begin(store, sha=SHA.upper())
    assert upload.sha256 == SHA


@pytest.mark.parametrize("size", [-1, None, "11", 1.5])
def test_a_declared_size_must_be_a_whole_number(store, size):
    with pytest.raises(UploadRefused) as refused:
        _begin(store, size=size)
    assert refused.value.code == "bad_size"


# --- space, shared with exports (decision F) -----------------------------------------


def test_a_file_over_256_mib_is_refused_before_anything_is_recorded(store):
    with pytest.raises(UploadRefused) as refused:
        _begin(store, size=256 * 1024**2 + 1)
    assert refused.value.code == "too_large"
    assert store.by_key("codex-anywhere", "k1", now=T0) is None


def test_uploads_count_against_exports_total(database, tmp_path):
    limits = Limits(max_export_bytes=100, max_total_bytes=150)
    uploads = _store(database, tmp_path, limits)
    exports = ExportStore(database, tmp_path / "exports", limits=limits, free_bytes=lambda: PLENTY)
    exports.open(now=T0)
    _begin(uploads, size=100)
    with pytest.raises(Exception) as refused:
        exports.begin("codex-anywhere", "e1", {"kind": "host"}, "f", 100, now=T0)
    assert refused.value.code == "quota"


def test_exports_count_against_uploads_total(database, tmp_path):
    limits = Limits(max_export_bytes=100, max_total_bytes=150)
    uploads = _store(database, tmp_path, limits)
    exports = ExportStore(database, tmp_path / "exports", limits=limits, free_bytes=lambda: PLENTY)
    exports.open(now=T0)
    export, _ = exports.begin("codex-anywhere", "e1", {"kind": "host"}, "f", 100, now=T0)
    assert export.state == EXPORT_STAGING
    with pytest.raises(UploadRefused) as refused:
        _begin(uploads, size=100)
    assert refused.value.code == "quota"


def test_the_free_floor_counts_what_both_have_yet_to_write(database, tmp_path):
    limits = Limits(max_export_bytes=100, max_total_bytes=10_000, free_floor_bytes=1000)
    uploads = _store(database, tmp_path, limits, free=lambda: 1150)
    exports = ExportStore(database, tmp_path / "exports", limits=limits, free_bytes=lambda: 1150)
    exports.open(now=T0)
    exports.begin("codex-anywhere", "e1", {"kind": "host"}, "f", 100, now=T0)
    with pytest.raises(UploadRefused) as refused:
        _begin(uploads, size=100)
    assert refused.value.code == "disk_floor"
    _begin(uploads, size=50)
    with pytest.raises(Exception) as refused:
        exports.begin("codex-anywhere", "e2", {"kind": "host"}, "f", 1, now=T0)
    assert refused.value.code == "disk_floor"


def test_uploads_begun_at_once_cannot_together_pass_the_total(database, tmp_path):
    store = _store(database, tmp_path, Limits(max_export_bytes=100, max_total_bytes=500))
    results, start = [], threading.Barrier(12)

    def one(i):
        start.wait()
        try:
            _begin(store, key=f"k{i}", size=100)
            results.append("ok")
        except UploadRefused as exc:
            results.append(exc.code)

    threads = [threading.Thread(target=one, args=(i,)) for i in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count("ok") == 5
    assert results.count("quota") == 7


# --- receiving (decision B) ----------------------------------------------------------


def test_a_whole_matching_body_is_sealed_and_ready_to_deliver(store):
    upload = _received(store)
    assert upload.state == DELIVERING
    assert upload.bytes_received == len(DATA)
    assert _files(store) == [upload.id]
    staged = store.directory / upload.id
    assert stat.S_IMODE(staged.stat().st_mode) == 0o400
    with store.open_staged(upload) as f:
        assert f.read() == DATA


def test_a_staged_copy_swapped_for_a_pipe_is_refused_and_never_waited_on(store):
    """Opened without waiting: a plain open of a pipe waits for a writer that
    never comes, and the check that it is a file comes after the open."""
    upload = _received(store)
    staged = store.directory / upload.id
    staged.unlink()
    os.mkfifo(staged)
    signal.signal(signal.SIGALRM, lambda *_: pytest.fail("it waited on the pipe"))
    signal.alarm(5)
    try:
        with pytest.raises(UploadRefused) as refused:
            store.open_staged(upload)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, signal.SIG_DFL)
    assert refused.value.code == "lost"


def test_a_body_that_does_not_match_its_hash_fails_and_leaves_nothing(store):
    upload = _received(store, data=b"hello wOrld", sha=SHA)
    assert upload.state == FAILED
    assert upload.failure_code == "hash_mismatch"
    assert upload.reserved_bytes == 0
    assert _files(store) == []


def test_a_body_shorter_than_declared_fails_and_leaves_nothing(store):
    upload = _received(store, data=b"hello", size=len(DATA), sha=SHA)
    assert upload.state == FAILED
    assert upload.failure_code == "short"
    assert _files(store) == []


def test_a_body_cannot_pass_its_declared_size(store):
    upload, _ = _begin(store, size=5)
    receiver = store.receiver(upload)
    receiver.write(b"hello")
    with pytest.raises(UploadRefused) as refused:
        receiver.write(b"!")
    assert refused.value.code == "too_long"


def test_a_staged_file_is_never_written_through_a_planted_link(store, tmp_path):
    upload, _ = _begin(store)
    target = tmp_path / "elsewhere"
    os.symlink(target, store.directory / (upload.id + ".part"))
    with pytest.raises(UploadRefused):
        store.receiver(upload)
    assert not target.exists()


def test_progress_is_recorded_while_receiving(store):
    upload, _ = _begin(store)
    store.progress(upload.id, 5)
    assert store.get("codex-anywhere", upload.id, now=T0).bytes_received == 5


# --- delivering, and the space coming back (decisions B and F) ------------------------


def test_a_delivery_with_the_declared_hash_deletes_the_staged_copy(store):
    upload = _received(store)
    done = store.delivered(upload, route="sftp", sha256=SHA, now=T0 + 1)
    assert done.state == DELIVERED
    assert done.route == "sftp"
    assert done.reserved_bytes == 0
    assert done.finished_at == T0 + 1
    assert _files(store) == []


def test_a_delivery_whose_destination_hashed_differently_fails(store):
    upload = _received(store)
    done = store.delivered(upload, route="sftp", sha256="0" * 64, now=T0)
    assert done.state == FAILED
    assert done.failure_code == "destination_hash"
    assert _files(store) == []


def test_a_failed_delivery_releases_its_space_and_deletes_the_copy(store):
    upload = _received(store)
    done = store.fail(upload, "unreachable", "the host did not answer", now=T0)
    assert done.state == FAILED and done.reserved_bytes == 0
    assert _files(store) == []


def test_only_a_receiving_upload_can_be_received_into(store):
    upload = _received(store)
    with pytest.raises(UploadRefused) as refused:
        store.receiver(upload)
    assert refused.value.code == "not_receiving"


def test_only_a_delivering_upload_can_be_delivered(store):
    upload, _ = _begin(store)
    with pytest.raises(UploadRefused) as refused:
        store.delivered(upload, route="sftp", sha256=SHA, now=T0)
    assert refused.value.code == "not_delivering"


# --- ownership (decision H) -----------------------------------------------------------


def test_another_token_cannot_see_an_upload(store):
    upload, _ = _begin(store)
    assert store.get("claude-code", upload.id, now=T0) is None
    assert store.by_key("claude-code", "k1", now=T0) is None
    assert store.get("codex-anywhere", upload.id, now=T0).id == upload.id


@pytest.mark.parametrize("upload_id", ["", "../x", "A" * 32, "0" * 31])
def test_an_id_that_is_not_an_upload_id_finds_nothing(store, upload_id):
    assert store.get("codex-anywhere", upload_id, now=T0) is None


# --- the one-time secret for a VM's pull (decision E) ----------------------------------


def test_a_pull_secret_works_once(store):
    upload = _received(store)
    secret = store.issue_pull_secret(upload, now=T0)
    assert len(secret) >= 43
    claimed = store.claim_pull_secret(secret, now=T0 + 1)
    assert claimed is not None and claimed.id == upload.id
    assert store.claim_pull_secret(secret, now=T0 + 2) is None


def test_a_pull_secret_expires_unused(store):
    upload = _received(store)
    secret = store.issue_pull_secret(upload, now=T0)
    assert store.claim_pull_secret(secret, now=T0 + PULL_SECRET_SECONDS + 1) is None


@pytest.mark.parametrize("secret", ["", "x", "0" * 43])
def test_an_unknown_pull_secret_finds_nothing(store, secret):
    _received(store)
    assert store.claim_pull_secret(secret, now=T0) is None


def test_a_pull_secret_is_only_for_an_upload_being_delivered(store):
    upload, _ = _begin(store)
    with pytest.raises(UploadRefused) as refused:
        store.issue_pull_secret(upload, now=T0)
    assert refused.value.code == "not_delivering"
    delivering = _received(store, key="k2")
    secret = store.issue_pull_secret(delivering, now=T0)
    store.delivered(delivering, route="pull", sha256=delivering.sha256, now=T0)
    assert store.claim_pull_secret(secret, now=T0) is None


def test_the_pull_secret_itself_is_not_stored(store, database):
    upload = _received(store)
    secret = store.issue_pull_secret(upload, now=T0)
    with sqlite3.connect(database.path) as check:
        row = check.execute("SELECT * FROM upload").fetchone()
    assert secret not in repr(row)


# --- a stop, and forgetting (decision G) ------------------------------------------------


def test_a_restart_fails_uploads_in_progress_and_deletes_their_files(database, store, tmp_path):
    receiving, _ = _begin(store, key="r")
    store.receiver(receiving).write(b"hel")
    delivering = _received(store, key="d")
    (store.directory / "stray").write_bytes(b"x")
    again = UploadStore(database, store.directory, free_bytes=lambda: PLENTY)
    was_delivering = again.recover(now=T0 + 1)
    assert [u.id for u in was_delivering] == [delivering.id]
    for key in ("r", "d"):
        upload = again.by_key("codex-anywhere", key, now=T0 + 1)
        assert upload.state == FAILED
        assert upload.failure_code == "interrupted"
        assert upload.reserved_bytes == 0
    assert _files(again) == []


def test_a_spent_record_answers_its_key_for_a_day_then_is_forgotten(store):
    upload = _received(store)
    store.delivered(upload, route="sftp", sha256=SHA, now=T0)
    store.sweep(now=T0 + KEEP_SPENT_SECONDS - 1)
    assert store.by_key("codex-anywhere", "k1", now=T0).state == DELIVERED
    store.sweep(now=T0 + KEEP_SPENT_SECONDS + 1)
    assert store.by_key("codex-anywhere", "k1", now=T0) is None


def test_the_sweep_leaves_uploads_in_progress(store):
    upload, _ = _begin(store)
    store.sweep(now=T0 + 10 * KEEP_SPENT_SECONDS)
    assert store.get("codex-anywhere", upload.id, now=T0).state == RECEIVING


# --- the directory and the database --------------------------------------------------


def test_the_directory_is_made_0700(store):
    assert stat.S_IMODE(store.directory.stat().st_mode) == 0o700


def test_a_directory_others_can_read_is_refused(database, tmp_path):
    (tmp_path / "uploads").mkdir(mode=0o755)
    os.chmod(tmp_path / "uploads", 0o755)
    with pytest.raises(Exception, match="0700"):
        _store(database, tmp_path)


def test_the_table_is_added_without_changing_the_version(database):
    with sqlite3.connect(database.path) as check:
        assert check.execute("PRAGMA user_version").fetchone()[0] == 1
        assert check.execute("SELECT COUNT(*) FROM upload").fetchone()[0] == 0


def _previous_database_module(tmp_path):
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    shown = subprocess.run(["git", "-C", str(REPO), "show", f"{PREVIOUS_RELEASE}:src/nervus/database.py"],
                           capture_output=True, text=True)
    if shown.returncode != 0:
        pytest.skip(f"this checkout has no {PREVIOUS_RELEASE}")
    source = tmp_path / "previous_database.py"
    source.write_text(shown.stdout)
    spec = importlib.util.spec_from_file_location("previous_database", source)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        del sys.modules[spec.name]
    return module


def test_the_release_before_still_opens_a_database_with_uploads(database, store, tmp_path):
    """A deploy that rolls back runs the deployed release against the
    database this one left."""
    _received(store)
    previous = _previous_database_module(tmp_path)
    rolled_back = previous.Database(database.path)
    rolled_back.open()
    link, _ = rolled_back.make_link(now=T0)
    rolled_back.use_link(link, now=T0)
    database.open()
    assert store.by_key("codex-anywhere", "k1", now=T0).state == DELIVERING
