"""The export store (ADR-0016 decisions B, D, E, F, G and I): owner-only
exports, space reserved before copying, copies that cannot outgrow their
reservation, finished exports that never change, 24-hour expiry, and recovery
after a stop."""

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

from nervus.config import ConfigError
from nervus.database import Database
from nervus.exports import (
    DELETED,
    EXPIRED,
    FAILED,
    KEEP_SPENT_SECONDS,
    LIFETIME_SECONDS,
    MAX_EXPORT_BYTES,
    READY,
    STAGING,
    ExportRefused,
    ExportStore,
    Limits,
    safe_filename,
)

T0 = 1_800_000_000.0
REPO = Path(__file__).resolve().parent.parent
# The release deployed before this one (procedures/022). Its database code is what a
# rollback would run.
PREVIOUS_RELEASE = "fa938f3"
PLENTY = 100 * 1024**3
SOURCE = {"kind": "vm", "vmid": 100, "path": "/tmp/a.tar.gz"}


@pytest.fixture
def database(tmp_path):
    db = Database(tmp_path / "nervus.db")
    db.open()
    return db


@pytest.fixture
def store(database, tmp_path):
    s = ExportStore(database, tmp_path / "exports", free_bytes=lambda: PLENTY)
    s.open(now=T0)
    return s


def _begin(store, token="codex-anywhere", key="k1", size=11, now=T0, filename="a.tar.gz"):
    return store.begin(token, key, SOURCE, filename, size, now=now)


def _ready(store, data=b"hello world", token="codex-anywhere", key="k1", now=T0):
    export, _ = _begin(store, token=token, key=key, size=len(data), now=now)
    writer = store.writer(export)
    writer.write(data)
    return store.finish(export, writer, now=now)


# --- making one, and a retry (decision I) ------------------------------------------


def test_begin_reserves_and_records_a_staging_export(store):
    export, created = _begin(store, size=11)
    assert created
    assert export.state == STAGING
    assert export.reserved_bytes == 11
    assert export.expires_at == T0 + LIFETIME_SECONDS
    assert len(export.id) == 32


def test_the_same_token_and_key_returns_the_same_export_and_starts_nothing(store, tmp_path):
    first, _ = _begin(store)
    again, created = _begin(store, size=999)
    assert not created
    assert again.id == first.id
    assert again.reserved_bytes == 11  # the retry's size changes nothing
    assert list((tmp_path / "exports").iterdir()) == []


def test_the_same_key_from_another_token_is_another_export(store):
    mine, _ = _begin(store, token="codex-anywhere")
    theirs, created = _begin(store, token="claude-code-project-a")
    assert created and theirs.id != mine.id


@pytest.mark.parametrize("key", ["", "a b", "../x", "k" * 129, "ключ"])
def test_a_request_key_must_be_plain(store, key):
    with pytest.raises(ExportRefused) as refused:
        _begin(store, key=key)
    assert refused.value.code == "bad_request_key"


# --- limits (decision D) -----------------------------------------------------------


def test_a_file_over_256_mib_is_refused_before_anything_is_recorded(store, tmp_path):
    with pytest.raises(ExportRefused) as refused:
        _begin(store, size=MAX_EXPORT_BYTES + 1)
    assert refused.value.code == "too_large"
    assert store.by_key("codex-anywhere", "k1") is None
    assert list((tmp_path / "exports").iterdir()) == []


def test_exactly_256_mib_is_allowed(store):
    _, created = _begin(store, size=MAX_EXPORT_BYTES)
    assert created


def test_the_total_counts_copies_still_being_made(database, tmp_path):
    store = ExportStore(database, tmp_path / "exports", limits=Limits(max_export_bytes=60, max_total_bytes=100),
                        free_bytes=lambda: PLENTY)
    store.open(now=T0)
    _begin(store, key="a", size=60)  # staging, not yet written
    with pytest.raises(ExportRefused) as refused:
        _begin(store, key="b", size=41)
    assert refused.value.code == "quota"
    _, created = _begin(store, key="c", size=40)
    assert created


def test_space_comes_back_when_an_export_fails_or_is_deleted(database, tmp_path):
    store = ExportStore(database, tmp_path / "exports", limits=Limits(max_export_bytes=100, max_total_bytes=100),
                        free_bytes=lambda: PLENTY)
    store.open(now=T0)
    a, _ = _begin(store, key="a", size=100)
    store.fail(a, "source", "the source refused", now=T0)
    b = _ready(store, data=b"x" * 100, key="b")
    with pytest.raises(ExportRefused):
        _begin(store, key="c", size=1)
    assert store.delete("codex-anywhere", b.id, now=T0)
    _, created = _begin(store, key="c", size=100)
    assert created


def test_the_free_space_floor_counts_what_copies_have_yet_to_write(database, tmp_path):
    free = {"bytes": 1000}
    store = ExportStore(database, tmp_path / "exports", limits=Limits(free_floor_bytes=500),
                        free_bytes=lambda: free["bytes"])
    store.open(now=T0)
    _begin(store, key="a", size=300)  # 300 promised, none written
    with pytest.raises(ExportRefused) as refused:
        _begin(store, key="b", size=201)  # 1000 - 300 - 201 < 500
    assert refused.value.code == "disk_floor"
    _, created = _begin(store, key="c", size=200)
    assert created


def test_exports_made_at_once_cannot_together_pass_the_total(database, tmp_path):
    """Decision D: the reservation is one transaction, so of many exports
    begun at the same moment, only as many as fit succeed."""
    store = ExportStore(database, tmp_path / "exports", limits=Limits(max_export_bytes=100, max_total_bytes=500),
                        free_bytes=lambda: PLENTY)
    store.open(now=T0)
    results, start = [], threading.Barrier(12)

    def one(i):
        start.wait()
        try:
            store.begin("codex-anywhere", f"k{i}", SOURCE, "f", 100, now=T0)
            results.append("ok")
        except ExportRefused as exc:
            results.append(exc.code)

    threads = [threading.Thread(target=one, args=(i,)) for i in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count("ok") == 5
    assert results.count("quota") == 7


# --- the copy (decisions F and G) --------------------------------------------------


def test_a_finished_export_has_the_hash_and_size_of_what_was_written(store, tmp_path):
    data = os.urandom(3 * 1024 * 1024 + 7)
    export, _ = _begin(store, size=len(data))
    writer = store.writer(export)
    for i in range(0, len(data), 1024 * 1024):
        writer.write(data[i:i + 1024 * 1024])
    done = store.finish(export, writer, now=T0)
    assert done.state == READY
    assert done.size == len(data)
    assert done.sha256 == hashlib.sha256(data).hexdigest()
    final = tmp_path / "exports" / export.id
    assert final.read_bytes() == data
    assert stat.S_IMODE(final.stat().st_mode) == 0o400
    assert [p.name for p in (tmp_path / "exports").iterdir()] == [export.id]


def test_a_source_smaller_than_declared_releases_the_rest(store):
    export, _ = _begin(store, size=100)
    writer = store.writer(export)
    writer.write(b"short")
    assert store.finish(export, writer, now=T0).reserved_bytes == 5


def test_a_copy_cannot_pass_its_reservation(store, tmp_path):
    export, _ = _begin(store, size=10)
    writer = store.writer(export)
    writer.write(b"0123456789")
    with pytest.raises(ExportRefused) as refused:
        writer.write(b"!")
    assert refused.value.code == "grew"
    failed = store.fail(export, refused.value.code, refused.value.message, writer=writer, now=T0)
    assert failed.state == FAILED and failed.failure_code == "grew"
    assert list((tmp_path / "exports").iterdir()) == []


def test_a_staging_file_is_never_written_through_a_planted_link(store, tmp_path):
    export, _ = _begin(store, size=5)
    outside = tmp_path / "outside"
    outside.write_text("untouched")
    (tmp_path / "exports" / f"{export.id}.part").symlink_to(outside)
    with pytest.raises(ExportRefused) as refused:
        store.writer(export)
    assert refused.value.code == "staging_exists"
    assert outside.read_text() == "untouched"


def test_an_export_deleted_while_being_copied_does_not_become_ready(store, tmp_path):
    export, _ = _begin(store, size=5)
    writer = store.writer(export)
    writer.write(b"hello")
    assert store.delete("codex-anywhere", export.id, now=T0)
    with pytest.raises(ExportRefused):
        store.finish(export, writer, now=T0)
    assert list((tmp_path / "exports").iterdir()) == []
    assert store.get("codex-anywhere", export.id, now=T0).state == DELETED


# --- reading one back (decisions B and G) ------------------------------------------


def test_the_token_that_made_it_can_open_it(store):
    done = _ready(store)
    export, f = store.open_ready("codex-anywhere", done.id, now=T0)
    with f:
        assert f.read() == b"hello world"
    assert export.sha256 == done.sha256


def test_another_token_cannot_see_or_open_or_delete_it(store, tmp_path):
    done = _ready(store)
    other = "claude-code-project-a"
    assert store.get(other, done.id, now=T0) is None
    assert store.open_ready(other, done.id, now=T0) is None
    assert not store.delete(other, done.id, now=T0)
    assert (tmp_path / "exports" / done.id).exists()


@pytest.mark.parametrize("export_id", ["", "../nervus.db", "..", "a/b", "0" * 31, "0" * 33, "A" * 32,
                                       "/etc/passwd", "0" * 32 + ".part"])
def test_an_id_that_is_not_an_export_id_finds_nothing(store, export_id):
    _ready(store)
    assert store.get("codex-anywhere", export_id, now=T0) is None
    assert store.open_ready("codex-anywhere", export_id, now=T0) is None


def test_a_staging_export_is_not_downloadable(store):
    export, _ = _begin(store)
    assert store.open_ready("codex-anywhere", export.id, now=T0) is None


def test_a_file_swapped_for_a_link_is_refused(store, tmp_path):
    done = _ready(store)
    final = tmp_path / "exports" / done.id
    outside = tmp_path / "secret"
    outside.write_bytes(b"hello world")  # even the same bytes
    final.unlink()
    final.symlink_to(outside)
    with pytest.raises(ExportRefused) as refused:
        store.open_ready("codex-anywhere", done.id, now=T0)
    assert refused.value.code == "lost"


def test_a_file_swapped_for_a_pipe_is_refused_and_never_waited_on(store, tmp_path):
    """Opened without waiting: a plain open of a pipe waits for a writer that
    never comes, and the check that it is a file comes after the open."""
    done = _ready(store)
    final = tmp_path / "exports" / done.id
    final.unlink()
    os.mkfifo(final)
    signal.signal(signal.SIGALRM, lambda *_: pytest.fail("it waited on the pipe"))
    signal.alarm(5)
    try:
        with pytest.raises(ExportRefused) as refused:
            store.open_ready("codex-anywhere", done.id, now=T0)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, signal.SIG_DFL)
    assert refused.value.code == "lost"


def test_a_file_of_the_wrong_size_is_refused(store, tmp_path):
    done = _ready(store)
    final = tmp_path / "exports" / done.id
    final.chmod(0o600)
    final.write_bytes(b"hello world, and more")
    with pytest.raises(ExportRefused):
        store.open_ready("codex-anywhere", done.id, now=T0)


# --- expiry and deletion (decision E) ----------------------------------------------


def test_an_export_expires_after_24_hours_and_its_file_goes(store, tmp_path):
    done = _ready(store)
    later = T0 + LIFETIME_SECONDS
    assert store.get("codex-anywhere", done.id, now=later - 1).state == READY
    assert store.get("codex-anywhere", done.id, now=later).state == EXPIRED
    assert store.open_ready("codex-anywhere", done.id, now=later) is None  # even before a sweep
    assert store.sweep(now=later) == 1
    assert list((tmp_path / "exports").iterdir()) == []


def test_a_retry_after_expiry_says_expired_rather_than_copying_again(store):
    _ready(store)
    again, created = _begin(store, now=T0 + LIFETIME_SECONDS + 1)
    assert not created and again.state == EXPIRED


def test_a_spent_record_is_forgotten_a_day_after_it_expired(store):
    done = _ready(store)
    store.sweep(now=T0 + LIFETIME_SECONDS)
    store.sweep(now=T0 + LIFETIME_SECONDS + KEEP_SPENT_SECONDS)
    assert store.get("codex-anywhere", done.id) is None


def test_a_client_can_delete_its_own_export_early(store, tmp_path):
    done = _ready(store)
    assert store.delete("codex-anywhere", done.id, now=T0)
    assert store.get("codex-anywhere", done.id, now=T0).state == DELETED
    assert list((tmp_path / "exports").iterdir()) == []
    assert not store.delete("codex-anywhere", done.id, now=T0)


# --- after a stop -------------------------------------------------------------------


def test_a_restart_fails_a_copy_in_progress_and_deletes_what_it_left(database, store, tmp_path):
    export, _ = _begin(store, key="half", size=10)
    writer = store.writer(export)
    writer.write(b"half")
    writer.close()
    kept = _ready(store, key="whole")
    (tmp_path / "exports" / "stray").write_text("not an export")
    ExportStore(database, tmp_path / "exports", free_bytes=lambda: PLENTY).open(now=T0 + 60)
    failed = store.get("codex-anywhere", export.id, now=T0 + 60)
    assert failed.state == FAILED and failed.failure_code == "interrupted"
    assert failed.reserved_bytes == 0
    assert sorted(p.name for p in (tmp_path / "exports").iterdir()) == [kept.id]
    assert store.get("codex-anywhere", kept.id, now=T0 + 60).state == READY


def test_a_restart_fails_a_ready_export_whose_file_has_gone(database, store, tmp_path):
    done = _ready(store)
    (tmp_path / "exports" / done.id).unlink()
    store.open(now=T0 + 60)
    lost = store.get("codex-anywhere", done.id, now=T0 + 60)
    assert lost.state == FAILED and lost.failure_code == "lost"


# --- the directory ------------------------------------------------------------------


def test_the_directory_is_made_0700(store, tmp_path):
    assert stat.S_IMODE((tmp_path / "exports").stat().st_mode) == 0o700


def test_a_directory_others_can_read_is_refused(database, tmp_path):
    (tmp_path / "exports").mkdir(mode=0o755)
    (tmp_path / "exports").chmod(0o755)
    with pytest.raises(ConfigError):
        ExportStore(database, tmp_path / "exports").open(now=T0)


def test_a_directory_that_is_a_link_is_refused(database, tmp_path):
    real = tmp_path / "elsewhere"
    real.mkdir(mode=0o700)
    (tmp_path / "exports").symlink_to(real)
    with pytest.raises(ConfigError):
        ExportStore(database, tmp_path / "exports").open(now=T0)


# --- the name a client is told ------------------------------------------------------


@pytest.mark.parametrize("given, told", [
    ("/tmp/out/a.tar.gz", "a.tar.gz"),
    ("C:\\x\\b.zip", "b.zip"),
    ("../../etc/passwd", "passwd"),
    (".hidden", "hidden"),
    ("/tmp/", "export"),
    ("a\nb\x1b[2J.txt", "ab[2J.txt"),
])
def test_the_suggested_filename_is_a_plain_name(given, told):
    assert safe_filename(given) == told


# --- the database: added without changing its version (ADR-0014 decision F) --------


def test_the_table_is_added_without_changing_the_version(database):
    with sqlite3.connect(database.path) as check:
        assert check.execute("PRAGMA user_version").fetchone()[0] == 1
        assert check.execute("SELECT COUNT(*) FROM export").fetchone()[0] == 0


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


def test_the_release_before_still_opens_a_database_with_exports(database, store, tmp_path):
    """A deploy that rolls back runs the deployed release against the
    database this one left."""
    _ready(store)
    previous = _previous_database_module(tmp_path)
    rolled_back = previous.Database(database.path)
    rolled_back.open()
    link, _ = rolled_back.make_link(now=T0)
    rolled_back.use_link(link, now=T0)
    database.open()
    assert store.by_key("codex-anywhere", "k1", now=T0).state == READY


# --- a failure before any space was reserved (decision I) ---------------------------


def test_a_refusal_is_kept_under_its_request_key(store, tmp_path):
    refused = store.refuse("codex-anywhere", "k1", SOURCE, "a.tar.gz", "not_a_file", "a directory", now=T0)
    assert refused.state == FAILED and refused.failure_code == "not_a_file"
    assert refused.reserved_bytes == 0
    again, created = _begin(store, key="k1")
    assert not created and again.id == refused.id
    assert list((tmp_path / "exports").iterdir()) == []


def test_a_refusal_never_replaces_an_export_the_key_already_has(store):
    export, _ = _begin(store, key="k1")
    assert store.refuse("codex-anywhere", "k1", SOURCE, "a", "x", "y", now=T0).id == export.id
    assert store.get("codex-anywhere", export.id, now=T0).state == STAGING
