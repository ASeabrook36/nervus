"""Tests for tools/release-archive (ADR-0032 questions 1 and 2, step 2), run against a scratch
preview repository.

The scratch repository is this repository's own committed tree (its `git archive HEAD`; in the
export's run of tests/, which has no .git, the tree's own files), shaped as tools/export-preview
shapes an export, by that tool's own lists: the deployment record and this repository's own files
left out, the preview's own files put in their place. It is at release NUMBER: its pyproject.toml
says so, its lock was made for it, and its CHANGES.md has that release's section, beginning
"Exported <a day>.", as the commit an export is made from has. It is one commit, with an origin
remote on GitHub under a made-up owner. The tool runs as the operator runs it, with this
Python. The release page's line is run as printed, in a scratch folder, with curl fetching the file
by file:// and a stand-in sudo that writes down where it ran and what it was asked, and runs
nothing. Nothing here touches this repository or any other.
"""

from __future__ import annotations

import gzip
import hashlib
import importlib.machinery
import importlib.util
import errno
import io
import os
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
TOOL = REPO / "tools" / "release-archive"
EXPORT_TOOL = REPO / "tools" / "export-preview"
NUMBER = "0.7.0"
TOP = f"nervus-{NUMBER}"
FILE = f"{TOP}.tar.gz"
PAGE = f"{TOP}.release.md"
REMOTE = "https://github.com/example-owner/nervus.git"
DOWNLOAD = f"https://github.com/example-owner/nervus/releases/download/v{NUMBER}"
CHANGES = (f"# Changes\n\nWhat each release changes.\n\n## {NUMBER}\n\nExported 2026-11-20.\n\n"
           "**What you will see:** the release download.\n\n**What each client must do:** nothing.\n\n"
           "**What the upgrade does:** `sudo ./install.sh --upgrade`.\n\n"
           "## 0.6.0\n\nExported 2026-11-01.\n\n**What you will see:** the one before.\n")
NEEDS_THE_LINE = pytest.mark.skipif(shutil.which("curl") is None or shutil.which("sha256sum") is None,
                                    reason="the release page's line needs curl and sha256sum, and this machine "
                                           "lacks one")


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.net",
                           "-c", "commit.gpgsign=false", *args], check=True, capture_output=True, text=True).stdout


def _load(path: Path, name: str):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def _module():
    return _load(TOOL, "release_archive")


def _as_an_export(tree: Path) -> None:
    """The tree shaped as tools/export-preview shapes an export, by its own lists: what it leaves out goes, and the
    preview's own files take their places. A tree with no preview/ is an export's already: the export's run of
    tests/ is in one."""
    export = _load(EXPORT_TOOL, "export_preview")
    if not (tree / "preview").is_dir():
        assert all((tree / target).is_file() for _, target in export.ADDED), "neither this repository nor an export"
        return
    added = {target: (tree / source).read_bytes() for source, target in export.ADDED}
    for name in export.LEFT_OUT:
        if (tree / name).is_dir():
            shutil.rmtree(tree / name)
        elif (tree / name).exists():
            (tree / name).unlink()
    for target, data in added.items():
        (tree / target).write_bytes(data)


def _own_tree(into: Path) -> None:
    """This repository's committed tree; in a tree with no .git, as the export's run of tests/ is, its files."""
    if (REPO / ".git").exists():
        into.mkdir(parents=True)
        archive = subprocess.run(["git", "-C", str(REPO), "archive", "--format=tar", "HEAD"], check=True,
                                 capture_output=True).stdout
        subprocess.run(["tar", "-x", "-C", str(into)], input=archive, check=True)
    else:
        shutil.copytree(REPO, into, symlinks=True,
                        ignore=shutil.ignore_patterns("__pycache__", ".venv", "secrets", ".pytest_cache"))


def _commit(repo: Path, name: str, text: str | None, message: str = "change") -> None:
    if text is None:
        _git(repo, "rm", "-q", name)
    else:
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(text)
        _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)


@pytest.fixture(scope="module")
def base(tmp_path_factory):
    preview = tmp_path_factory.mktemp("base") / "preview"
    _own_tree(preview)
    _as_an_export(preview)
    pyproject = preview / "pyproject.toml"
    pyproject.write_text(re.sub(r'(?m)^version = ".*"$', f'version = "{NUMBER}"', pyproject.read_text()))
    lock = preview / "requirements.lock"
    lock.write_text(re.sub(r"(?m)^# Made for nervus \S+ on ", f"# Made for nervus {NUMBER} on ", lock.read_text()))
    (preview / "CHANGES.md").write_text(CHANGES)
    _git(preview, "init", "-q", "-b", "main")
    _git(preview, "add", "-A")
    _git(preview, "commit", "-q", "-m", "Export of 0000000, 2026-11-20")
    _git(preview, "remote", "add", "origin", REMOTE)
    return preview


@pytest.fixture
def preview(base, tmp_path):
    copy = tmp_path / "preview"
    shutil.copytree(base, copy, symlinks=True)
    return copy


def _run(preview: Path, *args: str, out: Path | None = None, path: Path | None = None) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    if path is not None:
        env["PATH"] = f"{path}{os.pathsep}{env['PATH']}"
    there = ["--out", str(out if out is not None else preview.parent / "out")]
    return subprocess.run([sys.executable, str(TOOL), str(preview), *there, *args], capture_output=True, text=True,
                          timeout=180, env=env)


def _made(done: subprocess.CompletedProcess, out: Path) -> tuple[bytes, str]:
    assert done.returncode == 0, done.stdout + done.stderr
    data = (out / FILE).read_bytes()
    return data, (out / PAGE).read_text()


def _line(page: str, ending: str = " && sudo ./install.sh") -> str:
    """The one line of the page that begins with curl and ends as given."""
    found = [line for line in page.splitlines() if line.startswith("curl ") and line.endswith(ending)]
    assert len(found) == 1, page
    return found[0]


def _refused(done: subprocess.CompletedProcess, out: Path, *says: str) -> None:
    """Stopped, saying why, with nothing put in the out folder."""
    assert done.returncode == 1, done.stdout + done.stderr
    stop = next((line for line in done.stdout.splitlines() if "STOP" in line), "")
    for words in says:
        assert words in stop, done.stdout
    assert f"nothing was put in {out}" in done.stdout
    assert not (out / FILE).exists() and not (out / PAGE).exists()


def _release_name(*args: str, stdin: bytes | None = None, tool: Path = REPO / "tools" / "release-name") -> str:
    done = subprocess.run([sys.executable, "-I", str(tool), "--full", *args], input=stdin, capture_output=True,
                          check=True)
    return done.stdout.decode().strip()


# --- the archive, its hash and its page ------------------------------------------------------------------

def test_the_archive_is_made_and_its_hash_is_printed_and_in_the_line(preview, tmp_path):
    out = tmp_path / "out"
    done = _run(preview, out=out)
    data, page = _made(done, out)
    digest = hashlib.sha256(data).hexdigest()
    assert f"{out / FILE}: {len(data):,} bytes, SHA-256 {digest}" in done.stdout
    # ADR-0032 question 2's line, exactly: the two spaces are sha256sum's check format.
    install = (f"curl -fsSLO '{DOWNLOAD}/{FILE}' && echo '{digest}  {FILE}' | sha256sum -c - && tar -xzf {FILE} "
               f"&& cd {TOP} && sudo ./install.sh")
    assert _line(page) == install
    assert install.replace("sudo ./install.sh", "./install.sh") in page.splitlines()
    assert f"{install} --upgrade" in page.splitlines()
    assert install.replace("sudo ./install.sh", "./install.sh --upgrade") in page.splitlines()
    assert "apt-get update && apt-get install -y curl" in page.splitlines()
    assert "the file is whole, and is the one this page names" in " ".join(page.split())
    assert "who controls the repository's account" in " ".join(page.split())


def test_the_page_is_printed_and_written_with_its_title_tag_and_the_releases_changes(preview, tmp_path):
    out = tmp_path / "out"
    done = _run(preview, out=out)
    _, page = _made(done, out)
    sha = _git(preview, "rev-parse", "HEAD").strip()
    assert page in done.stdout
    assert f"title        nervus {NUMBER}" in done.stdout
    assert f"tag          v{NUMBER}, on commit {sha}" in done.stdout
    # The release's own section, below a heading of its own, and no other release's.
    changes = page.split(f"## What {NUMBER} changes\n", 1)[1]
    assert changes.startswith("\nExported 2026-11-20.\n") and "**What each client must do:** nothing." in changes
    assert "the one before" not in page and "## 0.6.0" not in page
    # The next step: the release, its tag on the export commit, the file attached, the description pasted.
    assert f"the tag v{NUMBER}, on commit {sha}, the export commit" in done.stdout
    assert f"attach {out / FILE}" in done.stdout and f"paste {out / PAGE}" in done.stdout


def test_every_member_is_under_the_releases_own_folder_and_the_header_holds_no_time_or_name(preview, tmp_path):
    out = tmp_path / "out"
    data, _ = _made(_run(preview, out=out), out)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        names = tar.getnames()
    assert TOP in names and "nervus-0.7.0/install.sh" in names and "nervus-0.7.0/tools/release-name" in names
    assert all(name == TOP or name.startswith(f"{TOP}/") for name in names), [n for n in names if TOP not in n]
    # gzip's header: no file name (flag 8), and its time, bytes 4 to 7, is 0.
    assert data[:3] == b"\x1f\x8b\x08" and not data[3] & 0x08 and data[4:8] == b"\0\0\0\0"


def test_the_same_commit_gives_the_same_bytes(preview, tmp_path):
    # On one machine, with one git and one Python: no time and no name in the header, nothing that moves between runs.
    first, second = tmp_path / "first", tmp_path / "second"
    a, page_a = _made(_run(preview, out=first), first)
    b, page_b = _made(_run(preview, out=second), second)
    assert a == b and page_a == page_b


def test_the_archive_is_the_commits_tree_as_release_name_names_it(preview, tmp_path):
    out = tmp_path / "out"
    done = _run(preview, out=out)
    _made(done, out)
    name = _release_name("--archive", stdin=subprocess.run(["git", "-C", str(preview), "archive", "HEAD"],
                                                           capture_output=True, check=True).stdout).split()[0]
    assert f"which release-name names {name}, as it names the commit" in done.stdout


@pytest.mark.parametrize("kept", [FILE, PAGE])
def test_a_file_already_in_the_out_folder_is_refused_and_left_as_it_was(preview, tmp_path, kept):
    out = tmp_path / "out"
    out.mkdir()
    (out / kept).write_text("made once and kept\n")
    done = _run(preview, out=out)
    assert done.returncode == 1, done.stdout + done.stderr
    assert f"{out / kept} is there already, and is never replaced" in done.stdout
    assert "2.   made" not in done.stdout  # refused before anything is made
    assert (out / kept).read_text() == "made once and kept\n"
    assert sorted(p.name for p in out.iterdir()) == [kept]


def test_a_file_that_appears_while_it_runs_is_not_replaced_and_nothing_is_left(tmp_path):
    # Checked first, and again as each file is made: a file is made only where none is, and on a refusal the
    # one made before it goes too, so the folder holds a whole pair or nothing of this run's.
    module = _module()
    (tmp_path / PAGE).write_text("made once and kept\n")
    with pytest.raises(module.Stop, match="is there already, and is never replaced"):
        module.keep(tmp_path, [(FILE, b"the archive"), (PAGE, b"the description")])
    assert sorted(p.name for p in tmp_path.iterdir()) == [PAGE]
    assert (tmp_path / PAGE).read_text() == "made once and kept\n"


@pytest.mark.parametrize("kept", [FILE, PAGE])
def test_a_link_to_nothing_in_the_out_folder_is_refused_and_left_as_it_was(preview, tmp_path, kept):
    out = tmp_path / "out"
    out.mkdir()
    (out / kept).symlink_to("nowhere")
    done = _run(preview, out=out)
    assert done.returncode == 1 and f"{out / kept} is there already, and is never replaced" in done.stdout
    assert os.readlink(out / kept) == "nowhere" and sorted(p.name for p in out.iterdir()) == [kept]


def test_the_files_are_made_whole_with_nothing_left_beside_them(tmp_path):
    _module().keep(tmp_path, [(FILE, b"the archive"), (PAGE, b"the description")])
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted([FILE, PAGE])
    assert (tmp_path / FILE).read_bytes() == b"the archive" and (tmp_path / PAGE).read_bytes() == b"the description"


@pytest.mark.parametrize("failing", [1, 2], ids=["the-archive", "the-description"])
def test_a_write_that_fails_leaves_nothing_of_this_run_in_the_out_folder(tmp_path, monkeypatch, failing):
    # A disk that fills as a file is written: a file cut short must never stand under the name a rerun would call
    # the one to publish. Whichever file it is, nothing this run made is left, and it stops saying why.
    module = _module()
    calls, fsync = [], os.fsync

    def full(fd):
        calls.append(fd)
        if len(calls) == failing:
            raise OSError(errno.ENOSPC, "No space left on device")
        fsync(fd)

    monkeypatch.setattr(module.os, "fsync", full)
    with pytest.raises(module.Stop, match="No space left on device"):
        module.keep(tmp_path, [(FILE, b"the archive"), (PAGE, b"the description")])
    assert list(tmp_path.iterdir()) == []


def test_only_the_commit_is_read_never_the_working_tree(preview, tmp_path):
    (preview / "CHANGES.md").write_text(CHANGES.replace("Exported 2026-11-20.", "Not yet exported."))
    (preview / "unsaved.txt").write_text("never committed\n")
    out = tmp_path / "out"
    data, _ = _made(_run(preview, out=out), out)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        assert f"{TOP}/unsaved.txt" not in tar.getnames()
        assert b"Exported 2026-11-20." in tar.extractfile(f"{TOP}/CHANGES.md").read()


# --- the commit must be an export's ---------------------------------------------------------------------

def test_its_list_of_what_no_export_holds_is_export_previews():
    # What export-preview leaves out and does not put back, and what it puts in their place: one list, in two tools.
    export = _load(EXPORT_TOOL, "export_preview")
    put_back = {target for _, target in export.ADDED}
    assert set(_module().NOT_IN_AN_EXPORT) == set(export.LEFT_OUT) - put_back
    assert set(_module().THE_PREVIEWS_OWN) == put_back


@pytest.mark.parametrize("name, what", [
    ("procedures/001-a-step.md", "the deployment record"), ("CURRENT_STATE.md", "the deployment record"),
    ("hosts.yaml", "the deployment record"), ("deployment/0001-a-note.md", "the deployment record"),
    (".mcp.json", "this repository's own files"), ("preview/README.md", "this repository's own files"),
], ids=["procedures", "current-state", "hosts", "deployment", "mcp-json", "preview"])
def test_a_commit_holding_what_no_export_holds_is_refused(preview, tmp_path, name, what):
    _commit(preview, name, "this repository's own\n")
    out = tmp_path / "out"
    _refused(_run(preview, out=out), out, f"is not the preview's export: it holds {name.split('/')[0]}, {what}, "
                                          "which tools/export-preview leaves out of every export")
    assert not out.exists()


def test_this_repositorys_own_commit_is_refused_as_holding_the_deployment_record(preview, tmp_path):
    # The private repository's commits say "Exported <the day>." from an export until the next number: the record
    # is what tells them from the preview's.
    for name in ("procedures/001-a-step.md", "deployment/0001-a-note.md", "CURRENT_STATE.md", "hosts.yaml"):
        (preview / name).parent.mkdir(parents=True, exist_ok=True)
        (preview / name).write_text("this installation's\n")
    _commit(preview, ".mcp.json", "{}\n")
    out = tmp_path / "out"
    done = _run(preview, out=out)
    _refused(done, out, "is not the preview's export: it holds .mcp.json, CURRENT_STATE.md, deployment, hosts.yaml "
                        "and procedures, the deployment record and this repository's own files, which",
             "It is a commit of this repository", "the preview repository's checkout")
    assert "2.   made" not in done.stdout


@pytest.mark.parametrize("name", [".mcp.json.example", "README.md"])
def test_a_commit_without_the_previews_own_files_is_refused(preview, tmp_path, name):
    _commit(preview, name, None)
    out = tmp_path / "out"
    _refused(_run(preview, out=out), out, f"is not the preview's export: it has no {name}")


@pytest.mark.parametrize("changes, says", [
    (CHANGES.replace("Exported 2026-11-20.", "Not yet exported."), "begins 'Not yet exported.'"),
    (CHANGES.replace("Exported 2026-11-20.", "Exported 2026-11-20. And more."), "begins 'Exported 2026-11-20. And"),
    (CHANGES.replace("Exported 2026-11-20.", "Exported on 2026-11-20."), "begins 'Exported on 2026-11-20.'"),
    (CHANGES.replace("Exported 2026-11-20.\n\n", ""), "begins '**What you will see:**"),
    (CHANGES.replace(f"## {NUMBER}", "## 0.6.9"), f"has no section for {NUMBER}"),
    (CHANGES.replace(f"## {NUMBER}", f"### {NUMBER}"), f"has no section for {NUMBER}"),
    (None, "has no CHANGES.md"),
], ids=["not-yet-exported", "more-on-the-line", "other-words", "no-day", "no-section", "another-level", "no-file"])
def test_a_commit_whose_section_does_not_say_it_was_exported_is_refused(preview, tmp_path, changes, says):
    _commit(preview, "CHANGES.md", changes)
    out = tmp_path / "out"
    _refused(_run(preview, out=out), out, says, "export commit")
    assert not out.exists()


def test_the_heading_may_go_on_after_the_number(preview, tmp_path):
    _commit(preview, "CHANGES.md", CHANGES.replace(f"## {NUMBER}\n", f"## {NUMBER} (the release download)\n"))
    out = tmp_path / "out"
    _made(_run(preview, out=out), out)


def test_commit_names_the_export_commit_when_head_is_not(preview, tmp_path):
    export = _git(preview, "rev-parse", "HEAD").strip()
    _commit(preview, "CHANGES.md", CHANGES.replace("Exported 2026-11-20.", "Not yet exported."))
    out = tmp_path / "out"
    _refused(_run(preview, out=out), out, "Not yet exported.")
    done = _run(preview, "--commit", "HEAD~1", out=out)
    _made(done, out)
    assert f"1.   commit {export}, release {NUMBER}" in done.stdout
    _refused(_run(preview, "--commit", "no-such-thing", out=tmp_path / "other"), tmp_path / "other",
             "no-such-thing is not a commit of")


@pytest.mark.parametrize("version, says", [
    ("version = 0.7", "0.7, is not in quotes"),
    ('version = "0.7"', "'0.7', is not three numbers with no leading zeros"),
    ('version = "0.07.0"', "'0.07.0', is not three numbers"),
    ('version = "v0.7.0"', "'v0.7.0', is not three numbers"),
    ('version = "0.7.0.1"', "'0.7.0.1', is not three numbers"),
    ('version = "0.7.0rc1"', "'0.7.0rc1', is not three numbers"),
    ("", "names no version"),
], ids=["not-in-quotes", "two-parts", "a-leading-zero", "a-letter-before", "four-parts", "letters-after",
        "no-version"])
def test_a_release_number_not_three_numbers_in_quotes_is_refused(preview, tmp_path, version, says):
    text = (preview / "pyproject.toml").read_text()
    _commit(preview, "pyproject.toml", re.sub(r'(?m)^version = ".*"$', version, text))
    out = tmp_path / "out"
    _refused(_run(preview, out=out), out, "the release number of commit" if version else "the pyproject.toml of",
             says)


def test_a_commit_with_no_pyproject_is_refused(preview, tmp_path):
    _commit(preview, "pyproject.toml", None)
    out = tmp_path / "out"
    _refused(_run(preview, out=out), out, "has no pyproject.toml")


# --- the folder the line downloads from -----------------------------------------------------------------

def test_url_is_used_as_given_whatever_the_remote(preview, tmp_path):
    _git(preview, "remote", "set-url", "origin", "https://code.example.net/someone/nervus.git")
    out = tmp_path / "out"
    _, page = _made(_run(preview, "--url", "https://downloads.example.net/nervus/", out=out), out)
    assert _line(page).startswith(f"curl -fsSLO 'https://downloads.example.net/nervus/{FILE}' && ")


@pytest.mark.parametrize("url", ["https://downloads.example.net/it's", "downloads.example.net/nervus",
                                 "https://downloads.example.net/a folder", "file:///",
                                 "https://downloads.example.net/nervus?v=1", "https://downloads.example.net/nervus#a",
                                 "https://downloads.example.net/```"],
                         ids=["a-quote", "no-scheme", "a-space", "nothing-after-the-scheme", "a-query", "a-fragment",
                              "backticks"])
def test_a_url_the_line_cannot_carry_cannot_run(preview, tmp_path, url):
    done = _run(preview, "--url", url, out=tmp_path / "out")
    assert done.returncode == 2 and "is not a URL the line can carry" in done.stderr, done.stdout + done.stderr
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize("remote", [
    "https://github.com/example-owner/nervus.git", "https://github.com/example-owner/nervus",
    "git@github.com:example-owner/nervus.git", "git@github.com:example-owner/nervus",
    "ssh://git@github.com/example-owner/nervus", "ssh://git@github.com/example-owner/nervus.git",
], ids=["https", "https-no-git", "scp-form", "scp-form-no-git", "ssh", "ssh-with-git"])
def test_the_download_folder_is_the_github_releases_from_the_origin_remote(preview, tmp_path, remote):
    _git(preview, "remote", "set-url", "origin", remote)
    out = tmp_path / "out"
    _, page = _made(_run(preview, out=out), out)
    assert _line(page).startswith(f"curl -fsSLO '{DOWNLOAD}/{FILE}' && ")


@pytest.mark.parametrize("remote, says", [
    ("https://code.example.net/example-owner/nervus.git", "https://code.example.net/example-owner/nervus.git, "
                                                         "is not on GitHub"),
    ("git@code.example.net:example-owner/nervus.git", "is not on GitHub"),
    ("https://github.com/example-owner", "is not on GitHub"),
    ("https://github.com.example.net/example-owner/nervus.git", "is not on GitHub"),
    (None, "it has no origin remote"),
], ids=["another-host", "another-host-scp-form", "no-repository", "a-lookalike-host", "no-remote"])
def test_a_remote_not_on_github_with_no_url_stops_it_asking_for_url(preview, tmp_path, remote, says):
    if remote is None:
        _git(preview, "remote", "remove", "origin")
    else:
        _git(preview, "remote", "set-url", "origin", remote)
    out = tmp_path / "out"
    _refused(_run(preview, out=out), out, says, "give it as --url")


# --- the checks on what was made ------------------------------------------------------------------------

def _archive(tmp_path: Path, *members: tuple) -> Path:
    """A gzipped tar of the members given, each (name, type, link target)."""
    path = tmp_path / "made.tar.gz"
    with tarfile.open(path, "w:gz") as tar:
        for name, kind, target in members:
            info = tarfile.TarInfo(name)
            info.type, info.linkname = kind, target or ""
            data = b"x\n" if kind == tarfile.REGTYPE else b""
            info.size, info.mode = len(data), 0o755 if kind == tarfile.DIRTYPE else 0o644
            tar.addfile(info, io.BytesIO(data))
    return path


GOOD = [(TOP, tarfile.DIRTYPE, None), (f"{TOP}/README.md", tarfile.REGTYPE, None),
        (f"{TOP}/docs", tarfile.DIRTYPE, None), (f"{TOP}/docs/readme", tarfile.SYMTYPE, "../README.md"),
        (f"{TOP}/docs/top", tarfile.SYMTYPE, "..")]


def test_an_archive_of_files_folders_and_links_inside_its_folder_passes(tmp_path):
    _module().members(_archive(tmp_path, *GOOD), TOP)


@pytest.mark.parametrize("member, says", [
    (("elsewhere/x", tarfile.REGTYPE, None), "is not under nervus-0.7.0/"),
    ((f"{TOP}/./docs/x", tarfile.REGTYPE, None), "has an empty or . part"),
    ((f"{TOP}//docs/x", tarfile.REGTYPE, None), "has an empty or . part"),
    ((f"./{TOP}/x", tarfile.REGTYPE, None), "is not under nervus-0.7.0/"),
    (("nervus-0.7.0-other/x", tarfile.REGTYPE, None), "is not under nervus-0.7.0/"),
    (("/etc/x", tarfile.REGTYPE, None), "is an absolute path"),
    ((f"{TOP}/../x", tarfile.REGTYPE, None), "goes up a folder"),
    ((f"{TOP}/l", tarfile.SYMTYPE, "/etc/passwd"), "is a link to an absolute path"),
    ((f"{TOP}/docs/l", tarfile.SYMTYPE, "../../x"), "is a link pointing outside nervus-0.7.0/"),
    ((f"{TOP}/l", tarfile.SYMTYPE, f"../{TOP}-other"), "is a link pointing outside nervus-0.7.0/"),
    ((f"{TOP}/docs/top/x", tarfile.REGTYPE, None), "lies beneath 'nervus-0.7.0/docs/top', a link"),
    ((f"{TOP}/h", tarfile.LNKTYPE, f"{TOP}/README.md"), "is a hard link"),
    ((f"{TOP}/c", tarfile.CHRTYPE, None), "is a device"),
    ((f"{TOP}/b", tarfile.BLKTYPE, None), "is a device"),
    ((f"{TOP}/f", tarfile.FIFOTYPE, None), "is a fifo"),
], ids=["another-folder", "a-dot-part", "an-empty-part", "dot-first", "a-longer-name", "absolute", "dot-dot",
        "link-absolute", "link-up-and-out", "link-to-a-folder-beside", "beneath-a-link", "hard-link",
        "character-device", "block-device", "fifo"])
def test_a_member_unsafe_to_unpack_is_refused(tmp_path, member, says):
    module = _module()
    with pytest.raises(module.Stop, match=re.escape(says)):
        module.members(_archive(tmp_path, *GOOD, member), TOP)


@pytest.mark.parametrize("more, says", [
    # A link stored with a slash at its end is the same link: what lies beneath it is beneath a link.
    ([(f"{TOP}/l/", tarfile.SYMTYPE, "docs"), (f"{TOP}/l/x", tarfile.REGTYPE, None)],
     "lies beneath 'nervus-0.7.0/l', a link"),
    # Each link alone resolves inside on paper, but on disk p is s/.., which is nervus-0.7.0/.., outside.
    ([(f"{TOP}/s", tarfile.SYMTYPE, "."), (f"{TOP}/p", tarfile.SYMTYPE, "s/..")],
     "'nervus-0.7.0/p' in the archive is a link whose target passes through 'nervus-0.7.0/s', a link"),
    ([(f"{TOP}/s", tarfile.SYMTYPE, "."), (f"{TOP}/p", tarfile.SYMTYPE, "s/.."), (f"{TOP}/q", tarfile.SYMTYPE, "p/..")],
     "'nervus-0.7.0/p' in the archive is a link whose target passes through 'nervus-0.7.0/s', a link"),
    ([(f"{TOP}/q", tarfile.SYMTYPE, "docs/top/x")], "passes through 'nervus-0.7.0/docs/top', a link"),
    # A target that leaves the folder on its way, and comes back: the way out is the person's own disk.
    ([(f"{TOP}/l", tarfile.SYMTYPE, f"../{TOP}/README.md")], "is a link pointing outside nervus-0.7.0/"),
], ids=["a-link-with-a-slash", "a-chain-out", "a-longer-chain-out", "through-a-link-to-a-folder", "out-and-back"])
def test_links_that_unpack_somewhere_other_than_they_read_are_refused(tmp_path, more, says):
    module = _module()
    with pytest.raises(module.Stop, match=re.escape(says)):
        module.members(_archive(tmp_path, *GOOD, *more), TOP)


def test_a_link_to_a_link_is_not_a_link_passed_through(tmp_path):
    # Its target ends at the other link, which resolves inside on its own: nothing is passed through.
    _module().members(_archive(tmp_path, *GOOD, (f"{TOP}/again", tarfile.SYMTYPE, "docs/readme")), TOP)


def test_a_committed_link_pointing_outside_stops_it_before_anything_is_unpacked(preview, tmp_path):
    (preview / "docs" / "outside").symlink_to("../../elsewhere")
    _git(preview, "add", "-A")
    _git(preview, "commit", "-q", "-m", "a link out")
    out = tmp_path / "out"
    _refused(_run(preview, out=out), out, "'nervus-0.7.0/docs/outside' in the archive is a link pointing outside")


def _standin_tar(bin_dir: Path, then: str) -> Path:
    """A tar that unpacks as the system's does, then does `then` in the folder it unpacked."""
    bin_dir.mkdir(exist_ok=True)
    fake = bin_dir / "tar"
    fake.write_text(f'#!/bin/sh\n{shutil.which("tar")} "$@" || exit\ncd {TOP} && {then}\n')
    fake.chmod(0o755)
    return bin_dir


@pytest.mark.parametrize("then", ["printf x >> README.md", "chmod u-x tools/check-up"],
                         ids=["a-byte-gained", "a-run-bit-lost"])
def test_an_archive_that_tar_unpacks_as_another_tree_is_refused(preview, tmp_path, then):
    out = tmp_path / "out"
    done = _run(preview, out=out, path=_standin_tar(tmp_path / "bin", then))
    _refused(done, out, "the archive is not the tree of commit", "install.sh would install another release")


def test_a_lock_not_made_for_its_release_is_refused(preview, tmp_path):
    lock = (preview / "requirements.lock").read_text()
    _commit(preview, "requirements.lock",
            lock.replace(f"# Made for nervus {NUMBER} on ", "# Made for nervus 0.6.0 on "))
    out = tmp_path / "out"
    _refused(_run(preview, out=out), out, f"requirements.lock was made for 0.6.0, and this tree is {NUMBER}",
             "install.sh would refuse it")


def test_an_install_sh_its_owner_may_not_run_is_refused(preview, tmp_path):
    _git(preview, "update-index", "--chmod=-x", "install.sh")
    _git(preview, "commit", "-q", "-m", "install.sh not runnable")
    out = tmp_path / "out"
    _refused(_run(preview, out=out), out, "install.sh is not a file its owner may run")


def test_an_install_sh_that_is_a_link_is_refused(preview, tmp_path):
    (preview / "install.sh").unlink()
    (preview / "install.sh").symlink_to("tools/check-up")
    _git(preview, "add", "-A")
    _git(preview, "commit", "-q", "-m", "install.sh a link")
    out = tmp_path / "out"
    _refused(_run(preview, out=out), out, "install.sh is not a file its owner may run")


def test_a_release_name_that_refuses_is_refused_saying_why(preview, tmp_path):
    _commit(preview, "tools/release-name", "import sys\nprint('release-name: it cannot', file=sys.stderr)\n"
                                           "sys.exit(1)\n")
    out = tmp_path / "out"
    _refused(_run(preview, out=out), out, "release-name cannot name the unpacked archive: it cannot")


@pytest.mark.parametrize("name", ["tools/release-name", "tools/lock-libraries"])
def test_an_archive_without_the_tools_install_sh_runs_is_refused(preview, tmp_path, name):
    _commit(preview, name, None)
    out = tmp_path / "out"
    _refused(_run(preview, out=out), out, f"the archive has no {name}, which install.sh runs")


# --- what it cannot run with ----------------------------------------------------------------------------

def test_an_out_folder_inside_the_preview_checkout_cannot_run(preview):
    done = _run(preview, out=preview / "dist")
    assert done.returncode == 2 and "cannot be inside the preview checkout" in done.stderr, done.stderr
    assert not (preview / "dist").exists()


def test_an_out_that_is_a_file_cannot_run(preview, tmp_path):
    (tmp_path / "out").write_text("a file\n")
    done = _run(preview, out=tmp_path / "out")
    assert done.returncode == 2 and "is not a folder" in done.stderr, done.stderr


@pytest.mark.parametrize("make", ["a-link-to-a-folder-in-it", "a-link-to-it-then-a-folder", "a-link-to-nothing-in-it"])
def test_an_out_folder_that_resolves_inside_the_preview_checkout_cannot_run(preview, tmp_path, make):
    link = tmp_path / "link"
    if make == "a-link-to-a-folder-in-it":
        (preview / "dist").mkdir()
        link.symlink_to(preview / "dist")
        out = link
    elif make == "a-link-to-it-then-a-folder":
        link.symlink_to(preview)
        out = link / "dist"
    else:
        link.symlink_to(preview / "dist")
        out = link
    done = _run(preview, out=out)
    assert done.returncode == 2 and "cannot be inside the preview checkout" in done.stderr, done.stdout + done.stderr
    assert not (preview / "dist").exists() or list((preview / "dist").iterdir()) == []


@pytest.mark.parametrize("lacking", ["git", "tar"])
def test_a_machine_without_git_or_tar_cannot_run(preview, tmp_path, lacking):
    # PATH holds only what is given: git alone, where tar is the one lacking.
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    if lacking == "tar":
        (bin_dir / "git").symlink_to(shutil.which("git"))
    done = subprocess.run([sys.executable, str(TOOL), str(preview), "--out", str(tmp_path / "out")],
                          capture_output=True, text=True, timeout=60, env={**os.environ, "PATH": str(bin_dir)})
    assert done.returncode == 2 and f"{lacking} is not installed" in done.stderr, done.stdout + done.stderr


@pytest.mark.parametrize("make", ["missing", "not-a-checkout"])
def test_a_preview_that_is_not_a_checkout_cannot_run(tmp_path, make):
    preview = tmp_path / "preview"
    if make == "not-a-checkout":
        preview.mkdir()
    done = _run(preview, out=tmp_path / "out")
    assert done.returncode == 2 and "give the preview repository's checkout" in done.stderr, done.stderr


# --- the release page's line, run (ADR-0032 verification 2) --------------------------------------------

def _standin_sudo(bin_dir: Path, record: Path) -> Path:
    """A sudo that writes down the folder it ran in and what it was asked to run, and runs nothing."""
    bin_dir.mkdir(exist_ok=True)
    fake = bin_dir / "sudo"
    fake.write_text(f'#!/bin/sh\npwd > {record}\necho "$@" >> {record}\n')
    fake.chmod(0o755)
    return bin_dir


def _paste(line: str, machine: Path, bin_dir: Path) -> subprocess.CompletedProcess:
    machine.mkdir(exist_ok=True)
    return subprocess.run(["bash", "-c", line], cwd=machine, capture_output=True, text=True, timeout=120,
                          env={**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"})


@NEEDS_THE_LINE
def test_the_line_downloads_checks_and_unpacks_the_release_and_runs_its_installer(preview, tmp_path):
    out = tmp_path / "out"
    _, page = _made(_run(preview, "--url", f"file://{out}", out=out), out)
    record, machine = tmp_path / "sudo-was-asked", tmp_path / "machine"
    bin_dir = _standin_sudo(tmp_path / "bin", record)
    done = _paste(_line(page), machine, bin_dir)
    assert done.returncode == 0, done.stdout + done.stderr
    assert f"{FILE}: OK" in done.stdout
    assert record.read_text().splitlines() == [str((machine / TOP).resolve()), "./install.sh"]
    # The folder the line unpacked is the release the commit is: release-name, as install.sh names it.
    by_commit = _release_name("--archive", stdin=subprocess.run(["git", "-C", str(preview), "archive", "HEAD"],
                                                                capture_output=True, check=True).stdout)
    assert _release_name(str(machine / TOP), tool=machine / TOP / "tools" / "release-name") == by_commit
    # The upgrade line, in the same folder, runs the installer with --upgrade.
    done = _paste(_line(page, " && sudo ./install.sh --upgrade"), machine, bin_dir)
    assert done.returncode == 0, done.stdout + done.stderr
    assert record.read_text().splitlines() == [str((machine / TOP).resolve()), "./install.sh --upgrade"]


@NEEDS_THE_LINE
def test_a_file_whose_bytes_differ_is_refused_before_anything_is_unpacked_or_run(preview, tmp_path):
    """ADR-0032 verification 2: an archive whose SHA-256 is not the line's is refused before anything
    is unpacked or run."""
    out = tmp_path / "out"
    data, page = _made(_run(preview, "--url", f"file://{out}", out=out), out)
    # One byte changed: gzip's time, which tar never reads, so the file is still a whole archive tar would unpack.
    # Only the hash can stop it.
    changed = data[:4] + b"\x01" + data[5:]
    assert gzip.decompress(changed) == gzip.decompress(data)
    (out / FILE).write_bytes(changed)
    record, machine = tmp_path / "sudo-was-asked", tmp_path / "machine"
    done = _paste(_line(page), machine, _standin_sudo(tmp_path / "bin", record))
    assert done.returncode != 0, done.stdout + done.stderr
    assert "FAILED" in done.stdout + done.stderr
    assert sorted(p.name for p in machine.iterdir()) == [FILE]  # downloaded, and nothing unpacked
    assert not record.exists()  # nothing run
