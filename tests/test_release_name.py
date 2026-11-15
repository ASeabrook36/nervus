"""tools/release-name (ADR-0029 question 3a): the name of the folder a release is installed in,
<number>-<the first 12 hex digits of its code>, its code one SHA-256 over what that folder holds.

Shown on a small git repository made here, which holds each kind of thing a tree holds: a file,
a file that may be run, an empty file, a link, a link to a folder, a link to nothing, a path too
long for tar's plain header, and the tree's own hosts.yaml, as this repository has one. The tool
runs as install.sh runs it, with `python3 -I`. Nothing here touches this repository or any other.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import os
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

TOOL = Path(__file__).resolve().parent.parent / "tools" / "release-name"

PYPROJECT = '[project]\nname = "thing"\nversion = "1.10.0"\n'
LONG = "src/thing/" + "a-rather-long-folder-name/" * 11 + "deep.py"  # over 256 bytes: a pax header in git's tar
FILES = {
    "pyproject.toml": (PYPROJECT, 0o644),
    "install.sh": ("#!/bin/bash\necho installing\n", 0o755),
    "src/thing/__init__.py": ("VALUE = 1\n", 0o644),
    "src/thing/core.py": ("def go():\n    return 1\n", 0o644),
    "src/thing/target/readonly-shell": ("#!/bin/sh\nexec true\n", 0o755),
    "docs/empty.md": ("", 0o644),
    "hosts.yaml": ("hosts:\n  - name: someone-elses\n", 0o644),
    LONG: ("DEEP = 1\n", 0o644),
}
LINKS = {"docs/latest.md": "empty.md", "bin": "src/thing/target", "docs/gone": "nowhere"}
LEFT_OUT_AT_THE_TOP = [".git", ".venv", "secrets", "transfer", "releases", "hosts.yaml", ".release"]


def _git(repo: Path, *args: str) -> bytes:
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.net", *args],
                          check=True, capture_output=True).stdout


def _write(tree: Path, files: dict, links: dict | None = None) -> Path:
    for name, (text, mode) in files.items():
        (tree / name).parent.mkdir(parents=True, exist_ok=True)
        (tree / name).write_text(text)
        (tree / name).chmod(mode)
    for name, target in (links or {}).items():
        (tree / name).parent.mkdir(parents=True, exist_ok=True)
        (tree / name).symlink_to(target)
    return tree


def _repository(at: Path, files: dict, links: dict | None = None) -> Path:
    _write(at, files, links)
    _git(at, "init", "-q", "-b", "main")
    _git(at, "add", "-A")
    _git(at, "commit", "-q", "-m", "tree")
    return at


@pytest.fixture(scope="module")
def repo(tmp_path_factory):
    return _repository(tmp_path_factory.mktemp("clone") / "thing", FILES, LINKS)


def _archive(repo: Path, form: str = "tar") -> bytes:
    return _git(repo, "archive", f"--format={form}", "HEAD")


def _unpacked(repo: Path, into: Path) -> Path:
    into.mkdir()
    subprocess.run(["tar", "-x", "-C", str(into)], input=_archive(repo), check=True)
    return into


def _run(*args: str, stdin: bytes | None = None, python=(sys.executable, "-I")) -> subprocess.CompletedProcess:
    return subprocess.run([*python, str(TOOL), *args], input=stdin or b"", capture_output=True, timeout=60)


def _full(*args: str, stdin: bytes | None = None) -> tuple[str, str, str]:
    done = _run("--full", *args, stdin=stdin)
    assert done.returncode == 0, done.stderr.decode()
    name, number, code = done.stdout.decode().split()
    return name, number, code


def _code(*args: str, stdin: bytes | None = None) -> str:
    return _full(*args, stdin=stdin)[2]


def _refused(done: subprocess.CompletedProcess, says: str) -> None:
    """Exit 1, the reason on standard error, and no name for install.sh to take."""
    assert (done.returncode, done.stdout) == (1, b""), done.stdout + done.stderr
    assert done.stderr.decode().startswith("release-name: "), done.stderr
    assert says in done.stderr.decode(), done.stderr


def test_a_clone_and_its_archive_unpacked_have_one_code(repo, tmp_path):
    """A clone's `git archive HEAD`, as install.sh reads it; that archive unpacked; the same
    unpacked with the tree's own hosts.yaml removed, as install.sh leaves the release's folder;
    the clone itself, as install.sh reads a plain copy; and the archive compressed, as
    docs/install.md's hand steps make it: one code, so one release."""
    code = _code("--archive", stdin=_archive(repo))
    unpacked = _unpacked(repo, tmp_path / "unpacked")
    assert _code(str(unpacked)) == code
    (unpacked / "hosts.yaml").unlink()
    assert _code(str(unpacked)) == code
    assert _code(str(repo)) == code
    assert _code("--archive", stdin=_archive(repo, "tar.gz")) == code


def test_a_name_outside_ascii_has_one_code_from_the_archive_and_the_folder(tmp_path):
    # Its path is hashed as its bytes, UTF-8's, read from the archive or the folder alike. It is
    # kept out of FILES, the tree the zip test unpacks: the unzip on macOS cannot unpack such a name.
    clone = _repository(tmp_path / "thing", {**FILES, "docs/caf\u00e9.md": ("x\n", 0o644)}, LINKS)
    unpacked = _unpacked(clone, tmp_path / "unpacked")
    assert _code("--archive", stdin=_archive(clone)) == _code(str(unpacked)) == _code(str(clone))


@pytest.mark.skipif(shutil.which("unzip") is None, reason="unzip is not installed")
def test_a_zip_unpacked_with_unzip_has_the_code_too(repo, tmp_path):
    # unzip keeps the run bits and links git writes into a zip; an unpacker that drops them makes other code.
    (tmp_path / "thing.zip").write_bytes(_archive(repo, "zip"))
    (tmp_path / "unzipped").mkdir()
    subprocess.run(["unzip", "-q", str(tmp_path / "thing.zip")], cwd=tmp_path / "unzipped", check=True)
    assert _code(str(tmp_path / "unzipped")) == _code("--archive", stdin=_archive(repo))


def _relink(path: Path, target: str) -> None:
    path.unlink()
    path.symlink_to(target)


def _link_as_file(path: Path) -> None:
    # The file holds the link's target as its bytes, so only the kind tells the two apart.
    target = os.readlink(path)
    path.unlink()
    path.write_text(target)


COUNTED = {
    "one byte changed": lambda t: (t / "src/thing/__init__.py").write_text("VALUE = 2\n"),
    "a file renamed": lambda t: (t / "src/thing/core.py").rename(t / "src/thing/main.py"),
    "a file moved to another folder": lambda t: (t / "src/thing/core.py").rename(t / "src/core.py"),
    "one run bit dropped": lambda t: (t / "install.sh").chmod(0o644),
    "one run bit given": lambda t: (t / "src/thing/core.py").chmod(0o744),
    "one empty file added": lambda t: (t / "docs/new.md").touch(),
    "one file removed": lambda t: (t / "docs/empty.md").unlink(),
    "a link's target changed": lambda t: _relink(t / "docs/latest.md", "other.md"),
    "a link made a file holding its target": lambda t: _link_as_file(t / "docs/latest.md"),
    "the file down the long path changed": lambda t: (t / LONG).write_text("DEEP = 2\n"),
}


@pytest.mark.parametrize("change", COUNTED)
def test_every_file_its_path_its_bytes_and_whether_it_may_be_run_count(repo, tmp_path, change):
    tree = _unpacked(repo, tmp_path / "tree")
    before = _code(str(tree))
    COUNTED[change](tree)
    assert _code(str(tree)) != before, f"{change}: the same code"


def _mkfile(path: Path, text: str = "x\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


NOT_COUNTED = {
    ".git at the top": lambda t: _mkfile(t / ".git" / "HEAD", "ref: refs/heads/main\n"),
    ".git at the top, a file, as in a git worktree": lambda t: _mkfile(t / ".git", "gitdir: /elsewhere\n"),
    ".venv at the top": lambda t: (_mkfile(t / ".venv" / "pyvenv.cfg"), (t / ".venv" / "python").symlink_to("/x")),
    "secrets at the top": lambda t: _mkfile(t / "secrets" / "tokens.yaml", "tokens: []\n"),
    "transfer at the top": lambda t: _mkfile(t / "transfer" / "upload.bin"),
    "releases at the top": lambda t: _mkfile(t / "releases" / "0.1.0-0123456789ab" / "pyproject.toml"),
    "the top's hosts.yaml changed": lambda t: (t / "hosts.yaml").write_text("hosts: []\n"),
    "the top's hosts.yaml removed": lambda t: (t / "hosts.yaml").unlink(),
    ".release at the top": lambda t: _mkfile(t / ".release", "format=1\n"),
    "__pycache__ at the top": lambda t: _mkfile(t / "__pycache__" / "x.cpython-313.pyc"),
    "__pycache__ deep down": lambda t: _mkfile(t / "src" / "thing" / "__pycache__" / "core.cpython-313.pyc"),
    "an empty folder": lambda t: (t / "src" / "thing" / "empty").mkdir(),
    "a file's mode but its owner's run bit": lambda t: ((t / "src/thing/core.py").chmod(0o600),
                                                        (t / "install.sh").chmod(0o711)),
    "run bits for a file's group and others, not its owner": lambda t: (t / "src/thing/core.py").chmod(0o655),
}


@pytest.mark.parametrize("change", NOT_COUNTED)
def test_what_is_not_the_release_does_not_count(repo, tmp_path, change):
    tree = _unpacked(repo, tmp_path / "tree")
    before = _code(str(tree))
    NOT_COUNTED[change](tree)
    assert _code(str(tree)) == before, f"{change}: other code"


@pytest.mark.parametrize("name", LEFT_OUT_AT_THE_TOP)
def test_what_is_left_out_at_the_top_counts_below_it(repo, tmp_path, name):
    # The names are an installation's own only at its top; below it, a file so named is the code's.
    tree = _unpacked(repo, tmp_path / "tree")
    before = _code(str(tree))
    _mkfile(tree / "docs" / name)
    assert _code(str(tree)) != before


@pytest.mark.parametrize("name", LEFT_OUT_AT_THE_TOP)
def test_only_those_names_themselves_are_left_out_at_the_top(repo, tmp_path, name):
    # Not every name that begins as one of them, nor every name that begins with a dot: this
    # repository's top holds .gitignore and .mcp.json, and both are the release's.
    tree = _unpacked(repo, tmp_path / "tree")
    before = _code(str(tree))
    _mkfile(tree / f"{name}-notes")
    assert _code(str(tree)) != before


def test_the_code_is_one_sha256_over_each_files_kind_digest_and_path(tmp_path):
    """The rule, worked out here by hand for a small tree. Each record is its kind, the SHA-256
    of its bytes (a link's: of its target) and its path, each ended by a NUL; the records go in
    the order of their paths' bytes, so B before a-b, a-b before a/b, and a.link between them."""
    tree = _write(tmp_path / "tree", {"pyproject.toml": (PYPROJECT, 0o644), "a-b": ("1", 0o644),
                                      "a/b": ("2", 0o755), "B": ("", 0o664)}, {"a.link": "a/b"})
    records = [(b"f", b"", b"B"), (b"f", b"1", b"a-b"), (b"l", b"a/b", b"a.link"), (b"x", b"2", b"a/b"),
               (b"f", PYPROJECT.encode(), b"pyproject.toml")]
    whole = b"".join(kind + b"\0" + hashlib.sha256(data).hexdigest().encode() + b"\0" + path + b"\0"
                     for kind, data, path in records)
    assert _code(str(tree)) == hashlib.sha256(whole).hexdigest()


def test_the_name_is_the_number_and_twelve_hex_of_the_code(repo):
    for args, stdin in ((["--archive"], _archive(repo)), ([str(repo)], None)):
        done = _run(*args, stdin=stdin)
        assert done.returncode == 0, done.stderr.decode()
        name = done.stdout.decode()
        assert re.fullmatch(r"(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*)){2}-[0-9a-f]{12}\n", name), name
        full = _full(*args, stdin=stdin)
        assert full[0] == name.strip()
        assert full[1] == "1.10.0"  # the tree's own number, from its pyproject.toml
        assert re.fullmatch(r"[0-9a-f]{64}", full[2]) and name.strip() == f"{full[1]}-{full[2][:12]}"


def test_the_number_is_the_pyproject_toml_at_the_top(tmp_path):
    # Others below it, before it and after it in an archive, are not the release's.
    clone = _repository(tmp_path / "thing", {**FILES, "a/pyproject.toml": ('[project]\nversion = "7.7.7"\n', 0o644),
                                             "z/pyproject.toml": ('[project]\nversion = "8.8.8"\n', 0o644)}, LINKS)
    assert _full("--archive", stdin=_archive(clone))[1] == "1.10.0"
    assert _full(str(clone))[1] == "1.10.0"


@pytest.mark.parametrize("pyproject, says", [
    ('[project]\nversion = "0.2"\n', "'0.2', is not three numbers with no leading zeros"),
    ('[project]\nversion = "0.02.0"\n', "'0.02.0', is not three numbers with no leading zeros"),
    ('[project]\nversion = "1.0.0.0"\n', "'1.0.0.0', is not three numbers with no leading zeros"),
    ('[project]\nversion = 0.2\n', "0.2, is not in quotes"),
    ('[project]\nname = "thing"\n', "names no version"),
    ('[tool.thing]\nversion = "0.2.0"\n', "names no version"),
    ("[project\n", "cannot read the pyproject.toml"),
    (None, "has no pyproject.toml"),
])
def test_a_release_number_not_in_its_form_is_refused(tmp_path, pyproject, says):
    tree = _write(tmp_path / "tree", {"install.sh": ("#!/bin/bash\n", 0o755)})
    if pyproject is not None:
        (tree / "pyproject.toml").write_text(pyproject)
    _refused(_run(str(tree)), says)


def test_an_archive_whose_number_is_not_in_its_form_is_refused(tmp_path):
    clone = _repository(tmp_path / "thing", {**FILES, "pyproject.toml": ('[project]\nversion = "0.2"\n', 0o644)})
    _refused(_run("--archive", stdin=_archive(clone)), "the release number of the archive, '0.2', is not")


def test_it_needs_only_the_standard_library(repo):
    # -S: no site-packages, so nothing installed beside Python can be imported, as on nervus's machine
    # before any venv exists.
    for args, stdin in ((["--archive"], _archive(repo)), ([str(repo)], None)):
        alone = _run(*args, stdin=stdin, python=(sys.executable, "-I", "-S"))
        assert alone.returncode == 0, alone.stderr.decode()
        assert alone.stdout == _run(*args, stdin=stdin).stdout


def test_what_is_not_a_file_a_link_or_a_folder_is_refused(repo, tmp_path):
    # The code would not say all that the folder holds.
    tree = _unpacked(repo, tmp_path / "tree")
    os.mkfifo(tree / "docs" / "pipe")
    _refused(_run(str(tree)), "docs/pipe in")


def _stream(*members: tarfile.TarInfo) -> bytes:
    """A tar stream written by Python's tarfile, not git: a pyproject.toml, then the members given."""
    out, data = io.BytesIO(), PYPROJECT.encode()
    with tarfile.open(fileobj=out, mode="w") as archive:
        pyproject = tarfile.TarInfo("pyproject.toml")
        pyproject.size = len(data)
        archive.addfile(pyproject, io.BytesIO(data))
        for member in members:
            archive.addfile(member)
    return out.getvalue()


def test_what_is_not_a_file_a_link_or_a_folder_in_an_archive_is_refused():
    # A hard link, which tar unpacks as a second name for a file: the code would not count it.
    assert _run("--archive", stdin=_stream()).returncode == 0
    again = tarfile.TarInfo("docs/again")
    again.type, again.linkname = tarfile.LNKTYPE, "pyproject.toml"
    _refused(_run("--archive", stdin=_stream(again)), "docs/again in the archive")


def _cut(whole: bytes) -> bytes:
    # The archive up to its last member's header: pyproject.toml, before it, can be read, and one file is lost.
    return whole[:list(tarfile.open(fileobj=io.BytesIO(whole)))[-1].offset]


def _bad_header(whole: bytes) -> bytes:
    # The last member's name changed by one bit, so its header's checksum no longer agrees.
    last = list(tarfile.open(fileobj=io.BytesIO(whole)))[-1].offset
    return whole[:last] + bytes([whole[last] ^ 1]) + whole[last + 1:]


@pytest.mark.parametrize("how", ["cut short between two files", "the same, compressed",
                                 "a header that cannot be read"])
def test_an_archive_not_read_to_its_end_is_refused(repo, how):
    # tarfile stops at each as at the archive's end, saying nothing; the code would leave files out.
    whole = _archive(repo)
    stdin = {"cut short between two files": lambda: _cut(whole),
             "the same, compressed": lambda: gzip.compress(_cut(whole)),
             "a header that cannot be read": lambda: _bad_header(whole)}[how]()
    _refused(_run("--archive", stdin=stdin), "is not a whole tar archive")


@pytest.mark.parametrize("args", [[], ["--archive", "."]], ids=["neither", "both"])
def test_neither_a_folder_nor_an_archive_or_both_cannot_run(args):
    done = _run(*args)
    assert (done.returncode, done.stdout) == (2, b""), done.stderr
    assert b"give a folder, or --archive" in done.stderr


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a file whatever its mode")
def test_a_file_that_cannot_be_read_is_refused(repo, tmp_path):
    # A reason install.sh can show, not a traceback.
    tree = _unpacked(repo, tmp_path / "tree")
    (tree / "src/thing/core.py").chmod(0o000)
    _refused(_run(str(tree)), "cannot read")


@pytest.mark.parametrize("what", ["no such folder", "a file", "nothing on standard input",
                                  "standard input not a tar archive"])
def test_what_is_not_a_tree_is_refused(tmp_path, what):
    (tmp_path / "a-file").write_text("x\n")
    done = {"no such folder": lambda: _run(str(tmp_path / "missing")),
            "a file": lambda: _run(str(tmp_path / "a-file")),
            "nothing on standard input": lambda: _run("--archive", stdin=b""),
            "standard input not a tar archive": lambda: _run("--archive", stdin=b"not an archive\n" * 100)}[what]()
    _refused(done, "is not a")
