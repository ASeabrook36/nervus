"""requirements.lock and tools/lock-libraries (ADR-0029, "Not settled here", settled 2026-11-15):
every library an install fetches, each at one exact version with the SHA-256 of each of its files,
so that an install is the set the release's tests ran.

The tool is run as install.sh and the export run it, with `python3 -I`. Checking is shown on small
trees made here; making, with a stand-in `uv`, so that nothing here asks the package index. This
repository's own lock is checked as it stands, and against the libraries these tests run on."""

from __future__ import annotations

import importlib.metadata
import os
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest
from packaging.markers import Marker
from packaging.utils import canonicalize_name

REPO = Path(__file__).resolve().parent.parent
TOOL = REPO / "tools" / "lock-libraries"

PYPROJECT = """[build-system]
requires = ["hatchling==1.27.0"]
build-backend = "hatchling.build"

[project]
name = "thing"
version = "{number}"
requires-python = ">=3.11"
dependencies = [
    "alpha=={alpha}",
    "Beta_Lib==2.0",
]
"""
HASH = "    --hash=sha256:" + "ab" * 32
LOCK = """# requirements.lock: a test's.
# Made for nervus {number} on 2026-11-15, by tools/lock-libraries with uv 0.0.0.
alpha=={alpha} \\
{hash}
beta-lib==2.0 ; sys_platform != 'emscripten' \\
{hash} \\
{hash}
gamma==3.1.4 \\
{hash}
hatchling==1.27.0 \\
{hash}
"""


def _tree(tmp: Path, number="0.9.9", alpha="1.0.0", lock: str | None = LOCK, pyproject=PYPROJECT) -> Path:
    tree = tmp / "tree"
    tree.mkdir()
    (tree / "pyproject.toml").write_text(pyproject.format(number=number, alpha=alpha))
    if lock is not None:
        (tree / "requirements.lock").write_text(lock.format(number=number, alpha=alpha, hash=HASH))
    return tree


def _check(tree: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-I", str(TOOL), "--check", str(tree)], capture_output=True, text=True)


def _locked(path: Path) -> dict[str, tuple[str, str]]:
    """Each library in a lock, by its name as the index knows it: its version and its marker."""
    found = {}
    for line in path.read_text().splitlines():
        if match := re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*)==(\S+)(?: ; (.+?))? \\", line):
            found[canonicalize_name(match.group(1))] = (match.group(2), match.group(3) or "")
    return found


# --- this repository's own lock ---------------------------------------------------------------

def test_this_repositorys_lock_is_its_releases_and_holds_what_pyproject_names():
    done = _check(REPO)
    assert done.returncode == 0, done.stdout + done.stderr


def test_the_libraries_these_tests_run_on_are_the_locks():
    # What makes "the set this release's tests ran" true. An environment that has drifted from the
    # lock is brought back with: .venv/bin/pip install --require-hashes -r requirements.lock
    differ = []
    for name, (version, marker) in _locked(REPO / "requirements.lock").items():
        if marker and not Marker(marker).evaluate():
            continue  # not for this Python or this system
        try:
            here = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            here = "not installed"
        if here != version:
            differ.append(f"{name}: the lock has {version}, this environment {here}")
    assert not differ, ("these tests are not running on requirements.lock's libraries; bring the environment back "
                        "with `.venv/bin/pip install --require-hashes -r requirements.lock`:\n  " + "\n  ".join(differ))


def test_the_lock_holds_every_library_nervus_names_and_what_builds_it():
    project = tomllib.loads((REPO / "pyproject.toml").read_text())
    locked = _locked(REPO / "requirements.lock")
    for requirement in project["project"]["dependencies"] + project["build-system"]["requires"]:
        name, version = requirement.split("==")
        assert locked[canonicalize_name(name)][0] == version, requirement
    assert len(locked) > len(project["project"]["dependencies"])  # and what those need in turn


def test_every_library_in_the_lock_has_its_files_hashes():
    text = (REPO / "requirements.lock").read_text()
    blocks = re.split(r"(?m)^(?=[A-Za-z0-9])", text)
    pins = [b for b in blocks if re.match(r"[A-Za-z0-9][A-Za-z0-9._-]*==", b)]
    assert pins and all(re.search(r"--hash=sha256:[0-9a-f]{64}", b) for b in pins)


# --- checking -------------------------------------------------------------------------------

def test_a_lock_made_for_this_release_holding_its_libraries_passes(tmp_path):
    done = _check(_tree(tmp_path))
    assert done.returncode == 0 and "0.9.9" in done.stdout, done.stdout + done.stderr


@pytest.mark.parametrize("change, says", [
    (dict(lock=None), "has no requirements.lock"),
    (dict(lock=LOCK.replace("Made for nervus {number}", "Made for nervus 0.9.8")), "was made for 0.9.8, and this tree is 0.9.9"),
    (dict(lock=LOCK.replace("# Made for nervus {number} on 2026-11-15, by tools/lock-libraries with uv 0.0.0.\n", "")),
     "does not say which release it was made for"),
    (dict(lock=LOCK.replace("alpha=={alpha}", "alpha==0.9.0")), "alpha==1.0.0, and the lock has alpha 0.9.0"),
    (dict(lock=LOCK.replace("beta-lib==2.0 ; sys_platform != 'emscripten' \\\n{hash} \\\n{hash}\n", "")),
     "Beta_Lib==2.0, and the lock has no beta-lib"),
    (dict(lock=LOCK.replace("hatchling==1.27.0 \\\n{hash}\n", "")), "hatchling==1.27.0, and the lock has no hatchling"),
    (dict(lock=LOCK.replace("gamma==3.1.4 \\\n{hash}\n", "gamma==3.1.4\n")), "gamma has no --hash"),
    (dict(lock=LOCK + "delta>=1.0 \\\n{hash}\n"), "not a library at one exact version"),
    (dict(pyproject=PYPROJECT.replace('"alpha=={alpha}"', '"alpha>={alpha}"')), "alpha>=1.0.0 is not one exact version"),
])
def test_a_lock_that_is_not_this_releases_is_refused_saying_why(tmp_path, change, says):
    done = _check(_tree(tmp_path, **change))
    assert done.returncode == 1 and says in done.stderr, done.stdout + done.stderr
    assert done.stdout == ""


def test_checking_changes_nothing(tmp_path):
    tree = _tree(tmp_path)
    before = {p.name: p.read_bytes() for p in tree.iterdir()}
    assert _check(tree).returncode == 0
    assert {p.name: p.read_bytes() for p in tree.iterdir()} == before


# --- making, with a stand-in uv ---------------------------------------------------------------

UV = """#!/bin/sh
[ "$1" = --version ] && { echo "uv 9.9.9 (test)"; exit 0; }
printf '%s\\n' "$@" > "$UV_ARGS"
[ -n "$UV_FAILS" ] && { echo "error: no solution found" >&2; exit 2; }
out=; next=
for a in "$@"; do [ -n "$next" ] && { out=$a; next=; }; [ "$a" = -o ] && next=1; done
for f in "$@"; do case $f in *.in) cp "$f" "$UV_BUILD_IN";; esac; done
cat > "$out" <<'EOF'
alpha==1.0.0 \\
    --hash=sha256:1111111111111111111111111111111111111111111111111111111111111111
beta-lib==2.0 \\
    --hash=sha256:2222222222222222222222222222222222222222222222222222222222222222
hatchling==1.27.0 \\
    --hash=sha256:3333333333333333333333333333333333333333333333333333333333333333
EOF
"""


def _make(tree: Path, tmp: Path, *, uv=True, fails=False) -> subprocess.CompletedProcess:
    bin_dir = tmp / "bin"
    bin_dir.mkdir(exist_ok=True)
    if uv:
        (bin_dir / "uv").write_text(UV)
        (bin_dir / "uv").chmod(0o755)
    env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "UV_ARGS": str(tmp / "uv-args"), "UV_BUILD_IN": str(tmp / "build-in"),
           "HOME": str(tmp), **({"UV_FAILS": "1"} if fails else {})}
    return subprocess.run([sys.executable, "-I", str(TOOL), str(tree)], capture_output=True, text=True, env=env)


def test_making_asks_uv_for_every_system_and_python_the_installer_takes_with_hashes_at_the_newest(tmp_path):
    tree = _tree(tmp_path, lock=None)
    done = _make(tree, tmp_path)
    assert done.returncode == 0, done.stdout + done.stderr
    args = (tmp_path / "uv-args").read_text().splitlines()
    assert args[:3] == ["pip", "compile", str(tree / "pyproject.toml")]
    for flag in ("--universal", "--generate-hashes", "--upgrade", "--no-header", "--no-annotate"):
        assert flag in args, flag
    assert args[args.index("--python-version") + 1] == "3.11"  # pyproject's requires-python, the oldest it takes
    assert (tmp_path / "build-in").read_text() == "hatchling==1.27.0\n"  # what builds nervus's package, locked too
    lock = (tree / "requirements.lock").read_text()
    assert re.search(r"(?m)^# Made for nervus 0\.9\.9 on \d{4}-\d\d-\d\d, by tools/lock-libraries with uv 9\.9\.9\.$", lock)
    assert "alpha==1.0.0 \\\n    --hash=sha256:" + "1" * 64 in lock
    assert _check(tree).returncode == 0  # what it makes is what it checks


def test_making_again_replaces_the_lock_whole(tmp_path):
    tree = _tree(tmp_path)
    assert "gamma" in (tree / "requirements.lock").read_text()
    assert _make(tree, tmp_path).returncode == 0
    assert "gamma" not in (tree / "requirements.lock").read_text()
    assert [p.name for p in tree.iterdir() if p.name.startswith("requirements")] == ["requirements.lock"]


@pytest.mark.parametrize("how, says", [(dict(uv=False), "uv is not installed"), (dict(fails=True), "no solution found")])
def test_a_lock_that_cannot_be_made_leaves_the_one_there(tmp_path, how, says):
    tree = _tree(tmp_path)
    before = (tree / "requirements.lock").read_bytes()
    done = _make(tree, tmp_path, **how)
    assert done.returncode == 1 and says in done.stderr, done.stdout + done.stderr
    assert (tree / "requirements.lock").read_bytes() == before
    assert sorted(p.name for p in tree.iterdir()) == ["pyproject.toml", "requirements.lock"]


def test_a_lock_uv_made_without_one_of_the_named_libraries_is_not_kept(tmp_path):
    # The tool checks what it made before it puts it in place.
    tree = _tree(tmp_path, alpha="1.5.0")
    before = (tree / "requirements.lock").read_bytes()
    done = _make(tree, tmp_path)  # the stand-in gives alpha 1.0.0, whatever was asked
    assert done.returncode == 1 and "alpha==1.5.0, and the lock has alpha 1.0.0" in done.stderr
    assert (tree / "requirements.lock").read_bytes() == before
