"""Tests for tools/export-preview (ADR-0018, as amended), run against a scratch repository.

The tool is copied into a small git repository made here, so it treats that one as "this
repository": it has a deployment record, a private README, the preview's own files, a
release number with its section in CHANGES.md, and a tests/ of its own. A folder beside it
stands for the last export, at the release before, and is what --against names. gitleaks is
a stand-in on PATH whose answer each test chooses. Nothing here touches this repository or
any other.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

TOOL = Path(__file__).resolve().parent.parent / "tools" / "export-preview"

PYPROJECT = '[project]\nname = "thing"\nversion = "{}"\n'
FILES = {
    "src/thing/__init__.py": "VALUE = 1\n",
    "tests/test_thing.py": "import thing\n\ndef test_value():\n    assert thing.VALUE == 1\n",
    "decisions/0001.md": "# a decision\n",
    "pyproject.toml": PYPROJECT.format("0.2.0"),
    "CHANGES.md": "# Changes\n\n## 0.2.0\n\n- VALUE is 1\n\n## 0.1.0\n\n- the first export\n",
    "procedures/001.md": "what was done on the first installation\n",
    "deployment/0001.md": "this installation's notes\n",
    "CURRENT_STATE.md": "state\n",
    "hosts.yaml": "hosts: []\n",
    ".mcp.json": '{"mcpServers": {}}\n',
    "README.md": "# the private README\n",
    "preview/README.md": "# the preview's README\n",
    "preview/mcp.json.example": '{"mcpServers": {"nervus": {}}}\n',
}
MAP = 'check:\n  - leakedname\n  - { word: hush }\n'


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                   env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.net",
                        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.net"})


@pytest.fixture
def world(tmp_path):
    repo = tmp_path / "repo"
    for name, text in FILES.items():
        (repo / name).parent.mkdir(parents=True, exist_ok=True)
        (repo / name).write_text(text)
    (repo / "tools").mkdir()
    shutil.copy(TOOL, repo / "tools" / "export-preview")
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "first")
    (tmp_path / "map.yaml").write_text(MAP)
    (tmp_path / "last").mkdir()
    (tmp_path / "last" / "pyproject.toml").write_text(PYPROJECT.format("0.1.0"))
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    return tmp_path, repo, bin_dir


def _gitleaks(bin_dir: Path, code: int, says: str = "") -> None:
    fake = bin_dir / "gitleaks"
    fake.write_text(f"#!/bin/sh\necho '{says}'\nexit {code}\n")
    fake.chmod(0o755)


def _run(world, *args: str, gitleaks: int | None = 0, against: bool = True) -> subprocess.CompletedProcess:
    tmp, repo, bin_dir = world
    if gitleaks is not None:
        _gitleaks(bin_dir, gitleaks, "leak found" if gitleaks == 1 else "")
    path = f"{bin_dir}:{os.environ['PATH']}" if gitleaks is not None else _path_without_gitleaks(bin_dir)
    last = ["--against", str(tmp / "last")] if against else []
    return subprocess.run([sys.executable, str(repo / "tools" / "export-preview"), str(tmp / "out"),
                           "--map", str(tmp / "map.yaml"), *last, *args],
                          capture_output=True, text=True, timeout=120, env={**os.environ, "PATH": path})


def _path_without_gitleaks(bin_dir: Path) -> str:
    dirs = [d for d in os.environ["PATH"].split(os.pathsep) if not (Path(d) / "gitleaks").exists()]
    return os.pathsep.join([str(bin_dir), *dirs])


def _commit(repo: Path, name: str, text: str) -> None:
    (repo / name).parent.mkdir(parents=True, exist_ok=True)
    (repo / name).write_text(text)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", f"change {name}")


def _pyproject(world, tree: str, text: str | None) -> None:
    """Gives "the export" (by a commit) or "the last export" this pyproject.toml; None takes it away."""
    tmp, repo, _ = world
    if tree == "the last export":
        if text is None:
            (tmp / "last" / "pyproject.toml").unlink()
        else:
            (tmp / "last" / "pyproject.toml").write_text(text)
    elif text is None:
        _git(repo, "rm", "-q", "pyproject.toml")
        _git(repo, "commit", "-q", "-m", "no pyproject.toml")
    else:
        _commit(repo, "pyproject.toml", text)


def _refused(done: subprocess.CompletedProcess, *says: str) -> None:
    """Stopped at the release, the step after the build: before the check list, gitleaks and the tests."""
    assert done.returncode == 1, done.stdout + done.stderr
    lines = done.stdout.splitlines()
    assert len(lines) > 1 and "1-3. built from" in lines[0] and "STOP" in lines[1], done.stdout + done.stderr
    for words in says:
        assert words in lines[1], done.stdout


def test_a_clean_export_leaves_out_the_record_and_adds_the_previews_own_files(world):
    tmp = world[0]
    done = _run(world)
    assert done.returncode == 0, done.stdout + done.stderr
    out = tmp / "out"
    assert (out / "README.md").read_text() == "# the preview's README\n"
    assert (out / ".mcp.json.example").read_text() == FILES["preview/mcp.json.example"]
    for gone in ("procedures", "deployment", "CURRENT_STATE.md", "hosts.yaml", ".mcp.json", "preview"):
        assert not (out / gone).exists(), gone
    for kept in ("src/thing/__init__.py", "tests/test_thing.py", "decisions/0001.md", "tools/export-preview",
                 "pyproject.toml", "CHANGES.md"):
        assert (out / kept).exists(), kept
    assert "1 passed" in done.stdout
    assert "Export of " in done.stdout


def test_a_name_on_the_check_list_stops_it_and_says_where(world):
    _commit(world[1], "src/thing/more.py", "# talks about leakedName here\n")
    done = _run(world)
    assert done.returncode == 1
    assert "src/thing/more.py:1  [leakedname]" in done.stdout
    assert "commit nothing from it" in done.stdout
    assert "Export of " not in done.stdout


def test_a_word_on_the_check_list_matches_only_whole(world):
    _commit(world[1], "src/thing/more.py", "# hushed is fine; HUSH is not\n")
    done = _run(world)
    assert done.returncode == 1
    assert done.stdout.count("[hush]") == 1


def test_a_gitleaks_finding_stops_it(world):
    done = _run(world, gitleaks=1)
    assert done.returncode == 1 and "gitleaks found something" in done.stdout


def test_gitleaks_missing_stops_it_and_says_how_to_install_it(world):
    done = _run(world, gitleaks=None)
    assert done.returncode == 1 and "brew install gitleaks" in done.stdout


def test_a_failing_test_in_the_preview_stops_it(world):
    _commit(world[1], "tests/test_broken.py", "def test_broken():\n    assert False\n")
    done = _run(world)
    assert done.returncode == 1 and "tests/ failed on the preview" in done.stdout


def test_only_the_commit_goes_out_never_the_working_tree(world):
    tmp, repo, _ = world
    (repo / "src/thing/unsaved.py").write_text("# leakedname, never committed\n")
    (repo / "src/thing/__init__.py").write_text("VALUE = 2  # leakedname, edited but not committed\n")
    done = _run(world)
    assert done.returncode == 0, done.stdout
    assert not (tmp / "out/src/thing/unsaved.py").exists()
    assert (tmp / "out/src/thing/__init__.py").read_text() == "VALUE = 1\n"


def test_a_folder_that_is_not_empty_is_refused(world):
    tmp = world[0]
    (tmp / "out").mkdir()
    (tmp / "out" / "something").write_text("x")
    done = _run(world)
    assert done.returncode == 2 and "not empty" in done.stderr


def test_a_commit_without_the_previews_own_files_is_refused(world):
    repo = world[1]
    _git(repo, "rm", "-q", "preview/README.md")
    _git(repo, "commit", "-q", "-m", "no preview readme")
    done = _run(world)
    assert done.returncode == 1 and "has no preview/README.md" in done.stdout


def test_against_shows_only_what_changed_since_the_last_export(world, monkeypatch):
    # Python writing bytecode, as it does unless told not to: the run of tests/ leaves __pycache__/ in the result.
    monkeypatch.delenv("PYTHONDONTWRITEBYTECODE", raising=False)
    tmp, repo, _ = world
    assert _run(world).returncode == 0
    # The last export as the preview repository holds it: committed, without bytecode, in a checkout with a .git.
    shutil.rmtree(tmp / "last")
    shutil.copytree(tmp / "out", tmp / "last", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.rmtree(tmp / "out")
    for args in (("init", "-q", "-b", "main"), ("add", "-A"), ("commit", "-q", "-m", "Export of the first")):
        _git(tmp / "last", *args)
    _pyproject(world, "the export", PYPROJECT.format("0.3.0"))
    _commit(repo, "CHANGES.md", "## 0.3.0\n\n- NEW\n")
    _commit(repo, "src/thing/new.py", "NEW = True\n")
    done = _run(world)
    assert done.returncode == 0, done.stdout
    assert (tmp / "out" / "tests" / "__pycache__").is_dir()  # the bytecode is there, to be left out
    shown = done.stdout.split("against the last export:\n")[1]
    # CHANGES.md, pyproject.toml and new.py, each named from the top of its tree; no file of .git or __pycache__/.
    assert " {last => this}/pyproject.toml " in shown and "this/src/thing/new.py" in shown, shown
    assert " 3 files changed," in shown, shown


def test_against_is_required(world):
    done = _run(world, against=False)
    assert done.returncode == 2 and "--against" in done.stderr, done.stderr
    assert not (world[0] / "out").exists()


def test_a_release_number_equal_to_the_last_exports_is_refused_naming_both(world):
    _pyproject(world, "the last export", PYPROJECT.format("0.2.0"))
    _refused(_run(world), "the release number 0.2.0 is not above the last export's, 0.2.0")


@pytest.mark.parametrize("number, last", [("0.3.0", "0.10.0"), ("0.1.10", "0.2.0")],
                         ids=["above-as-strings", "above-with-its-digits-run-together"])
def test_a_release_number_below_the_last_exports_is_refused(world, number, last):
    # 0.3.0 is below 0.10.0 as numbers, though above it as strings; 0.1.10 is below 0.2.0, though 110 is above 20.
    _pyproject(world, "the last export", PYPROJECT.format(last))
    _pyproject(world, "the export", PYPROJECT.format(number))
    _refused(_run(world), f"the release number {number} is not above the last export's, {last}")


@pytest.mark.parametrize("number, last", [("0.10.0", "0.9.0"), ("0.2.1", "0.2.0"), ("1.0.0", "0.10.0")],
                         ids=["below-as-strings", "the-last-part-counts", "the-first-part-counts-most"])
def test_release_numbers_compare_as_numbers_part_by_part(world, number, last):
    _pyproject(world, "the last export", PYPROJECT.format(last))
    _pyproject(world, "the export", PYPROJECT.format(number))
    _commit(world[1], "CHANGES.md", f"## {number}\n\n- above {last}\n")
    done = _run(world)
    assert done.returncode == 0, done.stdout
    assert f"release {number}, above the last export's {last}" in done.stdout


@pytest.mark.parametrize("name, committed, unsaved, says", [
    ("pyproject.toml", PYPROJECT.format("0.1.0"), PYPROJECT.format("0.2.0"),
     "the release number 0.1.0 is not above the last export's, 0.1.0"),
    ("CHANGES.md", "# Changes\n\n## 0.1.0\n\n- the first export\n", FILES["CHANGES.md"],
     "CHANGES.md has no section for 0.2.0"),
], ids=["number", "section"])
def test_the_release_is_read_from_the_commit_never_the_working_tree(world, name, committed, unsaved, says):
    repo = world[1]
    _commit(repo, name, committed)
    (repo / name).write_text(unsaved)  # the number raised, or the section written, but not committed
    _refused(_run(world), says)


@pytest.mark.parametrize("tree, number", [("the export", "0.2.0rc1"), ("the last export", "v0.1.0"),
                                          ("the last export", "0.1."), ("the export", "0.2"),
                                          ("the export", "0.2.0.1"), ("the export", "0.02.0")],
                         ids=["export-letters", "last-letters", "last-empty-part", "export-two-parts",
                              "export-four-parts", "export-a-leading-zero"])
def test_a_release_number_not_three_numbers_is_refused_naming_it(world, tree, number):
    # Three, as tests/test_package.py requires, so the export stops here, not at its tests: pip takes 0.2 and 0.2.0
    # for one release, and the package built from 0.02.0 says 0.2.0.
    _pyproject(world, tree, PYPROJECT.format(number))
    _refused(_run(world), f"the release number of {tree}", repr(number),
             "is not three numbers with no leading zeros")


@pytest.mark.parametrize("tree", ["the export", "the last export"], ids=["export", "last"])
def test_a_release_number_not_in_quotes_is_refused_saying_so(world, tree):
    # TOML reads version = 0.2 as a number, not as text: it is digits and dots, but not in quotes.
    _pyproject(world, tree, '[project]\nname = "thing"\nversion = 0.2\n')
    _refused(_run(world), f"the release number of {tree}", "0.2, is not in quotes")


@pytest.mark.parametrize("tree, text, says", [
    ("the last export", None, "has no pyproject.toml"),
    ("the last export", '[project]\nname = "thing"\n', "names no version"),
    ("the last export", "[project\n", "cannot read"),
    ("the export", None, "has no pyproject.toml"),
    ("the export", '[project]\nname = "thing"\n', "names no version"),
    ("the export", 'project = "thing"\n', "names no version"),
], ids=["last-no-file", "last-no-version", "last-not-toml", "export-no-file", "export-no-version",
        "export-project-not-a-table"])
def test_a_tree_without_a_release_number_is_refused_saying_which(world, tree, text, says):
    _pyproject(world, tree, text)
    _refused(_run(world), tree, says)


def test_an_export_without_changes_md_is_refused_naming_the_release(world):
    repo = world[1]
    _git(repo, "rm", "-q", "CHANGES.md")
    _git(repo, "commit", "-q", "-m", "no CHANGES.md")
    _refused(_run(world), "the export has no CHANGES.md", "a section for 0.2.0")


@pytest.mark.parametrize("text", ["# Changes\n\n## 0.1.0\n\n- the first export\n",
                                  "# Changes\n\n## 0.2.0.1\n\n- what changed\n",
                                  "# Changes\n\n### 0.2.0\n\n- what changed\n"],
                         ids=["another-release", "a-longer-number", "another-level"])
def test_changes_md_without_a_section_for_the_release_is_refused(world, text):
    _commit(world[1], "CHANGES.md", text)
    _refused(_run(world), "CHANGES.md has no section for 0.2.0")


@pytest.mark.parametrize("text", ["# Changes\n\n## 0.2.0\n\n## 0.1.0\n\n- the first export\n",
                                  "# Changes\n\n## 0.2.0\n \n\n"],
                         ids=["before-the-next-section", "to-the-end"])
def test_an_empty_section_for_the_release_is_refused(world, text):
    _commit(world[1], "CHANGES.md", text)
    _refused(_run(world), "CHANGES.md's section for 0.2.0 is empty")


def test_a_section_heading_may_go_on_after_the_number(world):
    _commit(world[1], "CHANGES.md", "# Changes\n\n## 0.2.0 (the first with an installer)\n\n- VALUE is 1\n")
    done = _run(world)
    assert done.returncode == 0, done.stdout


def test_headings_within_a_section_do_not_end_it(world):
    _commit(world[1], "CHANGES.md", "## 0.2.0\n### What a person running nervus will see\n- VALUE is 1\n")
    done = _run(world)
    assert done.returncode == 0, done.stdout


# --- lines the map allows (ADR-0018, amended 2026-11-15: the copyright line in NOTICE) ---------------

ALLOWING = MAP + 'allow:\n  - { file: NOTICE, line: "Copyright 2026 LeakedName" }\n'


def test_a_line_the_map_allows_is_passed_over_and_said(world):
    (world[0] / "map.yaml").write_text(ALLOWING)
    _commit(world[1], "NOTICE", "thing\nCopyright 2026 LeakedName\n")
    done = _run(world)
    assert done.returncode == 0, done.stdout + done.stderr
    assert "found nothing; passed over, as the map allows: NOTICE:2" in done.stdout
    assert (world[0] / "out" / "NOTICE").read_text() == "thing\nCopyright 2026 LeakedName\n"


@pytest.mark.parametrize("name, text, where", [
    ("src/thing/more.py", "Copyright 2026 LeakedName\n", "src/thing/more.py:1"),
    ("docs/NOTICE", "Copyright 2026 LeakedName\n", "docs/NOTICE:1"),
    ("NOTICE", "Copyright 2026 LeakedName, of somewhere\n", "NOTICE:1"),
    ("NOTICE", " Copyright 2026 LeakedName\n", "NOTICE:1"),
    ("NOTICE", "Copyright 2026 LeakedName\nwritten by leakedname at home\n", "NOTICE:2"),
], ids=["another-file", "same-name-in-a-folder", "more-on-the-line", "indented", "another-line-of-the-file"])
def test_the_allowed_words_anywhere_else_still_stop_it(world, name, text, where):
    (world[0] / "map.yaml").write_text(ALLOWING)
    _commit(world[1], name, text)
    done = _run(world)
    assert done.returncode == 1, done.stdout + done.stderr
    assert f"{where}  [leakedname]" in done.stdout
    assert done.stdout.count("[leakedname]") == 1, done.stdout  # the allowed line itself is not among the hits
    assert "Export of " not in done.stdout


@pytest.mark.parametrize("allow", ["allow: NOTICE\n", "allow:\n  - NOTICE\n", "allow:\n  - { file: NOTICE }\n",
                                   "allow:\n  - { file: NOTICE, line: 7 }\n",
                                   'allow:\n  - { file: NOTICE, line: "a\\nb" }\n'],
                         ids=["not-a-list", "not-a-mapping", "no-line", "line-not-text", "two-lines"])
def test_an_allowance_the_tool_cannot_read_stops_it_before_anything_is_built(world, allow):
    (world[0] / "map.yaml").write_text(MAP + allow)
    done = _run(world)
    assert done.returncode == 1, done.stdout + done.stderr
    assert "STOP" in done.stdout and "allow" in done.stdout
    assert not (world[0] / "out").exists()


def test_a_map_that_allows_nothing_says_nothing_of_it(world):
    done = _run(world)
    assert done.returncode == 0, done.stdout + done.stderr
    assert "passed over" not in done.stdout
