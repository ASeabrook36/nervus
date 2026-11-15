"""The release number (ADR-0029 question 2a): written in one place,
pyproject.toml, and what nervus says of itself read from its installed
package."""

import ast
import re
import subprocess
import sys
import tomllib
from importlib import metadata
from pathlib import Path

import nervus

REPO = Path(__file__).resolve().parent.parent


def test_nervus_version_is_what_the_installed_package_says():
    # Not compared with pyproject.toml's number. When the number is raised in pyproject.toml, an editable install
    # (this venv, and the one the preview export runs its tests with) still says the old number until it is
    # installed again, so a test that the two agree would fail at each raise.
    assert nervus.__version__ == metadata.version("nervus")


def test_from_a_tree_not_installed_the_version_is_unknown():
    # -S: no site-packages, so no installed nervus to read; the tree's own src/ is the one on the path.
    done = subprocess.run([sys.executable, "-I", "-S", "-c",
                           "import sys; sys.path.insert(0, sys.argv[1]); import nervus; print(nervus.__version__)",
                           str(REPO / "src")], capture_output=True, text=True, timeout=60)
    assert (done.returncode, done.stdout) == (0, "unknown\n"), done.stderr


def test_the_release_number_is_written_once_in_pyproject_toml():
    """pyproject.toml's [project] version: three numbers with no leading
    zeros, such as 0.2.0. One form for every release, so that two compare as
    numbers as pip compares them (to pip, 0.2 and 0.2.0 are one), and nervus
    says the number as written (hatchling, building the package, writes 0.02.0
    as 0.2.0). No file under src/ writes it again, as __init__.py once did,
    saying 0.1.0 whatever its code; nor does Python there write any release's
    number, such as an older one."""
    number = tomllib.loads((REPO / "pyproject.toml").read_text())["project"]["version"]
    assert re.fullmatch(r"(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*)){2}", number), \
        f"pyproject.toml's version, {number!r}, is not three numbers with no leading zeros, such as 0.2.0"
    files = [path for path in sorted((REPO / "src").rglob("*")) if path.is_file() and "__pycache__" not in path.parts]
    # The number whole, not a piece of a longer one such as an address.
    whole = re.compile(rb"(?<![0-9])(?<![0-9]\.)" + re.escape(number.encode()) + rb"(?!\.?[0-9])")
    copies = [f"{path.relative_to(REPO)}:{n}" for path in files
              for n, line in enumerate(path.read_bytes().splitlines(), 1) if whole.search(line)]
    assert copies == [], f"pyproject.toml's number, {number}, is written again under src/"
    # Any release's number, as a whole string in Python: the search above finds only this release's.
    literals = [f"{path.relative_to(REPO)}:{node.lineno} {node.value!r}" for path in files if path.suffix == ".py"
                for node in ast.walk(ast.parse(path.read_bytes()))
                if isinstance(node, ast.Constant) and isinstance(node.value, str)
                and re.fullmatch(r"[0-9]+(\.[0-9]+){2}", node.value)]
    assert literals == [], "a release's number is written under src/; nervus's own is its package's"
