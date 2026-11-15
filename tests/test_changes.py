"""CHANGES.md, at the top of the repository and exported with it (ADR-0029
question 9a, step 1): it has a section for the release pyproject.toml names,
which begins with the day that release was exported; every section is headed
by a release number, newest first; and each names the three heads and says
something under each. Both files are found from this file's own path, at the
top of its tree, so the export's run of tests/ reads the exported tree's own."""

import re
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CHANGES = REPO / "CHANGES.md"
PYPROJECT = REPO / "pyproject.toml"
HEADS = ("What you will see", "What each client must do", "What the upgrade does")
# A section's heading after "## ": the release number, three numbers with no leading zeros as
# tests/test_package.py has it, which may go on after a space.
RELEASE = re.compile(r"((?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2})(?: .*)?")
# A head: in bold, at the start of a line. What it says runs to the next head, or to the section's end.
HEAD = re.compile(r"^\*\*(" + "|".join(map(re.escape, HEADS)) + r"):\*\*", re.M)
# A section's first line once its release is exported, and nothing else on it; until then it
# begins "Not yet exported.".
EXPORTED = re.compile(r"Exported [0-9]{4}-[0-9]{2}-[0-9]{2}\.")


def _sections():
    """Each section as (heading, body): a line starting "## ", and what follows it to the next."""
    parts = re.split(r"^## (.*)\n?", CHANGES.read_text(), flags=re.M)
    return list(zip(parts[1::2], parts[2::2]))


def _number(heading):
    """The release number a section's heading names, or None."""
    match = RELEASE.fullmatch(heading)
    return match.group(1) if match else None


def _releases():
    """The release number of each section headed by one, in the file's order."""
    return [number for number in (_number(heading) for heading, _ in _sections()) if number]


def _heads(body):
    """Each head in a section's body, as (head, what it says)."""
    parts = HEAD.split(body)
    return list(zip(parts[1::2], parts[2::2]))


def _release():
    """The release pyproject.toml names."""
    return tomllib.loads(PYPROJECT.read_text())["project"]["version"]


def test_changes_md_has_a_section_for_the_release_in_pyproject_toml():
    release = _release()
    assert release in _releases(), f"CHANGES.md has no section for {release}, the release pyproject.toml names"


def test_the_section_for_the_release_in_pyproject_toml_is_dated():
    # pyproject.toml names the last export, or, in the commit an export is made from, the one being made: by then
    # its "Not yet exported." has become the day. The export runs tests/ on what it exports, so a line left as it
    # was stops the export there. A later release's section, the next export's, still says it.
    release = _release()
    for heading, body in _sections():
        if _number(heading) == release:
            first = (body.strip().splitlines() or [""])[0]
            assert EXPORTED.fullmatch(first), \
                f'the section for {release} begins {first!r}: at its export, that line becomes "Exported <the day>."'


def test_every_section_is_headed_by_a_release_number():
    sections = _sections()
    assert sections, "CHANGES.md has no sections"
    for heading, _ in sections:
        assert RELEASE.fullmatch(heading), f"CHANGES.md has a section headed {heading!r}, not a release number"


def test_sections_are_newest_first():
    # Compared as numbers, part by part: 0.10.0 is newer than 0.9.0.
    numbers = [tuple(int(part) for part in release.split(".")) for release in _releases()]
    assert all(newer > older for newer, older in zip(numbers, numbers[1:])), _releases()


def test_every_section_names_the_three_heads():
    for heading, body in _sections():
        named = [head for head, _ in _heads(body)]
        for head in HEADS:
            assert head in named, f"section {heading!r} has no **{head}:**"


def test_every_head_says_something():
    # On the head's own line, or below it as a list. "Nothing" is something: what each client must do is often
    # nothing (ADR-0029 question 9a), and said so, it cannot be taken for something forgotten.
    for heading, body in _sections():
        for head, says in _heads(body):
            assert says.strip(), f"section {heading!r} says nothing under **{head}:**"
