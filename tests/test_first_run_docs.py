"""The docs for first-run setup (ADR-0015, ADR-0007 consequences 1 and 4):
the preview README carries the non-goals and what an agent can do to you;
docs/install.md has the tier chosen at setup, and no longer says there is no
first-run setup."""

import re
from pathlib import Path

from nervus.pages import NON_GOALS

REPO = Path(__file__).resolve().parent.parent
# The preview's README: in preview/ here; in the export, which has no preview/ and runs these tests
# on its own tree, the README.md at its top (tools/export-preview steps 3 and 7).
README = REPO / "preview" / "README.md"
if not README.exists():
    README = REPO / "README.md"
INSTALL = REPO / "docs" / "install.md"


def _section(path, heading):
    match = re.search(rf"^## {re.escape(heading)}\n(.*?)(?=^## |\Z)", path.read_text(), re.S | re.M)
    assert match, f"{path.name} has no section {heading!r}"
    return " ".join(match.group(1).split())


def test_the_readme_states_the_non_goals_in_plain_words():
    # ADR-0007 decision 9 and verification 1, its README half.
    said = _section(README, "What nervus does not defend against")
    for words in ("containment and accountability", "Programs running as you", "read the token that client uses",
                  "anyone with root on its machine", "unlocked computer", "nervus records it",
                  "a machine attacking its own data"):
        assert words.lower() in said.lower(), words


def test_the_readme_says_one_nervus_is_one_trust_domain():
    # ADR-0007 decision 10: "The README must say it".
    said = _section(README, "What nervus does not defend against")
    assert "One nervus is one trust domain" in said and "no user accounts" in said
    assert "share all of it" in said


def test_the_readme_says_never_to_forward_a_port():
    said = _section(README, "What nervus does not defend against")
    assert "Never forward a port on your router to nervus" in said and "overlay network" in said
    assert "cannot see a forwarded port" in said


def _opening(goal: str) -> str:
    """A non-goal's opening words: up to its first colon or full stop."""
    return " ".join(goal.split(":")[0].split(".")[0].split()).lower()


def test_the_readme_and_the_setup_page_name_the_same_non_goals():
    # Each of the setup page's non-goals, by its opening words, is in the README too.
    said = _section(README, "What nervus does not defend against").lower()
    for goal in NON_GOALS:
        assert _opening(goal) in said, _opening(goal)


def test_every_non_goal_the_readme_names_is_on_the_setup_page_too():
    # The other way: procedure 054, finding 5. ADR-0027 step 6 gave the README two non-goals on
    # backups and the setup page neither, though the README says the page "says the same".
    match = re.search(r"^## What nervus does not defend against\n(.*?)(?=^\*\*|^## )", README.read_text(), re.S | re.M)
    named = [_opening(bold) for bold in re.findall(r"^- \*\*(.+?)\*\*", match.group(1), re.S | re.M)]
    assert len(named) == 9 and "losing the recovery key, or giving it away" in named
    on_the_page = [_opening(goal) for goal in NON_GOALS]
    assert named == on_the_page


def test_the_readme_says_what_an_agent_can_do_to_you():
    # ADR-0007 consequence 4, as ADR-0015 decision H amended it: a section, concrete.
    said = _section(README, "What an agent can do to you")
    assert "issue, a pull request, a web page" in said
    for level, what in (("read-only", "kernel refuses"), ("standard", "what nervus's account owns"),
                        ("full", "anything you could as root")):
        assert f"**{level}**" in said and what in said, level
    assert "stops changes, not reading" in said
    assert "switch that client off" in said and "audit log" in said
    assert "fewest machines at the lowest level" in said


def test_the_readme_no_longer_says_there_is_no_first_run_setup():
    text = README.read_text()
    assert "no first-run setup" not in text.lower()
    assert "first-run setup (ADR-0015)" in _section(README, "What works, and what does not yet")


def test_install_md_no_longer_says_there_is_no_first_run_setup():
    assert "no first-run setup" not in INSTALL.read_text().lower()


def test_install_md_step_3_chooses_the_tier_first():
    said = _section(INSTALL, "3. Sign in, choose the tier, and add the machines nervus reaches")
    tier, machines = said.index("Choose nervus's tier"), said.index("Machines** page")
    assert tier < machines
    for words in ("every other page waits", "your clients are not held back", '"Where nervus may run"',
                  "Never forward a port on your router to nervus", "declare its range internal",
                  "a note naming your declaration", "the tier at the top of every page"):
        assert words in said, words
