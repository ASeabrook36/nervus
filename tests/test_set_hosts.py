"""Tests for tools/set-hosts, run as a script against a stand-in token file.

The values below are fake. The layout follows procedure 006: one list item per
token, `hosts:` as a one-line list, and comments the tool must leave alone.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from nervus.auth import load_tokens

SET_HOSTS = Path(__file__).resolve().parent.parent / "tools" / "set-hosts"

A = "a" * 43
B = "b" * 43
C = "c" * 43
D = "d" * 43

TOKENS = f"""\
# nervus tokens -- 0600, never committed
tokens:
  - token: {A}
    id: claude-code-ops
    client: claude-code
    project: nervus
    hosts: [host-a, host-b]
  # the one Codex uses everywhere
  - token: {B}
    id: codex-anywhere
    client: codex
    project: "*"
    hosts: [host-a, host-b]   # decision 7
  - token: {C}
    id: codex-project-a
    client: codex
    project: project-a
    hosts: [host-a, host-b]
  - id: claude-code-project-a
    token: {D}
    client: claude-code
    project: project-a
    hosts: [host-a, host-b]
"""


@pytest.fixture
def tokens(tmp_path):
    p = tmp_path / "tokens.yaml"
    p.write_text(TOKENS)
    p.chmod(0o600)
    return p


def run(tokens: Path, *args: str) -> subprocess.CompletedProcess:
    env = {**os.environ, "NERVUS_TOKENS_FILE": str(tokens)}
    return subprocess.run([sys.executable, str(SET_HOSTS), *args], env=env,
                          capture_output=True, text=True, timeout=30)


def hosts_by_id(p: Path) -> dict[str, frozenset[str]]:
    return {t.id: t.hosts for t in load_tokens(p).values()}


def test_adds_the_host_to_the_named_tokens_and_changes_nothing_else(tokens):
    r = run(tokens, "hv", "claude-code-ops", "codex-anywhere", "claude-code-project-a")
    assert r.returncode == 0, r.stderr
    assert hosts_by_id(tokens) == {
        "claude-code-ops": {"host-a", "host-b", "hv"},
        "codex-anywhere": {"host-a", "host-b", "hv"},
        "codex-project-a": {"host-a", "host-b"},
        "claude-code-project-a": {"host-a", "host-b", "hv"},
    }
    # Byte for byte, only the three hosts lines differ; the comment on one survives.
    before, after = TOKENS.splitlines(), tokens.read_text().splitlines()
    changed = [(b, a) for b, a in zip(before, after) if b != a]
    assert len(before) == len(after)
    assert changed == [
        ("    hosts: [host-a, host-b]", "    hosts: [host-a, host-b, hv]"),
        ("    hosts: [host-a, host-b]   # decision 7", "    hosts: [host-a, host-b, hv]   # decision 7"),
        ("    hosts: [host-a, host-b]", "    hosts: [host-a, host-b, hv]"),
    ]
    assert os.stat(tokens).st_mode & 0o777 == 0o600


def test_check_reports_and_writes_nothing(tokens):
    r = run(tokens, "--check", "hv", "codex-anywhere")
    assert r.returncode == 0, r.stderr
    assert tokens.read_text() == TOKENS
    assert "codex-anywhere" in r.stdout and "gains hv" in r.stdout and "not written" in r.stdout
    assert not [p for p in tokens.parent.iterdir() if p.name.startswith(".tokens.")]


def test_no_token_value_is_ever_printed(tokens):
    for args in (["--check", "hv", "codex-anywhere"], ["hv", "codex-anywhere"], ["hv", "codex-anywhere"]):
        r = run(tokens, *args)
        for value in (A, B, C, D):
            assert value not in r.stdout and value not in r.stderr


@pytest.mark.parametrize(
    "args, reason",
    [
        (["hv", "no-such-token"], "no token with id"),
        (["host-a", "codex-anywhere"], "already has"),
        (["hv", "codex-anywhere", "codex-anywhere"], "named twice"),
        (["Hv; rm", "codex-anywhere"], "not an inventory name"),
        (["hv"], "usage"),
    ],
)
def test_refusals_change_nothing(tokens, args, reason):
    r = run(tokens, *args)
    assert r.returncode == 1
    assert reason in r.stderr and "nothing changed" in r.stderr
    assert tokens.read_text() == TOKENS


def test_a_hosts_list_it_cannot_edit_safely_stops_it(tokens):
    block = TOKENS.replace(
        "    project: nervus\n    hosts: [host-a, host-b]\n",
        "    project: nervus\n    hosts:\n      - host-a\n      - host-b\n",
    )
    tokens.write_text(block)
    r = run(tokens, "hv", "codex-anywhere", "claude-code-ops")
    assert r.returncode == 1 and "nothing changed" in r.stderr
    assert tokens.read_text() == block


def test_an_id_that_appears_twice_stops_it(tokens):
    # load_tokens keys by value, so it accepts two entries sharing an id. The
    # tool must not guess which hosts line is meant.
    dup = TOKENS.replace("id: codex-project-a", "id: codex-anywhere")
    tokens.write_text(dup)
    r = run(tokens, "hv", "codex-anywhere")
    assert r.returncode == 1 and "nothing changed" in r.stderr
    assert tokens.read_text() == dup
