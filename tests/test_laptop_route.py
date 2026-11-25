"""The laptop's route beside /mcp (ADR-0032 questions 4, 5 and 11): GET serves the script for a
good code and spends nothing; GET /windows serves the PowerShell one; POST hands the token over,
once. Only over HTTPS, never in lockdown, and every fetch and hand-over audited by the code's id
and the token's, never either's value."""

import json

import pytest
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.testclient import TestClient

from nervus.audit import AuditLog
from nervus.database import Database
from nervus.laptop import LaptopRoute, laptop_endpoints
from nervus.token_codes import TokenCodes

PIN = "sha256//47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
ROOT = "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUZmFrZSByb290IGZvciB0ZXN0cw==\n-----END CERTIFICATE-----\n"
BASE = "https://nervus.example:8000"


class World:
    def __init__(self, tmp_path, pin=PIN):
        self.db = Database(tmp_path / "nervus.db")
        self.db.open()
        self.audit = AuditLog(path=tmp_path / "audit.jsonl")
        self.codes = TokenCodes(self.db)
        self.pin, self.lockdown = pin, False
        self.route = LaptopRoute(self.codes, self.audit, pin=lambda: self.pin, root=lambda: ROOT,
                                 locked=lambda: self.lockdown)
        sh, windows = laptop_endpoints(self.route)
        app = Starlette(routes=[Route("/laptop/{code}", sh, methods=["GET", "POST"]),
                                Route("/laptop/{code}/windows", windows, methods=["GET"])])
        self.client = TestClient(app, base_url=BASE)

    def issue(self, kind="claude-code", token_id="laptop"):
        value, _ = self.codes.issue(token_id, kind, kind if kind != "other" else "cursor", "p", ["node-a"])
        return value

    def records(self):
        return [json.loads(line) for line in self.audit.path.read_text().splitlines()] if self.audit.path.exists() else []


@pytest.fixture
def world(tmp_path):
    return World(tmp_path)


def test_get_serves_the_script_for_its_code_and_spends_nothing(world):
    code = world.issue()
    first = world.client.get(f"/laptop/{code}")
    assert first.status_code == 200 and first.headers["cache-control"] == "no-store"
    assert first.text.startswith("#!/bin/sh\n# nervus: set this computer up to reach nervus at "
                                 "https://nervus.example:8000, for Claude Code, with the token laptop.")
    assert f"url='https://nervus.example:8000/laptop/{code}'" in first.text or \
        f"url=https://nervus.example:8000/laptop/{code}" in first.text
    assert "mcp=https://nervus.example:8000/mcp" in first.text
    assert world.client.get(f"/laptop/{code}").status_code == 200
    assert world.client.head(f"/laptop/{code}").status_code == 200
    assert world.codes.find(code) is not None


def test_windows_is_served_its_own_script(world):
    code = world.issue(kind="codex")
    page = world.client.get(f"/laptop/{code}/windows")
    assert page.status_code == 200 and page.text.startswith("# nervus: set this computer up to reach nervus at")
    assert "$nervusClient = 'codex'" in page.text and page.text.isascii()


def test_post_hands_the_token_over_once_and_it_lets_its_client_in(world):
    code = world.issue()
    handed = world.client.post(f"/laptop/{code}")
    assert handed.status_code == 200 and handed.headers["cache-control"] == "no-store"
    value = handed.text.strip()
    assert world.db.token(value).id == "laptop"
    again = world.client.post(f"/laptop/{code}")
    assert again.status_code == 404 and "was used already" in again.text and value not in again.text
    assert world.client.get(f"/laptop/{code}").status_code == 404


def test_every_fetch_and_hand_over_is_audited_by_ids_never_by_value(world):
    code = world.issue()
    world.client.get(f"/laptop/{code}")
    value = world.client.post(f"/laptop/{code}").text.strip()
    world.client.post(f"/laptop/{code}")
    records = [r for r in world.records() if r.get("tool") == "laptop"]
    intents = [r for r in records if r["phase"] == "intent"]
    assert [r["action"] for r in intents] == ["fetch", "hand_over", "hand_over"]
    assert all(r["target"] == "laptop" and r["client"] == "claude-code" and r["code_id"] for r in intents)
    results = [r for r in records if r["phase"] == "result"]
    assert [r.get("served") or r.get("handed_over") or r.get("failure_code") for r in results] == [
        "macos-linux", True, "used"]
    text = world.audit.path.read_text()
    assert code not in text and value not in text


def test_an_unknown_code_is_refused_and_recorded(world):
    refused = world.client.get("/laptop/not-a-code")
    assert refused.status_code == 404 and "unknown, used or expired" in refused.text
    assert world.client.post("/laptop/not-a-code").status_code == 404
    assert [r["reason"] for r in world.records() if r.get("phase") == "refused"] == [
        "unknown, used or expired code"] * 2


def test_over_plain_http_it_serves_nothing_and_keeps_the_code(tmp_path):
    world = World(tmp_path, pin=None)
    code = world.issue()
    for answer in (world.client.get(f"/laptop/{code}"), world.client.post(f"/laptop/{code}")):
        assert answer.status_code == 503 and "plain HTTP" in answer.text
    world.pin = PIN
    assert world.client.post(f"/laptop/{code}").status_code == 200


def test_in_lockdown_it_hands_over_nothing_and_keeps_the_code(world):
    code = world.issue()
    world.lockdown = True
    for answer in (world.client.get(f"/laptop/{code}"), world.client.post(f"/laptop/{code}")):
        assert answer.status_code == 503 and "locked down" in answer.text
    world.lockdown = False
    assert world.client.post(f"/laptop/{code}").status_code == 200


def test_a_token_revoked_before_its_line_is_used_hands_over_nothing(world):
    code = world.issue()
    world.db.revoke_token("laptop")
    answer = world.client.post(f"/laptop/{code}")
    assert answer.status_code == 404 and "unknown" in answer.text


def test_the_script_names_nervus_by_the_address_the_line_used(world):
    code = world.issue()
    other = TestClient(world.client.app, base_url="https://[2001:db8::5]:8000")
    text = other.get(f"/laptop/{code}").text
    assert "origin='https://[2001:db8::5]:8000'" in text and "host=2001:db8::5" in text
    assert "safe=2001-db8--5" in text and "name=2001-db8--5-laptop" in text


def test_the_guide_s_two_lines_are_the_ones_the_clients_page_shows():
    import re
    import shlex
    from pathlib import Path

    from nervus.laptop import laptop_line, laptop_url, powershell_line

    guide = (Path(__file__).resolve().parent.parent / "docs" / "clients.md").read_text()

    def block(name, language):
        found = re.search(rf"<!-- laptop:{name} -->\n *```{language}\n *(.*?)\n *```", guide, re.S)
        assert found, f"docs/clients.md has no laptop:{name} block"
        return (found.group(1).strip().replace("<nervus's key>", PIN[len("sha256//"):])
                .replace("<nervus>", "nervus.example").replace("<one-time code>", "C0DE"))
    shown = laptop_line(laptop_url("nervus.example", 8000, "C0DE"), PIN)
    assert shlex.split(block("sh", "bash")) == shlex.split(shown)
    assert block("windows", "powershell") == powershell_line(laptop_url("nervus.example", 8000, "C0DE", True), PIN).strip()
