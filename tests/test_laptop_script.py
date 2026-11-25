"""The laptop's script and its helper (ADR-0032 questions 4, 5, 6 and 11), run here in real shells
as the person would run them, piped (`curl … | sh`).

`PATH` holds only logging stand-ins: each real command the script runs is a shim that writes its
arguments to a log, then runs the real one, so the tests can say what no command was given. curl,
uname, id and the macOS keychain's `security` are stood in for: curl answers as nervus would, and
`security` keeps what it is given in a folder. Verification 6 is checked on every run: the token is
in no command's arguments, on neither of the script's outputs, and in no file but the one named.
The Windows script is parsed by PowerShell where there is one here; it runs on Windows in the
trial (procedure 069)."""

import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from nervus.laptop import TARGET, laptop_powershell, laptop_script

PIN = "sha256//47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
ROOT = "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUZmFrZSByb290IGZvciB0ZXN0cw==\n-----END CERTIFICATE-----"
OTHER_ROOT = "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUYW5vdGhlciBuZXJ2dXMncyByb290\n-----END CERTIFICATE-----"
TOKEN = "Tok3nValueForTheseTestsOnly-0123456789abcdefg"
ORIGIN, HOST = "https://192.0.2.5:8000", "192.0.2.5"
URL = f"{ORIGIN}/laptop/C0DE"
SHELLS = ["sh"] + (["dash"] if shutil.which("dash") else [])
SH = shutil.which("sh")
REAL = ["mktemp", "cmp", "cp", "chmod", "mv", "mkdir", "awk", "grep", "rm", "sed", "head", "cat", "printf", "tr", "find"]

# What nervus answers: the code's check, the root's, and the hand-over. Each run of it is logged too.
CURL = r'''#!/bin/sh
printf 'curl %s\n' "$*" >> "$W/argv"
case " $* " in
  *" -X POST "*) [ -n "${POST_DOWN:-}" ] && exit 7
                 # As nervus answers: the token, or its reason, and a line break; then curl's -w.
                 printf '%s\n\n%s' "$(cat "$W/send")" "${POST_STATUS:-200}"; exit 0 ;;
  *" --cacert "*) [ -n "${CHECK_FAILS:-}" ] && { echo "curl: (60) SSL certificate problem: unable to get local issuer" >&2; exit 60; }
                  exit 0 ;;
  *" -o /dev/null "*) [ -n "${DOWN:-}" ] && { echo "curl: (7) Failed to connect" >&2; exit 7; }
                      printf %s "${FIRST:-200}"; exit 0 ;;
esac
exit 2
'''
# The keychain: an item is a file under $W/keychain; what `security -i` is given is kept, to check its -T "".
SECURITY = '''#!{python}
import os, shlex, sys
w = os.environ["W"]
kept = os.path.join(w, "keychain")
os.makedirs(kept, exist_ok=True)
with open(os.path.join(w, "argv"), "a") as log:
    log.write("security " + " ".join(sys.argv[1:]) + "\\n")
args = sys.argv[1:]
if args == ["default-keychain"]:
    print('    "' + os.path.join(w, "login.keychain-db") + '"')
    sys.exit(0)
if args[:1] == ["show-keychain-info"]:
    sys.exit(152 if os.environ.get("LOCKED") else 0)
def item(words):
    return words[words.index("-s") + 1]
if args[:1] == ["find-generic-password"]:
    path = os.path.join(kept, item(args))
    if not os.path.exists(path):
        sys.exit(44)
    if "-w" in args:
        print(open(path).read())
    sys.exit(0)
if args == ["-i"]:
    given = sys.stdin.read()
    open(os.path.join(w, "security-input"), "a").write(given)
    for line in given.splitlines():
        words = shlex.split(line)
        if words[:1] == ["add-generic-password"] and "-U" not in words:
            if os.path.exists(os.path.join(kept, item(words))):
                sys.exit(1)
            open(os.path.join(kept, item(words)), "w").write(words[words.index("-w") + 1])
    sys.exit(0)
sys.exit(2)
'''


def _command(path: Path, body: str) -> None:
    path.write_text(body)
    path.chmod(0o755)


class Laptop:
    """A person's computer that has never seen nervus, under one folder."""

    def __init__(self, tmp: Path, os_name="Linux", python=True):
        self.w, self.home = tmp, tmp / "home"
        self.bin = tmp / "bin"
        for d in (self.home, self.bin, tmp / "tmp"):
            d.mkdir(parents=True)
        (tmp / "argv").touch()
        (tmp / "send").write_text(TOKEN)
        for name in REAL + (["python3"] if python else []):
            real = shutil.which(name) if name != "python3" else sys.executable
            _command(self.bin / name, f'#!/bin/sh\nprintf "{name} %s\\n" "$*" >> "$W/argv"\nexec {shlex.quote(real)} "$@"\n')
        _command(self.bin / "curl", CURL)
        _command(self.bin / "uname", f'#!/bin/sh\nprintf "uname %s\\n" "$*" >> "$W/argv"\necho {os_name}\n')
        _command(self.bin / "id", '#!/bin/sh\nprintf "id %s\\n" "$*" >> "$W/argv"\necho "${UID_IS:-1000}"\n')
        _command(self.bin / "security", SECURITY.format(python=sys.executable))
        self.dir = self.home / ".config" / "nervus"

    def script(self, client="claude-code", token_id="laptop") -> str:
        return laptop_script(origin=ORIGIN, host=HOST, url=URL, pin=PIN, root_pem=ROOT, token_id=token_id,
                             client=client)

    def env(self, **more):
        # SHELL given: unset, a Mac's sh sets it to the account's own login shell.
        return {"PATH": str(self.bin), "HOME": str(self.home), "W": str(self.w), "LANG": "C", "SHELL": "/bin/bash",
                "TMPDIR": str(self.w / "tmp"), "NERVUS_SECURITY_BIN": str(self.bin / "security"), **more}

    def run(self, client="claude-code", shell="sh", text=None, **env):
        done = subprocess.run([shutil.which(shell)], input=self.script(client) if text is None else text,
                              capture_output=True, text=True, env=self.env(**env), timeout=60)
        # Verification 6, on every run: in no command's arguments, on neither output.
        assert TOKEN not in (self.w / "argv").read_text()
        assert TOKEN not in done.stdout + done.stderr
        return done

    @property
    def argv(self):
        return (self.w / "argv").read_text().splitlines()

    def files_holding_the_token(self):
        return sorted(str(p.relative_to(self.w)) for p in self.w.rglob("*")
                      if p.is_file() and not p.is_symlink() and TOKEN.encode() in p.read_bytes()
                      and p.name != "send")

    def printed(self, done, starts):
        return [line.strip() for line in done.stdout.splitlines() if line.strip().startswith(starts)]


@pytest.fixture
def laptop(tmp_path):
    return Laptop(tmp_path)


# --- what it makes, and where the token goes ------------------------------------------------

@pytest.mark.parametrize("shell", SHELLS)
def test_on_linux_it_saves_the_root_the_helper_and_the_token_and_prints_claude_code_s_commands(laptop, shell):
    done = laptop.run(shell=shell)
    assert done.returncode == 0, done.stderr
    assert (laptop.dir / f"root-{HOST}.pem").read_text() == ROOT + "\n"
    assert (laptop.dir / "roots.pem").read_text() == ROOT + "\n"
    helper = laptop.dir / "nervus-headers"
    assert helper.read_text() == (TARGET / "nervus-headers").read_text() and os.access(helper, os.X_OK)
    token = laptop.dir / f"token-{HOST}-laptop"
    assert token.read_text() == TOKEN + "\n" and stat.S_IMODE(token.stat().st_mode) == 0o600
    # In no file but the one named (verification 6).
    assert laptop.files_holding_the_token() == [str(token.relative_to(laptop.w))]
    [add] = laptop.printed(done, "claude mcp add-json")
    words = shlex.split(add)
    assert words[:6] == ["claude", "mcp", "add-json", "--scope", "user", "nervus"]
    assert json.loads(words[6]) == {"type": "http", "url": f"{ORIGIN}/mcp",
                                    "headersHelper": f"{laptop.dir}/nervus-headers {HOST}-laptop"}
    assert "It runs none of them." in laptop.script()


def test_the_code_is_asked_about_first_then_the_root_checked_then_the_token_fetched(laptop):
    laptop.run()
    calls = [line for line in laptop.argv if line.startswith("curl ")]
    assert calls[0] == f"curl -sSk --pinnedpubkey {PIN} -o /dev/null -w %{{http_code}} {URL}"
    assert calls[1].startswith("curl -sS -o /dev/null --max-time 10 --cacert ") and calls[1].endswith(f" {ORIGIN}/")
    assert calls[2] == f"curl -sSk --pinnedpubkey {PIN} -X POST -w \\n%{{http_code}} {URL}"
    assert len(calls) == 3


def test_every_nervus_root_saved_here_is_gathered_into_roots_pem_certificates_alone(laptop):
    laptop.dir.mkdir(parents=True)
    (laptop.dir / "root-other.pem").write_text("junk before\n" + OTHER_ROOT + "\njunk after\n")
    assert laptop.run().returncode == 0
    gathered = (laptop.dir / "roots.pem").read_text()
    assert ROOT in gathered and OTHER_ROOT in gathered and "junk" not in gathered


def test_a_different_root_saved_for_the_same_name_is_replaced_by_nervus_s_own_and_said(laptop):
    laptop.dir.mkdir(parents=True)
    (laptop.dir / f"root-{HOST}.pem").write_text(OTHER_ROOT + "\n")
    done = laptop.run()
    assert (laptop.dir / f"root-{HOST}.pem").read_text() == ROOT + "\n"
    assert "in place of the one saved there before, another nervus's at that name" in done.stdout


def test_the_printed_settings_command_on_linux_names_the_roots_for_claude_code(laptop):
    done = laptop.run()
    [mkdir] = laptop.printed(done, "mkdir -p")
    [python] = laptop.printed(done, "python3 -c")
    env = laptop.env()
    subprocess.run([SH, "-c", mkdir + " && " + python], env=env, check=True)
    settings = json.loads((laptop.home / ".claude" / "settings.json").read_text())
    assert settings == {"env": {"NODE_EXTRA_CA_CERTS": str(laptop.dir / "roots.pem")}}


def test_settings_that_name_the_roots_already_need_nothing(laptop):
    (laptop.home / ".claude").mkdir()
    (laptop.home / ".claude" / "settings.json").write_text(
        json.dumps({"env": {"NODE_EXTRA_CA_CERTS": str(laptop.dir / "roots.pem")}}))
    done = laptop.run()
    assert laptop.printed(done, "python3 -c") == [] and laptop.printed(done, "plutil") == []


def test_settings_that_name_another_file_are_warned_of_not_overwritten(laptop):
    (laptop.home / ".claude").mkdir()
    (laptop.home / ".claude" / "settings.json").write_text('{"env": {"NODE_EXTRA_CA_CERTS": "/etc/company.pem"}}')
    done = laptop.run()
    assert "name /etc/company.pem as the file of roots it trusts" in done.stdout
    assert f"cat '{laptop.dir / 'roots.pem'}' >> '/etc/company.pem'" in done.stdout
    assert laptop.printed(done, "python3 -c") == []


def test_without_python_the_setting_is_said_in_words(tmp_path):
    laptop = Laptop(tmp_path, python=False)
    done = laptop.run()
    assert f'set "NODE_EXTRA_CA_CERTS": "{laptop.dir / "roots.pem"}"' in done.stdout


@pytest.mark.parametrize("shell", SHELLS)
def test_for_codex_the_printed_commands_add_the_server_whole_with_its_helper(laptop, shell, tmp_path):
    done = laptop.run(client="codex", shell=shell)
    assert done.returncode == 0, done.stderr
    [append] = laptop.printed(done, "mkdir -p")
    assert "\\n[mcp_servers.nervus]" in append  # printed as typed, never turned into a line break by echo
    codex_home = laptop.home / ".codex"
    codex_home.mkdir()
    (codex_home / "config.toml").write_text('model = "x"\n\n[tui]\nanimations = false\n')
    subprocess.run([SH, "-c", append], env=laptop.env(), check=True)
    import tomllib
    config = tomllib.loads((codex_home / "config.toml").read_text())
    assert config["mcp_servers"]["nervus"] == {"url": f"{ORIGIN}/mcp",
                                               "http_headers_helper": f"{laptop.dir}/nervus-headers {HOST}-laptop"}
    assert config["tui"] == {"animations": False}
    assert f"echo \"export CODEX_CA_CERTIFICATE='{laptop.dir / 'roots.pem'}'\" >> ~/.profile" in done.stdout
    assert "  codex mcp remove nervus" not in done.stdout


def test_for_codex_a_server_named_nervus_already_is_removed_first(laptop):
    (laptop.home / ".codex").mkdir()
    (laptop.home / ".codex" / "config.toml").write_text('[mcp_servers.nervus]\nurl = "https://old:8000/mcp"\n')
    done = laptop.run(client="codex")
    lines = [line.strip() for line in done.stdout.splitlines()]
    assert lines.index("codex mcp remove nervus") < next(i for i, l in enumerate(lines) if l.startswith("mkdir -p"))


# Never run unasked: Codex is the operator's to run (procedure 030 step 6). Only where NERVUS_TEST_CODEX names a
# Codex they chose to have the tests run, with a scratch CODEX_HOME, nothing of theirs read or changed.
@pytest.mark.skipif(not os.environ.get("NERVUS_TEST_CODEX"), reason="Codex runs only where NERVUS_TEST_CODEX names it")
def test_codex_itself_reads_the_server_the_printed_command_adds(laptop):
    done = laptop.run(client="codex")
    [append] = laptop.printed(done, "mkdir -p")
    subprocess.run([SH, "-c", append], env=laptop.env(), check=True)
    seen = subprocess.run([os.environ["NERVUS_TEST_CODEX"], "mcp", "get", "nervus"],
                          capture_output=True, text=True, env={**os.environ, "CODEX_HOME": str(laptop.home / ".codex")},
                          timeout=60)
    assert seen.returncode == 0, seen.stderr
    assert f"url: {ORIGIN}/mcp" in seen.stdout and "http_headers_helper: <redacted>" in seen.stdout


def test_another_client_is_told_the_helper_the_address_and_the_roots(laptop):
    done = laptop.run(client="other")
    assert f"nervus's MCP address is {ORIGIN}/mcp" in done.stdout
    assert f"{laptop.dir}/nervus-headers {HOST}-laptop prints them" in done.stdout
    assert "claude mcp" not in done.stdout and "codex" not in done.stdout


# --- on a Mac: the keychain ------------------------------------------------------------------

@pytest.mark.parametrize("shell", SHELLS)
def test_on_a_mac_the_token_goes_into_the_keychain_on_its_standard_input_trusting_no_application(tmp_path, shell):
    laptop = Laptop(tmp_path, os_name="Darwin")
    done = laptop.run(shell=shell)
    assert done.returncode == 0, done.stderr
    item = f"nervus-{HOST}-laptop"
    assert (laptop.w / "keychain" / item).read_text() == TOKEN
    [given] = (laptop.w / "security-input").read_text().splitlines()
    words = shlex.split(given)
    assert words[:6] == ["add-generic-password", "-a", "nervus", "-s", item, "-l"]
    assert words[words.index("-T") + 1] == "" and words[-2] == "-w"
    assert not (laptop.dir / f"token-{HOST}-laptop").exists()
    # The keychain's own folder aside, in no file (verification 6).
    assert laptop.files_holding_the_token() == [f"keychain/{item}", "security-input"]
    assert f"macOS asks whether security may use {item}: Allow, never Always Allow." in done.stdout


@pytest.mark.skipif(not Path("/usr/bin/osascript").exists(), reason="no osascript: not a Mac")
@pytest.mark.parametrize("before", [None, "{}\n", '{\n  "model": "x",\n  "env": {"FOO": "bar"}\n}\n'],
                         ids=["none", "empty", "others"])
def test_on_a_mac_the_printed_command_names_the_roots_for_claude_code_keeping_the_rest(tmp_path, before):
    laptop = Laptop(tmp_path, os_name="Darwin")
    if before is not None:
        (laptop.home / ".claude").mkdir()
        (laptop.home / ".claude" / "settings.json").write_text(before)
    done = laptop.run()
    [command] = laptop.printed(done, "mkdir -p")
    subprocess.run([SH, "-c", command], env={**laptop.env(), "PATH": "/usr/bin:/bin"}, check=True)
    settings = json.loads((laptop.home / ".claude" / "settings.json").read_text())
    kept = json.loads(before) if before else {}
    assert settings == {**kept, "env": {**kept.get("env", {}), "NODE_EXTRA_CA_CERTS": str(laptop.dir / "roots.pem")}}


def test_on_a_mac_an_item_of_the_same_name_stops_it_before_the_code_is_used(tmp_path):
    # Replacing an item that trusts no application asks the person, so it is never replaced.
    laptop = Laptop(tmp_path, os_name="Darwin")
    (laptop.w / "keychain").mkdir()
    (laptop.w / "keychain" / f"nervus-{HOST}-laptop").write_text("old")
    done = laptop.run()
    assert done.returncode == 1 and "security delete-generic-password -a nervus -s" in done.stderr
    assert not any(line.startswith("curl") for line in laptop.argv) and not laptop.dir.exists()


def test_on_a_mac_a_locked_keychain_stops_it_before_the_code_is_used(tmp_path):
    # Step 5's review: over SSH a Mac's keychain is locked; the token would be fetched and kept nowhere.
    laptop = Laptop(tmp_path, os_name="Darwin")
    done = laptop.run(LOCKED="1")
    assert done.returncode == 1 and "your login keychain is locked" in done.stderr
    assert not any(line.startswith("curl") for line in laptop.argv) and not laptop.dir.exists()


@pytest.mark.skipif(not Path("/usr/bin/osascript").exists(), reason="no osascript: not a Mac")
def test_on_a_mac_a_settings_file_that_is_a_link_is_changed_where_it_points_its_mode_kept(tmp_path):
    laptop = Laptop(tmp_path, os_name="Darwin")
    dotfiles = tmp_path / "dotfiles"
    dotfiles.mkdir()
    (dotfiles / "settings.json").write_text('{"model": "x"}\n')
    (dotfiles / "settings.json").chmod(0o600)
    (laptop.home / ".claude").mkdir()
    (laptop.home / ".claude" / "settings.json").symlink_to(dotfiles / "settings.json")
    done = laptop.run()
    [command] = laptop.printed(done, "mkdir -p")
    subprocess.run([SH, "-c", command], env={**laptop.env(), "PATH": "/usr/bin:/bin"}, check=True)
    assert (laptop.home / ".claude" / "settings.json").is_symlink()
    assert json.loads((dotfiles / "settings.json").read_text()) == {
        "model": "x", "env": {"NODE_EXTRA_CA_CERTS": str(laptop.dir / "roots.pem")}}
    assert stat.S_IMODE((dotfiles / "settings.json").stat().st_mode) == 0o600


@pytest.mark.parametrize("make", ["link", "writable", "parent-writable"])
def test_a_folder_not_the_person_s_alone_keeps_nothing_of_nervus_s(laptop, tmp_path, make):
    # Step 5's review: another account able to write there could take the token or swap the helper.
    config = laptop.home / ".config"
    if make == "link":
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        config.mkdir()
        (config / "nervus").symlink_to(elsewhere)
    elif make == "writable":
        (config / "nervus").mkdir(parents=True)
        (config / "nervus").chmod(0o777)
    else:
        config.mkdir()
        config.chmod(0o775)
    done = laptop.run()
    assert done.returncode == 1 and ("is not a folder of yours" in done.stderr or "can write in" in done.stderr), done.stderr
    assert not any(" -X POST " in line for line in laptop.argv)
    assert not list((laptop.home / ".config").rglob("token-*")) and not list((tmp_path / "elsewhere").glob("*"))


@pytest.mark.parametrize("config", ['[mcp_servers.nervus]\nurl = "x"\n', '[mcp_servers."nervus"]\nurl = "x"\n',
                                    '[mcp_servers]\nnervus = { url = "x" }\n', 'mcp_servers.nervus.url = "x"\n'],
                         ids=["table", "quoted", "inline", "dotted"])
def test_for_codex_a_server_named_nervus_in_any_form_is_removed_first(laptop, config):
    (laptop.home / ".codex").mkdir()
    (laptop.home / ".codex" / "config.toml").write_text(config)
    done = laptop.run(client="codex")
    assert "  codex mcp remove nervus" in done.stdout


@pytest.mark.parametrize("shell, files, written", [
    ("/bin/zsh", [], "~/.zprofile"), ("/bin/bash", [], "~/.profile"), ("/bin/bash", [".bash_profile"], "~/.bash_profile"),
    ("/bin/bash", [".bash_login"], "~/.bash_login"), ("", [], "~/.profile")])
def test_codex_s_root_goes_into_the_login_file_the_person_s_shell_reads(laptop, shell, files, written):
    for name in files:
        (laptop.home / name).write_text("")
    done = laptop.run(client="codex", SHELL=shell)
    assert f"export CODEX_CA_CERTIFICATE='{laptop.dir / 'roots.pem'}'\" >> {written}" in done.stdout


def test_a_client_s_settings_folder_holding_a_quote_is_refused(laptop):
    done = laptop.run(CODEX_HOME=str(laptop.home / "it's"))
    assert done.returncode == 1 and "holds a quote" in done.stderr and not laptop.dir.exists()


# --- what stops it, and what it leaves ------------------------------------------------------

@pytest.mark.parametrize("env, says", [
    ({"UID_IS": "0"}, "run this as yourself, not as root"),
    ({"FIRST": "404"}, "this line's code is used or expired (nervus answered 404)"),
    ({"DOWN": "1"}, "could not reach nervus at https://192.0.2.5:8000"),
    ({"CHECK_FAILS": "1"}, "nervus does not check out against its own root as 192.0.2.5"),
], ids=["root", "used-code", "nervus-out-of-reach", "root-does-not-check-out"])
def test_what_stops_it_before_it_changes_anything(laptop, env, says):
    done = laptop.run(**env)
    assert done.returncode == 1 and says in done.stderr and "Nothing here was changed." in done.stderr
    assert not laptop.dir.exists() and not any(" -X POST " in line for line in laptop.argv)
    assert list((laptop.w / "tmp").iterdir()) == []


def test_neither_a_mac_nor_linux_is_sent_to_the_windows_line(tmp_path):
    laptop = Laptop(tmp_path, os_name="FreeBSD")
    done = laptop.run()
    assert done.returncode == 1 and "run the PowerShell line" in done.stderr and not laptop.dir.exists()


def test_a_token_nervus_will_not_hand_over_leaves_the_root_and_helper_and_says_why(laptop):
    (laptop.w / "send").write_text("nervus: this line's code was used already, so the token went to whatever ran it first")
    done = laptop.run(POST_STATUS="404")
    assert done.returncode == 1
    assert "nervus did not hand over the token: this line's code was used already" in done.stderr
    assert (laptop.dir / "nervus-headers").exists() and not list(laptop.dir.glob("token-*"))


def test_what_is_not_a_token_is_never_kept(laptop):
    (laptop.w / "send").write_text("<html>not a token</html>")
    done = laptop.run()
    assert done.returncode == 1 and "is not a token" in done.stderr and not list(laptop.dir.glob("token-*"))


def test_a_folder_with_a_character_a_command_line_would_split_is_refused(laptop):
    done = laptop.run(XDG_CONFIG_HOME=str(laptop.home / "my config"))
    assert done.returncode == 1 and "has a character a client's command line would split" in done.stderr


# --- a download cut partway ------------------------------------------------------------------

def _cuts(script: str) -> list[int]:
    """Every byte of every line outside the body's function, every point of the last 200 bytes, around
    each line ending of every fifth line, and every 97 bytes besides; up to the group's closing brace."""
    last = script.rindex("}")
    body = script.index("nervus_laptop() {")
    points = set(range(script.index("\n{\n"), body + len("nervus_laptop() {") + 1))
    points.update(range(script.rindex("\n}\n", 0, script.rindex("nervus_laptop </dev/null")), last))
    points.update(range(max(0, len(script) - 200), last))
    for n, i in enumerate(i for i, c in enumerate(script) if c == "\n"):
        if n % 5 == 0:
            points.update((i, i + 1))
    points.update(range(0, len(script), 97))
    return sorted(p for p in points if 0 <= p < last)


@pytest.mark.parametrize("shell", SHELLS)
def test_a_download_cut_partway_runs_nothing_and_changes_nothing(laptop, shell):
    """Consequence 4: wherever it stops, nothing of it runs, no command is looked for, nothing is said."""
    script = laptop.script()
    before = sorted(laptop.w.rglob("*"))
    cuts = _cuts(script)
    assert len(cuts) > 300
    for at in cuts:
        done = laptop.run(shell=shell, text=script[:at])
        assert laptop.argv == [], (at, script[max(0, at - 60):at])
        assert done.stdout == "" and "not found" not in done.stderr, (at, done.stdout, done.stderr)
    assert sorted(laptop.w.rglob("*")) == before
    assert laptop.run(shell=shell, text=script).returncode == 0


def test_the_script_is_one_group_closed_on_its_last_line():
    script = Laptop.script(None)
    assert script.endswith("\nnervus_laptop </dev/null\n}\n") and "\n{\nset -u\n" in script
    assert all(line.startswith("#") or not line for line in script.split("\n{\n")[0].splitlines())


# --- the helper ------------------------------------------------------------------------------

def _helper(laptop, *args, os_name="Linux"):
    folder = laptop.w / "installed"
    folder.mkdir(exist_ok=True)
    helper = folder / "nervus-headers"
    shutil.copy(TARGET / "nervus-headers", helper)
    helper.chmod(0o755)
    _command(laptop.bin / "uname", f"#!/bin/sh\necho {os_name}\n")
    return folder, subprocess.run([SH, str(helper), *args], capture_output=True, text=True, env=laptop.env())


def test_the_helper_prints_the_header_from_the_file_beside_it(laptop):
    folder = laptop.w / "installed"
    folder.mkdir()
    (folder / "token-h-laptop").write_text(TOKEN + "\n")
    _, done = _helper(laptop, "h-laptop")
    assert done.returncode == 0 and json.loads(done.stdout) == {"Authorization": f"Bearer {TOKEN}"}
    assert done.stderr == ""


def test_on_a_mac_the_helper_reads_the_keychain(laptop):
    (laptop.w / "keychain").mkdir()
    (laptop.w / "keychain" / "nervus-h-laptop").write_text(TOKEN)
    _, done = _helper(laptop, "h-laptop", os_name="Darwin")
    assert done.returncode == 0 and json.loads(done.stdout) == {"Authorization": f"Bearer {TOKEN}"}


@pytest.mark.parametrize("args, kept, says", [
    ([], None, "usage"),
    (["../x"], None, "is not a token's name"),
    (["h-laptop"], None, "no token file"),
    (["h-laptop"], "not a token at all\n", "is not a nervus token"),
    (["h-laptop"], "short\n", "is not a nervus token"),
])
def test_the_helper_refuses_what_is_not_a_token_and_prints_nothing(laptop, args, kept, says):
    folder = laptop.w / "installed"
    folder.mkdir()
    if kept is not None:
        (folder / "token-h-laptop").write_text(kept)
    _, done = _helper(laptop, *args)
    assert done.returncode != 0 and says in done.stderr and done.stdout == ""


# --- the Windows script, parsed where PowerShell is here --------------------------------------

def _windows(client="claude-code"):
    return laptop_powershell(origin=ORIGIN, host=HOST, url=URL + "/windows", pin=PIN, root_pem=ROOT,
                             token_id="laptop", client=client)


def test_the_windows_script_is_ascii_and_one_block_closed_on_its_last_line():
    text = _windows()
    assert text.isascii() and text.rstrip().endswith("}")
    assert "\n& {\n$nervusOrigin = " in text
    assert all(line.startswith("#") or not line for line in text.split("\n& {\n")[0].splitlines())
    assert (TARGET / "nervus-headers.ps1").read_text().rstrip() in text


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="no PowerShell here")
@pytest.mark.parametrize("client", ["claude-code", "codex", "other"])
def test_the_windows_script_and_its_helper_parse_and_any_cut_does_not(tmp_path, client):
    text = _windows(client)
    (tmp_path / "laptop.ps1").write_text(text)
    last = text.rindex("}")
    cuts = sorted(set(range(text.index("\n& {\n"), text.index("function Invoke-NervusLaptop") + 30))
                  | set(range(0, last, 89)) | set(range(max(0, last - 120), last)))
    (tmp_path / "cuts").write_text("\n".join(map(str, cuts)))
    check = tmp_path / "check.ps1"
    check.write_text(r'''param([string]$Path, [string]$Cuts, [string]$Helper)
$text = [IO.File]::ReadAllText($Path)
$errors = $null
$null = [System.Management.Automation.Language.Parser]::ParseInput($text, [ref]$null, [ref]$errors)
"whole: $($errors.Count)"
$errors = $null
$null = [System.Management.Automation.Language.Parser]::ParseFile($Helper, [ref]$null, [ref]$errors)
"helper: $($errors.Count)"
$clean = foreach ($at in [IO.File]::ReadAllLines($Cuts)) {
    $errors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseInput($text.Substring(0, [int]$at), [ref]$null, [ref]$errors)
    if ($errors.Count -eq 0) { $at }
}
"parsed without error: $(@($clean) -join ',')"
''')
    done = subprocess.run(["pwsh", "-NoProfile", "-NonInteractive", "-File", str(check), str(tmp_path / "laptop.ps1"),
                           str(tmp_path / "cuts"), str(TARGET / "nervus-headers.ps1")],
                          capture_output=True, text=True, timeout=300)
    assert done.returncode == 0, done.stderr
    lines = done.stdout.splitlines()
    assert lines[:2] == ["whole: 0", "helper: 0"]
    # A cut in the opening comment parses, and holds nothing but comments; any cut inside the block does not.
    clean = [int(at) for at in lines[2].split(": ", 1)[1].split(",") if at]
    assert all(at <= text.index("\n& {\n") + 1 for at in clean), clean


# --- the line itself, run with the real curl against nervus's route over HTTPS ------------------

@pytest.fixture
def nervus_over_https(tmp_path):
    """The laptop route served over HTTPS with a certificate of nervus's own authority, as nervus serves
    it, on 127.0.0.1; its key's pin and its root as nervus gives them."""
    import socket
    import threading
    import time

    import uvicorn
    from cryptography import x509
    from starlette.applications import Starlette
    from starlette.routing import Route

    from nervus.audit import AuditLog
    from nervus.database import Database
    from nervus.laptop import LaptopRoute, laptop_endpoints
    from nervus.tls import generate_own_authority, key_pin, root_cert_path
    from nervus.token_codes import TokenCodes

    cert, key = tmp_path / "tls" / "tls.crt", tmp_path / "tls" / "tls.key"
    cert.parent.mkdir()
    generate_own_authority(cert, key, ["127.0.0.1", "nervus.test"])
    pin = key_pin(x509.load_pem_x509_certificate(cert.read_bytes()).public_key())
    root = root_cert_path(cert).read_text()
    db = Database(tmp_path / "nervus.db")
    db.open()
    codes = TokenCodes(db)
    sh, windows = laptop_endpoints(LaptopRoute(codes, AuditLog(path=tmp_path / "audit.jsonl"), pin=lambda: pin,
                                               root=lambda: root))
    app = Starlette(routes=[Route("/laptop/{code}", sh, methods=["GET", "POST"]),
                            Route("/laptop/{code}/windows", windows, methods=["GET"]),
                            Route("/", lambda request: __import__("starlette.responses").responses.PlainTextResponse(
                                "", status_code=404))])
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error",
                                           ssl_certfile=str(cert), ssl_keyfile=str(key)))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(300):
        if server.started:
            break
        time.sleep(0.01)
    yield type("Served", (), {"db": db, "codes": codes, "pin": pin, "root": root, "port": port})
    server.should_exit = True
    thread.join(timeout=10)


def _real_line(tmp_path, pin, url):
    """The line as the page gives it, run by a real shell with the real curl, the person's home in tmp_path,
    and the keychain stood in for, so this computer's own is never touched."""
    from nervus.laptop import laptop_line

    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    stand_in = tmp_path / "security"
    stand_in.write_text(SECURITY.format(python=sys.executable))
    stand_in.chmod(0o755)
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(home), "W": str(tmp_path), "LANG": "C",
           "NERVUS_SECURITY_BIN": str(stand_in)}
    done = subprocess.run([SH, "-c", laptop_line(url, pin)], capture_output=True, text=True, env=env, timeout=60)
    return home, env, done


@pytest.mark.skipif(shutil.which("curl") is None, reason="curl is not installed")
def test_the_line_run_with_the_real_curl_sets_the_computer_up_and_its_helper_gives_the_token(nervus_over_https,
                                                                                             tmp_path):
    from nervus.laptop import laptop_url

    served = nervus_over_https
    code, _ = served.codes.issue("laptop", "claude-code", "claude-code", "p", ["node-a"])
    home, env, done = _real_line(tmp_path, served.pin, laptop_url("127.0.0.1", served.port, code))
    assert done.returncode == 0, done.stdout + done.stderr
    folder = home / ".config" / "nervus"
    assert (folder / "root-127.0.0.1.pem").read_text().strip() == served.root.strip()
    # What the helper gives the client is the token nervus now knows, whichever place this computer keeps it in.
    header = subprocess.run([SH, str(folder / "nervus-headers"), "127.0.0.1-laptop"], capture_output=True,
                            text=True, env=env, timeout=30)
    assert header.returncode == 0, header.stderr
    value = json.loads(header.stdout)["Authorization"].removeprefix("Bearer ")
    assert served.db.token(value).id == "laptop"
    assert value not in done.stdout + done.stderr
    # Run again, the line is refused, its code used, and changes nothing.
    again = subprocess.run([SH, "-c", f"curl -fsSk --pinnedpubkey '{served.pin}' "
                                      f"'{laptop_url('127.0.0.1', served.port, code)}' | sh"],
                           capture_output=True, text=True, env=env, timeout=60)
    assert "404" in again.stderr and "nervus:" not in again.stdout


@pytest.mark.skipif(shutil.which("curl") is None, reason="curl is not installed")
def test_a_line_pinned_to_another_key_is_refused_by_curl_and_runs_nothing(nervus_over_https, tmp_path):
    # ADR-0032 verification 5: the line refuses a server whose key is not nervus's.
    from nervus.laptop import laptop_url

    served = nervus_over_https
    code, _ = served.codes.issue("laptop", "codex", "codex", "p", ["node-a"])
    other = "sha256//" + "A" * 43 + "="
    home, _, done = _real_line(tmp_path, other, laptop_url("127.0.0.1", served.port, code))
    assert "public key does not match pinned public key" in done.stderr or "(90)" in done.stderr, done.stderr
    assert not (home / ".config").exists() and served.codes.find(code) is not None


# --- the Windows script, run where PowerShell is here, nervus stood in for by a curl.exe function ------------

def _windows_argv(line: str) -> list[str]:
    """A command line split as a Windows program's C runtime splits it (CommandLineToArgvW's rules): what
    claude.exe is given when PowerShell passes the rest of a line after --% exactly as written."""
    args, current, i, quoted, started = [], [], 0, False, False
    while i < len(line):
        c = line[i]
        if c == "\\":
            n = 0
            while i < len(line) and line[i] == "\\":
                n, i = n + 1, i + 1
            if i < len(line) and line[i] == '"':
                current.append("\\" * (n // 2))
                if n % 2:
                    current.append('"')
                    i += 1
                started = True
            else:
                current.append("\\" * n)
                started = True
            continue
        if c == '"':
            quoted, started, i = not quoted, True, i + 1
            continue
        if c in " \t" and not quoted:
            if started:
                args.append("".join(current))
                current, started = [], False
            i += 1
            continue
        current.append(c)
        started, i = True, i + 1
    if started:
        args.append("".join(current))
    return args


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="no PowerShell here")
@pytest.mark.parametrize("client", ["claude-code", "codex"])
def test_the_windows_script_runs_its_steps_and_prints_commands_that_parse(tmp_path, client):
    home = tmp_path / "home"
    home.mkdir()
    (tmp_path / "laptop.ps1").write_text(_windows(client))
    (tmp_path / "send").write_text(TOKEN)
    harness = tmp_path / "harness.ps1"
    harness.write_text(r'''param([string]$Script, [string]$Log, [string]$Send)
function curl.exe {
    Add-Content -Path $Log -Value ($args -join ' ')
    $global:LASTEXITCODE = 0
    if ($args -contains 'POST') { [IO.File]::ReadAllText($Send); ''; '200'; return }
    if ($args -contains '--cacert') { return }
    if ($args -contains 'NUL') { '200'; return }
    $global:LASTEXITCODE = 2
}
iex ([IO.File]::ReadAllText($Script))
''')
    done = subprocess.run(["pwsh", "-NoProfile", "-NonInteractive", "-File", str(harness), str(tmp_path / "laptop.ps1"),
                           str(tmp_path / "curl.log"), str(tmp_path / "send")], capture_output=True, text=True,
                          env={**os.environ, "HOME": str(home)}, timeout=120)
    out = done.stdout + done.stderr
    assert done.returncode == 0 and "nervus: kept the token laptop in" in out, out
    assert TOKEN not in out and TOKEN not in (tmp_path / "curl.log").read_text()
    folder = home / ".config" / "nervus"  # PowerShell reads .config\nervus as a folder in a folder here too
    assert (folder / f"root-{HOST}.pem").read_text().strip() == ROOT
    assert ROOT in (folder / "roots.pem").read_text()
    assert (folder / "nervus-headers.ps1").read_text().strip() == (TARGET / "nervus-headers.ps1").read_text().strip()
    kept = (folder / f"token-{HOST}-laptop").read_text()
    assert TOKEN not in kept and kept.strip()
    calls = (tmp_path / "curl.log").read_text().splitlines()
    assert calls[0] == f"-sSk --pinnedpubkey {PIN} -o NUL -w %{{http_code}} {URL}/windows"
    assert "--ssl-no-revoke --cacert" in calls[1] and calls[2].startswith(f"-sSk --pinnedpubkey {PIN} -X POST")
    if client == "claude-code":
        call = "& (Get-Command claude -CommandType Application)[0].Source --% "
        [line] = [l.strip() for l in done.stdout.splitlines() if l.strip().startswith(call)]
        argv = _windows_argv(line[len(call):])
        assert argv[:5] == ["mcp", "add-json", "--scope", "user", "nervus"]
        given = json.loads(argv[5])
        assert given["url"] == f"{ORIGIN}/mcp" and given["type"] == "http"
        assert given["headersHelper"] == (f'powershell -NoProfile -ExecutionPolicy Bypass -File '
                                          f'"{str(folder).replace(chr(92), "/")}/nervus-headers.ps1" {HOST}-laptop')
    else:
        [line] = [l.strip() for l in done.stdout.splitlines() if "[IO.File]::AppendAllText(" in l]
        toml_text = re.search(r'AppendAllText\(\'[^\']*\', "(.*)"\)$', line).group(1)
        toml_text = toml_text.replace('""', '"').replace("`r", "\r").replace("`n", "\n")
        import tomllib
        server = tomllib.loads(toml_text)["mcp_servers"]["nervus"]
        assert server["url"] == f"{ORIGIN}/mcp" and server["http_headers_helper"].endswith(f'" {HOST}-laptop')
        assert "[Environment]::SetEnvironmentVariable('CODEX_CA_CERTIFICATE'" in done.stdout
