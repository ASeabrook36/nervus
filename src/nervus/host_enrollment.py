"""Enrolling a machine with two lines run on it as root (ADR-0024 decision 2).

The owner fetches the enrollment script from nervus with a one-time code,
over HTTPS pinned to nervus's own key, reads it, and runs it. The script
makes the account `agent` and its restrictions for the level the owner chose,
gives it exactly nervus's key, and sends the machine's host keys and machine
id back to nervus with the same code.

This file holds the script, written for one code, and the route that serves
it and takes the report back.

What the script holds to:
- **It does only what its opening comment says**, which names this
  machine's level and nothing else, for the owner reading it with `less`.
- **nervus's key goes in last.** A script that stops partway leaves an
  account nervus cannot log in to, never one with more than the level.
- **Read-only:** bubblewrap installed if missing; nervus's read-only shell,
  carried inside the script, at `/usr/local/lib/nervus/readonly-shell`,
  root-owned; tried as `agent` before the key is written, so a machine where
  bwrap cannot run is refused here, saying to choose standard (decision 1).
- **Where AppArmor keeps programs from making user namespaces** (Ubuntu 24.04
  and later), and bwrap cannot start as installed, read-only gives nervus its
  own copy of bubblewrap, which only `agent` may run, an AppArmor profile that
  lets it make them, and an apt hook that keeps the copy the system's; then
  tries the shell again (question 9). The three are read-only's alone: the
  script takes them off first at every level, and again if nervus refuses.
- **Standard and read-only remove any sudoers line an earlier enrollment
  left; full writes one, checked by `visudo`** before it is put in place.
- **Full refuses the machine nervus runs on before it changes anything**
  (decision 6). nervus puts in it a hash of the code and its own machine
  id, never the id, and the script compares its own.
- **What nervus does not accept is taken back**: if nervus refuses the
  report, or cannot be reached, the script takes nervus's key off `agent`
  again, and at full its sudoers line; the account stays, with no key.
- **A spent or expired code changes nothing**: the script asks nervus
  whether its code is still good before it touches anything, so a copy
  left in the folder by an earlier fetch stops at once (procedure 037).
- **tmux is installed for nervus's background jobs** at every level
  (decision 7, as amended after procedure 037).
- **Only nervus is told**: the report goes to the URL the script came from,
  pinned to the same key; curl's `-k` drops only its check against the
  machine's own trusted authorities, which do not know nervus's private one,
  and the pin is still checked (curl's documentation, and the route's tests).

What the route holds to:
- **Only over HTTPS, and not in lockdown.** Over plain HTTP there is no key to
  pin, so it serves nothing and keeps the code; an unreadable switches file
  is a lock, as it is for clients.
- **A report is accepted once.** The code is spent before anything is
  checked, so a refused machine needs a new code, and two reports at once
  enroll one machine.
- **Never full access to the machine nervus runs on** (decision 6), judged by
  the machine id it reports, before nervus logs in; if nervus cannot read
  its own, full is refused everywhere.
- **The keys pinned are the ones the machine sent**, and nervus logs in with
  only them: a server at that address with other keys is refused.
- **A code made from nervus's page enrolls only a machine that reports the
  key that answered its login** (ADR-0026 question 2): if that key is not
  among the host keys the machine itself sent, the report is refused before
  any SSH, saying the password may have been seen. The refusal reaches the
  script as a status that is not 200, so it takes nervus's key off as for any
  refusal.
- **The machine must be its level**, seen over SSH as agent: sudo gives root
  only at full, and a write to agent's home fails only at read-only.
- **A code made without an address enrolls the machine at the one its
  report came from** (decision 4a); one made with an address, at that.
- **Every fetch and report is audited** under the code's id, never the code
  (ADR-0012 decision 6); without the audit log nothing happens.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import shlex
from collections.abc import Callable, Iterable
from pathlib import Path

import asyncssh
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response

from nervus import certs
from nervus.audit import AuditError
from nervus.enrolled_hosts import LEVELS, MACHINE_ID, HostRefused
from nervus.enroller import CHECK_SECONDS, Connect
from nervus.enrollments import EnrollmentRefused, host_keys as pinned_keys

READONLY_SHELL = Path(__file__).resolve().parent / "target" / "readonly-shell"
READONLY_SHELL_PATH = "/usr/local/lib/nervus/readonly-shell"
_END = "NERVUS_READONLY_SHELL"

BWRAP_COPY_PATH = "/usr/local/lib/nervus/bwrap"
APPARMOR_PROFILE_PATH = "/etc/apparmor.d/nervus-bwrap"
APT_HOOK_PATH = "/etc/apt/apt.conf.d/99nervus-bwrap"

# Read-only's alone (question 9): taken off first at every level, so the opening
# comment of every level says so.
_TAKEN_OFF = (
    f"#      Takes off nervus's copy of bwrap ({BWRAP_COPY_PATH}), its AppArmor\n"
    f"#      profile and its apt hook, if an earlier read-only enrollment left them.\n"
)

_WHAT = {
    "read-only": (
        "#   2. installs bubblewrap if it is missing, and puts nervus's read-only shell at\n"
        f"#      {READONLY_SHELL_PATH}. Every command nervus runs here goes through it:\n"
        "#      every file read-only except agent's own ~/.nervus, enforced by the kernel.\n"
        "#      Where this machine's AppArmor keeps programs from making user namespaces,\n"
        "#      as Ubuntu's does since 24.04, so bubblewrap cannot start as installed: a\n"
        f"#      copy of it that only agent may run, {BWRAP_COPY_PATH}, an AppArmor\n"
        f"#      profile letting that copy alone make them, {APPARMOR_PROFILE_PATH},\n"
        f"#      and an apt hook keeping the copy the system's, {APT_HOOK_PATH};\n"
        "#      any of the three an earlier enrollment left are taken off first.\n"
        "#      Removes /etc/sudoers.d/nervus-agent, if an earlier enrollment left one.\n"
    ),
    "standard": (
        "#   2. removes /etc/sudoers.d/nervus-agent, if an earlier enrollment left one:\n"
        "#      agent can change only what it owns.\n" + _TAKEN_OFF
    ),
    "full": (
        "#   2. installs sudo if it is missing, and lets agent use it without a password\n"
        "#      (/etc/sudoers.d/nervus-agent, checked by visudo): agent can do anything here.\n"
        "#      Before anything, it refuses if this is the machine nervus runs on.\n" + _TAKEN_OFF
    ),
}

_HEAD = """#!/bin/sh
# nervus: enroll this machine as {name}, {level}.
#
# nervus, at {origin}, wrote this for the machine you added in its web page.
# Run it as root. It does exactly this, and nothing else:
#   1. makes the account agent, if there is none, with no password, and installs
#      tmux for nervus's background jobs, if it is missing;
{what}#   3. makes agent trust nervus's certificate authority, and no other key;
#   4. sends this machine's SSH host keys and its machine id back to nervus over
#      the same pinned connection, so nervus knows it is talking to this machine.
# nervus then logs in as agent, checks the level, and only then adds the machine.
# If nervus does not add the machine, the script takes that trust off again.
# Once enrolled, nervus's page shows the commands that take all of this off again.

set -u
name={q_name} level={q_level}
url={q_url}
pin={q_pin}
key={q_key}
own={q_own}
"""

_BODY = r'''root=${NERVUS_ENROLL_ROOT:-}  # set only by nervus's own tests
umask 022
fail() { echo "nervus enrollment: $*" >&2; exit 1; }
say() { echo "nervus enrollment: $*"; }

[ "$(id -u)" = 0 ] || fail "run this as root: in a root shell, or with sudo sh nervus-enroll.sh"
[ -x "$root/usr/sbin/sshd" ] || fail "this machine has no SSH server: install openssh-server, then run this again"
command -v curl >/dev/null 2>&1 || fail "curl is not installed"

# This machine's id, sent to nervus; at full, checked first against the hash
# of nervus's own with this code ($own), before anything here changes.
machine_id=$(cat "$root/etc/machine-id" 2>/dev/null || cat "$root/var/lib/dbus/machine-id" 2>/dev/null)
[ -n "$machine_id" ] || fail "this machine has no machine id (/etc/machine-id)"
if [ "$level" = full ]; then
  command -v sha256sum >/dev/null 2>&1 || fail "there is no sha256sum to check this is not nervus's own machine"
  mine=$(printf '%s:%s' "${url##*/}" "$machine_id" | sha256sum | cut -d' ' -f1)
  if [ "$mine" = "$own" ]; then
    fail "this is the machine nervus runs on, and nervus never holds root there. In nervus's page, add it as standard or read-only instead. Nothing here was changed."
  fi
fi

# Installs package $2 if command $1 is missing, with apt-get, or says what to install.
need() {
  command -v "$1" >/dev/null 2>&1 && return 0
  command -v apt-get >/dev/null 2>&1 || fail "$1 is missing and there is no apt-get here: install $2, then run this again"
  say "installing $2"
  DEBIAN_FRONTEND=noninteractive apt-get update -q >/dev/null \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$2" >/dev/null \
    || fail "apt-get could not install $2"
  command -v "$1" >/dev/null 2>&1 || fail "$2 is installed but there is still no $1"
}

# Is this script's code still good? One left in the folder by an earlier
# fetch carries a spent code: it stops here, before changing anything.
first=$(curl -sSk --pinnedpubkey "$pin" -o /dev/null -w '%{http_code}' "$url") \
  || fail "could not reach nervus at $url. Nothing here was changed."
[ "$first" = 200 ] || fail "this script's code is used or expired (nervus answered $first): make new lines in nervus's page. Nothing here was changed."

# 1. The account, and tmux for nervus's background jobs.
if ! getent passwd agent >/dev/null 2>&1; then
  command -v useradd >/dev/null 2>&1 || fail "there is no useradd to make the account agent"
  useradd -m -s /bin/sh agent || fail "useradd could not make the account agent"
  say "made the account agent"
fi
home=$(getent passwd agent | cut -d: -f6)
[ -n "$home" ] && [ -d "$home" ] || fail "the account agent has no home folder"
need tmux tmux

# 2. The level.
sudoers=$root/etc/sudoers.d
lib=$root/usr/local/lib/nervus
copy=$lib/bwrap apparmor=$root/etc/apparmor.d/nervus-bwrap hook=$root/etc/apt/apt.conf.d/99nervus-bwrap
# nervus's copy of bubblewrap, its AppArmor profile and its apt hook (question 9)
# are read-only's alone, where every command agent runs is inside the sandbox:
# taken off first at every level, and again if nervus does not add the machine.
unbwrap() {
  if [ -e "$apparmor" ] && command -v apparmor_parser >/dev/null 2>&1; then
    apparmor_parser -R "$apparmor" >/dev/null 2>&1
  fi
  rm -f "$copy" "$apparmor" "$hook"
}
if [ -e "$copy" ] || [ -e "$apparmor" ] || [ -e "$hook" ]; then
  unbwrap
  [ -e "$copy" ] || [ -e "$apparmor" ] || [ -e "$hook" ] \
    && fail "cannot take off nervus's copy of bwrap, its AppArmor profile or its apt hook"
  say "took off nervus's copy of bwrap, its AppArmor profile and its apt hook, which an earlier enrollment left"
fi
if [ "$level" = full ]; then
  need sudo sudo
  command -v visudo >/dev/null 2>&1 || fail "sudo is installed but there is no visudo"
  [ -d "$sudoers" ] || fail "there is no $sudoers"
  tmp=$sudoers/.nervus-agent
  rm -f "$tmp"
  printf 'agent ALL=(ALL) NOPASSWD: ALL\n' > "$tmp" && chmod 440 "$tmp" \
    || { rm -f "$tmp"; fail "cannot write the sudoers line"; }
  visudo -cqf "$tmp" || { rm -f "$tmp"; fail "visudo refused the sudoers line"; }
  mv -f "$tmp" "$sudoers/nervus-agent" || { rm -f "$tmp"; fail "cannot put the sudoers line in place"; }
  say "agent may use sudo"
else
  if [ -e "$sudoers/nervus-agent" ]; then
    rm -f "$sudoers/nervus-agent" || fail "cannot remove $sudoers/nervus-agent"
    say "removed agent's sudoers line"
  fi
fi
if [ "$level" = read-only ]; then
  need bwrap bubblewrap
  mkdir -p "$lib" && chown root:root "$lib" && chmod 755 "$lib" || fail "cannot make $lib"
  tmp=$lib/.readonly-shell
  rm -f "$tmp"
  cat > "$tmp" <<'NERVUS_READONLY_SHELL' || { rm -f "$tmp"; fail "cannot write the read-only shell"; }
{readonly_shell}NERVUS_READONLY_SHELL
  chown root:root "$tmp" && chmod 755 "$tmp" && mv -f "$tmp" "$lib/readonly-shell" \
    || { rm -f "$tmp"; fail "cannot put the read-only shell in place"; }
  # The shell as nervus will meet it: as agent, inside bubblewrap.
  if ! tried=$(su -s /bin/sh -c "SSH_ORIGINAL_COMMAND=true $lib/readonly-shell" agent 2>&1); then
    # Where AppArmor keeps programs from making user namespaces (question 9):
    # a copy of bubblewrap only agent may run, a profile letting that copy alone
    # make them, and an apt hook keeping the copy the system's. Then again.
    restricted=$(cat "$root/proc/sys/kernel/apparmor_restrict_unprivileged_userns" 2>/dev/null)
    [ "$restricted" = 1 ] && command -v apparmor_parser >/dev/null 2>&1 && [ -d "$root/etc/apparmor.d" ] \
      || fail "bubblewrap cannot run here, so this machine cannot be read-only ($tried). In nervus's page, add it as standard instead."
    say "this machine's AppArmor keeps programs from making user namespaces: giving nervus's own copy of bwrap, which only agent may run, a profile that lets it"
    system=$(command -v bwrap)
    tmp=$lib/.bwrap
    rm -f "$tmp"
    cp "$system" "$tmp" && chown root:agent "$tmp" && chmod 750 "$tmp" && mv -f "$tmp" "$copy" \
      || { rm -f "$tmp"; fail "cannot make nervus's copy of bwrap"; }
    cat > "$apparmor" <<'NERVUS_APPARMOR' || { unbwrap; fail "cannot write nervus's AppArmor profile"; }
# nervus (ADR-0024 question 9): nervus's own copy of bubblewrap, which only the
# account agent may run, may make user namespaces, for nervus's read-only shell,
# which runs it with --disable-userns. Nothing else here is changed. Taken off
# when the machine is enrolled at another level, or removed.
abi <abi/4.0>,
include <tunables/global>

profile nervus-bwrap /usr/local/lib/nervus/bwrap flags=(unconfined) {
  userns,
}
NERVUS_APPARMOR
    loaded=$(apparmor_parser -r "$apparmor" 2>&1) \
      || { unbwrap; fail "AppArmor would not load nervus's profile for its copy of bwrap ($loaded). In nervus's page, add this machine as standard instead."; }
    if [ -d "$root/etc/apt/apt.conf.d" ]; then
      cat > "$hook" <<NERVUS_APT_HOOK || { unbwrap; fail "cannot write nervus's apt hook"; }
// nervus (ADR-0024 question 9): after apt changes packages, nervus's copy of
// bubblewrap is made the system's again, so it never lags bubblewrap's updates.
// Taken off when the machine is enrolled at another level, or removed.
DPkg::Post-Invoke { "if [ -e /usr/local/lib/nervus/bwrap ] && [ -x $system ] && ! cmp -s $system /usr/local/lib/nervus/bwrap; then cp $system /usr/local/lib/nervus/.bwrap && chown root:agent /usr/local/lib/nervus/.bwrap && chmod 750 /usr/local/lib/nervus/.bwrap && mv -f /usr/local/lib/nervus/.bwrap /usr/local/lib/nervus/bwrap; fi; true"; };
NERVUS_APT_HOOK
    fi
    if ! tried=$(su -s /bin/sh -c "SSH_ORIGINAL_COMMAND=true $lib/readonly-shell" agent 2>&1); then
      unbwrap
      fail "bubblewrap cannot run here, even as nervus's own copy with its AppArmor profile, so this machine cannot be read-only ($tried). In nervus's page, add it as standard instead."
    fi
  fi
  line="cert-authority,restrict,command=\"/usr/local/lib/nervus/readonly-shell\" $key"
else
  line="cert-authority $key"
fi

# 3. nervus's certificate authority, and no other key. agent writes it itself. Its home is its
# own, and where agent has no sudo, anything root did there by path -- a write, a chown, a
# rename -- could be turned onto a file elsewhere by a link agent swaps in at the right instant
# (procedure 056, C32, whose first fix closed only a link planted beforehand; procedure 058).
# As agent, a link reaches only what agent could reach already. The line is no secret, so root
# leaves it where agent can read it.
[ -L "$home/.ssh" ] && fail "$home/.ssh is a symbolic link; remove it, then run this again"
command -v su >/dev/null 2>&1 || fail "this machine has no su, which this uses to write agent's key as agent"
# In /tmp itself, whatever root's TMPDIR: agent must be able to read it.
line_file=$(mktemp /tmp/nervus-enroll.XXXXXX) || fail "cannot make a temporary file"
printf '%s\n' "$line" > "$line_file" && chmod 644 "$line_file" \
  || { rm -f "$line_file"; fail "cannot write agent's authorized_keys"; }
su -s /bin/sh -c "umask 077; mkdir -p '$home/.ssh' && chmod 700 '$home/.ssh' && rm -f '$home/.ssh/.authorized_keys.nervus' && cat '$line_file' > '$home/.ssh/.authorized_keys.nervus' && mv -f '$home/.ssh/.authorized_keys.nervus' '$home/.ssh/authorized_keys'" agent \
  || { rm -f "$line_file"; fail "agent could not write its authorized_keys in $home/.ssh"; }
rm -f "$line_file"
say "agent trusts nervus's certificate authority"

# 4. The host keys and machine id, back to nervus.
if command -v systemctl >/dev/null 2>&1; then
  systemctl is-active --quiet ssh || systemctl is-active --quiet sshd \
    || systemctl start ssh 2>/dev/null || systemctl start sshd 2>/dev/null \
    || fail "cannot start the SSH server"
fi
ls "$root"/etc/ssh/ssh_host_*_key.pub >/dev/null 2>&1 || fail "the SSH server has no host keys in /etc/ssh"
report=$(mktemp) && answer=$(mktemp) || fail "cannot make a temporary file"
trap 'rm -f "$report" "$answer"' EXIT
{ echo "machine-id $machine_id"; cat "$root"/etc/ssh/ssh_host_*_key.pub; } > "$report"
# What nervus does not accept is taken back: its key, and at full its sudoers line.
undo() {
  su -s /bin/sh -c "rm -f '$home/.ssh/authorized_keys'" agent
  what="its key is taken off agent again"
  if [ "$level" = full ]; then rm -f "$sudoers/nervus-agent"; what="$what, and agent's sudoers line removed"; fi
  if [ -e "$copy" ]; then unbwrap; what="$what, and nervus's copy of bwrap with its AppArmor profile"; fi
  echo "nervus enrollment: nervus did not add this machine, so $what" >&2
}
say "asking nervus to check and add this machine"
if ! status=$(curl -sSk --pinnedpubkey "$pin" -H 'Content-Type: text/plain' --data-binary "@$report" \
  -o "$answer" -w '%{http_code}' "$url"); then
  undo
  fail "could not reach nervus at $url"
fi
cat "$answer"
[ "$status" = 200 ] || { undo; exit 1; }
'''


def own_hash(code: str, machine_id: str) -> str:
    """What a full script compares its own machine id with: nervus's, hashed
    with the code, so the script never holds nervus's id (decision 6)."""
    return hashlib.sha256(f"{code}:{machine_id}".encode()).hexdigest()


def enroll_script(*, name: str, level: str, origin: str, url: str, pin: str, key: str,
                  own_hash: str | None = None, readonly_shell: str | None = None) -> str:
    """The enrollment script for one code: machine `name` at `level`, its
    report sent to `url`, whose last part is the code, pinned to `pin`
    (`sha256//<base64>`), giving `agent` nervus's public `key`. `origin`
    names nervus in the opening comment. A full script, and only a full one,
    takes `own_hash`, from own_hash()."""
    if level not in LEVELS:
        raise ValueError(f"not a level: {level!r}")
    if (level == "full") != bool(own_hash) or (own_hash and not re.fullmatch(r"[0-9a-f]{64}", own_hash)):
        raise ValueError("a full script, and only a full one, takes nervus's machine id hashed with the code")
    if any(c in text for text in (name, origin, url, pin, key) for c in "\r\n\0"):
        raise ValueError("a value for the script holds a line break")
    shell = READONLY_SHELL.read_text() if readonly_shell is None else readonly_shell
    if not shell.endswith("\n") or _END in shell.splitlines():
        raise ValueError("the read-only shell cannot be carried in the script as it is")
    head = _HEAD.format(name=name, level=level, origin=origin, what=_WHAT[level],
                        q_name=shlex.quote(name), q_level=shlex.quote(level), q_url=shlex.quote(url),
                        q_pin=shlex.quote(pin), q_key=shlex.quote(key), q_own=shlex.quote(own_hash or ""))
    return head + _BODY.replace("{readonly_shell}", shell)


# What the owner runs as root to take nervus off a machine once it is
# forgotten (decision 5a): its processes, the account with its home and key,
# its sudoers line, nervus's AppArmor profile and apt hook (question 9), and
# the read-only shell with the copy of bwrap. Shown in the UI; tested as written.
REMOVE_COMMANDS = f"""pkill -KILL -u agent; sleep 1
userdel -r agent
rm -f /etc/sudoers.d/nervus-agent
apparmor_parser -R {APPARMOR_PROFILE_PATH} 2>/dev/null; rm -f {APPARMOR_PROFILE_PATH} {APT_HOOK_PATH}
rm -rf /usr/local/lib/nervus
"""


def enroll_url(host: str, port: int, code: str) -> str:
    """Where a machine fetches its script: nervus's MCP port at `host`."""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"  # an IPv6 address
    return f"https://{host}:{port}/enroll/{code}"


def enroll_lines(url: str, pin: str) -> str:
    """The two lines the owner runs as root on the machine (decision 2a): the
    first fetches the script, checked against nervus's key; the second shows
    it, then runs it."""
    return (f"curl -fsSk --pinnedpubkey {shlex.quote(pin)} -o nervus-enroll.sh {shlex.quote(url)}\n"
            "less nervus-enroll.sh && sh nervus-enroll.sh\n")


# --- The route: GET /enroll/<code> serves the script; POST takes the report --

TOOL = "enroll"
REPORT_BYTES = 64 * 1024
# What nervus asks, logged in as agent with the reported keys pinned: who it
# is, whether sudo gives root, and whether it can write in its own home.
CHECK = ('id -un; if sudo -n id -un 2>/dev/null; then :; else echo no-sudo; fi; '
         'if (: > "$HOME/.nervus-enroll-check") 2>/dev/null; then rm -f "$HOME/.nervus-enroll-check"; '
         'echo writes; else echo no-writes; fi')
EXPECTED = {
    "read-only": ["agent", "no-sudo", "no-writes"],
    "standard": ["agent", "no-sudo", "writes"],
    "full": ["agent", "root", "writes"],
}
FULL_UNKNOWN = ("nervus cannot read its own machine id, so it cannot tell whether this is the machine it runs on; "
                "full access is refused. Add it as standard or read-only.")
HTTPS_ONLY = ("this nervus serves plain HTTP, and enrollment needs HTTPS: the machine checks nervus's key "
              "before it runs anything nervus sends. Serve MCP over HTTPS (docs/install.md), then make a new code.")
UNKNOWN = "this enrollment code is unknown, used or expired; make a new one in nervus's page"
NOT_ITS_OWN = ("the key that answered nervus's login at {address} is not one of this machine's own "
               "host keys, so something between nervus and the machine may have answered instead and "
               "seen {login}'s password. nervus did not add the machine. Change that password, then add "
               "the machine with the two lines.")


class Refused(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def _report(body: str) -> tuple[str, list[str]]:
    """The machine id and the host key lines the script sent."""
    lines = [line.strip() for line in body.splitlines() if line.strip()]
    if not lines or not lines[0].startswith("machine-id "):
        raise Refused(400, "the report does not start with the machine id")
    return lines[0].split(" ", 1)[1].strip(), lines[1:]


def check_failed(level: str, seen: list[str]) -> str | None:
    """None if what the machine answered is this level; otherwise why not, in
    words for the machine's owner."""
    if seen == EXPECTED[level]:
        return None
    if not seen or seen[0] != "agent":
        return f"nervus logged in, but not as agent ({' '.join(seen)[:80]!r})"
    sudo = seen[1:2] == ["root"]
    if sudo and level != "full":
        return ("agent can still use sudo without a password: something other than nervus's sudoers line "
                "allows it, a group or another file in /etc/sudoers.d. Remove that, or add the machine as full.")
    if not sudo and level == "full":
        return "agent cannot use sudo without a password, so the machine is not full"
    if level == "read-only":
        return "agent can write outside ~/.nervus, so the read-only shell is not in force"
    return "agent cannot write in its own home folder"


class HostEnrollment:
    """The enrollment route's work. `key` is nervus's public key line for
    `agent`; `connect` opens SSH as agent trusting only the keys given; `pin`
    is nervus's serving key as curl pins it, None where MCP is plain HTTP;
    `own_machine_id` is nervus's machine's, None if unreadable; `reserved`
    the names hosts.yaml has. The callables are read at each request."""

    def __init__(self, codes, store, audit, *, key: Callable[[], str], connect: Connect,
                 pin: Callable[[], str | None], own_machine_id: str | None,
                 reserved: Callable[[], Iterable[str]], locked: Callable[[], bool] = lambda: False):
        self.codes, self.store, self.audit = codes, store, audit
        self.key, self.connect, self.pin = key, connect, pin
        self.own_machine_id, self.reserved, self.locked = own_machine_id, reserved, locked

    def _open(self, value: str, action: str, client: str):
        """The code and the run id of its intent record, or Refused."""
        fields = {"actor": "operator", "action": action, "from": client}
        if self.pin() is None:
            self.audit.record_refusal(TOOL, {**fields, "reason": "plain HTTP"})
            raise Refused(503, HTTPS_ONLY)
        if self.locked():
            self.audit.record_refusal(TOOL, {**fields, "reason": "lockdown"})
            raise Refused(503, "nervus is locked down, so it enrolls nothing; ask its operator")
        code = self.codes.find(value)
        if code is None:
            self.audit.record_refusal(TOOL, {**fields, "reason": "unknown, used or expired code"})
            raise Refused(404, UNKNOWN)
        run_id = self.audit.record_intent(TOOL, {**fields, "code_id": code.id, "name": code.name,
                                                 "address": code.address, "level": code.level})
        return code, run_id

    def script(self, value: str, url: str, origin: str, client: str) -> str:
        code, run_id = self._open(value, "fetch", client)
        own = None
        if code.level == "full":
            if self.own_machine_id is None:
                self.audit.record_result(run_id, TOOL, {"failure_message": FULL_UNKNOWN})
                raise Refused(403, FULL_UNKNOWN)
            own = own_hash(value, self.own_machine_id)
        text = enroll_script(name=code.name, level=code.level, origin=origin, url=url, pin=self.pin(),
                             key=self.key(), own_hash=own)
        self.audit.record_result(run_id, TOOL, {"served": True})
        return text

    async def report(self, value: str, body: str, client: str) -> str:
        code, run_id = self._open(value, "report", client)
        if self.codes.spend(value) is None:
            self.audit.record_result(run_id, TOOL, {"failure_code": "spent"})
            raise Refused(404, UNKNOWN)
        machine_id = None
        # nervus's check signs as the operator's, under this record (ADR-0025).
        certs.acting_for(None, run_id)
        try:
            machine_id, lines = _report(body)
            enrolled, replaced = await self._enroll(code, code.address or client, machine_id, lines)
        except Refused as exc:
            self.codes.finish(code.id, f"refused: {exc.message}")
            self.audit.record_result(run_id, TOOL, {"failure_message": exc.message, "machine_id": machine_id,
                                                    **certs.ssh_ports()})
            raise
        before = f" It was {replaced.level} before." if replaced and replaced.level != enrolled.level else ""
        self.codes.finish(code.id, f"enrolled {enrolled.name}, {enrolled.level}")
        self.audit.record_result(run_id, TOOL, {"enrolled": True, "machine_id": machine_id, "address": enrolled.address,
                                                "host_keys": list(enrolled.host_keys), "replaced": bool(replaced),
                                                **certs.ssh_ports()})
        return (f"nervus: {enrolled.name} is enrolled, {enrolled.level}.{before} In nervus's page, give a "
                f"token this machine to let a client use it.\n")

    async def _enroll(self, code, address: str, machine_id: str, lines: list[str]):
        if not MACHINE_ID.fullmatch(machine_id):
            raise Refused(400, f"{machine_id[:40]!r} is not a machine id")
        if code.level == "full":
            if self.own_machine_id is None:
                raise Refused(403, FULL_UNKNOWN)
            if machine_id == self.own_machine_id:
                raise Refused(403, "this is the machine nervus runs on, and nervus never holds root there "
                                   "(ADR-0023). Add it as standard or read-only.")
        try:
            keys = pinned_keys(lines)
        except EnrollmentRefused as exc:
            raise Refused(400, exc.message) from None
        made = self.codes.login_of(code.id)
        if made is not None and made.host_key not in keys:
            raise Refused(409, NOT_ITS_OWN.format(address=code.address, login=made.login))
        if not address:
            raise Refused(400, "nervus cannot tell which address this report came from; make a new code "
                               "and give the machine's address")
        why = await self._check(address, code.level, keys)
        if why is not None:
            raise Refused(422, f"nervus checked {address} and did not add it: {why}")
        try:
            return self.store.add(code.name, address=address, level=code.level, host_keys=keys,
                                  machine_id=machine_id, enrolled_by=code.made_by, reserved=self.reserved())
        except HostRefused as exc:
            raise Refused(409, exc.message) from None

    async def _check(self, address: str, level: str, keys: tuple[str, ...]) -> str | None:
        try:
            conn = await self.connect(address, keys)
        except asyncssh.HostKeyNotVerifiable:
            return f"the SSH server at {address} has other host keys than this machine sent: is {address} this machine?"
        except asyncssh.PermissionDenied:
            return f"the SSH server at {address} refused nervus's key"
        except (OSError, asyncio.TimeoutError, asyncssh.Error) as exc:
            return f"no SSH at {address} ({type(exc).__name__}: {str(exc)[:120]})"
        try:
            result = await conn.run(CHECK, check=False, timeout=CHECK_SECONDS)
        except (OSError, asyncio.TimeoutError, asyncssh.Error) as exc:
            return f"the check did not finish ({type(exc).__name__})"
        finally:
            conn.close()
        return check_failed(level, str(result.stdout or "").split())


def own_machine_id(paths=("/etc/machine-id", "/var/lib/dbus/machine-id")) -> str | None:
    """The machine id of the machine nervus runs on, or None if none can be
    read: then full access is refused everywhere (decision 6)."""
    for path in paths:
        try:
            found = Path(path).read_text().strip()
        except OSError:
            continue
        if MACHINE_ID.fullmatch(found):
            return found
    return None


def enroll_endpoint(enrollment: HostEnrollment):
    """GET and POST /enroll/{code}, beside /mcp (ADR-0024 decision 2). Every
    answer is plain text for the owner at the machine.

    Starlette answers HEAD on a route that takes GET, and a HEAD is a GET
    without its body: it is served as one, so it spends nothing. Taken for a
    report, as every request but a GET once was, a HEAD from a link preview or
    a checker spent the one-time code (procedure 056)."""

    async def endpoint(request: Request) -> Response:
        value = request.path_params["code"]
        client = request.client.host if request.client else ""
        try:
            if request.method in ("GET", "HEAD"):
                url = str(request.url.replace(query="", fragment=""))
                origin = f"{request.url.scheme}://{request.url.netloc}"
                return PlainTextResponse(enrollment.script(value, url, origin, client))
            body = bytearray()
            async for chunk in request.stream():
                body += chunk
                if len(body) > REPORT_BYTES:
                    return PlainTextResponse("nervus: the report is too large\n", status_code=413)
            return PlainTextResponse(await enrollment.report(value, body.decode("utf-8", "replace"), client))
        except Refused as exc:
            return PlainTextResponse(f"nervus: {exc.message}\n", status_code=exc.status)
        except AuditError:
            return PlainTextResponse("nervus: cannot write its audit log, so it does nothing\n", status_code=503)

    return endpoint
