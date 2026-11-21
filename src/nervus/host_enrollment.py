"""Enrolling a machine with two lines run on it as root (ADR-0024 decision 2).

The owner fetches the enrollment script from nervus with a one-time code,
over HTTPS pinned to nervus's own key, reads it, and runs it. The script
makes nervus's accounts and their restrictions for the level the owner chose,
gives each exactly nervus's line, and sends the machine's host keys and
machine id back to nervus with the same code.

Since ADR-0031 a machine has two accounts of nervus's, named on the form that
adds it, `nervusagent` and `nervusagent-readonly` by default (question 8): the
read-write one, at standard or full, and the read-only one, at every level,
kept read-only by nervus's read-only shell. Where the shell cannot start, a
machine at standard or full is added read-write alone, saying why (question 5).
nervus logs in as each, checks it, and records what it found
(nervus.accounts.MachineAccounts), tied to this enrollment. A machine
described by hand gains the read-only account alone (question 4).

This file holds the script, written for one code, and the route that serves
it and takes the report back.

What the script holds to:
- **It does only what its opening comment says**, which names this
  machine's level and nothing else, for the owner reading it with `less`.
- **nervus's key goes in last.** A script that stops partway leaves an
  account nervus cannot log in to, never one with more than the level: the
  read-only account's line after its shell is tried, the read-write one's last,
  and at full its sudoers line after that, though visudo checks it before any
  line. An account whose ~/.ssh is a link stops the script before anything
  changes (procedure 068, section 12).
- **An account already there is used as it is**, its groups said, and its own
  SSH keys replaced by nervus's line, which it says; never root or one of the
  machine's system accounts. An account nervus used there before loses
  nervus's line and its sudoers file, and only those, once nervus has added
  the machine: a re-add nervus refuses leaves it as it was (question 11).
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
  report, or cannot be reached, the script takes nervus's lines off its
  accounts again, and nothing else of them, and at full the sudoers line; the
  accounts stay, with no line of nervus's.
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

from nervus import accounts, certs
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

# ADR-0031: a machine described by hand gains a read-only account alone (question 4).
READONLY_ACCOUNT = accounts.READONLY_ACCOUNT_KIND

_TAKEN_OFF = (
    f"#      Takes off nervus's copy of bwrap ({BWRAP_COPY_PATH}), its AppArmor\n"
    f"#      profile and its apt hook first, if an earlier enrollment left them.\n"
)

_READONLY = (
    "#      The read-only account, {ro}: installs bubblewrap if it is missing, and puts\n"
    f"#      nervus's read-only shell at {READONLY_SHELL_PATH}. Every command nervus runs as\n"
    "#      {ro} goes through it: every file read-only except its own ~/.nervus,\n"
    "#      enforced by the kernel. Where this machine's AppArmor keeps programs from\n"
    "#      making user namespaces, as Ubuntu's does since 24.04: a copy of bubblewrap\n"
    f"#      that only {{ro}} may run, {BWRAP_COPY_PATH}, an AppArmor profile letting that\n"
    f"#      copy alone make them, {APPARMOR_PROFILE_PATH}, and an apt hook keeping the\n"
    f"#      copy the system's, {APT_HOOK_PATH}. The shell is tried as {{ro}} first.\n"
)

_WHAT = {
    "read-only": (
        "#   2. " + _READONLY[7:] +
        "#      Removes nervus's sudoers line for {ro}, if an earlier enrollment left one.\n" + _TAKEN_OFF
    ),
    "standard": (
        "#   2. {rw}, the read-write account, can change only what it owns: removes\n"
        "#      /etc/sudoers.d/nervus-{rw}, if an earlier enrollment left one.\n" + _READONLY +
        "#      Where bubblewrap cannot run here, the machine is added with {rw} alone,\n"
        "#      and this says why.\n" + _TAKEN_OFF
    ),
    "full": (
        "#   2. installs sudo if it is missing, and, once {rw}'s line is in (3), lets {rw}, the\n"
        "#      read-write account, use it without a password (/etc/sudoers.d/nervus-{rw},\n"
        "#      checked by visudo first): {rw} can do anything here. Before anything, it refuses\n"
        "#      if this is the machine nervus runs on.\n" + _READONLY +
        "#      Where bubblewrap cannot run here, the machine is added with {rw} alone,\n"
        "#      and this says why.\n" + _TAKEN_OFF
    ),
    READONLY_ACCOUNT: (
        "#   2. " + _READONLY[7:] + _TAKEN_OFF +
        "#      Nothing else here is changed: not the account this machine is described\n"
        "#      with in nervus, not sudo.\n"
    ),
}

_HEAD = """#!/bin/sh
# nervus: {doing}.
#
# nervus, at {origin}, wrote this for the machine you added in its web page.
# Run it as root. It does exactly this, and nothing else:
#   1. makes the account{plural} {accounts}, where missing, with no password, and installs
#      tmux for nervus's background jobs, if it is missing. An account already here is
#      used as it is, its groups said, and its SSH keys replaced by nervus's line alone;
{what}#   3. makes {trusting} trust nervus's certificate authority, and no other key;{off_line}
#   4. sends this machine's SSH host keys and its machine id back to nervus over
#      the same pinned connection, so nervus knows it is talking to this machine.
# nervus then logs in as each account, checks it, and only then adds the machine.
# If nervus does not add the machine, or this stops before it is done, it puts back
# everything it changed here as it was, and deletes the accounts it made; the packages
# it installed stay.
# Once enrolled, nervus's page shows the commands that take all of this off again.

set -u
name={q_name} level={q_level} kind={q_kind}
rw={q_rw} ro={q_ro} off={q_off}
url={q_url}
pin={q_pin}
key={q_key}
plainkey={q_plainkey}
own={q_own}
"""

_BODY = r"""root=${NERVUS_ENROLL_ROOT:-}  # set only by nervus's own tests
umask 022
# Once this has begun to change the machine, a stop puts back everything it changed, as nervus not adding
# the machine does (ADR-0031 question 12).
changing=
fail() { echo "nervus enrollment: $*" >&2; [ -z "$changing" ] || undo; exit 1; }
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
# As need, for what only the read-only account needs: where it cannot be had,
# says why in $why instead of stopping (ADR-0031 question 5).
want() {
  command -v "$1" >/dev/null 2>&1 && return 0
  command -v apt-get >/dev/null 2>&1 || { why="$1 is missing and there is no apt-get here to install $2"; return 1; }
  say "installing $2"
  DEBIAN_FRONTEND=noninteractive apt-get update -q >/dev/null \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$2" >/dev/null \
    || { why="apt-get could not install $2"; return 1; }
  command -v "$1" >/dev/null 2>&1 || { why="$2 is installed but there is still no $1"; return 1; }
}

# Is this script's code still good? One left in the folder by an earlier
# fetch carries a spent code: it stops here, before changing anything.
first=$(curl -sSk --pinnedpubkey "$pin" -o /dev/null -w '%{http_code}' "$url") \
  || fail "could not reach nervus at $url. Nothing here was changed."
[ "$first" = 200 ] || fail "this script's code is used or expired (nervus answered $first): make new lines in nervus's page. Nothing here was changed."

# The accounts nervus's page named (ADR-0031 question 8): only an ordinary
# account, never root or one of this machine's own system accounts: below
# UID_MIN; above UID_MAX up to 65535, which a machine keeps for itself, nobody
# (65534) among them, and systemd's dynamic users; or the last two uids, never
# an account. From 65536, a directory's ordinary accounts (procedure 068,
# section 13).
uid_min=1000 uid_max=60000
if [ -r "$root/etc/login.defs" ]; then
  while read -r k v rest; do
    case $k in UID_MIN) uid_min=$v ;; UID_MAX) uid_max=$v ;; esac
  done < "$root/etc/login.defs"
fi
case $uid_min in ''|*[!0-9]*) uid_min=1000 ;; esac
case $uid_max in ''|*[!0-9]*) uid_max=60000 ;; esac
for u in $rw $ro; do
  if getent passwd "$u" >/dev/null 2>&1; then
    uid=$(id -u "$u" 2>/dev/null) || fail "cannot read the account $u"
    case $uid in ''|*[!0-9]*) fail "cannot read the account $u's uid" ;; esac
    if [ "$uid" -lt "$uid_min" ] || { [ "$uid" -gt "$uid_max" ] && [ "$uid" -le 65535 ]; } \
        || [ "$uid" -ge 4294967294 ]; then
      fail "$u is one of this machine's system accounts (uid $uid), which nervus never uses: in nervus's page, give another name. Nothing here was changed."
    fi
  fi
done
# Each account's line is written as the account, in its ~/.ssh; a link there would take it elsewhere.
# Every account this script touches is looked at now, before anything changes (procedure 068, section 12).
for u in $rw $ro $off; do
  getent passwd "$u" >/dev/null 2>&1 || continue
  h=$(getent passwd "$u" | cut -d: -f6)
  if [ -L "$h/.ssh" ]; then
    fail "$h/.ssh is a symbolic link; remove it, then run this again. Nothing here was changed."
  fi
done
command -v su >/dev/null 2>&1 \
  || fail "this machine has no su, which this uses to write each account's key as the account. Nothing here was changed."

sudoers=$root/etc/sudoers.d
lib=$root/usr/local/lib/nervus
copy=$lib/bwrap apparmor=$root/etc/apparmor.d/nervus-bwrap hook=$root/etc/apt/apt.conf.d/99nervus-bwrap
# nervus's copy of bubblewrap, its AppArmor profile and its apt hook (question 9)
# are the read-only account's alone: taken off first, made again below where
# that account needs them, and put back as they were if nervus does not add the machine.
unbwrap() {
  if [ -e "$apparmor" ] && command -v apparmor_parser >/dev/null 2>&1; then
    apparmor_parser -R "$apparmor" >/dev/null 2>&1
  fi
  rm -f "$copy" "$apparmor" "$hook"
}

# nervus's keys, as any line of nervus's holds them: its certificate authority's, and its own, which a
# machine given it by hand or enrolled before ADR-0025 holds (procedure 068, section 12). Each account
# reads this, so it is in /tmp itself, whatever root's TMPDIR.
patterns=$(mktemp /tmp/nervus-enroll.XXXXXX) || fail "cannot make a temporary file. Nothing here was changed."
trap 'rm -f "$patterns"' EXIT
{
  printf '%s\n' "$key" | cut -d' ' -f1-2
  if [ -n "$plainkey" ]; then printf '%s\n' "$plainkey"; fi
} > "$patterns" && chmod 644 "$patterns" || fail "cannot make a temporary file. Nothing here was changed."

# What this will change, kept first, in a folder root's alone: each account's authorized_keys, read by the
# account itself as trust reads it, and its sudoers file; nervus's read-only shell; and its copy of bwrap
# with the profile and the hook. If nervus does not add the machine, or this stops before it is done, undo
# puts each back as it was and deletes the accounts this made (ADR-0031 question 12).
keep=$(mktemp -d /tmp/nervus-enroll.XXXXXX) || fail "cannot make a temporary folder. Nothing here was changed."
trap 'rm -f "$patterns"; rm -rf "$keep"' EXIT
for u in $rw $ro; do
  getent passwd "$u" >/dev/null 2>&1 || continue
  h=$(getent passwd "$u" | cut -d: -f6)
  if su -s /bin/sh -c "[ -f '$h/.ssh/authorized_keys' ]" "$u"; then
    su -s /bin/sh -c "cat '$h/.ssh/authorized_keys'" "$u" > "$keep/keys-$u" \
      || fail "cannot read $u's authorized_keys as $u. Nothing here was changed."
  elif ! su -s /bin/sh -c "[ -d '$h/.ssh' ]" "$u"; then
    : > "$keep/nossh-$u"
  fi
  if [ -e "$sudoers/nervus-$u" ]; then
    cp -p "$sudoers/nervus-$u" "$keep/sudoers-$u" \
      || fail "cannot keep a copy of $sudoers/nervus-$u. Nothing here was changed."
  fi
done
for f in "$lib/readonly-shell" "$copy" "$apparmor" "$hook"; do
  if [ -e "$f" ]; then cp -p "$f" "$keep/${f##*/}" || fail "cannot keep a copy of $f. Nothing here was changed."; fi
done
lib_was=
[ -d "$lib" ] && lib_was=yes

# Account $1's authorized_keys put back as it was before this ran, by $1 itself: 0 when it is, 2 when it
# cannot be. Never stops the script, as undo uses it.
put_back() {
  h=$(getent passwd "$1" | cut -d: -f6)
  { [ -n "$h" ] && [ ! -L "$h/.ssh" ]; } || return 2
  if [ -e "$keep/keys-$1" ]; then
    su -s /bin/sh -c "umask 077; mkdir -p '$h/.ssh' && cat > '$h/.ssh/.authorized_keys.nervus' && mv -f '$h/.ssh/.authorized_keys.nervus' '$h/.ssh/authorized_keys'" "$1" < "$keep/keys-$1" \
      || return 2
  else
    su -s /bin/sh -c "rm -f '$h/.ssh/authorized_keys' '$h/.ssh/.authorized_keys.nervus'" "$1" || return 2
    if [ -e "$keep/nossh-$1" ]; then su -s /bin/sh -c "rmdir '$h/.ssh' 2>/dev/null; true" "$1"; fi
  fi
  return 0
}
# Everything this changed, put back as it was before it ran (ADR-0031 question 12): each account's
# authorized_keys and sudoers file, nervus's read-only shell, and its copy of bwrap with the profile and
# the hook; and the accounts this made, deleted. The packages it installed stay. Never stops; says what it
# could not put back.
undo() {
  changing=
  trap '' HUP INT TERM
  back= left=
  for u in $rw $ro; do
    case " $made " in *" $u "*) continue ;; esac
    getent passwd "$u" >/dev/null 2>&1 || continue
    if put_back "$u"; then back="$back, $u's SSH keys"; else left="$left, $u's SSH keys"; fi
  done
  if [ "$kind" = machine ]; then
    for u in $rw $ro; do
      rm -f "$sudoers/.nervus-$u"
      case " $made " in *" $u "*) rm -f "$sudoers/nervus-$u"; continue ;; esac  # it goes with the account
      if [ -e "$keep/sudoers-$u" ]; then
        if cp -p "$keep/sudoers-$u" "$sudoers/nervus-$u"; then back="$back, $u's sudoers line"
        else left="$left, $u's sudoers line"; fi
      elif [ -e "$sudoers/nervus-$u" ]; then
        if rm -f "$sudoers/nervus-$u"; then back="$back, no sudoers line for $u"
        else left="$left, $u's sudoers line"; fi
      fi
    done
  fi
  had=
  for f in bwrap nervus-bwrap 99nervus-bwrap; do [ -e "$keep/$f" ] && had=yes; done
  if [ -e "$copy" ] || [ -e "$apparmor" ] || [ -e "$hook" ] || [ -n "$had" ]; then
    unbwrap
    ok=yes
    if [ -e "$keep/bwrap" ]; then { mkdir -p "$lib" && cp -p "$keep/bwrap" "$copy"; } || ok=; fi
    if [ -e "$keep/99nervus-bwrap" ]; then cp -p "$keep/99nervus-bwrap" "$hook" || ok=; fi
    if [ -e "$keep/nervus-bwrap" ]; then
      { cp -p "$keep/nervus-bwrap" "$apparmor" \
        && { ! command -v apparmor_parser >/dev/null 2>&1 || apparmor_parser -r "$apparmor" >/dev/null 2>&1; }; } || ok=
    fi
    if [ -z "$ok" ]; then left="$left, nervus's copy of bwrap with its AppArmor profile"
    elif [ -n "$had" ]; then back="$back, nervus's copy of bwrap with its AppArmor profile as it was"
    else back="$back, nervus's copy of bwrap with its AppArmor profile taken off"; fi
  fi
  rm -f "$lib/.readonly-shell" "$lib/.bwrap"
  if [ -e "$keep/readonly-shell" ]; then
    cp -p "$keep/readonly-shell" "$lib/readonly-shell" || left="$left, nervus's read-only shell"
  else
    rm -f "$lib/readonly-shell"
  fi
  [ -n "$lib_was" ] || rm -rf "$lib"
  gone=
  for u in $made; do
    if command -v pkill >/dev/null 2>&1 && pkill -KILL -u "$u" >/dev/null 2>&1; then sleep 1; fi
    userdel -r "$u" >/dev/null 2>&1
    if getent passwd "$u" >/dev/null 2>&1; then left="$left, the account $u"; else gone="$gone $u"; fi
  done
  echo "nervus enrollment: so this put back what was here before it ran${back:+:${back#,}}${gone:+; the accounts it made are deleted:$gone}" >&2
  [ -z "$left" ] || echo "nervus enrollment: it could NOT put back${left#,}: see to them by hand" >&2
}

# 1. The accounts, and tmux for nervus's background jobs. Those this script makes are named in its report,
# so that removing the machine deletes only the accounts nervus made (ADR-0031 question 9).
made=
# From here on, a stop puts back what this changed.
changing=yes
trap 'fail "stopped before it finished"' HUP INT TERM
account() {
  if getent passwd "$1" >/dev/null 2>&1; then
    say "using the account $1, which was here already, as it is: it is in the groups $(id -Gn "$1" 2>/dev/null)"
  else
    command -v useradd >/dev/null 2>&1 || fail "there is no useradd to make the account $1"
    useradd -m -s /bin/sh "$1" || fail "useradd could not make the account $1"
    say "made the account $1"
    made="$made $1"
  fi
  h=$(getent passwd "$1" | cut -d: -f6)
  [ -n "$h" ] && [ -d "$h" ] || fail "the account $1 has no home folder"
}
[ -n "$rw" ] && account "$rw"
account "$ro"
need tmux tmux

# 2. The level.
# The line letting $rw use sudo without a password, written at $1 and checked by visudo; or the script stops.
sudo_line() {
  rm -f "$1"
  printf '%s ALL=(ALL) NOPASSWD: ALL\n' "$rw" > "$1" && chmod 440 "$1" \
    || { rm -f "$1"; fail "cannot write the sudoers line"; }
  visudo -cqf "$1" || { rm -f "$1"; fail "visudo refused the sudoers line"; }
}
# Is group $2 account $1's alone: no member but $1, and no other account's own group?
alone() {
  [ -n "$2" ] || return 1
  for m in $(getent group "$2" | cut -d: -f4 | tr ',' ' '); do [ "$m" = "$1" ] || return 1; done
  getent passwd | { while IFS=: read -r n _ _ g _; do [ "$g" = "$2" ] && [ "$n" != "$1" ] && exit 1; done; exit 0; }
}
if [ -e "$copy" ] || [ -e "$apparmor" ] || [ -e "$hook" ]; then
  unbwrap
  [ -e "$copy" ] || [ -e "$apparmor" ] || [ -e "$hook" ] \
    && fail "cannot take off nervus's copy of bwrap, its AppArmor profile or its apt hook"
  say "took off nervus's copy of bwrap, its AppArmor profile and its apt hook, which an earlier enrollment left"
fi
if [ "$kind" = machine ]; then
  # One sudoers file for each of nervus's accounts, nervus-<account> (procedure 068): another account's
  # is never touched, so `agent`'s, where nervus uses this machine as a VM by its id, stays as it is.
  if [ "$level" = full ]; then
    need sudo sudo
    command -v visudo >/dev/null 2>&1 || fail "sudo is installed but there is no visudo"
    [ -d "$sudoers" ] || fail "there is no $sudoers"
    # Checked by visudo now, before any key; put in place only once $rw's line is in (3), so a script
    # that stops before then leaves no account with sudo it did not have (procedure 068, section 12).
    # A name with a dot in it is never read by sudo, so the file being checked gives nothing.
    sudo_line "$sudoers/.nervus-$rw" && rm -f "$sudoers/.nervus-$rw"
  elif [ -n "$rw" ] && [ -e "$sudoers/nervus-$rw" ]; then
    rm -f "$sudoers/nervus-$rw" || fail "cannot remove $sudoers/nervus-$rw"
    say "removed $rw's sudoers line"
  fi
  # The read-only account never has one. The accounts nervus used here before lose theirs once nervus has
  # added the machine, below (ADR-0031 question 11).
  for u in $ro; do
    if [ -e "$sudoers/nervus-$u" ]; then
      rm -f "$sudoers/nervus-$u" || fail "cannot remove $sudoers/nervus-$u"
      say "removed $u's sudoers line, which nervus wrote here before"
    fi
  done
fi

# The read-only account's sandbox (ADR-0031): bubblewrap, and nervus's read-only
# shell, tried as the account before its line is written. Where it cannot run,
# a machine at standard or full is added read-write alone (question 5).
readonly=yes why=
want bwrap bubblewrap || readonly=no
if [ $readonly = yes ]; then
  mkdir -p "$lib" && chown root:root "$lib" && chmod 755 "$lib" || fail "cannot make $lib"
  tmp=$lib/.readonly-shell
  rm -f "$tmp"
  cat > "$tmp" <<'NERVUS_READONLY_SHELL' || { rm -f "$tmp"; fail "cannot write the read-only shell"; }
{readonly_shell}NERVUS_READONLY_SHELL
  chown root:root "$tmp" && chmod 755 "$tmp" && mv -f "$tmp" "$lib/readonly-shell" \
    || { rm -f "$tmp"; fail "cannot put the read-only shell in place"; }
  # The shell as nervus will meet it: as the read-only account, inside bubblewrap.
  if ! tried=$(su -s /bin/sh -c "SSH_ORIGINAL_COMMAND=true $lib/readonly-shell" "$ro" 2>&1); then
    # Where AppArmor keeps programs from making user namespaces (question 9):
    # a copy of bubblewrap only the read-only account may run, a profile letting
    # that copy alone make them, and an apt hook keeping the copy the system's.
    restricted=$(cat "$root/proc/sys/kernel/apparmor_restrict_unprivileged_userns" 2>/dev/null)
    # The copy runs for one group, the read-only account's own, which must be its alone: AppArmor lets the
    # copy make user namespaces, for every member of that group (procedure 068, section 12).
    gid=$(id -g "$ro" 2>/dev/null) || gid=
    case $gid in ''|*[!0-9]*) gid= ;; esac
    if [ "$restricted" = 1 ] && command -v apparmor_parser >/dev/null 2>&1 && [ -d "$root/etc/apparmor.d" ] \
        && ! alone "$ro" "$gid"; then
      readonly=no why="its own group (${gid:-unknown}) is not $ro's alone, so nervus makes no copy of bwrap, which AppArmor would let every member of that group use to make user namespaces"
    elif [ "$restricted" = 1 ] && command -v apparmor_parser >/dev/null 2>&1 && [ -d "$root/etc/apparmor.d" ]; then
      say "this machine's AppArmor keeps programs from making user namespaces: giving nervus's own copy of bwrap, which only $ro may run, a profile that lets it"
      system=$(command -v bwrap)
      tmp=$lib/.bwrap
      rm -f "$tmp"
      cp "$system" "$tmp" && chown root:"$gid" "$tmp" && chmod 750 "$tmp" && mv -f "$tmp" "$copy" \
        || { rm -f "$tmp"; fail "cannot make nervus's copy of bwrap"; }
      cat > "$apparmor" <<'NERVUS_APPARMOR' || { unbwrap; fail "cannot write nervus's AppArmor profile"; }
# nervus (ADR-0024 question 9, ADR-0031): nervus's own copy of bubblewrap, which only
# nervus's read-only account may run, may make user namespaces, for nervus's read-only
# shell, which runs it with --disable-userns. Nothing else here is changed. Taken off
# when the machine is enrolled without a read-only account, or removed.
abi <abi/4.0>,
include <tunables/global>

profile nervus-bwrap /usr/local/lib/nervus/bwrap flags=(unconfined) {
  userns,
}
NERVUS_APPARMOR
      if loaded=$(apparmor_parser -r "$apparmor" 2>&1); then
        if [ -d "$root/etc/apt/apt.conf.d" ]; then
          cat > "$hook" <<NERVUS_APT_HOOK || { unbwrap; fail "cannot write nervus's apt hook"; }
// nervus (ADR-0024 question 9, ADR-0031): after apt changes packages, nervus's copy of
// bubblewrap is made the system's again, so it never lags bubblewrap's updates.
// Taken off when the machine is enrolled without a read-only account, or removed.
DPkg::Post-Invoke { "if [ -e /usr/local/lib/nervus/bwrap ] && [ -x $system ] && ! cmp -s $system /usr/local/lib/nervus/bwrap; then cp $system /usr/local/lib/nervus/.bwrap && chown root:$gid /usr/local/lib/nervus/.bwrap && chmod 750 /usr/local/lib/nervus/.bwrap && mv -f /usr/local/lib/nervus/.bwrap /usr/local/lib/nervus/bwrap; fi; true"; };
NERVUS_APT_HOOK
        fi
        if ! tried=$(su -s /bin/sh -c "SSH_ORIGINAL_COMMAND=true $lib/readonly-shell" "$ro" 2>&1); then
          unbwrap
          readonly=no why="bubblewrap cannot run here, even as nervus's own copy with its AppArmor profile ($tried)"
        fi
      else
        unbwrap
        readonly=no why="AppArmor would not load nervus's profile for its copy of bwrap ($loaded)"
      fi
    else
      readonly=no why="bubblewrap cannot run here ($tried)"
    fi
  fi
fi
if [ $readonly = no ]; then
  why=$(printf '%s' "$why" | tr '\r\n' '  ' | cut -c1-300)
  [ "$kind" = machine ] || fail "$why, so $ro cannot be a read-only account here. Nothing was added."
  [ "$level" != read-only ] \
    || fail "$why, so this machine cannot be read-only. In nervus's page, add it as standard instead."
  say "this machine cannot have a read-only account: $why. It is added with $rw alone, read-write: no client can be read-only here until it is added again."
fi

# 3. nervus's certificate authority, and no other key. Each account writes its own line. Its home is
# its own, and where it has no sudo, anything root did there by path -- a write, a chown, a rename --
# could be turned onto a file elsewhere by a link it swaps in at the right instant (procedure 056,
# C32, whose first fix closed only a link planted beforehand; procedure 058). As the account, a link
# reaches only what it could reach already. A line is no secret, so root leaves it where any account
# can read it.
trust() {  # $1 the account, $2 its line, which replaces every line it had
  h=$(getent passwd "$1" | cut -d: -f6)
  [ -L "$h/.ssh" ] && fail "$h/.ssh is a symbolic link; remove it, then run this again"
  # Whether it has keys of its own, read by the account itself: root reading by path in its home would
  # follow a link it swapped in (procedure 068, section 12).
  own_keys=$(su -s /bin/sh -c "grep -v -F -f '$patterns' '$h/.ssh/authorized_keys' 2>/dev/null | grep -q . && echo yes" "$1")
  # In /tmp itself, whatever root's TMPDIR: the account must be able to read it.
  line_file=$(mktemp /tmp/nervus-enroll.XXXXXX) || fail "cannot make a temporary file"
  printf '%s\n' "$2" > "$line_file" && chmod 644 "$line_file" \
    || { rm -f "$line_file"; fail "cannot write $1's authorized_keys"; }
  su -s /bin/sh -c "umask 077; mkdir -p '$h/.ssh' && chmod 700 '$h/.ssh' && rm -f '$h/.ssh/.authorized_keys.nervus' && cat '$line_file' > '$h/.ssh/.authorized_keys.nervus' && mv -f '$h/.ssh/.authorized_keys.nervus' '$h/.ssh/authorized_keys'" "$1" \
    || { rm -f "$line_file"; fail "$1 could not write its authorized_keys in $h/.ssh"; }
  rm -f "$line_file"
  [ "$own_keys" = yes ] && say "$1's own SSH keys are replaced by nervus's line: whoever logged in to $1 with a key can no longer"
}
# nervus's lines taken off account $1's authorized_keys, by $1 itself, every other line kept: 0 when
# they are, 1 when it holds none, 2 when they cannot be. Never stops the script, so undo can use it.
drop_lines() {
  getent passwd "$1" >/dev/null 2>&1 || return 1
  h=$(getent passwd "$1" | cut -d: -f6)
  [ -L "$h/.ssh" ] && return 2
  # Read by the account itself, as trust reads it.
  held=$(su -s /bin/sh -c "if grep -q -F -f '$patterns' '$h/.ssh/authorized_keys' 2>/dev/null; then echo yes; else echo no; fi" "$1") \
    || return 2
  [ "$held" = yes ] || return 1
  su -s /bin/sh -c "umask 077; { grep -v -F -f '$patterns' '$h/.ssh/authorized_keys' || true; } > '$h/.ssh/.authorized_keys.nervus' && mv -f '$h/.ssh/.authorized_keys.nervus' '$h/.ssh/authorized_keys'" "$1" \
    || return 2
}
untrust() {  # $1 an account nervus used here before: nervus's line taken off it, its other lines kept
  drop_lines "$1"
  case $? in
    0) say "took nervus's line off $1, which nervus used here before" ;;
    2) fail "$1 could not take nervus's line off its authorized_keys" ;;
  esac
}
if [ $readonly = yes ]; then
  trust "$ro" "cert-authority,restrict,command=\"/usr/local/lib/nervus/readonly-shell\" $key"
  say "$ro trusts nervus's certificate authority, read-only"
else
  untrust "$ro"  # an earlier enrollment's read-only line, which nothing here can run now
fi
# The read-write account's line goes in last of the lines; at full, its sudoers line after it.
if [ -n "$rw" ]; then
  trust "$rw" "cert-authority $key"
  say "$rw trusts nervus's certificate authority"
fi
if [ "$kind" = machine ] && [ "$level" = full ]; then
  sudo_line "$sudoers/.nervus-$rw"
  mv -f "$sudoers/.nervus-$rw" "$sudoers/nervus-$rw" \
    || { rm -f "$sudoers/.nervus-$rw"; fail "cannot put the sudoers line in place"; }
  say "$rw may use sudo"
fi

# 4. The host keys and machine id, back to nervus.
if command -v systemctl >/dev/null 2>&1; then
  systemctl is-active --quiet ssh || systemctl is-active --quiet sshd \
    || systemctl start ssh 2>/dev/null || systemctl start sshd 2>/dev/null \
    || fail "cannot start the SSH server"
fi
ls "$root"/etc/ssh/ssh_host_*_key.pub >/dev/null 2>&1 || fail "the SSH server has no host keys in /etc/ssh"
report=$(mktemp) && answer=$(mktemp) || fail "cannot make a temporary file"
trap 'rm -f "$patterns" "$report" "$answer"; rm -rf "$keep"' EXIT
{
  echo "machine-id $machine_id"
  [ $readonly = no ] && echo "nervus-readonly-none $why"
  for u in $made; do echo "nervus-made $u"; done
  cat "$root"/etc/ssh/ssh_host_*_key.pub
} > "$report"
say "asking nervus to check and add this machine"
if ! status=$(curl -sSk --pinnedpubkey "$pin" -H 'Content-Type: text/plain' --data-binary "@$report" \
  -o "$answer" -w '%{http_code}' "$url"); then
  fail "could not reach nervus at $url"
fi
cat "$answer"
# What nervus does not accept is put back as it was (ADR-0031 question 12).
[ "$status" = 200 ] || fail "nervus did not add this machine"
# nervus has added the machine with its new accounts: nothing is put back from here. Only now do the
# accounts nervus used here before lose nervus's line and sudoers file (ADR-0031 question 11), so a re-add
# nervus refuses, or cannot hear, leaves them as they were.
changing=
trap - HUP INT TERM
left=
for u in $off; do
  if [ -e "$sudoers/nervus-$u" ]; then
    if rm -f "$sudoers/nervus-$u"; then say "removed $u's sudoers line, which nervus wrote here before"; else left="$left $u"; fi
  fi
  drop_lines "$u"
  case $? in
    0) say "took nervus's line off $u, which nervus used here before" ;;
    2) left="$left $u" ;;
  esac
done
[ -z "$left" ] || fail "nervus added this machine, but could not take its line or sudoers file off$left: take them off by hand"
"""


# A public key's type and base64, as an authorized_keys line holds them.
_KEY_WORDS = re.compile(r"[a-z0-9@.-]+ [A-Za-z0-9+/]+={0,3}")


def own_hash(code: str, machine_id: str) -> str:
    """What a full script compares its own machine id with: nervus's, hashed
    with the code, so the script never holds nervus's id (decision 6)."""
    return hashlib.sha256(f"{code}:{machine_id}".encode()).hexdigest()


def enroll_script(*, name: str, level: str, origin: str, url: str, pin: str, key: str,
                  own_hash: str | None = None, readonly_shell: str | None = None,
                  readwrite: str | None = None, readonly: str | None = None, off: Iterable[str] = (),
                  kind: str = "machine", nervus_key: str | None = None) -> str:
    """The enrollment script for one code: machine `name` at `level`, its
    report sent to `url`, whose last part is the code, pinned to `pin`
    (`sha256//<base64>`), making the accounts trust nervus's certificate
    authority, whose public `key` this is. `origin` names nervus in the opening
    comment. A full script, and only a full one, takes `own_hash`, from own_hash().

    The accounts (ADR-0031 question 8): `readwrite`, at standard or full, and
    `readonly`, always, nervus's names by default. `off` names the accounts
    nervus used on this machine before and will not now, whose line it takes
    off. Of `kind` READONLY_ACCOUNT, for a machine described by hand (question
    4), the read-only account alone, nothing else changed. `nervus_key` is
    nervus's own public key, which a machine given it by hand or enrolled
    before ADR-0025 holds: a line with it is nervus's too, taken off the
    accounts nervus used there before (procedure 068, section 12)."""
    if kind == "machine":
        if level not in LEVELS:
            raise ValueError(f"not a level: {level!r}")
        if readwrite is None and level != "read-only":
            readwrite = accounts.READWRITE
    elif kind == READONLY_ACCOUNT:
        if level != READONLY_ACCOUNT:
            raise ValueError("a read-only account alone is its own kind and level")
    else:
        raise ValueError(f"not a kind of enrollment: {kind!r}")
    if level in ("read-only", READONLY_ACCOUNT) and readwrite is not None:
        raise ValueError("at read-only alone, and for a machine described by hand, there is no read-write account")
    readonly = accounts.READONLY if readonly is None else readonly
    off = sorted(set(off))
    for account in (readwrite, readonly, *off):
        if account is not None and (not accounts.NAME.fullmatch(account) or account == "root"):
            raise ValueError(f"not an account nervus uses: {account!r}")
    if readwrite == readonly or {readwrite, readonly} & set(off):
        raise ValueError("the read-write and the read-only accounts are two, and neither is one to take off")
    if (level == "full") != bool(own_hash) or (own_hash and not re.fullmatch(r"[0-9a-f]{64}", own_hash)):
        raise ValueError("a full script, and only a full one, takes nervus's machine id hashed with the code")
    if any(c in text for text in (name, origin, url, pin, key) for c in "\r\n\0"):
        raise ValueError("a value for the script holds a line break")
    # The script finds nervus's lines by these words, so neither may be empty or other than a key's.
    plainkey = " ".join((nervus_key or "").split()[:2])
    if not _KEY_WORDS.fullmatch(" ".join(key.split()[:2])) or (nervus_key and not _KEY_WORDS.fullmatch(plainkey)):
        raise ValueError("a key for the script is not a public key's type and base64")
    shell = READONLY_SHELL.read_text() if readonly_shell is None else readonly_shell
    if not shell.endswith("\n") or _END in shell.splitlines():
        raise ValueError("the read-only shell cannot be carried in the script as it is")
    both = [a for a in (readwrite, readonly) if a]
    head = _HEAD.format(
        doing=(f"give {name} the read-only account {readonly}" if kind == READONLY_ACCOUNT
               else f"enroll this machine as {name}, {level}"),
        origin=origin, plural="s" if len(both) > 1 else "", accounts=" and ".join(both),
        what=_WHAT[level].format(rw=readwrite, ro=readonly), trusting=" and ".join(both),
        off_line=(f"\n#      once nervus has added this machine, takes nervus's line and sudoers file off\n"
                  f"#      {', '.join(off)}, which nervus used here before;" if off else ""),
        q_name=shlex.quote(name), q_level=shlex.quote(level), q_kind=shlex.quote(kind),
        q_rw=shlex.quote(readwrite or ""), q_ro=shlex.quote(readonly), q_off=shlex.quote(" ".join(off)),
        q_url=shlex.quote(url), q_pin=shlex.quote(pin), q_key=shlex.quote(key), q_plainkey=shlex.quote(plainkey), q_own=shlex.quote(own_hash or ""))
    return head + _BODY.replace("{readonly_shell}", shell)


def _line_off(account: str, keys: Iterable[str]) -> str:
    """For an account that was there before nervus (ADR-0031 question 9a):
    nervus's line taken off it by the account itself, as the script writes it,
    every other line kept. `keys` are nervus's key words, its authority's and
    its own, as a line holds them."""
    words = [w for w in keys if _KEY_WORDS.fullmatch(w)]
    if not words:
        return f"# take nervus's line off {account} by hand: nervus could not read its own keys to name them\n"
    patterns = " ".join(f'-e "{w}"' for w in words)
    return (f"su -s /bin/sh -c 'umask 077; f=$HOME/.ssh/authorized_keys; [ -f \"$f\" ] || exit 0; "
            f"grep -v -F {patterns} \"$f\" > \"$f.nervus\"; mv -f \"$f.nervus\" \"$f\"' {account}\n")


def _made_first(names: list[str], made: Iterable[str]) -> list[str]:
    """The accounts nervus made: those of the machine's names first, then those
    of names it had before (ADR-0031 question 13)."""
    ours = accounts.made_names(made)
    return [a for a in names if a in ours] + [a for a in ours if a not in names]


def remove_commands(readwrite: str | None = "agent", readonly: str | None = None, made: Iterable[str] = (),
                    keys: Iterable[str] = ()) -> str:
    """What the owner runs as root to take nervus off a machine once it is
    forgotten (decision 5a). Every account nervus's script made there (`made`, as
    its record says), those of names the machine had before included (ADR-0031
    question 13), goes with its processes, its home and its key, as always. Any
    other, one that was there before nervus or one nervus cannot tell about,
    keeps itself, its home and its own keys, and loses only nervus's line, by
    `keys`, and nervus's sudoers file (question 9a). Then nervus's AppArmor
    profile and apt hook (question 9), and the read-only shell with the copy of
    bwrap. Shown in the UI; tested as written."""
    names = [a for a in dict.fromkeys((readwrite, readonly)) if a]
    deleted = _made_first(names, made)
    kept = [a for a in names if a not in deleted]
    lines = []
    if deleted:
        lines.append("; ".join(f"pkill -KILL -u {a}" for a in deleted) + "; sleep 1\n")
        lines.extend(f"userdel -r {a}\n" for a in deleted)
    keys = tuple(keys)
    lines.extend(_line_off(a, keys) for a in kept)
    # Each account's own sudoers file (procedure 068): `agent`'s is nervus-agent, as it always was.
    files = " ".join(f"/etc/sudoers.d/nervus-{a}" for a in names + [a for a in deleted if a not in names])
    return ("".join(lines) + f"rm -f {files}\n"
            f"apparmor_parser -R {APPARMOR_PROFILE_PATH} 2>/dev/null; rm -f {APPARMOR_PROFILE_PATH} {APT_HOOK_PATH}\n"
            "rm -rf /usr/local/lib/nervus\n")


def remove_readonly_commands(readonly: str, made: Iterable[str] = (), keys: Iterable[str] = ()) -> str:
    """For a machine described by hand: its read-only account, deleted where
    nervus's script made it, and otherwise kept with nervus's line off it
    (ADR-0031 question 9a), and any read-only account nervus made there under
    an earlier name, deleted (question 13); and what nervus put there for that
    account alone, its copy of bwrap with the AppArmor profile and the apt hook.
    The account the machine is described with stays, and so does the read-only
    shell, which that account may use too, where it is read-only by hand
    (docs/install.md; procedure 068, section 12)."""
    deleted = _made_first([readonly], made)
    first = ("; ".join(f"pkill -KILL -u {a}" for a in deleted) + "; sleep 1\n"
             + "".join(f"userdel -r {a}\n" for a in deleted)) if deleted else ""
    if readonly not in deleted:
        first += _line_off(readonly, keys)
    return (first + f"apparmor_parser -R {APPARMOR_PROFILE_PATH} 2>/dev/null; "
                    f"rm -f {APPARMOR_PROFILE_PATH} {APT_HOOK_PATH}\n"
            f"rm -f {BWRAP_COPY_PATH}\n")


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
# And of the read-only account (ADR-0031): its groups too, from the account
# database, which the sandbox shows as it is.
CHECK_READONLY = CHECK + '; echo groups; id -Gn "$(id -un)"'
EXPECTED = {
    "read-only": ["{account}", "no-sudo", "no-writes"],
    "standard": ["{account}", "no-sudo", "writes"],
    "full": ["{account}", "root", "writes"],
}
FULL_UNKNOWN = ("nervus cannot read its own machine id, so it cannot tell whether this is the machine it runs on; "
                "full access is refused. Add it as standard or read-only.")
HTTPS_ONLY = ("this nervus serves plain HTTP, and enrollment needs HTTPS: the machine checks nervus's key "
              "before it runs anything nervus sends. Serve MCP over HTTPS (docs/install.md), then make a new code.")
UNKNOWN = "this enrollment code is unknown, used or expired; make a new one in nervus's page"
OLDER_CODE = ("this enrollment code was made by a release of nervus before this one, which kept no accounts for "
              "its script; make new lines in nervus's page")
NOT_ITS_OWN = ("the key that answered nervus's login at {address} is not one of this machine's own "
               "host keys, so something between nervus and the machine may have answered instead and "
               "seen {login}'s password. nervus did not add the machine. Change that password, then add "
               "the machine with the two lines.")


class Refused(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


# A machine's reason for having no read-only account (ADR-0031 question 5) comes from the machine, which
# may send anything up to REPORT_BYTES: nervus keeps and shows what its own script sends at most, any
# unprintable character as "?" (procedure 068, section 13).
REASON_CHARS = 300


def _reason(text: str) -> str:
    return "".join(c if c.isprintable() else "?" for c in text)[:REASON_CHARS].strip() or "it could not be made"


def _report(body: str) -> tuple[str, list[str]]:
    """The machine id and the host key lines the script sent."""
    lines = [line.strip() for line in body.splitlines() if line.strip()]
    if not lines or not lines[0].startswith("machine-id "):
        raise Refused(400, "the report does not start with the machine id")
    return lines[0].split(" ", 1)[1].strip(), lines[1:]


def check_failed(level: str, seen: list[str], account: str = "agent") -> str | None:
    """None if what the machine answered, logged in as `account`, is this
    level; otherwise why not, in words for the machine's owner."""
    if seen == [w.format(account=account) for w in EXPECTED[level]]:
        return None
    if not seen or seen[0] != account:
        return f"nervus logged in, but not as {account} ({' '.join(seen)[:80]!r})"
    sudo = seen[1:2] == ["root"]
    if sudo and level != "full":
        return (f"{account} can still use sudo without a password: something other than nervus's sudoers line "
                "allows it, a group or another file in /etc/sudoers.d. Remove that, or add the machine as full.")
    if not sudo and level == "full":
        return f"{account} cannot use sudo without a password, so the machine is not full"
    if level == "read-only":
        return f"{account} can write outside ~/.nervus, so the read-only shell is not in force"
    return f"{account} cannot write in its own home folder"


class HostEnrollment:
    """The enrollment route's work. `key` is nervus's public key line for
    `agent`; `connect` opens SSH as agent trusting only the keys given; `pin`
    is nervus's serving key as curl pins it, None where MCP is plain HTTP;
    `own_machine_id` is nervus's machine's, None if unreadable; `reserved`
    the names hosts.yaml has. The callables are read at each request."""

    def __init__(self, codes, store, audit, *, key: Callable[[], str], connect: Connect,
                 pin: Callable[[], str | None], own_machine_id: str | None,
                 reserved: Callable[[], Iterable[str]], locked: Callable[[], bool] = lambda: False,
                 machine_accounts=None, described: Callable[[], dict] = lambda: {}, connect_described=None,
                 nervus_key: Callable[[], str | None] = lambda: None,
                 taken: Callable[[str], Iterable[str]] = lambda name: ()):
        """ADR-0031: `machine_accounts` keeps what nervus found of each machine's
        accounts; `described` gives the machines described by hand by name, and
        `connect_described` opens SSH to one of them as nervus does, with the
        known_hosts file, as the account chosen for the call. `nervus_key` gives
        nervus's own public key, for the script to find a line holding it.
        `taken` gives, for a machine described by hand, the accounts every
        hosts.yaml entry at its address is described with."""
        self.codes, self.store, self.audit = codes, store, audit
        self.key, self.connect, self.pin = key, connect, pin
        self.own_machine_id, self.reserved, self.locked = own_machine_id, reserved, locked
        self.machine_accounts, self.described, self.connect_described = machine_accounts, described, connect_described
        self.nervus_key, self.taken = nervus_key, taken

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
        made = self.codes.accounts_of(code.id)
        if made is None:
            self.audit.record_result(run_id, TOOL, {"failure_message": OLDER_CODE})
            raise Refused(409, OLDER_CODE)
        own = None
        if code.level == "full":
            if self.own_machine_id is None:
                self.audit.record_result(run_id, TOOL, {"failure_message": FULL_UNKNOWN})
                raise Refused(403, FULL_UNKNOWN)
            own = own_hash(value, self.own_machine_id)
        text = enroll_script(name=code.name, level=code.level, origin=origin, url=url, pin=self.pin(),
                             key=self.key(), own_hash=own, readwrite=made.readwrite, readonly=made.readonly,
                             off=made.off, kind=made.kind, nervus_key=self.nervus_key())
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
        made = self.codes.accounts_of(code.id)
        try:
            if made is None:
                raise Refused(409, OLDER_CODE)
            machine_id, lines = _report(body)
            # Lines of nervus's own, beside the host keys (ADR-0031 question 5).
            why_none = next((_reason(line.split(" ", 1)[1]) if " " in line else "it could not be made"
                             for line in lines if line.split(" ", 1)[0] == "nervus-readonly-none"), None)
            # The accounts the script made (ADR-0031 question 9), of this code's alone.
            made_here = ({line.split(" ", 1)[1].strip() for line in lines
                          if line.split(" ", 1)[0] == "nervus-made" and " " in line}
                         & {a for a in (made.readwrite, made.readonly) if a})
            lines = [line for line in lines if not line.startswith("nervus-")]
            if made.kind == READONLY_ACCOUNT:
                said = await self._readonly_account(code, made, why_none, made_here,
                                                    machine_id if MACHINE_ID.fullmatch(machine_id) else None)
                self.codes.finish(code.id, f"{code.name} has the read-only account {made.readonly}")
                self.audit.record_result(run_id, TOOL, {"readonly_account": made.readonly, "machine_id": machine_id,
                                                        **certs.ssh_ports()})
                return said
            enrolled, replaced, groups = await self._enroll(code, code.address or client, machine_id, lines, made,
                                                            why_none, made_here)
        except Refused as exc:
            self.codes.finish(code.id, f"refused: {exc.message}")
            self.audit.record_result(run_id, TOOL, {"failure_message": exc.message, "machine_id": machine_id,
                                                    **certs.ssh_ports()})
            raise
        before = f" It was {replaced.level} before." if replaced and replaced.level != enrolled.level else ""
        readwrite = made.readwrite if enrolled.level != "read-only" else None
        if why_none is None:
            has = (f" Its read-only account is {made.readonly}" + (f", in {', '.join(groups)}" if groups else "")
                   + (f"; its read-write account is {readwrite}." if readwrite else "."))
        else:
            has = (f" It has no read-only account ({why_none}), so no client can be read-only there until it is "
                   f"added again; its read-write account is {readwrite}.")
        self.codes.finish(code.id, f"enrolled {enrolled.name}, {enrolled.level}"
                                   + (", read-write alone" if why_none else ""))
        self.audit.record_result(run_id, TOOL, {"enrolled": True, "machine_id": machine_id, "address": enrolled.address,
                                                "host_keys": list(enrolled.host_keys), "replaced": bool(replaced),
                                                "readwrite": readwrite,
                                                "readonly": None if why_none else made.readonly,
                                                **({"readonly_none": why_none} if why_none else {}),
                                                **certs.ssh_ports()})
        return (f"nervus: {enrolled.name} is enrolled, {enrolled.level}.{before}{has} In nervus's page, give a "
                f"token this machine to let a client use it.\n")

    async def _enroll(self, code, address: str, machine_id: str, lines: list[str], made, why_none,
                      made_here: Iterable[str] = ()):
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
        login = self.codes.login_of(code.id)
        if login is not None and login.host_key not in keys:
            raise Refused(409, NOT_ITS_OWN.format(address=code.address, login=login.login))
        if not address:
            raise Refused(400, "nervus cannot tell which address this report came from; make a new code "
                               "and give the machine's address")
        readwrite = made.readwrite if code.level != "read-only" else None
        if readwrite is not None:
            why = await self._check(address, code.level, keys, certs.Route(code.name, readwrite, False, code.level))
            if why is not None:
                raise Refused(422, f"nervus checked {address} and did not add it: {why}")
        groups: tuple[str, ...] = ()
        if why_none is None:
            why, groups = await self._check_readonly(address, keys, certs.Route(code.name, made.readonly, True,
                                                                                "read-only"))
            if why is not None:
                raise Refused(422, f"nervus checked {address} and did not add it: {why}")
        elif code.level == "read-only":
            raise Refused(422, f"nervus checked {address} and did not add it: {why_none}")

        def found(db, row) -> None:
            # What nervus found, tied to this enrollment (ADR-0031), kept with the machine in one
            # transaction: a machine kept without it reads as one from before this release, through
            # `agent` (procedure 068, section 12).
            accounts.MachineAccounts.write(db, code.name, enrolled_at=row.enrolled_at, readwrite=readwrite,
                                           readonly=None if why_none else made.readonly, groups=groups,
                                           why_none=why_none, made=made_here, machine_id=machine_id)
        try:
            enrolled, replaced = self.store.add(code.name, address=address, level=code.level, host_keys=keys,
                                                machine_id=machine_id, enrolled_by=code.made_by,
                                                reserved=self.reserved(),
                                                also=found if self.machine_accounts is not None else None)
        except HostRefused as exc:
            raise Refused(409, exc.message) from None
        except Exception as exc:  # nothing was kept: the transaction is undone whole
            raise Refused(500, f"nervus could not keep what it found of {code.name} ({type(exc).__name__}), "
                               f"so it did not add the machine") from exc
        return enrolled, replaced, accounts.groups_shown(groups)

    async def _login(self, address: str, keys: tuple[str, ...], route, command: str):
        """Log in to `address` as `route` names, the keys pinned, and run
        `command`: its words, or why not (ADR-0031: each account as nervus will
        use it, the read-only one by a read-only certificate)."""
        certs.take(route)
        try:
            conn = await self.connect(address, keys, machine=route.host)
        except asyncssh.HostKeyNotVerifiable:
            return None, f"the SSH server at {address} has other host keys than this machine sent: is {address} this machine?"
        except asyncssh.PermissionDenied:
            return None, f"the SSH server at {address} refused nervus's key for {route.username}"
        except (OSError, asyncio.TimeoutError, asyncssh.Error) as exc:
            return None, f"no SSH at {address} ({type(exc).__name__}: {str(exc)[:120]})"
        try:
            result = await conn.run(command, check=False, timeout=CHECK_SECONDS)
        except (OSError, asyncio.TimeoutError, asyncssh.Error) as exc:
            return None, f"the check did not finish ({type(exc).__name__})"
        finally:
            conn.close()
        return str(result.stdout or "").split(), None

    async def _check_readonly(self, address: str, keys: tuple[str, ...], route) -> tuple[str | None, tuple[str, ...]]:
        """The read-only account: that account, no sudo, no writes; and its
        groups, which the record keeps and the Machines page shows."""
        seen, why = await self._login(address, keys, route, CHECK_READONLY)
        if why is not None:
            return why, ()
        words, groups = (seen[:seen.index("groups")], seen[seen.index("groups") + 1:]) if "groups" in seen \
            else (seen, [])
        return check_failed("read-only", words, route.username), tuple(g for g in groups if g != route.username)

    async def _readonly_account(self, code, made, why_none, made_here: Iterable[str] = (),
                                machine_id: str | None = None) -> str:
        """A machine described by hand, given the read-only account alone
        (ADR-0031 question 4): checked as nervus will use it, with the
        known_hosts file's keys, and recorded."""
        host = self.described().get(code.name)
        if host is None or self.connect_described is None or self.machine_accounts is None:
            raise Refused(409, f"{code.name} is not a machine described by hand in this nervus's inventory now")
        if why_none is not None:
            raise Refused(422, f"{code.name} cannot have a read-only account: {why_none}")
        if made.readonly == host.agent_user or made.readonly in set(self.taken(code.name)):
            raise Refused(409, f"{made.readonly} is the account {code.name}, or another entry of hosts.yaml at its "
                               f"address, is described with, not a second one")
        certs.take(certs.Route(code.name, made.readonly, True, "read-only"))
        try:
            conn = await self.connect_described(host)
        except asyncssh.PermissionDenied:
            raise Refused(422, f"nervus checked {code.name} and did not record it: it refused nervus's key for "
                               f"{made.readonly}") from None
        except (OSError, asyncio.TimeoutError, asyncssh.Error) as exc:
            raise Refused(422, f"nervus checked {code.name} and did not record it: no SSH there "
                               f"({type(exc).__name__})") from None
        try:
            result = await conn.run(CHECK_READONLY, check=False, timeout=CHECK_SECONDS)
        except (OSError, asyncio.TimeoutError, asyncssh.Error) as exc:
            raise Refused(422, f"nervus checked {code.name} and did not record it: the check did not finish "
                               f"({type(exc).__name__})") from None
        finally:
            conn.close()
        seen = str(result.stdout or "").split()
        words, groups = (seen[:seen.index("groups")], seen[seen.index("groups") + 1:]) if "groups" in seen \
            else (seen, [])
        why = check_failed("read-only", words, made.readonly)
        if why is not None:
            raise Refused(422, f"nervus checked {code.name} and did not record it: {why}")
        groups = accounts.groups_shown(g for g in groups if g != made.readonly)
        try:
            self.machine_accounts.record(code.name, enrolled_at=None, readwrite=None, readonly=made.readonly,
                                         groups=groups, why_none=None, made=made_here, machine_id=machine_id)
        except Exception as exc:  # nothing was recorded
            raise Refused(500, f"nervus could not record {code.name}'s read-only account ({type(exc).__name__}), "
                               f"so it did not add the machine's read-only account") from exc
        return (f"nervus: {code.name} has the read-only account {made.readonly}"
                + (f", in {', '.join(groups)}" if groups else "")
                + ". In nervus's page, a token can now be read-only there.\n")

    async def _check(self, address: str, level: str, keys: tuple[str, ...], route=None) -> str | None:
        if route is not None:
            seen, why = await self._login(address, keys, route, CHECK)
            return why if why is not None else check_failed(level, seen, route.username)
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
