#!/bin/bash
# install.sh -- install nervus on the machine it will run on (ADR-0023), or
# upgrade it there (ADR-0029).
#
#   sudo ./install.sh --address <nervus's address> [--name <nervus's name>]... [--yes]
#   sudo ./install.sh --restore <backup> --address <nervus's address> [--name <nervus's name>]... [--yes]
#   sudo ./install.sh --proxmox --address <nervus's address> [--yes]
#   sudo ./install.sh --upgrade [--yes]
#   sudo ./install.sh --back [--yes]
#
# Run as root, from this repository's top folder, on nervus's own machine: Linux
# with systemd. It installs exactly the committed tree it sits in, and does what
# docs/install.md's "By hand" does: nervus's account, the code and
# its venv, its folders, its SSH key, its TLS authority and certificate, its
# service, and its off switch, with an empty inventory and token file. Then it
# starts nervus, makes the recovery key every backup is locked to (ADR-0027),
# whose private half it prints once, and a timer that backs nervus up once a
# day; and prints the root's fingerprint and a sign-in link.
#
# The code goes in a folder of its own, /opt/nervus/releases/<number>-<code>,
# named by tools/release-name for the tree's release number and a code worked
# out from its files, and its venv is built inside it; /opt/nervus/.venv is a
# link to that venv, so the service and every command keep their paths
# (ADR-0029 question 3a). The code is root's: nervus's account owns only its
# secrets, the transfer folder, the inventory and its log (question 12).
#
# --restore <backup> installs the same way, but makes no keys: it puts back the
# backup's, with its database and audit log (`nervus-ctl restore`, which asks
# for the recovery key), and nervus starts in lockdown. Install at the same
# name the backup's nervus had: its clients trust that name.
#
# It leaves to you: tokens, issued in nervus's web UI; the machines nervus
# reaches (docs/install.md step 3, by hand until enrollment exists); and,
# with a Proxmox host, the root scripts that run on that host. Once those have
# written nervus's Proxmox settings, `--proxmox` adds the two flags nervus needs.
#
# --address is the address your clients and VMs reach nervus at; it goes into
# nervus's certificate, and VMs fetch uploads from it. --name adds a name to the
# certificate too, if your network gives nervus one; sign-in links then use it.
#
# --upgrade, run from a newer tree (a clone brought up to date with git pull,
# or a newer archive unpacked in a folder of its own), upgrades the nervus this
# installer installed here: it builds the new release beside the running one,
# makes a backup, switches nervus to the new release, and checks that nervus
# answers its clients; if it does not, or a step after the stop fails, or the
# run is interrupted, it goes back to the release before by itself. It keeps
# the release before, refuses an older release, and says "nothing to do" for the
# one installed. Its address, keys, tokens and data stay as they are, so no
# client's configuration changes (ADR-0029).
#
# --back puts back the release kept from the last upgrade, on your word, as an
# upgrade that does not come up does by itself. It keeps the database as it is,
# and is refused once a migration has run, since that release could not read it.
#
# It shows what it will do and waits for "yes" (or --yes). It changes nothing
# if anything it needs is missing, if this folder has uncommitted changes or a
# release number not of the form 0.2.0, or, without --upgrade, if nervus is
# already installed here: it then says which release runs and how to upgrade.
#
# NERVUS_INSTALL_ROOT puts every system path under a folder, for its tests only.
set -euo pipefail
# What it makes is for nervus's account to read, whatever the umask of the shell it was run from,
# which sudo passes on: from a strict one, a venv only root can read (procedure 051, finding 1).
umask 022

R=${NERVUS_INSTALL_ROOT:-}
OPT=$R/opt/nervus
VENV=$OPT/.venv
UNIT_DIR=$R/etc/systemd/system
UNIT=$UNIT_DIR/nervus.service
DROPIN=$UNIT_DIR/nervus.service.d/instance.conf
LOGDIR=$R/var/log/nervus
STATE=$R/var/lib/nervus
MARKER='# Written by install.sh (ADR-0023).'
TREE=$(cd "$(dirname "$0")" && pwd)

say() { printf '%s\n' "$*"; }
ok() { printf '  ok    %s\n' "$*"; }
complain() { printf 'install.sh: %s\n' "$*" >&2; }
die() { complain "$*"; exit 1; }

# --- arguments --------------------------------------------------------------------

ADDRESS= YES= PROXMOX= RESTORE= UPGRADE= BACK=
NAMES=()
while [ $# -gt 0 ]; do
  case $1 in
    --address) ADDRESS=${2:-}; shift 2 ;;
    --name) NAMES+=("${2:-}"); shift 2 ;;
    --yes) YES=1; shift ;;
    --proxmox) PROXMOX=1; shift ;;
    --restore) RESTORE=${2:-}; shift 2 ;;
    --upgrade) UPGRADE=1; shift ;;
    --back) BACK=1; shift ;;
    -h|--help) sed -n '2,60p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1 (see --help)" ;;
  esac
done
[ -z "$RESTORE" ] || [ -z "$PROXMOX" ] || die "--restore and --proxmox are separate steps: restore first, then --proxmox"
if [ -n "$UPGRADE" ]; then
  # The installation keeps its address and names, in its certificate and its drop-in.
  [ -z "$ADDRESS$RESTORE$PROXMOX" ] && [ ${#NAMES[@]} -eq 0 ] \
    || die "--upgrade takes no --address, --name, --restore or --proxmox: the installation keeps its own"
fi
if [ -n "$BACK" ]; then
  [ -z "$ADDRESS$RESTORE$PROXMOX$UPGRADE" ] && [ ${#NAMES[@]} -eq 0 ] \
    || die "--back takes no --address, --name, --restore, --proxmox or --upgrade: the installation keeps its own"
fi
if [ -n "$RESTORE" ]; then
  [ -f "$RESTORE" ] || die "--restore $RESTORE: no such file"
  RESTORE="$(cd "$(dirname "$RESTORE")" && pwd)/$(basename "$RESTORE")"
fi
if [ -z "$UPGRADE$BACK" ]; then
  [ -n "$ADDRESS" ] || die "give --address, the address your clients and VMs reach nervus at (see --help)"
  python3 -c 'import ipaddress, sys; ipaddress.ip_address(sys.argv[1])' "$ADDRESS" 2>/dev/null \
    || die "--address $ADDRESS is not an IP address"
fi
for n in ${NAMES[@]+"${NAMES[@]}"}; do
  [[ $n =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || die "--name $n is not a DNS name"
done
case $ADDRESS in *:*) URL_HOST="[$ADDRESS]" ;; *) URL_HOST=$ADDRESS ;; esac
UI_HOST=${NAMES[0]:-$URL_HOST}

confirm() {
  [ -n "$YES" ] && return 0
  printf 'Type yes to go ahead: '
  read -r answer || answer=
  [ "$answer" = yes ] || die "nothing changed"
}

wait_active() {
  local i
  for i in $(seq 1 15); do
    systemctl is-active --quiet nervus && return 0
    sleep 1
  done
  journalctl -u nervus -n 30 --no-pager >&2 || true
  die "nervus did not start; its journal is above"
}

# build_release: the tree named $RELEASE ($NAMED) into its own folder, $REL, with its own venv;
# on failure, says what failed and $UNFINISHED. The install and the upgrade build alike.
build_release() {
  install -d -m 0755 "$OPT" "$OPT/releases" "$REL"
  # Unpacked as root's, whoever owned the tree: tar run as root keeps the owners it reads, a plain
  # copy's own (ADR-0029 question 12).
  if [ -e "$TREE/.git" ]; then
    git -C "$TREE" archive HEAD | tar -x -C "$REL" --no-same-owner \
      || die "the code could not be copied into $REL, as it says above. $UNFINISHED"
    rm -f "$REL/hosts.yaml"   # never a copy's own inventory
  else
    tar -C "$TREE" --exclude=./secrets --exclude=./.venv --exclude=./transfer --exclude=./releases \
      --exclude=./hosts.yaml --exclude=./.release --exclude=__pycache__ -cf - . | tar -x -C "$REL" --no-same-owner \
      || die "the code could not be copied into $REL, as it says above. $UNFINISHED"
  fi
  # tar run as root gives the folder it unpacks into the mode of the stream's own top folder, which
  # a plain copy's stream has ('./'): the release's folder is 0755 whatever the tree's was.
  chmod 0755 "$REL"
  # What was copied is the release that was named: no file lost, gained or changed on the way.
  [ "$(python3 -I "$TREE/tools/release-name" --full "$REL")" = "$NAMED" ] \
    || die "the code copied into $REL is not the tree named $RELEASE: a file was lost, gained or changed on the way. $UNFINISHED"
  # The venv is built where it stays and filled by its own pip, never through the link: its scripts
  # name the path they were installed at, so a venv cannot be moved (procedure 050).
  python3 -m venv "$REL/.venv"
  "$REL/.venv/bin/pip" install --quiet "$REL" \
    || die "pip could not install nervus and its libraries into $REL/.venv, as it says above; the package index may be out of reach. $UNFINISHED"
}

# never_ran_here: an install was begun here and nervus has never run: the installer's folders, and
# none of what nervus makes as it runs (its database, its backups, its audit log) or the installer
# once it has started (the recovery key). Only then is removing what is here ever offered: a machine
# may hold an earlier installation's backups, the very ones a restore is being run from.
never_ran_here() {
  [ -d "$OPT/releases" ] && [ ! -e "$STATE/nervus.db" ] && [ ! -e "$STATE/backups" ] \
    && [ ! -e "$LOGDIR/audit.jsonl" ] && [ ! -e "$OPT/secrets/recovery.pub" ]
}

# unfinished_install: that the install here did not finish, and exactly what to remove to start
# again, which the next run could otherwise take for an installed nervus (procedure 051, finding 2).
unfinished_install() {
  local path made=()
  for path in "$OPT" "$LOGDIR" "$STATE/switches.yaml" "$UNIT" "$UNIT.d" "$UNIT_DIR/nervus-backup.service" "$UNIT_DIR/nervus-backup.timer"; do
    if [ -e "$path" ]; then made+=("$path"); fi
  done
  say "install.sh: the install here did not finish, and nervus has never run here, so nothing of yours is in it."
  say "To start again, remove what it made, then run install.sh again:"
  if [ -e "$UNIT" ]; then say "  sudo systemctl disable --now nervus"; fi
  say "  sudo rm -rf ${made[*]}"
  if id nervus >/dev/null 2>&1; then say "  sudo userdel nervus"; fi
}

# stopped_installing: run as an install ends, until nervus has started: if it stopped, what to do.
stopped_installing() {
  if never_ran_here; then
    unfinished_install >&2
  else
    say "install.sh: the install here did not finish. nervus has run here, so what it keeps is left as it is; read what stopped it, above." >&2
  fi
}

# point_at <release>: /opt/nervus/.venv a link to that release's venv, replaced in one step, so
# that whatever starts nervus finds one release or the other, never neither (ADR-0029 question 3a).
point_at() {
  rm -f "$VENV.new"
  ln -s "releases/$1/.venv" "$VENV.new" \
    && python3 -I -c 'import os, sys; os.replace(sys.argv[1], sys.argv[2])' "$VENV.new" "$VENV"
}

# below <number> <number>: whether the first release number is below the second, part by part as
# numbers (0.9.0 is below 0.10.0); both are three numbers with no leading zeros.
below() {
  local a b i
  IFS=. read -ra a <<<"$1"
  IFS=. read -ra b <<<"$2"
  for i in 0 1 2; do
    [ "${a[i]}" -lt "${b[i]}" ] && return 0
    [ "${a[i]}" -gt "${b[i]}" ] && return 1
  done
  return 1
}

# judge_up <since>: whether nervus, started at <since>, is up as its clients need it, not merely
# active (ADR-0029 question 7): active within 20 seconds, on the same main process 5 seconds
# later, its MCP endpoint and web UI answering over HTTPS checked against its own root
# (tools/check-up, which gives it up to a minute to begin listening), still on that main process, and
# nothing in its start lines saying it refuses clients. If not, $WHY says why.
judge_up() {
  local i pid again journal
  WHY=
  for i in $(seq 1 20); do systemctl is-active --quiet nervus && break; sleep 1; done
  systemctl is-active --quiet nervus || { WHY="it did not become active within 20 seconds"; return 1; }
  pid=$(systemctl show -p MainPID --value nervus)
  sleep 5
  again=$(systemctl show -p MainPID --value nervus)
  [ "$pid" != 0 ] && [ "$pid" = "$again" ] || { WHY="it did not stay running (main process $pid, then $again, where 0 is none)"; return 1; }
  WHY=$(python3 -I "$TREE/tools/check-up" "$OPT/secrets/tls-root.crt" "$MCP_PORT" "$UI_PORT" 2>&1) || return 1
  # That can take a while, and a release that restarts may answer between one fall and the next.
  again=$(systemctl show -p MainPID --value nervus)
  [ "$pid" = "$again" ] || { WHY="it restarted while it was being checked (main process $pid, then $again)"; return 1; }
  # Read first, then search: with pipefail, `journalctl | grep -q` can say "not found" when grep
  # stops early on a match, the one case this must catch.
  journal=$(journalctl -u nervus --since "$1" --no-pager -q 2>/dev/null || true)
  if grep -q 'off switch is fixed' <<<"$journal"; then
    WHY="it says its off switch is unreadable, so it refuses every client"; return 1
  fi
  if grep -q -- '--proxmox ' "$DROPIN" && grep -q 'no inventory entry is marked' <<<"$journal"; then
    WHY="it has no Proxmox host: no inventory entry is marked hypervisor: proxmox"; return 1
  fi
  WHY=
}

# start_and_judge: nervus started on the release the link names, and judged. STARTED, when.
start_and_judge() {
  STARTED=$(date '+%Y-%m-%d %H:%M:%S')
  systemctl start nervus || true
  judge_up "$STARTED"
}

# last_words: nervus's own last lines since it was started, which say why it is not up in words a
# person can act on: a release's traceback, or systemd's "Permission denied" (procedure 051, finding 4).
last_words() {
  say "Its journal since it started, the last lines:"
  journalctl -u nervus --since "$STARTED" -n 15 --no-pager -q -o cat 2>/dev/null | cut -c1-200 | sed 's/^/    /' || true
}

# find_installed: WAS, the release an installation by this installer runs: the one its link names
# (ADR-0029 question 3a), in the installer's own words, its drop-in's first line the installer's.
# Empty for any other installation.
find_installed() {
  WAS=
  if [[ $(readlink "$VENV" 2>/dev/null) =~ ^releases/((0|[1-9][0-9]*)(\.(0|[1-9][0-9]*)){2}-[0-9a-f]{12})/\.venv$ ]] \
      && [ -d "$OPT/releases/${BASH_REMATCH[1]}/.venv" ] && [ "$(head -n 1 "$DROPIN" 2>/dev/null)" = "$MARKER" ]; then
    WAS=${BASH_REMATCH[1]}
  fi
}

# dropin_for <unit file>: the installer's drop-in for that unit, on standard output: its command
# line, then the installation's own flags, which are whatever follows the installed unit's command
# line in the drop-in now (ADR-0029 question 5a). A drop-in that is not as the installer writes it
# fails, saying where it differs.
dropin_for() {
  python3 -I - "$DROPIN" "$UNIT" "$1" "$MARKER" <<'PY'
import re, sys
dropin, old_unit, new_unit, marker = sys.argv[1:5]

def command_line(path):
    """A unit's ExecStart, as the installer copies it into the drop-in: from its first line to the
    first that does not end in a backslash, which is given one there, for the flags after it."""
    lines, on = [], False
    for line in open(path).read().splitlines():
        on = on or line.startswith("ExecStart=")
        if on:
            lines.append(line)
            if not line.endswith("\\"):
                return lines[:-1] + [lines[-1] + " \\"]
    sys.exit(f"{path} has no ExecStart")

head = [marker, "[Service]", "ExecStart="]
written = open(dropin).read().splitlines()
expected = head + command_line(old_unit)
for n, line in enumerate(expected):
    if n >= len(written) or written[n] != line:
        sys.exit(f"its line {n + 1} is {written[n] if n < len(written) else 'missing'!r}, where install.sh "
                 f"writes {line!r}: the old unit's command line, then the installation's own flags")
flags = written[len(expected):]
if not flags or flags[-1].endswith("\\") or not all(re.fullmatch(r"    --[a-z][a-z-]* \S+ \\", f) for f in flags[:-1]) \
        or not re.fullmatch(r"    --[a-z][a-z-]* \S+", flags[-1]):
    sys.exit(f"after the old unit's command line, its lines are not the installation's own flags as install.sh "
             f"writes them, one '    --flag value' to a line: {flags!r}")
print("\n".join(head + command_line(new_unit) + flags))
PY
}

# ports_of <drop-in>: MCP_PORT and UI_PORT, which judge_up asks nervus on; fails if it gives none.
ports_of() {
  MCP_PORT=$(sed -n 's/^.*--bind-port \([0-9][0-9]*\).*$/\1/p' <<<"$1" | tail -n 1)
  UI_PORT=$(sed -n 's/^.*--ui-port \([0-9][0-9]*\).*$/\1/p' <<<"$1" | tail -n 1)
  [ -n "$MCP_PORT" ] && [ -n "$UI_PORT" ]
}

# place <file> <unit>: a unit file put in place in one step, written beside and renamed over. `install`
# alone removes the one there before it writes, so a full disk would leave no unit to start nervus with,
# going back included. systemd reads no file named .new as a unit.
place() {
  install -m 0644 "$1" "$2.new" && mv -f "$2.new" "$2" && return 0
  rm -f "$2.new"
  return 1
}

# switch_to <release> <drop-in>: that release current, with its units and that drop-in, and systemd
# told. nervus is stopped first. The link, each unit and the drop-in each change in one step. Every step
# is tried, whichever fails, and it fails if any did: going back needs all of them it can get.
switch_to() {
  local folder=$OPT/releases/$1 name failed=
  point_at "$1" || failed=1
  place "$folder/deploy/nervus.service" "$UNIT" || failed=1
  for name in nervus-backup.service nervus-backup.timer; do
    place "$folder/deploy/$name" "$UNIT_DIR/$name" || failed=1
  done
  # Written beside and renamed over, so the drop-in is the old one or the new one, never half of one;
  # systemd reads only a drop-in's .conf files, so the one beside is never read. 0644 as the install
  # makes it: every backup reads it, as nervus's account. By cat, not by bash's own printf: going back
  # with a terminal that has gone, some C libraries keep the lines bash could not write in its buffer,
  # and its printf would write them here.
  { cat > "$DROPIN.new" <<<"$2" && chmod 0644 "$DROPIN.new" && mv -f "$DROPIN.new" "$DROPIN"; } || failed=1
  systemctl daemon-reload || failed=1
  [ -z "$failed" ]
}

# hold_off_backups: the daily backup let finish, and held off until this run ends, however it ends.
hold_off_backups() {
  local i
  systemctl stop nervus-backup.timer
  trap ending EXIT
  for i in $(seq 1 600); do systemctl is-active --quiet nervus-backup.service || break; sleep 1; done
}

GOES_BACK= SWITCHED= STARTED= COPY_DB=

# ending: how a run that has held off the backups ends, however it ends. Before the stop and once nervus
# is judged up, it only lets the backups go on; between them it goes back first (question 7). Nothing
# interrupts that and nothing that fails stops it, a terminal that has gone included: it is the last chance.
ending() {
  local status=$?
  trap '' HUP INT PIPE TERM
  if [ -n "$GOES_BACK" ]; then
    set +eu
    "$GOES_BACK"
    status=1
  fi
  systemctl start nervus-backup.timer || true
  exit "$status"
}

# goes_back_with <function>: from here, at the stop, until nervus is judged up and GOES_BACK is emptied,
# any way this run ends calls that function: a step that fails, which set -e ends it at; a signal, taken
# once the step under way ends; or the judge. NOT_UP says why, each step setting it first.
goes_back_with() {
  GOES_BACK=$1
  trap 'NOT_UP="this run was stopped by a signal"; exit 1' HUP INT PIPE TERM
}

# put_back <release>: nervus on the release it was on, and judged: stopped, whatever it is doing; that
# release current again if the switch began; the database's copy put back if the new release may have
# moved on from it, removed if it never started, the database then being as it was. Every step is tried,
# whichever fails, and AS_BEFORE says whether all of them did. Whether nervus is up is what it returns.
put_back() {
  AS_BEFORE="and runs as before"
  systemctl stop nervus || true
  if [ -n "$SWITCHED" ]; then
    switch_to "$1" "$OLD_DROPIN" || AS_BEFORE="and runs, but not all of it could be put back, as it says above"
  fi
  if [ -n "$COPY_DB" ] && [ -n "$STARTED" ]; then
    # A stale write-ahead file would be read into the copy put back.
    { rm -f "$DB-wal" "$DB-shm" && mv -f "$COPY_DB" "$DB"; } \
      || AS_BEFORE="and runs, but not all of it could be put back, as it says above"
  elif [ -n "$COPY_DB" ]; then
    rm -f "$COPY_DB"
  fi
  start_and_judge
}

# database_version: the version of nervus's database, read as nervus's account; nothing if it has
# none yet. schema_of <tree>: the version that tree's release knows.
database_version() {
  [ -e "$STATE/nervus.db" ] || return 0
  runuser -u nervus -- python3 -I -c 'import pathlib, sqlite3, sys
print(sqlite3.connect(pathlib.Path(sys.argv[1]).as_uri() + "?mode=ro", uri=True).execute("PRAGMA user_version").fetchone()[0])' "$STATE/nervus.db"
}
schema_of() {
  sed -n 's/^SCHEMA_VERSION = \([0-9][0-9]*\)$/\1/p' "$1/src/nervus/database.py"
}

# read_off_switch <tree>: what that tree's rule says of the off switch, in SWITCH_NOW; it needs only the
# running release's python. A switch nervus cannot read stops the run here, before anything changes:
# every release refuses every client while it is so, and nothing may overwrite a lock nobody can read.
read_off_switch() {
  SWITCH_NOW=$("$VENV/bin/python" "$1/tools/ensure-switches" --check "$STATE/switches.yaml" 2>&1) \
    || die "${SWITCH_NOW#ensure-switches: STOP  }; nothing changed"
}

# kept_release <running release>: KEPT, the release kept from the last upgrade (ADR-0029 question
# 7b). No record names it (question 3a), so the numbers do: the other release here that is whole,
# whose number is below the running one's. One above is what a failed upgrade, or going back, left;
# another build of the same number counts only if none is below.
kept_release() {
  local folder name number=${1%-*} under=() same=() found=()
  for folder in "$OPT/releases"/*; do
    name=${folder##*/}
    [[ $name =~ ^(0|[1-9][0-9]*)(\.(0|[1-9][0-9]*)){2}-[0-9a-f]{12}$ ]] && [ "$name" != "$1" ] \
      && [ -x "$folder/.venv/bin/nervus" ] || continue
    if below "${name%-*}" "$number"; then
      under+=("$name")
    elif [ "${name%-*}" = "$number" ]; then
      same+=("$name")
    fi
  done
  if [ ${#under[@]} -gt 0 ]; then found=("${under[@]}"); elif [ ${#same[@]} -gt 0 ]; then found=("${same[@]}"); fi
  [ ${#found[@]} -gt 0 ] \
    || die "no release is kept here to go back to: $1 has none before it. To go to a newer release, upgrade from its tree; nothing changed"
  [ ${#found[@]} -eq 1 ] \
    || die "more than one release here could be the one kept (${found[*]}): remove from $OPT/releases those not wanted; nothing changed"
  KEPT=${found[0]}
}

# --- --proxmox: the one change made to an installed nervus -----------------------

if [ -n "$PROXMOX" ]; then
  [ "$(id -u)" = 0 ] || [ -n "$R" ] || die "run it as root"
  grep -qxF "$MARKER" "$DROPIN" 2>/dev/null || die "nervus was not installed by install.sh here; add the flags by hand (docs/install.md)"
  grep -q -- '--proxmox ' "$DROPIN" && die "the drop-in already has --proxmox; nothing changed"
  [ -f "$OPT/secrets/proxmox.yaml" ] || die "no $OPT/secrets/proxmox.yaml yet: run tools/proxmox-access on the Proxmox host first"
  "$VENV/bin/python" - "$OPT/hosts.yaml" <<'PY' || die "no entry in hosts.yaml is marked 'hypervisor: proxmox' yet (docs/install.md, A Proxmox host)"
import sys, yaml
hosts = (yaml.safe_load(open(sys.argv[1])) or {}).get("hosts") or []
sys.exit(0 if any(isinstance(h, dict) and h.get("hypervisor") == "proxmox" for h in hosts) else 1)
PY
  say "install.sh will add to $DROPIN:"
  say "    --proxmox /opt/nervus/secrets/proxmox.yaml"
  say "    --upload-pull-url https://$URL_HOST:8000/upload-pull"
  say "and restart nervus."
  confirm
  "$VENV/bin/python" - "$DROPIN" "https://$URL_HOST:8000/upload-pull" <<'PY'
import sys
path, pull = sys.argv[1], sys.argv[2]
text = open(path).read().rstrip("\n")
open(path, "w").write(text + " \\\n    --proxmox /opt/nervus/secrets/proxmox.yaml \\\n"
                      f"    --upload-pull-url {pull}\n")
PY
  systemctl daemon-reload
  systemctl restart nervus
  wait_active
  if journalctl -u nervus -n 30 --no-pager | grep -q "no inventory entry is marked"; then
    die "nervus started but has no Proxmox host; see its journal"
  fi
  ok "nervus restarted with its Proxmox settings"
  exit 0
fi

# --- --back: to the release kept from the last upgrade (ADR-0029 question 7b) ------

# It installs nothing from this tree, so what a tree must be for an install or an upgrade does not
# apply: it needs only this script and tools/check-up, from a clone in any state or from a release's
# own folder.
if [ -n "$BACK" ]; then
  say "install.sh: reading this machine; nothing changes until you say yes."
  [ "$(id -u)" = 0 ] || [ -n "$R" ] || die "run it as root"
  [ -d "$R/run/systemd/system" ] || die "systemd is not running here; this preview runs nervus under systemd (docs/install.md, Where nervus may run)"
  find_installed
  if never_ran_here; then unfinished_install >&2; exit 1; fi
  [ -n "$WAS" ] || die "the nervus here was not installed by this installer in release folders ($VENV is not its link into $OPT/releases, or its drop-in's first line is not install.sh's), so it has no release kept to go back to; nothing changed"
  NOW=$WAS
  kept_release "$NOW"
  FOLDER=$OPT/releases/$KEPT

  # While the database's version is one that release knows: once a migration has run it would refuse it.
  DB_KEPT=$(schema_of "$FOLDER")
  [[ $DB_KEPT =~ ^[0-9]+$ ]] || die "$FOLDER/src/nervus/database.py gives no SCHEMA_VERSION; nothing changed"
  DB_NOW=$(database_version) || die "the database, $STATE/nervus.db, cannot be read as nervus's account; nothing changed"
  if [ -n "$DB_NOW" ] && [ "$DB_NOW" -gt "$DB_KEPT" ]; then
    die "the database's version, $DB_NOW, is newer than $KEPT knows, $DB_KEPT: a migration has run since the upgrade, so going back is refused. Only the backup made before the upgrade holds a database that release can use, and restoring it loses everything done since (docs/install.md, Backups); nothing changed"
  fi

  OLD_DROPIN=$(cat "$DROPIN")
  NEW_DROPIN=$(dropin_for "$FOLDER/deploy/nervus.service") \
    || die "$DROPIN is not as install.sh writes it, so going back cannot write it again: put it right; nothing changed"
  ports_of "$NEW_DROPIN" || die "$KEPT's command line gives no --bind-port or no --ui-port to check nervus on; nothing changed"
  [ -f "$OPT/secrets/tls-root.crt" ] \
    || die "no $OPT/secrets/tls-root.crt, nervus's root, which nervus is checked against once it starts; nothing changed"
  read_off_switch "$FOLDER"

  say ""
  say "It will go back from $NOW to $KEPT, the release kept from the last upgrade:"
  say "  - nervus stopped and started on $KEPT, which takes a few seconds: each client's"
  say "    session ends and it connects again, and a call in flight then is cut"
  say "  - the database kept as it is, at version ${DB_NOW:-none yet}: $KEPT ignores any table it does not know"
  if [ "$NEW_DROPIN" = "$OLD_DROPIN" ]; then
    say "  - the service, and the backup's service and timer, from $KEPT; its drop-in, the same"
  else
    say "  - the service, and the backup's service and timer, from $KEPT; its drop-in written again"
    say "    with its command line and this installation's own flags. Now:"
    printf '%s\n' "$OLD_DROPIN" | sed 's/^/      /'
    say "    then:"
    printf '%s\n' "$NEW_DROPIN" | sed 's/^/      /'
  fi
  say "  - then nervus checked; if it is not up as its clients need it, or a step after the stop fails,"
  say "    it returns to $NOW by itself"
  say "  - $NOW's folder stays in $OPT/releases until the next upgrade"
  say ""
  confirm

  hold_off_backups
  "$VENV/bin/nervus-ctl" --unit "$UNIT" upgrade-record back "$KEPT" "$NOW" --why "on the operator's word: install.sh --back" >/dev/null \
    || die "the first record of going back could not be written to nervus's audit log, so it does not begin (ADR-0001 s10). Nothing was stopped: nervus runs on, on $NOW"

  # Not up, as a failed upgrade is not, or anything else on the way: back where it was, by itself (question 7).
  back_returns() {
    say "nervus is not up on $KEPT: $NOT_UP"
    [ -z "$STARTED" ] || last_words
    say "Returning to $NOW."
    if put_back "$NOW"; then
      "$VENV/bin/nervus-ctl" --unit "$UNIT" upgrade-record up "$KEPT" "$NOW" --why "returned to it: $KEPT was not up: $NOT_UP" >/dev/null \
        || say "  NOTE  nervus is back, but its record of returning could not be written to its audit log"
      complain "going back did not finish, so nervus returned to $NOW by itself, $AS_BEFORE. Why: $NOT_UP. nervus's journal (journalctl -u nervus) is left for reading"
    else
      complain "NERVUS IS DOWN: it was not up on $KEPT ($NOT_UP), nor, returned, on $NOW ($WHY). Read its journal: journalctl -u nervus -n 50. Restoring a backup on this machine is docs/install.md, Backups"
    fi
  }
  NOT_UP="systemctl could not stop nervus, as it says above"
  goes_back_with back_returns
  systemctl stop nervus
  NOT_UP="the switch to $KEPT failed, as it says above"
  SWITCHED=1
  switch_to "$KEPT" "$NEW_DROPIN"
  if start_and_judge; then
    GOES_BACK=
    ok "nervus is up on $KEPT: active and steady, answering MCP and its web UI as itself"
    "$VENV/bin/nervus-ctl" --unit "$UNIT" upgrade-record back "$KEPT" "$NOW" --why "done: nervus runs $KEPT again" >/dev/null \
      || say "  NOTE  nervus is up, but the last record of going back could not be written to its audit log"
    say ""
    say "nervus has gone back, from $NOW to $KEPT, and is running. No client's configuration changes."
    say "$NOW's folder stays in $OPT/releases until the next upgrade; to go forward again, run"
    say "install.sh --upgrade from its tree."
    exit 0
  fi
  NOT_UP=$WHY
  exit 1
fi

# --- 1. read, change nothing -------------------------------------------------------

say "install.sh: reading this machine; nothing changes until you say yes."
[ "$(id -u)" = 0 ] || [ -n "$R" ] || die "run it as root"
[ -d "$R/run/systemd/system" ] || die "systemd is not running here; this preview runs nervus under systemd (docs/install.md, Where nervus may run)"

INSTALLED=
if [ -e "$OPT" ] || [ -e "$UNIT" ] || id nervus >/dev/null 2>&1; then INSTALLED=1; fi
[ -n "$INSTALLED" ] || [ -z "$UPGRADE" ] \
  || die "nervus is not installed here, so there is nothing to upgrade: install it, without --upgrade; nothing changed"

SOURCE=
if [ -e "$TREE/.git" ]; then
  command -v git >/dev/null 2>&1 || die "this folder is a git clone, but git is not installed"
  # As root, under sudo, whatever git writes in a person's clone becomes root's: `status` leaves the
  # clone as it found it, its index not refreshed (procedure 051, finding 1).
  [ -z "$(GIT_OPTIONAL_LOCKS=0 git -C "$TREE" status --porcelain --untracked-files=no)" ] \
    || die "this clone has uncommitted changes; install.sh installs only a committed tree. Commit or discard them"
  SOURCE="commit $(git -C "$TREE" rev-parse --short HEAD) of $TREE"
else
  [ -f "$TREE/pyproject.toml" ] && [ -d "$TREE/src/nervus" ] || die "$TREE is not nervus's repository"
  SOURCE="the tree at $TREE (not a git clone)"
fi

MISSING=() PACKAGES=()
if ! command -v python3 >/dev/null 2>&1; then
  MISSING+=("python3, 3.11 or later"); PACKAGES+=(python3 python3-venv)
elif ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))'; then
  die "Python $(python3 -c 'import platform; print(platform.python_version())') is too old; nervus needs 3.11 or later"
elif ! python3 -c 'import venv, ensurepip' 2>/dev/null; then
  MISSING+=("Python's venv"); PACKAGES+=(python3-venv)
fi
command -v ssh-keygen >/dev/null 2>&1 || { MISSING+=("ssh-keygen"); PACKAGES+=(openssh-client); }
command -v useradd >/dev/null 2>&1 || { MISSING+=("useradd"); PACKAGES+=(passwd); }
command -v runuser >/dev/null 2>&1 || { MISSING+=("runuser"); PACKAGES+=(util-linux); }
command -v age >/dev/null 2>&1 && command -v age-keygen >/dev/null 2>&1 || { MISSING+=("age"); PACKAGES+=(age); }
if [ ${#MISSING[@]} -gt 0 ] && ! command -v apt-get >/dev/null 2>&1; then
  die "missing, and no apt-get to install them with: ${MISSING[*]}. Install them, then run it again"
fi

# The folder the code goes in is named for its release, the number and the code of exactly what
# will be installed: a clone's committed tree, or the plain copy (ADR-0029 question 3a).
# release-name runs on the machine's own python3, so it comes after the checks above: the address
# check ran python3, and the version check refused one older than 3.11, which has no tomllib to
# read pyproject.toml with.
if [ -e "$TREE/.git" ]; then
  NAMED=$(git -C "$TREE" archive HEAD | python3 -I "$TREE/tools/release-name" --full --archive) \
    || die "this clone's release cannot be named (release-name says why, above); nothing changed"
else
  NAMED=$(python3 -I "$TREE/tools/release-name" --full "$TREE") \
    || die "this tree's release cannot be named (release-name says why, above); nothing changed"
fi
read -r RELEASE NUMBER _ <<<"$NAMED"
REL=$OPT/releases/$RELEASE

find_installed
if never_ran_here; then unfinished_install >&2; exit 1; fi
if [ -n "$INSTALLED" ] && [ -z "$UPGRADE" ]; then
  die "nervus is already installed here ($OPT, $UNIT or the account nervus exists); nothing changed. It runs ${WAS:-a release not installed by this installer in release folders}, and this tree holds $RELEASE.$([ -n "$WAS" ] && printf ' To upgrade it to this tree: sudo %s/install.sh --upgrade' "$TREE")"
fi

# --- --upgrade: from the release installed here to this tree's (ADR-0029) ----------

if [ -n "$UPGRADE" ]; then
  # Only an installation this installer made in release folders (question 8a); any other is
  # upgraded by hand.
  [ -n "$WAS" ] || die "the nervus here was not installed by this installer in release folders ($VENV is not its link into $OPT/releases, or its drop-in's first line is not install.sh's), so it is upgraded by hand (docs/install.md); nothing changed"
  WAS_NUMBER=${WAS%-*}
  below "$NUMBER" "$WAS_NUMBER" \
    && die "this tree holds $NUMBER, older than the $WAS_NUMBER installed here: an upgrade never goes back (question 2a); nothing changed"
  [ "$RELEASE" != "$WAS" ] || die "nothing to do: this tree's release, $RELEASE, is the one installed here; nothing changed"

  # The drop-in written again (question 5a): the new unit's command line, then the installation's
  # own flags, which are whatever follows the old unit's command line in it. A drop-in that is not
  # as the installer writes it stops the upgrade, saying where it differs.
  OLD_DROPIN=$(cat "$DROPIN")
  NEW_DROPIN=$(dropin_for "$TREE/deploy/nervus.service") \
    || die "$DROPIN is not as install.sh writes it, so the upgrade cannot write it again: put it right, or upgrade by hand (docs/install.md); nothing changed"
  ports_of "$NEW_DROPIN" \
    || die "the new release's command line gives no --bind-port or no --ui-port to check nervus on; nothing changed"
  [ -f "$OPT/secrets/tls-root.crt" ] \
    || die "no $OPT/secrets/tls-root.crt, nervus's root, which nervus is checked against once it starts; nothing changed"
  read_off_switch "$TREE"

  # The database's version (question 6a): never above what the new release knows; copied first,
  # as nervus's account, where it rises, so that going back can put the copy back.
  DB=$STATE/nervus.db
  DB_NEW=$(schema_of "$TREE")
  [[ $DB_NEW =~ ^[0-9]+$ ]] || die "this tree's src/nervus/database.py gives no SCHEMA_VERSION; nothing changed"
  COPY_DB=
  DB_NOW=$(database_version) || die "the database, $DB, cannot be read as nervus's account; nothing changed"
  if [ -n "$DB_NOW" ]; then
    [ "$DB_NOW" -le "$DB_NEW" ] \
      || die "the database's version, $DB_NOW, is newer than this release knows, $DB_NEW, so it would refuse it; nothing changed"
    if [ "$DB_NOW" -lt "$DB_NEW" ]; then COPY_DB=$DB.before-$RELEASE; fi
  fi

  CHECKED=$("$VENV/bin/nervus-ctl" --unit "$UNIT" backup --last-check 2>&1) || CHECKED="unknown: $CHECKED"
  # What changed since the installed release, newest first: CHANGES.md's sections above its number,
  # up to this tree's (question 9a); and what each says each client must do.
  changes() {  # changes <all|clients>
    python3 -I - "$TREE/CHANGES.md" "$WAS_NUMBER" "$NUMBER" "$1" <<'PY'
import re, sys
path, was, now, what = sys.argv[1:5]
number = lambda text: tuple(int(part) for part in text.split("."))
release = re.compile(r"((?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2})(?: .*)?")
try:
    parts = re.split(r"^## (.*)\n?", open(path).read(), flags=re.M)
except OSError:
    sys.exit(0)
for heading, body in zip(parts[1::2], parts[2::2]):
    found = release.fullmatch(heading)
    if found and number(was) < number(found.group(1)) <= number(now):
        if what == "all":
            print(f"      ## {heading}\n" + "\n".join(f"      {line}" if line else "" for line in body.strip().splitlines()))
        else:
            says = re.search(r"^\*\*What each client must do:\*\*(.*?)(?=^\*\*|\Z)", body, re.M | re.S)
            print(f"  {found.group(1)}: " + " ".join((says.group(1) if says else "nothing said").split()))
PY
  }

  say ""
  say "It will upgrade nervus $WAS_NUMBER to $NUMBER, from $SOURCE:"
  say "  - installed now: $WAS; this tree: $RELEASE$([ "$NUMBER" = "$WAS_NUMBER" ] && printf ', the same number with other code: a build between exports')"
  if [ "$NUMBER" != "$WAS_NUMBER" ]; then
    say "  - what changed, from CHANGES.md:"
    changes all
  fi
  [ ${#PACKAGES[@]} -gt 0 ] && say "  - apt-get update, then apt-get install ${PACKAGES[*]} (missing: ${MISSING[*]})"
  [ -e "$REL" ] && say "  - $REL, here already and not the release running, removed first"
  say "  - the new release built beside the running one, root's, in $REL, while nervus serves on"
  say "  - a backup first, by the running release, into $STATE/backups; the recovery key: $CHECKED"
  say "  - nervus stopped and started on the new release, which takes a few seconds: each client's"
  say "    session ends and it connects again, and a call in flight then is cut"
  if [ -n "$COPY_DB" ]; then
    say "  - the database's version rises from $DB_NOW to $DB_NEW: it is copied first, to $COPY_DB, so that"
    say "    going back can put it back, losing what the new release wrote in the meantime"
  else
    say "  - the database kept as it is, at version ${DB_NOW:-none yet}"
  fi
  say "  - the off switch: ${SWITCH_NOW#ensure-switches: }"
  if [ "$NEW_DROPIN" = "$OLD_DROPIN" ]; then
    say "  - the service, and the backup's service and timer, from the new release; its drop-in, the same"
  else
    say "  - the service, and the backup's service and timer, from the new release; its drop-in written again"
    say "    with the new release's command line and this installation's own flags. Now:"
    printf '%s\n' "$OLD_DROPIN" | sed 's/^/      /'
    say "    then:"
    printf '%s\n' "$NEW_DROPIN" | sed 's/^/      /'
  fi
  say "  - then nervus checked; if it is not up as its clients need it, or a step after the stop fails,"
  say "    it goes back to $WAS by itself"
  say ""
  confirm

  if [ ${#PACKAGES[@]} -gt 0 ]; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${PACKAGES[@]}"
    ok "installed ${PACKAGES[*]}"
  fi

  # Built beside, nervus serving on: the step that fails most often, fetching libraries, changes
  # nothing if it fails (question 3a).
  rm -rf "$REL"
  UNFINISHED="nervus runs on as it was, on $WAS; the folder is left for reading, and the next upgrade removes it"
  build_release
  ok "the new release, $RELEASE, built beside the running one, in $REL"

  # What the new release needs and this installation lacks, made as the installer makes it ("Settled
  # already"); what exists is never replaced. Made while nervus serves on, so that a failure here stops
  # nothing, and before the backup, which then holds it.
  "$REL/.venv/bin/python" "$REL/tools/ensure-switches" --owner nervus "$STATE/switches.yaml" \
    || die "the off switch could not be kept or made, as it says above. $UNFINISHED"
  [ -e "$OPT/secrets/nervus_ed25519" ] || runuser -u nervus -- ssh-keygen -q -t ed25519 -N '' -C nervus -f "$OPT/secrets/nervus_ed25519" \
    || die "nervus's SSH key could not be made, as it says above. $UNFINISHED"
  [ -e "$OPT/secrets/nervus_ca_ed25519" ] || runuser -u nervus -- ssh-keygen -q -t ed25519 -N '' -C nervus-ca -f "$OPT/secrets/nervus_ca_ed25519" \
    || die "nervus's SSH certificate key could not be made, as it says above. $UNFINISHED"

  # The backup first, by the running release, the daily one let finish and held off till the end
  # (question 4a); then the upgrade's first record, without which it does not begin (ADR-0001 s10).
  hold_off_backups
  MADE=$("$VENV/bin/nervus-ctl" --unit "$UNIT" backup 2>&1) \
    || die "the backup did not succeed, as it says: $MADE. Nothing was stopped: nervus runs on, on $WAS"
  BACKUP=$(sed -n 's/^made \([^ ]*\) .*$/\1/p' <<<"$MADE" | head -n 1)
  ok "a backup by the running release: ${BACKUP:-$MADE}"
  "$VENV/bin/nervus-ctl" --unit "$UNIT" upgrade-record begin "$WAS" "$RELEASE" >/dev/null \
    || die "the upgrade's first record could not be written to nervus's audit log, so it does not begin (ADR-0001 s10). Nothing was stopped: nervus runs on, on $WAS"

  # Not up, or anything else on the way: back to the release before, by itself (question 7), with its
  # unit and drop-in. The new release's folder and the journal stay for reading.
  upgrade_goes_back() {
    say "nervus is not up on $RELEASE: $NOT_UP"
    [ -z "$STARTED" ] || last_words
    say "Going back to $WAS."
    if put_back "$WAS"; then
      "$VENV/bin/nervus-ctl" --unit "$UNIT" upgrade-record back "$WAS" "$RELEASE" --why "$NOT_UP" >/dev/null \
        || say "  NOTE  nervus is back, but its record of going back could not be written to its audit log"
      complain "the upgrade did not finish, so nervus went back to $WAS by itself, $AS_BEFORE. Why: $NOT_UP. $REL and nervus's journal (journalctl -u nervus) are left for reading; the next upgrade removes the folder"
    else
      complain "NERVUS IS DOWN: it was not up on $RELEASE ($NOT_UP), nor, gone back, on $WAS ($WHY). Read its journal: journalctl -u nervus -n 50. The backup made first is $BACKUP; restoring it on this machine is docs/install.md, Backups"
    fi
  }
  NOT_UP="systemctl could not stop nervus, as it says above"
  goes_back_with upgrade_goes_back
  systemctl stop nervus
  if [ -n "$COPY_DB" ]; then
    NOT_UP="the database could not be copied before its version rises, as it says above"
    rm -f "$COPY_DB"
    runuser -u nervus -- python3 -I -c 'import os, sqlite3, sys
os.umask(0o077)  # as private as the database itself
copy = sqlite3.connect(sys.argv[2]); sqlite3.connect(sys.argv[1]).backup(copy); copy.close()' "$DB" "$COPY_DB"
    ok "the database copied, to $COPY_DB"
  fi
  NOT_UP="the switch to $RELEASE failed, as it says above"
  SWITCHED=1
  switch_to "$RELEASE" "$NEW_DROPIN"
  if start_and_judge; then
    GOES_BACK=
    ok "nervus is up on $RELEASE: active and steady, answering MCP and its web UI as itself"
    RECOVERY=
    if [ ! -e "$OPT/secrets/recovery.pub" ]; then
      RECOVERY=$("$VENV/bin/nervus-ctl" --unit "$UNIT" recovery-key) || RECOVERY="  NOTE  no recovery key could be made: run $VENV/bin/nervus-ctl recovery-key"
    fi
    [ -z "$COPY_DB" ] || rm -f "$COPY_DB"
    # The release before kept whole, for going back; any older removed (question 3a).
    for old in "$OPT/releases"/*; do
      case ${old##*/} in "$RELEASE"|"$WAS") ;; *) rm -rf "$old" ;; esac
    done
    "$VENV/bin/nervus-ctl" --unit "$UNIT" upgrade-record up "$WAS" "$RELEASE" >/dev/null \
      || say "  NOTE  nervus is up, but the upgrade's last record could not be written to its audit log"
    say ""
    say "nervus is upgraded, from $WAS_NUMBER to $NUMBER, and running. The release before, $WAS, is kept"
    say "in $OPT/releases."
    if [ "$NUMBER" != "$WAS_NUMBER" ]; then
      say ""
      say "What each client must do, from CHANGES.md:"
      changes clients
    fi
    [ -z "$RECOVERY" ] || { say ""; printf '%s\n' "$RECOVERY" | sed 's/^/  /'; }
    say ""
    say "Check the backup made before the upgrade with the recovery key, as after every upgrade:"
    say "  sudo $VENV/bin/nervus-ctl backup --check ${BACKUP:-<its name>}"
    exit 0
  fi
  NOT_UP=$WHY
  exit 1
fi

# --- 2. the plan -------------------------------------------------------------------

say ""
say "It will install nervus $NUMBER from $SOURCE:"
[ ${#PACKAGES[@]} -gt 0 ] && say "  - apt-get update, then apt-get install ${PACKAGES[*]} (missing: ${MISSING[*]})"
say "  - the account nervus, no login; the code and its own venv in $REL, root's, and $VENV a link to that venv"
say "  - folders $OPT/secrets (0700), $OPT/transfer and $LOGDIR (0750), owned by nervus, which can change nothing else"
say "  - an empty inventory ($OPT/hosts.yaml) and token file ($OPT/secrets/tokens.yaml, 0600)"
if [ -n "$RESTORE" ]; then
  say "  - no new keys: nervus's keys, certificates, database and audit log from the backup"
  say "      $RESTORE (it asks for the recovery key), and nervus started in lockdown"
else
  say "  - nervus's SSH key, and its TLS authority and certificate for:"
  say "      ${NAMES[*]:+${NAMES[*]}, }$ADDRESS, and this machine's own addresses and hostname"
  say "  - a recovery key, which every backup is locked to; its private half is shown once, at the end"
fi
say "  - a backup once a day, into $STATE/backups (nervus-backup.timer)"
say "  - the service, $UNIT, and its drop-in, with sign-in links at https://$UI_HOST:8443"
say "  - the off switch, $STATE/switches.yaml, nothing switched off"
say "  - then start nervus, serving HTTPS on 8000 (clients) and 8443 (web UI)"
say ""
confirm

# --- 3. install ----------------------------------------------------------------------

if [ ${#PACKAGES[@]} -gt 0 ]; then
  # A fresh container template's package lists can name versions the mirror no longer has.
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y "${PACKAGES[@]}"
  ok "installed ${PACKAGES[*]}"
fi

# A failure from here until the link is made leaves only $OPT, which did not exist before this run.
UNFINISHED="The account nervus and the service were not made; remove $OPT (sudo rm -rf $OPT) before running it again"
build_release
# From here until nervus has started, stopping leaves more than the release's folder: it says so,
# and what to remove, whatever stopped it.
trap 'if [ $? -ne 0 ]; then stopped_installing; fi' EXIT
# The link last, once the release is whole: a release's folder no link points at is one an
# install left unfinished.
ln -s "releases/$RELEASE/.venv" "$VENV"
ok "the code and its own venv in $REL, with nervus installed in it, and $VENV a link to that venv"

printf 'hosts: []\n' > "$OPT/hosts.yaml"
useradd --system --home-dir /opt/nervus --shell /usr/sbin/nologin nervus
ok "the account nervus"

install -d -m 0700 "$OPT/secrets"
install -d -m 0750 "$OPT/transfer" "$LOGDIR"
(umask 077; printf 'tokens: []\n' > "$OPT/secrets/tokens.yaml")
# nervus's account gets its own and nothing else: the code, and the folder the link to it is in,
# stay root's, so what root runs is only what root installed (ADR-0029 question 12).
chown -R nervus:nervus "$OPT/secrets" "$OPT/transfer" "$OPT/hosts.yaml" "$LOGDIR"
ok "folders, an empty inventory and an empty token file"

if [ -z "$RESTORE" ]; then
  runuser -u nervus -- ssh-keygen -q -t ed25519 -N '' -C nervus -f "$OPT/secrets/nervus_ed25519"
  # Read as the key's owner reads it, and given a time: root opens nothing by name in a folder
  # another account owns, here as everywhere else in this script. --foreground, since this runs
  # from a terminal, where a plain timeout can be stopped together with what it times.
  ok "nervus's SSH key: $(runuser -u nervus -- timeout --foreground 10 cut -d' ' -f1,2 "$OPT/secrets/nervus_ed25519.pub" | cut -c1-40)…"
  # The authority that signs a certificate for each connection, naming the client
  # and the run in each machine's own log (ADR-0025). Kept as the key above is.
  runuser -u nervus -- ssh-keygen -q -t ed25519 -N '' -C nervus-ca -f "$OPT/secrets/nervus_ca_ed25519"
  ok "nervus's SSH certificate authority: $(runuser -u nervus -- timeout --foreground 10 cut -d' ' -f1,2 "$OPT/secrets/nervus_ca_ed25519.pub" | cut -c1-40)…"

  TLS_NAMES=()
  for n in ${NAMES[@]+"${NAMES[@]}"} "$ADDRESS"; do TLS_NAMES+=(--name "$n"); done
  (cd "$OPT" && runuser -u nervus -- "$VENV/bin/nervus" tls-init --bind-host 0.0.0.0 "${TLS_NAMES[@]}")
  ok "nervus's TLS authority and certificate"
fi

install -d -m 0755 "$UNIT_DIR/nervus.service.d"
install -m 0644 "$REL/deploy/nervus.service" "$UNIT"
{
  printf '%s\n' "$MARKER"
  printf '[Service]\nExecStart=\n'
  awk '/^ExecStart=/{on=1} on{print; if ($0 !~ /\\$/) exit}' "$UNIT" | sed '$s/$/ \\/'
  printf '    --ui-url https://%s:8443\n' "$UI_HOST"
} > "$DROPIN"
chmod 0644 "$DROPIN"
ok "the service and its drop-in"
install -m 0644 "$REL/deploy/nervus-backup.service" "$REL/deploy/nervus-backup.timer" "$UNIT_DIR/"
ok "the daily backup's service and timer"

"$VENV/bin/python" "$REL/tools/ensure-switches" --owner nervus "$STATE/switches.yaml"
systemctl daemon-reload
if [ -n "$RESTORE" ]; then
  # Checks the backup before it changes anything, keeps what it replaces, and
  # starts nervus in lockdown (ADR-0027 question 5).
  "$VENV/bin/nervus-ctl" --unit "$UNIT" restore "$RESTORE" ${YES:+--yes} \
    || die "the restore did not finish; nervus is installed but not started. Its output is above"
  systemctl enable nervus
  wait_active
  trap - EXIT
  ok "nervus is restored and running, in lockdown"
  [ -f "$OPT/secrets/recovery.pub" ] \
    || say "  NOTE  the backup held no recovery key, so none is made yet: run $VENV/bin/nervus-ctl recovery-key"
else
  STARTED=$(date '+%Y-%m-%d %H:%M:%S')
  systemctl enable --now nervus
  wait_active
  # Answering its clients, as an upgrade judges it, not merely started: systemd calls a service
  # active the moment its process exists. nervus makes its database as it first starts, and a
  # record in its audit log before that -- the recovery key's, next -- makes it refuse to start
  # for good, as if its database had been lost (procedure 058).
  ports_of "$(cat "$DROPIN")" || die "the service's command line gives no --bind-port or no --ui-port to ask nervus on"
  if ! WHY=$(python3 -I "$TREE/tools/check-up" "$OPT/secrets/tls-root.crt" "$MCP_PORT" "$UI_PORT" 2>&1); then
    last_words >&2
    die "nervus started but does not answer its clients: $WHY. Its own last words are above; no recovery key was made"
  fi
  trap - EXIT
  ok "nervus is running"
  RECOVERY=
  if ! RECOVERY=$("$VENV/bin/nervus-ctl" --unit "$UNIT" recovery-key); then
    die "nervus is running, but no recovery key was made, so no backup can be: run $VENV/bin/nervus-ctl recovery-key"
  fi
  ok "the recovery key"
fi
systemctl enable --now nervus-backup.timer
ok "a backup once a day"

# --- 4. what to do next ------------------------------------------------------------

ROOT_FP=$(cd "$OPT" && runuser -u nervus -- "$VENV/bin/nervus" tls-fingerprint | sed -n 's/.*root certificate SHA-256 //p')
say ""
if [ -n "$RESTORE" ]; then
  # The tier, the machines, the tokens and every client's trust came back with the backup
  # (procedure 047, finding 3): what is left is to look, lift lockdown, and back it up again.
  say "nervus is restored from $RESTORE and running, in LOCKDOWN: it acts for no client until you"
  say "lift it, once you have looked."
  say ""
  say "Its root certificate's fingerprint, the backup's, unchanged by the restore:"
  say "  $ROOT_FP"
  say ""
  say "Clients and machines need nothing changed: the same root, tokens and certificate authority as"
  say "before. A client that reaches nervus at the same name or address as before works as it is once"
  say "lockdown is lifted. If clients reach it by an address the backup's nervus did not have, add the"
  say "address to its certificate: nervus tls-reissue --name <address> (docs/install.md)."
  say ""
  say "Next, from docs/install.md (Backups):"
  say "  1. Sign in to the web UI with this link (it works once, within 5 minutes; nervus-ctl signin makes another):"
  "$VENV/bin/nervus-ctl" --unit "$UNIT" signin | sed 's/^/     /'
  say "  2. Look before lifting lockdown. The Machines page says when the backup was made: machines added"
  say "     and tokens issued after it are not here: add them again. A client switched off stays off."
  say "  3. Lift lockdown: sudo $VENV/bin/nervus-ctl unlock --all, or on its Clients page."
  say "  4. On its Backups page, make a backup of the restored nervus, and check it with the recovery key:"
  say "       sudo $VENV/bin/nervus-ctl backup --check <its name>"
else
  say "nervus is installed and running."
  say ""
  printf '%s\n' "$RECOVERY" | sed 's/^/  /'
  say ""
  say "Its root certificate's fingerprint (keep it with your tokens; each client machine compares it once):"
  say "  $ROOT_FP"
  say ""
  say "Next, from docs/install.md and docs/clients.md:"
  say "  1. Sign in to the web UI with this link (it works once, within 5 minutes; nervus-ctl signin makes another):"
  "$VENV/bin/nervus-ctl" --unit "$UNIT" signin | sed 's/^/     /'
  say "  2. On its setup page, the first it shows, choose nervus's tier (docs/install.md step 3)."
  say "  3. On its Machines page, add each machine nervus will reach (docs/install.md step 3), and on"
  say "     its Clients page, issue a token for each client."
  say "  4. On each client machine, in your copy of this repository:"
  say "       tools/nervus-trust https://$URL_HOST:8000/mcp --expect '$ROOT_FP'"
fi
say ""
say "Never give nervus full access to this machine (it refuses): an agent could then read nervus's"
say "own key and tokens through nervus (docs/install.md, Where nervus may run)."
