# ADR-0029: upgrading nervus from one preview export to a newer one

**Status:** **Accepted 2026-11-05, at the operator's word** ("Yes, accept it"), every verification
item observed: items 1 and 2 on throwaway machines by the trial (procedure 051), and 2 in tests too;
items 3 to 9 in tests, each seen to fail with what it shows broken on purpose, and of those 4 and the
first half of 6 by the trial as well. Its amendments to ADR-0023 question 7 and ADR-0018 decision E are
marked there. Step 7 of its order of work stays open, not among the verification items, until a release
first raises the database's version. Step 8, the first installation's move onto this path, was done by
procedure 052, finished 2026-11-07. **Decided by the operator on 2026-11-01**, in a Claude Code session: questions 1 to 11,
each as the drafting session recommended ("All as recommended"); question 12, raised while building
step 2, on 2026-11-03, as recommended. Each question keeps its options, so the record shows what was
not chosen. **Proposed 2026-11-01** the same day, its Context checked
against a fresh install on a throwaway machine before the decision (procedure 050). **Steps 1
and 2 of its order of work built 2026-11-01** (the release number; release folders), **steps 3 to
5 on 2026-11-04** (`install.sh --upgrade`, `install.sh --back`, the docs). **Step 6, the trial, done
2026-11-05** (procedure 051): verification 1 and 2 observed on throwaway machines; of its five
findings the first four fixed the same day, the fifth left for step 7. **Step 8, the first installation,
moved onto this path 2026-11-06** (procedure 052). Nothing exported. **Amended 2026-11-06, at the
operator's word** ("Yes, fix it"): that move's work found that a step failing between the stop and
the start left nervus stopped. What can stop an upgrade now comes before the stop, and from the stop
until nervus is judged up, any way the run ends goes back: steps 1, 2, 4, 6, 7 and 10 below, question
7, and verification 10, observed in tests and on a throwaway machine (procedure 053).
**Amended 2026-11-15, decided by the operator:** the two things this record left. The libraries
below nervus's own get a lock file ("Not settled here", now settled). And step 7's finding is
answered: the backup made before an upgrade is kept until the next upgrade. Migrations themselves
wait for the first release that needs one, as question 6a decided; that is the decision, not an
open step.
**Date:** 2026-11-01
**Asked for by:** the operator, item 6 of the order before friends are invited: "An upgrade path for
a friend taking a newer export."
**Settles what earlier records left here:** ADR-0023 question 7 (the installer "refuses a machine
that already has nervus, and says that upgrading is item 6's"); ADR-0027 consequence 5 ("an upgrade
makes a backup first"); and, for the first installation, whether its libraries and `pyproject.toml`
are brought together, an open item in its record (question 11).
**Builds on:** ADR-0001 s10 (what cannot be audited does not happen); ADR-0005, "Alternatives
considered" (the operator's own instance kept on the published code); ADR-0007 decision 2 and
ADR-0023 (the tiers); ADR-0014 decision F (a table added keeps the database's version); ADR-0018
decision E (the preview: one commit per export, on top of the last); ADR-0019 (the deployment record
is not exported); ADR-0023 questions 5 to 7 (the installer checks by need, takes every step that has
one right answer, installs a committed tree, runs as root); ADR-0027 (backups; a restore refuses a
database from a newer release).
**Amends, now Accepted:** ADR-0023 question 7 (question 1); ADR-0018 decision E's export (questions
2 and 9).
**Evidence:** procedure 053, the amendment's trial, on a throwaway machine; procedure 051, the trial, on throwaway machines; procedure 050, on a throwaway machine:
what an install by the installer leaves, and question 3a's premise tried; `install.sh`, nervus's units and its code, read 2026-11-01; procedures
035 and 047 (installs by the installer, on throwaway machines); procedure 007 (nervus runs its
installed package, not the tree); procedure 045 (what the first installation keeps); procedures 018,
022, 031, 038, 043 and 048 (what the first installation's deploys needed besides code); procedure
034 (clients across a restart).
**Written to the policy of ADR-0019:** this record names no system. Paths are those nervus's own
unit and installer use.

## Context

### What an install leaves, and what an upgrade must do with each

Read from `install.sh` and `deploy/` on 2026-11-01, and observed the same day on a fresh install by
the installer (procedure 050; also procedures 035, 047):

| piece | where | made by | an upgrade |
|---|---|---|---|
| the tree nervus was installed from | `/opt/nervus` | the installer: `git archive` of the commit, or a plain copy of the tree as it is | **replaces** |
| the venv: nervus's package and its libraries | `/opt/nervus/.venv` | the installer, `pip install` with dependencies | **replaces**, with the new release's libraries |
| nervus's unit; the backup's service and timer | `/etc/systemd/system/` | copied from `deploy/` | **replaces** |
| the unit's drop-in: the installation's own flags | `/etc/systemd/system/nervus.service.d/instance.conf` | the installer, and `--proxmox` | **writes again** (point 3 below) |
| system packages: Python and its venv, `ssh-keygen`, `useradd`, `runuser`, `age` | the system | the installer, those missing | **adds** what a release newly needs; removes none |
| the account `nervus` | the system | the installer | keeps |
| keys, certificates, the token file, known host keys, the recovery key's public half, a hypervisor's settings | `/opt/nervus/secrets/` | the installer, `tls-init`, `nervus-ctl`, the person | **keeps**; makes only what a release adds and is missing |
| the inventory | `/opt/nervus/hosts.yaml` | the installer (empty), the person | keeps |
| the database | `/var/lib/nervus/nervus.db` | nervus, at its first start | keeps; nervus **migrates** it if a release changes its layout |
| the off switch | `/var/lib/nervus/switches.yaml` | the installer | keeps |
| backups; what a restore replaced; a renewed certificate | `/var/lib/nervus/backups`, `replaced-*`, `tls/` | nervus, `nervus-ctl` | keeps |
| the audit log | `/var/log/nervus/audit.jsonl` | nervus | keeps, and records the upgrade |
| exports, uploads, the transfer folder | `/var/lib/nervus/exports`, `uploads`; `/opt/nervus/transfer` | nervus, for clients | keeps; short-lived |

Four things in it decide most of what follows:

1. **nervus runs from its venv, not from the tree.** A venv is a folder holding nervus's package and
   the libraries it uses, apart from the system's. The tree in `/opt/nervus` is what the package was
   built from, with the `tools/` and `deploy/` the installer uses; nervus imports the copy `pip`
   installed into the venv (procedures 007, 050). A new tree alone changes nothing. Nor can a venv
   be renamed: its scripts name its own path, written into their first line (procedure 050).
2. **Its libraries are pinned one level deep.** `pyproject.toml` names each of nervus's eight
   libraries at one exact version. What those need in turn is whatever the package index (PyPI,
   where Python's libraries are downloaded from) offers on the day: on a fresh install, 23 of the
   venv's 31 (procedure 050). So building a venv needs the internet, and two installs of one release
   weeks apart can differ below the eight.
3. **The drop-in hides a new command line.** A drop-in is a small file beside a unit that changes
   some of its lines. systemd cannot add flags to a command line from one; it can only clear the
   command line and give it whole again. So the installer's drop-in holds a copy of the unit's whole
   `ExecStart`, as it was at install, with the installation's own flags after it (`--ui-url`, and
   with a hypervisor `--proxmox` and `--upload-pull-url`), and systemd runs that copy (procedure
   050). A new release's unit with a changed `ExecStart` would be installed and ignored. Its other
   lines, such as its hardening, take effect.
4. **No installation knows which release it is.** The package has said version 0.1.0 since the
   project's first day, whatever its code. The installer prints the commit it installs and keeps it
   nowhere; an archive has no commit; and the preview's commits are its own, naming this
   repository's commit only in their message. So "older" and "newer" mean nothing yet.

### How the database's version moves today

The database carries one number, its schema version (`PRAGMA user_version`: which layout of tables it
has), and it has been 1 since the database was first made. ADR-0014 decision F raises it only for a
change an older release cannot live with. A table added is not one: nervus makes a missing table at
every start, and the release before ignores a table it does not know, so going back still starts.
Twelve tables have been added since, and none changed. nervus refuses a database of any other
version, older or newer ("made by another release of nervus"), and `nervus-ctl restore` refuses a
backup whose database is any other version. ADR-0027 question 5 restores onto "the same release or a
newer one", which holds only while the version stays 1. No migration (a step that changes the tables
from one version's layout to the next) exists, and none has been needed.

### What releases have needed besides code

On the first installation, some of this was done by its deploy tools, written for that release, and
the rest by hand in that deploy's procedure. On a friend's machine each must be the upgrade's, or
the friend's, from what the release says:

| release | needed | procedure |
|---|---|---|
| the off switch (ADR-0003); its move to the state folder (ADR-0014 decision A) | a file made before nervus starts; then made again elsewhere, the old one left for going back | 018, 022 |
| nervus's own TLS (ADR-0010), then its own authority (ADR-0021) | keys and certificates made once by `tls-init`, then put under the authority by `tls-init --upgrade`; a flag taken out of the drop-in | 020, 038 |
| uploads (ADR-0020) | a flag added to the drop-in | 031 |
| a certificate per call (ADR-0025) | a key made before the release could start: the SSH certificate authority | 043 |
| backups (ADR-0027) | a system package (`age`); two units, the backup's service and timer; a recovery key whose private half a person keeps | 048 |

And once on a client machine: procedure 047's first finding changed what `tools/nervus-trust` saves
there, so each client machine's copy of the repository needed pulling and the tool running again.

### The first installation's deploy

Its own tools, kept in its deployment record (procedures 007, 043, 048), build the release on
another computer: nervus's package, checked against the commit's own files. They copy two releases
to nervus's machine, the one running and the new one; stop with nothing changed unless the installed
package, unit, drop-in and inventory are exactly the running release's; unpack the new tree over the
old; install the package without its libraries, offline; install the unit and the drop-in, which
that installation's repository keeps; restart nervus; and judge it up when it is active on one main
process for 5 seconds and its MCP port answers over HTTPS checked against nervus's own root. If not,
they put the old tree, package, unit and drop-in back. They make no backup first, and install no
package or unit: procedure 048 did those by hand. Installing without libraries, they have never
moved one: that installation runs older libraries than `pyproject.toml` declares, an open item in
its record.

It is the one upgrade path that works today. It is that installation's, and its record is not
exported (ADR-0019 decision H), so a friend has none.

### Who has installed what

The preview has one export, of 2026-10-17, made before the installer existed, and friends are not
yet invited. So there is no friend's installation to upgrade: the release friends first install,
from the next export, is the first an upgrade starts from. The only installations today's installer
has made are throwaway ones, for trials, destroyed after.

### By tier

The steps are the same on every tier. What differs is where the newer tree comes from, and who could
change it before it runs as root:

- **Tier 1**, nervus on a computer apart from the everyday one: the tree reaches nervus's machine as
  it did for the install, by a clone there brought up to date with `git pull` (which needs the
  person's access to the private preview there, as the clone did), or by an archive made on the
  everyday computer, copied over and checked by its SHA-256 (`docs/install.md`, "By hand").
- **Tiers 2 and 3**, nervus on the everyday computer: the tree is within reach of the person's own
  account (on tier 2 their own clone; on tier 3 everything of nervus's is). The upgrade, like the
  install, runs as root what that tree holds, so a program running as the person could change it
  first. That is no weaker than the install was, and no stronger. On tier 2 the packages an upgrade
  adds are added to the everyday computer itself.

A backup beside nervus survives a mistake in an upgrade on every tier; on tiers 2 and 3 it does not
survive the computer (ADR-0027's table).

### Clients across a restart

An upgrade restarts nervus, as every deploy of the first installation has. What that did to clients
(procedure 034): each client's MCP session, the conversation nervus holds in memory with a client,
ended, and was turned away until the client began a new one; and a Claude Code session open across
the restart went on with the tool descriptions it had been given before, without the parameter the
new release added, until the session itself was restarted. nervus stops within 5 seconds of being
asked (its unit). A call in flight then is cut, its intent in the audit log without a result. A
background job runs on, in tmux on its own machine. An export or upload in progress is marked failed
at the next start.

## The upgrade, in order

How the recommended options fit together, so the whole can be read before its parts. Each step names
the question that decides it.

1. **Read, and change nothing** (question 1). As root, from the newer tree. Stop with nothing
   changed if: no nervus is installed here (that is the install); the installation was not made by
   an installer that keeps releases apart (question 8); a clone has uncommitted changes (ADR-0023
   question 7); the tree's release is older than the installed one, or is the same release with the
   same code (question 2); the drop-in is not in the installer's shape (question 5); something the
   new release needs is missing with no `apt-get` to install it (ADR-0023 question 5); or the off
   switch is one nervus cannot read, since every release then refuses every client and nothing may
   overwrite a lock nobody can read. Read the database's version, as nervus's account (question 6).
2. **Show the plan, and wait for yes:** which release to which, with the commit, or the archive's
   SHA-256, to compare with the export's; the `CHANGES.md` sections in between (question 9); the
   packages to add; the drop-in before and after; whether the database's version moves, and what
   going back would then lose (question 7); when the recovery key last opened a backup (question
   4); what the off switch holds; and that nervus restarts, and what clients see (question 10).
3. **Add the packages** the new release needs and the machine lacks, by `apt-get`; none removed.
   nervus still serves.
4. **Build the new release beside the running one:** its tree, and its venv with its libraries
   (question 3). If the package index cannot be reached or a library will not install, the upgrade
   stops here, nothing else changed, nervus still serving. Then make what the new release needs and
   lacks ("Settled already"), still serving: if that fails it stops here too, and the backup that
   follows holds what was made.
5. **Make a backup**, by the running release, with the daily backup's timer stopped first and any
   backup it began let finish (question 4). It must succeed. An operator record naming both releases
   goes into the audit log before anything stops (ADR-0001 s10).
6. **Stop nervus**, which takes at most 5 seconds. If the new release raises the database's version,
   copy the database first (question 6). From this stop until nervus is judged up, any way the run
   ends goes back by itself, as step 10 says: a step that fails, a signal, a terminal that has gone.
7. **Switch:** point `/opt/nervus/.venv` at the new release (question 3); install the unit and the
   backup's units from the new tree; write the drop-in again (question 5); and tell systemd. Each
   file changes in one step.
8. **Start nervus.** If its database's version is older than the new release's, nervus migrates it
   before anything else uses it (question 6).
9. **Judge it** (question 7): active, on one main process for 5 seconds; MCP answering over HTTPS
   checked against nervus's own root, with nervus's own refusal of a call without a token; the web UI
   answering; nothing in its start lines saying it refuses clients.
10. **Up:** the timer started again; the release before kept, any older removed; the database's copy
    removed; an operator record saying how it ended; and closing lines saying what changed for
    clients and asking for `nervus-ctl backup --check` on the backup just made (question 4).
    **Not up, or anything else since the stop:** it goes back by itself (question 7): nervus stopped;
    the release before current again, with its unit and drop-in, if the switch began; the database's
    copy put back if the new release may have moved on from it, and otherwise removed, the database
    being as it was; nervus started and judged the same way; an operator record saying why; the new
    release's folder and the journal left for reading. Nothing interrupts that, and a step of it that
    fails stops no other: it says what could not be put back, or that nervus is down.

A machine that stops part-way starts again on whichever release `/opt/nervus/.venv` names, and
`install.sh --back` (question 7b) puts the release before back, with its unit and drop-in.

## Questions

### 1. What the person runs, and from what

- **a. `sudo ./install.sh --upgrade`, on nervus's machine, from the newer tree: a clone brought up
  to date with `git pull`, or the newer archive unpacked in a folder of its own.** The same script
  that installed nervus, so it carries what its own release needs. As at install (ADR-0023 question
  7), it installs exactly the committed tree it sits in, refuses uncommitted changes in a clone,
  shows its plan and waits for "yes". Without `--upgrade`, on a machine that has nervus, it still
  changes nothing, and now says which release is installed, which this tree holds, and the command
  that upgrades. The same on every tier (Context, "By tier").
- b. A script of its own, `upgrade.sh`, beside the installer. The two would share most of their steps
  (the checks by need, the venv, the unit, the drop-in) and drift apart.
- c. `nervus-ctl upgrade <tree>`, run by the installed nervus. One command the installed system
  already knows; but the installed release would be judging what a newer one needs, which only the
  newer one knows: this release's `age`, and whatever the release after it needs.

*Recommended: a.* **Decided 2026-11-01: a.** The newer tree is the only thing that knows what the newer release needs, and its
installer already does most of an upgrade's steps.

### 2. Which release is which, and refusing to go back by accident

- **a. A release number in `pyproject.toml`, raised in this repository in the commit each export is
  made from: one number per export, only going up.** The 2026-10-17 export's tree already says
  0.1.0; the next export is 0.2.0. nervus's package carries the number, so an installed nervus knows
  its own: `nervus-ctl status` and every signed-in page of the web UI say it, and the backups' manifests,
  which already record the package's version, start meaning something. The installer reads the
  tree's number from `pyproject.toml`, clone or archive alike. The export refuses a number not above
  the preview's last export's. The upgrade refuses an older release (a downgrade: question 7b is the
  way back); says "nothing to do" for the same release with the same code; and goes ahead, saying
  so, for the same release with other code, a build between exports, which only this repository
  makes.
- b. The preview's commit id. Every clone has it; an archive does not, and commit ids have no order,
  so "older" could not be told without the history.
- c. The export's date. Ordered, but a second export on one day needs a suffix, and nothing in the
  package carries it unless it is written there, which is a with a date for a number.

*Recommended: a.* **Decided 2026-11-01: a.** One number, in the package, readable from any copy of the tree, and ordered.

### 3. Where the new release goes, and so how it can be undone

The new code and its libraries must be in place before nervus starts on them, and the old must be
there to go back to. Installing libraries needs the package index, and can fail part-way.

- **a. Beside the running release, then switched.** Each release gets a folder of its own under
  `/opt/nervus/releases/`, named for its number and its code, holding its tree and its own venv,
  built there with its libraries while the running nervus serves on. `/opt/nervus/.venv` becomes a
  symbolic link (a name that points at another folder) to the current release's venv, so the unit,
  the backup's timer, `nervus-ctl` and every command the docs give keep their paths. Switching is
  pointing that link at the new release. Going back is pointing it at the old one, which needs
  neither the network nor the old tree, and gets back exactly its libraries. The release before is
  kept whole; older ones are removed by the next upgrade. A release takes about 68 MB, a venv of 64
  MB and its tree (procedure 050). What nervus keeps stays where it is: `hosts.yaml`, `secrets/` and
  `transfer/` at the top of `/opt/nervus`, the rest in `/var/lib/nervus` and `/var/log/nervus`. The
  installer installs this way from the release that builds this; an installation made by an earlier
  installer is not upgraded (question 8). **Tried on a throwaway machine** (procedure 050): a second
  release's venv, built beside the first while nervus served on, ran nervus under its unit through
  the link, and the daily backup's unit and `nervus-ctl` with it; pointed back, the link ran the
  installer's own venv, moved aside, as before.
- b. In place, as the first installation's deploy does it: the new tree unpacked over the old, the
  new package installed into the same venv, the old put back the same way to undo it. The layout
  stays. But with its libraries, a download that fails part-way leaves a venv half changed with
  nervus stopped, and going back needs the network again and may not find the same versions; without
  them, as that deploy does it, going back is offline, but no library ever moves, which is how that
  installation came to run older libraries than declared. A file a release removes stays behind
  unless the upgrade removes it.
- c. Every upgrade a restore: a backup, nervus removed, the new release installed afresh with
  `install.sh --restore`. It reuses the restore, shown on real machines (procedure 047); but every
  upgrade asks for the recovery key, ends every sign-in and starts in lockdown, and while it runs
  neither release is installed, so a failure halfway leaves nothing running.

*Recommended: a.* **Decided 2026-11-01: a.** The step that fails most often, fetching libraries, runs while nervus still serves,
and changes nothing if it fails. Going back is one link, offline and exact. And libraries move with
each release as `pyproject.toml` says, which b cannot do and keep its way back. The cost is a layout
change, made once, at install.

### 4. The backup first, and whether the upgrade opens it

ADR-0027 settled that an upgrade makes a backup first. A backup opens only with the recovery key,
which nervus never holds, so nervus can make a backup and cannot check one.

- **a. Made by the running release before anything stops; the upgrade goes no further without it;
  not opened.** The plan says when the recovery key last opened a backup (the Backups page's "last
  check that passed"), and the closing lines ask for `nervus-ctl backup --check` on the one just
  made, as the docs already ask after each upgrade (ADR-0027 question 7). Going back after a failed
  start does not need the backup (question 7); it is for what going back cannot mend.
- b. As a, and opened with the recovery key, pasted on the terminal, before anything stops. The
  backup is proven before the risk is taken; but every upgrade becomes a time to fetch the recovery
  key from wherever it is kept, and a friend without it to hand cannot upgrade.
- c. No backup of its own: the daily one is at most a day old. Nothing to wait for; but a day's
  enrollments and tokens are what a failed upgrade could cost, and ADR-0027 consequence 5 says
  otherwise.

*Recommended: a.* **Decided 2026-11-01: a.** The check that matters is that the key opens a backup at all, and ADR-0027 already
has the person make it, calmly, after install and after each upgrade. An upgrade that went wrong
enough to need the backup is rare, since going back needs none.

### 5. The unit and its drop-in

The unit is nervus's own, and the drop-in holds the installation's flags. But the installer's
drop-in restates the unit's whole command line (Context, point 3), so a release that changes the
command line needs the drop-in written again.

- **a. The unit, and the backup's service and timer, installed from the new tree; the drop-in
  written again: the new unit's command line, followed by the installation's own flags, read from
  the old drop-in as whatever follows the old unit's command line in it.** The plan shows both
  drop-ins. A drop-in the installer did not write, or whose command line does not begin with the old
  unit's, stops the upgrade before anything changes, saying what differs; the person puts it right,
  or writes it by hand (`docs/install.md`).
- b. A drop-in that holds only the installation's flags, in a variable the unit's command line names
  (systemd's `Environment=`), so the unit's command line can change freely and nothing is written
  again. Cleaner for good; but `nervus-ctl` reads every path from the command line and would have to
  expand the variable as systemd does, and every installation's drop-in changes shape once.
- c. The drop-in left as it is, and no release changes the unit's command line: a new option gets a
  default instead, as ADR-0027's recovery key did. Nothing to build; but a release that must change
  the command line has no way to.

*Recommended: a.* **Decided 2026-11-01: a.** It needs nothing new from `nervus-ctl` or the unit, keeps every installation's
drop-in in the shape it has, and refuses rather than guesses where a person has changed it.

### 6. How the database's version moves, and refusing an older nervus

- **a. Forward only, by nervus itself at start.** A release that must raise the version, as ADR-0014
  decision F says, carries a migration from each older version, one version at a time, each in one
  transaction, run at start before anything else uses the database, and recorded in the audit log as
  nervus records who it is (ADR-0027 question 6). nervus still refuses a database newer than it
  knows. The upgrade compares the database's version with the new release's before anything stops:
  where the new one is higher, it copies the database first, beside it as
  `nervus.db.before-<release>` (the database holds hashes, never a secret, and the name falls under
  the paths the docs leave out of a copy of nervus's machine), so going back can put it back.
  `restore` then accepts a backup from an older release, and nervus migrates it at its start, which
  makes ADR-0027 question 5's "the same release or a newer one" true across versions. No migration
  is written until a release needs one.
- b. Forward only, by the upgrade, as a step of its own (`nervus-ctl migrate`), nervus still refusing
  an older database at start. The step shows; but a backup restored onto a newer release would need
  it too, and a nervus that finds an older database after anything else would refuse rather than
  migrate.
- c. Both ways: each migration with its reverse, so going back keeps what the new release wrote.
  Every change written and tested twice, for a way back that a copy taken a minute before already
  gives.

*Recommended: a.* **Decided 2026-11-01: a.** Every way a database reaches a newer nervus, by an upgrade or by a restore, then
ends in one it can use, by one code path; and the version moves as rarely as ADR-0014 F keeps it.

### 7. When the new release counts as up, and what going back is

"Up" must mean what clients need, not that systemd started a process (AGENTS.md rule 3): nervus can
be active and refusing every client. Every option judges up the same way: active within 20 seconds
and on the same main process 5 seconds later; MCP answering on its port over HTTPS, checked against
nervus's own root, with nervus's own refusal of a call that carries no token; the web UI answering on
its port; and nothing in its start lines saying it refuses clients, such as an unreadable off switch.
The first installation's deploy judges all but the web UI this way. The options differ in what
happens when it is not up, and afterwards.

What going back means once the database has moved on:
- **Its version unchanged**, the common case (tables added, rows written): the database is kept. The
  release before ignores the tables it does not know (ADR-0014 decision F), so nothing is lost; if
  the person upgrades again, the newer release finds its tables as it left them, with nothing
  written there in between.
- **Its version raised**, a migration having run: the release before would refuse it, so the copy
  taken just before the switch is put back. What the new release wrote to its database between its
  start and going back is lost: seconds, after a failed start. Its audit records stay, since the
  audit log is never rolled back.

- a. Back by itself when the new release is not up; no going back afterwards. The way on from a
  release that is up but wrong is the next export.
- **b. As a, and back later on the person's word: `sudo ./install.sh --back` puts back the release
  kept from the last upgrade, as going back after a failed start does, while the database's version
  is one that release knows.** Refused once a migration has run, saying why: only the backup made
  before the upgrade holds a database that release can use, and restoring it loses everything done
  since.
- c. Never by itself: the upgrade stops and says how to go back. The person sees every failure; but
  a friend who stepped away comes back to a nervus that is down.

*Recommended: b.* **Decided 2026-11-01: b.** Going back by itself keeps a failed start from leaving nervus down. Going back
later costs almost nothing more, since the release before is kept whole (question 3a) and the
database's version almost never moves; it is the answer to "the new export broke something I use".

**Amended 2026-11-06:** going back by itself covers the whole stretch from the stop until nervus is
judged up, not only a failed start. As first built, a step between the stop and the start that failed
ended the run with nervus stopped and nothing to start it, the very thing this question decided against
(procedure 052). `--back` returns by itself on the same terms.

### 8. Skipping exports

- **a. From any release friends were given to any newer one, in one upgrade.** Each upgrade makes
  what its release needs and the machine lacks ("Settled already"), and migrations run one version
  at a time up to the newest (question 6), so most steps do not care how far behind an installation
  is. A step that a release's upgrade must do once, such as moving a file, stays in every later
  release's upgrade for as long as an installation that needs it can exist. The plan shows every
  `CHANGES.md` section in between. Refused, saying so: an installation not made by this record's
  installer, which only throwaway ones are, and the first installation (question 11).
- b. One export at a time: the upgrade refuses every installed release but the export just before
  its own; a friend two behind checks out each export in turn (`git checkout <export>`) and upgrades
  once for each, nervus restarting each time. Each step is the one that was tested; but the friend
  does the stepping, and an archive has no history to step through.

*Recommended: a.* **Decided 2026-11-01: a.** A friend who skipped an export should not pay for it in restarts, and a's steps are
"make what is missing", which do not care how much is missing. Its cost falls on whoever writes a
one-time step, who keeps it while it can be needed; raising the oldest release an upgrade starts
from is a decision of its own, recorded with the release that raises it.

### 9. How a friend learns that a newer export exists, and what changed

- **a. `CHANGES.md` at the top of the repository, exported with it: one section per release, newest
  first, written before each export from what the records say changed since the last, under three
  heads: what a person running nervus will see, what each client must do (often nothing), and what
  the upgrade will do on nervus's machine.** The export refuses a release without its section. The
  upgrade shows the sections between the installed release and its own before asking for yes. When
  an export is pushed, the operator tells the friends, as they already talk (ADR-0018 decision H);
  they `git pull` and read it.
- b. As a, and a GitHub release on the preview repository for each export, which emails each friend
  who watches its releases. One more outward step per export, on the operator's word; and only the
  friends who chose to watch releases hear.
- c. nervus asks the preview repository whether a newer export exists, and says so in its web UI. A
  friend learns without being told; but nervus would need a credential for a private repository, and
  would make a call to the internet it otherwise never makes.

*Recommended: a.* **Decided 2026-11-01: a.** The group is small and talks already; what it lacks is a place that says what
changed, in words for someone running nervus, which the export's commit message ("Export of
<commit>, <date>") is not.

### 10. What changes for clients

Ideally nothing, and nearly nothing does: an upgrade keeps nervus's address, its TLS root and every
token, so no client's configuration changes. What the restart does is in the Context.

- **a. Nothing in a client's configuration, by any upgrade; and every release keeps the tools of the
  release before working as clients called them: a new parameter is optional, and nothing is renamed
  or removed without `CHANGES.md` saying so, under clients.** A session open across the restart,
  which keeps its old descriptions, then still works; it learns what is new when it is restarted,
  which `CHANGES.md` and the upgrade's closing lines say to do when tools changed. A change on the
  client's own side (`tools/nervus-trust`, `docs/clients.md`) is said there too: pull the repository
  on each client machine, and what to run.
- b. As a, and nervus waits before it stops: it refuses new calls and lets calls in flight finish,
  for up to a minute. Fewer calls cut; but every upgrade waits, and an agent's long command is still
  cut at the minute.
- c. No promise about tools: `CHANGES.md` says what changed, and every client restarts its sessions
  after every upgrade.

*Recommended: a.* **Decided 2026-11-01: a.** No client can be told that tools changed once the restart has ended its session,
and a session open across it keeps its old descriptions (procedure 034), so keeping old calls
working is what makes an upgrade safe to run while clients are busy. A call cut at a restart is
recorded, and its client sees an error it can retry, as at any restart.

### 11. The first installation

It has its own deploy (Context), kept in its deployment record. What sets it apart from a friend's
installation is its own: it was built by hand before the installer existed; its repository keeps its
drop-in and its inventory, which its deploy installs with each release; its deploy sets its tokens'
grants each time; and it builds nervus's package on another computer and installs it offline.

- **a. It moves onto the friends' path once the trial has shown that path on throwaway machines, by
  a procedure of its own:** its layout made the installer's, its venv moved into a release folder
  rather than rebuilt (a venv at `/opt/nervus/.venv` runs from elsewhere through the link, procedure
  050), its drop-in written in the installer's shape with its own flags, and whether its machine
  reaches the package index read first. From then on its deploy is `install.sh --upgrade`, run on its
  machine from a tree copied in, and its deployment record keeps only what is its own: its
  inventory, its tokens' grants, its hypervisor's checks. Its first upgrade there builds a venv with
  the libraries `pyproject.toml` declares, which closes that open item in its record. The friends'
  path is then run at every deploy here, as ADR-0005 argues for the operator's own instance.
- b. It keeps its own deploy, changed where a release needs it: its tools name nervus's package file
  with the release number in it, which question 2a starts moving, and they install neither a new
  package nor a new unit. Its machine fetches nothing at a deploy; but there are two upgrade paths
  to keep, and the friends' one runs only in trials and for friends.
- c. It keeps its own deploy until friends have upgraded once, and this is asked again then.

*Recommended: a.* **Decided 2026-11-01: a.** ADR-0005 keeps the operator's own instance on the published code because defects
were found by running the system, not by reading it; the friends' upgrade will be found wanting the
same way, and better here first. Whichever is chosen, if the release number moves (question 2a), its
tools must first find nervus's package file whatever its number, or its next deploy stops.

### 12. Who owns the code on nervus's machine

Raised while building step 2, by its review. Every installation so far gives the whole of
`/opt/nervus` to nervus's account (`chown -R nervus:nervus /opt/nervus`, in the installer and in the
hand steps): its code and venv too, and, with release folders (question 3a), the release kept for
going back. Root runs that code: the daily backup's unit runs `nervus-ctl` as root, and the upgrade
and `--back` will run the new and the old release's. The running nervus cannot write there
(`ProtectSystem=strict`); but anything else running as its account could change the code root runs
next, or point `/opt/nervus/.venv` at another folder, since it owns the folder the link is in.

- **a. Root owns the code; nervus's account keeps only its own.** `/opt/nervus` itself, `releases/`,
  every release's folder with its venv, and the link `/opt/nervus/.venv` are root's: the account
  reads them and can change none. It keeps what it owns now apart from the code: `secrets/`,
  `transfer/`, `hosts.yaml` and `/var/log/nervus`, which is also what a restore gives it back. The
  code is unpacked as root's whoever owned the tree it came from: a plain copy's files would
  otherwise keep their owner's.
- b. As before: the account owns all of `/opt/nervus`.

*Recommended: a.* **Decided 2026-11-03: a** ("Ownership first", asked whether to settle this before
step 3). It is the usual practice for a system service: code owned by root that the service's account
can only read, so that what root runs is only what root installed. It costs nervus nothing: read
2026-11-03, nothing it runs as its account writes outside `secrets/`, `transfer/`, `/var/lib/nervus`
and `/var/log/nervus` (its TLS commands, `nervus-ctl`, the switches, the restore). The first
installation keeps its layout, and so its owners, until its move (question 11).

## Settled already

- **A committed tree, run as root, a plan and a yes** (ADR-0023 question 7): the upgrade, like the
  install, installs exactly a committed tree, refuses uncommitted changes in a clone, runs as root on
  nervus's machine, shows what it will do and waits for "yes", or `--yes`.
- **What a release newly needs, the upgrade makes, as the installer would** (ADR-0023 question 6,
  by question 1a's one script): a package, by need, with `apt-get` where it exists (ADR-0023
  question 5), never removing one; a folder; a file, such as the off switch; a key that nothing
  trusts yet; a recovery key, its private half made and shown once on the terminal, as the installer
  does (ADR-0027). What only the person can give, such as a hypervisor's credentials, it names, as
  `CHANGES.md` does. It never replaces what exists: keys, certificates, the token file, the
  inventory, the off switch, backups, the audit log.
- **A backup first** (ADR-0027 consequence 5); question 4 asks only whether it is opened.
- **What cannot be audited does not happen** (ADR-0001 s10): an upgrade's start, its end and going
  back are operator records in the audit log, as a restore's are (ADR-0027); an upgrade whose first
  record cannot be written does not begin. The audit log is never rolled back, nor edited.
  *Since 2026-11-15 the end with nervus up on neither release is on record too, on `--upgrade` and
  on `--back`. As first built that end, the one that most needs a record, was told to the terminal
  alone (found 2026-11-06). It is written by the release current at that moment, as every record
  is; one from before the stage `down` writes it as `back`, its reason beginning "NERVUS IS DOWN".*
- **A database newer than nervus knows is refused** (`database.py`), and so is a backup's (ADR-0027
  question 5). **A table added keeps the version** (ADR-0014 decision F).
- **The deployment record is not exported** (ADR-0019 decision H), so the friends' upgrade lives in
  the product: `install.sh` and `docs/install.md`.

## Not chosen

- **Upgrades by themselves, on a timer:** an upgrade restarts nervus, may show a recovery key once,
  and may ask clients to restart; a person should be at the terminal. And the preview is private: a
  timer would need a credential for it on nervus's machine.
- **Signed exports, checked by the upgrade:** the check would run from the tree it checks. A friend
  who wants that assurance compares the commit the plan prints with the one the operator announced.
- **A package, or the container image, as what an upgrade installs** (ADR-0023 question 7c, ADR-0005
  decision 1): later, if at all; that image would bring an upgrade of its own.
- **Upgrading the system or its Python:** the system's own. A new Python is taken up by the next
  nervus upgrade, which builds its venv afresh.

## Not settled here

- **The libraries below nervus's own.** Every install and upgrade takes what the package index
  offers on the day below `pyproject.toml`'s eight (Context, point 2), so a friend can install a set
  no test ran against. A lock file (every library at an exact version with its hash, installed with
  `pip --require-hashes`) would make each install the set the export's tests ran, and refuse a file
  the index changed. It changes the install and the export as much as the upgrade, so it is a
  question of its own, raised here and not resolved. An upgrade that fails on such a library goes
  back by itself (question 7), so the upgrade need not wait for it.

  **Settled 2026-11-15, decided by the operator: a lock file.** Asked whether to add one, the
  operator first asked: "So in my mind, the idea of locking things to a particular version of
  dependencies makes it seem like it could get out our date really easily because if I'm not going
  through and making sure to update every single dependency in package, then it's just gonna stay
  locked there and anybody who wants to install this it's gonna need to install a bunch of old
  libraries eventually. But again, I don't come from this world so I don't know whether this is
  normal practice or best practice for self or individual created software like this. So I really
  am in need of your input."

  The session's answer. The eight named libraries are already at exact versions until a release
  moves them; the lock applies that rule to what they need in turn. An installed nervus changes
  its libraries only at an upgrade, lock or no lock, so the lock changes only what a new install
  or an upgrade fetches: the set the release's tests ran, in place of the day's. Old libraries are
  cured by a release either way, so the lock is made again, at the newest versions, for every
  release, and the export refuses a release whose lock was not made for it. A lock kept in the
  repository is standard practice for software that is installed and run; the advice against one
  is for libraries other software builds on. And the installer runs as root on the machine that
  holds nervus's keys, where libraries fetched unpinned are the one place a broken or tampered
  upload gets in unseen. What a lock does not change: a fix in any library reaches an
  installation only through a release.

  Asked again, the operator chose **"Yes, add it (Recommended)"**. So:
  - **`requirements.lock`, at the top of the repository:** every library an install fetches, at
    one exact version with the SHA-256 of each of its files: nervus's eight, what they need in
    turn, and what builds nervus's own package; for every system, and every Python the installer
    accepts.
  - **Made by `tools/lock-libraries`,** with `uv`, at the newest versions `pyproject.toml`'s eight
    allow, for one release: its first lines name the release it was made for.
  - **The installer, the upgrade and the hand steps install from it** with pip's hash-checking
    mode, and then nervus's own package with nothing more fetched. A file whose content differs
    from the lock's stops the install, or the upgrade before nervus is stopped. A tree whose lock
    is not its release's is refused before anything changes.
  - **The export refuses a release whose lock was not made for its number,** or whose lock does
    not hold `pyproject.toml`'s eight at their versions (ADR-0018 decision E's checks gain it).
  - **The tests run on the lock's set:** one of them compares the libraries it runs with against
    the lock.

## Consequences

1. **For a friend:** `git pull`, read `CHANGES.md`, `sudo ./install.sh --upgrade` and "yes"; a backup
   and a restart, under a minute without nervus; the check of that backup with the recovery key;
   and a client session restarted when `CHANGES.md` says so.
2. **For nervus:** the installer's `--upgrade` and `--back`; installs in release folders; the
   release number in `nervus-ctl status` and the web UI; and, with the first release that raises the
   database's version, migrations at start and `restore` accepting an older database.
3. **For each export:** its release number raised, and its `CHANGES.md` section, both checked by the
   export (ADR-0018 decision E gains the two checks).
4. **For every release from here:** a tool keeps working as the last release's clients call it
   (question 10); a changed command line goes through the drop-in written again (question 5); the
   database's version moves only as ADR-0014 F says, with its migration (question 6); a one-time
   step is kept while it can be needed (question 8).
5. **For the first installation:** question 11.
6. **ADR-0023 question 7 is amended** by question 1: the installer upgrades an installation when
   told to. Its verification 2 stands, the installer now naming both releases.

## Order of work

Each step waits for the operator (rule 1), and is built as the code around it is: tests named for
the guarantee they show, each guarantee broken on purpose and seen caught, the whole suite passing at
the end of each step (`pytest`, both folders), its count recorded in `CURRENT_STATE.md`. The suite's
result is recorded before the first change.

0. ~~The operator's decisions on questions 1 to 11.~~ Done 2026-11-01: all as recommended.
1. ~~**The release number** (question 2): `pyproject.toml` the one place it is written, which the
   package reads its own from; `nervus-ctl status` and every page of the web UI say it; `CHANGES.md`
   begun, with the next export's section; `tools/export-preview` refuses a number not above the
   preview's last export's and a `CHANGES.md` without its section. In the same step, the first
   installation's deploy tools find nervus's package file whatever its number (question 11), so its
   next deploy does not stop.~~ **Built 2026-11-01**, not deployed, with two readings the operator
   confirmed the same day, landing it ("All right. Land step one"):
   - **The number's form:** three numbers with no leading zeros, as 0.1.0 and 0.2.0 are. pip
     takes 0.2 and 0.2.0 for one release, and the package built from 0.02.0 says 0.2.0, so a freer
     form would let two releases compare as different where pip sees one.
   - **"Every page of the web UI" read as every signed-in page.** The pages for signing in keep to
     ADR-0011 verification 5: without a session, the web UI shows nothing but how to sign in.

   One limit, left for the operator: the first installation's deploy still refuses, as "nothing to
   deploy", a release whose number alone changes, since it checks what it installs by the code,
   which is the same. That installation then says the older number until code changes; step 8 ends
   it. The export also leaves `.git` and Python's bytecode out of what it shows as changed, now
   that a checkout of the preview is always given (`--against`).
2. ~~**Release folders** (question 3): `install.sh` installs into `/opt/nervus/releases/`, with
   `/opt/nervus/.venv` its link; `docs/install.md`'s hand steps follow, or say that a hand install is
   upgraded by hand.~~ **Built 2026-11-01**, not deployed. It raised three questions no record
   answered, two of them binding every later release (question 8a), put to the operator with options;
   **decided by the operator the same day, each as recommended**, on the building session's judgment
   that each is standard practice ("I'm relying on your judgment as to whether this is something
   novel and exotic we're inventing or whether this is standard good practice for releases"):
   - **A release's folder is named `<number>-<code>`**, its code the first 12 hex digits of one
     SHA-256 over what the folder holds, worked out by `tools/release-name` the same way for a clone
     (from `git archive HEAD`) and for a plain copy: for each file or link, sorted by its path's
     bytes, its kind (a file, a file its owner may run, a link), the SHA-256 of its bytes or of the
     link's target, and its path, each ended by a NUL. Left out: at the top, `.git`, `.venv`,
     `secrets`, `transfer`, `releases`, `hosts.yaml` and `.release`; at any depth, `__pycache__`. So
     a clone and an archive of one export name one release, and the same number with other code
     names another, as question 2a needs. The tree's own `hosts.yaml` is not copied into the folder.
   - **The hand steps follow the layout**, naming the release with the same `tools/release-name`,
     and say that a hand install is upgraded by hand.
   - **No record file.** An installation is this installer's when its drop-in's first line is the
     installer's own and `/opt/nervus/.venv` is a link into `releases/`, made only once the release's
     venv is whole; the current release is the one the link leads to. The hand steps lay out the
     same folders but write no such first line, so the upgrade refuses them, as question 8a says.
   The rough edge step 5 names, "Updating means installing a newer tree by hand", is gone: followed
   over release folders it would change the release kept for going back. Until the upgrade is built,
   `docs/install.md` says a newer release goes onto a new machine by a backup and `install.sh
   --restore`; step 5 replaces that with "Upgrading". **Its owners, decided and built 2026-11-03**
   (question 12, raised by its review): the code root's, unpacked as root's whoever owned the tree,
   and nervus's account given only `secrets/`, `transfer/`, `hosts.yaml` and `/var/log/nervus`, by
   the installer and the hand steps alike, which the tests now compare; not deployed.
3. ~~**`install.sh --upgrade`** (questions 1 to 6, 7a, 8 to 10, and "Settled already"): "The
   upgrade, in order", run in its tests under `NERVUS_INSTALL_ROOT` with root's commands stood in
   for, as the installer's are; each refusal, going back by itself, and the drop-in written again,
   each broken on purpose and caught.~~ **Built 2026-11-04**, not deployed, and not yet tried on a
   machine (step 6). Beyond `install.sh` it needed three small pieces:
   - `nervus-ctl upgrade-record`: the operator records of an upgrade's start, its end and its going
     back, each written by the release running at that moment, with its own unit;
   - `nervus-ctl backup --last-check`: the plan's line on when the recovery key last opened a
     backup, without `status`'s asking every machine for its jobs;
   - `tools/check-up`: nervus's MCP endpoint and web UI asked over HTTPS, checked against nervus's
     own root, as the first installation's deploy asks its endpoint; shown here against a real
     nervus, not only stand-ins.
   A later release's installer calls an earlier release's `upgrade-record` and `backup
   --last-check`, so their arguments keep their shape. One reading, confirmed by the operator
   2026-11-04 ("i confirm the naming reading"): the plan names each release by its folder's name, and
   a clone's commit. An archive's SHA-256 is
   not the upgrade's to see, since it runs from the tree already unpacked, so a friend compares it
   before unpacking, as `docs/install.md` has them do for the install; step 5 says so.
4. ~~**`install.sh --back`** (question 7b), with its refusal once a migration has run, tested with a
   stand-in release that raises the version.~~ **Built 2026-11-04**, not deployed, and not yet tried
   on a machine (step 6). It does as going back after a failed start does, on the person's word: the
   kept release current again with its units, the drop-in written for its command line, the
   database kept, nervus judged up, and back where it was by itself if not. So, like that going back,
   it makes no backup first. It installs nothing from the tree it runs from, so any tree with the
   script will do, in any state, the running release's own folder too. No record names the release
   kept (question 3a), so the numbers do: the other whole release below the running one. One above
   is what a failed upgrade, or going back, left, and the way there is an upgrade. Another build of
   the same number counts only if none is below, and more than one candidate is refused, naming them.
5. ~~**The docs:** `docs/install.md` gains "Upgrading" (where the newer tree comes from, by tier; the
   command; what it shows; going back; the check after) and loses its rough edge "Updating means
   installing a newer tree by hand"; `docs/clients.md` says what a client does after an upgrade; the
   preview README says nervus upgrades. Tested as written.~~ **Built 2026-11-04**. `docs/install.md`
   and the README say the upgrade is shown by tests, its trial on real machines still to come, until
   step 6 shows it; `CHANGES.md`'s 0.2.0 section names it too.
6. ~~**The trial**, a procedure on throwaway machines, kept as simple as ADR-0027's: a nervus installed
   from one release's tree, a machine added, a real client's call; the newer release by `git pull`
   and `install.sh --upgrade`; the same client calling the same machine, its configuration unchanged;
   then an upgrade to a release made on purpose not to start, which goes back by itself. The rest by
   tests.~~ **Done 2026-11-05** (procedure 051), to its end, with one slip of its own that showed the
   first finding. From a person's clone, as the guide writes the commands, nervus went to the newer
   release in under two seconds of stopping; every piece the Context's table keeps was the same by its
   hash, and the audit log's old bytes; the same Claude Code, its configuration unchanged, ran a command
   on a machine added under the older release, whose own journal names it. A release that would not
   start went back by itself, its link, units and drop-in the same by hash. It also moved a flag in a
   unit's command line, so the drop-in was written again under real systemd, ran `--back` once, and went
   forward again after it. **Its findings; the first four fixed the same day at the operator's word
   ("Yes, fix them"), by tests, not deployed:**
   - **The installer took the person's umask,** which `sudo` passes on: from a strict one an install
     stopped partway, an upgrade built a release nervus could not read and went back, going back wrote
     the drop-in so that every later backup failed, and root's `git status` could leave the person's
     clone unusable. Now it sets its own, gives the drop-in its mode, and writes nothing in the clone.
   - **A half-finished install left no way forward:** it then said nervus was installed. Now it says
     the install did not finish and what to remove, as it stops and on every later run, and only where
     nervus has never run: no database, backups, audit log or recovery key, since a machine may hold
     an earlier installation's backups.
   - **The check after a start asked once,** 5 seconds after it became active, so a machine that took
     longer to listen would have a good release sent back. Question 7 sets no time for the answer, so
     nervus now has up to a minute to begin listening; any answer counts at once, and it must still be
     on the same main process after it.
   - **The reason given said little.** It now comes with nervus's last lines since that start.
   - **The backup made before an upgrade is its day's only while it is its day's last** (ADR-0027 step
     notes): for step 7.
7. **Migrations** (question 6): none now. The first release that raises the version builds them, its
   migration, their tests, and `restore` accepting the older database, under this record. It must then
   answer procedure 051's finding 5: a backup made the same day after the upgrade removes the one copy of
   the database the older release can read, which going back and the guide send a person to.
   **Finding 5 answered 2026-11-15, decided by the operator, ahead of the first migration.** Asked how
   the backup made before an upgrade should be kept: **"Until the next upgrade (Recommended)"**, over
   keeping it so only where the upgrade raises the database's version. The backup an upgrade makes is
   kept under a name of its own, which the daily keeping never removes (ADR-0027 question 4), for as
   long as the release before is kept for going back: the next upgrade that comes up removes it, having
   made its own. `install.sh --back`'s refusal and the guide name it. What is left of this step is the
   migrations themselves, which wait for the first release that needs one, as question 6a decided.
8. ~~**The first installation** (question 11), as decided: a procedure of its own, after the trial.~~
   **Done 2026-11-06** (procedure 052), rehearsed first on a throwaway machine to its limits. One reading
   of question 11: its venv was copied, not moved, with the release's own package installed in the copy.
   The upgrade writes its first record with the running release's `nervus-ctl upgrade-record`, which the
   release it ran lacked; and a copy lets nervus serve on while it is made, and makes going back a rename.
   Its first `install.sh --upgrade` then ran as a friend's would, from a tree copied in, in half a minute at
   its limits, and brought the libraries `pyproject.toml` declares. With clients connected, nervus takes its
   whole grace to stop, so an upgrade is about 7 seconds of downtime, not 2. Its own deploy tools were then
   replaced by one that wraps the upgrade with what question 11 says stays its own.

## Verification

Moves to Accepted when observed, in tests first seen to fail or on throwaway machines by the trial:

1. Over a release installed by its own installer, `install.sh --upgrade` from a newer release's tree
   ends with the newer release running, and every piece the Context's table keeps as it was: keys and
   certificates by fingerprint, the inventory, the token file, the off switch, the database's rows;
   the audit log as it was, followed by the upgrade's records. A real client, its configuration
   unchanged, runs a command on a machine added under the older release. (The trial: **observed
   2026-11-05**, procedure 051.)
2. When the new release does not come up, the upgrade goes back by itself: the release before runs
   again, from its own venv, with its unit and drop-in and a database it can use (question 7), and
   the audit log says so. (The trial, and tests: **observed 2026-11-05**, procedure 051.)
3. Refused before anything changes: an older release; the same release and code; uncommitted changes;
   an installation this record's installer did not make; a drop-in not in the installer's shape; a
   package missing without `apt-get`; a backup that fails. (Tests.)
4. After an upgrade whose unit changes its command line, systemd runs the new command line with
   exactly the installation's own flags. (Tests; and under real systemd, procedure 051.)
5. Where the new release raises the database's version, going back puts back the copy; where it does
   not, the database is kept. (Tests, with a stand-in release that raises it.)
6. `install.sh --back` puts back the release before after a good upgrade, and is refused where the
   database's version is newer than that release knows. (Tests; its first half also in procedure 051.)
7. An upgrade from two releases back shows both `CHANGES.md` sections, and ends as item 1 does.
   (Tests.)
8. The export refuses a release number not above the preview's last export's, and a `CHANGES.md`
   without the release's section. (Tests.)
9. Without `--upgrade`, on a machine that has nervus, the installer changes nothing and names the
   installed release and the tree's. (Tests; ADR-0023 verification 2 stands.)
10. From the amendment of 2026-11-06. An off switch nervus cannot read is refused before anything
    changes, and what the new release lacks is made before the stop, a failure there stopping nothing.
    A stop that fails, a step of the switch that fails, a signal and a terminal that has gone each go
    back by itself, on `--upgrade` and on `--back`. (Tests, and under real systemd and `sudo`, a
    terminal really lost, by the trial: **observed 2026-11-06**, procedure 053.)
