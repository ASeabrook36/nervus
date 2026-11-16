# ADR-0027: backing up nervus, and proving a restore works

**Status:** **Accepted 2026-11-01, at the operator's word** ("Yes, accept it"), every verification
item observed: items 1 to 3 and 5 to 10 in tests, each first seen to fail, and item 4 on throwaway
machines by the trial (procedure 047). Built 2026-10-28 and 10-29, deployed on the first
installation 2026-11-01 (procedure 048; see "Order of work"). ADR-0007 decision 7 amended as
question 2 says. **Decided by the operator on 2026-10-28**, in a Claude Code session: questions 1
to 8 as recommended, except question 4's keeping of backups, and with question 7 kept simple ("daily
backups for a week, weekly backups for a month, monthly backups for a year, and nothing older than a
year. otherwise all as recommended. although i want to keep the restore proving simple because that
could get really complicated"). Each question keeps its options, so the record shows what was not
chosen. **Proposed 2026-10-28** the same day.
**Date:** 2026-10-28
**Asked for by:** the operator, item 5 of the order before friends are invited: "Backups: an ADR
first (what, where, how a restore is proven)".
**Settles what earlier records left here:** ADR-0005 consequence 6 (refuse loudly when nervus's key
is gone but enrolled machines remain), deferred to this record by ADR-0015 question G ("a database
that names enrolled machines, without nervus's key ... left to the backups ADR"); ADR-0011
consequence 4 ("backups now include the database"); and whether audit-log retention (ADR-0005
consequence 7, ADR-0013) is settled here (question 8).
**Builds on:** ADR-0001 s10 (what cannot be audited does not happen); ADR-0005 s4 (no MCP tool reads
the audit log); ADR-0007 (the assets, the tiers, decision 7's "no export path" for secrets);
ADR-0009 decision 4 (a copy is pulled, by a key that can only read); ADR-0003 (the off switch and
lockdown); ADR-0011, ADR-0012, ADR-0014, ADR-0022, ADR-0024, ADR-0026 (what the database holds);
ADR-0021 (nervus's TLS root, issuer and certificate); ADR-0023 (where nervus may run, the installer);
ADR-0025 (nervus's SSH certificate authority, which every machine trusts).
**Amends, now Accepted:** ADR-0007 decision 7 (question 2).
**Evidence:** procedure 045, read-only, on the first installation: what nervus keeps, where, and
what each piece's loss costs, read off the machine and from the code.
**Written to the policy of ADR-0019:** this record names no system. Paths are those nervus's own
unit and installer use.

## Context

### What nervus keeps

Read from nervus's unit, installer and code, and observed on an installation by procedure 045:

| piece | where | secret | if it is lost |
|---|---|---|---|
| **SSH certificate authority key** | `secrets/nervus_ca_ed25519` | yes: signs a login to every machine | nervus refuses to start. **Every machine trusts this key and no other** (ADR-0025), so a new one means every machine's line rewritten, by hand or by enrolling it again. |
| SSH key | `secrets/nervus_ed25519` | yes | nervus refuses to start. Replaceable: machines trust the CA, which certifies whatever key nervus presents (ADR-0025 question 1a). |
| TLS key, certificate | `secrets/tls.key`, `tls.crt`; a renewal in the state folder's `tls/` | key yes | nervus refuses to start. No command today makes a new key under the same issuer. |
| TLS issuer key and certificate, root certificate | `secrets/tls-issuer.*`, `tls-root.crt` | issuer key yes | a new authority, and every client trusts nervus again. The root's key was never written, by design (ADR-0021). |
| **The database** | `/var/lib/nervus/nervus.db` | hashes only: tokens issued in the UI, sessions, sign-in links, codes | **nervus starts and makes an empty one, saying nothing.** Every enrolled machine and VM, every token issued in the UI, the tier and the declared ranges are gone; the machines still trust the CA; every UI-issued token is refused. |
| **The audit log** | `/var/log/nervus/audit.jsonl` | no, but it says what every client did, and what it ran | nervus starts a new one at the next call. The record of everything before is gone, unless a copy exists. |
| Hand-written tokens | `secrets/tokens.yaml` | **yes, each in clear** | those clients are refused; tokens made again and given out again. |
| Inventory, host keys of hand-written machines | `hosts.yaml`, `secrets/known_hosts` | no | written again by hand, host keys read again off each machine. |
| A hypervisor connection's credentials (ADR-0009) | named by the unit's drop-in, in `secrets/` | yes | made again with the hypervisor's own tool. |
| The off switch | `/var/lib/nervus/switches.yaml` | no | nervus refuses every client until it is made again, and **a client switched off comes back on.** |
| The unit's drop-in | `/etc/systemd/system/nervus.service.d/` | no | the installation's own flags: written again. |
| Sessions, sign-in links, enrollment codes | the database | hashes | a sign-in, a code made again. Short-lived by design. |
| Exports, uploads, the transfer folder | `/var/lib/nervus/exports`, `uploads`; `/opt/nervus/transfer` | the files are clients' | a transfer repeated. Short-lived by design. |
| Code and its venv | `/opt/nervus`, `.venv` | no | installed again from the release. |

Today nothing in nervus backs any of it up, and the docs say nothing about backing it up.

### What a backup is for, and what it is not for

Two losses:
- **A mistake on nervus's own machine:** an upgrade that goes wrong (item 6 of the order before
  friends, the upgrade path, will need this), a damaged database, a file removed by hand.
- **nervus's machine itself lost:** a disk failing, a VM or container deleted, a laptop gone.

Not a third: **a compromised nervus.** A backup brings back the same keys, so it brings back
whatever an attacker took with them. Recovering from a compromise is new keys and every machine
enrolled again, which is not this record's subject.

### Four things that make this harder than copying a folder

1. **The secrets.** A backup that can bring nervus back must hold the CA key, which signs a login to
   every machine, at full access root. ADR-0007 decision 7 says nervus's secrets have "no export
   path". A backup is one, so this record has to say how it is protected, and amend decision 7.
2. **The database cannot be copied as a file while nervus runs.** It is in WAL mode (write-ahead
   logging: recent changes sit in a side file until merged), observed by procedure 045; a copy of
   the main file alone, or of both at slightly different moments, can be missing changes or
   damaged. SQLite's own backup command copies it whole and consistent while nervus runs.
3. **The audit log only grows.** On the first installation, about 0.46 MB a day of steady use, and
   it compresses only to about half (gzip and zstd measured on 21.6 MB, 2026-10-28: 12.8 MB and
   12.1 MB), since much of each record is random identifiers. A year at that rate is about
   170 MB, about 100 MB compressed, in each backup that carries the whole log.
4. **nervus starts on whatever it finds.** A missing database is made empty without a word, a
   missing audit log is started afresh. A restore that misses a piece, or a backup put back over
   newer keys, would start a nervus that looks fine and has forgotten its machines.

### Where nervus may run, and where a backup can go

ADR-0023's tiers decide what a copy on another machine protects against:
- **Tier 1:** nervus on a computer separate from the everyday one. A copy on the everyday computer
  survives nervus's computer being lost; but the everyday computer is where hostile programs may run,
  so a copy there must give them nothing they can use.
- **Tiers 2 and 3:** nervus on the everyday computer. A copy beside nervus guards only against
  nervus's own mistakes; surviving the computer's loss needs another disk, or storage elsewhere.

A copy made by the platform nervus runs on (a hypervisor's backup of nervus's VM or container, a
whole-disk backup of a laptop) holds every secret in clear, and is reachable by whatever can reach
that platform's storage. ADR-0025 decision 5 already says it: where a copy exists, no client may
reach it.
Such a platform may also write its backup files readable by every account on that host (seen by
procedure 046), so a client with any shell there could read them: their permissions need checking,
not only the platform's own access rules.

## Questions

### 1. What a backup holds

- **a. Everything nervus cannot make again without touching machines or clients, taken at one
  moment; nothing short-lived.**
  - In: the SSH key and CA key; the TLS key, certificate, renewal, issuer and root; the hand-written
    token file, inventory and `known_hosts`; any hypervisor credentials the unit names; the off
    switch; the database, by SQLite's backup command; the whole audit log; the unit's drop-ins.
  - Out, deliberately: the code and venv (installed from the release); the files of exports, uploads
    and the transfer folder (clients' files in passing). A restore clears from the database what is
    short-lived: sessions, sign-in links, unused enrollment codes; and marks unfinished exports and
    uploads failed, so nothing waits for a file that is not there.
- b. As a, without the audit log, which is left to a copy of its own (ADR-0009 decision 4). Smaller
  backups; but ADR-0025 decision 5 says nervus must not lean on a copy many people will never make,
  and a restore without the log starts the record again from nothing.
- c. A whole-machine image, code included, made by the platform. Nothing to build; but every secret
  in clear, the database possibly mid-write, and no restore onto another kind of machine.

*Recommended: a.* **Decided 2026-10-28: a.** It brings back everything a person would otherwise rebuild by hand, and the record
of what clients did. Clearing sessions on restore also means a stolen browser session does not come
back with it.

### 2. The secrets in a backup, and how they are protected

- **a. In the backup, and the whole backup encrypted to a recovery key nervus never holds.** The
  installer makes a recovery key pair: nervus keeps the public half, which can lock a backup but not
  open it; the private half is printed once on the installer's terminal, never in a web page, to be
  kept by the person in a password manager or on paper, and never on nervus's machine or on a machine
  a client reaches at full access. So nervus makes backups unattended and cannot read them, and a
  backup is safe to put anywhere. The format is `age` (a small, widely used file-encryption tool,
  packaged in Debian; procedure 045 found it offered there), so a backup can be opened with the
  standard `age` tool, without nervus. `nervus-ctl recovery-key` makes a new pair for an installation
  that has none, or replaces one; backups already made stay locked to the old key.
  ADR-0007 decision 7 is amended: nervus's secrets leave it only inside a backup encrypted to a key
  nervus does not hold; never through an MCP tool, `put`/`get`, or in clear.
- b. Encrypted with a passphrase the person chooses, which nervus keeps so that it can make
  scheduled backups. One secret to remember instead of a key file; but nervus holds what opens its
  backups, so a platform's copy of nervus's machine carries both the backup and its passphrase.
- c. Secrets left out. A restore then makes new keys: every machine and every client again, which is
  most of what a backup is for.
- d. Not encrypted; the place it goes is trusted to protect it.

*Recommended: a.* **Decided 2026-10-28: a.** It is the one option where a lost backup gives nothing away and nervus needs no
secret to make one. The cost is a recovery key a person must keep; question 7 makes them prove they
still have it.

### 3. Where a backup goes

- **a. nervus writes each backup into its own state folder (`/var/lib/nervus/backups`, `0600`), and
  getting a copy off the machine is the person's, in one of three ways the docs describe for each
  tier:** downloading it from the UI, signed in; a pull by another computer, as ADR-0009 decision 4's
  audit copy is pulled; or the platform's own backup of nervus's machine, which now carries a
  consistent, encrypted file. Since each backup is encrypted, any of these is safe; only the recovery
  key needs a careful home. The UI and `nervus-ctl status` say when the newest backup was made and
  when one was last downloaded, and the docs say, for tiers 2 and 3, that a backup on the same
  computer does not survive that computer.
- b. nervus sends each backup to a destination set in the UI (SFTP, S3-style storage, a network
  share). Off the machine without the person doing anything; but nervus then holds credentials for
  that destination, and a compromised nervus can delete what it pushed. More to build and support.
- c. nervus makes no backup; the docs tell each tier how to back up nervus's machine with what they
  have. Nothing to build; every secret in clear, and see question 1c.

*Recommended: a.* **Decided 2026-10-28: a.** It keeps nervus's part small (make a file, keep a few) and puts the copy where each
person's own arrangements already are. b can follow later without changing the file.

### 4. How often, and what starts a backup

- **a. Once a day by a systemd timer, before every upgrade, and whenever asked** (`nervus-ctl backup`,
  or a button in the UI). The upgrade path (item 6) makes one first. nervus keeps the newest **7** and removes older ones. A day without a new backup shows
  as a warning in the UI's header and in `nervus-ctl status`. Making and failing to make a backup are
  audited (actor `operator`).
  At the first installation's rate (Context, point 3), 7 backups are about 85 MB today and about
  700 MB after a year; question 8 is where that is watched.
- b. As a, and also within minutes of every change to the database, the secrets or the off switch.
  Less to lose; more moments to get right, for a state that changes a few times a week.
- c. Only when asked.

*Recommended: a.* What a daily backup can miss is at most a day's enrollments and tokens, each of
which the person can redo from the UI; question 6 makes sure they are told.

**Decided 2026-10-28: a, with the operator's own keeping in place of "the newest 7":** a backup a
day kept for a week, one a week for a month, one a month for a year, and nothing older than a year.
At most about 23 backups at once (7 daily, 4 weekly, 12 monthly, fewer where one serves twice). Each
carries the whole audit log, so at the first installation's rate (Context, point 3) they take about
280 MB today and, estimated, 1.5 to 2 GB after a year, against about 700 MB for 7. Question 8 is
where that is watched; the space a backup folder takes shows in `nervus-ctl status`.

**Amended 2026-11-15 by ADR-0029 step 7, decided by the operator** ("Until the next upgrade
(Recommended)"): beside this keeping, the backup made before an upgrade is kept, under a name of its
own, until the next upgrade comes up. This keeping held it only while it was its day's newest, so a
second backup the same day removed it (procedure 051, finding 5).

### 5. How a restore is done

- **a. One command, on a nervus installed from the same release or a newer one:
  `nervus-ctl restore <file>`.** It asks for the recovery key on the terminal (pasted, never saved),
  then:
  1. opens the backup and checks it whole: the database passes SQLite's own integrity check, and
     each private key matches its public half;
  2. stops nervus;
  3. moves the state it replaces into a dated folder beside it, never deleting it;
  4. puts the backup's pieces in place, owned and permissioned as the installer makes them;
  5. clears the short-lived rows (question 1a) and switches every client off (lockdown, ADR-0003);
  6. starts nervus, whose first audit record says which backup, made when, it was restored from.
  The installer gains `--restore <file>`: install as usual, but instead of making keys, run this.
  A database from a newer release is refused, as nervus already refuses one (its schema version).
- b. Documented steps by hand (`age -d`, then `tar`, then permissions). Works without nervus's code,
  and is documented anyway as the last resort, but too many places to get one wrong.
- c. In the UI: upload the backup and paste the recovery key. Restoring is mostly needed when
  nervus is not running, and the recovery key would be typed into a web page.

*Recommended: a.* **Decided 2026-10-28: a.** One command that refuses a bad backup before changing anything, and keeps what it
replaced. Lockdown means a restored nervus acts for no one until the person has looked: a client
switched off after the backup was made does not quietly come back on.

### 6. What nervus does when it starts on a restored or partial state

- **a. nervus records who it is, and refuses to start as someone else, or as no one, without being
  told.** At its first start it writes into the database the fingerprints of its SSH key, its CA key
  and its TLS issuer. At every start:
  - **all present and matching:** it starts;
  - **a key missing, or not the one the database names:** it refuses, naming the piece, and says to
    restore that piece or the whole backup. This is ADR-0005 consequence 6's refusal, and ADR-0015
    question G's case: a database restored without its keys, or put beside newly made ones;
  - **no database, while the audit log already holds records:** it refuses to make an empty one:
    nervus has run here before and its database is gone. It says to restore a backup, or to start
    empty on purpose with one `nervus-ctl` command, which is audited;
  - **a database, but no audit log:** it refuses likewise, since nervus never removes its log; the
    same command starts a new log on purpose, its first record saying so;
  - **after a restore:** the Machines page and `nervus-ctl status` say "restored from a backup made
    <date>: machines enrolled and tokens issued after it are not here", until the next backup.
- b. Only the third case: never make an empty database where the log shows nervus has run. Keys as
  today, so a database beside new keys still starts and fails at every machine.
- c. As today, and the docs say how to check after a restore.

*Recommended: a.* **Decided 2026-10-28: a.** Each case is one comparison at start, and each turns a quiet, confusing failure
(every machine refusing nervus, every client refused) into one sentence saying what is missing.
Machines enrolled after the backup still trust the same CA; adding them again from the Machines page
works as before.

**Added by the operator on 2026-10-28, after step 2 was built: a key replaced on purpose.** The
refusal cannot tell a key swapped by accident from one swapped on purpose; only the person can.
`nervus-ctl accept-keys` shows which key differs, its old and new fingerprints and what the change
costs (the SSH key: nothing, machines trust the CA; the CA key: every machine enrolled again; the TLS
issuer, or a certificate given to nervus: every client trusts nervus again), asks for the key's name
typed, writes an operator record, and records the keys as nervus's own. All three keys stay checked.
A tool that replaces a key on purpose records the new one itself, as `nervus tls-init --upgrade`'s
new issuer already is. A backup carries the keys and the database together, so restoring one brings
back a set that matches.

### 7. How a restore is proven

- **a. Twice over: once by a trial on throwaway machines, which is this record's acceptance; and on
  every installation, by the person, a check that their recovery key opens their newest backup.**
  - **The trial** (a procedure, run again before any preview export that changes this): install a
    throwaway nervus from the guide; set it up; add a throwaway machine by Connect; issue a token to
    a real Claude Code and run a command on that machine; make a backup; **destroy nervus's machine**;
    install a second throwaway nervus with `--restore`, at the same name; switch the client back on;
    then the same Claude Code, its configuration unchanged, runs a command on the same machine,
    whose own journal names the client under the same CA. Every refusal of question 6 is then
    caused on purpose and seen. *(Left to tests by the decision below.)*
  - **The check:** `nervus-ctl backup --check <file>` asks for the recovery key, opens the backup,
    runs question 5's checks, compares its audit log with the live one (the backup's must be the
    start of it), and changes nothing. The docs ask for it once after install and after each
    upgrade, and the UI shows when it last passed. A backup nobody can open is the common way
    backups fail, and only the person holding the key can show theirs is not that.
- b. As a, and also the real installation's own backup restored onto a throwaway nervus that a real
  client uses on a real machine. The strongest proof; but while it lasts, two bastions hold the real
  CA key and the real machines answer both, the throwaway's audit log a second record of real calls.
- c. Tests only.

*Recommended: a.* It proves the whole path with a real client, without a second bastion over the real
machines, and the check carries the proof to each installation, where the recovery key is the part
most likely to be lost.

**Decided 2026-10-28: a, kept simple, as the operator asked** ("i want to keep the restore proving
simple because that could get really complicated"). The trial is the one path only: a throwaway nervus
with one throwaway machine and one real client; a backup; nervus's machine destroyed; a new one
restored with `--restore`; the same client runs a command on the same machine. Question 6's refusals
and question 5's checks are shown by tests, not by the trial. The check on each installation stays as
written: it is one command and changes nothing.

### 8. Audit-log retention

- **a. Stays separate.** This record fixes only that a backup carries the whole log and never trims
  it, and that the size a backup reaches shows in `nervus-ctl status`. Retention is decided when a
  log's size first matters, with the viewer's cost (ADR-0013); procedure 045's rate says that is
  months away on a home installation.
- b. Settled here: kept forever; the docs say how big it grows.
- c. Settled here: a new file each year, older years compressed and kept beside it and in backups.

*Recommended: a.* **Decided 2026-10-28: a.** Retention is a choice about how long a record of what agents did is worth keeping,
which deserves its own question; this record needs only that backups do not decide it by accident.

## Settled already

- **No client can make, list, read or restore a backup.** No MCP tool touches them (ADR-0005 s4,
  ADR-0007 decision 7); the UI's backup page is the operator's, signed in (ADR-0012).
- **What cannot be audited does not happen** (ADR-0001 s10): making a backup, downloading one, a
  restore, and starting empty on purpose are audited, actor `operator`.
- **A restore keeps nervus's names.** nervus's TLS issuer is limited to its DNS names (ADR-0021), so
  clients keep trusting a restored nervus only at the same name. Its address may change: machines
  trust the CA with no address restriction (procedure 045), and the installer writes the new address
  into the drop-in, as it does for any install.
- **A backup is made by nervus's own code, as the account nervus runs as**, which can read
  everything it backs up and write only its state folder; a timer runs `nervus-ctl backup` as root,
  which drops to that account, as `nervus-ctl` already does for the database.

## Not chosen

- **A second nervus kept in step**, for high availability: home scale does not need it, and two
  bastions holding one CA key is a hazard of its own (question 7b).
- **Backing up machines nervus reaches:** host management, which nervus is not (ADR-0025 "Not
  chosen").
- **Recovering from a compromised nervus:** see "What a backup is for".

## Consequences

1. **For a person installing nervus:** one more thing to keep, the recovery key, printed once by the
   installer. Then, from the docs for their tier, where to put copies, and one check to run.
2. **For nervus:** a backup module, a timer, five `nervus-ctl` commands (`backup`, `backup --check`,
   `restore`, `recovery-key`, and starting empty on purpose), checks at start, and a backup page in
   the UI. The installer gains the `age` package, the recovery key and `--restore`.
3. **ADR-0007 decision 7 is amended** by question 2: the one way secrets leave nervus.
4. **ADR-0005 consequence 6 and ADR-0015 question G are answered** by question 6.
5. **For the upgrade path (item 6):** an upgrade makes a backup first.
6. **For the first installation:** after the deploy, a recovery key made with `nervus-ctl
   recovery-key`, and where its copies go is decided in its deployment record. A platform backup of
   its nervus holds every secret in clear (procedure 045, finding 3), so that record decides it with
   that in view.

## Order of work

Each step waits for the operator (rule 1). Written for questions 1 to 8 as decided, so that an agent
that has read `AGENTS.md` and this record can build it. Where this section and the questions
disagree, the questions win.

How to build each step, as the code around it is built: a module docstring that lists what the
module holds to; tests named for the guarantee they show; each guarantee broken on purpose and seen
caught before its test is kept; the whole suite passing at the end of each step (`pytest`, both
folders), its count recorded in `CURRENT_STATE.md` with the step. Record the suite's result before
the first change, and judge each step against it.

**`age` is used as a program, not reimplemented.** Question 2 chose its format so that a backup
opens with the standard tool; nervus runs that same tool (`age`, and `age-keygen` to make a key
pair), found on `PATH`, and refuses with "age is not installed" without it. No encryption is written
in nervus's own code. The tests that encrypt or decrypt need `age` installed where they run, and skip,
saying so, where it is not, as the tests that need `tmux` do.

**Nothing is written in clear.** A backup is put together in memory and streamed into `age`, so no
unencrypted copy of a secret or of the database touches a disk, the backup folder included; a
recovery key's private half, when nervus is given one to check or restore, is passed to `age` through
a pipe, never a file.

0. **The operator's decisions on questions 1 to 8. Done 2026-10-28.**

1. ~~**Making a backup.** A new module `src/nervus/backup.py`; tests in a new `tests/test_backup.py`.~~
   Built 2026-10-28, not deployed: 27 tests, each guarantee broken on purpose and caught (21 breaks).
   Two differences from the text below. A missing audit log refuses the backup before its first
   record, which would otherwise start a new log and carry one line where the whole record was
   (found by the test of a missing log). And `make_backup` prunes itself once the backup is made,
   and its `backup_made` record names what it removed, so no backup is removed unrecorded and
   none after a failure; `prune(folder, now, keep)` takes the backup just made.
   - `Pieces`, a frozen dataclass: each thing question 1a backs up, by its **role**, with the path it
     has on this installation. Required: `ssh_key`, `ssh_ca_key`, `tokens`, `hosts`, `switches`,
     `database`, `audit_log`. Present only where the installation has them (`None` otherwise):
     `ssh_key_pub`, `ssh_ca_key_pub`, `known_hosts`, `tls_cert`, `tls_key`, `tls_issuer_cert`,
     `tls_issuer_key`, `tls_root_cert`, `tls_renewed`, `proxmox`, `proxmox_ca`; and `drop_ins`, a list.
     Step 3 builds it from the unit (`ctl.read_unit`); step 1's tests build it by hand.
   - `RECOVERY_KEY = "secrets/recovery.pub"`: where the recovery key's public half is kept, beside the
     other secrets, read-only to nervus as they are (the unit's `ProtectSystem=strict`). One line,
     `age1…`; `recipient(path) -> str` reads it and refuses anything else.
   - `make_backup(pieces, recipient, folder, audit, now=None) -> Path`. In this order:
     1. an operator record `backup`, with the file name it will make, before anything is read; if it
        cannot be written, no backup is made (ADR-0001 s10);
     2. the database, by SQLite's backup command (`Connection.backup`) into a database in memory,
        then `serialize()`: whole and consistent while nervus writes;
     3. every other file, read whole, once;
     4. the audit log **last**, up to its size at that moment and cut back to its last whole line, so
        that it holds the record of every change in the database it travels with, and the backup's
        own `backup` record;
     5. a `manifest.json`: the format (`1`), when it was made, nervus's version, the database's schema
        version, and for each piece its role, its path, its mode, its size and its SHA-256;
     6. one `tar.gz` stream of `manifest.json` and `pieces/<role>` (drop-ins as
        `pieces/drop_ins/<name>`), piped into `age --encrypt --recipient <recipient>`, written to
        `<folder>/nervus-backup-<UTC, 20261028T163000Z>.tar.gz.age.partial`, flushed to disk, and
        renamed to its name without `.partial` only once `age` has finished cleanly;
     7. an operator record `backup_made` (its file, size and SHA-256) or `backup_failed` (why).
     The folder is made `0700`, each backup `0600`. A required piece missing or unreadable refuses the
     backup, naming the piece: a backup that cannot bring nervus back is not one. A failure leaves no
     `.partial` behind and removes nothing.
   - `to_keep(made: list[datetime], now) -> set[datetime]`, a pure function: the newest backup of each
     of the last 7 days, of each of the last 5 ISO weeks within 31 days, and of each of the last 12
     calendar months within 365 days (UTC); nothing older than 365 days. `prune(folder, now) ->
     list[Path]` removes the backups not kept, after a backup has been made, never after one failed.
     It reads a backup's time from its name, not from the file's date (a copy changes that); it never
     touches a file whose name is not a backup's, and never the backup just made.
     *The newest of each day is kept, so a backup made before an upgrade is kept for a week only if it
     was that day's last; any other backup that day is removed at the next run.*
   - Tests: a backup made while another thread writes restores a database that passes
     `PRAGMA integrity_check` and holds every row committed before it began; it opens with the
     recovery key's private half by the standard `age -d`, and not with another key; it holds every
     piece `Pieces` names, each matching its manifest's SHA-256, and no export, upload or transfer
     file; a piece left out of `Pieces` (`None`) is absent from it; a required piece missing refuses
     the backup, naming it, and leaves no file; the audit log in it ends at a whole record and holds
     the `backup` record; the folder holds no `.partial` after a failure, nothing in clear at any
     time (no file in it but backups); the folder is `0700`, each backup `0600`; an audit log that
     cannot be written means no backup; `to_keep` keeps 7 daily, the weekly and the monthly, nothing
     over a year; `prune` leaves a file that is not a backup, and the newest, and does nothing after
     a failure.

2. ~~**Who nervus is.** `src/nervus/database.py`, a new `src/nervus/identity.py`, `src/nervus/__main__.py`;
   tests in a new `tests/test_identity.py` and in `tests/test_main.py`.~~ Built 2026-10-28, not deployed:
   20 tests, each guarantee broken on purpose and caught (15 breaks). Differences from the text below:
   recording who nervus is is audited first (`identity_recorded`, tool `nervus`), so after any first
   start the log exists, and a database that has recorded it beside no log can only mean a lost log;
   a TLS issuer appearing where none was recorded (`tls-init --upgrade`) is recorded, not refused.
   Every start now reads the SSH key's fingerprint, so tests that handed nervus a placeholder key
   now hand it a real one, and every test's audit log is kept in a folder of its own.
   **Answered by the operator the same day (question 6, `nervus-ctl accept-keys`, step 3):** replacing nervus's SSH key, CA key or TLS issuer on purpose, or
   moving to a certificate given to it, is now refused at start, and no command accepts it; question
   6 does not say how a deliberate change is made.
   - Two tables in `ADDED`; the version stays 1:
     ```sql
     CREATE TABLE IF NOT EXISTS identity (
         only INTEGER PRIMARY KEY CHECK (only = 1),
         ssh_key TEXT NOT NULL,
         ssh_ca_key TEXT NOT NULL,
         tls_issuer TEXT,
         recorded_at REAL NOT NULL
     );
     CREATE TABLE IF NOT EXISTS backup_event (
         kind TEXT NOT NULL,
         file TEXT NOT NULL,
         made_at REAL,
         at REAL NOT NULL
     );
     ```
     `identity` holds the SHA-256 fingerprints of nervus's SSH key, CA key and TLS issuer key (`NULL`
     where nervus serves a certificate it was given, and has no issuer). `backup_event` holds what the
     UI and `status` show (step 5): `made`, `checked`, `downloaded` and `restored`, with the backup's
     file and when it was made.
   - `identity.check(database, ssh_key, ssh_ca_key, tls_issuer_key)`: the first start records the
     three fingerprints (so does the first start of an installation from before this step); every
     later start compares them, and a missing or different key raises `IdentityRefused`
     (a `ConfigError`), naming the piece: "nervus's SSH certificate authority key is not the one its
     database was made with: restore that key, or the whole backup (`nervus-ctl restore`)".
   - `identity.check_history(database_path, audit_log)`, before `Database.open()`: no database beside
     an audit log holding a record refuses ("nervus has run here before and its database is gone");
     a database holding an `identity` row beside a missing or empty audit log refuses likewise. Each
     says to restore a backup, or to start empty on purpose with `nervus-ctl start-empty` (step 3).
     nervus itself has no flag to skip either: starting empty is that command's, and audited.
   - In `main()`: `check_history` immediately before `database.open()`, `identity.check` immediately
     after; both are refusals to start, as a missing key already is.
   - Tests: a first start records the fingerprints; a later start with the same keys starts; with the
     CA key, the SSH key or the issuer replaced by another, refused, naming it; with no database and
     an audit log with a record, refused and no database made; with no database and no log (a new
     installation), started; with a database and no log, refused; an installation's database made
     before this step, without an `identity` row, records one and starts.

3. ~~**`nervus-ctl`.** `src/nervus/ctl.py`, a new `src/nervus/restore.py`; tests in `tests/test_ctl.py`
   and a new `tests/test_restore.py`.~~ Built 2026-10-28, not deployed: 31 tests, each guarantee broken on
   purpose and caught (32 breaks). Differences from the text below, none a change of decision:
   - The recovery key's public half is not secret, so anyone could lock a file to it: a backup that
     opens is still checked piece by piece (each piece its manifest's hash, nothing unlisted), and
     the tests make such backups (found when four breaks went uncaught by a byte flipped in the
     file, which `age` itself refuses).
   - An audit log that already begins with the backup's is kept whole, since it holds the backup's
     and what came after; otherwise the backup's is put in place and the other kept aside.
   - The installation's own drop-ins are kept, since a new machine's installer writes its address
     there ("Settled already"); the backup's are saved beside what was replaced, and `restore` says
     when they differ. A piece the unit does not name, such as the Proxmox settings on a fresh
     install, goes back to the path the backup recorded.
   - Unfinished exports and uploads are not touched by `restore`: nervus's own start already fails
     them, and a ready export whose file is not there.
   - The check opens the database in memory, where SQLite cannot read the write-ahead mark in its
     header, so it checks a copy with the mark cleared; the file a restore writes keeps it.
   - nervus gains `--recovery-key` (default `secrets/recovery.pub`), and `served_key()`, the TLS key
     nervus serves with, which `nervus-ctl` reads its issuer beside, as nervus does.
   - nervus gains `--recovery-key` (default `secrets/recovery.pub`, so the unit needs no change);
     `Service` gains `recovery_key`, and `pieces(service) -> Pieces` reads every path from the unit,
     its drop-ins and, for `proxmox_ca`, the Proxmox settings file.
   - `nervus-ctl backup`: `make_backup`, which prunes, as nervus's account (`_as_account`), and a
     `made` row. Without a recovery key it refuses, saying to make one with `recovery-key`.
   - `nervus-ctl backup --check <file>`: asks for the recovery key's private half on the terminal
     (`getpass`, never echoed, never saved), opens the backup in memory, and checks: every piece in
     the manifest is present with its SHA-256; the database passes `PRAGMA integrity_check` and its
     schema version is one this nervus knows; each private key matches its public half (SSH keys,
     the TLS key and its certificate, the issuer's key and certificate); its audit log is the start of
     the live one (the live log's first bytes have the same SHA-256). It changes nothing on the
     machine but an operator record `backup_check` and a `checked` row.
   - `nervus-ctl restore <file>` (`restore.py`): question 5a's six steps, in order. Step 1 is
     `--check`'s checks without the audit-log comparison; any failure refuses before anything changes.
     The state it replaces goes to `/var/lib/nervus/replaced-<UTC>/pieces/<role>`, never deleted.
     Each piece is put where **this** installation's unit names its role, owned by nervus's account,
     with the mode the manifest records. The short-lived rows are cleared (`session`, `signin_link`,
     unused `enrollment_code` and their `enrollment_login`), exports and uploads not finished marked
     failed, the switches file set to lockdown, a `restored` row written. nervus is started with
     `systemctl start`, and the first record nervus's log gains is the operator record `restored`,
     naming the backup and when it was made. A backup whose database is a newer schema is refused.
     It asks for the recovery key as `--check` does, and for `restore` typed to go ahead (`--yes`
     skips only the second).
   - `nervus-ctl recovery-key`: runs `age-keygen`, writes the public half to the recovery key's path
     (`0600`, nervus's), prints the private half once with how to keep it, and an operator record
     with the public half. An installation that has one is refused unless `--replace`, which says that
     backups already made stay locked to the old key.
   - `nervus-ctl start-empty`: for question 6's two refusals. With no database, it makes an empty one
     (`Database.open`, as nervus's account); with no audit log, it starts one. Each asks for
     `start-empty` typed, and writes an operator record saying what it did and why, which is the
     new log's first record when the log was the missing piece.
   - `nervus-ctl accept-keys`: the operator's answer of question 6, added 2026-10-28. It reads
     nervus's keys from the unit, compares them with the database's `identity` row, and with none
     different says so and changes nothing. Otherwise, for each key that differs, it prints the old
     and new fingerprints and the cost, asks for the key's role typed (`ssh_key`, `ssh_ca_key`,
     `tls_issuer`; several, space-separated), writes an operator record `accept_keys` with both
     fingerprints of each, and replaces the row, as nervus's account.
   - `nervus-ctl status` gains: the newest backup and its age, a warning when it is more than 26 hours
     old, the space the backup folder takes, the last check that passed, and, after a restore, the
     note of question 6.
   - Tests: each command's guarantee as question 5, 6 and 7 state them, and Verification 6, 7 and 8:
     a damaged backup, a wrong key and a newer database each refused before any file changes; what a
     restore replaces kept; a restore leaves lockdown on, no sessions, links or unused codes, and its
     record first; `--check` fails on a log that is not the start of the live one and changes
     nothing; `recovery-key` never writes the private half to a file.

4. ~~**The installer and the unit.** `install.sh`, new `deploy/nervus-backup.service` and
   `deploy/nervus-backup.timer`; tests in `tests/test_install_sh.py`.~~ Built 2026-10-29, not deployed:
   9 tests, each guarantee broken on purpose and caught (18 breaks). Differences from the text below:
   - The recovery key is made once nervus is running, not after the TLS authority: `nervus-ctl`
     writes its record to nervus's audit log as nervus's account, as `signin` does there. Its
     private half is printed after "installed and running", where the steps above do not scroll it
     past.
   - A backup carries the recovery key's public half (role `recovery_key`, optional), so a nervus
     restored onto a new machine locks its next backups to the same key (found writing `--restore`,
     which makes no key). Where the backup holds none, the installer says to make one.
   - With `--restore`, nervus is started only by the restore, and enabled after it; a restore that
     fails leaves nervus installed and not started. `--restore` and `--proxmox` are refused together:
     restore first, then `--proxmox`. The installer prints how to add an address to the restored
     certificate (`nervus tls-reissue`) when clients reach nervus by one the backup's did not have.
   - The backup's service runs with `ProtectSystem=strict`, writing only nervus's state folder and
     its log.
   - `age` joins the packages the installer installs when missing.
   - After the TLS authority, `nervus-ctl recovery-key`: its private half printed once on the
     installer's terminal, with "keep it in a password manager or on paper, never on this machine".
   - `--restore <file>`: install as usual up to the keys; instead of making keys and a recovery key,
     run `nervus-ctl restore <file>`; refused with `--proxmox`.
   - `nervus-backup.service`: `Type=oneshot`, `ExecStart=/opt/nervus/.venv/bin/nervus-ctl backup`, as
     root (it drops to nervus's account). `nervus-backup.timer`: `OnCalendar=daily`,
     `RandomizedDelaySec=1h`, `Persistent=true`, so a machine off at the hour backs up when it starts.
     The installer installs and enables both.
   - Tests: as `test_install_sh.py` runs the installer under `NERVUS_INSTALL_ROOT`: `age` asked for
     when missing; the recovery key made and its public half in place; the timer and its service
     installed; `--restore` makes no keys.

5. ~~**The UI.** `src/nervus/ui.py`, `src/nervus/pages.py`; tests in a new `tests/test_ui_backups.py`.~~
   Built 2026-10-29, not deployed: 22 tests, each guarantee broken on purpose and caught (19 breaks).
   Differences from the text below:
   - The button makes the backup `nervus-ctl backup` makes, of the same pieces: nervus describes
     itself as `nervus-ctl` reads its unit (`ctl.service_of`, the drop-ins read from the unit's
     folder), and `restore.backup_now` does the rest, recorded as the UI's. A download is a link
     on the page (`backups?download=<name>`), taking only a name the folder holds.
   - The restore note shows on the Backups page as well as the Machines page; the warning names
     the newest backup's date, and links to the Backups page.
   - No backup yet is warned of as a day without one is, from the first page after install until
     the first backup.
   - Found by a test that failed one run in three: a backup's name is its second, so a second
     backup in the same second is refused. The refusal now says so ("made this same second").
   - The standing banner gains "no backup for more than a day" when the newest is over 26 hours old.
   - A Backups page, signed in: the backups in the folder, newest first, each with its date and
     size and a download (audited `backup_download`, a `downloaded` row); a "Make a backup now"
     button (same-origin form, audited as the UI's operator records are); the last check that
     passed, and the command that makes one; where copies go for the declared tier.
   - After a restore, the Machines page says "restored from a backup made <date>: machines enrolled
     and tokens issued after it are not here", until a backup is made after the restore.
   - Tests: the banner shown and not shown; download needs a session and is recorded; a name that is
     not a backup's in the folder is refused; the button needs a same-origin form; the note shown
     after a restore and gone after the next backup.

6. ~~**The docs.**~~ Built 2026-10-29: `docs/install.md` gains the recovery key in step 2, a step 5
   (check that the recovery key opens a backup), a section "Backups" and the by-hand steps; the
   preview's README (`preview/README.md`, the one the preview export ships) gains two non-goals and
   no longer says nothing backs nervus up, its "Works" saying the trial is still to come. 10 tests,
   each broken on purpose and caught (13 breaks): each documented command is one `nervus-ctl` or
   the installer takes, and the keeping said is the keeping the code does. As first written:  the recovery key, the backups and where to put copies per tier,
   `--check` after install and after each upgrade, a restore, and the last resort by hand (`age -d`,
   `tar`, permissions). `README.md`'s non-goals: a backup is as safe as its recovery key, and does not
   recover a compromised nervus. Tests in `tests/test_install_doc.py`, as for the other sections.

7. ~~**The trial** (question 7a, kept simple), a procedure, on throwaway machines.~~ **Done
   2026-10-29 by procedure 047: verification 4 observed**, with four findings, none blocking. Written
   at the operator's word ("Yes, write the trial"): N1 installed from
   the guide, M enrolled at standard, a real Claude Code's call; a backup; N1 destroyed; N2 restored
   at N1's address with `install.sh --restore`; the same Claude Code, its configuration unchanged,
   calls M again. The operator runs the client (`procedures/047-trial-claude.sh`) in their own
   terminal: the Claude Code a session starts is not signed in, and a tool call needs a model turn.

8. ~~**The first installation's deploy**, a procedure: the recovery key, the first backup and its
   check, and where copies go.~~ **Done 2026-11-01 by procedure 048:** the installation backs nervus
   up daily, its recovery key opens the first backup, and the platform's weekly copy of nervus's
   machine holds none of nervus's secrets or records; that copy's own keeping removed its first,
   which held every secret in clear.
   **Written 2026-10-31 as procedure 048**, with the operator's choice of the same day for
   the platform's copy of nervus's machine ("Yes, option 1"): that copy leaves out nervus's keys,
   tokens and records and keeps nervus's own locked backups, so a stolen copy holds nothing a
   recovery key does not lock, and a machine restored from it starts only after `nervus-ctl
   restore`. Proved once on throwaway machines first; where copies go, a question.
   **Amended 2026-11-01 at the operator's word ("Yes, leave it out")**, after procedure 048 step 11
   found such a copy still held the system's journal, with nervus's own log in it: nervus's records
   include that journal, and the copy leaves it out too. *Reason corrected the same day (ADR-0028
   question 3):* it said that log "names each command it runs". It names the commands nervus
   composes itself, with paths a client gave; a client's command goes on standard input and is not
   there (procedure 049). **Where copies go,
   answered the same day ("Yes, build it later"):** the installation's everyday computer pulls each
   backup, as question 3a allows; built apart from this step. **Asked again 2026-11-15, whether to
   build it now: "Not now".** It stays unbuilt by that decision. Until it is built, a copy leaves
   nervus's machine when the person downloads one from the Backups page (question 3a's first way).

## Verification

Moves to Accepted when observed in tests first seen to fail, or on throwaway machines by the trial:

1. A backup made while clients are calling restores a database that passes SQLite's integrity check
   and holds every write made before the backup started.
2. A backup cannot be opened without the recovery key, and nervus's machine holds nothing that opens
   it; the standard `age` tool opens it with the key.
3. A backup holds every piece of question 1a's list, and none of the files it leaves out.
4. After a restore onto a new machine at the same name, a real client, its configuration unchanged,
   runs a command on a machine enrolled before the backup, and that machine's journal names the
   client under the same CA.
5. A restored nervus starts in lockdown, with no sessions, sign-in links or unused codes, and its
   first audit record names the backup.
6. nervus refuses to start, saying which piece, with: the CA key missing; a CA key other than the
   database's; no database beside an audit log with records; a database without an audit log. Each
   starts once the piece is restored, or after starting empty on purpose, which is audited.
7. `restore` refuses a damaged backup, a wrong recovery key, and a database from a newer release,
   each before anything on the machine changes; what it replaces is kept.
8. `backup --check` passes on a good backup, fails on a damaged one and on one whose log is not the
   start of the live log, and changes nothing.
9. No MCP tool, and no client's token, reaches a backup.
   *Observed 2026-11-01 with a token that does not hold ADR-0009's full level: that level is root on
   nervus's machine and reaches every file there (ADR-0009 decision 3), a backup locked to the
   recovery key among them.*
10. A day without a backup shows in the UI's header and in `nervus-ctl status`.

## Amendment 2026-11-13: restore takes nothing from a backup but bytes, and writes as root only where root decided (procedures 056 and 058)

A backup is authenticated only by decrypting, and the recovery key's public half is not secret —
nervus holds it to make backups unattended — so a backup that decrypts is not proof that nervus made
it. The security review before the 0.2.0 export (procedure 056, finding 1) found that `restore`, run
as root, took from the backup's manifest *where* each piece went and *how*, and staged files at
predictable names that a symlink planted in nervus's own folders could redirect.

**Hardened 2026-11-12 (commit 6ae6cbd), recorded here.** Restore takes every destination from this
installation, never from the backup: a role this installation has no place for, or a drop-in name
that is not one plain name, is refused before anything changes; each piece's mode is clamped (never
setuid, setgid or sticky, never writable by group or other, owner-only for a secret); every file is
staged under an unpredictable name, made exclusively and renamed into place, so a symlink planted at
a guessed name is never followed; and the plan — every destination — is shown before the
confirmation. The recovery key's own staging file is made the same way.

**Completed 2026-11-13.** One destination still came from a file nervus's account may edit: the
Proxmox CA's, read from the Proxmox settings' `ca_file`, where an absolute path is used as given.
Pointed at a file root reads — a shell profile, say — a restore, even of an honest backup, moved that
file aside and wrote the CA in its place, owned by nervus's account, which could then rewrite it.
Restore now writes the Proxmox CA only beside the Proxmox settings, in nervus's secrets folder; a
`ca_file` that names any other place is refused before anything changes. Under the shipped unit the
service itself cannot edit those settings — trial A measured it from inside the running service's
own mount namespace: `/opt/nervus/secrets` is read-only to it, `/var/lib/nervus` and
`/var/log/nervus` are not — so this takes away a reliance on the sandbox rather than an open route
for the service (procedure 058).

**And the folder that keeps what is replaced.** It was named by the second, `replaced-<time>`, in
`/var/lib/nervus`, which the service may write: trial A planted a link at every name for the next ten
minutes, and root then made its `pieces` folder inside, and chmodded to 0700, the directory the link
named — `/etc` would have done as well. The folder's name now ends in random characters and is made
exclusively; it is opened at once without following a link, must be root's own and 0700 as made, and
everything inside it is done through that handle, so neither a planted link nor one swapped in while
the restore runs is followed. A swap is refused before anything is moved, and nervus is started again.

**And every folder by its handle (the class, swept 2026-11-13).** Each hole above was one instance of
one thing: root acting on a *path* inside a folder nervus's account can change, where a name proves
nothing. Sweeping for the rest of the kind found three more in restore. The audit log is staged beside
the log before the operator confirms, while nervus still runs, and restore then chmodded and chowned it
by name: swapped for a link while restore waited, the name carried both to whatever the link named. The
renewed certificate's folder sits inside the state folder: a link planted at its name had root write the
renewal, as nervus's own file, into any folder. And a folder or a pipe where a file belongs made restore
fail half-way, or wait for ever, after nervus was stopped. Restore now:
- reaches each folder it writes into without following any link that sits in a folder another account
  can change, and refuses such a link, naming it, before anything changes;
- refuses, before anything changes, a place that holds something other than a file (a link there is
  moved aside as a link, never followed);
- remembers which file it staged, by device and inode, and refuses, before anything is moved, if the
  name no longer means that file; and sets that file's mode and owner through its handle;
- moves, writes and renames through each folder's handle, never again by its path.

**The installer makes the recovery key only once nervus answers (2026-11-13).** Question 6 has nervus
refuse to start where its audit log holds records and its database is gone. The installer made the
recovery key, whose making is recorded in that log, as soon as systemd called the service active — the
moment its process exists — while nervus makes its database a second or two into its first start. When
the key's record came first, nervus took its database for lost and refused to start, at every restart,
while the installer said "nervus is installed and running": seen on a fresh install on a real machine
(procedure 058), a race the installs before it had happened to win. The installer now asks nervus
itself, as an upgrade does (ADR-0029 question 7): its MCP endpoint and its UI must answer before anything
else writes to its log, and a nervus that never answers is not called running. Question 6 is unchanged:
a record written before nervus's first start, by hand, still stops that start, with nervus's own words
saying how to go on (`nervus-ctl start-empty`).

**Not changed: authenticating backups.** A signature from a key nervus does not hold would refuse a
forged backup outright. The operator chose to harden restore only (2026-11-12).

**Verification gains:** *11. A backup cannot choose where or how restore writes: an unknown role, an
unsafe drop-in name, an over-broad mode, a symlink at a staging name or at the kept folder's name, a
kept folder or a staged audit log swapped while restore waits or runs, a link where a folder belongs, a
folder or a pipe where a file belongs, and a Proxmox CA named outside the secrets folder are each refused
or defused (tests in `test_restore.py`, seen to fail first).*
