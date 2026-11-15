# ADR-0014: client management in the UI — the off switch, and fallback tokens issued there

**Status:** **Accepted 2026-10-12, at the operator's word** ("mark ADR-0014 accepted"), every
verification item observed in tests or on the first installation (procedure 022). **Decided by the
operator on 2026-10-12**, in a Claude Code session: questions A to G, each as the session
recommended in a draft of this ADR ("all as recommended"). Each question keeps its options,
so the record shows what was not chosen. **Built on `main`, 2026-10-12** (`e741c2a` to
`e6a86b7`), and **deployed to the first installation the same day** at `fa938f3` (procedure
022). Every verification item is observed, in tests or there; "Where each stands" says which.
**Date:** 2026-10-12
**Rewritten:** 2026-10-17, under ADR-0019 F, to name no installation. No decision changed. The
original, with what the first installation held, is deployment note 0014.
**Decided by:** the operator, 2026-10-12
**Amends:** ADR-0003 decision 2, on where the switch file lives (decision A), marked there.
**Builds on:** ADR-0011 (the order of step 3: this is piece 4; decision 1, what nervus
writes is kept in SQLite; decision 2, the off switch stays a file of its own; consequence 3,
an installation's tokens move into the database "once", how decided with this piece), ADR-0003
(the off switch and `nervus-ctl`), ADR-0006 decisions 7 and 8 and verification 9 (fallback
tokens, labelled unconfined, issued from the UI), ADR-0009 decision 3 (the full level is one
token's alone), ADR-0012 (the UI, and "Left for later pieces": the switch file is read-only
to nervus), ADR-0013 (the audit log viewer)

## Context

ADR-0011's piece 4 is "client management: the switch in the UI, and fallback tokens issued
there (ADR-0006 decision 7)". ADR-0003 fixes what the switch does, and `nervus-ctl` already
does it from the command line. ADR-0006 decision 7 fixes what a fallback token is: a static
token, issued with one button, shown once, and labelled as not confined wherever it appears.
No ADR says how the UI does either.

### What the first installation held

Read through nervus on 2026-10-12, read-only, with no token value printed. The details as read
are in deployment note 0014. What bore on the questions:

- **The switch file** was `/opt/nervus/secrets/switches.yaml`, `600 nervus:nervus`, with nothing
  switched off.
- **The service cannot write it.** The unit has `ProtectSystem=strict`, and its
  `ReadWritePaths` are `/var/log/nervus` and `/opt/nervus/transfer`, so `/opt/nervus/secrets`
  is read-only to nervus. ADR-0012 noted this for piece 4. `nervus-ctl` can write it because it
  runs as root, outside the unit. Its replacement is atomic: a temporary file in the same
  directory, renamed over the old one, so writing it needs the *directory* writable.
- **The tokens were in `/opt/nervus/secrets/tokens.yaml`**, `600 nervus:nervus`, which nervus
  reads once, at start. Every one was a static bearer token: by ADR-0006's terms, every client
  of that installation was on a fallback token (ADR-0006 consequence 5).
- **Tools use the token file.** The first installation's deploy checks on every deploy that each
  grant it expects is in it, and stops if any token but the one with the full level holds the
  full-level entry (ADR-0009). `tools/set-hosts` changes allowlists in it, `tools/set-token`
  changes values, and `nervus-ctl` reads it to know which ids exist.
- **The database**, `/var/lib/nervus/nervus.db`, was schema version 1, with two tables,
  `signin_link` and `session`.

### A hazard in the database's version check, found while reading

`Database.open()` refuses a database whose `user_version` is not the one it knows: "made by
another release of nervus". The deployed release used version 1. If piece 4 adds its table by moving to
version 2, the release before it would refuse the migrated database and not start. So a
deploy of piece 4 that failed its checks and rolled back, as the first installation's deploy
does by itself,
would leave nervus down rather than back on the old release. Question F.

## Questions, and what was decided

### A. How the UI changes the switch file

1. **Make `/opt/nervus/secrets` writable** to the service. One unit line. But the directory
   also holds the fleet key and the token file, and its being read-only to nervus is
   deliberate: the unit says it "keeps `get` away from the secrets and the code".
2. **Move the switch file into nervus's state directory**, `/var/lib/nervus/switches.yaml`,
   which the unit already makes writable (`StateDirectory=nervus`). It stays a text file of its
   own, apart from the database, as ADR-0011 decision 2 requires, and root on the nervus
   machine can still edit it by hand. The deploy moves it once, keeping its content, and the unit's
   `--switches` names the new place, so `nervus-ctl` follows by itself.
3. **A directory of its own**, such as `/opt/nervus/switches/`, added to `ReadWritePaths`.
   As 2, with one more unit line and one more directory.
4. **The UI asks a root helper to write it**, so nervus itself never can. A new channel into a
   root process, for a file whose whole purpose is to be easy to change.

**Recommended: 2.** The secrets stay read-only to nervus, no new path is opened, and the file
lands where nervus's other writable state already is. The cost is a one-time move in the
deploy, which the deploy and `tools/ensure-switches` must learn, tested before it
runs, and an amendment to ADR-0003 decision 2's path.

**Decided: 2.**

### B. Stopping work from the UI

ADR-0003 has two depths: block new access, and also stop the jobs already running, which
cannot be undone. `nervus-ctl lock --kill-work` does both, listing the jobs first and asking
for the target's name.

1. **The UI switches access only.** Stopping jobs stays in `nervus-ctl`, and the UI says so
   beside the switch, with the command to run.
2. **The UI does both.** It lists the jobs a client has running, which means connecting to
   every host from the page, and stops them after the operator types the client's id.

**Recommended: 1, for piece 4.** No job was running on the first installation, a page that lists jobs waits on every host,
and the one irreversible action stays behind root on the nervus machine. The cost: in a bad
moment the operator has two places to go, the UI to switch off and the nervus machine to stop
work. If
that proves slow, stopping work can be added to the UI later, as the same confirmation
`nervus-ctl` uses.

**Decided: 1.**

### C. Where tokens live: the file, the database, or both

ADR-0011 decision 1 puts tokens nervus writes in the database, and consequence 3 says an
installation's tokens move there "once", how to be decided now.

1. **Both, for now.** The file's tokens stay in `tokens.yaml`, read at start as today, and every
   tool that uses it keeps working. Tokens issued in the UI go in the database, which nervus
   checks on every request, so a new token works at once and a revoked one stops at once. An
   id may exist in only one of the two. The UI lists both, marking where each lives; it can
   switch either off, but revoke only its own.
2. **Move them all into the database in this piece**, and retire `tokens.yaml`. One place for
   every token. But the deploy's grant check, `set-hosts`, `set-token`, `nervus-ctl` and
   procedures 005 and 006 all change in the same piece, and the deploy grows a one-time import
   that cannot be rolled back by putting the old code back.
3. **Leave the file's tokens there for good**; only new tokens go in the database. As 1, but
   decided as permanent rather than as a step.

**Recommended: 1.** It delivers ADR-0006 verification 9 (a token issued and used "without
editing any of nervus's files") without moving the tokens the deploy tools guard. The import
of ADR-0011 consequence 3 stays open, to be decided with whichever piece next changes the
token tools, most likely piece 7, when grants replace tokens anyway.

**Decided: 1.**

### D. What the UI can do to a token it issued

ADR-0006 decision 8: suspending is the switch; revoking deletes.

1. **Issue, switch off and on, and revoke.** No editing: a token's hosts are fixed when it is
   issued. To change them, issue another and revoke the old one.
2. **As 1, and edit a token's hosts** in place.

**Recommended: 1.** A token's reach then never changes under a client that holds it, and every
token's allowlist is visible in one audit record, its issuing.

**Sub-question, how a token is stored: only a hash of its value (recommended), or the value
itself.** With a hash, as for sessions (ADR-0012 decision 3), a copy of the database
authenticates no one, and the value really can be shown only once, as ADR-0006 decision 7
says. The cost: a lost value cannot be shown again; the operator issues another.

**Decided: 1, with a hash only.**

### E. Which actions ask for confirmation

1. **By whether an action can be undone.** Switching one client off or on, and lockdown on or
   off, are one button each: all reversible, and in a bad moment speed matters. Revoking a
   token, which cannot be undone, asks for its id to be typed, as `nervus-ctl` asks before
   stopping jobs. Issuing needs only its form.
2. **Every change asks** "are you sure" first.
3. **Nothing asks.**

**Recommended: 1,** following ADR-0003 decision 3: the interface should make the difference
between reversible and irreversible obvious, not treat them alike.

**Decided: 1.**

### F. Changing the database without breaking a rollback

1. **Version 2, with a migration.** The clean way. A failed deploy that rolls back leaves
   nervus down until someone restores the database or removes the table by hand.
2. **Additions keep the version.** `user_version` counts only changes an older release cannot
   live with. A new table is not one: the release before ignores a table it does not know, so
   nervus makes any missing table at start (`CREATE TABLE IF NOT EXISTS`) and stays on
   version 1. Read off the code: the deployed `open()` only checks the version, and checks for
   unknown tables only in an empty, version-0 database.
3. **A second database file** for tokens. Avoids the question, and makes two files to back up
   and keep consistent.

**Recommended: 2.** A rollback then works as it always has. The version is kept for a change
that really breaks an older release, which this is not. The cost: the rule must be written
where the schema is, so a later change that is incompatible does bump it.

**Decided: 2.**

### G. Smaller choices, which can be taken together

- **Where it sits:** a `clients` page, linked from every signed-in page's header beside the
  audit log. Lockdown on that page, at the top.
- **What the page shows for each token:** its id, client, project and hosts; where it lives
  (file or UI); on or off; **"unconfined: static token"** (ADR-0006 decision 7); and the time of
  its last call, read from the audit log as the viewer reads it (ADR-0013), so a token nothing
  uses is easy to see.
- **The label applies to the file's tokens too.** Each is a static token. The audit
  log gains `"unconfined": true` on every record made with one (ADR-0006 decision 7: "the audit
  log marks every call made with it").
- **Issuing:** the operator gives an id (lower-case letters, digits and `-`, unique across file
  and database), a client and a project, and ticks hosts from the inventory. An entry marked
  `issue: never`, the full level (ADR-0009 decision 3), is never offered; the first
  installation's deploy would stop on a token holding it anyway. The value, 256 random bits, is
  shown once on the page that follows, with a reminder that it is shown only once and belongs
  in the operator's password manager.

**Recommended:** all four as written.

**Decided: all four.**

## Settled already, by earlier decisions or by the pattern piece 2 set

- **Every change is audited**, actor `operator`, tool `ui`, with the browser's address
  (ADR-0003 decision 6, ADR-0012 decision 6).
- **What cannot be audited does not happen, except taking access away** (ADR-0001 s10, and
  ADR-0012's sign-out). Issuing, switching on and lifting lockdown are refused if their record
  cannot be written; switching off and lockdown stand without it, and say so.
- **Every form needs the session's form token and nervus's own origin** (ADR-0012).
- **A switched-off client still learns nothing about why** (ADR-0003 question B), and an
  issued-then-revoked token is refused exactly as an unknown one, after the same 50 ms (ADR-0003
  decision D).
- **Lockdown in the UI does not sign the operator out** (ADR-0012 decision 5).
- **The UI and `nervus-ctl` may change the switch file at the same moment.** Each re-reads the
  file and writes it whole; a lock file beside it makes the two take turns, so neither loses the
  other's change.

## Consequences

1. **Piece 4 builds, one commit each, every new test seen to fail first:**
   1. the database: a table of issued tokens, by hash only, added without changing the
      version (F); issue, look up, list and revoke; an entry marked `issue: never` and an id
      already taken refused;
   2. tokens from both places (C): nervus checks the file's tokens and the database's on every
      request; every audit record made with a static token carries `"unconfined": true` (G);
      `nervus-ctl` knows the database's tokens too;
   3. the switch file: one function changes it, under a lock the UI and `nervus-ctl` both take;
      `tools/ensure-switches` copies it to its new place, and the deploy and the unit name that
      place (A);
   4. the pages: the clients page, and the page that shows an issued token's value once (G);
   5. the UI serving them: switch, lockdown, issue and revoke, each audited (D, E).
2. **The deploy copies the switch file; it does not move it.** *How the session carries out
   decision A, not decided by the operator:* the deploy writes
   `/var/lib/nervus/switches.yaml` with the old file's content, only if the new one does not
   exist, and leaves `/opt/nervus/secrets/switches.yaml` in place. If the deploy rolls back by
   itself, within seconds, the old release finds its file as it was. A rollback by hand later
   (procedure 007) would find it stale: any change made since in the UI or with `nervus-ctl`
   would be missing from it. The old file is removed by a later deploy, once this one stands.
3. **Two places hold tokens until the import of ADR-0011 consequence 3 is decided.** The
   deploy tools guard only the file; the database's tokens are guarded by the code, which never
   issues an entry marked `issue: never`.
4. **The schema rule is written beside the schema** (F): the version changes only for a change
   an older release cannot live with.
5. **Backups now include issued tokens**, as hashes, and nothing backs nervus up (ADR-0011
   consequence 4).

## Verification

Moves to Accepted when observed in tests first seen to fail, or on an installation.

1. A token issued in the UI is used by a client at once, with no file of nervus's edited and no
   restart, and is labelled unconfined in the UI and in every audit record of its calls
   (ADR-0006 verification 9). The tokens in the file are labelled the same.
2. Revoking a token asks for its id, and its next call is refused exactly as an unknown
   token's, after the same 50 ms.
3. Switching a client off and on, and lockdown on and off, in the UI take effect on the next
   call with no restart. Each is audited, actor `operator`, tool `ui`, and `nervus-ctl status`
   shows the same state.
4. The UI and `nervus-ctl` changing the switch file at the same moment both land.
5. The database holds no token value, only hashes. A database with the new table still opens on
   the release before this piece.
6. An entry marked `issue: never` cannot be issued, and neither can an id already in the file
   or the database.
7. The deploy writes the switch file in its new place with the old one's content, never
   replacing an existing one, and leaves the old one where a rollback finds it.
8. The UI does not stop running work; beside the switch it says how to, with `nervus-ctl`.

**On the first installation, 2026-10-12, by procedure 022:**
- **1:** a token issued in the UI and used from a client 35 seconds later, its calls marked
  unconfined; the file's tokens labelled unconfined on the page.
- **2:** a mistyped revoke refused (screenshot); the revoked token refused (the operator's report).
- **3:** switching off on the page, audited, and `nervus-ctl status` showing it `OFF`. Switching
  on and lockdown were not done there: tests only.
- **5:** no value in the database's files (the operator's report). The release before opening
  it: tests only, since the deploy did not roll back.
- **6** and **8:** the full-level entry not offered, and the kill-work note, on the page.
- **7:** the switch file copied, identical, the old one left (step 3).

**Where each stood, 2026-10-12, before the deploy.** All in tests first seen to fail, with
the code missing or broken on purpose; the commit messages say how.
- **1:** a token issued in the UI works on a running nervus's next call (end to end), and is
  labelled unconfined on the page and in every audit record, as are the file's tokens.
- **2:** revoking needs the id typed; a revoked token's refusal is the same as an unknown
  token's, through the same middleware and its 50 ms wait.
- **3:** switching off and on and lockdown change the file and are audited; end to end, a
  client switched off on the clients page of a running nervus is refused on its next call.
  That `nervus-ctl status` shows the same state follows from both reading the one file; it
  is not tested as such.
- **4:** two writers, and `nervus-ctl` against a slow UI change, both land.
- **5:** no value in the database's files; the deployed release's own database code (`2740c30`,
  from git) opens a database with the new table and signs in.
- **6** and **8:** in tests.
- **7:** `ensure-switches --from` in tests; the deploy's use of it by reading it. Its run is
  the deploy's.

Also seen in the browser pane, on the developer's machine against the UI on loopback over
made-up tokens:
issuing, the value shown once, switching off, a mistyped revoke refused, then a revoke; one
audit record each.

## Amendment 2026-11-13: the switches file is written through its handle (procedure 058)

Decision A put the switches file in nervus's state directory, which nervus's account owns, so that
the UI can write it; `nervus-ctl`, run as root, writes it there too. The writer made the new copy
beside the old one, then set its mode and owner **by name**, then renamed it. In a folder another
account owns a name proves nothing: a process of that account can swap the new copy's name for a link
while root writes, and the name then carried root's chmod and chown to whatever the link named. Tried
on a real machine (procedure 058): one `nervus-ctl lock`, with the running service swapping names, gave
the service's account a file of root's, at the first try, and said the lock was on.

The writer now sets the new copy's mode and owner through its handle, and renames it only while its
name still means that file. A swap is refused, nothing is changed, and `nervus-ctl` and the UI say so
in those words. Nothing else of decision A changes. The off switch remains a control over clients, read
by nervus itself: it was never one over a nervus whose own account is taken, which is stopped, not
switched off.
