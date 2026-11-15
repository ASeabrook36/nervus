# ADR-0011: Phase 2 step 3 — where nervus keeps what the UI changes, and how enrollment works

**Status:** Proposed (Accepted when the verification below is observed). **Decisions 1 to
3 were made by the operator on 2026-10-05**, in a Claude Code session; decision 3's place
in the order is the session's proposal, which the operator did not object to. **Questions A
and B were decided by the operator on 2026-10-06**, as the session recommended (below).
**Date:** 2026-10-05
**Rewritten:** 2026-10-16, under ADR-0019 F, to name no installation. No decision changed.
**Builds on:** ADR-0003 (the kill switch), ADR-0005 decisions 4 and 5 and consequence 5 (the
UI, enrollment, state the service writes), ADR-0006 (client sign-in), ADR-0007 (the threat
model)
**Decided by:** the operator, 2026-10-05
**Prior art:** `research/2026-10-15-prior-art.md` ideas 2 and 4 bear on decision 3 (a middle enrollment level; pre-filling from the user's SSH config). A note, not a decision.

## Context

Phase 2 step 3 is the web UI, client sign-in, ADR-0003's kill switch inside the UI, and
ADR-0007's requirements. The ADRs already settle what the UI does:
- it carries setup, client management, the host list and the audit log viewer
  (ADR-0005 decision 4);
- the audit log is readable there and nowhere else (ADR-0005, ADR-0007);
- there is one trust domain and no user accounts (ADR-0007 decision 10);
- the kill switch's behaviour is fixed (ADR-0003);
- clients sign in by OAuth with one-click approval (ADR-0006).

Four questions came up that no ADR answers. Two are decided here; two stay open.

## Decision

**1. What nervus writes while it runs is kept in SQLite.** This covers:
- approved client apps (ADR-0006's grants, and their rotating refresh tokens);
- fallback tokens;
- enrolled hosts;
- the choices made at setup.

*Why:* until now nervus only read hand-edited files at start. With the UI it writes its
own records while running, and ADR-0006 makes one kind busy: every client's sign-in is
renewed hourly, with a new refresh token each time and a 60-second grace window, so writes
are frequent and sometimes simultaneous. SQLite makes each change all-or-nothing, and
handles two writers at once and a crash mid-write. Those are the three hazards ADR-0005
consequence 5 named for state the service writes. It is part of Python's standard library
(`sqlite3`), so it is no new dependency, and it is one file to back up. Text files suit
what people edit; they are the wrong tool for what the service rewrites every hour.

**2. The off-switch record stays a text file of its own, as ADR-0003 decision 2 decided.**
- **What it holds:** lockdown, and every client that is switched off. That covers fallback
  tokens and OAuth grants alike, so ADR-0006 decision 8's "suspend a grant" is recorded
  here. Revoking a grant is different: it deletes the grant from the database.
- **Who writes it:** the UI's switch, and `nervus-ctl` (ADR-0003 decision 5).
- **How nervus uses it:** it re-reads the file on every request. A missing or garbled file
  turns everything off (ADR-0003, question A).

*Why:* a kill switch is needed in a bad moment, which may be the moment the UI, the
database or nervus itself is misbehaving. Kept apart from both, the switch works whatever
state they are in, and the operator can always flip it by editing one file as root on the
nervus machine.

**3. Enrollment: the UI asks what it needs, then gives a command to run as root on the new
host.** The command is run as root, or after `su`, on the target. This is ADR-0005 decision
4's one-line command with a short-lived token. Running it as root is what lets the person
at that machine choose read-only or full access (ADR-0005 decision 5). Enrollment is built
in step 3, right after first-run setup: "set up nervus, then enroll a first host" is the
path a new user walks, and the sequence ADR-0005's verification tests.

## Questions A and B, decided by the operator, 2026-10-06

These were open when this ADR was written, and they blocked step 3, piece 2: the UI shell and
the operator's sign-in. The session recommended both answers, and the operator said: "Both of
those recommendations are fine."

**A. The operator signs in with a one-time link; there is no password.** The UI controls the
fleet: the off switch, grants and the audit log. So its sign-in matters as much as the fleet
key.
- A command run on the nervus machine prints a sign-in link that works once.
- The browser then keeps a session for **12 hours**.
- Signing in therefore needs the same authority as `nervus-ctl`: reaching the nervus machine as
  root.
- There is no password to guess, leak or forget.
- The cost: when the session expires, the operator runs that command again, as root on the
  nervus machine.

**B. Off loopback, the UI always uses HTTPS, on its own port, with nervus's own certificate
(ADR-0010).** This holds even where MCP is served over plain HTTP, as on the operator's
instance with `--insecure-plain-http`. A sign-in session sent over plain HTTP could be taken by
anyone who can watch the network.
- The first time, the browser warns that the certificate is not vouched for. The operator
  compares its fingerprint with the one nervus prints at start, and accepts it once.
  (Amended 2026-10-06, ADR-0012 decision 7a: nervus prints its public key's fingerprint,
  and browsers show the certificate's, a different number. `nervus-ctl signin` prints the
  certificate's beside the link, and that is what the operator compares.)
- Browsers allow that step; coding clients do not, so MCP stays on plain HTTP until the
  connector (ADR-0008).
- The cost: making the certificate once on the nervus machine (`nervus tls-init`), and the
  warning once per browser.

## Order of step 3 — proposed by the session, confirmed by the operator on 2026-10-06

The operator confirmed it on 2026-10-06 ("yes sure"). Piece 1 is built and deployed: the off switch and `nervus-ctl` (procedure 018), with
ADR-0003 decision D (procedure 019). With A and B decided, nothing blocks piece 2.

1. The kill switch mechanism (decision 2's file, checked on every request) and `nervus-ctl`.
2. The UI shell and the operator's sign-in. Needs A and B.
3. The audit log viewer.
4. Client management: the switch in the UI, and fallback tokens issued there (ADR-0006
   decision 7).
5. First-run setup: the tier choice and the public-address warning (ADR-0007).
6. Enrollment (decision 3).
7. Client sign-in by OAuth (ADR-0006), on decision 1's database.
8. The non-goals written into the README (ADR-0007 consequence 1).

## Alternatives considered

- **Text files for everything**, as today. Readable and editable by hand, but nervus would
  have to build safe replacement, concurrent writes and recovery from a damaged file
  itself. Rejected for what the service writes; kept for the off switch, where hand-editing
  in an emergency is the point.
- **The off switch in the database with everything else.** One place for all state, but a
  damaged database would take the emergency lever down with it. Rejected.

## Consequences

1. **Deployment must create the off-switch file** before nervus checks it, or every client
   is refused from the moment the code ships. ADR-0003 question A already says so.
   `tools/ensure-switches` is that step, run by a deploy, since piece 1.
2. **The database needs a writable home on the nervus machine.** The unit's `ProtectSystem=strict`
   allows writing only to `/var/log/nervus` and `/opt/nervus/transfer`. Where the database
   lives, and the unit change, are decided with the piece that first writes to it.
   (Settled 2026-10-06 by ADR-0012 decision 3: `/var/lib/nervus/nervus.db`, with
   `StateDirectory=nervus` in the unit, first written by piece 2.)
3. **Importing what exists:** an installation's `hosts.yaml`, with its provenance, and its
   tokens move into the database once. How is decided with that piece.
4. **Backups now include the database.** Nothing backs nervus up today (`CURRENT_STATE.md`),
   and that gap now covers more.

## Verification

Moves to Accepted when observed in tests first seen to fail, or on a machine:

1. Two writes to the database at the same moment both land, and a write cut off part-way
   leaves the previous state intact.
2. With the UI unavailable, editing the off-switch file by hand switches a client off on its
   next request. A missing or garbled file refuses every client.
3. Suspending an OAuth grant writes to the off-switch file; revoking it removes it from the
   database.
4. On a host that has never seen nervus, the UI's command, run as root, enrolls it read-only,
   and a client can then run a command there.
5. A sign-in link works once and only once. A session ends after 12 hours. Without a session,
   the UI shows nothing but how to sign in (A).
6. Off loopback, the UI does not answer over plain HTTP. Over HTTPS it presents nervus's own
   certificate, whose fingerprint is the one nervus prints at start (B).
