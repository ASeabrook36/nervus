# ADR-0012: how the UI is built, and how the operator signs in

**Status:** **Accepted 2026-10-09, at the operator's word.** Built on `main` (`b04be75` to
`3da056f`) and deployed to the first installation at `cb13e87` on 2026-10-09 (procedure 020).
Every verification item is observed, in tests first seen to fail or on that installation; the
procedure's last
table says which. Observed in tests only:
- items 1 and 2;
- item 3's expiry;
- item 4's `signout --all` ending a live session. On the installation it ran with no session to end,
  and the operator chose not to repeat it.

Item 7's browser fingerprint is the operator's report of what Chrome showed.
**Rewritten:** 2026-10-16, under ADR-0019 F, to name no installation. No decision changed.
**Decided by the operator on 2026-10-06**, in a Claude Code session: all seven decisions as
the session recommended them in a draft of this ADR ("all as recommended").
**Date:** 2026-10-06
**Builds on:** ADR-0011 questions A and B (decided 2026-10-06), ADR-0005 decision 4,
ADR-0003 decisions 5 and 6, ADR-0007 decisions 4 and 10, ADR-0010 decisions 2, 4 and 6
**Amends:** ADR-0011 question B, on what the operator compares (decision 7a), and ADR-0011
consequence 2, on where the database lives (decision 3). Each is marked where it stands.
**Decided by:** the operator, 2026-10-06

## Context

ADR-0011 settled two things on 2026-10-06:
- **A:** the operator signs in with a one-time link printed by a command on the nervus
  machine, with no password, and the browser keeps a 12-hour session.
- **B:** off loopback, the UI always uses HTTPS, on its own port, with nervus's own
  certificate.

No ADR said how the UI is built: what serves it, how its pages are made, where sign-in
state is kept, or the details A and B leave open. Two facts from the code shape the
answers.

- **The deploy cannot add a dependency.** The first installation's deploy installs nervus
  with `pip install --no-deps --no-index`, which brings nervus's own package and nothing
  else. A new library would need a new way onto the nervus machine, and none exists.
- **The UI will display text an attacker can write.** The audit log, which the UI shows
  from piece 3, holds the commands agents ran and what came back. An agent steered by
  hostile text (ADR-0007, adversary A) chooses that text. A page that displays it
  unescaped lets it run as code in the operator's signed-in browser; this is called
  cross-site scripting. So pages must escape text by default, not when someone remembers.

## Decision

**1. The UI runs inside the nervus process, as a second listener on port 8443, at the same
address as MCP.**
- On by default. Off loopback it serves only HTTPS (B). Without a certificate, nervus
  refuses to start and names `nervus tls-init`, as it already does for MCP (ADR-0010
  decision 4).
- On loopback, plain HTTP unless given a certificate, as for MCP.
- A new setting, `--ui-url`, is the address browsers use, and where sign-in links point.
  It is the installation's own, so it lives in the installation's drop-in (ADR-0019 D2).

*Why:* the UI needs what the nervus process holds: the inventory, the off switch, the
audit log, and in piece 7 the authorization server, whose approval page ADR-0006 puts in
front of every client's first sign-in. ADR-0005 decision 4 already serves both from one
container. One process is one unit, one deploy, one stop. The cost: a fault in UI code
shares a process with MCP.

**2. Pages are plain HTML made by nervus, with forms and buttons; no JavaScript framework,
no build step, and no new dependency.**
- Starlette, the web library MCP already runs on, serves them. It becomes a declared
  dependency at the version installed (1.7.0), not a new one.
- Python's standard library escapes every value put into a page, unless the code marks it
  as nervus's own markup. A test pushes hostile text through every page and fails if any
  comes out unescaped.
- One stylesheet, served by nervus. Nothing is loaded from anywhere else.

*Why:* the screens are tables, forms and buttons. A JavaScript application would add a
second language, a build toolchain and hundreds of npm packages to a security tool's
supply chain, for nothing these screens need. The cost: a page changes only when
reloaded. If the audit viewer wants a live tail (piece 3), that is one small script,
decided then.

**3. Sign-in links and sessions are kept in the SQLite database chosen by ADR-0011
decision 1, at `/var/lib/nervus/nervus.db`.** They are the first thing it holds.
- The unit gains `StateDirectory=nervus`. systemd then makes `/var/lib/nervus`, owned by
  `nervus`, and lets nervus write there despite `ProtectSystem=strict`. This settles
  ADR-0011 consequence 2 for this instance.
- Only a hash of each link and session is stored: a one-way fingerprint that can be
  checked but not turned back into the link. A copy of the database signs no one in.
- `nervus-ctl` writes to it as the `nervus` user, not as root, so every database file
  stays nervus's.

*Why:* a session survives a restart or a deploy, and signing out really ends it. Pieces 4,
5 and 7 need the database anyway. The cost: a unit change and a new directory now, rather
than in piece 4; and the database needs backing up, when nothing backs nervus up
(ADR-0011 consequence 4).

**4. `nervus-ctl signin` prints the link. It works once, within 5 minutes. It opens a page
with a single Sign in button, and pressing that is what uses the link.**
- `nervus-ctl` is already the operator's tool on the nervus machine, authorised by root
  (ADR-0003 decision 5). A gives sign-in that same authority.
- The button means a link preview (a chat app fetching the address to show a summary) or a
  browser loading ahead cannot use the link up. Those fetch pages; they do not press
  buttons.
- The UI's listener keeps no web access log, so no link reaches nervus's journal.
  Decision 6's records take its place.

*Why 5 minutes:* the link goes from a terminal to a browser straight away. One left in
scrollback or a transcript is dead soon after.

A connection that holds the full level on nervus's own host (ADR-0009 decision 3) can run
`nervus-ctl signin` through nervus. That is no new authority, since the full level can
already change everything the UI controls, and the call is audited.

**5. A session lasts 12 hours from sign-in and is not extended by use. Several browsers may
be signed in at once. A Sign out button ends this browser's session; `nervus-ctl signout
--all` ends every session.**

*Why from sign-in:* a stolen session lasts 12 hours at most, whatever the thief does. It is
also what ADR-0011 verification 5 tests. The cost: a session ends at the 12-hour mark even
mid-use.

*Why `signout --all`:* a lost laptop, or any doubt. It is the off switch for the UI itself.
Lockdown (`nervus-ctl lock --all`) does not sign the operator out, because the UI is where
lockdown will be managed.

**6. The audit log records every link made, every sign-in, every refused link (used,
expired or unknown) and every sign-out, with the actor `operator` and the browser's
network address.**

*Why:* the UI holds fleet-wide authority, which is why ADR-0003 decision 6 audits operator
actions. The audit viewer (piece 3) will then show every sign-in, including any the
operator did not make. The cost: anyone on the network can add refused-link records at
will. Public exposure is not supported in v1 (ADR-0007 decision 4), and retention is
already an open item.

**7. The certificate the browser shows.** As decided, B had two gaps with what a browser
does.

**a. `nervus-ctl signin` prints the certificate's SHA-256 fingerprint beside the link,
labelled as what a browser shows.** B had the operator compare the certificate's
fingerprint with the one nervus prints. But nervus prints its *public key's* fingerprint
(ADR-0010 decision 2), and Safari and Firefox show only the *certificate's*, a different
number. Chrome shows both, from memory; unchecked.
- The reference is read on the nervus machine, as ADR-0010 decision 6 requires. The UI
  never displays it as a check.
- The pinned identity stays the public key.
- The certificate's fingerprint changes when nervus re-issues it, every 795 days, and each
  browser then warns once more.

**b. `nervus tls-init` gains `--name`, for the name browsers use.** A certificate nervus
makes names `localhost`, the loopback addresses and the machine's hostname. Where the
browser goes to a different name, as on the first installation (procedure 020), without
this it would warn about the name as well as the issuer. Re-issuing keeps the names a certificate was made with, and `tls-init`
runs once, so the name has to be right the first time.

## Settled already

None of these needed a decision; each follows from an ADR or from standard practice.
- **No user accounts.** One instance is one trust domain (ADR-0007 decision 10).
- **The two doors stay separate.** An MCP token never opens the UI, and a UI session never
  reaches MCP (ADR-0005 decision 4).
- **No rate limiting or lockout.** A link carries 128 random bits, which cannot be guessed,
  and public exposure is unsupported in v1 (ADR-0007 decision 4).
- **Standard browser protections on every page:**
  - the session cookie travels only over HTTPS, scripts cannot read it, and other sites
    cannot make the browser send it;
  - every form carries a value only nervus's own page could know, so another site cannot
    submit it on the operator's behalf (cross-site request forgery);
  - a page may load nothing from elsewhere, and none is cached.
- **Signed out, the UI shows only how to sign in** (ADR-0011 verification 5).

## Left for later pieces

- **Piece 7:** whether approving a client's sign-in on nervus's approval page needs a
  signed-in UI session. It changes nothing in piece 2, but it decides who can approve.
- **Piece 4:** under `ProtectSystem=strict`, the switch file is read-only to nervus. The UI
  cannot flip it until the unit lets nervus write that one file.

## Alternatives considered

- **The UI as a separate service, with its own unit.** Isolates UI faults from MCP, but the
  separation cannot hold: stopping jobs (piece 4) and enrollment (piece 6) need the fleet
  key either way. Rejected.
- **Start without the UI, with a warning, when its certificate is missing.** MCP stays up,
  but the UI is then found missing in the bad moment it is needed. Rejected.
- **Jinja2**, the standard Python template library. It escapes by default and is better
  known than a small in-house helper. It costs two new packages and a change to the deploy
  to carry them. Rejected.
- **A JavaScript application** talking to nervus. A second language, a build toolchain and
  an npm supply chain, for screens that are tables and forms. Rejected.
- **Sign-in links and sessions in memory only.** No database yet, but every restart and
  deploy signs the operator out, and `nervus-ctl` would need a new channel into the
  running process to hand it a link. Rejected.

## Consequences

1. **Piece 2 builds:**
   - the listener, the signed-out page, the Sign in page, and a frame with Sign out and room
     for ADR-0007's standing banner;
   - `nervus-ctl signin` and `nervus-ctl signout --all`;
   - the database, with its first two tables;
   - decision 6's audit records;
   - `tls-init --name` and decision 7a's fingerprint;
   - tests for each, first seen to fail.

   No other screen.
2. **The first installation's unit changes:** the UI's settings, the database path, and
   `StateDirectory=nervus`.
3. **`nervus tls-init` must run on the nervus machine before piece 2 is deployed**, with decision 7b's
   name. Otherwise nervus refuses to start, and the deploy rolls back.
4. **Backups now include `/var/lib/nervus`**, and nothing backs nervus up.

## Before it can run on an installation

To be read off the machine, not assumed (rule 2):
- **No TLS key has been made there.** `nervus tls-init` runs once, as the `nervus` user.
  Whether that user can write `/opt/nervus/secrets` is unread.
- **The versions of uvicorn and Starlette** in the installation's environment. The deploy installs
  with `--no-deps`, so they are whatever is already there.
- **Port 8443 is free.**

## Verification

Moves to Accepted when observed in tests first seen to fail, or on an installation. ADR-0011
verification items 5 and 6 cover the link's single use, the 12-hour session and HTTPS;
these cover what this ADR adds.

1. Hostile text put through every page comes out escaped. No page loads anything from
   another address.
2. Off loopback with no certificate, nervus refuses to start and names `nervus tls-init`.
3. A link more than 5 minutes old is refused. Opening a link without pressing Sign in
   leaves it usable.
4. A session survives a restart of nervus. Sign out ends that browser's session;
   `nervus-ctl signout --all` ends every session.
5. No link or session value appears in the database file. After `nervus-ctl signin`, run
   as root, every database file is owned by `nervus`.
6. Each event in decision 6 writes one audit record, with the actor `operator` and the
   browser's address. No link appears in the journal.
7. The certificate fingerprint `nervus-ctl signin` prints is the one a browser shows for
   the UI. On the installation, the certificate names the address its browsers use.
8. Deployed with `--no-deps --no-index`, as today, piece 2 starts and serves the UI on the
   installation.
