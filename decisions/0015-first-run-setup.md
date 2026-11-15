# ADR-0015: first-run setup — the tier choice, and the public-address warning

**Status:** **Accepted 2026-10-24, at the operator's word** ("mark ADR-0015 and ADR-0026 Accepted"):
every verification item observed, 1 to 5 by procedure 039 on a throwaway installation, 6 by procedure
041 on the installation it deployed. **Decided by the
operator**, in a Claude Code session: questions A to E as the session recommended, C as revised
after the operator's report of 2026-10-12 ("all as recommended", given 2026-10-15). Each
question keeps its options, so the record shows what was not chosen. **Questions F to I added
2026-10-20**, raised by reading this record against ADR-0021 to ADR-0024 before building, and
**decided by the operator the same day, each as recommended** ("questions 1-4 are answered as
recommended"). Every step built and deployed.
**Date:** 2026-10-12, decided 2026-10-15; F to I 2026-10-20
**Rewritten:** 2026-10-17, under ADR-0019 F and the operator's word of 2026-10-15 ("We should not
reference the local network"). No decision changed. The original, with the first installation's
network as read, is deployment note 0015.
**Decided by:** the operator
**Amends:** ADR-0007 decision 4, on "not dismissible" (decision C); decision 2, the tiers' wording
(decision F); consequence 4, a section rather than a page (decision H); each marked there.
**Builds on:** ADR-0011 (the order of step 3: this is piece 5; decision 1, setup choices are kept
in SQLite), ADR-0007 decisions 2, 4, 9 and 10, consequence 2 and verification items 1 to 3,
ADR-0005 decision 4 (setup is in the UI), ADR-0012 (the UI, and the banner every signed-in page
already has room for), ADR-0014 decision F (a table is added without changing the version)

## Context

ADR-0011's piece 5 is "first-run setup: the tier choice and the public-address warning
(ADR-0007)". ADR-0007 settles what they are:
- **The tier.** Where nervus runs decides what another program on the same machine can do to
  it: tier 1, a separate machine (recommended); tier 2, the user's machine under its own
  account; tier 3, the user's machine as the user, which a default container setup gives. All
  three are supported. "The user declares the tier during first-run setup, and nervus takes them
  at their word", then "shows that tier wherever the installation is described". Nobody reaches
  the end of setup without having chosen one (decision 2, verification 2).
- **The public-address warning.** A public address is warned about, never refused: "stated
  during setup, carried as a standing banner in the UI, and written to the log on every start
  while the condition holds. It is not dismissible while the address is public" (decision 4,
  verification 3).
- **The non-goals**, including the single trust domain, are stated in the first-run flow
  (decisions 9 and 10, verification 1). The README is piece 8.

No ADR says where setup happens on an instance that already runs, what counts as a public
address, or when it is checked.

### What the code shows, and what a machine cannot

- **nervus listens on every address the machine has** when the unit's `--bind-host` is
  `0.0.0.0`, as the generic unit's is (ADR-0019 D2).
- **Python's standard library classes an address as global** when it is outside every private
  and reserved range. So would any check by address.
- **Whether an address is reachable from the internet cannot be read off the machine.** A
  private network can use addresses outside the reserved private ranges, reached only from
  inside it: global in form, private in fact. A check by address alone would call such a network
  public.
- **Nothing records a tier**, and **the UI's banner is empty**: `__main__.py` passes
  `banner=""`, with the comment "comes with first-run setup (piece 5)".

## Questions, and what was decided

### A. Where setup happens, and what it blocks

1. **In the UI.** Signed in, a browser sees the setup page, and nothing else, until a tier is
   chosen. MCP serves clients as before throughout. The choice is kept in the database.
2. **In the UI, and MCP refuses every client until setup is done.** Stricter. On an installation
   already running, every client would be refused from the deploy until the operator chose.
3. **A command**, `nervus-ctl setup --tier N`, or a line in the unit.

**Recommended: 1.** ADR-0005 decision 4 puts setup in the UI, and signing in already needs root
on the nervus machine (ADR-0011 question A). Blocking MCP adds nothing ADR-0007 asks for: the
tier is a declaration about where nervus runs, and a client's calls are no safer for its absence.
Option 3 puts a choice meant to be read and understood behind a flag nobody reads.

**Decided: 1.**

### B. Changing the tier later

1. **Changeable in the UI**, audited, from the same page.
2. **Fixed once chosen**; changing it means editing the database.

**Recommended: 1.** Moving nervus changes its tier, and a declaration that cannot follow the
move becomes the false belief ADR-0007 decision 2 exists to prevent.

**Decided: 1.**

### C. What counts as a public address

nervus is "public" when it listens on an address someone on the internet could reach. Nothing
on the machine can tell that for certain.

1. **By address.** Every address nervus listens on, every interface's for `0.0.0.0` or `::`,
   is checked with Python's standard library: one it classes as global makes nervus public.
   **On a network whose own addresses are global in form, the banner then stands on every
   signed-in page, and a warning is logged at every start, for as long as the network keeps
   them.**
2. **By address, with an exception the operator declares.** As 1, but at setup the operator may
   declare a range "not reachable from the internet", recorded and audited. The banner then
   becomes a smaller standing note naming the declaration, never nothing. This departs from
   ADR-0007 decision 4's "not dismissible", which would be amended.
3. **By reachability**, testing from outside. Needs a third-party service, and tells someone
   else where nervus is. Rejected in the draft.

**Recommended: 2,** revised after the operator's report of 2026-10-12 (deployment note 0015).
(The draft first recommended 1.) On a network that is global in form and private in fact, option
1 puts a warning on every page that the operator knows is false. A standing warning
known to be false teaches its reader to stop reading banners, which is the one thing ADR-0007
decision 4 must not do. Option 2 keeps the check and the record:
- The declaration names a range, never "everything", and is made at setup or later, signed in,
  audited, and changeable.
- **What stays visible:** a smaller standing note on every signed-in page ("<address> is global
  in form; declared internal by the operator on <date>"), and the same line in the log at every
  start. Never nothing.
- **What it does not cover:** an address outside every declared range is warned about in full,
  as in option 1. So a later move to a range nobody declared, or a second interface, is caught.

The cost: any future user can quiet the full banner by declaring their range. They have to name
it, and the note and the log keep saying so. ADR-0007 decision 4's "not dismissible" is amended to
"not dismissible, but reducible to a standing note by a recorded declaration naming the range".

**Decided: 2.**

*Reconsidered 2026-10-20, before building, and kept, at the operator's word* ("1, fine. as long as
it won't interfere with someone's actual setup and process"). Asked how necessary the check is when
a home network may use any addresses inside it, the session's answer: most home routers still hand
out private addresses, so the check is silent there; it catches exactly a machine with a public
address on itself, such as a rented server, the most exposed case; it misfires on a network that
uses public-form addresses inside, which the declaration answers; and it **cannot see a port
forwarded on a home router**, the likeliest way a home user exposes nervus, since the machine keeps
its private address. The options then: keep the check and add a sentence for what it cannot see
(chosen); drop it for a question at setup, as the tier is asked; or drop the warning, which would
reverse ADR-0007 decision 4. So:
- **The setup page also says, whatever the check finds:** never forward a port on a router to
  nervus; to reach it from outside, use an overlay network (ADR-0007 decision 4).
- **The check never interferes with a setup:** it only reads the machine's addresses, never changes
  them, never refuses a start, never blocks a client, and a check that fails says it could not tell
  and lets nervus start.

### D. When the address is checked

1. **At every start**, as ADR-0007 requires for the log line; the banner shows that result until
   the next start.
2. **At start and every few minutes**, so an address that changes while nervus runs moves the
   banner without a restart.

**Recommended: 1.** The address nervus listens on rarely changes while it runs, and a change
comes with a restart in practice. Option 2 is a timer and a moving state for a rare case.

**Decided: 1.**

*Clarified 2026-10-20, before step 4, at the operator's word* ("with declarations applied at once"):
the addresses are read at start only, but the banner matches them against the declared ranges each
time a page is shown, so a declaration made or withdrawn changes the banner and the notes at once,
without a restart. The line in the log follows at the next start.

### E. Where the tier is shown

ADR-0007: "wherever the installation is described".

1. **The UI's header on every signed-in page, the console line at every start, and `nervus-ctl
   status`.**
2. **The setup page and the home page only.**

**Recommended: 1.** Each is where someone looks to learn what an installation is. Each is one
line.

**Decided: 1.**

## Questions F to I: after ADR-0021 to ADR-0024

*Added 2026-10-20.* Between this record's decision and its building, ADR-0023 made an installer
that makes nervus's keys, ADR-0024 built enrollment, and ADR-0021 made HTTPS the normal transport.
Four questions this record did not answer followed.

### F. Which wording of the tiers the setup page uses

ADR-0007 decision 2 calls tier 3 "on the user's machine, as the user (Docker Desktop, rootless
Podman)". ADR-0023 rewrote the tiers around which computer hosts nervus, so a VM the everyday
computer hosts is tier 3 too, and `docs/install.md` uses that wording.

1. **ADR-0023's wording, and ADR-0007 decision 2 marked as amended by it.**
2. ADR-0007's wording, as this record cited it.

**Recommended: 1.** It is what the installer's guide already tells the reader, and it answers the
case ADR-0007's wording misses: a VM looks like a machine of its own and is not.

**Decided: 1.**

### G. A database that names enrolled machines, without nervus's key

ADR-0005 consequence 6 asks nervus to refuse to start when its key is gone but enrolled machines
remain; "Not proposed here" left that to the container image. Since ADR-0022 and ADR-0024 the
database does name enrolled machines, so the case can now arise on any installation, a database
restored without the key among them.

1. **Left to the backups ADR**, which decides what is kept, and restored, together.
2. Built with first-run setup.

**Recommended: 1.** The case is a restore's, and the backups ADR decides what a restore brings back.

**Decided: 1.**

### H. ADR-0007 consequence 4's "what an agent can do to you"

1. **A short section in the preview README, beside the non-goals**, built with this record's docs.
   ADR-0024's three levels give it its content. ADR-0007 consequence 4 is amended from a page to a
   section.
2. A page of its own.
3. Not part of first-run setup.

**Recommended: 1.** One place for what nervus does not defend and what an agent can still do.

**Decided: 1.**

### I. A banner for plain HTTP

The banner is for a public address. Plain HTTP off loopback is now the explicit exception
(ADR-0021), warned about in the log at every start (ADR-0010 decision 1).

1. **No banner for it.**
2. A banner beside the public-address one.

**Recommended: 1.** ADR-0007 does not ask for one, the log already says so, and the Machines page
already refuses to show enrollment's lines over plain HTTP (ADR-0024).

**Decided: 1.**

## Settled already

- **The choices are kept in the database** (ADR-0011 decision 1), in a table added without
  changing the version (ADR-0014 decision F).
- **The setup page states the non-goals of ADR-0007 decisions 9 and 10 in plain words**, above
  the tier choice, and says what each tier means in a sentence (consequence 2).
- **The banner is the one ADR-0012 built a place for**, on every signed-in page, and no page can
  leave it out. Signed out, nothing shows but how to sign in (ADR-0011 verification 5): the
  banner is for someone signed in.
- **Choosing or changing the tier is audited**, actor `operator`, tool `ui`, with the browser's
  address (ADR-0003 decision 6, ADR-0012 decision 6). Every form needs nervus's own origin and
  the session's form token.

## Not proposed here

- **Making the fleet key and nervus's TLS key at setup**, and refusing a volume that has
  enrolled hosts but no key (ADR-0005 consequence 6, ADR-0010 decision 4). Both belong with
  packaging nervus as a container for others; on the first installation both already exist.
  *Since 2026-10-19 the installer makes both keys (ADR-0023 6a); the refusal is the backups ADR's
  (decision G).*
- **Enrollment**, piece 6.

## Consequences

1. **Piece 5 builds, one commit each, every new test seen to fail first**, when its turn comes:
   1. what nervus listens on: every address, each global in form or not, the declared ranges it
      falls in, and the line logged at every start: the full warning, or the note (C, D);
   2. the database: the tier and the declared ranges, each with who declared it and when, in a
      table added without changing the version (ADR-0014 decision F);
   3. the pages: setup (the non-goals, the three tiers, the choice, declaring a range, and never
      forwarding a port to nervus), the
      banner or the note on every signed-in page, and the tier in the header (A, C, E);
   4. the UI serving them: until a tier is chosen, a signed-in browser sees only setup; choosing,
      changing and declaring are audited (A, B); `nervus-ctl status` shows the tier (E).
2. **On an installation already running, the deploy is followed by setup.** The operator
   chooses its tier and declares any range they know to be internal, so every page carries the
   note, not the banner. A declaration that later matches nothing can be removed.
3. **ADR-0007 decision 4 is amended**, by decision C: not dismissible, but reducible to a standing
   note by a recorded declaration that names the range.

## Verification

Moves to Accepted when observed in tests first seen to fail, or on an installation.

1. Signed in, with no tier chosen, every page shows setup and nothing else, and MCP serves
   clients throughout (ADR-0007 verification 2, first half). **Observed, procedure 039 steps 3 and
   4, and in tests.**
2. Once a tier is chosen, it shows in every signed-in page's header, in the line logged at start,
   and in `nervus-ctl status`; changing it later is audited (ADR-0007 verification 2, second half).
   **Observed, procedure 039 steps 6 and 8, and in tests.**
3. With an address global in form and in no declared range, every signed-in page carries the
   banner and every start logs the warning, and nervus runs (ADR-0007 verification 3). **Observed,
   procedure 039 steps 2 and 7, on a real `ip` reading, and in tests.**
4. With that address's range declared internal, every signed-in page carries the note naming the
   range and the declaration, never nothing, and every start logs the same; an address outside
   every declared range still gets the full banner. **Observed, procedure 039 step 7 (a range not
   covering the address left the full banner), and in tests.**
5. The setup page states ADR-0007 decisions 9 and 10's non-goals in plain words (ADR-0007
   verification 1, its first-run half). **Observed, procedure 039 step 5, and in tests.**
6. On an installation that declares a range, after setup: its tier in the header, and the note
   naming that range. **Observed 2026-10-24, procedure 041 step 7.2**, on the installation it deployed: Tier 1
   in the header and the note naming the declared range, no warning.
