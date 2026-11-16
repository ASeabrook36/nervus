# ADR-0007: the threat model for a published nervus

**Status:** **Accepted 2026-11-15, at the operator's word** ("Both Accepted (Recommended)", asked
of this record and ADR-0019 together), every verification item observed: "Where each stands",
under the list, says where, and names the two readings the operator was shown before accepting,
of items 4, 5 and 7. (It was Proposed: accepted when the verification below is observed.) The four
questions this ADR was drafted around were settled by the operator on 2026-09-18.
**Amended 2026-10-02** by ADR-0010 decision 1, decided by the operator: decision 3 and
verification 6.
**Amended 2026-10-20** by ADR-0015 decisions F and H, decided by the operator: decision 2's
tiers take ADR-0023's wording; consequence 4 is a section of the README, not a page.
**Amended 2026-10-23** by ADR-0026 question 2, decided by the operator: decision 3, for the moment of
first contact only. A machine added by an admin login is trusted on the first host key it answers
with, shown to the owner with how to check it, the password sent only to that key, and the key then
compared with those the machine itself reports. The two lines, unchanged, remain the way for a
network the owner does not trust. Deployed 2026-10-24; ADR-0026 Accepted the same day.
**Amended 2026-10-27** by ADR-0025 decision 5 and question 3, decided by the operator on 2026-10-21:
decisions 6 and 8 say what protects the record of which client did what, and that it holds with
nothing configured elsewhere; the machine underneath nervus is named. Deployed 2026-10-28; ADR-0025 Accepted the same day.
**Amended 2026-11-01** by ADR-0027 question 2, decided by the operator on 2026-10-28: decision 7,
nervus's secrets leave it inside a backup locked to a recovery key nervus does not hold, and in no
other way. Deployed 2026-11-01; ADR-0027 Accepted the same day.
**Date:** 2026-09-18
**Rewritten:** 2026-10-16, under ADR-0019 F, to name no installation. No decision changed.
**Implements:** ADR-0005 consequence 2, which says the public threat model "needs
rewriting, not extending", and is its own ADR
**Extends:** ADR-0006 consequences 7 and 10, which defer three questions to here
**Read alongside:** ADR-0001 s5 (where the boundary lives), ADR-0005 s5 (read-only
enforced by the target), ADR-0006 (client authentication)

## Context

ADR-0001 never wrote its threat model down, because it did not have to. Every
simplification rested on the same four assumptions: one operator, who is also the
developer; one LAN, physically controlled; clients written and run by that operator; and
a machine the operator can walk up to. Published, every one of those fails.

- **The operator is not the developer.** They will not read the source, and will
  reasonably assume a security property the code does not have.
- **The topology is unknown.** Someone will port-forward it, as ADR-0005 consequence 1
  predicted, or run it on a VPS, or on the same laptop as their editor.
- **Client input is attacker-reachable.** An agent reads issues, pull requests, web
  pages and package registries, and then calls tools. This is the ordinary case, not the
  worst case.
- **The machine may be shared, stolen, or someone else's.**

This ADR states what nervus defends, what it does not, and why — so that the things it
does not defend are known rather than discovered.

## Assets, in the order an attacker would want them

1. **The fleet SSH private key.** Root-equivalent on every enrolled host, and the reason
   the bastion exists. Its compromise is total and silent.
2. **The enrolled hosts themselves** — data, compute, and whatever they reach.
3. **Client credentials** (ADR-0006 grants, or fallback tokens). Each is fleet access
   within its allowlist and level.
4. **The audit log.** The only record that distinguishes one client from another, and
   what ADR-0001 trades per-session approval for.
5. **The inventory** — hostnames, addresses, roles. A map of the network.
6. **The transfer directory**, which moves files in both directions.

## Adversaries, and what each one can reach

| | adversary | reaches | likelihood |
|---|---|---|---|
| A | **Untrusted content an agent reads**, steering it into tool calls | every tool the calling client is granted | routine |
| B | **Another program running as the same user** as the client | that client's stored credential; nervus's own files if it runs as that user too | plausible |
| C | **Someone on the same network** | the endpoint, and anything unencrypted on the wire | plausible on shared or guest networks |
| D | **Someone on the internet**, if the endpoint is exposed | the endpoint, at unlimited rate | certain, once exposed |
| E | **A malicious client app** the user installed | whatever it is granted, under a name it chose | possible |
| F | **A compromised nervus** | the fleet key, every grant, and the audit log | catastrophic, low |
| G | **A compromised enrolled host** | its own data; the `agent` account; whatever that account reaches | plausible |
| H | **Physical access** to an unlocked client machine | as B, plus the browser session | out of scope below |

## Decisions

**1. Adversary A is the primary one, and filtering is not the answer.** An agent acting
on hostile text is the ordinary operating condition. ADR-0001 s5 already rejected
command filtering as trivially bypassed. The defences are, in order:

- **Read-only by default, enforced by the target** (ADR-0005 s5). A forced command in
  `authorized_keys` means a hostile instruction cannot write, whatever nervus is asked.
- **Per-client revocation** (ADR-0003, ADR-0006 decision 8), so a client that starts
  behaving badly can be switched off without touching the others.
- **The audit log**, which makes the damage legible afterwards.

nervus therefore promises *containment and accountability*, not *prevention*, against
this adversary — and the documentation must say exactly that. An agent with full access
to a host can do anything the person could.

**2. Adversary B is out of scope for client credentials, and in scope for nervus's own
secrets.** ADR-0006 settles the first half: on one machine under one user, a determined
program can take another client's credential, and only OS-level isolation would stop it.

The second half is this ADR's to answer, and the answer is **where nervus runs**:

| tier | nervus runs | adversary B can | status |
|---|---|---|---|
| 1 | on a separate machine | only call nervus, through sign-in and the log | **recommended** |
| 2 | on the user's machine, under its own account | only call nervus | supported |
| 3 | on the user's machine, as the user (Docker Desktop, rootless Podman) | enter the container; read the fleet key and the log; bypass nervus entirely | supported, labelled |

*Amended 2026-10-20 by ADR-0015 decision F:* the tiers are worded as ADR-0023 words them, by
which computer hosts nervus. Tier 1 is a different physical computer from the everyday one, in
any form; tier 2 the everyday computer, under nervus's own account; tier 3 the everyday computer
where the user's own account can get in, which includes a VM or container that computer hosts.

Tier 3 is what a default `docker compose up` produces, and on Linux, membership of the
`docker` group collapses tier 2 into tier 3. **All three are supported, because refusing
tier 3 would cost most users their easy start.** What is not acceptable is a user
believing they are in tier 1 when they are in tier 3.

**The user declares the tier during first-run setup, and nervus takes them at their
word.** It then shows that tier wherever the installation is described. Detection is not
attempted: the signals available inside a container are weak, and a confident wrong
answer is worse than an honest question. The declaration's purpose is that nobody reaches
the end of setup without having been told the three tiers differ and having chosen one.

**3. The network is not trusted, anywhere.** Adversary C is assumed on every network,
including home LANs. TLS off loopback is required (ADR-0005 consequence 1, ADR-0006
decision 6), nervus binds loopback by default, and the inventory and audit log are never
served unauthenticated. (Amended 2026-10-02, ADR-0010 decision 1: required unless
explicitly opted out, by a flag that names what it gives up and warns at every start. The
first installation is the case ADR-0006 decision 6 names.)

**4. Public exposure is not a supported configuration in v1.** *Amended 2026-10-15 by
ADR-0015 decision C:* the warning below is not dismissible, but a recorded declaration that
names an address range as internal reduces it, for that range only, to a standing note that
names the declaration. Never to nothing. Adversary D against a
service holding a root-equivalent key is a different class of problem: it needs rate
limiting, lockout, disclosure handling, and an authentication story that survives
attention. ADR-0001 s8 deferred public exposure to its own decision and that remains
true. The documented answer for reaching nervus from outside is an overlay network —
WireGuard, Tailscale, Headscale — which ADR-0005 s2 already chose over any alternative.

**nervus warns loudly rather than refusing.** A refusal would break legitimate setups it
cannot distinguish from mistakes — a VPS reached over an overlay, a host whose only
address is public — and a tool that blocks a user's own deployment gets worked around,
usually in a worse way. The warning is therefore unmissable rather than advisory: stated
during setup, carried as a standing banner in the UI, and written to the log on every
start while the condition holds. It is not dismissible while the address is public,
because the risk does not go away when the user stops reading it.

**5. A malicious client app (E) is bounded by consent, not by identity.** Under dynamic
registration a client names itself, so nervus cannot verify that "Claude Code" is Claude
Code (ADR-0006 decision 3). What bounds it is that a human approves each grant, in the
moment, from the app they just used; that the grant carries an allowlist and a level; and
that it can be revoked. Client ID metadata documents would strengthen the name, not the
boundary.

**6. A compromised nervus (F) is total, and the mitigation is evidence, not prevention.**
Whoever controls nervus controls the key, the grants and the log. Three things limit the
blast radius, and none of them is a wall:

- **The target's own `sshd` journal** is an independent record nervus cannot edit
  (ADR-0005), which is why agentless push is the architecture.
  *Amended 2026-10-27 by ADR-0025:* it names the client and the run behind every login, from
  the certificate nervus signs for each call, written by the machine before any command runs. It
  is a second witness, not a protected one: a client with full access to that machine can edit
  its journal afterwards. nervus does not manage machines' logs; forwarding them is the machine
  owner's choice, outside nervus.
- **Read-only hosts stay read-only.** The forced command lives on the target, so a fully
  compromised nervus cannot lift it (ADR-0005 s5).
- **nervus never accepts inbound connections from targets**, so a compromised host
  cannot reach back through it (adversary G).

**7. Secrets never leave nervus.** The fleet private key is generated on first run
(ADR-0005 consequence 6), stored 0600, and has **no export path**: not in the UI, not
through any MCP tool, not through `put`/`get`, whose confinement to the transfer
directory already exists for this reason. A user who needs a key they can paste is
choosing a different trust model and must be told no.

*Amended 2026-11-01 by ADR-0027 question 2:* nervus's secrets leave it only inside a backup
encrypted to a recovery key nervus does not hold; never through an MCP tool, `put`/`get`, or in
clear. nervus keeps the key's public half, which locks a backup but cannot open it; the person keeps
the private half, never on nervus's machine.

**8. The audit log is append-only against clients, not against root.** Anyone with root
on the nervus host can rewrite it; that is inherent to a log that lives on one machine,
and the targets' `sshd` journals are the cross-check.

*Amended 2026-10-27 by ADR-0025 decision 5 and question 3:* what protects the record of
which client did what, said plainly:

- **nervus's audit log is the record, and it is out of every client's reach.** The intent
  record is written before anything reaches a machine (ADR-0001 s10), so a command cannot
  remove the record of itself, an attempt to tamper with logs included. No MCP tool reads or
  writes it (ADR-0005 s4). No client reaches nervus's own machine as root (ADR-0024
  decision 6), and read-only or standard there cannot read the log's folder.
- **This needs no copy anywhere.** A copy elsewhere (ADR-0009 decision 4, the forwarding
  below) defends against root on nervus's machine, a compromised nervus or its operator, not
  against clients. Many people will never set one up, and nervus must not lean on it.
- **Where a copy exists, no client may reach it** (ADR-0009 decision 4: pulled, not pushed,
  by a key that can only read). A copy on a machine enrolled at full access is not a copy.
- **The machine underneath nervus is the exception.** ADR-0024 decision 6 refuses full access
  to the machine nervus runs on, by its machine id; a hypervisor or container host under
  nervus has another. A client with full access there, or a hypervisor connection that reaches
  nervus's own guest, can stop nervus and rewrite its disk, the log included. nervus says so
  wherever this guarantee is stated, and asks when full access is chosen for a machine; a
  hypervisor connection, set up by hand, excludes nervus's own guest.

**Where it lives, and how it is read:**

- **Read only through the UI**, never through an MCP tool. ADR-0005 s4 already fixes
  this: a client that can read the log sees what every other client did.
- **Stored locally by default**, in the container's volume, needing no configuration.
- **The user may point it at another location**, including a network path mounted into
  the container. That is one setting, not a second protocol, so it costs nothing to
  support and it keeps the log alive when the machine is not.
- **Forwarding to an external log service** (ADR-0001 s10's log store) stays a later
  option. It is the only real answer to tampering, because it puts a copy where whoever
  has root on the nervus host cannot reach it. Not in v1; not blocked by anything here.

**9. Non-goals, stated plainly.** nervus does not defend against: code running as the
same user as a client (B, for credentials); a hostile operator of the nervus instance;
physical access to an unlocked client machine (H); a user who grants full access and then
asks an agent to destroy something; or an enrolled host attacking its own data. It is
also **not multi-tenant**, which decision 10 settles.

## Consequences

1. **The README must carry the non-goals**, not bury them. The project's value is
   accountability; a project that overstates its guarantees undermines exactly that.
2. **First-run setup gains a required tier choice**, which means setup can no longer be
   a pure formality: it has to explain three deployment shapes in a few sentences a
   non-specialist will read.
3. **Read-only default becomes load-bearing for the whole model.** ADR-0005 s5 was
   argued as a sane default; here it is the primary defence against the primary
   adversary. Its verification matters more than its convenience.
4. **Documentation owes a "what an agent can do to you" page.** Not a warning label: a
   short, concrete account of the routine case — hostile text in a repository steering a
   tool call — and what read-only enforcement does and does not stop.
   *Amended 2026-10-20 by ADR-0015 decision H:* a short section of the README, beside the
   non-goals, not a page of its own.
5. **Any future public-exposure ADR inherits this one**, and must add rate limiting,
   lockout, and a disclosure process, none of which v1 has.

**10. One instance is one trust domain, in v1.** There are no user accounts. Whoever can
open the UI sees every client's audit entries, approves and revokes every grant, and
enrolls hosts. Two people sharing one instance share all of it: each sees what the
other's agents ran, and either can switch off the other's access.

That fits who this is for — one person, or one household with their own machines — and
it keeps the UI to a single authenticated surface rather than accounts, ownership and
per-user filtering.

**The README must say it**, because the failure mode is a small team deploying one
instance and assuming privacy between members that does not exist. Separate views are not
a screen to bolt on later: they change what a grant belongs to, what the audit log
filters by, and what the UI authenticates. If they are ever wanted, that is its own ADR
and a migration, decided knowingly rather than discovered.

## Verification

This ADR is mostly about what is *not* defended, so its verification is narrower than
ADR-0006's. Moves to Accepted when:

1. The README and first-run flow state the non-goals of decision 9 in plain words, and
   decision 10's single trust domain among them.
2. Setup cannot be completed without choosing a tier, and the chosen tier is then
   visible in the UI.
3. A public bind produces the warning at setup, a standing banner, and a line in the log
   at every start — and does not prevent the service running.
4. A read-only host refuses a write attempt at the target, with the refusal in that
   host's own `sshd` journal — ADR-0005 verification 3, repeated here because this model
   depends on it.
5. No MCP tool, UI page, or transfer path can retrieve the fleet private key, confirmed
   by attempting each as an authenticated client.
6. nervus started with a non-loopback bind serves only HTTPS; if it has no certificate,
   it refuses to start and says why. Plain HTTP there needs the explicit opt-out flag, and
   logs a warning at every start. (Amended 2026-10-02, ADR-0010 decision 1; it read
   "nervus started with a non-loopback bind and no TLS refuses to start, and its error
   says why".) Distinct from item 3: plain HTTP off loopback needs an explicit opt-out; a
   public address is warned about.
7. The audit log is readable in the UI, unreadable through every MCP tool, and follows
   the configured location when that is changed.

**Where each stands, 2026-11-15.** What this record asked for was built under later ones, and each
item was observed there. Read against the code, the tests and the procedures on 2026-11-15, after
the review of procedure 056 went through this list:

1. The README states the non-goals and the single trust domain, and the setup page states the same
   list: ADR-0015 verification 5 (procedure 039 step 5, and in tests). A test holds the two lists
   to each other since procedure 054's fifth finding.
2. ADR-0015 verification 1 and 2: procedure 039 steps 3, 4, 6 and 8, and in tests.
3. ADR-0015 verification 3: procedure 039 steps 2 and 7, on a real reading of a machine's
   addresses, and in tests.
4. ADR-0024 verification 2: a write outside `~/.nervus` is refused by the machine, on each system
   tried (procedures 037, 054, 055 and 057). **Read as ADR-0024 built it:** the refusal is made by
   the machine's kernel, inside the read-only shell, so it shows in the command's own answer, which
   nervus's audit log keeps as the call's result. The machine's own `sshd` journal holds the login,
   naming the client and the run (ADR-0025 verification 1, procedures 042 to 044); it holds no line
   for the refusal itself, as this item was first worded.
5. Every route tried by procedure 056 was refused, and ADR-0025 verification 7 observed the same
   for the certificate key (procedures 042 and 043). **With the exception ADR-0013 asked to have
   named here:** a token given root on the hypervisor under nervus's machine reaches everything in
   that machine. ADR-0009 decision 3 grants that level knowingly, and decision 8 above, as ADR-0025
   amended it, names the machine underneath nervus.
6. ADR-0010 verification 1, each part observed when that record was accepted (in tests, and at
   its deploy, procedure 017); and every installation the installer has made serves both its ports
   over HTTPS (procedures 035, 047, 054, 055 and 064).
7. Readable in the UI, and following `--audit-log`: ADR-0013 verification 8 (procedure 021).
   Unreadable through every MCP tool: procedure 056, with the same exception as item 5.
