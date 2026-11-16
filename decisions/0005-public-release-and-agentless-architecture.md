# ADR-0005: nervus will be published, and agentless push is the architecture

**Status:** Proposed (Accepted when the verification below is observed)
**Confirmed by the operator, 2026-11-15** ("Yes, in that order (Recommended)"): what is left
before nervus is published more widely is three projects, in this order: client sign-in
(ADR-0006), the connector (ADR-0008), and the container image (ADR-0005 decision 1). This record
stays Proposed until the third is built: its verification items 2 and 5 are worded for that image.
Item 1 was observed for the public repository on 2026-11-15 (procedure 064), item 3 as ADR-0024
verification 2, and item 4 as ADR-0007 verification 7.
**Date:** 2026-09-12
**Extends:** ADR-0001, which scoped nervus to one operator, one fleet, one LAN
**Decided by:** the operator, 2026-09-12
**Rewritten:** 2026-10-16, under ADR-0019 F, where it leaned on ADR-0004, now a deployment note. No decision changed.
**Prior art:** `research/2026-10-15-prior-art.md` idea 2 bears on decision 5 (a middle level, a shell with no sudo, enforced by the target's sudoers). A note, not a decision.
**Amended by:** ADR-0018 (2026-10-15), for a friends preview only: decision 3's split does not apply to it. The preview takes the deployment record too, with the operator's particulars taken out. Decision 3 still governs the public release.
**Amended by:** ADR-0018's amendment of 2026-11-13, at the operator's word: the friends preview's repository is made public under the project's name. Verification item 1 below applies to it.
**Amended by:** ADR-0019 (2026-10-15): decision 3's split between code and deployment record becomes a standing rule for every document, not a step at publication. Decision records and code name no system of the operator's; the deployment record does.

## Context

ADR-0001 built nervus for a known network and a trusted operator who is also its
developer. Every simplification it makes rests on that: plain HTTP because the LAN is
trusted, a hand-written `hosts.yaml` because there are two hosts, no user interface
because the operator has root on the container, and `agent` as an unrestricted
root-equivalent account because the only client authors are the operator's own agents.

On 2026-09-11 the operator asked whether nervus could be distributed to other people
running headless Linux machines at home. This ADR answers yes, and settles the
questions that answer forces. It also records a position ADR-0001 never argued for
explicitly, because a public version will be asked to justify it by every user who
has met Puppet, Salt or a Portainer agent.

### Why the architecture question has to be settled here

nervus reaches targets by opening an outbound SSH connection to an account it
provisioned. Nothing runs on the managed machines. That was partly circumstance in
ADR-0001 — SSH was already there — but it is defensible on its own terms, and the
alternative was never written down and rejected.

The design space divides on one question: **who holds the credential, and which way
does the connection go.**

| model | on each target | connection | examples |
|---|---|---|---|
| agentless push — nervus | nothing but `sshd` | central to target | Ansible, Fabric, Salt-SSH |
| agent, polling | a permanent daemon | target to central | Puppet, Salt minion, Portainer agent |
| message bus | a daemon on a broker | target to broker, central to broker | Salt/ZeroMQ, NATS, MQTT |
| per-machine server | one server per box | client to each target | what ADR-0001 replaced |

An agent's advantage is almost always **reachability**, not capability: it works from
behind NAT, survives roaming, and needs no inbound path. Those matter for laptops and
for machines at other sites. They do not describe the target user of this project —
someone with headless Linux boxes on their own LAN.

Against that, an agent puts a permanent root-privileged process on every machine
being protected, which becomes the operator's patch burden and the project's supply
chain on every node.

One property is easy to miss and is the strongest argument. **Push over SSH leaves an
independent witness.** Every connection appears in the target's own `sshd` journal,
written by the target, which nervus cannot edit. nervus's audit log is authoritative
for nervus, but whoever controls nervus controls that log; the target's journal is a
second record from a party with no stake in the first. This project treats the audit log
as authoritative (ADR-0001 s10), yet SSH that does not go through nervus, such as the
operator's own, leaves no record in it, so a gap there is invisible rather than obviously
absent (deployment note 0004 records how that arises on the first installation). A second,
independent record is
the mitigation. An agent architecture largely forfeits it, because the agent doing the
work is also the thing doing the reporting.

## Decision

**1. nervus will be published** as an open-source, self-hostable MCP bastion, packaged
as a container image with a compose file, aimed at people running headless Linux
machines at home who already use Claude Code or Codex.

**2. Agentless push over SSH is the architecture, not a stage.** It will be documented
as a deliberate choice with the reasoning above, not presented as a limitation. Adding
an agent is out of scope. If reachability becomes a requirement — a machine off the
LAN, or behind NAT — the answer is an overlay network beneath unchanged SSH transport
(WireGuard, Tailscale, Headscale), not an agent. That ordering is part of this
decision, so it is not relitigated the first time someone asks.

**3. This repository stays private. The public repository starts with fresh history.**
Publishing this history publishes this fleet. Every one of the eleven tracked markdown
files carries operator-specific content, `hosts.yaml` most of all: DNS names, subnet,
both machines' hardware, what listens on which port, and a careful account of what is
misconfigured or absent. Deployment note 0004 (ADR-0004 until 2026-10-16) maps the
operator's residual SSH access and names which key is load-bearing. Deleting those files later does not help, because git keeps
them.

The split is code versus deployment, not a fork:

- **Private (this repository)** — the deployment record for this fleet: `hosts.yaml`,
  deployment notes 0002 and 0004 (ADRs until 2026-10-16), `CURRENT_STATE.md`, the
  procedures as executed, and the operator-specific defaults in `tools/`.
- **Public (fresh history)** — `src/`, tests, packaging, the enrollment script, and
  generalised ADRs. `src/` was verified on 2026-09-12 to contain **zero**
  fleet-specific references; it was written generic and needs no scrubbing. The
  contamination outside it is confined to fixture names in `tests/`, one comment in
  `deploy/nervus.service`, and default values in `tools/nervus-status` and
  `tools/nervus-env`. *Found not to hold by 2026-10-15:* `src/` had come to hardcode the
  Proxmox host's name, and the unit to carry the instance's flags (ADR-0019 Context). Both
  were removed on 2026-10-16, and AGENTS.md rule 11 now keeps decisions and code clean as
  they are written.

Work continues in this repository. Publication is a separate, later, deliberate act.

**4. A web UI is in v1**, served by the same container as the MCP endpoint. It carries
first-run setup, enrollment (issuing the one-line command and its short-lived token),
token and client management, host inventory, and the audit log viewer.

The audit log's home is this UI and only this UI. **It must not be readable through
the MCP surface**: a client that can read the log sees what every other client did,
which is cross-client disclosure in a system whose whole value is per-client
attribution. That constraint is part of this decision.

**5. v1 defaults to read-only, and the restriction is enforced by the target.**
Enrollment takes a level. A read-only enrollment installs nervus's key into
`authorized_keys` with a forced command, so `sshd` on that machine runs one fixed
program regardless of what nervus asks for. Full access is opt-in, per host, chosen by
the person standing at that machine.

This is deliberately not MCP-layer filtering, which ADR-0001 s5 rejects. The
difference is that nervus cannot grant itself more than it was given: a fully
compromised nervus still cannot escalate on a read-only host, because the restriction
lives on the far end and nervus never had the ability to lift it. A filter nervus
applies to itself is a policy; a forced command is a boundary.

**6. The name stays `nervus`.** Researched on 2026-09-12 against the operator's
standard of "a serious collision". None found, though the name is not distinctive and
that cost is accepted knowingly.

Free, and these are the namespaces publication actually needs: PyPI, npm and
crates.io all return not-found for `nervus`; Docker Hub has no exact match; the GHCR
path follows the publishing account. `nervus.com` and `nervus.sh` are unregistered.

Taken, and none of it blocking: `github.com/nervus` is a personal account dating to
2011, so there is no org namespace — the public repository will live under the
operator's own account. `nervus.io` is an active freemium SaaS, an AI productivity
suite. `nervus.co.uk` is Nervus Ltd, a UK neurodiagnostics company selling EEG systems.
GitHub has 37 repositories with the name, the largest at 7 stars and none in this
space; the nearest neighbours are `kuchenboss/Nervus` (Linux peripheral and fan
control) and `wangqioo/nervus-v2` (a personal AI "nervous system" for Jetson), both
effectively dormant.

The residual risks are discoverability and trademark. Search results are already
crowded by an active SaaS, a medical company, and the Latin anatomical term that
appears in every anatomy text. On trademark: Nervus Ltd operates in medical devices,
a different class and market from a self-hosted developer tool, which normally means
no conflict — but **no registry record was retrieved and this is not a clearance
opinion.** If the project ever acquires commercial intent, that check should be done
properly by someone qualified.

## Alternatives considered

- **Publish this repository with the fleet-specific files removed.** Rejected: git
  history retains them, and a scrub-and-force-push is both error-prone and
  unverifiable after the fact.
- **Extract a shared library consumed by a public repository and a private one.**
  Rejected as machinery for two consumers, one of them a single fleet. The three
  defects found on 2026-09-11 were all found by exercising the running system; keeping
  the operator's own instance on the published code is what preserves that.
- **Ship v1 as config-file-driven, defer the UI.** Ships sooner, but leaves the audit
  log with nowhere to live and pushes token and enrollment state into files a new user
  must hand-edit correctly on their first day. Rejected: it undercuts the reason for
  publishing.
- **Full access by default, tiering later.** Rejected. A default that hands
  root-equivalent access to a language model is not a defensible thing to distribute,
  whatever the README says.

## Consequences

1. **The operator is no longer the developer.** Every simplification ADR-0001 justified
   by "the operator knows" becomes a defect. Plain HTTP on a trusted LAN is the clearest
   case: published, it will be port-forwarded within a week. v1 must refuse to bind a
   non-loopback address without TLS, or ship a working default.
2. **The threat model needs rewriting, not extending.** ADR-0001's is one operator, one
   LAN, trusted clients. The public one has an unknown operator, unknown topology, and
   clients whose prompt input is attacker-reachable. That is its own ADR.
3. **The UI is the largest single piece of new work** and brings its own authentication,
   session handling and attack surface — more code than the MCP server it fronts.
4. **The kill switch (ADR-0003) becomes UI-shaped.** It is specified and unbuilt; a
   per-client off switch is exactly what a client-management screen exists to offer.
   ADR-0003 should be built into the UI rather than ahead of it.
5. **`hosts.yaml` stops being a config file and becomes state the service writes.**
   Enrollment writes inventory. That brings atomic replacement, concurrent writes, and
   defined behaviour on a corrupt file.
6. **The persistent volume becomes load-bearing.** If nervus generates its own keypair
   on first run — which it should, so that no private key ever exists anywhere a user
   could paste it — then a recreated stack without its volume silently invalidates every
   enrolled host. First run must detect an empty volume alongside enrolled hosts and
   refuse loudly rather than start fresh.
7. **Audit log retention stops being deferrable.** It is undecided here because `pct
   resize` makes it cheap on one fleet. On someone else's disk it is not.
8. **A support burden begins at publication** and does not end.

## Verification

Moves to Accepted when all of the following are observed, not asserted:

1. A fresh public repository, from a scrubbed tree, with no fleet-specific string in
   any tracked file or in its history. Checked by search, not by inspection.
2. On a machine that has never seen nervus: deploy the stack, complete first-run
   setup, enroll one host read-only, and run a command from Claude Code — end to end,
   timed, without editing a file by hand.
3. On that read-only host, a write attempt through nervus is refused **by the target**,
   with the refusal visible in the target's own `sshd` journal as well as in nervus's
   audit log.
4. The audit log is reachable in the UI and **not** reachable through any MCP tool,
   confirmed by an authenticated client attempting it.
5. nervus started with no volume present generates its own keypair, and started with an
   empty volume while hosts are enrolled refuses to start.
