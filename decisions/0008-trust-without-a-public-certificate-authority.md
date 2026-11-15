# ADR-0008: a home user authorises nervus themselves, with a first-party connector

**Status:** Proposed (Accepted when the verification below is observed). **Amended
2026-10-02** by ADR-0010, decided by the operator: decisions 2 and 9 and verification 3.
What a connector pins, and a user compares, is nervus's public key, not its certificate;
where this ADR still says "pinned certificate", read the key.
**Amended 2026-10-17** by ADR-0021, decided by the operator: the Context's account of Claude
Code, decision 8's v1 paths, and the first alternative. Each is marked where it stands.
**Date:** 2026-09-18
**Extends:** ADR-0006 decision 6 (transport), which required HTTPS off loopback and left
certificates to deployment; ADR-0007 decision 2 (deployment tiers), whose recommended
tier is the one that pays for it
**Decided by:** the operator, 2026-09-18 — a home user should be able to say "I trust
this machine" without buying a domain or joining anyone's network
**Sequencing:** **after v1**, decided by the operator on 2026-09-18. See decision 8.
**Rewritten:** 2026-10-16, under ADR-0019 F, to name no installation. No decision changed.

## Context

ADR-0006 requires TLS for anything but `localhost`, and ADR-0007 recommends running
nervus on a separate machine. Together those say: **the deployment we recommend needs a
certificate**, and the honest ways to get one all reach outside the project — a domain
with a DNS provider's API, or an overlay service like Tailscale that issues certificates
for its own names. For a home user with a spare box and no domain, that is a wall in
front of the recommended setup. It is also a third-party dependency in the default path,
which the operator has rejected twice: once for a certificate-issuing reverse proxy, once
here.

### Why "just click trust" does not work today

What a home user wants is what SSH gives them: connect, see a fingerprint, accept it,
never think about it again. The mechanism is ordinary and sound.

The obstacle is **where that decision would be recorded**. The connection is made by the
coding tool, and Claude Code, Codex and Cursor expose no per-server certificate trust
setting; they trust whatever their TLS library trusts. Claude Code's usual escape hatch
is also gone — since it became a Bun-compiled binary, its networking ignores
`NODE_EXTRA_CA_CERTS` — and there are open reports of exactly this
([claude-code#2899](https://github.com/anthropics/claude-code/issues/2899),
[claude-code#55760](https://github.com/anthropics/claude-code/issues/55760)). Installing
a private certificate authority into every client machine's trust store is the remaining
option, and it is both the intrusive change ADR-0006 ruled out and a poor trade: a
mishandled private root is worse than the problem it solves.

*Amended 2026-10-17 by ADR-0021:* tested with Claude Code 2.1.299 on macOS, its MCP connections
honour `NODE_EXTRA_CA_CERTS`, and Codex honours `CODEX_CA_CERTIFICATE` (procedure 030). Each is a
setting of that client alone, not the machine's trust store. What remains true is that a
certificate trusted directly vouches for any name, and ADR-0021 answers that with a root above an
issuer limited to nervus's names.

We cannot add a trust prompt to somebody else's client. We can stop needing one.

## Decision

**1. nervus ships a connector: a small first-party program that runs on the client
machine.** It listens on `127.0.0.1`, speaks plain HTTP to the coding tools, and carries
that traffic onward to nervus over TLS.

**2. The connector — not the coding tool — holds the trust decision.** It pins nervus's
public key, not its certificate (amended 2026-10-02, ADR-0010 decision 2). On first
pairing it shows that key's fingerprint; nervus prints the same fingerprint on its console
and through a command run on its own machine, and those are what the user compares it
with (ADR-0010 decision 6). nervus's interface shows it too, but reached over the network
it is a convenience, not an independent check. The user compares them and
accepts. That is the "I trust this machine" moment, recorded in nervus's own software
where we can put it, and it is SSH's trust-on-first-use model, with the same strengths
and the same limits.

**3. Clients therefore only ever address `localhost`**, which every client accepts and
which the MCP specification and the SDK already allow without HTTPS. No certificate
enters any client's trust store, no domain is required, and no third-party service is in
the default path. **The LAN hop stays encrypted**, because the connector's own link to
nervus is TLS with a pinned certificate — this is not "turn off security at home".

**4. The connector carries the whole surface, not just the tool endpoint.** Sign-in
(ADR-0006) needs the approval page, the authorization and token endpoints and the
protected-resource metadata to be reachable at the same origin the client uses.
The connector proxies all of them on its local port, so the authorization server the
client sees is a loopback one — the case the SDK permits (`mcp/server/auth/routes.py`)
and the case ADR-0006 decision 6 already accepts as a knowing departure from the
specification's HTTPS requirement.

**5. Four levels of trust, and a user picks the one that fits.**

| setup | trust comes from | what the user does |
|---|---|---|
| nervus on the same machine | nothing to establish | nothing |
| **nervus on another machine at home** | **the user, comparing a fingerprint once** | install the connector, pair it |
| a domain the user owns, or an overlay that issues certificates | a public certificate authority | as ADR-0006 describes; still fully supported |
| an organisation | **its own certificate authority, and its own identity service** | point nervus at both |

**6. The organisational case is configuration, not new machinery.** A company that cares
already runs a certificate authority its machines trust, so nervus takes a certificate
from it and the connector is unnecessary. For identity, the MCP specification allows the
authorization server to be a separate entity from the MCP server: nervus's
protected-resource metadata can point at an existing identity provider instead of
nervus's own sign-in. That path is designed for here and built later; what this ADR
commits to is not foreclosing it.

**7. The connector is optional, always.** Anyone with a certificate — from their domain,
their overlay network, or their employer — points their client straight at nervus over
HTTPS and never installs it. It exists so that the recommended deployment does not
require buying a domain.

**8. It is built after v1, not in it.** v1 already carries a web UI, first-run setup, an
enrollment flow, an authorization server and a forced-command mechanism, against a test
suite that currently cannot run (ADR-0005 consequence 3, `CURRENT_STATE.md`). The
connector is the piece most likely to grow tails, because it is client-side software on
three operating systems rather than one container.

**v1 therefore ships the three paths that need no new code**, and says plainly which one
a user is choosing:

1. nervus on the same machine — `localhost`, nothing to configure.
2. nervus elsewhere, with a certificate from a domain the user controls.
3. nervus elsewhere, reached over an overlay network that issues its own certificates.

*Amended 2026-10-17 by ADR-0021 0 and A1:* v1 ships a fourth path, and it is the normal one:
nervus elsewhere, with nervus's own root trusted by each client in its own setting. It needs no
domain and no account. The connector stays after v1, as the way to remove even that step.

**Until the connector exists, the tier ADR-0007 recommends costs either a domain or
somebody else's account.** That is the gap this ADR was written to close, and v1
documentation must state it rather than let a user discover it after enrolling their
first host.

**9. nervus's key and certificate are made once, at setup, by a deliberate act**
(amended 2026-10-02, ADR-0010 decision 4; it said "nervus generates its own certificate
on first run"), alongside the keypair ADR-0005 consequence 6 already has it generate, and
stored in the same volume. Starting nervus never makes them. Its fingerprint is printed on
the console and by a command run on nervus's machine, because that is what a user
compares during pairing; the UI shows it as a convenience. Replacing that key invalidates
every pairing and requires each connector to be paired again; re-issuing the certificate
for the same key does not (ADR-0010 decisions 2 and 3). That is the correct behaviour,
and must be stated where someone might otherwise make a new key casually.

This is what makes path B in the table above self-contained: a user who owns no domain
and joins no overlay still gets an encrypted link, because both ends of it are ours.

## Alternatives considered

- **Install a private certificate authority on each client machine.** The intrusive
  change ADR-0006 ruled out, brittle in practice against Claude Code's current binary,
  and it makes every client machine trust a root that a compromise of nervus would hand
  to an attacker. *Amended 2026-10-17 by ADR-0021 A1 and F1: adopted, narrowed.* The root goes
  in each client's own setting, not the machine's store; Claude Code's binary honours it
  (procedure 030); and the root's key is never kept, so a compromise of nervus hands over only an
  issuer limited to nervus's names.
- **Require a domain and DNS API token.** Open to an operator who has a domain, and no
  answer at all for a user without one.
- **Require an overlay service such as Tailscale.** It genuinely solves certificates
  with no domain, and it stays documented as an option. Rejected as *the* answer because
  it puts a third party and an account in the default path of a self-hosted tool.
- **Allow plain HTTP across the LAN.** Rejected: ADR-0007 decision 3 assumes the network
  is hostile, and the SDK refuses a non-loopback plain-HTTP authorization server anyway.
- **Build certificate acquisition into nervus** (ACME plus a DNS provider's API). Still
  requires a domain, and carries the upkeep ADR-0006 declined for v1. Orthogonal to this
  ADR, and still possible later.
- **Ask clients for a trust setting.** Not ours to add, and waiting on three vendors is
  not a plan.

## Consequences

1. **A new component, on the client machine.** nervus's argument is that nothing runs on
   the *managed* machines; the connector runs on the machine doing the managing, which
   does not contradict ADR-0005 but is easy to misread. The README must be precise
   about that distinction, because it is the project's central claim.
2. **It must be small, boring, and installable without administrator rights**, as a
   background service on macOS, Linux and Windows. If it needs elevation, it has failed
   its purpose, since its whole job is to make the easy path easy.
3. **nervus's identity becomes per-connector, and that needs care.** Tokens are bound to
   the address the client used (ADR-0006, and the specification's audience rules), which
   with a connector is a loopback URL that differs per machine and port. nervus must
   therefore learn each connector's local address at pairing and accept it only for that
   paired connector, rather than trusting whatever address a request claims. Deriving
   identity from a request header instead would let anything on the network mint a
   plausible audience.
4. **Pairing creates a second credential on the client machine** — the pinned certificate
   and whatever proves the connector is the paired one. It sits under the same exposure
   ADR-0007 decision 2 already names for tier 3, and it must be no more powerful than a
   client grant: the connector carries traffic, it does not authorise anything.
5. **Trust-on-first-use is only as good as the comparison.** A user who accepts without
   checking is protected against later interception but not against a first connection to
   the wrong machine. The interface should make the comparison easy and refuse to hide
   it; it cannot make anyone do it.
6. **One more thing to maintain and ship**, on three operating systems, in a project
   whose appeal is that it is a few hundred lines.
7. **v1's documentation carries an unresolved rough edge, and the first installation is
   its first case.** Its operator chose on 2026-09-18 to wait for the connector rather than
   obtain a publicly trusted certificate they would later stop needing, which means their
   own clients stay on static tokens until it ships — ADR-0006's exposure, extended
   knowingly. Between publication and this connector, the recommended deployment is the
   expensive one. The README must present
   the three v1 paths honestly, including "run it on this machine" as a legitimate
   starting point rather than a consolation — which ADR-0007's tier table already makes
   defensible, since that tier is supported and labelled rather than discouraged.

## Verification

Moves to Accepted when observed, for each of Claude Code, Codex and Cursor, with nervus
on a different machine from the clients and holding only a self-signed certificate:

1. The client, pointed at the connector's `localhost` address, lists tools and runs a
   command on an enrolled host.
2. The full sign-in flow completes through the connector: the approval page opens, the
   grant is issued, and the audit log records the call under that grant.
3. The pairing shows a fingerprint that matches what nervus prints on its console and
   through its local command, and a connector paired against a different key refuses to
   connect rather than warning and continuing. (Amended 2026-10-02, ADR-0010 decisions 2
   and 6; it compared against nervus's interface, and a different certificate.)
4. Traffic between the connector and nervus is TLS, confirmed by capture on the wire,
   not by configuration.
5. The connector installs and runs as a background service on macOS, Linux and Windows
   without administrator rights, and survives a reboot.
6. A client configured straight at nervus over HTTPS, with no connector, still works —
   confirming decision 7.
7. A token issued for one connector's address is refused when presented through another,
   confirming consequence 3.
