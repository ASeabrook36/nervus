# ADR-0001: nervus — an MCP bastion giving any agent programmatic access to the operator's machines

**Status:** **Accepted 2026-09-11** — all six acceptance criteria observed on the machines, not inferred. Evidence in procedure 004.
**Amended 2026-10-28** by ADR-0025, Accepted by the operator the same day: s4, a host's `authorized_keys` trusts nervus's SSH certificate authority, not nervus's key; s5, attribution in a host's journal comes from the certificate nervus signs for each call, not from the separate `agent` user.
**Date:** 2026-09-10
**Rewritten:** 2026-10-16, under ADR-0019 F, to name no installation: every decision keeps its number and its meaning. The operator's original text, written for their own fleet, is kept whole in the deployment record (deployment note 0001). Where a section below speaks of the first installation, that note has the specifics.
**Implements:** the operator's standing agreement about what agents may control (Context)
**Consumers:** any project whose agents build, test, or operate on the operator's machines
**Read alongside:** ADR-0005, which extends this ADR to a public release, explains why s5's rejection of MCP-layer filtering is the reason access tiers are enforced by the target host instead, and carries the point that s2's "only path from any agent" is policy rather than structure: SSH that does not go through nervus leaves no record in its audit log.
**Prior art:** `research/2026-10-15-prior-art.md` ideas 5 and 6 bear on s9's tool surface (fronting other MCP servers; one command across many hosts). A note, not a decision.

## Context

nervus sits under an agreement, made before it and outside it, about what an agent may control on the operator's machines: compute through the hypervisor's API, Linux hosts over SSH, and other services through their own APIs. The network is observed, never configured: its configuration stays with a person. nervus implements that agreement; it neither restates nor alters it.

Before nervus, the SSH half was exercised ad hoc from the operator's laptop: Claude Code and Codex reached the hosts through a password manager's SSH agent, behind a biometric prompt. It produced real results (benchmarking, build and wiring work) but had structural limits: bound to one machine and one login session; dies when the laptop sleeps; leaves no record of what the agent ran; unavailable to any client not running on that laptop; and every session is implicitly approved by one prompt, so there is no way to grant standing access without giving up that step.

More than one project will drive agents against the same machines. The need is a single service that any MCP client, from any project, can attach to; that implements the agreement; and that records everything it does, attributed to the project and client that did it.

## Decision

**1. nervus is its own project.** Own repository, own ADRs (this directory), own host inventory. Consuming projects reference it; they do not embed it. The machine nervus runs on is a host in the operator's inventory like any other; this project owns the service.

**2. Topology — a bastion host.** `nervus` is the only holder of the agent SSH credential and the only path from any agent to the machines. Agents talk to `nervus` over MCP; `nervus` talks to hosts over SSH. No agent ever holds an SSH key.
- A small, dedicated, unprivileged container or machine of its own, separate from every host it reaches. The first installation's is in deployment note 0001.
- One MCP server over Streamable HTTP, run as a systemd service. Server, inventory, and unit file live in this repository; the machine is disposable and rebuildable from this repository plus the operator's password manager.

**3. Credential.** One ed25519 keypair, generated in the operator's password manager (source of truth), deployed to `nervus` as a 0600 file consumed by path. Never resolved from the password manager at runtime. It lives on a single operator-controlled host, so it carries no scheduled rotation; revocation is removal from `authorized_keys`.

**4. Host side.** On each in-scope Linux host, one `agent` user: supplementary groups mirror the operator's user on that host; passwordless sudo — root-equivalent, and named as such; `authorized_keys` contains exactly one key, `nervus`'s. The `agent` user is shared by all consuming projects; attribution by project comes from the audit log, not from the host account. Host keys are pinned in `nervus`'s `known_hosts` with strict checking enabled.

*Amended 2026-10-28 by ADR-0025:* `authorized_keys` holds one line, `cert-authority` and nervus's CA public key, with the level's options; nervus presents a certificate it signs for each call, valid for minutes, naming the client's token and the run. The host then admits only certificates nervus signs, never its key alone. A host given nervus's key before keeps working until moved (ADR-0025 consequence 4). The `agent` user is still shared, and the audit log is still the record; the certificate is how the host's own journal names the client too.

**5. Where the boundary lives.** Permission boundaries are SSH boundaries: which user the key is authorized as, that user's sudoers, and which hosts accept the key. The MCP layer performs no command filtering. Containment comes from bastion isolation, from the agreement (no network-write capability exists in the tool surface), and from egress rules on the network the hosts sit on, which are the network's to set, not nervus's. The separate `agent` user provides attribution in host journals and one-move revocation, not containment.

*Amended 2026-10-28 by ADR-0025:* the separate `agent` user tells nervus's logins apart from everyone else's in a host's journal, but not one client from another; the certificate does that, its key ID logged by the host's `sshd` at each login. A witness, not a protected one: a client with full access to a host can edit its journal afterwards (ADR-0007 decision 8, as amended). Revocation is still one move: removing the `cert-authority` line.

**6. Clients and tokens.** One static bearer token per (client, project) pair — e.g. Claude Code in project A, Codex in project A — generated and stored in the operator's password manager, deployed to `nervus` as a 0600 token file. Each token carries a host allowlist. This is the one authorization check the MCP layer performs: coarse, before SSH, "may this token reach this host at all." It is not command filtering. v1 tokens list every v1 host.

**7. Consumer integration.** A consuming project wires itself in by committing its own client configuration pointing at `nervus`: a project-scoped `.mcp.json` for Claude Code and a project-scoped `.codex/config.toml` for Codex, both referencing the token by environment variable rather than by value. The mechanism is validated on a real client before load-bearing use.

**8. Reach — Phase A.** Only a private network the operator controls: the LAN, and a VPN into it that ends inside the same trust boundary. Nothing public. Plain HTTP is accepted on this boundary for Phase A; TLS follows and is not a blocker (it came with ADR-0010). Public exposure for cloud-hosted clients (claude.ai, Cowork) is a separate future ADR (Phase B), not an amendment, and is not taken before Phase A has real audit history.

**9. Tool surface, v1.**
- `hosts` — inventory: name, address, role, what the calling token may reach.
- `exec` — run a command on a host; returns exit code plus bounded stdout/stderr with an explicit truncation marker and total byte count. Full output is always written to disk on the target host and retrievable.
- `exec_bg` — start a detached tmux session on the target host with output tee'd to a per-job log on that host; returns a job id. Jobs survive `nervus` restarts, client disconnects, and laptop sleep, and remain attachable by hand.
- `job` — status, logs (tail or range), kill, by job id.
- `put` / `get` — file transfer over SFTP.

Deferred: `proxmox_*` (the hypervisor's REST API with a scoped API token — the agent never has SSH to the hypervisor host), the APIs of other services the agreement covers, and `observe` (a log store). Absent by construction: any capability to write the network's configuration.

**10. Audit.** Every tool call appends one JSON record to an append-only JSONL file on `nervus`: timestamp, token id (resolving to client and project), host, user, working directory, command, exit code, duration, output bytes, log path. Forwarded to a log store once one exists.

**11. Onboarding procedures** (documented in this repo, executed one step at a time).
- A host: create `agent`, install the public key, pin the host key, add the inventory entry, run the negative auth test.
- A consumer: mint a token in the password manager, add it to the token file with its host allowlist, commit the client config in the consuming repo, confirm the first `exec` lands in the audit log under the new token id.

**12. Scope, v1.** The first installation's Linux hosts and its first consumer, named in deployment note 0001; other hosts and consumers join by s11's procedures. The hypervisor host is reached through its API only. A machine with no operating system yet is out of scope.

**13. Implementation.** Python, official MCP SDK, asyncssh. Built by Claude Code from a handoff prompt, one step at a time, state read off the machine before each step.

## Alternatives considered

- **Embed nervus in one of the projects that uses it.** Rejected: multiple consumers. A service owned by one consumer becomes that consumer's problem and every other consumer's dependency on it.
- **Status quo (ad hoc SSH from the laptop).** Rejected: laptop-bound, unaudited, unavailable to any client not running on that laptop.
- **Run the MCP server on one of the hosts it controls.** Rejected: the machine being controlled would hold the key, so compromise of one workload host becomes compromise of all.
- **Adopt a community SSH MCP server.** Rejected: the exec wrapper is commodity; the value is in the topology, job model, enforcement of the agreement, and audit, which none of them encode. The custom server is a few hundred lines.
- **Command allow/deny filtering in the MCP layer.** Rejected: trivially bypassed (`bash -c`, encoded payloads) and it fights the actual use case of installing, reconfiguring, building, and testing.
- **Depend on the MCP Tasks extension for long-running work.** Rejected as a dependency: support is per-client. The tmux job model works with any client; Tasks can be layered on later as a view of the same job table.
- **Resolve the SSH key from the password manager at runtime.** Rejected: puts the password manager in the unattended restart path.
- **Public exposure now.** Rejected: cloud-hosted clients require a publicly reachable endpoint and OAuth; that is a separate decision with its own attack surface.

## Consequences

- A standing credential replaces per-session biometric approval. The audit log is therefore mandatory, not a feature.
- `agent` is root-equivalent on every host it is onboarded to. Files it writes into paths that containers bind-mount under a fixed uid need `sudo chown` or a shared group.
- The agent reads untrusted internet content (documentation, repositories, model cards, package registries) and acts on it with root. The hosts nervus reaches should be under egress rules.
- Codex's default per-tool timeout is 60 seconds; work longer than that must use `exec_bg`, or `tool_timeout_sec` is raised deliberately.
- **Concurrency is unmanaged in v1.** Agents from two projects can act on the same host at once; nothing prevents two package installs colliding. The audit log makes collisions diagnosable. A per-host lease tool is the v2 answer if this bites.
- One more host to maintain, kept trivial by being disposable.

## Acceptance verification

Proposed becomes Accepted only when all of the following are observed on the machines, not inferred from documentation:

1. `nervus` survives a controlled reboot with the MCP service up and answering `hosts`.
2. An `exec` from Claude Code and an `exec` from Codex each appear in the audit log with the correct token id.
3. A job started with `exec_bg` survives a restart of the `nervus` service and remains attachable via tmux on the target host.
4. An `exec` whose output exceeds the bound returns the truncation marker, and the full output is present on disk.
5. The `agent` user cannot authenticate with any key other than `nervus`'s (negative test).
6. A token whose allowlist excludes a host is refused for that host (negative test).
