# ADR-0003: an operator kill switch — per-client or global, with optional termination of running work

**Status:** **Accepted 2026-10-06, at the operator's word.** All eight verification items
were observed on the first installation on 2026-10-05 (procedure 018): item 7 on a deploy, which counts by
the operator's decision, and item 8 by the method the operator decided. Response timing is
not part of item 8. A switched-off client was refused about 0.45 ms more slowly than a wrong
token (measured locally), and decision D, added 2026-10-05, closes that. It was deployed on
2026-10-06, and item 9 was observed on the first installation (procedure 019).
**Date:** 2026-09-11
**Rewritten:** 2026-10-16, under ADR-0019 F, to name no installation. No decision changed.
**Extends:** ADR-0001 s3 (revocation) and s6 (clients and tokens)
**Requested by:** the operator, 2026-09-11, after ADR-0001's revocation story was
found not to cover the case they actually need.
**Sequencing:** *Superseded 2026-10-05:* the operator started ADR-0011's piece 1 ("yes, start
piece 1"), which built the switches file and `nervus-ctl` ahead of the UI, and deployed them
the same day (procedure 018). The UI will drive the same file (ADR-0011 decision 2). The
earlier sequencing, kept for the record: still **unbuilt** as of 2026-09-18. ADR-0005 consequence 4 placed it in
the Phase 2 web UI rather than ahead of it — a per-client off switch is exactly what a
client-management screen exists to offer, and building it twice would be waste. **The
operator confirmed that sequencing on 2026-09-18**, so this ADR is not built on its own:
it is built as part of the UI, and ADR-0006 decision 8 gives it its mechanism —
suspending a grant refuses its tokens without deleting it, which is the reversible off
switch this ADR asks for, and revoking one forces re-approval.

## Context

ADR-0001 offers two levers for taking access away, and neither fits.

Section 3 defines revocation as removal from `authorized_keys`. That is fleet-wide
for the host it is done on, needs root on each host (so the operator's password,
since the operator's own account had no passwordless sudo on the first installation's
hosts — observed 2026-09-11, procedure 003), is not quickly
reversible, and cannot distinguish one misbehaving client from another. Every
consuming project shares the one `agent` account by design (s4), so pulling the key
stops all of them.

Section 6 defines tokens as a flat mapping with no notion of being switched off.
Turning one client off today means editing the live secrets file and restarting the
service, which drops every other client's session as collateral.

Neither answers the operator's actual question: *turn this one app off now, and put
it back later.* Both are also blind to work already in flight. ADR-0001 s9 makes
`exec_bg` jobs deliberately outlive nervus restarts and client disconnects, so
removing access does not stop what is already running — the jobs continue as
processes owned by `agent` on the target host, unreachable through nervus.

**The operator's requirement, as stated:** choose the scope in the moment (one
client or all); choose the depth in the moment (block new access, or also stop what
is already running); do it fast from the operator's own network; and have access changes
be reversible without regenerating any secret.

Two properties of the existing code make this cheap rather than invasive, both
read off the source on 2026-09-11:

1. `BearerAuthMiddleware.__call__` already wraps **every** inbound JSON-RPC request
   — `initialize` and `tools/list` included — so a single check there covers the
   entire surface. A switched-off client cannot even open a session or discover
   which tools exist.
2. A job's id **is** its audit run id (`jobs.start_job(..., job_id=run_id)`), and
   its tmux session is named `nervus-<run_id>`. Every detached job on a target host
   is therefore already attributable to a token, via the audit log, **with no change
   to the job model**.

## Decision

**1. Two independent dimensions, both chosen at the moment of use.**

|                 | Block new access | ...and stop work already running |
|-----------------|------------------|----------------------------------|
| **One client**  | disable that token id | + kill that token's jobs |
| **All clients** | global lockdown  | + kill every nervus job |

Depth is never implied by scope. Blocking access never terminates anything on its
own; terminating work is always a second, explicit choice.

**2. Access is governed by a non-secret switches file, re-read on every request.**

*Amended 2026-10-12 by ADR-0014 decision A:* the file moves to nervus's state directory,
`/var/lib/nervus/switches.yaml`, so the UI can change it while the secrets stay read-only to
nervus. It stays a file of its own, with the same content and rules.

```yaml
# switches.yaml -- contains no secrets. No restart. Takes effect immediately.
lockdown: false
disabled:
  - codex-laptop
```

Checked in `BearerAuthMiddleware`, so it applies mid-session: an already-connected
client is refused on its next call, not merely prevented from reconnecting.

This file is deliberately **not** part of `tokens.yaml`. The file an operator edits
under pressure should not be the file holding live credentials, where a fat-fingered
edit costs more than the operation was worth.

**3. Access changes are reversible; terminating work is not.** Re-enabling is
deleting a line. No secret is regenerated, nothing is redistributed to consumers,
and the token in the operator's password manager never changes. Killing a job, by contrast, destroys work
in progress and cannot be undone. The interface must make that asymmetry obvious
rather than treating the two as symmetrical options.

**4. Attribution comes from the audit log, not from the host.** To act on one
client's work: collect `run_id`s from the audit log where `token_id` matches, then
kill `nervus-<run_id>` on the relevant host. To act on all work: kill every tmux
session matching `nervus-*`. The `agent` account is shared (ADR-0001 s4), so the
host itself cannot distinguish clients; the audit log is the only thing that can.
This is a second load-bearing use of the audit log, reinforcing s10's "mandatory,
not a feature".

**5. The operator interface is a local CLI on the nervus machine.** A
command that reports before it acts, so the decision can be made against facts:

```
nervus-ctl status            # per token: enabled/disabled, and jobs running where
nervus-ctl lock <token-id>   # access only
nervus-ctl lock <token-id> --kill-work
nervus-ctl lock --all [--kill-work]
nervus-ctl unlock <token-id> | --all
```

It runs on nervus, uses nervus's own key to reach the target hosts, and bypasses
token authentication entirely — it is the operator acting locally, authorised by
holding root on the container, not a client acting through the tool surface. No
kill capability is ever exposed as an MCP tool: that would let one client terminate
another's work, which is a privilege escalation inside the very surface this
controls.

**6. Operator actions are themselves audited**, with an actor of `operator` in place
of a token id. A kill switch whose use leaves no trace would be a strange thing to
build into a system whose ADR calls the audit log mandatory.

**7. Terminating work stops jobs, not necessarily every descendant.**
`tmux kill-session` kills the session and its pane process group. A process that has
deliberately daemonised away from that group survives. Since `agent` is
root-equivalent, `sudo pkill -u agent` on the host remains the blunt instrument, and
the CLI should say so rather than implying a completeness it cannot deliver.

## Questions settled by the operator, 2026-09-11

Three sub-decisions were posed unresolved and are now answered. They are recorded
here because a decision not in an ADR is not a decision (rule 6).

**A. An unreadable switches file blocks everything. Fail-closed in both cases.**
A missing file blocks; a malformed file blocks. The operator chose this over the
recommended split (missing = allow, malformed = block), on the reasoning that a lock
once set must never be undone by a file going missing.

The consequence is that **deployment must create the switches file**, alongside
`tokens.yaml` and `known_hosts`, or the feature would refuse every client from the
moment it ships. With the file always present by construction, "missing" comes to
mean something is genuinely wrong — which is precisely the circumstance in which
refusing is correct. Recovery from either state is cheap and needs no restart: the
operator holds root on the nervus machine, and the file is re-read per request, so writing a valid
file restores service immediately.

**B. Lockdown refuses everything, and says nothing about why.** A locked-out client
receives the same generic `unauthorized` error an invalid token receives, for every
request including `initialize`, `tools/list` and `hosts`. It therefore cannot
distinguish a deliberate lock from a revoked token, a typo, or never having been
valid, and learns nothing about operator action. "Off" has exactly one meaning. The
real reason remains visible where it belongs: to the operator, in the audit log and
via `nervus-ctl status`.

**C. Both ADR-0001 s10 audit defects are fixed in the same body of work.**
*Done ahead of this ADR, on 2026-09-11 in commit `a2508ba`, at the operator's
request — the switches can now be built on an audit layer that already records
refusals.* Refusals
become audited — including refusals caused by these switches — and the `hosts` tool
gains the record it currently omits. The switch therefore never exists in a state
where it works but its use is invisible, and a locked-out client's continued
attempts are visible rather than silent. This also settles the defects recorded in
procedure 002 rather than leaving them open.

## Settled by the operator, 2026-10-05: refusal timing

**D. Every refusal takes at least 50 ms, so how long it takes says nothing either.**
Decision B makes a switched-off client's refusal match an invalid token's in content. On
2026-10-05 its timing was measured, and it did not match (procedure 018, Found):
- nervus reads the switches file and appends an audit line before refusing a known token,
  and refuses an unknown token before doing either;
- measured locally, the switched-off refusal was about 0.45 ms slower, and slower in 263 and
  265 of 300 pairs in two runs.
- the first figure recorded was 0.26 ms, from requests sent in a fixed order. Sent in random
  order within each pair, the gap was about 0.45 ms.

One request cannot show that difference, but many could. So the token check now answers no
refusal sooner than 50 ms after it began, whatever the reason:
- an invalid or missing token;
- a switched-off client;
- an unreadable switches file.

Served requests are not delayed. 50 ms is far longer than the extra work, which is one small
file read and one appended line, not synced. A refused client loses nothing it could use.
The session recommended this and the operator agreed: "yes lets close the timing gap after
item 8".

## Alternatives considered

- **An `enabled:` field inside `tokens.yaml`.** Rejected: it makes routine
  operations edit the live secrets file, and it inherits that file's 0600
  permission model and startup-only load.
- **Deleting the token and pasting it back from the password manager.** Works today with no
  code, and is the fallback if this ADR is never implemented. Rejected as the
  answer: it needs a restart, which drops every other client, and it makes the
  operator handle secret material to perform a routine on/off.
- **Exposing lock/kill as MCP tools.** Rejected: any client could then disable or
  terminate any other client. The control plane must not live inside the surface
  being controlled.
- **An HTTP control endpoint on nervus.** Rejected for Phase A: it needs its own
  credential and widens the attack surface of the one host holding the fleet key,
  to save one hop to the nervus machine. Revisit if the CLI proves too slow in practice.
- **Giving nervus an sshd and an operator account** so the CLI is one hop instead
  of two. Rejected for now on the same grounds: the first installation's container
  deliberately has no sshd, no password and no accounts (procedure 001), and reaching
  it from the machine that hosts it adds no new credential.
- **Killing work by restarting nervus.** It does drop nervus's in-flight SSH
  connections, but it cannot be scoped to one client and it does nothing to
  detached jobs, which are the long-running work that actually matters.

## Consequences

- The operator gains a fast, reversible, per-client off switch that needs no host
  root and no password — only root on the nervus machine, which they already hold. This is a
  materially lower bar than ADR-0001 s3's revocation, and that is the point.
- Two levers now exist with different properties: this one is fast, reversible and
  nervus-level; `authorized_keys` removal is slower, host-level, and revokes the
  credential itself. This ADR does not replace s3. If the concern is that the key
  itself is compromised, the switches file is the wrong tool — nervus holds the key
  and a switch inside nervus assumes nervus is still trustworthy.
- A switched-off client sees an authentication failure, not a distinct "you have
  been disabled" status. Distinguishing them would tell an untrusted caller about
  the operator's actions. The audit log is where the distinction lives.
- In-flight `exec` calls are not individually terminable, only bounded by their
  timeout. Only `exec_bg` jobs are addressable, because only they have an id.
- The audit log becomes load-bearing for a second purpose: without it, one client's
  jobs cannot be distinguished from another's on a shared `agent` account.

## Acceptance verification

Observed on the machines, not inferred:

1. With a token disabled in the switches file, that token is refused — **without
   restarting nervus** — and the other token continues to work in the same period.
2. Removing the line restores access, again without a restart, using the same
   unchanged token value.
3. With `lockdown` set, every token is refused; clearing it restores all of them.
4. A job started by one token is terminated by name while a job started by the
   other token, on the same host, keeps running. This is the test that proves
   attribution works.
5. Every lock, unlock and kill appears in the audit log attributed to `operator`.
6. A malformed switches file refuses all access, and so does a missing one
   (decision A) — both observed by removing and by corrupting the file, not assumed.
7. Deployment creates the switches file, so a freshly built nervus serves traffic
   rather than refusing it. This is the failure decision A would otherwise cause,
   and it is verified on a rebuild rather than reasoned about.
   *Operator, 2026-10-05: a deploy onto an existing machine whose switches file is
   missing satisfies this item. Observed that way in procedure 018.*
8. A locked-out client's error is indistinguishable from an invalid token's
   (decision B), checked by comparing the two responses byte for byte.
   *Operator, 2026-10-05: nervus puts a fresh random `mcp-session-id` on every response
   to a connection request, so no two such responses are ever identical byte for byte,
   whoever sends them. For a connection request the check therefore compares every byte
   except that value, shows that both values have the same form, and shows with a
   control pair of two invalid tokens that they differ in exactly that place. Inside an
   open session, where the session's own id is sent back, the comparison is literal.
   Measured in procedure 018. Response timing is not part of this item.*
9. *Added 2026-10-06, after acceptance on items 1 to 8, for decision D:* on the machine,
   a switched-off client's refusals and an invalid token's take the same time, within
   measurement noise, and neither takes less than 50 ms.
