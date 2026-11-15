# ADR-0020: uploads — a client sends a file from its own machine into a host or a VM

**Status:** **Accepted 2026-10-18, at the operator's word** ("Mark ADR-0020 accepted"), every
verification item observed in tests or on the fleet (procedure 031), as marked at each.
**Decided by the operator on 2026-10-15**, in a Claude Code session:
questions 0 and A to I, each as the session recommended in the draft ("all as recommended"). Each
question keeps its options, so the record shows what was not chosen. **Built 2026-10-17 and deployed
2026-10-18 (procedure 031); every verification item observed, in tests or on the fleet, as marked
at each.**
**Date:** 2026-10-15
**Rewritten:** 2026-10-17, under ADR-0019 F: procedures cited by number. It already named no installation.
**Decided by:** the operator, 2026-10-15
**Builds on:** ADR-0016 (exports: the store, its ceilings, ownership, request keys, the HTTP
route, the client's own SHA-256 check; its decision J sketched this ADR); ADR-0017 (templates;
J1, VMs enrolled into the SSH inventory later; L2, one small internal interface for nervus's own
work inside a guest); ADR-0001 s5 (the target's permissions are the boundary); ADR-0009
decision 2 (Proxmox's permissions decide for VMs)
**Written to the policy of ADR-0019** (decided 2026-10-15): this record
names no machine; the evidence is in the procedures it cites.
**Asked for by:** the operator, 2026-10-15, item 2 of "Next, in order" in `CURRENT_STATE.md`.

## Context

### What a client can do today

- **`put`** copies a file from nervus's own transfer directory to a host over SFTP. Nothing a
  client does puts a file in that directory except `get`, so `put` only relays what nervus
  fetched. It writes straight to the final path: a transfer cut off part-way leaves a partial file
  where the real one was (prior-art note, idea 3).
- **So agents upload through `exec`**, with the file inside the command as a heredoc, or through
  the guest agent's `exec` and `file-write`. Every byte passes through the model, as output it
  writes, and is then written into the audit log. At ADR-0013's reading such commands were 73% of
  the log.
- **Nothing reaches a VM in bulk.** `file-write` replaces the file on each call and carries at most
  60 KiB of content; `exec` carries at most 64 KiB of `input-data` (Proxmox's own code,
  `CURRENT_STATE.md`).

### What exports already built, for reuse

ADR-0016's store: a table of staged files owned by the token that made them, a request key that
makes a retry return the same item, reservations under a lock against a per-file ceiling
(256 MiB), a total (1 GiB) and a floor of free space (2 GiB), files nervus names itself in its
own state directory, an HTTP route on the MCP port checked exactly as an MCP call is, and audit
records for every step. Downloads have run for real since 2026-10-15 (procedure 023).

### Measured: writing into a VM (procedure 026)

On a fresh clone of the template, made and destroyed through the scoped API alone, with random
data and the whole file's SHA-256 checked in the guest:

| route | per call | what nervus alone would reach |
|---|---|---|
| guest agent `file-write`, 45 KiB a call, then join the parts | 0.55 s a call, **whatever its size** | 0.084 MB/s |
| guest agent `exec`, 47 KiB a call appended by `base64 -d` | 0.165 s, plus 0.12 s a status poll | 0.13 MB/s; **0.17** with one poll a chunk |
| the VM pulling over HTTP with `curl`, from a web server on the same network | one call for the whole file | **36 MB/s** |

The guest agent's cost is per call, not per byte, and its caps are small, so a 32 MiB upload
pushed through it takes about 3¼ minutes, and a 256 MiB one about 26. Reads through it run five to
eight times faster (procedure 024, ADR-0016 step 0). A host over SFTP takes 24.5 MB/s
(procedure 024). A VM made from the template has `curl`, and a network card on the same network
as nervus's own (procedure 026; ADR-0017 F1). The 36 MB/s was measured from another web server,
not from nervus; nervus's own speed serving a file is not measured.

### What the client's side looks like

The same as downloads: the client's own shell runs `curl` with its token from standard input
(procedure 005 step 5). A sandboxed Codex needs approval for each such command (ADR-0016
consequence 2). The model sees the command and the answer, never the bytes.

### The operator's aim

Efficiency in tokens, complexity and speed (ADR-0017 Context). For uploads that means: the file
never passes through the model; as few calls as possible; and VMs not stuck at guest-agent speed.

## Questions

### 0. Order

ADR-0019 decided (0, as recommended) that its own work goes first, before uploads. ADR-0017 J1 left the
enrollment ADR "before or beside uploads, at the operator's choice".

1. **Decide this ADR now; build it after ADR-0019's code change, and before enrollment.** The
   decisions do not depend on ADR-0019, and building after it means writing the new code without
   machine names from the start. With E1 below, VMs get fast uploads without enrollment, so
   enrollment need not come first.
2. Enrollment first, and VM uploads only over SSH once VMs can be enrolled (E3).

*Recommended: 1.*

### A. How the file reaches nervus

1. **One HTTP request that names the destination and does everything.** The client's shell runs
   one command: it hashes the file, then `curl -T <file>` sends it as `PUT /uploads` on the MCP
   port, with the token from standard input as for downloads, and the destination, SHA-256 and a
   request key as URL parameters (`curl --url-query` encodes them). nervus checks the token and the
   destination exactly as an MCP call, receives the file, delivers it (B to E) and answers with the
   result. **One call in the model's turn**, and nothing new for the model to learn but one
   command, given in procedure 005 and in `put`'s tool description.
2. A tool declares the upload, the shell sends it, the tool reports: ADR-0016's shape in reverse.
   Three calls (the hash, the tool, `curl`), where 1 needs one.
3. Through MCP, the file as base64 in a tool call. The bytes go through the model, which is what
   this ADR is for removing.

*Recommended: 1.* What made exports two halves was that the file starts on the fleet; here it
starts beside the shell, which can do it all at once.

### B. Integrity

1. **The client declares the SHA-256; the file is in place only if three hashes agree.** nervus
   hashes as it receives and refuses a mismatch before delivering anything. It writes the file at
   the destination under a temporary name, has the destination hash it there (`sha256sum`, over
   SSH or through the guest agent), and only then renames it into place. The answer names the
   hash only when all three agreed; otherwise it says which step failed, and nothing is left at
   the destination.
2. nervus reports the hash it received, and the client compares. One more step for the client,
   and no check that the destination wrote what it was sent.

*Recommended: 1.* The same standard as ADR-0016 F1, from the other side.

### C. Writing in place

1. **A temporary name in the same directory, then a rename**, so the destination holds either the
   old file or the whole new one, never part of one (prior-art note, idea 3). **An existing file is
   refused unless the client says `replace=1`.** The directory must already exist. An optional
   `mode` (for example `0755`); otherwise the target's default.
2. The same, always replacing.
3. Straight to the final name, as `put` does today.

*Recommended: 1.* Refusing by default costs a client one parameter; replacing by accident can cost
a file.

### D. Hosts: whose rights the file is written with

nervus reaches a host as its agent account, which is root-equivalent through `sudo` but writes
over SFTP with its own rights only. Agents often send files to places only root may write, such as
configuration and programs.

1. **The agent account's rights, and `root=1` for the rest.** With `root=1`, nervus writes the file
   to a temporary file the agent account owns, then runs one fixed command on the host, built and
   quoted by nervus: `sudo -n install` to a temporary name beside the destination, with the mode,
   then the hash there, then `sudo -n mv` into place (`install` alone replaces a file
   non-atomically, so C1 needs the rename). The host's `sudo` decides, as it does for `exec`: where the
   account has no `sudo`, the upload is refused with `sudo`'s reason.
2. The agent account's rights only; a root destination then takes a second call, an `exec` with
   `sudo`. Simpler in nervus, but a common case costs two calls, and agents would go on sending
   small root-owned files inside `exec`, through the model.

*Recommended: 1.* It grants nothing `exec` does not already grant, and it is what keeps small
configuration files out of the model.

### E. VMs: how the file gets in

The guest agent pushes at 0.17 MB/s at best; a VM pulling over HTTP moved 36 MB/s (Context).

1. **The VM pulls the file from nervus, and the guest agent is the fallback.** nervus, through the
   guest agent, runs one fixed script in the VM: `curl` fetches the staged file from nervus's MCP
   port to a temporary name, the guest hashes it, and renames it into place (B1, C1). The fetch
   carries a **one-time secret** nervus makes for this upload alone: valid for one fetch and a few
   minutes, passed into the VM in the script's standard input (never a command argument), never
   shown to the model or written to the log. If the VM cannot reach nervus or has no `curl`, the
   script says so and nervus pushes the file through the guest agent's `exec` instead, in 47 KiB
   chunks, under a smaller ceiling (F1). The answer says which route was used.
2. Push through the guest agent only. Works with no network, but 256 MiB takes about 26 minutes,
   and every upload pays guest-agent speed.
3. Push through the guest agent, and a VM that needs speed is first enrolled (ADR-0017 J1) and
   then uploaded to over SFTP as a host. Fast once enrolled, but every fast VM upload waits on the
   enrollment ADR, and a 60-second test VM would have to be enrolled to get a file in quickly.

*Recommended: 1.* ADR-0016 A3 rejected a one-time link because the model would see it and it would
sit in a URL in a tool result; here only nervus and the VM ever hold it, for one fetch. Like
every token today, it crosses the network in the clear until MCP moves to HTTPS (ADR-0010). The
fallback keeps VMs with no route to nervus working, slowly. Which VM may be written to is
Proxmox's decision, as for `export` (ADR-0016 C1). This is the "write a file through the guest
channel" half of ADR-0017 L2's interface.

### F. Size and space

1. **Exports' ceilings, shared.** One file at most 256 MiB; uploads and exports together at most
   1 GiB staged; never under 2 GiB free. nervus reserves the declared size (`Content-Length`)
   before reading the body, and refuses past it. **A VM upload that falls back to the guest agent
   is limited to 32 MiB** (about 3¼ minutes); a larger one is refused with that reason, rather
   than tying up the guest agent for half an hour. The staged copy is deleted as soon as it is
   delivered or has failed; uploads are not kept for 24 hours as exports are.
2. Separate ceilings for uploads.
3. No fallback ceiling.

*Recommended: 1.* One pool of space protects the audit log once, however files move.

### G. Waiting, retrying, and what the answer says

1. **The request key makes a retry safe, and the answer waits.** The client chooses a key, as for
   `export`. nervus answers when the file is in place, or after `wait` seconds (default 30) with
   its state: `receiving`, `delivering` (with bytes so far), `delivered` (destination, size, hash,
   route, `run_id`) or `failed` (a reason code and message). `GET /uploads/<key>` with the same
   token reports the state later. The same key sent again with the same hash returns that upload
   and discards the body; with a different hash it is refused. A nervus restart during a delivery
   marks it `failed`, deletes the staged copy, and removes the temporary file at the destination
   where it can (its name says it is nervus's, so it is recognisable if it cannot).
2. No request key: every request is a new upload. A retry after a timeout could deliver twice.

*Recommended: 1.* The same rule as ADR-0016 I1.

### H. Who may upload where, and what the log records

1. **As for `export`.** A host: where the token's allowlist reaches it, as `put`. A VM: where the
   allowlist includes the Proxmox host, and then Proxmox's permissions decide. The upload is owned
   by the token that sent it; another token's `GET` gets 404. A switched-off or revoked token is
   refused. **One audit intent** (destination, declared size and hash, `root`, `replace`) **and one
   result** (bytes received, route, the destination's hash, or the reason it failed), plus nervus's
   own calls to the target under the same run id. No token or one-time secret in any record or
   answer.

*Recommended: 1.*

### I. `put`, and what this leaves out

1. **`put` stays, gains C1's temporary name and rename, and its description points to uploads.**
   Leave out, as known limits: **directories** (archive first, then one `exec` to unpack);
   **resuming a cut-off upload** (send it again: at network speed 256 MiB takes seconds);
   **clients with no shell on the network** (as ADR-0016 J); **HTTPS** (ADR-0010); **containers**,
   which have no guest agent.
2. `put` unchanged.
3. Retire `put`, `get` and the transfer directory now. Clients may still use them; a separate
   decision.

*Recommended: 1.* The rename is the same small piece of code uploads need.

## Consequences

1. nervus gains one HTTP route, `PUT` and `GET /uploads`, and no tool. A file goes from the
   client's disk to its destination without passing through the model; the model's whole cost is
   one command and its answer.
2. With E1, nervus starts a fetch from inside a VM, through the guest agent, as part of a client's
   request. That is nervus composing a command in a guest, as `export` already does to hash a
   source (ADR-0016 F1).
3. With D1, nervus composes one privileged command on a host. It grants nothing `exec` does not.
4. The one-time secret is a second kind of credential, held only by nervus and one VM for one
   fetch.
5. Uploads and exports share 1 GiB of staged space.

## Order of work

Each step is one module with its tests, and waits for the operator (rule 1).

0. ~~The operator's decisions on 0 and A to I.~~ Done 2026-10-15: all as recommended.
1. ~~The upload store: exports' table and reservations extended to uploads, the request key, states,
   sweep and restart rule.~~ Done 2026-10-17 (`fc994f5`): `src/nervus/uploads.py`, a table of its
   own beside exports', counting against the same ceilings. It also holds decision E's one-time
   secret (a hash, single use, five minutes), so step 4 needs no change to the table.
2. ~~The route: `PUT` and `GET /uploads`, token and allowlist checks, receiving with the hash, audit.~~
   Done 2026-10-17: `src/nervus/upload_route.py` and `src/nervus/uploader.py`. The route takes a
   deliverer (one coroutine: the upload in, the route and the destination's SHA-256 out), so steps
   3 and 4 each supply one. Tested with real `curl -T` and `--fail-with-body` on loopback.
3. ~~Delivery to a host: temporary name, hash, rename; `root=1`; `put` given the same rename.~~ Done
   2026-10-17 (`3eb3097`, `1f3892f`), and wired into nervus's start-up.
4. ~~Delivery to a VM: the pull script and one-time secret, the guest-agent fallback, both with the
   guest's hash.~~ Done 2026-10-17 (`1f3892f`): the VM fetches from `GET /upload-pull`.
5. ~~Client instructions in procedure 005, tested as written; `put`'s description.~~ Done 2026-10-17
   (`7f6fd53`), in `docs/clients.md`, where client instructions have lived since ADR-0019.
6. A deploy procedure, written for approval before it runs (it restarts nervus; the operator warns
   other sessions first). **Done: procedure 031, deployed 2026-10-18.**
7. ~~A demonstration from a real client: a file to a host, one to a host as root, one into a fresh
   clone by pull, one by the fallback, each with the destination's hash matching the client's.~~
   Done 2026-10-18 (procedure 031 step 4), with the documented command, each hash matching.

## Verification

Moves to Accepted when observed, in tests or on the fleet:

1. A file sent from the client arrives at a host and in a VM with the client's SHA-256, in one
   shell command, and the model never sees its bytes. **Observed** (procedure 031 step 4).
2. A wrong declared hash, a body cut short, or a destination that hashes differently leaves nothing
   at the destination and the old file untouched. **In tests** (`test_uploads.py`,
   `test_upload_targets.py`).
3. An existing file is refused without `replace=1`; with it, the old file is replaced whole. **Observed**
   (procedure 031 step 4.2).
4. `root=1` writes where only root may, and is refused with `sudo`'s reason where there is none. **Writing
   observed** (procedure 031 step 4.3); the refusal in tests, against this Mac's real `sudo`.
5. A VM that cannot reach nervus gets the file through the guest agent; over 32 MiB it is refused. **The
   first observed** (procedure 031 step 4.5); the refusal in tests.
6. The one-time secret works once, then is refused, and expires unused. **In tests**; on the fleet, one
   fetch per secret in the audit log, and a fetch without one refused (procedure 031).
7. The same request key twice gives one delivery; a restart mid-delivery leaves `failed`, with no
   staged copy. **In tests.**
8. Ceilings: a file over 256 MiB is refused before its body is read; uploads and exports together
   cannot pass 1 GiB or the 2 GiB floor. **In tests.**
9. Another token's `GET` is 404; switched-off and revoked tokens are refused; every refusal is
   logged; no token or secret in any record or answer (searched for). **In tests; on the fleet, the
   audit log searched** (procedure 031 step 4.7).
