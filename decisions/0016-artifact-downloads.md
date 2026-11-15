# ADR-0016: artifact downloads — a client saves a file from the fleet onto its own machine

**Status:** **Accepted 2026-10-15, at the operator's word** ("mark ADR-0016 accepted"), every
verification item observed in tests or on the first installation (procedure 023), as marked at each item.
**Decided by the operator on 2026-10-14**, in a Claude Code session: questions 0 and A to J, each as the
session recommended in a draft of this ADR ("all as recommended"). Each question keeps its
options, so the record shows what was not chosen.
**Date:** 2026-10-13, revised 2026-10-14 after the requesting session's reply
**Rewritten:** 2026-10-17, under ADR-0019 F, to name no installation. No decision changed; decision
D's limits are stated as nervus's defaults. The original, with the first installation's figures,
is deployment note 0016.
**Decided by:** the operator, 2026-10-14
**Builds on:** ADR-0001 s5, s6, s9 and s10 (no command filtering, the per-token allowlist, the
tool surface, the audit log); ADR-0009 decision 2 (Proxmox's permissions are the boundary
for VMs; nervus's own container is out of the scoped token's reach); ADR-0003 and ADR-0014 (a switched-off
or revoked client is refused everywhere); ADR-0011 decision 1 and ADR-0014 decision F (what
nervus writes is in SQLite; a table is added without changing the version)
**Asked for by:** a request pasted by the operator on 2026-10-13, written for a Codex
session in another of the operator's projects. That session answered the draft's questions on
2026-10-14; its answers are cited below as "the requester's reply".

## Context

**What a client can do today.** `get` copies a file from a host into nervus's transfer
directory, `/opt/nervus/transfer` on the nervus machine, and answers `{"ok": true}`. Nothing
carries the file the rest of the way, to the machine the client runs on. The only route a
client has is through command output. The requester's Codex session moved an archive of about
7 MB out of a VM through Proxmox's guest agent in 54 pieces, each passing through the model's
context as text. It took about six minutes, and most of that was round trips
through the model, not the network (the requester's reply).

**Why it matters.** The operator, 2026-10-14: the operator's projects will regularly
need to move files of many kinds, and nervus is the hands nearly all agent work, local or
from the cloud, uses to reach the fleet and its inference stack. So those hands need to
be robust. People deploying nervus themselves will want the same.

**Why an MCP-only answer does not do it.** MCP has "resources", files a server offers for
reading. Codex supports them: the installed `codex-cli 0.162.0-alpha.17.2` has
`list_mcp_resources` and `read_mcp_resource` (read from its binary, 2026-10-13). But a
resource read returns the file to the model, base64-encoded for binary files, and the model
would then have to write that text to disk itself. That is today's route with fewer steps,
not a download. Neither Codex nor Claude Code has an MCP feature that writes a server's
file to disk without passing through the model.

**What a client's own shell can do.** Both clients can run commands on the client's machine, and the
standard way to download a file is an HTTP request, for example `curl`. nervus already
answers HTTP on port 8000, and every client already sends its token in a header there. So
an HTTP download beside `/mcp`, checked against the same token, gives a real download. The
file goes straight to disk, and the model sees only the size and the checksum.

**Read off the machines on 2026-10-13, and reported on 2026-10-14.** Perishable (rule 2).
- **Codex's shell is sandboxed with network access off.** The requesting project's main
  session's records show `workspace-write` and `network_access: false`. The requester's reply says its current
  session sends requests to run outside the sandbox to an automatic reviewer, not to the
  operator. A download therefore needs that reviewer's approval each time, which "is not
  guaranteed". The requester asks not to require network access for the whole project. These
  are Codex's settings; nervus cannot change them.
- **The Codex token's variable is set inside Codex's sandboxed shell** (the requester's reply,
  checked without printing the value). The session that wrote this ADR did not observe it.
- **A token kept in the operating system's keystore is in no environment** (ADR-0009 decision
  5). A Claude Code session would fetch it through `tools/nervus-headers`, which raises the
  keystore's prompt, as every connection already does.
- **Proxmox 9.2.3's guest-agent `file-read`** takes `file`, `offset` and `count` (at most
  16 MiB a call), and `decode=0` returns the bytes base64-encoded rather than as decoded
  text. It needs `VM.GuestAgent.FileRead` on the VM (the host's API schema). nervus's scoped
  token holds that on every VM but nervus's own, and `VM.GuestAgent.Unrestricted`, which
  running commands needs (`/access/permissions`, through nervus). So nervus itself can read a VM's file in chunks,
  through the API it already uses, with no guest account, no SSH into the VM, and no port
  opened on it. **How fast it is has not been measured.** Whether a VM has `stat` and
  `sha256sum` where the guest agent looks is not checked either (the requester asks that it be).
- **Step 0, read through nervus on 2026-10-14 on the first installation, read-only**
  (deployment note 0016). Nothing was written in the guest.
  - **The VM read has `stat` and `sha256sum`**, from coreutils that are **uutils 0.8.0** (the
    Rust rewrite), not GNU's. The guest agent runs commands as root.
    Its `sha256sum` printed the GNU format, `<hash>  <path>`.
  - **Proxmox's `file-read` returns corrupt data above 1 MiB with `decode=0`, and reports
    success.** Reading a file of about 33 MB in 16 MiB and 4 MiB calls gave 8 and 2 bytes
    too many and the wrong SHA-256. 1 MiB calls matched the guest's own hash. The cause is in
    `PVE/API2/Qemu/Agent.pm`: one call loops over 1 MiB guest-agent reads and joins their
    base64 text, each piece with its own padding. The result is not valid base64. The same
    16 MiB reads, decoded piece by piece at the padding, matched exactly. The answer also
    carries `bytes-read`, which the schema does not list. **So nervus reads at most 1 MiB per
    call**: each answer is then one valid base64 string, about 1.4 MB, well inside a small
    machine's memory, and nervus checks the decoded length against `bytes-read` on every call. That is
    how decision C's "in chunks" is carried out. It changes no decision.
  - **Speed: about 1.3 MB/s**, set by the guest agent: 13 s per 16 MiB call, through `pvesh`
    on the host. Through `pvesh`, 1 MiB calls managed 0.47 MB/s, because each call starts a
    new `pvesh` process. nervus calls the API, whose server is already running, so it should
    be near the 1.3 MB/s. That is expected, not measured. The requester's 7 MB archive would take
    about 6 seconds, and a 256 MiB export about 3½ minutes. **The ceilings stand.** Question
    I's waiting and polling is what makes the larger sizes workable.
- **nervus's filesystem is shared with the audit log and the database.** Filling it would stop
  nervus writing audit records, so storage for downloads needs a hard ceiling.
- **The first installation serves MCP over plain HTTP** (`--insecure-plain-http`; ADR-0010).
  Every token already crosses its network in the clear on every call. A download on the same port sends no
  credential that is not already sent. It does put **file contents** on the network in the
  clear, as `exec` output already is. **This ADR does not fix that.** Moving MCP to HTTPS
  stays separate work.
- **Starlette, which nervus already uses, serves byte ranges**, so a download that was cut
  off can resume where it stopped.
- **`curl -C -` resumes by byte offset alone** and ignores an `ETag` (the requester's reply, from
  curl's manual). The first draft relied on the `ETag`; F below no longer does.

## Questions

### 0. Order

`CURRENT_STATE.md` puts piece 5, first-run setup, next, and ADR-0015's draft is waiting
on its questions. This work is not in that order.

1. **Insert it before piece 5**, as the operator inserted ADR-0009 between steps 1 and 2.
2. After piece 5.

*Recommended: 1.* The operator has called it part of what nervus is for, the requester was using
the slow route, and it touches nothing piece 5 touches. ADR-0015's questions wait,
unchanged.

### A. How the file reaches the client

1. **An HTTP download on nervus's MCP port**: `GET /exports/<id>`, with the client's own
   token in the `Authorization` header, checked exactly as an MCP call is (the token, the
   off switch, the audit). The id names the export. It is not a secret and grants nothing
   alone. Byte ranges for resuming. The client instructions pass the header through
   standard input, so the token never appears in a command's arguments, which other
   processes can list:
   `printf 'Authorization: Bearer %s\n' "$NERVUS_TOKEN" | curl -fS -C - -H @- -o <file> http://<nervus>:8000/exports/<id>`
   (`printf` is built into the shell, so it starts no process). Then the client compares
   `shasum -a 256 <file>` with the SHA-256 nervus reported. Where any process can already read
   another's environment (ADR-0009 decision 5) this gains little, but it costs nothing, and
   elsewhere it matters.
2. An MCP resource. Rejected above: the bytes go through the model.
3. A one-time link with a secret in it (a "ticket"). It needs no token in the client's
   shell, but the link is a credential, and it would appear in the tool result and in the
   URL, which the request rules out.
4. The UI on port 8443. It needs a browser session, and `curl` does not trust nervus's own
   certificate.

*Recommended: 1.*

### B. Who may download an export

1. **Only the token that made it.** Any other token, including a valid one, gets 404, as
   if the export did not exist, and the refusal is audited. A switched-off or revoked token
   is refused as everywhere else. A token's allowlist is checked when the export is made,
   not again at download.
2. Any token whose allowlist reaches the source.

*Recommended: 1.* It is the narrowest rule, and it needs no new concept: the export records
its token id, as every audit record already does.

### C. What can be exported, and how it is authorized

A new tool, `export`, stages a copy of one regular file in nervus. It takes one of two
sources:

- **a host** (`host`, `remote_path`): read over SFTP like `get`, and allowed exactly where
  `get` is, by the token's allowlist.
- **a VM** (`vmid`, `path`): read by nervus through Proxmox's guest-agent `file-read`, in
  chunks. Allowed for any token whose allowlist includes the Proxmox host's scoped entry, as the
  `proxmox` tool is. Which VM and which file is **Proxmox's decision** (ADR-0009 decision 2).
  nervus's own container is a container, which the guest agent cannot reach at all.

Directories are not exported; a client makes an archive at the source first (the requester's
reply: that suits it). **The transfer directory is not a source**, as the requester asks. Its
files have no recorded owner, and nobody needs it. (The gap the requester names already exists:
any token can `put` a file another client fetched to a host it reaches, and read it there.
This ADR does not widen it, and does not close it.)

Options for the VM case:
1. **Proxmox's permissions are the boundary**, as for the `proxmox` tool.
2. A list of VMs each token may export from, kept in nervus. That is a new authorization
   concept, and ADR-0009 rejected curating access in nervus for VMs.

*Recommended: 1.*

### D. Limits on size and space

1. **One export at most 256 MiB. All exports together at most 1 GiB, counting copies still
   being made. Never leave nervus's filesystem with under 2 GiB free.** These are nervus's
   defaults, sized for a small dedicated machine; making them configurable is left to a future
   release (ADR-0019, the operator's policy 2). Before copying,
   nervus reads the source's size and **reserves** that much against the total, under a
   lock, so two exports made at once cannot both pass the check. While copying, it counts
   the bytes written and stops if the file grows past its reservation or the ceiling. A
   stopped or failed copy is deleted and its reservation released.
2. Other numbers.

*Recommended: 1.* The requester says these suffice, and larger artifacts can be split. Raising
them later is a one-line change and a deploy.

### E. How long an export lives, and where

1. **24 hours from when it is made**, then deleted. Expired exports are swept at every
   `export` call and once an hour. A client may delete its own export early, for example
   once it has checked the file (`export` with `action: "delete"`). Files go in
   **`/var/lib/nervus/exports`**, which nervus may already write (`StateDirectory=`), apart
   from the transfer directory, so `get` and `put` can never reach them. Each export's
   record is a new table in nervus's database, added without changing the version
   (ADR-0014 F), so a rollback can still open the database.
2. One hour.
3. Until the client deletes it.

*Recommended: 1.* The requester usually downloads within minutes, but says a session that is
interrupted needs the longer window.

### F. Integrity and resuming

1. **A finished export never changes, and its id is never reused.** So resuming by byte
   offset under the same id cannot splice two different files: there is only ever one
   file behind an id. nervus still sends the SHA-256 as the `ETag`, and honours `If-Range`
   for clients that use it. **The final check is the client's**: the SHA-256 of the saved
   file against the one nervus reported, before the client relies on it.

   **The reported hash is checked against the source.** nervus computes the SHA-256 of its
   copy as it writes it. Before and after reading, it asks the source for the file's size
   and SHA-256 (`stat`, `sha256sum`: over SSH for a host, through the guest agent for a
   VM). It **refuses** the export, and deletes the copy, unless all three hashes and both
   sizes agree. If the source cannot hash (no `sha256sum`, say), the export is refused with
   that reason, so a result that names a hash always means the source agreed.
2. Hash the staged copy only.

*Recommended: 1.* The requester asked for the staged copy to be compared with the guest's hash,
not only the guest's before and after values. Refusing a source that cannot hash is
stricter than reporting it unverified, and simpler to rely on. If a real source needs it,
that can be relaxed later.

### G. Paths and links

1. **The remote path is the target's business.** nervus does not filter it, because
   `agent` and the guest agent are root there (ADR-0001 s5). A link on the source is
   followed by the source, as `get` already does. **On nervus's side, the client never
   names a path.** Staged files are named by nervus with a random id, created
   exclusively, never through a link. A download opens only a recorded, finished export,
   by id, and refuses anything but a regular file inside `/var/lib/nervus/exports`.

*Recommended: 1.*

### H. What the audit log records

1. **`export`** writes an intent (source, path) and a result (size, SHA-256, expiry, or the
   reason it failed). **Each download request** writes one record: the export id, the byte
   range asked for, the bytes sent, and whether it finished. A resumed download is several
   records. Refusals are recorded like every other refusal. **Nothing in any record or
   result holds a token.**

*Recommended: 1.*

*Carried out (step 4, 2026-10-14):* "whether it finished" is recorded as `all_sent`: whether
nervus handed every byte asked for to the connection. A test found that is all a server can
know. A client killed part-way through a 3 MiB download was recorded as sent in full, because
the operating system had already buffered the rest. So `all_sent: true` does not prove the
client has the file; the client's own SHA-256 check does.

### I. Waiting, retrying and progress

The requester asks for an export that answers at once, can be polled, survives a client timeout
or disconnect, and is never duplicated by a retry. A 256 MiB copy may well outlast Codex's
60-second limit on one call. How fast the guest agent reads has not been measured.

1. **One call does everything.** `export` takes a `request_key` chosen by the client. The
   copy runs inside nervus, apart from the call. The call waits up to `wait` seconds
   (default 30), then returns the export's state: `staging` with bytes copied so far,
   `ready` with size, SHA-256 and expiry, or `failed` with a reason code and message.
   **Calling again with the same token and `request_key` returns that same export**,
   whether that is to check progress, to retry after a timeout, or after a disconnect. It
   never starts a second copy. A copy cut off by a nervus restart is marked `failed` when
   nervus starts, and its partial file is deleted. Asking again with a new key starts
   over.
2. A separate status tool and a job id, like `exec_bg` and `job`. That is two tools and a
   second id, for what option 1 does with one.
3. A call that waits until the copy is done. Simplest, but a large export then fails with
   the client's timeout, and a retry duplicates it.

*Recommended: 1.* It meets every point the requester made with one tool and no job model. The
"one key, one export" rule is held by the database, so it survives restarts.

The result also carries a suggested filename (the source's base name) and the call's
`run_id`, which is its audit reference. Source permissions and times are not kept
(the requester: not needed).

### J. What this ADR leaves out

1. **Leave out**, and record as known limits:
   - **Uploads**, a file from the client's machine into the fleet. The same design runs in
     reverse: an HTTP `PUT` of a file the client declared with a size and SHA-256, staged
     under the same ceilings, then sent to a host or VM by a tool. It deserves its own ADR,
     after this one has run.
   - **Clients with no shell on the LAN**, such as an agent running in the cloud. They
     cannot reach port 8000 until nervus is reachable from outside (ADR-0005, ADR-0008).
     Until then, the only route for them is MCP itself, through the model.
   - **HTTPS for MCP and downloads** (ADR-0010).
2. Take uploads into this ADR now.

*Recommended: 1.* One direction, finished and observed, first. The table, the ceilings, the
ownership and the audit records are built so an upload can reuse them.

## Consequences

1. nervus gains one tool and one HTTP route. Both are authenticated by the existing token
   check, and both are audited. No change to the token model, the unit file or Proxmox.
2. **Clients must be able to reach port 8000 from their shell.** For a sandboxed Codex,
   each download is a request to run outside the sandbox, which Codex's reviewer may
   refuse. nervus cannot remove that step, and the client instructions say so.
3. File contents and tokens cross the network in the clear until MCP moves to HTTPS (ADR-0010),
   as they already do for every call.
4. Up to 1 GiB of nervus's disk may hold exports at once, by default. The 2 GiB floor protects the
   audit log.
5. A published nervus inherits all of this. With HTTPS (ADR-0010) the token and the file
   are both encrypted.

## Order of work

Each step is one module with its tests, and each waits for the operator (rule 1):

0. ~~**Read before building**, through nervus, read-only: how fast `file-read` moves a file
   out of a VM, and whether `stat` and `sha256sum` are where the guest agent looks.
   If the speed makes the ceilings unreasonable, this ADR comes back before step 1.~~ Done
   2026-10-14 (Context, "Step 0"): both are there; about 1.3 MB/s; the ceilings stand; and
   reads above 1 MiB come back corrupt, so nervus reads 1 MiB at a time.
1. ~~The export store: the table, reservations under a lock, staging files, expiry and the
   sweep, and failing interrupted copies at start.~~ Done (`d231c7e`). Steps 2 to 5 are done too
   (`d670ecc`, `a662482`, `8b353cb`, `2948210`), and 6 and 7 by procedure 023, 2026-10-15.
2. The two sources, host over SFTP and VM through the guest agent, each with its hash
   check against the source.
3. The `export` tool: the request key, waiting, states, its audit records.
4. The download route: token check, owner check, ranges, its audit record.
5. Client instructions in procedure 005, for Codex and Claude Code.
6. A deploy procedure, written for approval before it runs, then deployed.
7. **The demonstration**, run by the operator in the requester's Codex session: an export from a
   VM saved to the client's machine, with its SHA-256 checked there against the guest's;
   a download cut off and resumed; a second client refused; a revoked token refused; an
   expired export gone; and an export refused for space. A success reported only by the
   server does not count.

## Verification

Moves to Accepted when all of the following are observed, in tests or on an installation, not
asserted:

1. A file exported from a host and from a VM downloads whole, and its SHA-256 on the
   client matches the source's own. **Observed on the first installation** (procedure 023 steps 4 and 5;
   step 6 for Codex), and in tests.
2. A source that changes while it is read, or that cannot hash, is refused, and no file is
   left behind. **In tests** (`test_export_sources.py`).
3. A download cut off partway resumes with `curl -C -` and ends with the right hash. **Observed
   on the first installation** (procedure 023 step 5), and in tests with real curl.
4. A file over 256 MiB is refused before anything is staged. Two exports made at once that
   together would pass 1 GiB, or the 2 GiB floor, do not both succeed. A source that grows
   past its reservation is stopped. **In tests** (`test_exports.py`, `test_export_sources.py`).
5. A token without the host, or without the Proxmox host's scoped entry, is refused `export`. A second valid token
   is refused the first token's export with 404. A switched-off token and a revoked token
   are refused both. Each refusal is in the audit log. **The second valid token's 404, and its
   refusal record, observed on the first installation** (procedure 023 step 6); the rest in tests. A revoked
   token is an unknown one, and is refused as the tests' wrong token is.
6. A download id that is not a recorded, finished export is refused, including ones shaped
   like paths. **In tests**; on the first installation the route refused a request with no token (step 3).
7. The same `request_key` twice gives one export, across a client timeout and a nervus
   restart. A restart during a copy leaves it `failed` with no partial file. **The repeated key
   observed on the first installation** (procedure 023 steps 4 and 6); timeouts and restarts in tests.
8. An export is gone after its expiry, and after a client deletes it. **Deletion observed on
   the first installation** (procedure 023 step 4); expiry in tests.
9. No token appears in any tool result, URL, command argument in the instructions, or audit
   record (searched for). **Observed on the first installation**: every token file value 0 times in the whole
   audit log, before and after (procedure 023 step 7); the commands as written, in tests.
10. The demonstration in step 7 of the order of work, observed through the Codex session's
    own record and the file on the client's machine. **Observed 2026-10-15** (procedure 023 step 6):
    Codex's report, and nervus's records of its export and its whole download.
