# ADR-0009: the Proxmox host becomes a target — scoped for every client, full only by the operator's explicit choice

**Status:** **Accepted 2026-10-01** by the operator. Every verification item was observed on the
first installation, except points the operator accepted on stated grounds instead, recorded at
each item. Amended twice on 2026-09-24 (after the host was surveyed, procedure 008, and after the
token-confinement research) and on 2026-09-30 (after step 6's verification, procedure 014); the
amendments are folded into the decisions below.
**Rewritten:** 2026-10-16, under ADR-0019 F and the operator's choice that day to split it, as
ADR-0001 was: every decision keeps its number and its meaning, stated for any Proxmox host. The
operator's original, written for their own host, is kept whole in the deployment record
(deployment note 0009). Where a decision below speaks of the first installation, that note has
the specifics.
**Date:** 2026-09-24
**Amends:** ADR-0001 s9 and s12, which kept the hypervisor host to its API and said the agent
never has SSH to it
**Makes exceptions to, on an installation that grants the full level:** ADR-0005 s4 and ADR-0007
s8, which keep the audit log unreadable through MCP
**Decided by:** the operator, 2026-09-22 to 2026-09-24, in a Claude Code session in this
repository
**Prior art:** `research/2026-10-15-prior-art.md` idea 1 bears on decision 2 (a token that cannot reach the Proxmox host still sees the `proxmox` tool). A note, not a decision.

## Context

Projects that use nervus need to stand up VMs for testing. The operator also wants agents to
report on the hypervisor, troubleshoot it, and do anything with any VM on it, whether the agent
created that VM or not. The goal is to help one person run their own machines, not to pass a
compliance standard. So the rule the operator set is **grant everything that stops short of
compromising nervus.**

The hypervisor host cannot be added the way other hosts are when **nervus runs on it**, as one of
its guests. Whoever has root on a hypervisor controls every guest on it: `pct exec`, `pct mount`,
or reading the container's volume directly exposes the token file and the fleet key, and lets the
audit log be rewritten. Hardening inside the container cannot change that. Proxmox's container
documentation says unprivileged mode protects the host from the container, not the container from
the host. Confidential computing (AMD SEV-SNP, Intel TDX) is the only technology that protects a
guest from its host. It applies to full VMs, not containers, and needs specific CPUs.

Proxmox documents its own model for automation, in the user-management chapter of the admin guide
(read online 2026-09-22; the privilege checks were later confirmed against the host's own API
schema, procedure 008):

- dedicated users with API tokens. `root@pam` is described as "an unconfined administrator".
- **privilege separation**, the default for new tokens: a token's effective rights are the
  intersection of its own rights and its user's, and the token can be revoked without touching
  the user.
- "Permissions on deeper levels replace those inherited from an upper level", and the built-in
  `NoAccess` role "cancels all other roles on a given path".
- `Datastore.Allocate` covers "delete volumes"; `Datastore.AllocateSpace` covers only allocating
  space.

Together these rules mean one token can hold broad rights over the whole host while having none
on nervus's own container. The host enforces that, not nervus.

Separately, **this project develops nervus.** On the first installation, deploys and fixes each
needed the operator at the host's keyboard (procedures 002, 006 and 007), and a hardware question
stayed open because nothing could reach the storage controller (procedure 001). For this
project's own agent, full access to the host, nervus's container included, removes that
bottleneck. The operator judged that worth the cost stated in decision 3.

A log store on the same machine as nervus, as ADR-0001 s10 might have had, could not be an
independent copy of nervus's log (deployment note 0009).

## Decision

**1. The Proxmox host joins the inventory as two entries**, one machine behind two accounts. The
existing per-token host allowlist chooses between them, so no new authorization concept is needed.

| entry | account | sudo | who gets it |
|---|---|---|---|
| scoped | `observer` | none | every in-use token |
| full | `agent` | passwordless, root-equivalent | one token, named by the operator |

Both entries use nervus's existing key and the same pinned host key. Since 2026-10-16 the
inventory marks the scoped entry `hypervisor: proxmox` and the full one `issue: never` (ADR-0019
decision D); their names are the installation's.

**2. The scoped level is a Proxmox API token plus a shell without sudo.**

- **API.** A `nervus@pve` user and one API token with privilege separation. One custom role,
  granted on `/`, holds every privilege **except** those that would amount to root on the host,
  and so to control of nervus:
  - changing permissions, users, groups or realms. **Proxmox makes one exception** (found at
    step 6, procedure 014, and read in its `check_perm_modify`). Holding `VM.Allocate` on a VM,
    or `Pool.Allocate` on a pool, lets a caller change that path's permissions. It may hand out
    only privileges it already holds there, and never `NoAccess`. So the scoped token can, on
    every VM but nervus's container and on pools. It cannot on nervus's container or nervus's
    storage, where it holds nothing, and it cannot give itself more than the role. **Accepted by
    the operator, 2026-09-30.** The only way to remove it is to withhold `VM.Allocate`, which
    creating and destroying VMs needs.
  - the host's root console (`Sys.Console`)
  - the host's own configuration, network, packages, services and power (`Sys.Modify`,
    `Sys.PowerMgmt`). Operator default, 2026-09-24: these could take nervus offline, and changing
    package sources is a delayed route to root.
  - deleting storage volumes directly (`Datastore.Allocate`), which could delete nervus's disk
  - hardware mappings, which would let a guest take a host device
  - changing SDN (software-defined networking), whose apply step reloads the host network

  `NoAccess` is set on nervus's container (`/vms/<its id>`), and on nervus's own storage
  (decision 6), for both the user and the token. nervus's container belongs to no pool, and the
  token cannot add it to one: changing pool membership also needs the right to modify
  permissions. **The privilege list is built from the host's own API schema**, the `apidoc.js`
  file that ships with `pve-docs` (procedure 008). `pvesh usage` does not show permission checks,
  although this ADR first said it did. Read on the first installation on 2026-09-24, Proxmox has
  47 privileges. The role holds 34, withholding these 13: `Permissions.Modify`, `User.Modify`,
  `Group.Allocate`, `Realm.Allocate`, `Realm.AllocateUser`, `Sys.Console`, `Sys.Modify`,
  `Sys.PowerMgmt`, `Sys.Incoming`, `Datastore.Allocate`, `Mapping.Modify`, `Mapping.Use`,
  `SDN.Allocate`. `tools/proxmox-access` sets all of this up.
- **Trusting the API.** nervus checks that it is talking to the real host by pinning Proxmox's
  own root certificate authority, "PVE Cluster Manager CA", which Proxmox issues for ten years. It
  does not pin the node certificate it signs, which is renewed automatically; pinning that would
  break at the first renewal.
- **Tool.** One `proxmox` tool takes any API call (method, path, parameters) and is audited like
  every other tool. The boundary is Proxmox's permission system, not a curated list of operations
  in nervus. That is ADR-0001 s5 applied to a new target. Settled by the operator on 2026-09-24,
  while the tool was being built:
  - **Who may call it:** any token whose host allowlist includes the scoped entry. The tool has
    no host argument; it always means the Proxmox host.
  - **The intent record** holds the method, the path and every parameter, as `exec`'s holds the
    full command. The exception is any parameter whose name contains `password` (`cipassword`,
    for example), which is recorded as `<redacted>`. The audit log may be copied off the host
    (decision 4), where agents may read it; a password there would outlive the thing it protects.
    The record still shows that one was set.
  - **The result record** holds the HTTP status, Proxmox's reason text and the response size, not
    the response body. That matches `exec`, which records sizes, not output. A refusal by
    Proxmox's permission system is a result, not a nervus refusal.
  - **Unconfigured means absent.** Without Proxmox settings, nervus does not offer the tool, so no
    client sees a tool that cannot work.
  - **Settings live with nervus** as `secrets/proxmox.yaml` (mode 0600: API address, token id,
    secret) and `secrets/pve-root-ca.pem`, the pinned CA.
  - A response larger than 256 KiB is refused, not cut short.
- **Inside VMs.** Commands inside any VM run through the Proxmox guest agent (a service inside the
  VM that Proxmox can run commands through), using the `VM.GuestAgent.*` privileges. New VMs do
  **not** join nervus's SSH inventory. That is deferred (decision 8). This has two limits. It works
  only in VMs that have `qemu-guest-agent` installed and the agent option enabled in their Proxmox
  config. And it does not reach containers at all: Proxmox's API has no way to run a command
  inside an LXC container, because `pct exec` is a root command on the host. At the scoped level,
  agents manage containers but cannot run commands in them; the full level can.
- **Shell.** `observer` has no sudo and belongs only to groups that read logs (`adm`,
  `systemd-journal`). Never `sudo`, `disk`, `www-data` or `lxc`. It is for diagnostics:
  processes, network, disks, logs. It is not a way to administer anything.
  `tools/proxmox-accounts` creates it, and `agent` for the full level.
- **Limits Proxmox imposes.** Proxmox reserves for its own root account the guest settings that
  would give a guest access to the host: bind mounts from the host, device passthrough, privileged
  containers, hook scripts. The scoped level cannot set them on any guest.

**3. The full level is root on the Proxmox host, nervus's container included, for one token the
operator names.** Its `agent` account matches the ones on other hosts. The operator accepts,
knowingly, that the agent holding it can:

- read the fleet key and every token. At home that adds little the token doesn't already have:
  the key reaches the same accounts on the same hosts. What it does add is a way around nervus's
  log.
- edit nervus's code, configuration and audit log. Decision 4 answers the log.
- cut off its own access: a bad redeploy, or a change to the host's network, takes down the
  connection it works through. The operator keeps a way back in that does not go through nervus
  (deployment note 0004).

**4. Before the full level is granted, every audit record is copied, as it is written, to a
machine the full level cannot reach.** Records already copied cannot be rewritten from the host.
That restores the property decision 3 gives away: a history the agent cannot erase.

- **The copy's machine pulls; nervus does not push.** Nothing there listens for connections.
- **The reader's key can do one thing:** stream the audit log from a byte offset, as a forced
  command in its `authorized_keys` (`tools/nervus-audit-stream`), on an account of its own whose
  only access is reading the log.
- **Each pull checks that nervus's log still begins with what was already copied.** If it
  doesn't, nervus's copy was edited, and the pull says so.
- **The copy is append-only** where the copy's machine can enforce that, and lives outside every
  project folder.
- The read key is a plain file. It can only read the log, so anyone who can read the key gains
  nothing more.
- **A pull that fails while nervus's machine answers is an alarm, after an hour.** *Amended
  2026-11-15, decided by the operator.* A pull that cannot reach nervus's machine is not an alarm:
  the copy's machine may be asleep or away, and the next pull catches up. As first built, every
  failure counted as that, a refused key and another machine answering in nervus's place included,
  so a copy that had stopped for good said nothing (procedure 013). Asked whether it should raise
  an alarm, and after how long, the operator chose **"Nervus answers, pull fails (Recommended)"**:
  an alarm once pulls have failed for an hour while nervus's machine itself answers on the
  network, and silence while it does not. Not chosen: that, and also an alarm after seven days
  without a pull for any reason; and no alarm.

On the first installation the copy is on the operator's own laptop, pulled once a minute
(deployment note 0009, procedure 013).

**5. Before the full level is granted, its token is in no process's environment, and every read
of it needs the operator's approval.** Delivering it as an environment variable would hand root on
the host to every agent session that can see that environment.

The decision first said the token would be "delivered to this project only". The research step
found that cannot be enforced on one machine under one user, for two reasons observed on
2026-09-24:

- **Any process can read another's environment.** Anything running as the same user can read
  another process's environment variables (`ps -E` on macOS). So no way of delivering a token as
  an environment variable confines it.
- **A project is not a security boundary.** Operating systems separate user accounts, not folders.
  A session in another project can start a client in this repository and fetch whatever this
  repository fetches without asking.

So the token is kept in the operator's operating-system keystore, in an item that trusts no
application, so that every read raises a prompt; the client fetches it through a helper when it
connects (`tools/nervus-headers` for Claude Code's `headersHelper`), so it lives only in that
client's memory; and it is rotated at the switch. The first installation's setup, its accepted
limits and the options rejected are in deployment note 0009 (procedure 009).

**6. When nervus runs on the host it manages, its disk moves to storage of its own.** A thin pool
lets guests claim more space than exists. If agents fill it, writes fail on every volume in the
pool, nervus's included. That is the one way the scoped level could damage nervus without
touching it. So:

- a fixed-size logical volume, from space outside every pool agents can write to, is formatted
  and added to Proxmox as storage of nervus's own, holding container root filesystems only.
- the scoped token gets `NoAccess` on that storage, so it cannot allocate there or move a disk
  onto it.
- nervus's root filesystem moves onto it.

Nothing agents do can then fill the disk nervus runs on. The move means a few minutes of nervus
downtime. The first installation's sizes, and the survey that found the space, are in deployment
note 0009 (procedures 008 and 011).

**7. Who gets what.** Every in-use token may get the scoped entry; the full entry goes to one
token. The first installation's grants are in deployment note 0009 and its token file.

**8. Deferred, without conditions.** The full level for other clients (Codex, Cursor, other
projects) may be added later. New VMs joining nervus's SSH inventory is also deferred.
(2026-10-15: ADR-0017 question J, decided by the operator, lifts the second deferral in
direction: VMs that do more than short work are to be enrolled through the guest agent. How is a
later ADR.)

**9. Order of work.** The first installation's, done between 2026-09-24 and 2026-10-01, is in
deployment note 0009 (procedures 008 to 016).

## Exceptions this makes, and to what

- **ADR-0001 s9 and s12.** "The agent never has SSH to the hypervisor host" no longer holds. The
  reason behind it, that nervus must not be controlled by what it controls, still holds for every
  token except the one with the full level.
- **ADR-0005 s4 and ADR-0007 s8** (the audit log is unreadable through MCP). The full level can
  read it on the host, and agents may be able to read the off-host copy. Those decisions exist to
  stop one client seeing another's activity; on an installation where every client is the
  operator's, that does not arise. **These are exceptions on such an installation, not changes to
  the published design.** ADR-0005 verification 4 and ADR-0007 verification 7 must be observed
  with a token that does not hold the full level. Whether published nervus should support
  enrolling its own host at full access is a separate decision, not taken here.
- **ADR-0001 s10.** A log store on nervus's own host cannot serve as the independent copy for the
  full level; decision 4's copy does that.
- **The operator's own way back in** (deployment note 0004) matters more: it is the recovery path
  when an agent at the full level cuts nervus off.

## Alternatives considered

- **Root-equivalent SSH on the host for every token.** Rejected: every allowlisted client would
  control nervus.
- **Hardening nervus's container against its host.** Not possible, as explained in Context.
  Confidential computing is VM-only and needs specific hardware.
- **Moving nervus off the host** so it can be an ordinary target. Viable, not chosen: it costs
  another machine, and the full level gets this project the benefit without it.
- **Curated `proxmox_*` tools**, as ADR-0001 s9 first sketched. Replaced by one passthrough tool:
  the operator wants "anything", and Proxmox's permissions are the boundary.
- **A sudo allowlist of diagnostic commands for `observer`.** Rejected: ADR-0001 s5 rejects
  command filtering, and common diagnostic tools can open a shell (a pager, for example).
- **The audit copy on nervus's own host.** It is the machine the full level controls.
- **nervus pushing the audit copy.** Rejected: it needs a listener on the copy's machine, and a
  copy's machine that nervus can reach.
- **The copy owned by a separate operating-system account.** Deferred. It would stop an agent on
  the copy's machine from editing the copy even deliberately. At home scale, the client's
  permission checks and the append-only mark were judged enough. The gap left open is a
  deliberate edit that a permission check fails to catch.

## Consequences

1. At the scoped level, agents can create, change and destroy any guest except nervus's container,
   and read everything about the host. They cannot change the host itself, and cannot set the
   guest options Proxmox reserves for root.
2. At the full level, the only safeguards are the off-host copy of the audit log, the operator's
   own way back in, and Proxmox's own task log. That task log covers API actions only; shell
   actions as root are recorded in the host's journal, which root can edit.
3. The scoped API token's secret lives with nervus. Compromising nervus compromises that token,
   just as it already compromises the fleet key.
4. Concurrency stays unmanaged (ADR-0001). Agents from two projects can act on the same VM at
   once.
5. The first installation's records of all this are its procedures from 008 onward and
   deployment note 0009.

## Verification

Moves to Accepted when all of the following are observed, not asserted. Observed on the first
installation, as marked:

1. The scoped token lists every guest except nervus's container, and creates, starts, snapshots,
   stops and destroys a test VM. Each action appears in nervus's audit log and in Proxmox's task
   log. **Observed 2026-09-30, procedure 014.**
2. The scoped token is refused on nervus's container for status, config, stop, snapshot, backup
   and destroy. If a backup of it exists by then, restoring it as a new guest is refused too.
   **Observed 2026-09-30, procedure 014**, except backup. That request was refused at the storage,
   not at the container. Testing it for real would, if the lock were wrong, copy nervus's secrets
   to shared storage. The operator accepted it on 2026-09-30 as not safely provable, resting on
   the same `NoAccess` that refused the other five. No backup existed to restore.
3. The scoped token is refused for: changing a permission, creating a user or token, deleting a
   storage volume directly, changing the host network, rebooting the host, creating a privileged
   container, adding a bind mount, setting a hook script, creating a hardware mapping, and
   creating a disk on or moving a disk to nervus's own storage. **Observed 2026-09-30, procedure
   014**, with two exceptions, both accepted by the operator that day:
   - Changing a permission is allowed within decision 2's exception. A change on a VM path that
     did not exist passed the permission check, then failed on the `NoAccess` rule; nothing
     changed.
   - A hook script could not be tested, because Proxmox checks the script exists first. It was
     accepted as not safely provable. The API cannot put a script on the host: its two ways to
     place a file on storage, `upload` and `download-url`, accept only `iso`, `vztmpl` and
     `import` (the host's API schema, read 2026-09-30).
4. Through nervus, `observer` on the host reads the journal and process list. It cannot read
   nervus's secrets or audit log through host paths. `sudo -n true` fails. **Observed 2026-09-30,
   procedure 014.**
5. The full-level token runs `sudo -n pct status <nervus's id>` on the full entry. Every other
   token is refused the full entry, and the refusal is in the audit log. **First sentence observed
   2026-10-01, procedure 016.** The second was accepted by the operator that day without a live
   attempt. The allowlist refusal and its audit record were observed live in procedure 004, and
   the token file was read before and after the grant, with the full entry on one token's
   allowlist alone.
6. A record nervus writes appears in the off-host copy within one pull interval. An edit to
   nervus's log is reported by the next pull. Truncating or deleting the copy fails while the
   append-only mark is set. **Observed:** the first sentence on 2026-09-25, procedure 013 (25
   seconds); the other two on 2026-10-01, procedure 016. A one-byte edit to nervus's real log,
   made through the full level and then undone, was reported by the next pull 16 seconds later.
7. From a session in another project: the full-level token is absent from its own environment and
   from every process's. Reading it from the keystore raises a prompt, and when the operator
   refuses, the read fails. From this repository, nervus's tools work and the audit log records
   the calls under that token. **Observed 2026-09-24, procedure 009.** Re-checked 2026-10-01
   (procedure 016): one long-running process still carried a value, most likely the retired one.
   It was stopped, after which no process carried the variable.
8. nervus's container's root filesystem is on its own storage, and the thin pool no longer holds
   its disk. **Observed 2026-09-25, procedure 011.**

## Amendment 2026-11-13: four whole-node bulk actions are refused by nervus itself (procedures 056 and 058)

**What was found.** The security review before the 0.2.0 export (procedure 056, finding 4) found that
Proxmox's whole-node bulk actions — `POST /nodes/<node>/startall`, `stopall`, `suspendall` and
`migrateall` — check their privilege on `/` and then act on every guest from Proxmox's own worker,
with no check per guest. Decision 2's NoAccess on nervus's own container therefore does not hold for
them: a token holding the scoped role could stop nervus's container, and the fleet with it.

**The change, made 2026-11-12 (commit 7fa3572) and recorded here.** nervus refuses those four before
anything is sent, by the last segment of the path, whatever the method. This is the one place nervus
narrows what its token may do through the `proxmox` tool; everywhere else "Proxmox's permissions are
the boundary" stands, and the tool's description, which every client reads, says so (2026-11-13).

**What trial D showed (procedure 058),** on a throwaway Proxmox VE 9.2 whose ACLs `tools/proxmox-access`
set, with NoAccess on nervus's container and on the storage that holds it:
- with the code before the change, a client's `stopall` through nervus shut down nervus's own
  container, NoAccess to the token: Proxmox logged it as the token's user;
- with the change, all four are refused by nervus, and nervus's container keeps running;
- they are the whole class. In Proxmox VE 9.2's own source exactly these four check `/` and act from
  the worker; its cluster-wide bulk-action API
  (`/cluster/bulk-action/guest/...`) acts guest by guest **as the caller's own token**, so, sent with
  no guest named, it shut down the guests the token may power and logged `403 Permission check failed
  (/vms/<id>, VM.PowerMgmt)` for nervus's container, which kept running. It is not refused: it does
  only what the token could do one guest at a time. `vzdump` with `all` skips guests the token may not
  back up.

**Verification gains:** *9. The four whole-node bulk actions are refused by nervus before anything
is sent, and nervus's container survives the cluster bulk-action API. **Observed 2026-11-13, procedure
058.***
