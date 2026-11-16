# ADR-0017: VM templates for agents — a VM any client can make and use through the API alone

**Status:** **Accepted 2026-10-16, at the operator's word**, every verification item observed on
the first installation's Proxmox host except two halves the operator accepted on stated grounds
instead, each recorded at its item: item 7's restart of nervus's container, on the code reading,
and item 8's `long-lived` run, as the same steps without the destroy. Built and verified by
procedure 025 (the first template) and procedure 005 step 6 (the client recipe). (It was Proposed: accepted when the verification below is observed.)
**Decided by the operator on 2026-10-15**, in a Claude Code session: questions A to L, each as the
session recommended in the revised draft ("all as recommended"). Each question keeps its options,
so the record shows what was not chosen.
The draft was **revised the same day** after the operator's comments on the first one (VMs may
live for a minute or for years; efficiency means tokens and complexity as well as speed) and the
measurement that followed: questions B, C, F, G, I, J and L changed before the decision.
**Amended 2026-11-15, decided by the operator** (question F, "Amended 2026-11-15"): the template
gives its clones the host's own processor model, and what a clone carries over from the template
is said in the `proxmox` tool's own description.
**Date:** 2026-10-15
**Rewritten:** 2026-10-17, under ADR-0019 F, to name no installation. No decision changed; the
clone's sizes are nervus's defaults. The original, with the first installation's host and
template, is deployment note 0017.
**Decided by:** the operator, 2026-10-15
**Lifts:** ADR-0009 decision 8's deferral of new VMs joining nervus's SSH inventory, in direction
only (J1); how enrollment works is a later ADR
**Builds on:** ADR-0001 s5 (the boundary is the target's, not a filter in nervus); ADR-0005 s2 and
s5 (agentless; a restriction enforced by the target is a boundary, one nervus applies to itself is
a policy); ADR-0007 decision 1 and 9 (adversary A, and the single trust domain); ADR-0009
decisions 2, 6 and 8 (the scoped Proxmox token, nervus's own container kept off the shared thin
pool, new VMs not in the SSH inventory); ADR-0011 (enrollment is a command the user runs as root on the new
machine); ADR-0016 (a VM is an `export` source through the guest agent)
**Asked for by:** the operator, 2026-10-15, as item 1 of "Next, in order" in `CURRENT_STATE.md`.

## Context

### What is missing

Every client whose allowlist includes the Proxmox host's scoped entry can create VMs through the
`proxmox` tool (ADR-0009 decision 2). None of them can make one it can use. Using a VM without SSH and without a guest
password means using Proxmox's **guest agent**: a small service inside the VM
(`qemu-guest-agent`) that lets Proxmox run commands and read and write files in it over a private
virtual serial line, with no network and no login. A cloud image does not include that service
(below), and nothing but root on the host can add it: a custom cloud-init file has to be placed on
the host's disk, which the API cannot do. Only the full level has root there (ADR-0009 decision 3).

The working idea, the operator's from the previous session and not a decision: **a template**
(a VM Proxmox keeps only as a master copy, which cannot be started, only copied) with the guest
agent installed and enabled, built once by a reviewed root procedure, which any client copies
("clones") through the API. A working VM is then one API call, with no root, SSH or credential.

### The aim this has to serve

The operator: nervus "as a product very powerful and convenient for people like me who have
compute at home they want agents to be able to manipulate easily but safely." So the design is
for a published nervus, where the person with root on the hypervisor is the user, not an agent,
and the operator's own machines are the first installation.

Two things the operator added on 2026-10-15:
- **A VM may live for a minute or for years.** At one end, a 60-second test; at the other, a VM
  the user asked for as part of production, with no retirement date, which may need to be reached
  through nervus like any other host. Nothing here may assume a VM is short-lived.
- **"Efficient" means tokens and complexity, not only speed.** Agents run on inference: every call
  is a turn of the model, and everything a result returns sits in its context. A channel that is
  fast once set up can still lose to one that needs no setup.

The next session will clone the template to measure upload speed into a VM, so "clone, use,
destroy" must be short and dependable for an agent.

### Read off the first installation's Proxmox host on 2026-10-15, read-only, through nervus

Perishable (rule 2); what was read, with run ids, is in deployment note 0017. What bore on the
questions:

- **The host had no templates and no pools.** Its storages were Proxmox's defaults: `local-lvm`,
  the thin pool, and `local`, a directory on the host's own root filesystem, plus nervus's own
  (ADR-0009 decision 6). There was no unallocated space for another fixed-size storage.
- **Its VMs sit on one bridge, `vmbr0`, on the home network.**
- `genisoimage` is installed with Proxmox (it makes cloud-init drives). `xorriso`,
  `cloud-localds`, `virt-customize` and `guestfish` are not.

**What the scoped token holds** (ADR-0009 decision 2): `NervusScoped` on `/` for both the user
`nervus@pve` and its token, 34 privileges; `NoAccess` on nervus's own container and storage. It
includes `VM.Allocate`, `VM.Clone`, `VM.Config.*`, `VM.GuestAgent.*`, `Pool.Allocate`,
`Datastore.AllocateSpace`, `Datastore.AllocateTemplate` and `Sys.AccessNetwork`. So it can already
fetch an image from the internet onto `local` (`download-url`, whose permission note names exactly
those last privileges), create a VM that imports it, and convert a VM into a template.

**What protects a template from the scoped token, read in Proxmox's code** (the runs are in
deployment note 0017). The files are `PVE/RPCEnvironment.pm`, `PVE/AccessControl.pm`, `PVE/API2/Qemu.pm`,
`PVE/API2/Pool.pm`, `PVE/API2/ACL.pm` and `PVE/Storage.pm`.
- **`protection` alone protects only against accidents.** The flag makes Proxmox refuse to
  destroy the VM, remove its disks, or restore over it. But setting or clearing it is a
  "general option" that needs only `VM.Config.Options` on the VM, which the scoped token holds
  everywhere. An agent could clear it and then destroy the template.
- **A permission entry on the template's own path does protect it.** Proxmox resolves a path
  from `/` downwards, and an entry on a deeper path **replaces** what was inherited
  (`AccessControl::roles`, "overwrite previous settings"). So an entry on `/vms/<template>`
  giving the token a role with only `VM.Audit` and `VM.Clone` leaves it exactly those two there.
  Then, each from the code:
  - destroy, convert, and change any option including `protection` are refused: they need
    `VM.Allocate` or `VM.Config.*`;
  - changing that entry is refused: `check_perm_modify` needs `Permissions.Modify`, or
    `VM.Allocate` on that path;
  - adding the template to a pool is refused: `Pool.pm` calls the same `check_perm_modify` on the
    VM;
  - deleting its disk directly is refused: `Datastore.Allocate`, withheld by ADR-0009;
  - attaching its disk to another VM is refused: `check_volume_access` asks for
    `VM.Config.Disk` on the owning VM;
  - **cloning is allowed**: `clone_vm` asks for `VM.Clone` on the source, plus `VM.Allocate` on
    the new VM's id or on the pool it goes into.
- **But one route needs `protection` as well.** Creating a VM accepts `VM.Allocate` **on a pool**
  in place of `VM.Allocate` on the VM's own id, and with `archive` and `force` that creation is a
  **restore over an existing VM**, which replaces it (`Qemu.pm`'s create; one restore path,
  `restore_tar_archive`, destroys the old VM first, "cleanup first"). The token can make a pool and holds `VM.Allocate` in
  it. So the entry alone does not stop "restore any backup over the template, naming a pool". The
  restore does check `protection` before overwriting, and with the entry in place the token
  cannot clear it. **So the template needs both: the entry and `protection: 1`.**
- **A pool cannot be the protection.** Roles granted on a pool are added to its member VMs only
  where the VM's own path has not set that role already; they can add, never take away. The one
  exception is `NoAccess` in a pool, which removes everything, cloning included
  (`RPCEnvironment`, "only use role from pool ACL if regular ACL didn't already set it"). And the
  template must be in no pool where the token holds rights, or those rights are added back.
- **The token can restrict itself.** `ACL.pm` lets a caller without `Permissions.Modify` hand out
  any role whose privileges it already holds on that path, `NoAccess` excepted. So a token can put
  the restricting entry on a VM it just made, locking itself out. Creating the role itself needs
  root. Noted for question D; not relied on.
- **Linked clones survive their template.** On LVM-thin, a clone of a template is a thin copy
  that shares unchanged blocks, and Proxmox's own comment says the base can be deleted without
  affecting the clones (`LvmThinPlugin.pm`). So an old template can be retired while clones of
  it still run.

**Proxmox has no quotas.** `Pool.pm` has no limit of any kind. Nothing in
Proxmox caps how much memory, CPU or disk the scoped token's VMs may use.

**Cloud images do not include the guest agent.** Read on 2026-10-15, from the
publishers' package manifests: Debian 13 `genericcloud` (build 20261001-2618) and Ubuntu 26.04
server cloud image both include `cloud-init` and not `qemu-guest-agent`. AlmaLinux 10 GenericCloud
does include it (its build role, `ansible/roles/gencloud_guest`, read on GitHub), but see below:
included is not usable.

**Proxmox's cloud-init drive** (Proxmox writes a small virtual CD per VM that cloud-init inside the
guest reads at boot) can set a user, password, SSH keys, addresses and DNS, and `ciupgrade`, which
**defaults to 1: a full package upgrade at first boot** (API schema). It cannot install a package.
A custom cloud-init file (`cicustom`) must sit on a storage with `snippets` content, which a default
Proxmox host has none of, and only root may name one (`check_volume_access`).

### Measured on 2026-10-15: the guest agent against SSH

Two throwaway VMs, both destroyed. Full results, with run ids, in procedure 024.

**First attempt, scoped API only (VM 9900, AlmaLinux 10, no network card).** The image downloaded
through `download-url` (checked by Proxmox against AlmaLinux's SHA-256), imported, booted, and its
agent answered `ping`. But `exec` was refused: "Command guest-exec has been disabled". RHEL-family
images run the agent with a filter that blocks commands and file access. A seed disc to lift it,
to be fetched by `download-url` from a short-lived web server on another host, never reached the
Proxmox host:
Claude Code's own safety check stopped the step, as it weakens a security setting. The scoped
token cannot delete what it downloads (`Datastore.Allocate`), so the image stayed until procedure
024's root clean-up.

**Procedure 024 (VM 9901, Debian 13, seed disc made by root).** The recommended build, C1,
rehearsed: the agent answered **70 s** after first start, including installing it over the network,
and **20 s** after a reboot, started by the device appearing (its unit is `static`). No account had
a usable password. The same tasks through both channels, SSH to an enrolled host standing in for
an enrolled VM:

| task | guest agent | SSH through nervus |
|---|---|---|
| one short command | 2 calls (start, then poll) | 1 call |
| 18,893 bytes of output | 2 calls, all of it returned | 1 call, all of it returned (cut at 32 KiB) |
| a 60-second command | start, then poll: 5 calls | `exec_bg`, then `job`: 4 calls |
| write a 4 KB file | 1 call, the text in it | 1 call, the text in it |
| 32 MiB out, by `export` | 1 call, **38.6 s (0.87 MB/s)** | 1 call, **1.4 s (24.5 MB/s)** |
| make the VM reachable by SSH | 3 calls, 9 s (read nervus's public key, create `agent` with it, read the host key) | — |

What that means for tokens:
- **Each command costs one extra call** through the guest agent: the start returns only a process
  number. What the command prints costs the same either way.
- **Output is cut only by accident.** SSH `exec` returns at most 32 KiB and keeps the rest on the
  host. A guest-agent poll returns everything, and the `proxmox` tool refuses any response over
  256 KiB outright, so a command with large output returns either a lot or nothing. **A real
  client's use of a VM over nine days** (nervus's log; deployment note 0017): about 2.2 calls a
  command; status results under a kilobyte at the median, but one in ten over 170 KB (roughly
  40,000 tokens each), most of it file content moved before `export` existed.
- **Files move 28 times faster over SSH**, for the same one call.
- **Setup is cheap.** Making a VM SSH-ready through the guest agent took three calls, and its host
  key arrived over a channel the network cannot tamper with. What is not measured is nervus
  learning about the VM, which today is a root edit on the nervus machine.

### Found while reading, outside this ADR's question

- **nervus's own container had no `protection`.** The LXC version of the restore route above
  exists too: `PVE/API2/LXC.pm` accepts pool `VM.Allocate` for a restore over an existing
  container. Two things stop it today: the container must be stopped first, and
  only nervus holds the scoped token, so the token can only be used while nervus runs. That is a
  coincidence, not a boundary. Question K.
- **`local` is the host's own root filesystem** (`/var/lib/vz`, on `pve-root`, Proxmox's default
  layout). The scoped token can fill it with downloads and backups. ADR-0009 decision 6 moved
  nervus's disk off the thin pool; it did not cover this. Filling the host's root filesystem would
  not fill nervus's disk, but it would disturb the host nervus runs on. Question K.

## Questions

### A. What a client gets

1. **A template, copied as a linked clone through the API.** The guest agent is installed and
   enabled in the template. A clone is a thin copy: it takes seconds and almost no disk until the
   clone writes. Any client whose allowlist includes the scoped entry may clone, exactly as it may call the
   `proxmox` tool today. Nothing new in nervus.
2. A bare cloud image every clone customises at first boot (question C3). Slower, and each clone
   depends on the internet.
3. A nervus tool that makes a VM. Question L.

*Recommended: 1.*

### B. Which operating system

1. **Debian 13, the `genericcloud` image.** Small (a few hundred MB),
   long support, and what most people running headless Linux at home already know. The agent is
   installed from Debian's own archive.
2. Ubuntu 26.04, an image the first installation already had. Larger, and with snaps.
3. An image that already includes the agent (AlmaLinux 10 GenericCloud). Measured: its agent
   blocks commands and file access, so it needs a build too (C4), and it is a different family from
   what the first installation runs.
4. Several, from the start.

*Recommended: 1.* One template first; a second OS is the same procedure with a different image,
once one has been used.

### C. How the template is built, without SSH into it

The image has to gain the agent once. Options:

1. **A builder VM, booted once from a seed disc.** Root writes two small cloud-init files, kept
   in this repository, onto a disc image with `genisoimage` (installed with Proxmox) and places it in
   `local:iso`. A VM built from the checked Debian image boots once with that disc. Cloud-init
   reads it ("NoCloud", the same mechanism Proxmox's own cloud-init drive uses), installs and
   enables `qemu-guest-agent`, and nothing else: no user, no password, no key. The procedure then
   checks **through the agent itself** that it answers and is enabled, and has the guest clear
   everything that must differ per clone (`cloud-init clean --logs --seed --machine-id`, and SSH
   host keys), then shuts it down. The disc is removed, Proxmox's own cloud-init drive is added,
   and the VM becomes the template. No host package changes, no storage configuration changes.
2. Edit the image offline with `virt-customize`. Needs `libguestfs-tools` installed on the host, a
   large package set on the hypervisor.
3. The template never boots; every clone installs the agent at its first boot from a cloud-init
   file the template names. Needs `snippets` content enabled on a storage (a storage
   configuration change), and every clone needs the internet and a minute or more before its
   agent answers.
4. An image that already has the agent (B3): import and convert, through the scoped API alone.
   Tried with AlmaLinux on 2026-10-15: the agent answers, but refuses commands and file access
   until its filter is lifted, which is a build of its own.

*Recommended: 1.* It changes nothing on the host but two files and the VMs themselves, and it
proves the agent works before the template exists. For a published nervus it is a script the user
runs once as root on their Proxmox host, the same shape as enrollment (ADR-0011): this procedure
is that script's first, reviewed run. **Rehearsed by procedure 024, and it worked.** A variant
needs no root on the hypervisor at all: `download-url` can fetch the seed disc from any address
the host can reach, as it fetches images, and nervus could serve it as it serves exports.
Not tried (Context, first attempt). For a published nervus it deserves its own decision, since it
would let a user with only an API token build a template.

### D. How the template is refreshed

Cloud images go out of date, and a template never runs, so it never updates itself.

1. **A new template beside the old one**, by re-running the same procedure on a newer image. Each
   carries the image's build date in its name and description (for example
   `nervus-debian-13-20261001`), so an agent can see its age. The old one is retired, by root, once
   the operator chooses; clones of it keep running (Context, linked clones). **On demand**, when
   the operator asks, not on a schedule.
2. The same, on a fixed schedule, such as monthly. Something has to run it, and the build needs
   root.
3. Let the token build refreshed templates itself and lock itself out of each one (Context, "the
   token can restrict itself"). Root still makes the role once and sets `protection`'s backstop.
   Possible, but a template any client can make is a template any client can fake; see
   Consequences 4.

*Recommended: 1.* Clones turn `ciupgrade` off (question F), so freshness comes from the template.

### E. How the template is protected from agents

The scoped token holds `VM.Allocate` on every VM but nervus's own, so without protection any client
could destroy or change the template. Context lists what Proxmox's code does.

1. **A role `NervusTemplateUse` with exactly `VM.Audit` and `VM.Clone`, granted on
   `/vms/<template>` to `nervus@pve` and its token, plus `protection: 1`, and the template in no
   pool.** The entry stops destroying, changing, snapshotting, starting, converting, re-permitting
   and pooling. `protection` stops the pool-restore route. Clients can still see it and clone it.
   Set by root in the build procedure.
2. `protection: 1` alone. Any client can clear it (Context).
3. `NoAccess` on the template. It stops cloning too.
4. A pool. Pools only add rights (Context).

*Recommended: 1.* It is ADR-0009's pattern for nervus's own container (an entry on the path, enforced by
Proxmox), narrowed from "nothing" to "look and copy". When root destroys a template to retire it,
Proxmox removes that path's entries with it, so a template id reused later starts unprotected; the
procedure sets them again, and the verification checks them.

### F. What a clone is, by default

A clone may live for a minute or for years (Context), so the defaults assume neither.

1. **Small, credential-free, and patched for as long as it lives**, set in the template so a plain
   clone inherits it, as nervus's defaults: 2 vCPU, 2 GiB memory, a 16 GiB disk, the guest agent,
   a serial console, Proxmox's cloud-init drive with `ip=dhcp`, `onboot=0`, on the host's default
   bridge (`vmbr0`, settable when the template is built). **No user, password or SSH
   key.** The build makes sure Debian's automatic security updates (`unattended-upgrades`, in the
   image by Debian's package list) are switched on, so a clone that lives a year keeps patching
   itself; whether Debian's image switches them on by itself is not checked. **`ciupgrade=0`** in
   the template, so a clone's agent answers within seconds of boot; a clone meant to last can set
   `ciupgrade=1` before its first start, to upgrade everything then. Size, memory and `onboot` are
   the clone-maker's to change: defaults, not limits.
2. The same, with `ciupgrade=1` for every clone. Every first boot then waits minutes for a full
   upgrade, which a 60-second test pays for nothing.

*Recommended: 1.*

**Amended 2026-11-15, decided by the operator.** Two things a clone takes from its template, each
found by a trial and neither decided until now, put to the operator together:

- **The processor model.** The template set none, so a clone got the hypervisor's default model:
  an old baseline, without instructions that newer programs are built for. One such program,
  tried in a clone, ran without end until that VM was given a newer model (procedure 032). Asked
  which model the template should set, the operator chose **"The host's own (Recommended)"**, over
  a fixed baseline (`x86-64-v3`). The template is built with `cpu: host`: a clone sees the
  processor its host has, so what the hardware can run, runs. It is the usual choice for a single
  host. Its cost is that a running VM cannot be moved live to a host with another processor, so,
  like the bridge and the storage, it can be set when the template is built (`CPU_MODEL`). A
  default, not a limit, as size and memory are.
- **The template's protection, tag and description.** A clone inherits all three (order of work,
  step 3): the hypervisor copies a template's configuration, and the template itself must keep
  `protection: 1` (question E). The recipe has the clone-maker set its own (step 4), and each
  trial since set them by hand (procedures 042, 047). Asked how a clone should lose them, the
  operator chose **"Say it where agents read (Recommended)"**, over nervus clearing them itself
  after a clone. The hypervisor's behaviour stays, and a VM meant to last keeps its protection.
  The `proxmox` tool's own description, which every client is shown, says what the recipe says:
  on a clone, set `protection=0` for a VM you will destroy, and your own tag and description. The
  tool stays a pass-through.

**On the home network.** The default bridge is usually the home network, so a clone can reach
everything the host's other VMs can. With no
credential and no listening login, there is nothing on the clone to log into from outside. What
the clone itself reaches is the agent's business, as with any host (ADR-0001 s5). A separate
network for agents' VMs needs a host network change (SDN, withheld by ADR-0009) and belongs with the
network's own egress rules, not here.

### G. Where agents' VMs go

1. **A pool, `agents`, as a label, not a boundary.** The recipe (question L) clones into it, so
   the operator, and the UI later, can see every agent-made VM at a glance and clean up. It
   cannot be enforced: the token holds `VM.Allocate` on every VM, and ADR-0009 gave agents "any VM
   on it" on purpose. Linked clones live beside the template, on its storage (by default
   `local-lvm`); Proxmox refuses a
   different storage for a linked clone ("parameter 'storage' not allowed for linked clones").
   Template ids from **9000** by default, clones from Proxmox's next free id.
   Which client made which clone is in nervus's audit log (the `clone` call and its result);
   Proxmox's own task log shows only `nervus@pve!nervus` for every client. Every agent-made VM
   goes here whatever its lifetime, tagged with what was intended (question I); a production VM
   can be moved to a pool of its own by whoever owns it.
2. Enforce it, by moving the token's `VM.Allocate` from `/` to the pool. That removes it from
   every VM outside the pool, which ADR-0009 decided against.
3. No pool.

*Recommended: 1.*

### H. How much they may use

Proxmox has no quota (Context). On the first installation's host there was ample room in the thin
pool and memory, and none for a separate fixed store (deployment note 0017).

1. **No limit beyond the machine's, with small defaults (F) and a stated expectation** in the
   client instructions: destroy what you make, and don't start more than you need. Running out
   costs agents' and other VMs, not nervus: nervus's disk is on its own storage (ADR-0009
   decision 6). If memory runs out, Linux's out-of-memory killer ends the process using the most,
   which would be a VM, not nervus's small container; that is general Linux behaviour, from memory, not
   tested here.
2. A ceiling counted by nervus, refusing clones past it. That is nervus filtering calls, which
   ADR-0001 s5 rejects, and an agent could still allocate by other API calls.
3. A dedicated, fixed-size storage for clones. The first installation had no unallocated space for it.

*Recommended: 1.* Revisit when real use shows a need; the audit log will show who used what.

### I. Lifetime and cleanup

1. **Whoever asks for the VM decides how long it lives, and the recipe records that on the VM as a
   Proxmox tag: `ephemeral` (the agent destroys it when its task ends) or `long-lived` (kept until
   someone decides otherwise).** An `ephemeral` VM still present after its task is the one to
   question, and the operator removes it. No automatic deletion. Tags are set with
   `VM.Config.Options`, which every client holds, so they record intent, not permission.
2. Also an expiry date on `ephemeral` VMs (`nervus-expires-YYYYMMDD`) and a sweep in nervus that
   destroys them past it. nervus would then act on the host on its own initiative, recorded as
   nervus rather than as a client: a new kind of actor, which deserves its own decision.
3. A sweep run by root on the host (a timer). Outside nervus, so outside its audit log.

*Recommended: 1 now, 2 considered after real use.* An expiry is easy to add later; a sweep that
destroys the wrong VM is not easy to undo.

### J. Which channel agents use inside a VM, and VMs joining nervus's inventory

Measured (Context): through the guest agent each command costs one more call than over SSH, output
comes back uncut up to 256 KiB and is refused beyond it, files move 28 times slower, and there are
no background jobs that survive a disconnect. Its strengths: it works from first boot, needs no
network path, account or key, and needs no setup. Making a VM SSH-ready through it took three calls
and nine seconds. What is left is nervus learning about the VM, which today is a root edit on the
nervus machine.

1. **Both, each for what it is good at.** The guest agent is how every VM starts and how a broken
   one is recovered, and it is enough for a short test. A VM that will do more than a handful of
   commands, move files, or live is **enrolled into nervus's SSH inventory through the guest
   agent**: an `agent` account with nervus's public key, and the VM's host key pinned from the
   guest agent's answer, never from the network. It is then a host like any other, with `exec`,
   `exec_bg`, `job`, `put`, `get` and `export` at network speed. This lifts ADR-0009 decision 8's
   deferral, which was "without conditions". **How enrollment works is its own ADR, the next one**:
   the inventory becoming something nervus writes (ADR-0005 consequence 5); which clients may
   enroll a VM and which then reach it; removing the entry when the VM is destroyed; and whether
   it is one nervus action rather than a recipe. This ADR only keeps the template ready for it:
   OpenSSH installed and running, and no account that would clash with `agent`.
2. Guest agent only, as the first draft had it. Every command costs an extra call; files move at
   under 1 MB/s; a production VM is never a first-class nervus host.
3. SSH only, with nervus's key built into the template. Every clone, a 60-second test included,
   would carry nervus's key from birth, and nervus would have to know about VMs that live a minute.

*Recommended: 1.* Enrolling costs about three calls; the guest agent costs one extra call per
command. So enrollment pays for itself after about three commands, before counting files and long
jobs, and sooner once it is one nervus action. For a short test, the guest agent wins.

### K. The two findings: nervus's own container's `protection`, and `local`

1. **Set `protection: 1` on nervus's container in the same root procedure; record the `local` exposure and
   change nothing there yet.** Protection closes the container restore route by Proxmox's own
   check, rather than by the coincidence that nervus is the token's only user. It does not stop
   starting, stopping or rebooting the container, and the deploy scripts do none of what it blocks (it
   blocks destroy, disk removal and restore). For `local`, the remedies all cost something
   (taking `Datastore.AllocateTemplate` or backups away from agents, or moving `local` off the
   root filesystem), and nothing has filled it.
2. Leave both as findings.
3. Act on both now.

*Recommended: 1.* One line in a procedure already being written, against a route that ends at
nervus's own container.

### L. Making "clone, use, destroy" easy, and how far to generalise beyond Proxmox

nervus's principle is that it passes requests through to the target's own permission system
rather than curating operations: ADR-0001 s5 for SSH, ADR-0009 decision 2 for Proxmox, which
rejected curated `proxmox_*` tools. Other hypervisors have the same pieces, under other names:

| concept | Proxmox | VMware vSphere | Hyper-V | libvirt |
|---|---|---|---|---|
| **template**: a master copy clients may copy, not change | VM template | VM template | exported VM / parent disk | a base image, copied by hand |
| **clone** | linked or full clone | linked or full clone | differencing disk | backing-file image |
| **guest channel**: commands and files inside the guest, no network or login | QEMU guest agent | VMware Tools, Guest Operations API | Integration Services, PowerShell Direct | QEMU guest agent |
| **area**: where agents' VMs go | pool | folder or resource pool | (none built in) | (none built in) |
| **limit** | none | resource pool limits | per-VM settings only | none |
| **protection** of the template | permission entry plus `protection` | role on the template's object | Windows permissions | polkit rules |

What the guest channel can do differs too: vSphere's guest operations need a user and password
inside the guest, where QEMU's agent needs none; Hyper-V's PowerShell Direct needs a Windows
host.

**How agents do "clone, use, destroy" here:**

1. **A recipe in the client instructions (procedure 005), with no new nervus tool.** The exact
   `proxmox` calls: find the newest template (`/cluster/resources`, `template: 1`, name
   `nervus-*`), clone it into `agents` (`/nodes/{node}/qemu/<template>/clone`, `newid` from
   `/cluster/nextid`) and tag it `ephemeral` or `long-lived` (I), start it, wait until the agent
   answers (`agent/ping`), run commands (`agent/exec` with `/bin/sh` and the script in
   `input-data`, then `agent/exec-status` until it reports exited), take files out with `export`,
   and, if `ephemeral`, stop and destroy it (`DELETE /nodes/{node}/qemu/<id>`, `purge=1`). Two rules
   that save tokens, from the measurement: **send output that may be large to a file and `export`
   it**, because a status poll returns all of it, and over 256 KiB returns nothing; and **enroll a
   VM that will do more than a few commands** (J), once enrollment exists. Tested as written, as
   ADR-0016 step 5's instructions are.
2. A tool, `vm`, that does the steps for the agent. Shorter calls, but it is the curated
   `proxmox_*` tools ADR-0009 rejected, and Proxmox's own task output says more than a wrapper
   would.

**How far to generalise:**

1. Proxmox only, and no shared vocabulary. Cheapest now; a second backend may then reshape what
   was built.
2. **Name the concepts now (the table above), keep one passthrough tool per backend, and put a
   small internal interface only where nervus itself does work inside a guest.** That is ADR-0016's
   VM source today (reading a file through the guest channel) and the upload target next (writing
   one). A second backend would then be a new passthrough tool (for example `vsphere`) plus one
   implementation of "read a file, write a file, run a command, through the guest channel", not a
   redesign. The client instructions describe the recipe in these terms, with Proxmox's calls as
   its first instance. `export`'s `vmid` parameter is Proxmox's word; a second backend would add a
   field saying which hypervisor, without changing this one.
3. A generic layer: `vm_create`, `vm_exec`, `vm_destroy`, mapped onto each hypervisor. **What it
   costs against the principle:** nervus would decide which operations exist and what they mean;
   it would have to translate each backend's permissions into its own, which puts the boundary
   inside nervus, and a filter nervus applies to itself is a policy, not a boundary (ADR-0005 s5);
   it offers only what every backend shares, so a Proxmox user loses what Proxmox has; every new
   backend feature waits on nervus; and agents, which already know Proxmox's API, would learn a
   second, poorer one.

*Recommended: recipe 1, and generalisation 2.* Implement Proxmox only.

## Consequences

1. Any client with the scoped entry in its allowlist can make, use and destroy a VM with no root, no SSH
   into the guest and no new credential: the API call is the whole of it, and every step is in
   nervus's audit log and Proxmox's task log.
2. **The guest agent is root inside every clone, and the scoped token reaches every clone's
   agent.** Any client can run anything in any other client's clone. That was already true of
   every VM (ADR-0009 consequence 1); clones only make more VMs. It is ADR-0007 decision 10's
   single trust domain.
3. Templates change only by root, through a procedure. A refresh is the operator's call (D1).
4. Any client can still make a VM, convert it to a template and name it like ours. What
   identifies the real one is `protection: 1` and the restricting entry, which only root (or the
   token, on a VM it just made, D3) can set, and the client instructions say to check them. A
   client planting a lookalike gains nothing it did not already have: it could act inside the
   other client's clone directly (2).
5. Agents' VMs share the thin pool and memory with the host's other VMs. A leak costs other work
   before it costs nervus.
6. **Until enrollment exists (J), agents work inside VMs through the guest agent**, at one extra call
   per command and under 1 MB/s for files. That is fine for tests and costly for anything sustained;
   the enrollment ADR is what removes it. A long-lived VM made before then can be enrolled later
   without being rebuilt, since enrollment needs only the guest agent.
7. For a published nervus: the build becomes a script the user runs once as root on their Proxmox
   host, kept in this repository with its seed files, and the client instructions become a page
   of the documentation. The scoped token, role and permission entries are already root's to make
   (`tools/proxmox-access`, ADR-0009); this adds one role and two entries per template.

## Order of work

Each step waits for the operator (rule 1).

0. The operator's decisions on A to L. (Procedure 024 already measured the channels and
   rehearsed C1's build on a throwaway VM, 2026-10-15.)
1. **The build files**: the two cloud-init seed files and the build script, in this repository,
   with a test that the seed files are valid cloud-config. Procedure 024's seed files are the
   starting point, with `unattended-upgrades` switched on added. Committed before anything runs.
   **Done 2026-10-15:** `tools/proxmox-template` (renamed 2026-10-16, ADR-0019 C), one self-contained root script with both seed files
   inside it, and its tests, now `tests/test_proxmox_template.py` (each guarantee broken on purpose
   and seen to fail one). The script also has cloud-init check the seed inside the builder
   (`cloud-init schema --system`), which no test off a Proxmox host can. Its Proxmox commands were
   checked against the host's own help, read-only (deployment note 0017): `qm agent` is now
   `qm guest cmd`, and `/pools` lists no members, so the pool check reads `/cluster/resources`.
2. ~~**Procedure 025, written before it runs, for approval**, run through the full level with each
   step's state read first: fetch the Debian image and check it against Debian's published
   SHA-512; make the seed disc; create the role; build, boot and check the builder VM through
   its agent; clear it; make it the template; set the entry and `protection`; set `protection` on
   nervus's container (if K1). Nothing here restarts nervus or touches other VMs.~~
3. ~~**Verification** (below), through the scoped token, as an agent would.~~ **Steps 2 and 3 done
   2026-10-15** by procedure 025: the first template, and protection on nervus's container; items 1 to 6 and item
   7's first half observed. Found: a clone inherits the template's `protection: 1` and description,
   which the recipe deals with (step 4).
4. ~~**The recipe** in procedure 005, tested as written.~~ **Done 2026-10-15**: step 6 of
   procedure 005, run as written for an `ephemeral` VM (item 8).
5. The next session clones the template to measure uploads (CURRENT_STATE, item 2).
6. **An ADR for enrolling VMs into nervus's inventory** (J1), before or beside uploads, at the
   operator's choice of order.

## Verification

Moves to Accepted when all of the following are observed on an installation's Proxmox host through
nervus, not asserted:

1. Through the `proxmox` tool (the scoped token, which every client shares): clone the template
   into `agents`, start it, see the agent answer, run `id -u` through the agent and get `0`, and
   destroy it, with no root, SSH or credential at any step. Each step is in nervus's audit log.
   **Observed 2026-10-15** (procedure 025 step 4).
2. The clone's agent answers again after the clone reboots. (Already seen on procedure 024's
   Debian VM, whose agent is started by the device appearing.) **Observed 2026-10-15** on a clone
   of the first installation's template (procedure 025 step 4).
3. Two clones made one after the other have different machine ids, MAC addresses, DHCP
   addresses and SSH host keys. **Observed 2026-10-15** (procedure 025 step 5).
4. A clone holds no credential: no password set for any account, no key in any
   `authorized_keys` file (cloud-init leaves an empty one for root, as procedure 024 saw), and the
   template's configuration has no `ciuser`, `cipassword` or `sshkeys`. Automatic security updates
   are switched on in it. **Observed 2026-10-15** (procedure 025 step 5).
5. The scoped token is refused, by Proxmox, each of these on the template: destroy; any
   configuration change, `protection: 0` included; snapshot; start; convert; changing its
   permission entry; adding it to a pool; restoring a backup over it through a pool; deleting its
   disk; attaching its disk to another VM. The refusals that cannot be tried without risk if the
   protection were wrong (restore, delete) are tried against a disposable protected test
   template made for the purpose, not the real one. Each refusal is in nervus's audit log.
   **Observed 2026-10-15** (procedure 025 step 6), each with the reason predicted. The restore
   through a pool passed the permission check and was stopped by `protection`, as the Context
   says.
6. A template retired by root leaves a running linked clone of it working. **Observed 2026-10-15**
   on a disposable template (procedure 025 step 7).
7. If K1: `pct config <nervus's id>` shows `protection: 1`, and the container still stops and
   starts by the operator's hand. The restore route is accepted on the code reading above, as
   ADR-0009 accepted the backup of nervus's container it could not safely prove. **First half
   observed 2026-10-15** (procedure 025 step 3); the operator's restart (step 8) not done. **The second half accepted by the operator on
   2026-10-16 on the code reading**: Proxmox checks `protection` on a container only when restoring
   over it or destroying it (`PVE/API2/LXC.pm`), never when starting or stopping it.
8. The recipe in procedure 005, run as written by a client: an `ephemeral` clone ends
   destroyed with nothing left in `agents`, and a `long-lived` one stays, tagged. **The
   `ephemeral` half observed 2026-10-15** (procedure 005 step 6, run as written); the
   `long-lived` half is the same steps without the last, and was not run. **Accepted by the operator
   on 2026-10-16 as those same steps without the destroy**, the clone keeping the template's
   `protection: 1`.
