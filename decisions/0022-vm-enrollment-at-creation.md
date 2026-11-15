# ADR-0022: a VM joins nervus when it is made — enrollment through the guest agent, with no DNS

**Status:** **Accepted 2026-10-19, at the operator's word** ("Mark ADR-0022 Accepted"), every
verification item observed, on real VMs (procedure 033) or in tests, as marked at each, and deployed
(procedure 034). **Decided by the operator on 2026-10-18**, in a Claude Code session: questions 1 to
10, each as the drafting session recommended ("ADR-0022: all as recommended"), and, after step 1, a
VM that cannot be enrolled is tried again at every call (under question 3). Each question keeps its
options, so the record shows what was not chosen.
**Date:** 2026-10-18
**Asked for by:** the operator, as item 2 of the order before friends are invited
(`CURRENT_STATE.md`, "Install and host enrollment"), and in the requirement quoted in Context, given
during ADR-0021's VM trial (procedure 032).
**Builds on:** ADR-0001 s4 and s5 (the `agent` account, host keys pinned with strict checking, the
boundary is the target's); ADR-0005 decision 5 and consequence 5 (read-only enrollment; the inventory
becomes state nervus writes); ADR-0009 consequence 1 and decision 8 (the scoped Proxmox token reaches
every VM's guest agent; new VMs' enrollment deferred); ADR-0011 decisions 1 and 3 (enrolled hosts in
the database; a host is enrolled by a command a person runs as root); ADR-0017 J1 and L2 (VMs that do
more than short work are enrolled through the guest agent, how being "its own ADR, the next one"; one
internal interface for nervus's own work inside a guest); ADR-0020 E1 (a VM pulls an upload from
nervus); ADR-0021 B1 (nervus's issuer is limited to DNS names; addresses stay unlimited)
**Written to the policy of ADR-0019:** this record names no system; the evidence is in the
procedures it cites.

## Context

### The requirement

The operator, 2026-10-18, during ADR-0021's VM trial:

> one VM is spun up and meant to be a part of work being done that an agent asked for, the agent
> should have a full proof way of giving it files receiving files from it and that should be
> established everything that that relationship depends on should be established when the VM is
> spun up.

And, the same day:
- this process gets **no administrative access to the firewall or to DNS**, and no person adds a
  DNS record per VM;
- host names are better than addresses for HTTPS, and in practice a DHCP server rarely moves an
  address;
- nervus "is supposed to handle the relationship between the agents and the machines that they go
  and access", VMs included.

### What a VM is to nervus today

- **An agent makes a VM** from a template through the `proxmox` tool, and uses it **through
  Proxmox's guest agent by VM id** (ADR-0017; `docs/clients.md`, "Make a VM, use it, and destroy
  it"). No DNS is involved anywhere, and nothing about the VM is written into nervus.
- **The guest agent is a channel nervus already trusts.** It is a virtual serial line between the
  hypervisor and the VM: no network, no login, and nothing on the network can tamper with it. Every
  token whose allowlist includes the hypervisor's entry is already root inside every VM through it
  (ADR-0017 consequence 2).
- **Files:** in by upload, which the VM pulls from nervus at network speed, or pushed through the
  guest agent at 0.17 MB/s under 32 MiB (ADR-0020, procedures 026 and 031); out by `export`, read
  through the guest agent at under 1 MB/s (procedure 024).
- **What enrollment would add** was measured in procedure 024: making a VM reachable by SSH took
  three guest-agent calls and nine seconds (read nervus's public key, create `agent` with it, read
  the host key), and then each command costs one call instead of two and files move 28 times faster.
  What was not built is nervus *learning* about the VM: today that is a root edit of `hosts.yaml` and
  `known_hosts` on nervus's machine, and a restart.

### Where names come in, by direction

Each connection needs the far end to be found, and, over HTTPS, to prove its name.

| connection | needs a name today? | why |
|---|---|---|
| nervus → VM, SSH | no | SSH checks the host **key**, not a name; nervus can connect by address |
| VM → nervus, an upload's pull | yes, once HTTPS is used | the VM's `curl` checks nervus's certificate against the URL's host |
| a person's client (Claude Code, Codex) → nervus | yes | the client checks nervus's certificate; it is told the URL once |
| a person's browser → a service an agent runs in a VM | only if HTTPS | outside nervus today |

**What testing showed:**
- On the operator's machine, connected over a VPN, the trial VM **could not be reached by name**
  without a line added to that machine's `/etc/hosts`: the name was in no DNS the machine asked, and
  multicast DNS does not cross the VPN (procedure 032).
- Claude Code accepts nervus's certificate **by address** when the address is in the certificate's
  alternative names, under the two-layer authority (procedure 030, case F, on loopback). It cannot
  apply a name limit written as an address, which is why ADR-0021 B1 limits the issuer to DNS names
  and leaves addresses unlimited. A LAN address, and Codex by address, are not yet tested.

### Found while reading, which the requirement turns into questions

1. **An upload's pull does not survive HTTPS.** The script nervus runs in the VM calls `curl` with no
   certificate to trust (`upload_targets.py`, `PULL_SCRIPT`). Against an HTTPS nervus, the VM refuses
   nervus's certificate, the pull fails, and nervus falls back to the guest-agent push: 0.17 MB/s,
   and nothing over 32 MiB. The first installation pulls over plain HTTP, so this has not shown yet.
2. **A fresh install sets no pull address.** `docs/install.md` never gives `--upload-pull-url`, so
   on a friend's nervus every VM upload takes the slow push.
3. **`tls-init` already accepts an address** as a `--name`, and writes it into nervus's certificate,
   outside the issuer's limit (`tls.py`, `_split_names`; ADR-0021 B1). The install doc does not say
   so, and says names "cannot be added later". For DNS names that is true: the issuer's limit is
   fixed when it is made. For an address it is only true of today's commands: the issuer could sign
   a new certificate for nervus with a new address, and every client's saved root would still hold.

## Questions

### 1. What this ADR covers

Item 2 opens with "an ADR that maps the ways people will install nervus", then an installer, then
enrollment (ADR-0011 decision 3) with read-only access (ADR-0005 decision 5).

- **a. VMs here, and the inventory becoming state nervus writes; the install map and host
  enrollment by a person's root command in a companion ADR, next.** The VM half has a requirement in
  the operator's words and depends on no installer. The host half depends on the install map (where
  nervus runs decides what an enrollment command can reach).
- b. One ADR for all of item 2. Larger, and the install map would hold up what the requirement asks
  for now.

*Recommended: a.* A host and a VM differ in one thing that decides the design: for a host, the
person standing at it is what nervus trusts, so they run the command (ADR-0011 decision 3); for a
VM nervus can reach through the guest agent, that channel is what nervus trusts, so no person is
needed. The two share the database (ADR-0011 decision 1) and nothing else.

### 2. When a VM is enrolled, and who starts it

The requirement: everything the relationship depends on is in place by the time the agent uses the
VM, with nothing for anyone to add by hand.

- **a. nervus enrolls a VM in the first nervus call that names it.** Any nervus tool given a VM
  id (question 4), `export` included, finds the VM not yet enrolled, enrolls it through the guest
  agent (question 3), and carries on with the call. An upload enrolls only if the VM's own pull
  fails, since the pull is faster than SSH (question 7). The agent does nothing extra, and cannot forget a step. The first
  call takes a few seconds longer. Recorded under that client's token and run id.
- b. nervus enrolls a VM when a client starts it through the `proxmox` tool, in the background,
  waiting for its guest agent. Closest to "when the VM is spun up" in time. But nervus would watch
  passthrough calls and act on its own afterwards, the new kind of actor ADR-0017 I2 held back; it
  misses VMs started any other way; and every 60-second test VM would get an account and nervus's key
  it never uses, which ADR-0017 J3 rejected.
- c. A tool, `enroll`, the agent calls once. Explicit, but it is one more step to remember, and an
  agent that forgets it falls back to the guest agent's slower path without knowing why.

*Recommended: a.* It meets the requirement as the agent sees it: from the first thing the agent
does with a VM, files in and out and commands work, with nothing set up by anyone. It also checks
the relationship each time instead of trusting that it was made once (question 5). A VM used only
through the `proxmox` tool's guest-agent calls, such as a short test, is never touched.

### 3. What enrollment does, and where its trust comes from

- **a. nervus does it all through the guest agent, and the template is unchanged.** One fixed
  script, composed and quoted by nervus as uploads' are (ADR-0020 consequence 2), run as root in the
  VM:
  - creates `agent` if it is missing, with exactly nervus's public key in `authorized_keys` and a
    `sudoers.d` file giving it passwordless `sudo`, checked by `visudo -c` (ADR-0001 s4);
  - makes sure `sshd` is running, and waits for the VM's host keys to exist;
  - prints the host public keys.

  nervus then reads the VM's addresses (`agent/network-get-interfaces`), pins the host keys **as the
  guest agent reported them, never as the network offers them**, connects by SSH with strict
  checking, and runs `id -un; sudo -n id -un` expecting `agent` and `root`. Only then is the VM
  enrolled. Works for any VM with a working guest agent, `sshd`, `sudo` and `useradd`, the template's
  clones included (the trial VM had all of them, procedure 032); otherwise it fails with the reason,
  and the guest agent stays usable.
- b. The template carries an `agent` account with no key; enrollment adds the key. Saves one line of
  the script, and every template must be rebuilt.
- c. The template carries nervus's key. Rejected by ADR-0017 J3: every clone, a 60-second test
  included, would carry nervus's key from birth.

*Recommended: a.* The guest agent is the trust anchor, as a person at the console is for a host.
What it reports can only be lied about by root in that VM, who is root there anyway. **A VM that
reports another machine's address gains nothing:** nervus checks the host key before it offers its
own key (asyncssh verifies the server first), so the other machine's key fails the check and nervus
never authenticates to it. VMs are always enrolled with full access: read-only enrollment
(ADR-0005 decision 5) is a person's choice for their own machine, and any client that reaches a VM
already holds root in it through the guest agent.

**A VM that cannot be enrolled: decided by the operator on 2026-10-18, after step 1** ("retry every
call"). This ADR did not say whether a failed enrollment is remembered. **nervus remembers nothing:
every call naming a VM that is not enrolled tries again**, and a failure says why each time. The
likeliest failure is a VM not ready yet, just booted, which the next call should enroll; a memory
would keep it on the slow path, and would need a length and a way to clear it. The cost falls only
on a VM that is really unenrollable: about two seconds a call for a missing tool, about ten for a
network that blocks SSH. Rejected for now: remembering a failure for a while, with its reason. It
can be added later as a table of its own if the trial (step 6) shows the cost matters.

### 4. How a client names an enrolled VM

- **a. By its VM id, as `export` and uploads already do: every tool that takes `host` also takes
  `vmid`.** The agent already holds the id: it made the VM with it. `hosts` lists enrolled VMs with
  their id, Proxmox name, address and when they were enrolled.
- b. A generated inventory name, such as `vm-123`, given as `host`. No tool changes, but a second
  name for the same thing, and one that tempts code to read meaning from a name (ADR-0019, rule 11).

*Recommended: a.* One handle across every tool, the one Proxmox uses. With one hypervisor entry per
installation (ADR-0019 D) an id is unambiguous; a second hypervisor would add a field saying which,
as ADR-0017 L2 foresaw.

### 5. Where the entry lives, and how it stays true

- **a. One database row per enrolled VM, keyed by VM id, holding its address, its pinned host keys,
  when and by which token it was enrolled. The row is checked at every use, and repaired or dropped
  from what the guest agent and the API say:**
  - **the address moved** (SSH times out or is refused): nervus reads the addresses again through the
    guest agent and retries once with the same pinned keys. A DHCP move costs one call, no person.
  - **the host key differs** (the VM was rebuilt, or the id was reused by a new VM after a destroy
    nervus did not see): nervus never accepts a key from the network. It asks the guest agent; if the
    guest agent reports the new key, the VM is enrolled afresh, and the answer and the log say "VM
    123's host key changed, as its guest agent reports; enrolled again".
  - **the VM is gone** (the API has no such id): the row is dropped, and the call fails saying so.
    `hosts` drops such rows too, with one `/cluster/resources` call.

  `hosts.yaml` and `known_hosts` stay as they are, for machines described by hand. Pins for VMs live
  in the database: host public keys are not secret, and `secrets/` stays read-only to nervus
  (ADR-0014 A).
- b. The same, plus removal when a client destroys the VM through the `proxmox` tool. Tidier lists,
  but nervus would watch passthrough calls (2b), and it still needs a's check for VMs destroyed
  elsewhere.
- c. Rows written into `hosts.yaml` and `known_hosts`. Text files nervus rewrites while clients read
  them: the hazards ADR-0011 decision 1 moved to the database to avoid.

*Recommended: a.* Nothing has to be removed for nervus to stay right, because nothing is trusted
without being checked against the VM. This is the first inventory nervus writes, which ADR-0005
consequence 5 foresaw.

### 6. Which tokens reach an enrolled VM

- **a. Every token whose allowlist includes the hypervisor's entry**, and no other. Those tokens are
  root in that VM through the guest agent already; SSH gives them speed, not reach.
- b. Only the token that enrolled it, plus tokens given it by hand. A restriction nervus applies to
  itself, while the others still reach the VM as root through the guest agent: a policy, not a
  boundary (ADR-0005 s5). And by-hand grants are the per-VM administration the requirement rules out.
- c. Per-VM entries in each allowlist. The same per-VM administration.

*Recommended: a.* It changes no one's reach, so it needs no new permission model. A friend who
wants a client kept out of VMs leaves the hypervisor entry out of its allowlist, as today.

### 7. Files, once a VM is enrolled

- **a. nervus takes the fastest route it has, and the answer says which.** `export` from a `vmid`
  reads over SFTP (24.5 MB/s against under 1 MB/s, procedure 024), enrolling first by 2a, and
  through the guest agent only if the VM cannot be enrolled. An upload to a `vmid` keeps the VM's pull first (36 MB/s, procedure 026),
  then SFTP when enrolled, which lifts the 32 MiB limit for an enrolled VM that cannot reach nervus,
  then the guest-agent push. The client's command does not change.
- b. Leave both as they are; an enrolled VM's files go through `get` and `put` as a host's.

*Recommended: a.* "A foolproof way of giving it files and receiving files from it" is one command,
the same one, whatever state the VM is in.

### 8. The VM reaching nervus, under HTTPS (finding 1 and 2)

- **a. nervus hands the VM what it needs, with each pull.** The pull script receives nervus's root
  certificate on standard input with the one-time secret, writes it to a temporary file, and gives it
  to `curl` as `--cacert`; nothing stays in the VM. The pull address names nervus **by address**,
  which nervus's certificate carries (question 10), so no DNS is asked. `docs/install.md` sets
  `--upload-pull-url` at install, from the address it names in the certificate.
- b. The same, but the pull address keeps a name, and the script passes `curl --resolve
  <name>:<port>:<address>`, so the VM checks the name without looking it up. Equally DNS-free, one
  more value to configure.
- c. Enrollment installs nervus's root into the VM's own trust store. Then only enrolled VMs pull
  fast over HTTPS, and every program in the VM trusts nervus's issuer (ADR-0021 F rejected this for
  client machines).
- d. The pull stays on plain HTTP even when MCP is HTTPS. What crosses is one file and a secret good
  for one fetch (ADR-0020 E1), but the file itself is then readable and alterable on the network,
  and the three-hash check (ADR-0020 B1) only catches the alteration afterwards.

*Recommended: a.* It fixes the HTTPS pull for every VM, enrolled or not, a 60-second test
included, and leaves nothing behind in it.

### 9. Where names still matter

With 2a to 8a, **no VM ever needs a name**: nervus reaches it by an address it reads through the
guest agent, and the VM reaches nervus by an address nervus gives it. Names remain where a person's
own program connects over HTTPS:

1. **nervus itself, named once at install.** Every client is told nervus's URL once. Question 10.
2. **A service an agent runs in a VM, reached from the user's browser**, such as a web app under
   test. Is that in scope?
   - **a. Not in this ADR.** The agent tells the user the VM's address and port, from `hosts`. Plain
     HTTP is the norm for a throwaway test service; one that needs HTTPS uses its own certificate,
     which a browser lets the user accept once. Nothing in nervus changes.
   - b. nervus forwards HTTP from the user to a port in a VM. A new reach for nervus, from the user's
     network into VMs, which ADR-0001 kept out of the tool surface; its own ADR if real use asks.
   - c. A name per VM. Needs DNS administration, which the operator ruled out.

   *Recommended: a.* The user's need is to look at the service, which an address meets. If agents
   come to build services users keep, a proxy deserves its own decision then.

### 10. Addresses in nervus's certificate, and a fresh install with no local DNS (finding 3)

The issuer must be limited to at least one DNS name, and the machine's hostname always counts
(ADR-0021 B1), so this is about what else the certificate names, and what the install doc tells a
friend.

- **a. `tls-init` names the machine's current non-loopback addresses by default, beside its
  hostname and any `--name`, and prints them. The install doc says: if nothing on your network
  answers for nervus's name, use its address in each client's URL, and reserve that address in
  your router if you can. A new command, `tls-reissue --name <address>`, re-issues nervus's
  certificate with an added address under the same issuer, so clients keep their saved root if the
  address ever moves.** Names in DNS stay the better choice where they exist, and the doc says so.
- b. Addresses only when the user passes them, as today, and the doc says how. The friend without
  DNS has to know to do it.
- c. Names only: no local DNS means a line in `/etc/hosts` on every client machine (procedure 032),
  or a `.local` name, which does not cross a VPN.

*Recommended: a.* It costs no trust: a stolen issuer key could already impersonate any bare
address (ADR-0021 consequence 3), so naming nervus's own adds nothing a thief lacks. It gives a
friend with no DNS a working URL with nothing to edit by hand, and the operator's note that DHCP
addresses rarely move is what makes an address good enough, with `tls-reissue` for the rare move.
Testing still to do: Claude Code and Codex by a LAN address over the network, not only loopback.

## Consequences

1. **For an agent:** make the VM, then use it with `vmid` in any tool. Commands, background jobs,
   files in and files out work from the first call; the guest agent remains for recovery and for a
   VM that cannot be enrolled. The recipe in `docs/clients.md` loses its "enrollment is not built
   yet" paragraph and most of step 5.
2. **For a friend:** nothing per VM, and nothing to give nervus but what install already asks.
   No DNS, firewall or router change; a router reservation for nervus's address is advised, not
   required.
3. **For nervus:** it writes inventory for the first time (a table beside exports' and uploads');
   it composes one more fixed script inside a guest (ADR-0017 L2's "run a command" half); `vmid`
   joins `host` on each tool; the pull script carries a root certificate.
4. **nervus's key ends up in every VM a client uses over SSH**, and nowhere else. A destroyed VM
   takes it with it; a VM kept for years keeps it until nervus's key is rotated, which ADR-0001 s3
   handles as removal from `authorized_keys`, and which for VMs nervus could do through the guest
   agent. Not designed here.
5. **Reach does not change.** Every token that can SSH into an enrolled VM could already run
   anything in it as root.
6. **The host half of item 2 waits for its companion ADR:** the install map, the installer, and
   enrollment of a person's own machine by a root command, with read-only access.

## Order of work

Each step is one module with its tests, and waits for the operator (rule 1).

0. ~~The operator's decisions on 1 to 10.~~ Done 2026-10-18: all as recommended.

**Reordered by the operator on 2026-10-18:** the two upload gaps (findings 1 and 2) come first,
ahead of steps 1 to 4, which they do not depend on ("do the two upload gaps first, ahead of
ADR-0022 steps 1 to 4"). They are taken out of step 5 as 0a and 0b.

0a. ~~The pull over HTTPS (8a): the pull script is handed nervus's root with the secret, and gives it
    to `curl`, leaving nothing in the VM; with tests.~~ Built 2026-10-18 (`1ed176e`), not deployed.
0b. ~~`docs/install.md` sets `--upload-pull-url` at install, naming nervus by an address its
    certificate carries; tested as written.~~ Done 2026-10-18 (`d772109`).
1. ~~The enrollment store: the table, the row's states, repair and drop (5a), with tests.~~ Built
   2026-10-18 (`enrollments.py`), not deployed.
2. ~~The enrollment step through the guest agent (3a): the script, the host-key pin, the SSH check,
   against a fake guest agent in tests.~~ Built 2026-10-18 (`guest.py`, `enroller.py`), not
   deployed. The shape of `agent/network-get-interfaces` is QEMU's, as documented, not yet read off
   a real VM; the trial (step 6) reads it.
3. ~~`vmid` on the tools (4a), enrollment on first use (2a), reach by the hypervisor entry (6a), and
   `hosts` listing VMs.~~ Built 2026-10-18 (`vm_targets.py`, `server.py`), not deployed. `host`
   becomes optional in each tool's schema. A VM call's audit records name `vmid`, not `host`; the
   audit viewer's host filter does not find them, which is not yet looked at in the UI.
4. ~~Files by the fastest route (7a).~~ Built 2026-10-18 (`exporter.py`, `upload_targets.py`), not
   deployed. An export's route is kept in a table of its own, `export_route`.
5. ~~`tls-init`'s addresses and `tls-reissue` (10a); `docs/install.md` (naming without DNS) and
   `docs/clients.md` (the recipe), tested as written. (The pull over HTTPS and the install's pull
   address moved to 0a and 0b.)~~ Done 2026-10-18 (`60f526c` and the docs after it), not deployed.
   `tls-init` reads the machine's addresses from `ip -j address`, never a privacy address.
6. A trial on a throwaway VM, written as a procedure; then a deploy procedure, written for approval
   (it restarts nervus; other sessions are warned first). **The trial done 2026-10-19 (procedure
   033): every verification item observed. Deployed 2026-10-19 (procedure 034), at `2161c24`: a
   fresh VM enrolled on its first call by id, a file out over SFTP and in by pull, and the VM
   forgotten once destroyed, on this installation.**
7. The companion ADR: the install map and host enrollment.

## Verification

Moves to Accepted when observed, in tests first seen to fail, or on an installation's Proxmox host
through nervus:

1. A fresh clone of the template, started and never touched by hand, answers an `exec` with `vmid`
   as `agent`, with `sudo -n` giving root, in one call from the client; the audit log shows the
   enrollment under that client's run id. **Observed 2026-10-19, procedure 033 step 5.**
2. The pinned host key is the one the guest agent reported. A server at the VM's address with any
   other key is refused before nervus offers its own key (test). **First half observed, procedure 033
   step 5; second half in tests (`tests/test_enroller.py`), seen to fail first.**
3. The VM's address changed by hand: the next `exec` succeeds, and the row holds the new address.
   **Observed, procedure 033 step 9 (by removing its IPv4 address; a new MAC kept the same address).**
4. The VM destroyed and its id reused by a new clone: the next `exec` reports the changed host key,
   enrolls the new VM, and runs. The VM destroyed and the id unused: the call fails saying the VM is
   gone, and `hosts` no longer lists it. **Observed, procedure 033 step 9.**
5. A token without the hypervisor's entry is refused a `vmid`; a token with it reaches every enrolled
   VM. **Observed, procedure 033 step 6.**
6. An `export` from an enrolled VM goes over SFTP, and an upload to one that cannot reach nervus
   goes over SFTP above 32 MiB; each answer names its route, and every hash matches the client's.
   **Observed, procedure 033 step 7.**
7. Against an HTTPS nervus, an upload into a fresh, unenrolled VM is pulled, by address, with
   certificate checking on, and leaves no certificate in the VM. **Observed, procedure 033 step 8.**
8. On a fresh install from `docs/install.md` with no DNS entry for nervus, Claude Code and Codex
   connect by nervus's address with certificate checking on; after `tls-reissue` adds a new address,
   they connect by it without saving a new root. **Observed, procedure 033 step 10: Claude Code
   headless and `nervus-status` from the Mac, Codex in the ChatGPT app by the re-issued address.**
9. No step needed DNS, a firewall change, or a person acting per VM. **Observed, procedure 033.**

## Amendment 2026-11-08: the guest agent is not a trustworthy anchor when the VM is root-compromised (procedure 056, finding 2)

The security review before the 0.2.0 export found that **verification item 2's safety property — "a
VM that reports another machine's address gains nothing" — did not hold under a root-compromised VM.**
This ADR takes the guest agent as the trust anchor, "as a person at the console is for a host." A VM
compromised at root controls its own guest agent, so it can report, through the agent, *another
enrolled machine's* real host keys and address. nervus pins those (the keys are public), connects to
that machine, and the machine — trusting nervus's CA like any enrolled machine — answers `agent` then
`root`, so nervus stored the row **vmid → the other machine**. Because a token holding the hypervisor
entry may name any vmid (decision 6a), a client could then reach that machine **outside its own
allowlist**, recorded only as the vmid. Reproduced against a scratch nervus (procedure 056).

**The hardening applied (procedure 056).** nervus now refuses to enroll a VM whose reported host keys
already belong to a machine it knows under another identity — another enrolled VM or a host enrolled
from the UI (`enrollments.py`, `_key_clash`, in the enrollment transaction). A machine's host public
keys are its identity here, so a shared key betrays the aliasing. With the existing rule that only a
machine trusting nervus's CA passes the enrollment check, a compromised VM can no longer alias itself
to a machine nervus already trusts. A cloned VM that kept a template's host keys is refused with a
message to regenerate them. Verification item 2 gains: *and a VM that reports host keys already
belonging to a machine nervus knows is refused (tests in `test_enrollments.py`, seen to fail first).*

**Open question left for the operator (not resolved here).** Two gaps remain, both needing the
operator's design call rather than a lone hardening:
- a VM could still claim the host keys of a machine described by hand in `hosts.yaml` (not "enrolled",
  so in neither store nervus checks);
- the stronger fix the review named — binding the connection to the VM's identity through the trust
  anchor (Proxmox / the guest-agent channel nervus controls) rather than trusting a VM-reported
  address at all — would close the class, not just the reproduced vector.
The reproduced vector (a VM aliasing itself to an already-enrolled machine) is closed; whether to go
further is the operator's to decide.

## Amendment 2026-11-13: enrollment proves, through the guest agent, that it reached this VM (procedure 058; answers the open question above)

**Decided at the operator's word.** Asked to close the review's findings, the operator said "get this
closed, and I mean everything closed", then chose to run the machine trials (procedure 058). That
answers the open question above: close the class, not just the reproduced vector.

**Three gaps, not two.** Besides the two above, the shared-key refusal has a race: a VM that enrolls
*before* the machine whose keys it claims finds nothing to clash with, so the first claimant wins. And
any fix that only checks *where* nervus connected has a fourth: the enrollment script reports host keys,
nervus pinned **all** of them, and a compromised VM could list another machine's public key beside its
own. Its own key passes the enrollment check; afterwards it forwards its SSH port to that machine, which
presents the smuggled key, and every call naming the vmid lands there.

**What enrollment does now.**
1. *A challenge, left by the trust anchor.* The enrollment script, run as root inside the VM by its
   guest agent, creates a root-only file under `/run` whose name carries a fresh 128-bit random
   challenge, made exclusively. The SSH check — still `agent`, then root by `sudo` — now also removes
   that file through `sudo` and says so. Only the machine that holds the file can. A machine reached at a
   reported address that is not this VM — another VM, a host from `hosts.yaml` or the UI, or one behind a
   forwarder the VM runs — cannot, whatever host keys it presents: it is refused and nothing is stored.
2. *Only the proven key is pinned.* The row keeps the one host key the server presented in that
   challenged session — the key whose private half is, by step 1, inside this VM — not every key the
   script reported. Later calls, and the search for a VM whose address moved, accept only that key, so a
   key the VM merely listed is never trusted.

**What stays.** The shared-key refusal (2026-11-08) stays: it no longer carries the security weight,
but it still tells a VM cloned with a template's host keys apart, with its message. A VM whose address
moved is still found among its reported addresses by its pinned key, without a new challenge: that key
was proven to be this VM's at enrollment. Anything that falls through to enrolling again meets the
challenge. Rows enrolled before this amendment keep the keys they were pinned with until the VM is next
enrolled.

**Verification item 2 gains:** *a VM whose guest agent reports another machine's host keys and address
is refused, whether that machine is enrolled or not and wherever it is described, because the machine at
that address cannot remove the challenge the guest agent left in the VM; and a VM that lists another
machine's key beside its own is pinned to its own alone (tests in `test_enroller.py`, seen to fail
first; procedure 058, on real machines).*
