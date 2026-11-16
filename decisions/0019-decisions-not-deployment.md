# ADR-0019: decision records hold decisions, the deployment record holds the installation, and code names no system

**Status:** **Accepted 2026-11-15, at the operator's word** ("Both Accepted (Recommended)", asked
of this record and ADR-0007 together), every verification item observed; "Where each stands",
under the list, says where. (It was Proposed: accepted when the verification below is observed.)
**Its policy was set by the operator on 2026-10-15** (quoted below). **Decided by the operator the same day**, in a
Claude Code session, one question at a time: D as the session revised it after the operator's
question about other hypervisors, E as set with the policy, and 0, A, B, C, F, G and H as
recommended.
**Decided by:** the operator, 2026-10-15 Each keeps its options, so the record shows what was not
chosen.
**Date:** 2026-10-15
**Rewritten:** 2026-10-17, under its own decision F, to name no installation. No decision changed.
The original, with the hardcoded lines as they stood, is deployment note 0019.
**Amends:** ADR-0018 (decision H), ADR-0005 decision 3 (the private/public split becomes a rule
for every document, not a step at release)
**Builds on:** AGENTS.md rules 2 and 6, ADR-0001 (nervus is not written for any one fleet),
ADR-0009 (the Proxmox host as a target)

## Context

While mapping what to scrub for the friends preview (ADR-0018), the session found that the
operator's machines are named all through `decisions/`, not only in the procedures. Most of
it is evidence: rule 2 says to read a machine before acting, and the ADRs recorded what was read
("6.5 GB free", "the address is global in form"). A few places go further:

- **Code.** `server.py` hardcoded the Proxmox host's inventory name: the `proxmox` tool was
  allowed only for a token whose allowlist named that host. `database.py` hardcoded its root
  entry's name: the UI never issued a token for a host so called. The `proxmox` tool's
  description, which every client reads, named the host too, and used it in its example path.
  Elsewhere in `src/`, machine names occurred only in comments. (The lines as they stood are in
  deployment note 0019.)
- **Defaults chosen with one machine in view.** ADR-0016's export limits were set with the first
  installation's disk in mind; ADR-0017's template sizes likewise.
- **Records that are about running this one instance, not about nervus.** ADR-0002 (how this
  instance is addressed on this LAN) and ADR-0004 (the operator's own direct SSH access).
- **A general decision told through this LAN.** ADR-0015 decision C rests on this LAN's
  addresses.

**The operator, 2026-10-15:**

> I would rather us do additional development work to make variables of parameterize or
> genericize things or make a decision about certain thresholds and sizes of storage and VMS or
> stuff like that, then leave peculiarities or names of my system or particular references to
> my specific hardware in the documentation. [...] The proxmox thing is fine because we chose a
> platform. but I don't like that our code hardcodes, the [Proxmox] host name. We should get rid of
> that. We should never be hard coding system names into our code. I would rather establish
> that the default are our assessed way to start this rather than reference our machines at
> all, and say that customization on this front is something that can be done in a future
> release. ADR0004 seems like it shouldn't be an ADR, and instead should be an actual record of
> deployment [...] ADR 0002 in the same case. [...] I don't want there to be particular
> references to my hardware or my systems, I would rather us just say, in testing it was shown
> that this was the right way to do things, or something similar. [...] We should not
> reference the local network.

## The policy, as set by the operator

1. **A decision record records a decision.** It names no machine, address, hardware or network
   of the operator's. Where evidence matters, it says what testing showed, in general terms.
2. **Numbers are nervus's assessed defaults**, stated as such, not as fitted to a machine.
   Making them configurable is left to a future release, and the ADR says so.
3. **Records about operating this instance are the deployment record**, not ADRs. ADR-0002 and
   ADR-0004 move there.
4. **Code never names a system.** What a host is for comes from configuration.
5. **Choosing a platform is a decision**, and naming it is fine: Proxmox stays.

## Questions

### 0. Order

1. **First, before ADR-0018's export work and before uploads.** The export is far simpler once
   the documents are clean, and the code change should land before any friend sees a hardcoded
   host name.
2. In parallel with ADR-0018, scrubbing what is still unclean at each export.

*Recommended: 1.* **Decided: 1.**

### A. Where the evidence goes, and how an ADR points to it

Rule 2 still applies: what was observed must be recorded somewhere. Removing it from an ADR
must not lose it.

1. **The specifics move to the deployment record (the procedure that observed them, or a
   deployment note), and the ADR cites it by number only:** "testing showed the guest agent
   copies files at about 1 MB/s (procedure 024)". A procedure number names no system. In the
   export it reads as a reference to a private record, which the preview README explains.
2. The same, without any citation. Cleaner for readers, but the operator could no longer get
   from an ADR to its evidence.
3. Leave the evidence in the ADRs and let the export map scrub it. That is what the policy rules
   out.

*Recommended: 1.* **Decided: 1.**

### B. Where the deployment record lives

1. **Where it is, declared by a rule.** `procedures/`, `CURRENT_STATE.md` and `hosts.yaml` are
   the deployment record already, so they stay put; AGENTS.md names them. A new `deployment/`
   folder takes ADR-0002 and ADR-0004 as deployment notes. Each keeps a stub in `decisions/` of
   the same number, saying it moved, so the numbering and the references hold.
2. Move all of it into `deployment/`. Tidier, but it changes hundreds of path references.
3. A second private repository. The cleanest split, but every session then works across two
   repositories.

*Recommended: 1.* **Decided: 1.**

### C. Tools

`tools/` mixes the product (`set-hosts`, `set-token`, `ensure-switches`, `nervus-status`,
`compare-refusals`) with operating this instance (the deploy, a survey of the Proxmox host, its
API access and accounts, and others), and several carry the first installation's names as
defaults.

1. **Each tool either becomes generic, taking names from arguments or the environment with no
   default naming a system, or moves to `deployment/tools/`.** Sorted one tool at a time, in a
   later step, with the operator shown the list first.
2. All of `tools/` is the deployment record for now.

*Recommended: 1.* **Decided: 1.**

### D. How the code knows which host is the Proxmox host

Then, one host's name decided it, and another name marked the entry the UI never issues.

1. **Two optional fields in the inventory.** `proxmox: true` marks the one entry whose
   allowlist gates the `proxmox` tool; more than one is refused at start. *(As decided, this
   field is `hypervisor: proxmox`; see below.)* `issue: never` marks
   an entry the UI never issues a token for, whatever it is called. With no entry marked
   `proxmox`, the tool refuses every call, and nervus says why at start. The tool's
   description stops naming a node and tells the client to read the node name from `/nodes`.
2. Command-line options, `--proxmox-host NAME` and `--never-issue NAME`. Works, but puts a
   fact about a host somewhere other than the inventory that describes hosts.
3. Take it from `proxmox.yaml`, which already holds the API's address.

*Recommended: 1.* The inventory is where hosts are described, and `issue: never` is not tied
to Proxmox. **For the first installation**, the code and the inventory carrying both fields go
out in one release, so the `proxmox` tool never refuses a running client for want of them. The
deploy restarts nervus, and the operator is told first (memory: warn before restarting nervus).

*Corrected 2026-10-16.* The draft had the first installation's inventory take the fields first,
then the code. Reading the machine before acting (rule 2) showed why that was wrong: nervus reads
its inventory only at start, so a change on its own does nothing; and that installation's deploy
refuses to deploy unless the installed `hosts.yaml` is exactly the running release's, so a change
by hand would block the deploy (procedure 027). The code running then ignores both fields (checked by loading the new file with it),
so one release carrying both is safe in either direction, rollback included.

**Decided by the operator, 2026-10-15: 1, the inventory** ("inventory field is the right way").
The operator then asked whether it helps when other hypervisors are supported. As drafted it
would not: a yes/no field for one platform means a new field for each platform. So the field
names the type:

```yaml
- name: hyper
  hypervisor: proxmox
```

- **`proxmox` is the only value nervus accepts today.** Any other value is refused at start,
  with the reason. A later platform adds a value and the code for its API; the inventory's
  shape does not change.
- **At most one entry per instance has `hypervisor: proxmox`**, as today. Several would need the
  tool to be told which host a call is for: a later decision, not this one.
- **The tool stays `proxmox`**, speaking the Proxmox API as it is. A common hypervisor tool that
  hides the differences between platforms is a design of its own, for when a second platform is
  real, not guessed now.
- **`issue: never` is unchanged**, since it was already not tied to any platform.

### D2. The systemd unit (added 2026-10-16)

Sorting the tools (C) left one product file naming this instance: `deploy/nervus.service`, with
this instance's sign-in address, its Proxmox flag and its plain-HTTP flag. A systemd drop-in can
replace a unit's command line but not add to it.

**Decided by the operator, 2026-10-16, as the session recommended:**
- **The unit is generic, and an installation's own flags go in a drop-in that restates
  `ExecStart`** (rather than one variable the unit expands, which would need `nervus-ctl` to
  allow an environment). `nervus-ctl` reads the unit and its drop-ins as systemd does. A test
  holds this instance's drop-in to the unit's command line plus exactly its own flags.
- **The generic unit's defaults are secure ones:** every address, since nervus exists to be
  reached from other machines; HTTPS for MCP and the UI; no Proxmox tool; no sign-in address
  (ADR-0007, ADR-0010). Listening on loopback only was not chosen: nervus would be useless until
  changed.

### E. Defaults

1. **Each number stays a named constant in the code, and its ADR states it as nervus's default,
   with the reasoning for that value.** "Configurable in a future release" is said once per
   ADR. Set by the operator.
2. Make them configurable now.

*Set by the operator: 1.*

### F. Rewriting the existing ADRs

1. **In place, one ADR per step and per commit, editorial only:** particulars out, general
   evidence in, specifics moved under A. No decision changes meaning. Where a decision only
   made sense for the first installation, the session stops and asks rather than rewriting it. The old
   wording stays in git history, which stays private. ADR-0015 decision C keeps its decision
   (the operator declares whether an address is public) and loses the account of this LAN.
2. Leave the ADRs as they are and write separate generic versions for the export. Two copies of
   every decision, which drift.

*Recommended: 1.* **Decided: 1.**

### G. A rule for future work

1. **AGENTS.md gets rule 11:** decision records and code name no system of the operator's;
   the deployment record does. Every session reads it, so new ADRs are clean from the start.
2. This ADR alone.

*Recommended: 1.* **Decided: 1.** Rule 6 makes this ADR authoritative, but a rule in AGENTS.md is read before
any work starts.

### H. What this does to ADR-0018

1. **ADR-0018 is amended:** the export leaves out the deployment record whole (procedures,
   `CURRENT_STATE.md`, `hosts.yaml`, `deployment/`), close to ADR-0005's original split. The
   map stays, as a safety net that stops an export if any real value slipped into the rest.
   Because the procedures no longer go, ADR-0018 G changes: friends get a generic install
   guide, `docs/install.md`, written from what the procedures did but naming no system.
2. Keep ADR-0018 as decided, and export the procedures scrubbed.

*Recommended: 1.* **Decided: 1.** It is what the policy implies: procedures are this instance's record.

## Order of work

Each a step of its own, under rule 1.

1. This ADR, decided.
2. AGENTS.md rule 11 (G).
3. The code change (D), with tests; then `hosts.yaml` with both fields, and one deploy of the
   two together, with the operator told before the restart.
4. ADR-0002 and ADR-0004 to `deployment/`, with stubs (B).
5. The tools, sorted (C).
6. The ADRs rewritten, one per step (F), the operator reading each.
7. ADR-0018 amended (H), then its own order of work resumes, with `docs/install.md` added.

## Verification

1. `src/` has no system name outside comments, and no comment depends on one: a search for
   every host name in the inventory finds nothing in code.
2. With an inventory whose Proxmox host has any name, the `proxmox` tool works and the UI never
   issues the entry marked `issue: never`. Two entries with `hypervisor: proxmox`, or a
   `hypervisor` value nervus doesn't know, stop nervus at start with the reason. A test, and on
   the first installation after the deploy (procedure 027).
3. ADR-0018's map check, run over `decisions/` alone, finds nothing. **Observed 2026-10-17**, after every
   ADR was rewritten (step 6): the map's check list over all 20 files, 0 hits; a wider pass for this
   instance's names, the full-level token's id and the planned range found only general words
   ("the operator's machine", Codex's sandbox, the macOS keychain, Caddy in ADR-0010's sources).
4. Every observation removed from an ADR is found in the deployment record.

**Where each stands, 2026-11-15.**

1. Searched again on 2026-11-15: no name in the first installation's inventory occurs anywhere in
   `src/`, `tools/`, `deploy/`, `install.sh`, `docs/` or `decisions/`. The export's own check, with
   its longer list, found nothing in the whole exported tree the same day (procedure 064).
2. In tests; and on the first installation after the deploy (procedure 027): the `proxmox` tool
   worked through the entry marked as the hypervisor, and issuing the entry marked `issue: never`
   was refused. One piece was seen in a test and not on that installation: the Clients page leaving
   that entry out of what it offers, which the operator was told before accepting.
3. Observed 2026-10-17, as the item says.
4. Each ADR rewritten under decision F names the deployment note that keeps its original, and each
   note named exists in `deployment/` (checked 2026-11-15: nine notes, 0001 to 0019).
