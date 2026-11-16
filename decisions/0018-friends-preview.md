# ADR-0018: a friends preview, exported from this repository with what is particular to the operator taken out

**Status:** **Accepted by the operator, 2026-11-15**, its verification observed on the public
repository (procedure 064). **Decided by the
operator on 2026-10-15**, in a Claude Code session: question A in the operator's own words
(quoted below); B and the rest as recommended; C and D differently from the recommendation, as
marked at each. Each question keeps its options, so the record shows what was not chosen.
**Date:** 2026-10-15
**Rewritten:** 2026-10-17, under ADR-0019 F, to name this repository's particulars only by kind.
No decision changed; two passages note what ADR-0019 has since fixed. The original is deployment
note 0018.
**Decided by:** the operator, 2026-10-15
**Amends:** ADR-0005 decision 3, for the preview only (decision I)
**Amended by:** ADR-0029 questions 2 and 9 (2026-11-05), marked at decision E: each export has a release number above the last's, and a `CHANGES.md` section for it.
**Amended by:** ADR-0019 decision H (2026-10-15), carried out by the section at the end of this ADR (2026-10-17), which governs: the deployment record stays out whole, the map becomes a check rather than a rewrite, and friends get `docs/install.md` and `docs/clients.md`.
**Amended:** 2026-11-13, by the operator (the section before the last): the preview's repository is made public and takes the project's name; nobody is invited as a collaborator.
**Amended:** 2026-11-15, by the operator (the last section): the public commits' author, the Apache License 2.0 with a `NOTICE`, the README for any reader, the preview's repository deleted and made again, this repository's new name, and security problems reported privately.
**Builds on:** ADR-0005 decisions 1 and 3 (nervus will be published; this repository stays
private; the public one starts with fresh history), AGENTS.md rule 7 (secrets never enter the
repository)

## Context

**What the operator asked for, 2026-10-15:** to give this repository to "a small set of friends
to see how they get on with the product", a group the operator describes as "pretty small and
trustworthy", who "all have access to some AI tools as well". The operator knows that some
user-experience questions are unresolved.

**Why not just add them to this repository.** ADR-0005 decision 3 says this repository stays
private, because "publishing this history publishes this fleet". Giving someone access to a git
repository gives them every past version of every file, not only the current one. Removing a
file now hides it from the latest commit, but `git log` still shows it. Revoking GitHub access
later doesn't take back a clone, and a clone ends up on the friend's laptop, in their backups,
and in whatever AI tool they point at it. The operator, 2026-10-15: the clone concern "throws it
actually into pretty sharp and useful relief". So whatever the friends get has to be a separate
repository with fresh history.

**Rewriting this repository's history was considered and is not an option here.**
`CURRENT_STATE.md` and the procedures cite commit hashes as evidence (`e4a45d9`, `fa938f3`, and
others). A rewrite (`git filter-repo`) changes every hash and breaks that record. This repository
is also already on GitHub (private), which may keep old objects after a forced push.

### What the repository holds

Read off this repository on 2026-10-15 by the session drafting this ADR.

- **124 tracked files and 236 commits.** `src/` 22, `tests/` 32, `decisions/` 17,
  `procedures/` 25, `tools/` 18, `research/` 1, `deploy/` 1, and 8 at the root.
- **No credentials anywhere in the history.** The history was searched for private keys,
  GitHub tokens, Proxmox API tokens with values, and nervus token values. The only matches were
  code that builds an `Authorization` header from variables. That was a pattern search, not a
  proof, so decision E adds a scanner.
- **What is particular to the operator**, with the number of tracked files mentioning each:
  - the home domain (44 files), and the operator's account name (48)
  - the LAN's addresses (9), a ULA prefix (1), and MAC addresses (4 files: one in
    `hosts.yaml`, three in procedure 001). Procedure 020 also has TLS fingerprints that are
    shaped like MAC addresses.
  - the names of two other projects (30 and 8 files). They also appear in token names, more than
    100 times in all.
  - the operator's home path (2 files)
  - hardware: two server models and a CPU model, in `hosts.yaml`, ADR-0009, ADR-0017 and
    procedures 001 and 008
  - **the weakness map:** `hosts.yaml` records what is misconfigured or missing on each host,
    and ADR-0004 records which of the operator's keys can still bypass nervus and why
- **`src/` mentioned no domain, address or account, but it was not free of the first
  installation's naming.** ADR-0005 recorded `src/` as clean on 2026-09-12. Since ADR-0009 the
  code had hardcoded the Proxmox host's inventory name, and reserved its root entry's by name.
  That did no harm in a preview, but a friend's Proxmox host would have had to carry the same
  name. *Fixed 2026-10-16 by ADR-0019 decision D: the inventory marks the entries, and `src/`
  names no system.*

### What the operator values

The operator, 2026-10-15: "having reasoning about why I made a decision or what the
justification for a feature is is almost as valuable as having the code for that feature
itself. So this should be more about excluding things which are particular to me, and I don't
particularly feel like sharing, rather than just deciding what merely to include."

That changes ADR-0005's split. ADR-0005 shares the code and keeps the deployment record private.
This preview shares the deployment record too, with the operator's particulars taken out. The
procedures are also the only install guide nervus has (decision G). A friend's AI tool can read
procedures 001 to 003 and 005 and adapt them to the friend's own machines.

## Questions

### 0. Order

`CURRENT_STATE.md` has uploads next, then piece 5 (first-run setup).

1. **Insert this before uploads.** It works only in this repository. It touches nothing in
   `src/` and nothing on the fleet, so it doesn't conflict with either.
2. After piece 5, so friends get first-run setup.

*Recommended: 1.* What friends say about the product now is what should shape piece 5. Waiting
for it would mean building piece 5 first and asking afterwards. **Decided: 1.**

### A. Leave out what is particular, rather than choose what to put in

1. **Everything goes in except what decision D leaves out, with the substitutions in decision C
   applied.** New files go in by default.
2. Only what is listed goes in (ADR-0005's code-and-generalised-ADRs split).

**Decided by the operator, 2026-10-15: 1** (quoted under "What the operator values"). The cost
is that a new file containing something personal goes out unless the check in decision E finds
it. The map in decision C is what makes that check possible.

### B. Where the preview lives

1. **A new private GitHub repository under the operator's own account (`nervus-preview`), with
   fresh history, and the friends added as collaborators with read access.**
2. A public repository now.

*Recommended: 1.* ADR-0005 decision 3 calls publication "a separate, later, deliberate act", and
this preview isn't that act. A private repository can be made public with one setting later,
but a public one can't be made private again in any way that matters. **Decided: 1.**

### C. How particulars are replaced

Each real value is replaced with a fixed placeholder, the same every time:

| real | placeholder | why that one |
|---|---|---|
| the home domain | `example.net` | reserved for examples (RFC 2606) |
| the operator's account name | `operator` | the word the documents already use |
| the LAN's /24 | `203.0.113.0/24` | a documentation range (RFC 5737). Like the real one, it's global in form, so ADR-0015's reasoning that the address is "global in form and private in fact" still reads correctly. A private range would make that passage nonsense. |
| the ULA prefix | `fd00:db8:1:1` | an example ULA prefix |
| MAC addresses and TLS fingerprints | `02:00:00:…` and `00:…`, keeping their length | still shaped like the originals |
| the two other projects' names | `project-a`, `project-b` | token names follow, e.g. `claude-code-project-a` |
| the operator's home path | `/Users/operator` | |

What stays: the three host names (they carry the story, and `src/` then used one of them); the
private range planned for the network; product names (Proxmox,
UniFi, WireGuard, 1Password, Keychain, Claude Code, Codex), since the reasoning depends on them;
hardware; and the operator's quoted words.

1. **The table above, kept in `secrets/preview-map.yaml`, outside the repository.** The map lists
   every real value next to its placeholder, so it's the most sensitive file in the whole
   process, and it is gitignored, like everything in `secrets/` (rule 7).
2. The same, with the map in the repository. Rejected: the map would leak exactly what it hides.

*Recommended: 1.* The operator should read the "what stays" list. Hardware and the host names are
the likeliest items to have on it that they would rather not share.

**Decided: 1, with hardware and host names moved from "what stays" to replaced** (the operator,
2026-10-15). Product names, the planned private range and the operator's quoted words stay. That
adds these rows:

| real | placeholder | note |
|---|---|---|
| the three host names | `node-a`, `node-b`, `hyper` | whole words only, so `proxmox` is untouched. The Proxmox host's root entry becomes `hyper-root`, the operator's per-host key names follow, and so do file names that carry a host name. |
| the second project's former name | `project-b-old` | found in `CURRENT_STATE.md` while recording this decision |
| hardware models: the two servers, the CPU, the RAID controller and the SSDs | "a rack server", "an 8-core CPU", "a RAID controller" | |
| sizes and counts that describe a machine (CPUs, threads, memory, disks) | removed | only in the lines the map names. A size can't be recognised by pattern alone, so the map lists each line, and the operator checks the list in step 2. |

**This reached into `src/`**, which then used the Proxmox host's two inventory names, so the
preview's code would have said `hyper` and `hyper-root`. The same substitution applies to the
tests, and decision E's test run on the exported tree is what shows the code still works after
it. *Since ADR-0019 decision D, `src/` names no host, so the substitution no longer touches it.*

### D. What is left out whole

Only what makes no sense, or still gives something away, once it is scrubbed.

1. **Leave out:** `.mcp.json`, which points a friend's agent at the operator's instance. It is
   replaced by `.mcp.json.example`. Untracked files such as `.venv` and caches never go anyway,
   since the export works from a commit (decision E).
2. **Also leave out** some of these. The operator picks; each is kept, scrubbed, unless named:
   - **ADR-0004**, the operator's residual SSH access. Scrubbed, it describes a general pattern
     ("my own keys stay in the password manager's agent, gated by the approval prompt"), and it's the
     argument that ADR-0005's "independent witness" reasoning rests on.
   - **`hosts.yaml`'s notes on each host's misconfigurations.** Scrubbed, they describe unnamed
     machines. They are also the best example of the provenance rule (rule 2).
   - **The 2026-09-15 fleet findings in `CURRENT_STATE.md`**, the same in kind.

*Recommended: 1 alone.* The danger from a weakness map is that it can be matched to a real
network. Decision C removes everything that matches it: a friend who knows the operator could
still guess whose it is, but a copy that gets out points at nothing. The operator's own phrase
was "I don't particularly feel like sharing", and that is the operator's call, not something a
session can judge.

**Decided: 2, all three** (the operator, 2026-10-15). In practice:
- **ADR-0004** is replaced by a stub of the same name. The stub says the ADR exists, is withheld
  from the preview, and covers the operator's own access to the fleet. Without it, references
  from ADR-0001, ADR-0005, ADR-0009, `README.md` and `CURRENT_STATE.md` would point at nothing.
- **`hosts.yaml`** is replaced by `preview/hosts.yaml`, an inventory written for the preview. It
  keeps the shape and the provenance convention, with placeholder hosts and none of the
  per-host notes.
- **`CURRENT_STATE.md`** loses two sections: "Fleet findings, and why they are perishable", which
  is the findings themselves, and the section on the operator's own access, which restates
  ADR-0004. The
  session included the second as part of the operator's choice, since keeping it would undo the
  ADR-0004 decision. The operator confirms or reverses that in step 5.
- **Not covered, and not a choice the operator made:** procedures, such as procedure 008's
  survey of the Proxmox host, also record what a machine lacks. They go in, scrubbed. The dry run in step 5 is where
  the operator sees them and can name more to remove.

### E. How each export is made and checked

1. **`tools/export-preview`, run on the operator's machine.** It:
   - takes a commit (default `HEAD`) and builds the tree from that commit with `git archive`, so
     unsaved work and untracked files never go out
   - applies decision D and the map
   - adds the preview's own `README.md` (decision F)
   - **refuses to finish** if any real value from the map is still there in any form (any case,
     dots escaped or not), if `gitleaks` finds anything, or if the test suite fails on the
     exported tree. The tests include fixtures that change under decision C, and a substitution
     that breaks a test would show up as a failure.
   - then shows the difference from the preview repository's last export. The operator reads it
     and commits it (`Export of <commit>, <date>`), and pushes.
2. The same, without the test run. Faster, but a substitution that breaks something would reach
   the friends first.

`gitleaks` was not installed on the operator's machine (checked 2026-10-15). It comes from Homebrew
(`brew install gitleaks`), and the operator installs it, since it is software on their machine.

*Recommended: 1.* Each update is one command and one diff to read. The preview's history is one
commit per export, and none of this repository's commits ever leave. Changes flow one way only:
anything a friend sends back is copied in by hand. **Decided: 1.**

*Amended 2026-11-05 by ADR-0029 questions 2 and 9:* the export also refuses a release number not above
the preview's last export's, and a `CHANGES.md` without that release's section, so a friend's upgrade
can tell a newer release from an older one and say what changed.

### F. The preview's README

1. **A README of its own, kept in this repository as `preview/README.md` and exported as the
   preview's `README.md`.** This repository's own README is left alone, since its job is
   different and it says the repository is private. The preview README covers:
   - what nervus is, and that this is an early preview
   - **what works, and what is missing:** no container image, no first-run setup, MCP over plain
     HTTP (the Proxmox host's name no longer matters since ADR-0019 decision D)
   - how to read the repository (ADRs for why, procedures for what was done, and a warning that
     they are records, not instructions)
   - that `AGENTS.md` and `CLAUDE.md` are the operator's rules for agents, which a friend's agent
     will load and follow inside the preview
   - that commit hashes cited in the documents point to the private history and won't resolve
   - how to install it (decision G) and how to send feedback (decision H)
2. One README for both repositories. It would have to describe two situations and would do
   neither well.

*Recommended: 1.* **Decided: 1.**

### G. How a friend installs it

1. **Manually, from the procedures, said plainly.** Build the wheel and install it. Install
   `deploy/nervus.service`. Write `hosts.yaml` and the token file. Onboard each host as procedure
   003 did. Connect a client as procedure 005 does. The README gives the steps in outline and
   points to those procedures, and it suggests handing them to the friend's own AI tool to adapt.
2. Build the container image and compose file from ADR-0005 decision 1 first.

*Recommended: 1.* Option 2 is the public release's job. It would take sessions of its own, and
none of this preview's readers would get the product until it was done. Friends with AI tools
and a Linux box can follow option 1, and how hard they find it is itself useful feedback for
ADR-0015 and the container work. **Decided: 1.**

### H. Feedback

1. **GitHub issues on the preview repository**, which the operator reads and brings back here
   by hand.
2. Whatever channel each friend already uses with the operator.

*Recommended: 1*, plus whatever friends already do. Issues keep feedback next to the version it
was about. **Decided: 1.**

### I. Relation to ADR-0005

ADR-0005 decision 3's split (code public, deployment record private) still governs the public
release, which this ADR doesn't decide. For the preview only, it is amended by decision A: the
deployment record goes too, scrubbed. ADR-0005 decision 3 is marked to say so. **Decided** with the rest, as recommended.

## Consequences

1. **The map becomes the boundary.** Something personal not in the map, such as a new project's
   name or a new address, goes out on the next export. Adding to the map is part of any work
   that brings a new particular into this repository.
2. **The preview lags this repository** by however long it has been since the last export.
3. **Friends see the decision record with its options intact**, including what was rejected.
   That is by design, and is decision A's point.
4. **`src/` hardcoded the Proxmox host's name** (Context). The preview would have renamed it by
   substitution (decision C), which is not a fix. *Fixed properly on 2026-10-16 by ADR-0019
   decision D.*
5. **The preview has gaps where things were withheld:** ADR-0004 is a stub, and two sections of
   `CURRENT_STATE.md` are gone. The preview README says so, so a reader doesn't take them for
   mistakes.

## Order of work

Each a step of its own, under rule 1.

1. This ADR, decided.
2. `secrets/preview-map.yaml`, written by the session from decision C and read by the operator,
   since only the operator knows whether a particular is missing. It includes the hardware lines
   to remove, and the list of what decision D leaves out or replaces.
3. `tools/export-preview` and its tests.
4. `preview/README.md`, `preview/hosts.yaml`, the ADR-0004 stub and `.mcp.json.example`.
5. A dry run into a folder on the operator's machine. The session and the operator both read the result,
   starting with the files that mention the most particulars: `CURRENT_STATE.md`, procedure
   018, ADR-0009 and `hosts.yaml`.
6. **The operator creates `nervus-preview` and invites the friends**, or tells a session to do
   it with `gh`. It is outward-facing, so it happens only on the operator's word.
7. The first export is committed and pushed.

## Verification

1. The export's leak check finds no real value from the map anywhere in the exported tree, and
   `gitleaks` finds nothing.
2. The test suite passes on the exported tree.
3. The preview repository's history contains export commits only. None of its commits has this
   repository's history as an ancestor.
4. A fresh clone of the preview shows the preview's README, not this repository's, and has no
   `.mcp.json`.

## Amended 2026-10-17 by ADR-0019 decision H: what the export is now

ADR-0019 decision H, decided by the operator on 2026-10-15, leaves the deployment record out of the
export whole. Since then every ADR and every line of code was made to name no installation
(ADR-0019 steps 2 to 6), so the export no longer needs to scrub anything; it needs to leave out
the record and check that nothing slipped through. Decisions C, D and G above, and the order of
work, are kept as the record of what was decided first; where they differ from this section, this
section governs.

**What goes in:** `src/`, `tests/`, `decisions/`, `deploy/`, `tools/`, `research/`, `docs/`,
`AGENTS.md`, `CLAUDE.md`, `pyproject.toml`, `.gitignore`, and the preview's own `README.md`
(decision F) and `.mcp.json.example` (decision D).

**What stays out, whole:** the deployment record (`procedures/`, `CURRENT_STATE.md`, `hosts.yaml`,
`deployment/`), `.mcp.json`, `secrets/`, and this repository's own `README.md`.

**Decision C becomes a check, not a rewrite** *(the session's proposal, confirmed by the operator on 2026-10-17: "the map is a check, not a rewrite")*. The map's check list stays, in `secrets/` as
before, widened to every name rule 11 forbids. The export applies no substitutions: a hit stops
it, and the fix is made in this repository, at the source, where rule 11 says it belongs. A
substitution would quietly rewrite a leak instead of exposing it.

**Decided by the operator, 2026-10-17, as the session recommended:**
- **Tests of this instance's deployment tools and drop-in move to `deployment/tests/`**, beside
  what they test: `test_audit_pull.py`, `test_nervus_deploy.py`, and the tests in
  `test_ensure_switches.py`, `test_ctl.py` and `test_main.py` that read `deployment/`. pytest runs
  both folders here; the export, without `deployment/`, runs `tests/` alone, and it must pass.
  (Rejected: keeping them in `tests/` and having the export skip them, which a new test would
  silently break.)
- **The client instructions become product documentation, `docs/clients.md`**: connecting a
  client, downloading an export, and the VM recipe, written for any installation with
  `<nervus>` in place of an address. The tests that run the commands as written read that
  file. Procedure 005 keeps the first installation's specifics and points to it. (Rejected:
  leaving them in procedure 005, which would give friends no client instructions.)
- **Decision G's install guide is `docs/install.md`**, written from what procedures 001 to 003
  did, naming no system, beside an example inventory, `docs/hosts.example.yaml`.

**Order of work, from here.** Each a step of its own, under rule 1.
1. This amendment.
2. The map's check list widened (in `secrets/`, not committed). A trial over what the export
   takes, on 2026-10-17, found three things to fix at the source before any export: steps 3 to 5.
3. The tests that read `deployment/` moved to `deployment/tests/`; pytest's `testpaths` names both.
   The generic unit's test checks for this instance's names by listing them; it checks
   positively instead, as the stub tests do.
4. `docs/clients.md`, from procedure 005, and the tests that run its commands reading it.
5. This instance's token ids, still used as test fixtures, replaced by neutral ones; and
   `research/2026-10-15-prior-art.md`, which no step had rewritten, made to name no installation.
6. `tools/export-preview` and its tests: build from a commit, leave out the record, add the
   preview's files, check with the map and `gitleaks`, run `tests/` on the result, show the diff.
7. `docs/install.md`, `docs/hosts.example.yaml`, the preview's `README.md` and `.mcp.json.example`.
8. A dry run into a folder on the operator's machine, read by the session and the operator.
9. **The operator creates `nervus-preview` and invites the friends**, or tells a session to do it.
10. The first export is committed and pushed, on the operator's word.

**Verification, from here:** in place of decision E's list, the export's own check finds nothing;
`tests/` passes on the exported tree; the preview's history holds export commits only; and a
fresh clone shows the preview's README and no `.mcp.json`, `procedures/`, `deployment/` or
`CURRENT_STATE.md`.

## Amended 2026-11-13: the preview's repository is made public, under the project's name

**Decided by the operator on 2026-11-13**, in a Claude Code session, in their words: "the export
should move it to a public repo that i'm going to rename `nervus`. i think we ought to deploy first
though." Asked whether `nervus-preview` is the repository that goes public and takes that name:
"Yes, that one."

**What it changes.** Decision B chose a private repository, with friends added as collaborators with
read access, over "a public repository now". A repository under a personal account cannot give a
collaborator read-only access (found 2026-11-07): a friend could also push. The operator's answer is
the option decision B set aside: the preview's repository is public, and nobody is invited to it as a
collaborator. Its name becomes the project's own.

**What follows from it,** by decisions already made:
- **The order of the renaming.** This repository is private and holds that name today. It is renamed
  first, and every checkout of it pointed at its new address, before the preview's repository takes
  the name: a checkout still pointing at the old address would otherwise push this repository's
  history to the public one.
- **ADR-0005's first verification item now applies to the preview's repository:** nothing of an
  installation in any tracked file or in its history, checked by search. Each export is checked as it
  is made (the section above). The commits already there were checked as the export stood when each
  was made, so before the repository is public they are checked again with the check as it is now,
  or the repository starts again from the next export.
- **What goes in and what stays out is unchanged** (the section above): the deployment record stays
  out, whole.
- **Decision H stands:** feedback comes as issues on the preview's repository, now from anyone.

**The order of work.** This installation is deployed first, so that it runs what the export
describes before that is public: the decision records in an export say what each release fixed.
Then the export, then the renaming above, then the repository is made public.

## Amended 2026-11-15: what the public repository carries, and how it starts

**Decided by the operator on 2026-11-15**, in a Claude Code session, each question put with its options
and a recommendation. The first three were put on 2026-11-13 and again on 2026-11-14: the public
commits would carry the operator's own name and address as their author, the project had no license
file, and the preview's README was written for friends. The fourth is the amendment above's "checked
again ... or the repository starts again"; the fifth follows from its order of the renaming. Where the
operator typed an answer it is quoted; otherwise the answer is the option they chose, by its name.

**1. Whose name the public commits carry: the operator's name, with the no-reply address GitHub gives
their account.** "Name, no-reply", chosen over the account's name with that address, and over their name
with their own address, which would become public and could not be taken back. An export's commit has
that name and address as its author and as its committer. The address itself is in the deployment
record (procedure 064).

**2. The license: the Apache License, version 2.0, with the operator's own name on the copyright
line.** The operator: "i was thinking of Apache 2.0 but with my name on the copyright, but then i
recalled that I also am interested in doing work under [a lab's name, in two forms; their words are in
procedure 064]. Is there a way to cover the names? i'd need to settle on a name". Put to them: the
copyright is the author's from the writing of it, and a notice records that and no more; a name that is
not yet a registered business can hold nothing; and a later release can add a name, with the releases
before it still valid. Then decided: "Apache 2.0", over MIT, and "Your name now", over "the nervus
authors" and over a lab's name. So:
- **`LICENSE` is the license's own text, unchanged.** It names nobody.
- **`NOTICE` carries the copyright line:** the year and the operator's name. Whoever passes nervus on
  must keep it (the license's section 4(d)).
- **The export's check allows that one line, and nothing else.** The check list refuses the operator's
  name in every exported file, and still does. The map, outside the repository as before, may now list
  lines it allows, each a file's name and a whole line. A match is passed over only where it lies in that
  file, on a line that is exactly that line; the same words anywhere else stop the export as before. The
  tool learns the line from the map and names nothing itself, and says which lines it passed over.
  (Rejected: taking the name off the check list, which would let it through everywhere.)

**3. The preview's README is reworded for any reader**, in the operator's words: 'Line 9 becomes: "This
is an early preview, public so that anyone can try it and say how they get on with it." A new last
section, License, says: "nervus is released under the <license we figure out>: see LICENSE." Nothing
else changes. We still need to resolve the exact license we're using before that last sentence can be
correct.' By answer 2 the sentence names the Apache License, version 2.0, and `NOTICE` beside it.

**4. The preview's repository starts afresh, by being deleted and made again.** "Delete and re-make",
chosen over replacing its one commit and over keeping that commit in the history. Read on 2026-11-15:
the export's check as it is now, and `gitleaks`, find nothing in that commit's files; but it carries the
operator's own address as its author, which answer 1 keeps out, and replacing a commit on GitHub is not
known to remove it from GitHub. The operator deletes the repository and makes an empty private one of the
same name; the next export is its only commit.

**5. This repository's new name: `nervus-private`.**

**6. Asked the same day, beyond the five: security problems are reported privately.** "Yes, add it."
The README's Feedback section says a security problem is reported through the repository's private
vulnerability reporting rather than as an issue, and the operator switches that on when they make the
repository public. For everything else decision H stands.
