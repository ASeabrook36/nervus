# ADR-0023: where nervus may run, for the preview, and what its installer does

**Status:** **Accepted 2026-10-19, at the operator's word** ("Mark ADR-0023 Accepted"), every
verification item observed, on a fresh VM and container (procedure 035) or in tests, as marked at
each. **Decided by the operator on 2026-10-19**, in a Claude Code session: questions 1 to 7, each as
the drafting session recommended ("ADR-0023: all as recommended"), after the tiers were rewritten at
the operator's request around which computer hosts nervus. Each question keeps its options, so the
record shows what was not chosen.
**Amended 2026-11-05** by ADR-0029 question 1, decided by the operator on 2026-11-01: question 7, the
same script upgrades the nervus it installed, with `--upgrade`, and without it says which release is
installed and which the tree holds. ADR-0029 Accepted the same day.
**Date:** 2026-10-19
**Asked for by:** the operator, item 2 of the order before friends are invited: "an ADR that maps
the ways people will install nervus (ADR-0007's three tiers, including the user's own computer),
across the operating systems a friend may use, such as macOS without systemd, which are supported
for the preview, and what an installer does for each". ADR-0022 question 1a left host enrollment to
a companion ADR; question 1 here says which.
**Builds on:** ADR-0001 s2 (nervus is the only path to the fleet, on a machine of its own); ADR-0005
decisions 1 and 5 (a container image for publishing; read-only enrollment enforced by the target);
ADR-0007 decision 2 (the three tiers, declared at setup); ADR-0011 decision 3 (enrollment by a root
command); ADR-0014 (tokens issued in the UI); ADR-0015 (first-run setup in the UI, the tier chosen
there); ADR-0018 (the friends preview); ADR-0021 (HTTPS clients trust); ADR-0022 (VMs enrolled
through the guest agent).
**Written to the policy of ADR-0019:** this record names no system; the evidence is in the
procedures it cites.

## Context

### What a friend has today

`docs/install.md`: about an hour by hand, on "a machine of its own for nervus: a small container
or VM... Linux with systemd, and Python 3.11 or later; tested on Debian 13". Followed end to end on
throwaway VMs three times (procedures 029, 032, 033), each time finding something the doc got
wrong. There is no installer, no container image (ADR-0005 decision 1) and no first-run setup
(ADR-0015).

### What the code needs, read from it

- **Python 3.11 or later**, and the packages `pyproject.toml` declares; nothing compiled beyond
  what the wheels carry. `ssh-keygen` for nervus's key; SQLite from Python.
- **systemd, in two places.** The unit runs nervus, with its sandboxing (`ProtectSystem=strict`,
  `StateDirectory=`), and **`nervus-ctl` reads every path from that unit and its drop-ins**
  (`ctl.py`), so the off switch, sign-in links and token tools work only where a systemd unit
  describes nervus. nervus itself runs anywhere Python does: the test suite runs it on macOS.
- **An empty inventory and an empty token file are accepted** (`hosts: []`, `tokens: []`, read
  2026-10-19). So nervus can start with neither: tokens can come from the UI (ADR-0014) and hosts
  from enrollment.
- `tls-init` names the machine's own addresses from `ip -j address`, Linux's; elsewhere it names
  none, and names still work (ADR-0022 10a).

### The tiers: which computer nervus lives on, and who can reach into it there

ADR-0007 decision 2 sorts installations by one question. Take the user's **everyday computer**: the
one where their clients (Claude Code, Codex) run, and where any program they run might be hostile.
**Can a program there get inside nervus without going through nervus's front door?**

- **Tier 1: nervus lives on a different physical computer from the everyday one** (recommended).
  Nothing on the everyday computer can get in. The form nervus takes there does not matter: a
  container or a VM on a hypervisor host, or a service installed straight onto a small box (a mini
  PC, a single-board computer). Only the separate hardware makes it tier 1.
- **Tier 2: nervus lives on the everyday computer, under an account of its own** (`nervus`), as a
  system service. The user's programs cannot read its files without admin rights: the operating
  system is the wall.
- **Tier 3: nervus lives on the everyday computer, and the user's own account can get into it.**
  Three ways: run as the user; in Docker Desktop or rootless Podman; or **in a VM the everyday
  computer hosts** (UTM, OrbStack, Multipass, Parallels, VMware). The last looks like a machine of
  its own and is not: the VM is a program running as the user, and its disk a file in the user's
  home folder, so anything running as the user can open that file or drive the VM.

So the same VM is tier 1 or tier 3 by **which computer hosts it**, not by being a VM, and a
container and a VM are alike:

| nervus runs as | on a separate computer (a hypervisor host, a small box) | on the everyday computer |
|---|---|---|
| a VM | tier 1 | tier 3 |
| a container (LXC, Docker, Podman) | tier 1 | tier 3 |
| a service under its own `nervus` account | tier 1 | tier 2 |
| a program run as the user | — | tier 3 |

The user declares the tier in first-run setup (ADR-0015).

**Apart from the tiers: nervus on a machine it also controls.** A friend with one Linux server may
want it to be both nervus's home and a machine agents act on. That is dangerous for another reason:
nervus holds root there, so any agent can, through nervus itself, read nervus's key, tokens and
audit log on that machine, and reach every other machine as nervus. That is ADR-0001 s2's reason
for a machine of its own. It is safe only if nervus has no root on its own machine: not enrolled,
or enrolled read-only (ADR-0005 decision 5), which is not built.

### What each place takes to support

| where nervus runs | tier | service manager | what supporting it takes |
|---|---|---|---|
| Linux, on a separate computer (a VM or container on a hypervisor host, or a small box) | 1 | systemd | today's path; an installer |
| Linux, the everyday computer, as user `nervus` | 2 | systemd | the same installer |
| Linux, in a VM the everyday computer hosts | 3 | systemd | the same installer; declared tier 3 |
| macOS, the everyday computer, as its own account | 2 | launchd | a launchd daemon, a hidden account, `nervus-ctl` reading a plist; tests on macOS |
| macOS, the everyday computer, as the user | 3 | launchd agent | less; weakest |
| Windows, in WSL2 | 3 | systemd, if enabled | untested |
| a container image (Docker, Podman) | 1 or 3, by where it runs | none inside | ADR-0005 decision 1's image; first-run key making (ADR-0015 "Not proposed") |
| a machine nervus also controls | — | systemd | refused with root; allowed read-only (ADR-0024) |

## Questions

### 1. What this ADR covers

- **a. Where nervus may run, and the installer, here; host enrollment and read-only access in the
  next ADR (ADR-0024).** The installer is about nervus's own machine; enrollment is about every
  other machine, and read-only access is a design of its own (what a forced command allows).
- b. All of item 2 in one ADR.

*Recommended: a.* ADR-0022 settled VMs; hosts are the half left, and they depend on this ADR only
for where nervus runs.

### 2. Where nervus may run, for the preview

- **a. Supported: Linux on a separate computer, in whatever form (tier 1, recommended), and Linux on
  the everyday computer under nervus's own account (tier 2). Supported and declared tier 3: Linux
  in a VM the everyday computer hosts. Not for the preview, and the docs say why: macOS natively,
  Windows, a container image, and a machine nervus also controls with root.**
- b. Tier 1 only. Simplest to support, but a friend without a hypervisor or a spare box has no way
  in.
- c. Everything in the table, macOS natively included, before inviting friends.

*Recommended: a.* It covers a friend with a hypervisor, a spare box, or a Linux computer they use
every day; every supported place runs the same installer under systemd, so one path is tested, not
five. The places left out each need work of their own (question 3, ADR-0005 decision 1, ADR-0024),
and the docs can send a Mac-only friend to a VM their Mac hosts, declared tier 3, rather than leave
them out.

### 3. macOS, for a friend with only a Mac

- **a. Not natively in the preview: a Linux VM the Mac hosts, under the installer, declared tier 3.**
  Nothing new to build; the doc names the tier honestly. A friend with a separate computer as well
  runs nervus there instead, tier 1.
- b. Natively, as a launchd daemon under a hidden account of its own (tier 2): the installer makes
  the account and the plist, and `nervus-ctl` learns to read its paths from the plist. Real work,
  tested on macOS, and the first non-systemd path.
- c. Natively, as the user (tier 3). Least work, and no better than a VM the Mac hosts.

*Recommended: a* for the preview, and b, if friends ask for it, as an ADR of its own. A Mac-only
friend's Mac is their everyday computer, so nervus on it can be no better than tier 2 either way;
the honest first step is the label, not a second service manager.

### 4. A machine nervus also controls

- **a. Not supported with full access: the docs say so where they say where nervus may run, the
  installer says so when it finishes, and ADR-0024's enrollment refuses to give nervus root on its
  own machine.** Allowed read-only once that exists, for this machine only.
- b. Supported and labelled, as tier 3 is: the user is told and chooses.
- c. Not mentioned.

*Recommended: a.* Tier 3 exposes nervus to programs the user runs on the everyday computer; this
exposes it to every agent nervus serves, which is adversary A of ADR-0007, the one nervus exists to contain. A label cannot
make that safe; a missing root can. The trials (procedures 032 and 033) used a VM as its own host
on purpose and were destroyed; the docs say not to do that with a real nervus.

### 5. Which Linux

- **a. The installer checks for what it needs, not a distribution's name: Python 3.11 or later
  with `venv`, `ssh-keygen`, systemd as the running init, `useradd`. Where `apt` exists it installs
  what is missing; elsewhere it stops and names each missing piece.** Supported as tested: Debian
  13 (procedures 029, 032, 033), and Ubuntu 24.04 once the newcomer trial (item 7) has run on it.
  *Run 2026-11-07, procedure 054:* on Ubuntu 24.04.5, Python 3.12.3, the installer installed what was
  missing (`venv`, `age`), and nervus ran, backed itself up and served a client as the docs say. A
  machine it reaches there went in at standard; read-only is refused there (ADR-0024). *The same
  evening ADR-0024 question 9 made read-only work there too.* *Run 2026-11-08, procedure 055:* on
  Ubuntu 26.04.1, Python 3.14.4, its `sudo` and coreutils Rust rewrites, the installer, nervus, a
  backup and an upgrade, as the docs say; read-only there through Ubuntu's own bubblewrap profile
  (ADR-0024 question 9, as amended).
  *Mended 2026-11-15:* a machine with no Python at all was not installed what it lacked. The
  installer needs Python itself, to check `--address` and to name the release, and used it for
  both before it looked whether Python was there: such a machine was told its address was not an
  IP address (found 2026-11-01, at ADR-0029 step 2). It now looks for Python first; where there
  is none and `apt` exists it says so, asks, and installs Python alone, then reads the machine,
  shows its plan and asks again, as on any other. Nothing but Python is installed before the
  plan's own yes, and whatever stops it after that says Python stays installed.
- b. Debian and Ubuntu by name, refusing everything else.
- c. Also Fedora and its family, with `dnf`.

*Recommended: a.* A check by need tells a friend on another distribution exactly what to fix, and
refuses Ubuntu 22.04 for the right reason (its Python is 3.10, from memory, not read off a
machine) rather than by its name.

### 6. What the installer does, and what it leaves

- **a. On nervus's own machine, as root, everything `docs/install.md` steps 2, 3, 7 and 8 do: the
  account, the code and its venv, the folders, nervus's SSH key, its TLS authority and certificate
  (`tls-init`, with the names given and the machine's addresses), the unit and a drop-in, the off
  switch, and an empty inventory and token file; then it starts nervus and prints the root's
  fingerprint and a sign-in link.** It leaves: tokens to the UI (ADR-0014); the tier to first-run
  setup (ADR-0015); hosts to enrollment (ADR-0024; by hand until then); a Proxmox host's root
  scripts, which run on that host, with a flag `--proxmox` adding the two drop-in flags once its
  settings file exists.
- b. The same, and it also makes a first token and prints it. One step less for the friend, but the
  token then sits in a terminal's scroll-back; the UI issues one where only the browser sees it.
- c. Steps 2 and 8 only; the rest by hand.

*Recommended: a.* Each step it takes has one right answer; each it leaves needs the person.

### 7. How it runs, and from what

- **a. `install.sh` at the top of the preview repository, run as root on nervus's machine from a
  copy of the repository there (a clone, or `docs/install.md`'s archive): it installs exactly the
  committed tree it sits in, refusing uncommitted changes in a clone. It prints what it will do and
  waits for "yes", or proceeds with `--yes`. It refuses a machine that already has nervus, and says
  that upgrading is item 6's.**
- b. `curl … | sudo bash` from the repository. The preview repository is private, and a script run
  unread as root is what this project tells agents never to do.
- c. A package (`.deb`). More to build and to sign; after the container image, if at all.

*Recommended: a.* The friend has the repository already (ADR-0018); the script is read before it
runs; and what it installs is a commit, as every deploy here has been.

*Amended 2026-11-05 by ADR-0029 question 1:* run with `--upgrade` from a newer tree, it upgrades the
nervus it installed. Without it, it still changes nothing on a machine that has nervus, and says which
release is installed, which this tree holds, and the command that upgrades.

## Consequences

1. **For a friend:** one command on nervus's machine, then the browser: sign in, choose the
   tier, issue tokens, and point clients at nervus (`docs/clients.md`). `docs/install.md` opens with
   where nervus may run and which tier each place is, then the installer; the hand steps stay
   below it, for other distributions and for reading what the installer does.
2. **The preview supports one service manager, systemd,** and one install path, tested on Debian
   13, then Ubuntu 24.04.
3. **A Mac-only friend runs nervus in a Linux VM their Mac hosts, declared tier 3,** until a native
   macOS path is decided, if friends ask for one.
4. **nervus never holds root on its own machine.** The docs and the installer say so; ADR-0024 may
   allow a read-only enrollment of it.
5. **Not changed:** the container image stays before publishing widely (ADR-0005 decision 1).

## Order of work

Each step waits for the operator (rule 1).

0. ~~The operator's decisions on 1 to 7.~~ Done 2026-10-19: all as recommended.
1. ~~`docs/install.md`: "Where nervus may run", the Context's two tables, each place with its tier.~~
   Done 2026-10-19, held by `tests/test_install_doc.py` (verification 6).
2. ~~`install.sh`, with tests:~~ Built 2026-10-19 (26 tests, eleven guarantees broken on purpose and
   caught); not yet run on a real machine. With tests: its checks, its plan, its refusals, each step run against stand-ins
   for the root-only commands as procedure 033's script was, and the drop-in and files it writes
   compared with what the hand steps write.
3. ~~`docs/install.md` around the installer, the hand steps kept below it; tested as written.~~ Done
   2026-10-19.
4. ~~A trial on throwaway machines: a Debian 13 VM and a Debian 13 container, from scratch, each to
   a client's first call; written as a procedure.~~ Done 2026-10-19 (procedure 035); it found and
   fixed `apt-get update` (`9adf30d`), `nervus-ctl`'s audit writes as root (`92990a6`), and the guide's
   assumption of `sudo`.
5. ADR-0024: host enrollment by a root command, and read-only access.

## Verification

1. On a fresh Debian 13 VM and container, `install.sh` run as root from a clone ends with nervus
   active over HTTPS, the root's fingerprint and a sign-in link printed, and nothing else to do on
   that machine before a browser signs in. **Observed, procedure 035 steps 2 and 3, once its two
   faults were fixed.**
2. Run again, it changes nothing and says nervus is already there. **Observed, procedure 035 step 2.**
3. On a machine missing Python 3.11, systemd or `ssh-keygen`, it stops before changing anything and
   names what is missing. **Observed with `apt-get` installing what was missing (procedure 035); the
   stop without `apt-get`, in tests.**
4. In a clone with uncommitted changes, it refuses. **Observed, procedure 035 step 2.**
5. What it writes (unit, drop-in, folders, modes, owners) is what `docs/install.md`'s hand steps
   write, compared in tests. **In tests (`tests/test_install_sh.py`).**
6. `docs/install.md` names each place in the Context's tables with its tier, by which computer
   hosts nervus, and says nervus must not hold root on its own machine. **In tests
   (`tests/test_install_doc.py`).**
