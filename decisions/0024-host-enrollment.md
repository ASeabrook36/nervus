# ADR-0024: enrolling a machine from the web UI, at the level its owner chooses

**Status:** **Accepted 2026-10-20, at the operator's word** ("yes to both"): every verification
item below observed, 1 to 8 by procedure 037 on throwaway machines; 1, 7, part of 2 (`exec` and
`exec_bg`) and part of 4 (a code works once) again on this installation by procedure 038, which
deployed it. **Decided by the operator on 2026-10-19**, in a Claude Code session:
questions 1 to 7, each as the drafting session recommended ("yes this is great, agreed with the
recommendations"). Each question keeps its options, so the record shows what was not chosen.
**Question 8 added 2026-10-19**, raised while building step 4, and **decided by the operator the same
day: a, as recommended** ("ADR-0024 question 8: a, as recommended"). Every step of the order of
work done.
**Amended 2026-10-23** by ADR-0026 question 1, decided by the operator: decision 2's two lines become
the advanced way, beside an admin login given once from the web UI, which is the default; consequence
1 likewise. Deployed 2026-10-24; ADR-0026 Accepted the same day.
**Question 9 added 2026-11-07**, raised by procedure 054, the newcomer trial, which found read-only
refused on Ubuntu 24.04, and **decided by the operator the same day**: to pursue Ubuntu's standard
way, now ("if there's a standard way to handle read-only for ubuntu then i think we should pursue
it ... i'm for doing it now rather than waiting"), in the form the session recommended, b, after
trying it on that trial's machine; the operator may still choose another form. **Built and tried
the same day:** verification item 9 observed on that machine, through a trial nervus (procedure 054).
**Question 9 amended 2026-11-08** after procedure 055 found Ubuntu 26.04 letting bubblewrap through by
a profile of its own: the read-only shell gives `--disable-userns` to the system's bubblewrap too,
wherever it knows the flag, at the operator's word ("I'm good with that fix"). **Built and tried the
same night** (procedure 055).
**Amended 2026-11-23** by ADR-0031, Accepted by the operator the same day: enrolling a machine at
standard or full makes two accounts, the read-write one and a read-only one beside it, named on the form;
a machine where the read-only account cannot start is added read-write alone, saying why; and a machine
described by hand gains the read-only account by two lines from the Machines page.
**Date:** 2026-10-19
**Asked for by:** the operator, item 2 of the order before friends are invited ("enrollment
(ADR-0011 decision 3), with read-only access (ADR-0005 decision 5) if the design allows"); the half
ADR-0022 question 1a and ADR-0023 question 1a left to this ADR.
**Builds on:** ADR-0001 s4 (the `agent` account, one key, host keys pinned); ADR-0005 decision 5
(read-only by default, enforced by the target, the level chosen by the person at the machine);
ADR-0011 decisions 1 and 3 (enrolled hosts in the database; the UI gives a command to run as root
on the new host); ADR-0012 (one-time links, stored as hashes); ADR-0014 (tokens and their allowlists
in the UI); ADR-0022 (VMs enrolled through the guest agent, a table of their own); ADR-0023 question
4 (never root for nervus on its own machine).
**Prior art:** `research/2026-10-15-prior-art.md` idea 2 (a middle level: a shell without `sudo`,
enforced by the target) and idea 4 (pre-filling from an SSH config; its keys never borrowed).
**Written to the policy of ADR-0019:** this record names no system.

## Context

### What giving nervus a machine means today

`docs/install.md` step 3, by hand, as root on the machine: an account `agent` with nervus's key and
passwordless `sudo`, then its host keys copied into nervus's `known_hosts`, the machine added to
`hosts.yaml`, and nervus restarted. Every machine gets full access, root by `sudo`. The procedure 035
trial took about ten commands and one restart, and showed that a minimal machine may lack `sudo`
altogether.

### What nervus does on a machine, read from the code

Any level must leave room for this, or nervus stops working there:
- **`exec`** runs the command with bash and keeps its whole output in `~/.nervus/runs/<run>/`
  (`ssh.py`), so a long output is never lost.
- **`exec_bg` and `job`** keep each job in a tmux session, its log in `~/.nervus/jobs/<job>/`
  (`jobs.py`).
- **`get`, `export`** read files over SFTP; **`put` and uploads** write files over SFTP, as `agent`
  or, with `root=1`, through `sudo`.

So nervus always writes in `~/.nervus`, and nowhere else unless asked to.

### What "read-only" can honestly mean

ADR-0005 decision 5 promised a read-only level "enforced by the target": a forced command in
`authorized_keys`, so the machine's own SSH server runs one fixed program whatever nervus asks for.
A fully compromised nervus still could not change such a machine. Three things decide what that
program can be:
- **An SSH forced command sees the command as text** (`SSH_ORIGINAL_COMMAND`). It cannot tell
  reading from writing in arbitrary shell, so a list of allowed commands would break `exec` and be
  easy to get around.
- **The operating system can make the filesystem read-only for one process tree.** On Linux,
  `bubblewrap` (`bwrap`) runs a command with every file read-only except folders named writable,
  enforced by the kernel. It needs no root at run time; it needs unprivileged user namespaces, which
  Debian enables (from memory when written; seen working on Debian 13, in a VM and in an
  unprivileged container, by procedure 036; Ubuntu 24.04's AppArmor rules for it not yet tried).
  *Tried 2026-11-07 by procedure 054:* Ubuntu 24.04 as installed moves a user namespace made by an
  unprivileged program into an AppArmor profile that refuses it its uid map, so `bwrap` cannot run
  there, and enrollment refuses read-only, as decision 1 says. Question 9 decides what nervus does
  there.
- **SFTP has a read-only mode of its own:** `sftp-server -R` refuses every write. A forced command
  can run it for SFTP requests.

So a read-only level means **nervus cannot change the machine's files, apart from its own scratch
folder `~/.nervus`.** It can still read anything the account can read, run programs, and reach the
network from there. The docs must say exactly that.

### Two directions, two things to trust

- **nervus → the machine, SSH:** nervus must pin the machine's host keys, read off the machine,
  never trusted from the network (ADR-0001 s4, as ADR-0022 3a does through the guest agent).
- **The machine → nervus, HTTPS, during enrollment:** the command fetches what it needs from
  nervus, so the machine must check it is talking to nervus. `curl --pinnedpubkey` checks nervus's
  public key against a hash written into the command; the machine needs no root file.

## Questions

### 1. The levels, and how the machine enforces each

| | **read-only** | **standard** | **full** |
|---|---|---|---|
| account `agent`, nervus's key only | yes | yes | yes |
| `sudo` | no | no | passwordless (today's level) |
| change the machine's files | no: only `~/.nervus`, enforced by the kernel (`bwrap`) | only what `agent` owns | anything |
| `exec`, `exec_bg`, `job` | yes | yes | yes |
| `get`, `export` | yes, read-only SFTP | yes | yes |
| `put`, uploads | refused by the machine | into `agent`'s own folders | anywhere, `root=1` through `sudo` |
| what enforces it | a forced command in `authorized_keys` | the absence of a sudoers line | — |

- **a. Three levels, as above; read-only the default (ADR-0005 decision 5).** A machine where
  `bwrap` cannot run is refused read-only at enrollment, saying why, and offered standard.
- b. Two levels, as ADR-0005 wrote: read-only and full.
- c. Standard and full now; read-only later, as an ADR of its own once `bwrap` is tested on the
  machines friends have.

*Recommended: a.* Standard is prior art idea 2: most work needs a shell but not root, and the
machine enforces it with nothing but the absence of a sudoers line. Read-only is ADR-0005's promise,
and `bwrap` makes it a kernel boundary rather than a list nervus keeps. If testing shows `bwrap`
does not run where friends need it, c is the fallback, and the default becomes standard.

### 2. What the person runs, and how it reaches nervus

- **a. The UI's "Add a machine" page asks for a name, the address nervus should use, and the level,
  then shows two lines to run as root on the machine:**

  ```
  curl -fsSk --pinnedpubkey 'sha256//<nervus's key hash>' -o nervus-enroll.sh 'https://<nervus>:8000/enroll/<one-time code>'
  less nervus-enroll.sh && sh nervus-enroll.sh
  ```

  The first fetches the script, checked against nervus's own key. The second shows it, then runs it.
  (`-k` added at step 3: without it curl also checks nervus's certificate against the machine's own
  trusted authorities, which do not know nervus's private one, and refuses it. With `-k` the pin is
  still checked, and a wrong pin is refused; shown with real curl in the route's tests.)
  The script makes the account and its restrictions for the level, then sends the machine's host keys
  and its machine id back to nervus with the same code. nervus pins the keys, checks over SSH
  (`id -un`, then the level: `sudo -n id -un` must fail, or give `root` at full), and only then
  adds the machine. The page then shows it enrolled.
- b. One line, `curl … | sudo sh`. Shorter, but it runs a root script unread, which ADR-0023 7b
  refused for the installer.
- c. The UI shows the whole script to paste into a root shell, and the script prints the host keys
  for the person to paste back into the UI. No connection from the machine to nervus, but two pastes
  of long text each way.

*Recommended: a.* It is ADR-0005 decision 4's "one-line command with a short-lived token", plus one
line to read it first. The code is one-time, expires in 15 minutes, and is stored as a hash
(ADR-0012). The pin needs no file on the machine and fails closed.

### 3. Where enrolled machines are kept

- **a. A table in the database, one row per machine: its name, the address nervus uses, its level,
  its pinned host keys, its machine id, and when and by whom it was enrolled.** `hosts.yaml` stays
  for machines described by hand, and for the hypervisor's entries. Names are unique across both. A
  token's allowlist (ADR-0014) may name either. nervus reads the table at every call, so enrolling
  needs no restart.
- b. Rows written into `hosts.yaml` and `known_hosts`. The text files nervus would rewrite while
  running, which ADR-0011 decision 1 moved to the database to avoid.

*Recommended: a,* as ADR-0022 5a did for VMs.

### 4. The address nervus uses

- **a. What the person types on the page: a name or an address, pre-filled with the address the
  enrollment request came from, which they can change.** A machine on DHCP should be given a
  reserved address or a name, as the docs say for nervus itself.
- b. Always the address the request came from. Wrong behind a VPN or a router that rewrites it.

*Recommended: a.* A host has no guest agent to ask where it moved (ADR-0022 5a), so the person
chooses something stable once. If it moves, the page lets them change it; the pinned keys stay.

### 5. Changing the level, or removing a machine

- **a. The level changes only when the person at the machine runs a new enrollment command for it.**
  Removing it in the UI forgets the machine and shows the commands that take nervus's account and
  key off it, to run there.
- b. As a, and the UI may also lower a machine's level from afar, never raise it: nervus, holding
  full access, rewrites `authorized_keys` itself.

*Recommended: a.* ADR-0005 decision 5 gives the level to the person at the machine; lowering from
afar is a convenience that can come later without changing anything here.

### 6. nervus's own machine

- **a. The script sends the machine id (`/etc/machine-id`); nervus compares it with its own, and
  refuses full access to the machine it runs on. Read-only and standard are allowed:** the account
  can read nothing of nervus's (its secrets are `0700 nervus`, its log's folder `0750 nervus`), and
  cannot stop nervus's processes.
- b. Refuse every level there.

*Recommended: a,* as ADR-0023 question 4 decided: the danger is root, not the account.

### 7. Which machines

- **a. Linux with OpenSSH: `useradd` and an SSH server always; `sudo` for full (the script installs it
  with `apt-get` if missing, and otherwise says so); `bwrap` for read-only, likewise.** macOS and
  others by hand, as today.
- b. Also macOS, with its own account tools; read-only there would need another mechanism.

*Recommended: a* for the preview; b as an ADR of its own if friends ask.

*Amended 2026-10-19 after procedure 037, at the operator's word* ("have the enrollment script install
tmux, and record that in ADR-0024 decision 7"): the script also installs `tmux`, at every level,
likewise. `exec_bg` and `job` keep each job in a tmux session, and the trial's VM, cloned from the
template, had none, so background jobs failed there until it was installed by hand. ADR-0005
decision 2 had left `tmux` to the person setting the machine up.

### 8. When what a name reaches changes under the tokens that name it

*Added 2026-10-19, raised while building step 4.* A token's allowlist names machines (ADR-0014), so
a token reaches whatever nervus calls that name now. nervus cannot tell one machine from another
across a reinstall: a fresh install has new host keys and a new machine id. The name is the only
thing that carries over, and only the operator chooses it: codes are made only in the signed-in UI,
and a machine cannot name itself. So the risk here is not an attacker but the operator forgetting,
months later, which tokens name what. The cases:

| | what the operator wants for the tokens that name it |
|---|---|
| the same machine reinstalled | to keep working |
| new hardware in the old one's place | to keep working |
| the same machine raised to a higher level | to be told: every token naming it gains that level |
| a removed name reused for an unrelated machine | not to reach it unknowingly |
| a machine removed for good | nothing, until its name is reused |

A reinstall needs no removal: adding the machine again under its name replaces its row (decision
3), new keys and machine id included, and its tokens keep working. A name with no machine that
tokens still name can only be a removed one, or one taken out of `hosts.yaml`; the token form never
offers a name nothing has.

- **a. Tokens follow the name, and the Machines page asks before a change gives them something new.
  Making a code for a name that tokens still name but no machine has, or for a higher level than its
  machine has, shows those tokens and what they will reach, and goes ahead only with the name typed.
  The same name at the same or a lower level asks nothing. The page says that a reinstall is adding
  the machine again under its name, not removing it.** The record of the code's making lists the
  tokens shown. Removal keeps showing the tokens that still name the machine (step 4).
- b. Refuse a name that tokens still name while no machine has it. The operator's first instinct,
  and the strictest; but a machine removed and then reinstalled needs new tokens, each pasted again
  into every client's settings, and a name in the token file, which the UI cannot revoke, could never
  come back through the page.
- c. As built in step 4: say at removal which tokens still name the machine, and nothing later.
  Nothing stops the unknowing reuse, and nothing is said when a level is raised.
- d. Removal also revokes the tokens that name the machine. A token naming other machines too would
  lose them, a token's machines cannot be changed once issued (ADR-0014), and the token file is not
  the UI's to change.

*Recommended: a.* It asks at the one moment the operator is there to answer, only when the answer
matters, and keeps a reinstall to one step. A raised level is asked about for the same reason as a
reused name: what the tokens reach changes without anything said.

### 9. Read-only where AppArmor keeps programs from making user namespaces

*Added 2026-11-07, raised by procedure 054.* Ubuntu keeps an unprivileged program from making a user
namespace unless an AppArmor profile for that program allows it: 23.10 added the restriction, off,
and 24.04 turned it on, in its `apparmor` package (`kernel.apparmor_restrict_unprivileged_userns =
1`); later releases' notes say nothing of changing it. A namespace an unconfined program makes is
moved into the profile `unprivileged_userns`, which refuses it its uid map. bubblewrap needs one, so
decision 1's read-only shell cannot start there, and enrollment refuses read-only, as decision 1
says. Ubuntu's documented way, for a program that needs user namespaces, is an AppArmor profile for
that program that allows them (`userns`).

- a. Say so: where the machine restricts user namespaces, read-only is refused, and the docs name
  Ubuntu 24.04 and later, so the owner chooses standard there.
- **b. nervus's own copy of bubblewrap, which only `agent` may run (`/usr/local/lib/nervus/bwrap`,
  `0750 root:agent`), given an AppArmor profile of nervus's (`/etc/apparmor.d/nervus-bwrap`) that
  allows it user namespaces and nothing else. The read-only shell runs the copy with
  `--disable-userns`, so no command inside the sandbox makes a namespace of its own. An apt hook
  (`/etc/apt/apt.conf.d/99nervus-bwrap`) makes the copy the system's again whenever apt changes
  packages, so it never lags bubblewrap's updates. The script makes the three only at read-only, and
  only where bubblewrap cannot start as installed and the machine's AppArmor restricts user
  namespaces; at standard and full, and by the removal commands, they are taken off.**
- c. Ubuntu's own bubblewrap profile, `bwrap-userns-restrict` (in `apparmor-profiles` on 24.04),
  switched on. It changes bubblewrap for every program and account on the machine, and Ubuntu took it
  out of 24.04's defaults after it broke Flatpak (Launchpad bug 2072811).
- d. Turn the restriction off (`kernel.apparmor_restrict_unprivileged_userns = 0`): Ubuntu's
  protection undone for every program on the machine.

*Recommended: b.* It is Ubuntu's own way for one program, kept to nervus's account. No other program
or account on the machine gains anything, and `agent` gains only what the read-only sandbox needs:
at read-only every command it runs is inside that sandbox, where no namespace can be made. At
standard `agent` runs commands outside any sandbox, so the copy must not exist there. Tried by hand
on procedure 054's Ubuntu 24.04 machine before this was written, then undone: as `agent` the
sandbox started, `/etc` and `agent`'s home refused writes, `~/.nervus` took them, and a namespace
asked for inside was refused; the system's bubblewrap stayed refused to `agent`; another account
could not run the copy.

*Amended 2026-11-08 after procedure 055, at the operator's word ("I'm good with that fix"):* Ubuntu
26.04 ships and loads its own bubblewrap profile, `bwrap-userns-restrict`, so bubblewrap starts as
installed there, read-only takes the plain path, and the script makes none of b's three files. What
runs inside is confined by that profile's `unpriv_bwrap`, which refused the capability a mount needs,
but a command could still make a user namespace. So the read-only shell gives `--unshare-user
--disable-userns` to the system's bubblewrap too, wherever that bubblewrap knows the flag (0.8 and
later), as it always has to nervus's copy: no command inside the sandbox makes a namespace of its
own, wherever bubblewrap can refuse it, whichever path the machine takes.

## Settled already

- **The account is `agent`**, with exactly nervus's key (ADR-0001 s4).
- **Every enrollment is audited**, actor `operator`, the level and the machine id with it; the
  machine's request is recorded under the one-time code's id, never the code itself (ADR-0012
  decision 6).
- **Host keys come from the machine itself**, sent with the code over the pinned HTTPS connection,
  and are checked over SSH before the machine is added.

## Consequences

1. **For a friend:** "Add a machine" in the UI, two lines on the machine, and it is there, read-only
   unless they choose more. `docs/install.md` step 3's hand commands become "By hand".
2. **For nervus:** a second inventory table beside the VMs'; an enrollment route on port 8000 for the
   script and the host keys; a small read-only shell program on each read-only machine.
3. **For agents:** the level shows in `hosts`. A write refused on a read-only machine is the
   machine's refusal, with its reason.
4. **Not changed:** machines in `hosts.yaml`, this installation's included, keep full access until
   their owner enrolls them afresh.
5. **For the operator (question 8):** tokens follow a machine's name; reusing a removed name, or
   raising a level, is asked about once, on the page, with the tokens it affects.
6. **For a read-only machine whose AppArmor restricts user namespaces (question 9):** three more
   files of nervus's there, a copy of bubblewrap, its AppArmor profile and an apt hook, each named in
   the script's opening comment, and taken off at another level or by removal.

## Order of work

Each step waits for the operator (rule 1).

0. ~~The operator's decisions on 1 to 7.~~ Done 2026-10-19: all as recommended.
1. ~~The read-only shell, the forced command's program: `bwrap` with `~/.nervus` writable, `sftp-server
   -R` for SFTP; tested on a throwaway Debian VM and container, then Ubuntu 24.04.~~ Built 2026-10-19
   (`src/nervus/target/readonly-shell`, 11 tests) and tried on a Debian 13 VM and unprivileged
   container through their own SSH servers, every check passing (procedure 036). Ubuntu 24.04 tried
   by the newcomer trial, procedure 054, 2026-11-07: refused, as the Context says; question 9.
2. ~~The enrolled-host table, read at every call beside `hosts.yaml`.~~ Built 2026-10-19
   (`enrolled_hosts.py`), not deployed. The UI's token form learns enrolled machines in step 4.
3. ~~The enrollment code, its route (the script; the host keys back), and the script for each level,
   with tests.~~ Built 2026-10-19, not deployed: `enrollment_codes.py` (a hash kept, 15 minutes, one
   report), `host_enrollment.py` (the script for each level, and `GET`/`POST /enroll/<code>` beside
   `/mcp`); 84 tests, the script in real `sh` and `dash`, the route over real SSH and real curl, each
   guarantee broken on purpose and caught. Over plain HTTP, and in lockdown, it enrolls nothing.
   Fixed the same day, found while writing step 6's trial, at the operator's word: the script made
   the account before nervus judged it, so at full on nervus's own machine it left root by nervus's
   key although nervus refused. Now a full script compares a hash of the code and nervus's machine
   id first and changes nothing there, and a refused enrollment takes nervus's key back off.
4. ~~The UI's "Add a machine" page and removal.~~ Built 2026-10-19, not deployed: a Machines page
   lists enrolled machines and the codes made in the last day with what became of each; adding shows
   the two lines once (none over plain HTTP); an address can be changed, keeping the keys; removing
   needs the name typed and shows the commands that take nervus off the machine (tested as written)
   and the tokens that still name it. The token form offers enrolled machines. Decision 4a's address
   is optional on the page: left blank, nervus uses the one the machine's report comes from, since
   that address exists only once the machine reports. Seen working in a browser.
4a. ~~Question 8 (decided 2026-10-19, a): the Machines page's question before a reused name or a
   raised level, with tests. Before step 5, so the docs describe it.~~ Built 2026-10-19, not
   deployed: the question lists the tokens and what they will reach, and goes on with the name
   typed. A raised level that no token reaches asks nothing, since no token gains anything. Seven
   guarantees broken on purpose and caught; seen working in a browser.
5. ~~`docs/install.md` step 3 and `docs/clients.md`, tested as written.~~ Done 2026-10-19: step 3
   adds machines on the Machines page, the hand commands kept as "By hand: a machine nervus
   reaches"; `docs/clients.md` says what each level lets a client do; both tested as written
   (`tests/test_enrollment_docs.py`). Found while writing it, and fixed the same day at the
   operator's word: on a read-only or standard machine a refused upload hinted to send `root=1`,
   which cannot help where there is no `sudo`; it now names the machine's level instead.
6. A trial on throwaway machines, then a deploy procedure, each for approval. **The trial done
   2026-10-19** (procedure 037): verification items 1 to 8 all observed on a real VM and container.
   It found three faults to fix first: a failed fetch lets the second line run an older script; the
   request log writes enrollment codes into the journal; the installer's closing text describes the
   old step 3. **All three fixed the same day**, at the operator's word, with the two smaller
   findings: the script checks its code before changing anything; enrollment codes are kept out of
   the request log; the installer's next steps describe the Machines page; the script installs tmux
   (decision 7, amended); an unknown machine is "not in nervus's inventory". Next, the deploy
   procedure.
7. ~~Question 9 (decided 2026-11-07, b): the script, the read-only shell, the removal commands and
   the docs, with tests; then tried through a trial nervus on procedure 054's Ubuntu 24.04 machine,
   as verification item 9 says.~~ Done 2026-11-07: built with its tests (`e78090c`), each new test
   seen to fail first; item 9 observed (procedure 054).
8. ~~Question 9 as amended 2026-11-08: the read-only shell, with tests; then tried through a trial
   nervus on procedure 055's Ubuntu 26.04 machine, as verification item 9 says.~~ Done 2026-11-08: the
   shell (`bae6d65`), three tests seen to fail first; item 9 observed on Ubuntu 26.04 (procedure 055).

## Verification

1. On a machine that has never seen nervus, the two lines run as root enroll it read-only, and a
   client can run a command there (ADR-0011 verification 4).
2. On that machine a write outside `~/.nervus`, by `exec` or by `put`, is refused **by the machine**,
   and `exec`, `exec_bg` and `get` still work (ADR-0005 verification 3).
3. Standard: `sudo -n` fails; a file `agent` owns can be written. Full: `sudo -n id -un` gives `root`.
4. A code works once, within 15 minutes; a script fetched with a wrong pin is refused by `curl`.
5. The pinned keys are the machine's own; a server at that address with other keys is refused.
6. Full access to nervus's own machine is refused, with the reason; read-only there is allowed.
7. Removing a machine forgets it; its commands, run there, leave no `agent` account and no key.
8. Making a code for a removed name that tokens still name, or for a higher level, shows those tokens
   and goes ahead only with the name typed; adding a machine again at its own level asks nothing,
   and its tokens reach it once it is enrolled.
9. On a machine whose AppArmor restricts user namespaces, read-only enrolls, item 2's checks pass, and
   a namespace asked for inside the sandbox is refused; the system's bubblewrap is still refused to
   `agent`, and the copy to every other account. Enrolled again at standard, none of the three files
   is left, and the removal commands leave none. **Observed, procedure 054, 2026-11-07,** on Ubuntu
   24.04 through a trial nervus's Machines page, its apt hook included. *As amended:* whichever path
   the machine takes, nervus's copy or its own profile for bubblewrap, a namespace asked for inside
   is refused. **Observed on Ubuntu 26.04, procedure 055, 2026-11-08,** by its own profile.

## Amendment 2026-11-08: the read-only sandbox leaked through agent's session bus on Ubuntu 26.04 (procedure 057, finding 5)

The security review before the 0.2.0 export asked whether the read-only sandbox fully contains a
read-only agent -- verification item 2's property, "a write outside `~/.nervus` is refused by the
machine." A trial on throwaway VMs (procedure 057) found it **did not hold on Ubuntu 26.04**, the
current LTS.

The sandbox makes only the filesystem read-only; it shares the host's PID, IPC and network namespaces
(the network on purpose). `--unshare-user` puts each command in a child user namespace, which blocks
the routes through `/proc/<pid>/root` of a process outside the sandbox (the ptrace-mode check fails
across user namespaces). But an `agent` SSH login also starts a `systemd --user` manager that runs
*outside* the sandbox, as the same user, and its **session bus** (`/run/user/<uid>/bus`) was reachable
from inside the sandbox on Ubuntu 26.04. A command could therefore `systemd-run --user` and have that
outside manager write anywhere `agent` can -- escaping read-only. Confirmed end to end: the file
landed in agent's real home. Debian 13 did not expose the bus in the sandbox's mount view, so it was
already contained; only testing Ubuntu, and 26.04 specifically, caught this.

**The fix (procedure 057).** The read-only shell masks the per-user runtime directory -- `--tmpfs
/run/user` in its bubblewrap invocation -- so the session bus and the `systemd --user` private socket
are not reachable from inside the sandbox. tmux's socket lives in `~/.nervus/tmux`, not `/run/user`,
so background jobs are unaffected; this avoids `--unshare-pid`, which would have killed the detached
tmux server a job depends on. Re-verified on a fresh Ubuntu 26.04 VM: the bus is unreachable,
`systemd-run --user` fails, nothing lands outside `~/.nervus`, direct and `/proc` writes stay blocked,
ordinary commands run, and a detached background job survives across connections.

Verification item 2 gains: *and a command inside the sandbox cannot reach agent's session bus or the
`systemd --user` manager to write for it* (test in `test_readonly_shell.py`, seen to fail first;
observed on Ubuntu 26.04, procedure 057).

## Amendment 2026-11-13: in agent's home, the enrollment script acts as agent (procedures 056 and 058)

The enrollment script runs as root on the machine being added and puts nervus's line in `agent`'s
`authorized_keys`. That folder is `agent`'s own. Where `agent` has no sudo — the standard and
read-only levels — anything root does there by path can be turned onto a file elsewhere by a link
`agent` plants or swaps in: the review's C32. Its first fix (2026-11-12) wrote the staging file so
that a link planted beforehand is refused; root's chown, chmod and rename of that name, which
followed, could still be turned by a link swapped in between them.

`agent` now writes the file itself: root leaves the line, which is no secret, where `agent` can read
it, and `agent` makes `~/.ssh`, writes the file and renames it into place. As `agent`, a link reaches
only what `agent` could reach already, so no privilege crosses. Taking the key off again, when nervus
refuses the machine, is `agent`'s too. A VM enrolled through its guest agent is unchanged: `agent` has
`sudo` there by decision (ADR-0001 section 4), so there is no line to cross.
