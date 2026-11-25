# What installing nervus should feel like

A research note, 2026-11-24: not a decision. It sets out the experience a newcomer should have,
from nothing to an agent working on their machines, against what 0.3.0 gives them; says which
parts are already decided (ADR-0005, ADR-0006, ADR-0008, and the order the operator confirmed on
2026-11-15); and names the questions no record answers yet. Each of those becomes an ADR once the
operator has answered it.

## Today, in 0.3.0

A newcomer meets three places, and has to work out for themselves which is which:

| place | what they do there today |
|---|---|
| **nervus's machine** | clone the repository, run `sudo ./install.sh`, copy down a recovery key, a fingerprint and a sign-in link |
| **each machine nervus reaches** | nothing, if it takes a password login with `sudo`: the web UI's Connect does it. Otherwise, open a root shell there and paste two lines |
| **each computer an agent runs on** | clone the repository again; run `tools/nervus-trust`; copy a token out of the web UI into an environment variable or the keychain; write the client's settings by hand; restart the client; run `tools/nervus-status` |

The first two are close to what people expect. The third is where it falls apart: a clone of
the source code on every laptop, a secret copied by hand, and four settings in three files.

## The experience to aim for

Told as one person's first hour. Each step says which record decides it, or that none does yet.

**1. They pick where nervus lives.** The front page offers two doors, and says which is safer:

- *On a small box on your network* (a mini PC, a Proxmox container, a VM on another computer):
  recommended, tier 1.
- *On this computer*, to try it: quick, and tier 3, which the page says plainly.

**2. They install it with one command or one file.** On a Linux box: a command they copy from
the release page, which downloads that release, checks it and shows what it will do before it does
it. With Docker: a compose file. Either way, no clone. *(Not decided: question 1.)* At the end the
installer prints three things and says what each is for: a sign-in link, nervus's fingerprint,
and the recovery key.

**3. They open the link.** Setup asks where nervus runs (built: ADR-0015).

**4. They add their machines from the browser.** For each: a name, a level, its address. The page
shows the machine's key to compare, then asks for an admin password once. They never open a
terminal on that machine. Where it takes no password, the page gives one line to paste into a
terminal already logged in there (built: ADR-0024, ADR-0026; question 4 asks whether two lines
can become one).

**5. They connect their laptop with one command.** The Clients page shows it. It installs the
connector, a small program that runs in the background (ADR-0008), and pairs it with nervus. The
person checks that the fingerprint it shows is the one the installer printed in step 2. That is
the only check they make, once per laptop. *(How the connector is delivered is not decided:
question 2.)*

**6. They add nervus to Claude Code or Codex**, with the one command the connector prints for
each (`claude mcp add …`, `codex mcp add …`), or the connector does it for them *(question 3)*.

**7. The first time the agent uses nervus, a browser tab opens on nervus's approval page**:
"Claude Code wants to use nervus. It will reach: *build-box*, read-write; *media-server*,
read-only. Approve?" They approve. From then on it just works. They never see a token
(decided: ADR-0006).

**8. Day to day** they read the audit log and switch a client off from the same web UI (built).

What the person runs, in all: one command on nervus's box, a password per machine in the browser,
and one command per laptop. Everything else is a page in the browser.

## Already decided, not built

The operator confirmed the order on 2026-11-15: client sign-in (ADR-0006), then the connector
(ADR-0008), then the container image (ADR-0005 decision 1).

- **Sign-in (ADR-0006)** turns steps 6 and 7 from "copy a token into a setting" into "approve once
  in a browser". Claude Code, Codex and Cursor each document OAuth for HTTP MCP servers. This was
  researched, not observed (ADR-0006, "What the clients support"). One open Codex bug on macOS
  could leave no usable login.
- **The connector (ADR-0008)** removes the certificate step and the laptop's clone. The coding tool
  talks to the connector on `localhost`, and the connector talks to nervus over TLS with nervus's
  key pinned. ADR-0008 requires it to install without administrator rights, on macOS, Linux and
  Windows.
- **The container image (ADR-0005 decision 1)** is the compose-file door in step 2.

## The operator's answers, 2026-11-24

Asked in a session on 2026-11-24, as four stories; answered the same day, each with the leaning
below:

- **Question 1: a, the release download.** The container image follows later, as the 2026-11-15
  order has it.
- **Question 2: a, served by nervus itself**, starting with today's certificate step.
- **Question 3: print the command.**
- **Question 5: the separate box first**; "try it on this computer" second, marked less safe.

Question 4 was not asked. Each answer becomes an ADR before anything is built. Still to settle:
where the release download and the laptop command fall against the 2026-11-15 order.

## Open questions

**1. How nervus reaches its own machine, without a clone.**

- a. *A release archive and a small bootstrap command*, published with each release: download,
  check the SHA-256, show the plan, wait for `yes`, then run today's `install.sh` from the
  unpacked tree. Small to build. Upgrades (ADR-0029) work as now, since they already take an
  unpacked archive. ADR-0023 question 7 turned `curl … | sudo bash` down for two reasons. One has
  gone: the repository is now public. The other, a script run unread as root, is met by showing
  the plan and waiting for `yes`, as `install.sh` does now, and by making reading it first easy.
- b. *The container image*, already decided as the way to publish more widely. It brings its own
  upgrade and backup path (ADR-0029 calls it "an upgrade of its own"), its own sandboxing in place
  of the systemd unit's, and Docker Desktop on a laptop is tier 3.
- c. *A Proxmox one-liner* that makes a container and installs nervus in it. Familiar to homelab
  users, but narrow.
- d. *A `.deb` and an apt repository.* The most standard on Debian and Ubuntu. Signing keys and a
  repository to run; ADR-0023 put it after the image, "if at all".

Leaning: a now, since it removes the clone with little new code; b stays where the 2026-11-15
order puts it. Still open: whether b replaces a or sits beside it.

**2. How the connector, and until then the certificate step, reaches a laptop.**

- a. *Served by nervus itself*, fetched by a one-line command that refuses any server whose key is
  not nervus's, the way the Machines page's two lines already work. No third party, and the
  version always matches nervus. The catch: the line is shown in a browser page, and the browser's
  view of nervus has not been checked. So the key in it has to be compared once with the
  fingerprint the installer printed, as step 5 says.
- b. *Homebrew, pipx or winget.* Familiar, but a package to publish on each, and a second channel
  to trust.
- c. *A single file per operating system on the release page.*

Leaning: a. It could ship before the connector exists, doing today's `tools/nervus-trust` job, so
that laptops lose the clone straight away.

**3. Whether the connector changes the coding tool's settings itself, or prints the command.**
Doing it is smoother. Printing it keeps every change to the person's computer something they ran
themselves.

**4. Whether a machine's two lines can be one.** Today one line fetches the script and the
other shows it and runs it. One line is the common pattern elsewhere; two let a careful person
read the script first.

**5. Which door is the default.** ADR-0006 expected nervus "on the same machine as the clients";
ADR-0007 recommends a separate one, and the guide leads with that. The front page has to put one
first.
