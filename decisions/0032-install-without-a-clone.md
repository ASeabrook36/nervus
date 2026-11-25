# ADR-0032: nervus installs from a release, and a laptop from nervus, with no clone anywhere

**Status:** Proposed 2026-11-24. **Decided by the operator on 2026-11-24**, in a Claude Code
session, as the research note of the same day (`research/2026-11-24-install-experience.md`) put
them: the release download; the laptop's command served by nervus itself; the client's settings
printed, not made; the separate box as the front page's first door. Then, on being told the two
things the note left open: one line rather than two for a machine ("one line is better"), and the
container image beside the release download, not replacing it ("for now the container image
should sit beside the release download"). Questions 1, 2, 4, 6, 7, 8 and 9 below record those
answers. **Questions 3 and 10 were decided the same day, each as recommended.** Questions 11 and
12, Windows, were added when the operator found that the draft had left Windows laptops out
without asking. **Questions 5 and 11 were decided the same day, a for each** ("for question 5, my
answer is yes. for question 11, my answer is yes"), after question 5 was made to say how the line
knows the laptop, the client and where the token goes. **Question 12 was decided the same day,
b** ("Wait for the image"), once the operator had asked what WSL2 asks of a person. **Every
question is answered.** The record stays Proposed until its verification is observed. Nothing is
built. **Question 13 was added and decided during the build, a** ("Show it once"), on
2026-11-24. **The Windows laptop's trial waits for a later session**, at the operator's word that
day, asked how the Windows installer should reach the trial ("Leave Windows for later"): Microsoft's
evaluation download needs their registration. Steps 2 to 6 build Windows' line, script and helper
as question 11 decided; verification 5's Windows part is observed in that later session, and the
record stays Proposed until it is.
**Its verification was observed on 2026-11-25** on throwaway machines (procedure 069), every item
but verification 5's Windows part.
**Date:** 2026-11-24
**Asked for by:** the operator, 2026-11-24: "asking people to clone a GitHub repo is too much …
somebody could have a very straightforward path for getting nervus up and running".
**Builds on:** ADR-0005 decision 1 (the container image); ADR-0006 (clients sign in, so no token
is copied); ADR-0008 (the connector on the client's machine); ADR-0018 (the preview); ADR-0021
(each client machine trusts nervus's root, once); ADR-0023 question 7 (the installer, run from a
copy of the repository); ADR-0024 question 2 and ADR-0026 (a machine added by the web UI, or by
lines run on it); ADR-0029 (upgrading from a newer tree, a clone or an archive).
**Amends, once Accepted, each to be marked there:** ADR-0023 question 7 (where the tree comes
from), ADR-0024 question 2 a (two lines become one), ADR-0021 (how a laptop gets nervus's root),
and ADR-0018 decision G (how a friend installs it, already moved on by ADR-0023's installer).
**Written to the policy of ADR-0019:** this record names no system.

## Context

### What a newcomer does today, in 0.3.0

| place | what they do |
|---|---|
| nervus's machine | clone the repository; `sudo ./install.sh --address … --name …`, the address and name typed into the command; copy down a recovery key, a fingerprint and a sign-in link |
| each machine nervus reaches | nothing, by Connect, if it takes a password login with `sudo`; otherwise two lines pasted into a root shell there |
| each laptop | clone the repository again; `tools/nervus-trust`; copy a token from the web UI into an environment variable or the keychain; write each client's settings by hand; restart the client; `tools/nervus-status` |

The source code is needed in two of the three places, and only to run one script in each. Nothing
in nervus needs the history, the tests or the decision records on either machine.

### What is already decided and not built

The operator's order of 2026-11-15: client sign-in (ADR-0006), then the connector (ADR-0008),
then the container image (ADR-0005 decision 1). Sign-in removes the copied token. The connector
removes the certificate step. The image is a second way to run nervus. None of them removes the
clone on nervus's machine, and the connector has to reach the laptop somehow. This record answers
both.

### What the pieces already allow

- **The installer already takes an archive** (`install.sh`'s header; ADR-0029 question 1). A tree
  that is not a clone is installed as it is, and named by `tools/release-name`.
- **A machine already fetches a script from nervus with nervus's key pinned** (ADR-0024 question
  2): `curl --pinnedpubkey 'sha256//…'`, which refuses any server whose public key is not
  nervus's. That key survives renewal: nervus re-issues its certificate for the same key
  (`tls.py`, `key_fingerprint`).
- **The repository is public now.** ADR-0023 question 7 turned down `curl … | sudo bash` partly
  because it was private.

## Questions

### 1. What nervus's machine downloads, and from where

- **a. One archive per export, made at export from the preview repository's export commit,
  attached to that release on the repository's release page, with its SHA-256 written into the
  install line on the same page.**
- b. The source archive GitHub generates for the release's tag. Nothing to upload, but GitHub
  makes those bytes on request and has changed them before (2023), which breaks a hash written
  down earlier.
- c. A clone, as today.

**Decided 2026-11-24: a release download** (research note, question 1 a). *a over b is this
draft's recommendation:* the hash is of a file made once and kept.

What the hash proves, said plainly: the file is whole, and is the one the release page names. It
does not protect against someone who controls the repository's account, who could change both.
Signing releases is not settled here.

### 2. What the person runs on nervus's machine

- **a. One line, copied from the release page: it downloads the archive, checks its SHA-256,
  unpacks it into a folder named for its release, and runs `sudo ./install.sh` from there.**
  Nothing is piped into a shell. The installer shows its plan and waits for `yes`, as it does now.
  The same line with `--upgrade` upgrades (ADR-0029), since the folder is the release's own.
- b. `curl … | sudo bash`: a bootstrap script that does the same. Shorter, but a script run as
  root before anyone has seen it, which ADR-0023 question 7 turned down, and which this project
  tells agents never to do.

**Decided 2026-11-24: a** ("downloads that release, checks it, shows the plan, waits for yes,
then runs today's installer").

```bash
curl -fsSLO <release page>/nervus-0.4.0.tar.gz && echo '<sha256>  nervus-0.4.0.tar.gz' | sha256sum -c - && tar -xzf nervus-0.4.0.tar.gz && cd nervus-0.4.0 && sudo ./install.sh
```

In a root shell, as on a fresh container with no `sudo`, the page gives the same line without
`sudo`. The README cannot carry the line, since the archive holds the README and so cannot hold
its own hash. The README links to the latest release instead.

### 3. Whether the installer asks for its address, or must be told

The line above has no `--address`. Today the installer refuses to run without it, so the person
would have to edit the line before pasting it.

- **a. Asked, when not given.** The installer lists the machine's own addresses, and its hostname
  as a name, and asks which ones clients will use. `--address` and `--name` still skip the
  question, for scripts and for the guide's examples.
- b. Required, as now. The release page's line has a placeholder the person replaces.

*Recommended: a.* A line that has to be edited before it's pasted is the step people get wrong,
and the installer knows the answers better than the person does. **Decided 2026-11-24: a.**

### 4. How a laptop gets what it needs

- **a. One line, shown on the web UI's Clients page, run as the person, not as root. It fetches a
  script from nervus's MCP port with nervus's key pinned, as a machine's line does.** Until the
  connector exists, the script does `tools/nervus-trust`'s job: it saves nervus's root, carried in
  the script itself, to the same files `nervus-trust` writes (`~/.config/nervus/root-<nervus>.pem`
  and `roots.pem`). Then it prints what each client needs (question 6). Once the connector exists,
  the same line installs it and pairs it (ADR-0008), with no administrator rights (ADR-0008
  consequence 2).
- b. Homebrew, pipx or winget. Familiar, but a package to publish on each, and a second channel to
  trust.
- c. A file per operating system on the release page.

**Decided 2026-11-24: a** (research note, question 2 a).

**How the person knows the line is nervus's.** The page reaches them through a browser whose
view of nervus nothing has checked. An attacker in the middle could show a line carrying their
own key. So the installer now prints nervus's key in the form the line carries it (`sha256//…`),
beside the root's SHA-256 it prints today. The Clients page shows that key above the line and asks
the person to check it is the one the installer printed. *As built:* the Machines page shows it
above a machine's line too, the same key that line has always pinned (question 7). This is the same single comparison
ADR-0021 asks of `nervus-trust --expect`, and ADR-0008 decision 2 asks of the connector. Here it
is made once, by eye, before running anything.

**Windows laptops: open, question 11.** The first draft said a Windows laptop was not covered.
That was the drafting session's own choice, not the operator's, and it is withdrawn.

### 5. Whether the laptop's line carries the client's token

ADR-0006's sign-in removes the token. Until it is built, and afterwards for clients whose sign-in
fails (ADR-0006 decision 7), a token has to reach the client.

- **a. Yes, by a one-time code.** Issuing a token on the Clients page makes, beside it, a code
  that works once, within 15 minutes, as a machine's code does. The page shows the line with the
  code in it. The script fetches the token with the code and keeps it in a place of nervus's own
  on the laptop. The commands it prints tell the client to read it from there (below). The token
  is never on the screen, in a clipboard, or in any command's arguments.
- b. No. The line does the certificate step only. The token is shown once on the page and copied
  by hand, as today.

**How the script knows what to do with it** (asked by the operator, 2026-11-24: "how does it
know if the person has a Linux computer or a Windows computer … how does the user indicate which
client application … how does our script know exactly where to place that key?"). It guesses none
of the three:

- **The operating system, from the laptop itself.** The script runs there, and asks it
  (`uname`). macOS and Linux run the same line. Windows cannot run it, so a Windows laptop would
  get a line of its own (question 11).
- **The client application, from the token.** The person says which client when they issue the
  token. Today the Clients page asks for the client as free text, so nothing nervus could rely on.
  With a, it asks from a list instead: Claude Code, Codex, or other. That fits ADR-0030's one token
  for each client application. The code names the token, so the script learns the application
  from nervus. For "other", it keeps the token, prints where, and prints no client command.
- **Where the token goes: a place of nervus's, not wherever the client happens to look.** Both
  clients can run a command when they connect, which prints the request's headers. Claude Code
  calls it `headersHelper`, as `docs/clients.md` uses now. Codex calls it `http_headers_helper`,
  in its own configuration reference, read 2026-11-24. So the line installs one small helper in
  the person's home folder, as `tools/nervus-headers` is today, and keeps the token where the
  helper reads it: in the macOS keychain, which asks before each read, or on Linux in a file only
  the person can read. What the script prints then points the client at the helper:

  | client | what the script prints |
  |---|---|
  | Claude Code | `claude mcp add-json --scope user nervus '{…, "headersHelper": "<the helper>"}'` |
  | Codex | `codex mcp add nervus --url …`, then a command that adds `http_headers_helper` to `~/.codex/config.toml`, since `codex mcp add` has no flag for it. *As built:* one command that appends the whole `[mcp_servers.nervus]` table, since `codex mcp add` puts its table among the others, where a line appended after it can fall into another (procedure 069, section 2) |

  The only knowledge of the operating system is the helper's: the keychain on macOS, a file on
  Linux. The only knowledge of each client is its own command and the name of its helper setting,
  tested for each client before a release ships. Neither client then holds the token in its
  environment, which is better than today's Codex path (`docs/clients.md`, an environment
  variable).

  **Not yet seen working:** Codex's helper is read from its documentation, partly in summary, not
  observed. That documentation says it is "supported only for locally connected HTTP MCP servers".
  If that means a server on `localhost`, Codex can use it only once the connector exists (ADR-0008),
  and until then keeps its environment variable. Verification 8 settles it. *Seen 2026-11-24
  (procedure 069, section 2):* Codex 0.171 ran its helper and sent its header to a server at a
  network address, not `localhost`; "locally" is where Codex itself runs. So Codex's path is the
  helper.

**Which computer gets the token** is the one the person pastes the line into. The laptop reaches
nervus, never the other way round, as a machine's line does. The code says which token to hand
over, so nervus needs to know nothing about the laptop. Whoever presents the code first gets the
token, once. If someone else got there first, the person's own run fails, saying the code was
used, and they revoke that token on the Clients page.

*Recommended: a.* Copying the token is where ADR-0006's exposure began (its Context, "What went
wrong"). The code is the pattern enrollment already uses, and the fallback ADR-0006 keeps needs it
anyway. **Decided 2026-11-24: a** ("for question 5, my answer is yes").

### 6. Who changes the client's own settings

- **a. The person. The script prints the exact commands for each client it finds installed
  (`claude mcp add …`, `codex mcp add …`), and they run them.** A setting with no command of its
  own is printed as a command that makes that one change.
- b. The script makes the changes, asking first.

**Decided 2026-11-24: a.** Every change to the person's computer is one they ran themselves.

### 7. A machine's lines: one, not two

- **a. One line, `curl … --pinnedpubkey … '<enroll URL>' | sudo sh`, or `| sh` in a root shell.**
  The script is written so that a download cut partway runs nothing: its body is defined first and
  called only on its last line. The Machines page shows the script's text beneath the line, for
  anyone who wants to read it first. Its code is checked when the script runs, as now, so reading
  it costs nothing.
- b. Two lines, as now: fetch to a file, then `less` it and run it.

**Decided 2026-11-24: a** ("one line is better"). Connect stays the page's first way, and this
the way for a machine that takes no password.

### 8. Which door the front page opens first

**Decided 2026-11-24: nervus on a separate box on the network (tier 1) first; "try it on this
computer" second, marked as less safe.** On Linux the second door is the same line, tier 2. On a
Mac it waits for the container image, which runs there in Docker Desktop at tier 3. Until then a
Mac runs Linux in a VM, as `docs/install.md` says now. On Windows, see question 12.

### 9. The container image, beside the release download

**Decided 2026-11-24: the image sits beside the release download, two ways onto the same release,
not replacing it** ("for now"). ADR-0005 decision 1 still decides the image. What it brings for
upgrades, backups and sandboxing is that record's to settle when it is built (ADR-0029, "an
upgrade of its own").

### 10. Where this falls in the order of 2026-11-15

- **a. First: this record, then sign-in, then the connector, then the image.**
- b. After sign-in, before the connector.
- c. Last, after the image.

*Recommended: a.* It is small and builds on what exists: the installer, the archive path, the
pinned fetch. It removes both clones at once. And the connector needs its delivery (question 4)
anyway. **Decided 2026-11-24: a.**

### 11. A Windows laptop: the computer Claude Code or Codex runs on

Both clients run on Windows. Nothing on nervus's side would change: the same route, code and
token. What would be new is all on the laptop:

- a second line on the Clients page, for PowerShell, beside the macOS and Linux one. Windows 10
  and 11 come with `curl.exe`, which should be able to make the same pinned fetch. That is not yet
  seen;
- a second script and helper, in PowerShell, doing what the first two do;
- the token kept by Windows' own per-user encryption, which only that Windows account can open,
  in place of the keychain or a private file;
- a Windows VM, made once, and tried at every release's trial.

A client run inside WSL, Windows' built-in Linux, takes the Linux line unchanged.

- **a. Covered by this record, as above.**
- b. Not in this record. A Windows laptop keeps today's path, an environment variable and the
  root set by hand, which has never been tried on Windows, until a record of its own.

*Recommended: a.* It is a second copy of a small script, not new machinery, and most people who
might use nervus are on Windows or a Mac. The larger cost is the Windows machine at each trial.
**Decided 2026-11-24: a** ("for question 11, my answer is yes").

### 12. nervus itself on a Windows computer

ADR-0023 question 2 a (decided 2026-10-19) left Windows out of the preview, because every
supported place runs the same installer under Linux's service manager, so only one path needs
testing. It listed WSL2 as tier 3, untested.

- **a. In WSL2, tried and documented as tier 3**, as "try it on this computer" for Windows: the
  release line, run inside WSL2's Linux, with its service manager switched on. Two things need
  setting on the Windows side, and the guide would say how. WSL stops its Linux when no window is
  open, so nervus would stop with it. And WSL keeps its Linux behind a private network, so other
  computers cannot reach nervus without a Windows setting. Clients on the same computer reach it
  as it is.
- b. Left to the container image, which on Windows runs in Docker Desktop, itself on WSL2, at
  tier 3.
- c. Natively, as a Windows service. Most of what installs, upgrades and backs up nervus assumes
  Linux: its own account, file permissions, its service, its release folders. A rewrite of each,
  for a tier-3 place.

*Recommended: a*, if the operator wants Windows in "try it on this computer" before the image
exists; b otherwise. Not c. **Decided 2026-11-24: b** ("Wait for the image"). The operator asked
what WSL2 asks of a person first. Getting it is one command, `wsl --install`, and a restart. Keeping
a service running in it is the awkward part: a startup task so it does not stop, logged in to
Windows for it to run, and an address that can move. Docker Desktop, which the image uses on
Windows, sets WSL2 up out of sight and deals with most of that, so the session recommended
waiting. Until then a Windows user runs nervus on a separate box, the front page's first door,
and their laptop is question 11's.

### 13. Issuing a token when nervus serves plain HTTP

Raised by the build's independent review (procedure 069). Someone runs nervus with
`--insecure-plain-http`, on a network they control, and issues a token on the Clients page. Over
plain HTTP there is no key for the laptop's line to pin, so the page can give no line; and
question 5 a says the token is never on the screen. Built as first written, that nervus could give
a new client no token from its web UI at all, only by editing its token file.

- **a. Over plain HTTP only, the page shows the token's value once, as 0.3.0 did, and says why
  there is no line.** Over HTTPS, the line, and the token never shown.
- b. Refuse: over plain HTTP the Clients page issues no token; a client is given one in the token
  file by hand.

*Recommended: a.* Plain HTTP already sends every token across the network unencrypted, and its
web UI listens on loopback alone; showing the value once there is what 0.3.0 did, and loses
nothing the mode has not already given up. **Decided 2026-11-24: a** ("Show it once").

## Settled already

- Connect, an admin password typed once on the Machines page, stays the first way to add a
  machine (ADR-0026).
- `tools/nervus-trust` and `tools/nervus-status` stay, for anyone with a clone. A laptop set up by
  either path writes the same files, so a client set up before this changes nothing.
- An installation made from a clone upgrades from a clone, and one made from a release from a
  release. The installer takes either (ADR-0029).

## Not chosen

- `curl … | sudo bash` on nervus's machine (question 2 b).
- A `.deb` and an apt repository: signing keys and a repository to run. ADR-0023 put it after the
  image, "if at all".
- A Proxmox one-liner that makes nervus's container: familiar to some, but for one hypervisor
  only.
- Homebrew, pipx or winget for the laptop (question 4 b).

## Not settled here

- Signing releases, beyond the SHA-256 on the release page.
- A Windows machine as one nervus reaches: its SSH server, and what could keep a read-only account
  read-only there.
- Sign-in (ADR-0006), the connector (ADR-0008) and the image (ADR-0005 decision 1), which the
  laptop's line and the release page later carry.

## Consequences

1. **Export day gains a step.** After the export commit: make the archive, take its SHA-256, and
   publish the release with its page: the install line, the upgrade line, and `CHANGES.md`'s
   section. The operator publishes it, as they push the export now.
2. **The release page becomes where nervus is installed from.** The README points there. The
   guide's own first steps change to the line, and the clone moves into "By hand".
3. **nervus serves one more unauthenticated thing**, the laptop's script, on its MCP port, as it
   serves enrollment's. It holds nervus's root and URL, both public. With question 5 a, the token
   comes only with its one-time code.
4. **`curl | sh` is used, on the laptop and on a machine nervus reaches, bounded:** nervus's key is
   pinned in the line, and each script runs nothing until it has all arrived.
5. **A Mac's "try it on this computer" waits for the image.**

## Order of work

Each step waits for the operator (rule 1).

1. This record, every question answered: done 2026-11-24. It is Accepted only once its
   verification is observed, after step 7.
2. The release archive: a tool run at export, which makes it from the preview's export commit,
   checks it unpacks and installs as the tree does, and prints its SHA-256 and the release page's
   text. The export procedure gains the step.
3. The installer: question 3, and nervus's key printed in its `sha256//` form.
4. A machine's one line, and its script safe against a cut download (question 7). The Machines
   page and `docs/install.md` updated.
5. First, verification 8 on a laptop with Codex: whether Codex's helper reaches a nervus that is
   not on `localhost`. Then the laptop's line: nervus's route serving its script, the Clients page showing the line and
   the key to check, the one-time code, the client chosen from a list, and the helper. A second
   line, script and helper for Windows, in PowerShell (question 11). `docs/clients.md` rewritten
   around them.
6. The README and `docs/install.md` opened with the separate box and the release page (question
   8).
7. A trial on throwaway machines: nervus installed by the line on a fresh Debian 13 container,
   Ubuntu 24.04 and Ubuntu 26.04; a machine added by its one line; a macOS, a Linux and a Windows
   laptop set up by theirs, with no clone on any of them.
8. Exported as the next release, its page published.

## Verification

1. On a fresh Debian 13 container and fresh Ubuntu 24.04 and 26.04 machines, the release page's
   line, pasted unchanged, installs nervus with no clone. With question 3 a, there is nothing to
   edit in it. Where a minimal machine lacks `curl`, the page says what to install first.
2. An archive whose SHA-256 is not the line's is refused before anything is unpacked or run.
3. An installation made by the line upgrades from the next release's line (ADR-0029), keeping
   everything.
4. A machine's one line adds it as the two lines did, at each level. A download cut partway, made
   on purpose, runs nothing and changes nothing.
5. On macOS, Linux and Windows, a client set up only by the laptop's line and the commands it printed
   makes a real call through nervus, with no clone on that laptop. The line refuses a server whose
   key is not nervus's.
6. With question 5 a: the token appears in no command's arguments, on no screen and in no file but
   the one named. Its code works once, and not after 15 minutes.
7. A client set up before this, by `tools/nervus-trust`, works unchanged after the upgrade.
8. With question 5 a: before anything is built, on a laptop, Codex's `http_headers_helper` is seen
   sending nervus a token for a nervus that is not on `localhost`, or seen refused. The answer
   decides Codex's path in step 5.
