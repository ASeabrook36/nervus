# Changes

What each release of nervus changes, for someone running it. One section per release, newest
first. A release is one export of the preview; its number is `version` in `pyproject.toml`, which
`nervus-ctl status` and the web UI show. Each section's first line is the day its release was
exported; until then it says "Not yet exported.", and what is still being built. Then come three
heads: what you will see, what each client must do, and what the upgrade does on nervus's
machine. An ADR named beside a change is the decision record behind it, in `decisions/`.

## 0.4.0

Exported 2026-11-25.

**What you will see:**

- **nervus installs from its release page** (ADR-0032 questions 1 and 2). The page gives one line
  that downloads the release, checks its SHA-256 against the one written in the line, unpacks it into
  a folder of its own and runs the installer from there; a file that is not the one the page names is
  refused before anything is unpacked or run. Nothing is cloned. The same line ending `--upgrade`
  upgrades a nervus installed from an earlier release. A clone still works, as before.
- **The installer asks which address and names your clients will use** (question 3), listing the
  machine's own, when `--address` is not given; `--address` and `--name` still skip the question. It
  ends by printing nervus's key, as `sha256//…`, which the Machines and Clients pages show above each
  line they give, for you to check there.
- **A client's computer is set up by one line from the Clients page** (questions 4, 5, 6 and 11):
  issuing a token asks which client it is for (Claude Code, Codex, or another by name), then shows
  nervus's key and two lines, one for macOS and Linux and one for Windows PowerShell, to run on the
  computer the client runs on, as yourself. The line saves nervus's root where `tools/nervus-trust`
  saves it, puts a small helper there, fetches the token once by a one-time code that works for 15
  minutes, keeps it where only you can read it (the macOS keychain, a file only you can read on Linux,
  a file Windows encrypts for your account), and prints the commands that tell your client to use
  nervus, which you run. **The token is never shown**: not on the page, in a clipboard, in a
  command's arguments, or in your client's environment. A line that expires unused can be made again
  for its token; whatever runs a line first gets the token, so if yours says its code was used and
  you did not run it, revoke the token.
- **Codex reads its token through the same helper** (`http_headers_helper`), seen working against a
  nervus on the network, not only on `localhost` (verification 8), so it no longer needs an
  environment variable.
- **A machine is added by one line**, `curl … | sudo sh`, in place of two (question 7), the script it
  runs shown beneath it on the Machines page. Nothing in either script runs until all of it has
  arrived, so a download cut partway changes nothing.

**What each client must do:** nothing. A client set up before keeps working unchanged: the same
address, root and token. A new client is set up by the line.

**What the upgrade does:** `sudo ./install.sh --upgrade`, from this release's folder, which the
release page's upgrade line downloads and checks. One table is added to nervus's database, for the
one-time codes, whose version stays 1, so going back still starts; a token whose line was never used
lets no one in on the release before, as on this one.

## 0.3.0

Exported 2026-11-20.

**What you will see:**

- **A client can be read-only on a machine other clients change** (ADR-0031). A machine added at
  standard or full now gets two accounts of nervus's: the read-write one, `nervusagent`, at the
  level you chose, and a read-only one, `nervusagent-readonly`, which the machine's kernel keeps
  read-only, as a read-only machine's account is. At read-only, the read-only account alone. The
  Machines page fills in both names and lets you give others, asking first, since an account that
  is there already keeps nothing of its own SSH keys. Where the read-only account's sandbox cannot
  start, a machine at standard or full is added read-write alone, saying why.
- **Issuing a token asks, for each machine with both accounts, whether the token is on it, and if
  so read-only or read-write**, nothing chosen for you. nervus chooses the account from that; the
  client has no say, and the machine refuses what the account may not do. A read-only client may
  `exec`, `exec_bg`, `job`, `get` and `export`; `put` and uploads are refused there, and, where it is
  read-only on the Proxmox host, the `proxmox` tool and a VM by its id. Each refusal is in the audit
  log with its reason.
- **`hosts` gives the level a client has on each machine**: `read-only`, the machine's own, or
  `read-write` for a machine described by hand. The clients page shows where each token is
  read-only, the Machines page each machine's accounts, and the audit page the level each call ran
  at. The machine's own log names the account: `Accepted publickey for nervusagent-readonly`.
- **A machine described by hand can be given a read-only account** from the Machines page, by two
  lines run on it as root; nothing else there changes.
- **An add that nervus refuses, or that stops part way, leaves the machine as it was** (ADR-0031
  question 12): every account's SSH keys and sudo file, nervus's read-only shell and its copy of
  bubblewrap are put back, and the accounts it made are deleted. So a failed attempt to change a
  machine's level leaves nervus the access it had. The packages it installed stay.
- **Removing a machine deletes only the accounts nervus made there** (questions 9 and 13), those of
  names the machine had before included. An account that was there before nervus keeps itself, its
  home and its own keys, and loses only nervus's line and sudo file; so does `agent` on a machine
  added before this release.
- **The names the page gives are never root or one of the machine's system accounts**: none below
  `UID_MIN`, nor above `UID_MAX` up to 65535, `nobody` among them.
- **`~/.nervus` is made its account's alone** wherever nervus uses it; before, `mkdir -p` left it as
  the account's umask made it, `775` on some machines.
- `nervus-ctl status` and `lock --kill-work` list and stop jobs under a machine's read-only account
  too, as `<machine> (<account>)`.

**What each client must do:** nothing. A token issued before keeps reaching what it reached, as
before; a token read-only somewhere is a new token, issued in the web UI.

**What the upgrade does:** `sudo ./install.sh --upgrade`, from this release's copy on nervus's
machine, as `docs/install.md`, "Upgrading", says. Three tables are added to nervus's database, whose
version stays 1, so going back still starts: a release before this one refuses a token read-only
anywhere as unknown, rather than read it as read-write everywhere. Machines added before keep their
one account, `agent`, until you add them again; a read-only assignment there is refused until then.

## 0.2.2

Exported 2026-11-19.

**What you will see:**

- `nervus-ctl status` lists, and `nervus-ctl lock --kill-work` stops, the jobs on every machine
  nervus reaches. Before, they looked only at the machines in `hosts.yaml`, so a job on a machine
  added from the web UI, or in a VM used by its id, was neither listed nor stopped by the off
  switch. A VM is shown as `vmid 104`; a machine that does not answer within ten seconds is named
  as not read (ADR-0003).
- The README's three diagrams leave room at their right for GitHub's own zoom and pan buttons,
  which covered part of each on a desktop screen. On a narrow one they may still sit over the
  diagram, which those buttons then move.

**What each client must do:** nothing.

**What the upgrade does:** `sudo ./install.sh --upgrade`, from this release's copy on nervus's
machine, as `docs/install.md`, "Upgrading", says.

## 0.2.1

Exported 2026-11-16.

**What you will see:**

- The README says how nervus works, with three diagrams: where everything sits, one call from
  start to finish, and the steps of getting started.
- An install on a machine with no Python: the installer asks first whether it may install Python,
  then shows its plan as on any machine. Before, it told such a machine that its address was not
  an IP address (ADR-0023).
- The libraries nervus runs on are the ones this release was tested with. `requirements.lock`
  names every one at an exact version, with a fingerprint of each file, and the installer checks
  each file it fetches against it; a file that differs stops the install (ADR-0029).
- The backup made before an upgrade is kept until the next upgrade, whatever the daily keeping
  removes meanwhile. The upgrade's last line gives the name it is kept under, to check it by, and the
  Backups page and `nervus-ctl status` show which it is (ADR-0029, ADR-0027).
- Adding a machine by an admin login works on a machine that has no `curl`: nervus installs it,
  and says so among its steps. Before, it said the machine could not reach nervus (ADR-0026).
- More in the audit log: every form the web UI refuses, with what was asked and why; and an
  upgrade, or going back, that ends with nervus down (ADR-0012, ADR-0029).
- The audit page's Host column and filter find a call made to a VM by its id, as `vmid 104`, and
  with it a machine's enrollment and what you did to that machine in the web UI (ADR-0013).
- Going back after an upgrade that did not come up checks nervus on the ports of the release it
  returns to, so a release that moved nervus's ports cannot have a good one called down (ADR-0029).
- With a Proxmox host: `tools/proxmox-template` gives the VMs cloned from its template the host's
  own processor model, on which newer programs run; and the `proxmox` tool tells every client what
  a clone takes from its template (ADR-0017).

**What each client must do:** nothing in its configuration. A session that was open across the
upgrade works as before; restart it to be shown the `proxmox` tool's new description.

**What the upgrade does:** `sudo ./install.sh --upgrade`, from this release's copy on nervus's
machine, as `docs/install.md`, "Upgrading", says. It builds this release with its libraries from
`requirements.lock`, which needs the package index, as an install does; keeps the backup it makes
until the next upgrade; and leaves your address, keys, tokens and data as they are. A VM template
built by an earlier release keeps the processor model it was built with: on the Proxmox host, as
root, `qm set <its id> --cpu host` gives its later clones the host's own.

## 0.2.0

Exported 2026-11-15.

**What you will see:**

- Uploads: a file sent from a client's own computer into a machine or a VM, checked by SHA-256
  (ADR-0020).
- HTTPS that Claude Code and Codex trust: each client machine saves nervus's root once, with
  `tools/nervus-trust`, after comparing one fingerprint (ADR-0021).
- VMs used by their id in any tool, enrolled by nervus on the first call (ADR-0022).
- The installer, `install.sh`, which installs nervus with one command on its machine (ADR-0023).
- Machines added from the web UI, by an admin login given once (ADR-0026) or two lines run on the
  machine (ADR-0024), at the level you choose: read-only, standard or full.
- First-run setup: before anything else, the web UI asks where nervus runs, its tier, and shows it
  at the top of every page, with a warning when nervus listens on an address that looks public
  (ADR-0015).
- A short-lived certificate for each call, so each machine's own log names the client behind every
  login (ADR-0025).
- A backup of nervus once a day that only you can open, with the recovery key the installer prints
  once; restored with one command (ADR-0027).
- The release number, in `nervus-ctl status` and the web UI (ADR-0029).
- Upgrading from this release on, with one command from a newer copy, which goes back by itself if
  the new release does not come up: `docs/install.md`, "Upgrading" (ADR-0029).

**What each client must do:** 0.2.0 is installed afresh, so connect each client anew, from
`docs/clients.md`: a new token from the web UI, and nervus's root saved once on each client
machine.

**What the upgrade does:** 0.1.0 had no installer, so there is nothing to upgrade from: install
0.2.0 afresh, from `docs/install.md`.

## 0.1.0

Exported 2026-10-17.

**What you will see:** the tools `hosts`, `exec`, `exec_bg`, `job`, `put`, `get`, `export` and
`proxmox`; the web UI with sign-in; the off switch; client tokens issued from the UI; downloads
(ADR-0016); and VMs made from a template on Proxmox (ADR-0017).

**What each client must do:** connect from `docs/clients.md`, over plain HTTP on a network you
control, since most clients did not yet trust nervus's own certificate.

**What the upgrade does:** nothing: it was the first release, installed by hand from
`docs/install.md`.
