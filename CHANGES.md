# Changes

What each release of nervus changes, for someone running it. One section per release, newest
first. A release is one export of the preview; its number is `version` in `pyproject.toml`, which
`nervus-ctl status` and the web UI show. Each section's first line is the day its release was
exported; until then it says "Not yet exported.", and what is still being built. Then come three
heads: what you will see, what each client must do, and what the upgrade does on nervus's
machine. An ADR named beside a change is the decision record behind it, in `decisions/`.

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
