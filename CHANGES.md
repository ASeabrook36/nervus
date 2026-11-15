# Changes

What each release of nervus changes, for someone running it. One section per release, newest
first. A release is one export of the preview; its number is `version` in `pyproject.toml`, which
`nervus-ctl status` and the web UI show. Each section's first line is the day its release was
exported; until then it says "Not yet exported.", and what is still being built. Then come three
heads: what you will see, what each client must do, and what the upgrade does on nervus's
machine. An ADR named beside a change is the decision record behind it, in `decisions/`.

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
