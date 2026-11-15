# ADR-0010: nervus's own TLS — on by default off loopback, its key is what is pinned, and it is made once, on purpose

**Status:** **Accepted 2026-10-05** by the operator.
- Every verification item below is observed. Two points rest on the operator's report:
  `systemctl reload` on the first installation (item 5), and that item 7's open session was
  open before the deploy.
- One point is accepted at the operator's word: item 7 asks for this repository's sessions,
  and the open session observed was another project's (procedure 017, 3b).
- It was Proposed, Accepted when the verification below is observed.

**All six decisions were accepted by the operator on 2026-10-02.**
- Drafted 2026-10-02 by a Claude Code session, at the operator's request. It answers the
  six questions the 2026-10-01 session recorded in `CURRENT_STATE.md` (Phase 2, step 2).
- The operator accepted the decisions as summarized in that session, not on a close
  reading of this text. The one detail beyond those summaries, decision 3's timing (re-issue
  when 30 days remain, retry daily), may be adjusted by the build, which reports any change.
- Two decisions depend on others: decision 3's re-issue needs decision 2, and decision 1's
  "nervus's own certificate" needs decision 4.
- **Built 2026-10-02** on branch `phase2-step2-tls`, merged to `main` the same day
  (`e6ba446`). Verification items 1 to 6 are observed in tests, each first seen to fail.
  The build kept decision 3's timing as written: 30 days, checked daily.
- **Deployed 2026-10-05** (`62a5dd9`, procedure 017). Item 7 is observed:
  - the journal shows plain HTTP and the warning;
  - a new session in this repository reached nervus;
  - a session already open across the deploy reached it with no reconnect by hand.

  The open session was in another project, not this repository, as the item's wording
  says; procedure 017 records why that does not change what it shows. Decision 5 on the
  first installation (`systemctl reload` keeps the same process) is the operator's report.

**Amended 2026-10-17** by ADR-0021, decided by the operator: decision 3 (the shape of the
certificate nervus makes, its names, and where a renewal is written), decision 6 (the root is also
read from the handshake), and the alternative "a certificate authority of nervus's own", now
adopted. Each is marked where it stands. ADR-0021 is built, and Accepted 2026-10-18.

**Date:** 2026-10-02
**Rewritten:** 2026-10-16, under ADR-0019 F, to name no installation. No decision changed;
decision 1's note on the first installation's unit records where its flag lives since
ADR-0019 D2.
**Amends:**
- ADR-0008 decision 2 (what a connector pins and a user compares), decision 9 (when the
  certificate is made, and what replacing it breaks) and verification 3 (what the pairing
  fingerprint is compared with).
- ADR-0007 verification 6 (refuse to start becomes serve TLS) and decision 3 ("TLS off
  loopback is required" now admits the explicit opt-out). Decision 3 was missed when this
  was drafted, and added when the amendments were applied.

Applied 2026-10-02; each amended passage is marked where it stands.
**Builds on:** ADR-0005 consequences 1 and 6; ADR-0006 decision 6 and consequence 8;
ADR-0007 decisions 3 and 4
**Decided by:** the operator, 2026-10-02, in a Claude Code session in this repository
**Sequencing:** before branch `phase2-step2-tls` is merged. Decisions 2 and 4 change what
that branch builds, and they cost least now, before any connector has paired.

## Context

Branch `phase2-step2-tls` (2026-10-01) gives nervus TLS, opt-in:
- `--tls-cert` and `--tls-key` serve HTTPS.
- `--tls-generate` makes a self-signed pair at start if neither file exists.
- The certificate's SHA-256 fingerprint is printed at every start.
- A replaced certificate is reloaded within 5 seconds.

It is tested and not deployed. Building it raised six questions no ADR answers. On one
of them, the ADRs disagree:

- ADR-0005 consequence 1: v1 "must refuse to bind a non-loopback address without TLS, or
  ship a working default".
- ADR-0007 verification 6: nervus "started with a non-loopback bind and no TLS refuses to
  start".
- ADR-0006 decision 6: the first installation stays on plain HTTP until it has a
  certificate.

### Three principles

This ADR answers all six by applying three principles. Each is standard practice for
software that holds its own TLS identity. The examples are the drafting session's
knowledge, not checked against their sources; see Sources.

1. **Secure by default; insecure only by an explicit, named choice.** Where the software
   can provide the secure path itself, it does. Where it cannot, it warns. nervus cannot
   make a public address private, which is why ADR-0007 decision 4 warns about one.
2. **Trust attaches to the key, not to the certificate around it.** A certificate is a
   signed statement about a key: names, dates and a signature. The key is the identity.
   SSH pins the key, with no certificate involved, and ADR-0008 adopts SSH's
   trust-on-first-use model.
3. **Identity is created by a deliberate act, never inferred from a missing file.** After
   setup, missing identity files are an error. They are not a sign of a new
   installation.

### What the branch does that these principles reject

- **It prints the certificate's fingerprint, and ADR-0008 says to pin the certificate.**
  Every renewal would change that fingerprint and break every pairing. That is why expiry
  looked unsolvable on 2026-10-01.
- **`--tls-generate` makes a new pair at any start where the files are missing.** A
  container recreated without its volume would quietly get a new identity, and every
  pairing would break. This is ADR-0005 consequence 6's lost-volume problem, applied to
  the certificate.

On `main` as well, SIGHUP stops nervus, because nothing handles it.

### Read from this repository

- **The secrets directory is read-only under the unit.** The unit sets
  `ProtectSystem=strict`, and `ReadWritePaths` does not include `/opt/nervus/secrets`
  (`deploy/nervus.service`).
- **The unit file travels with each release.** The first installation's deploy installs
  `deploy/nervus.service` from the release it deploys, and installs the wheel with
  `--no-deps`.
- **nervus already uses the other standard form of this trust model.** It pins the
  Proxmox host's own certificate authority, `pve-root-ca.pem` (ADR-0009, procedure 010).
- **TLS mode on the branch needs uvicorn 0.47 or later.** The first installation's version
  has not been read.

## Decision

**1. Off loopback, nervus serves HTTPS. Plain HTTP there needs a flag that names what it
gives up.** *(Question 1.)*

| bind | certificate | nervus |
|---|---|---|
| loopback | none configured | plain HTTP, as today (ADR-0006 decision 6) |
| loopback | configured | HTTPS |
| any other address | configured, or nervus's own (decision 4) | HTTPS only |
| any other address | none exists | refuses to start, and says how to make one (decision 4) or opt out |
| any other address, with the opt-out flag | — | plain HTTP, with a warning at every start |

- **The opt-out flag.** It is a single flag, proposed as `--insecure-plain-http`. Its
  name is the point: someone reading a unit file they did not write should see what it
  gives up.
- **Its warning.** With the flag, nervus writes a line at every start saying that tokens
  and traffic cross the network unencrypted. This is ADR-0007 decision 4's
  standing-warning pattern.
- **It does not enable OAuth.** ADR-0006 verification 8 stands: off loopback without TLS,
  nervus offers no sign-in.
- **An installation that serves plain HTTP says so in its own unit.** The flag goes there in
  the same release as the code that needs it, so the two cannot be deployed apart. The first
  installation does, until the connector exists, which is ADR-0006 decision 6's fallback,
  stated in its own configuration. *Since 2026-10-16 (ADR-0019 D2) that is the installation's
  drop-in, not `deploy/nervus.service`, which names no installation.*
- **Why serve rather than refuse.** ADR-0005 consequence 1 allows either. Once nervus has
  a certificate, it can serve securely with no further step, so refusing then would add a
  step that protects nothing.
- **Amends** ADR-0007 verification 6 to: "nervus started with a non-loopback bind serves
  only HTTPS. If it has no certificate, it refuses to start and says why. Plain HTTP there
  needs the opt-out flag, and logs a warning at every start."

**2. A user compares, and a connector pins, the SHA-256 of nervus's public key, not of
its certificate.** *(Question 3. The decision the others lean on.)*

- **What is hashed.** The certificate's SubjectPublicKeyInfo (SPKI), the public-key part
  of a certificate. This is the standard form of certificate pinning; Android's network
  security configuration pins exactly this.
- **What breaks a pairing.** Re-issuing the certificate for the same key, with new dates
  or new names, leaves this fingerprint unchanged. Only a new key changes it, which is
  exactly when every pairing should break.
- **How it is printed.** Colon-separated hex, as today, but labelled as the public key's.
  A browser shows a certificate's fingerprint, so this one must not be mistaken for that.
- **Amends** ADR-0008 decision 2 so the connector pins nervus's public key, and shows
  that key's fingerprint, where it now says certificate. **Amends** decision 9: replacing
  the key, not the certificate, invalidates every pairing.
- **Scope.** This governs nervus's own certificate, the connector's path (ADR-0008
  decision 5, second row). A certificate from a domain, an overlay or an organisation is
  trusted through its certificate authority, not pinned. Its key fingerprint is printed
  all the same.

**3. The certificate nervus makes is ECDSA P-256, valid 825 days, and re-issued
automatically for the same key.** *(The rest of question 3. The re-issue needs decision
2.)*

*Amended 2026-10-17 by ADR-0021 A1, B1, C1 and D1:* nervus's certificate is no longer
self-signed. `tls-init` also makes a root, whose key is never saved, and an issuer limited to
nervus's DNS names, both valid 20 years. nervus's certificate, still P-256 and 825 days for the same
key, is signed and re-issued by the issuer. A renewal is written to the state directory, because
the unit leaves `secrets/` read-only and the re-issue below could not write there. Its names never
include `localhost`; its addresses stay in it, outside the issuer's limit. Clients accept nervus by
trusting the root (procedure 030).

- **P-256.** It is accepted by every TLS client and by browsers, which the web UI needs,
  and it is what certbot and Caddy generate by default. RSA works but is larger and
  slower, for nothing here. Ed25519 certificates are not accepted by browsers.
- **825 days.** This is the longest validity Apple's platforms accept for any TLS server
  certificate, including one trusted by hand. mkcert sets its own certificates' lifetime
  below it for the same reason.
- **Why shorter would not help.** Public certificates are moving to much shorter
  lifetimes, because certificate authorities mis-issue and revocation is unreliable. A
  pinned key involves neither. If nervus's key is stolen, the remedy is a new key and
  re-pairing, whatever the dates say.
- **Re-issued automatically.** When 30 days remain, nervus re-issues the certificate for
  the same key, without a restart; new connections get it through the reload already
  built. A failure is retried daily and logged each time. Nobody is asked to do anything.
- **Names.** `localhost`, the loopback addresses, the hostname, and a specific bind
  address, as built. A pinning client never checks them.
- **A certificate given to nervus is not nervus's to renew.** This covers one from a
  domain, an overlay or an organisation. Once 30 days remain, nervus logs a warning at
  every start and daily. ADR-0006 consequence 8's file watch picks up the renewal.

**4. nervus's own key and certificate are made once, by a deliberate act. Starting
nervus never makes them.** *(Questions 2 and 6.)*

- **A separate one-time command makes them.** They go beside nervus's other secrets, both
  0600, and the command refuses if either file exists. In v1's container, first-run setup
  runs it; that is what "first run" means in ADR-0008 decision 9.
- **Starting never makes a key.** If the files nervus needs are missing, it refuses to
  start, names them, and says how to make them. For a lost volume, it says that every
  pairing must be redone.
- **So no certificate exists while TLS is off.** One exists only once nervus has been set
  up to serve TLS (question 2).
- **`--tls-generate` is withdrawn before it ships.** It exists only on the unmerged
  branch.
- **Why a command, not the first-run marker proposed on 2026-10-01.** A marker detects the
  hazard; a command removes it, and adds no state. Vault (`operator init`) and PostgreSQL
  (`initdb`) work this way. The opposite pattern, machine images that regenerate SSH host
  keys at boot when they are missing, is what produces "REMOTE HOST IDENTIFICATION HAS
  CHANGED" after a rebuild.
- **Amends** ADR-0008 decision 9: "nervus generates its own certificate on first run"
  becomes "nervus's key and certificate are made once, at setup, by a deliberate act".

**5. Reload is the file watch, plus SIGHUP as "check now".** *(Question 4.)*

- **The file watch stays the mechanism.** ADR-0006 consequence 8's watch runs every 5
  seconds, as built.
- **SIGHUP runs the same check at once.** It is not a second mechanism. Reloading on
  SIGHUP is the classic Unix daemon convention (nginx and sshd re-read on it), and
  renewal tools' hooks are written for it, typically as `systemctl reload <service>`.
- **The unit gains `ExecReload=/bin/kill -HUP $MAINPID`**, so `systemctl reload nervus`
  works.
- **With TLS off, SIGHUP does nothing.** That is a change from today, where it stops
  nervus. systemd's `Restart=on-failure` treats a SIGHUP death as a clean exit and does
  not restart, so today someone used to `kill -HUP` would leave nervus down.

**6. The fingerprint is shown on the nervus machine: its console, and a command run
there. The UI follows later, with a caveat.** *(Question 5.)*

*Amended 2026-10-17 by ADR-0021 E2:* nervus also presents its root in its TLS handshake.
`tools/nervus-trust` reads it there, openly unchecked, and saves it once the user has compared its
SHA-256 with the value `tls-init` printed or the command below prints. The command prints the
root's fingerprint beside the key's, each labelled. The rule below stands: no MCP tool or HTTP
endpoint shows a fingerprint for checking.

- **On the console** (nervus's journal), at every start and every reload, as built.
- **Through a command run on the nervus host**, which prints it on demand from the key
  file, as `ssh-keygen -lf` does for SSH host keys. A journal line from months ago is hard
  to find on the day of pairing.
- **Never through an MCP tool or an HTTP endpoint for the purpose of checking it.** A
  fingerprint read over the connection being verified proves nothing.
- **A caveat this places on ADR-0008 decision 2.** nervus's web interface is reached over
  the network. Someone able to intercept the connector's connection can intercept the
  browser's too, and show a matching fingerprint on both. The interface is therefore a
  convenience, not an independent check, unless it is opened on the nervus machine itself.
  The pairing flow should name the console or the local command as the reference.
  ADR-0008 comes after v1 and settles its own flow; this records the constraint for it.

## Alternatives considered

- **Refuse to start off loopback unless a certificate is configured explicitly.** This is
  ADR-0005 consequence 1's first branch, and the recommendation of 2026-10-01. Rejected:
  once nervus has its own certificate, a further step protects nothing.
- **Warn and serve plain HTTP**, ADR-0007 decision 4's pattern. Rejected: that pattern is
  for conditions nervus cannot fix, and it can fix this one.
- **Pin the certificate**, as ADR-0008 and the branch do today. Rejected: every renewal
  would break every pairing.
- **A certificate authority of nervus's own, pinned by connectors.** This is Proxmox's
  model, the one nervus already relies on for the Proxmox host. It is workable. Rejected as more
  machinery than one server needs: a CA key is a second secret, more powerful than the
  server key it signs. *Amended 2026-10-17 by ADR-0021 A1: adopted.* The objection is answered:
  the root's key is never kept, and the issuer's is limited to nervus's names, so the key kept is
  less powerful than a server certificate trusted directly, which vouches for every name
  (procedure 030).
- **A long-lived certificate** (ten years) instead of renewal. Rejected: Apple's platforms
  refuse more than 825 days, and with the key pinned, renewal costs nothing.
- **RSA or Ed25519 keys.** RSA is larger and slower, with no benefit here. Browsers do not
  accept Ed25519.
- **Generating at start when files are missing** (`--tls-generate`, as built). Rejected
  by decision 4.
- **A first-run marker** (proposed 2026-10-01). Rejected for decision 4's command.
- **Making SIGHUP harmless but useless** (proposed 2026-10-01). Rejected: the convention
  makes it useful, at no cost.
- **Showing the fingerprint through an MCP tool or an HTTP endpoint.** Rejected by
  decision 6.

## Consequences

1. **Branch `phase2-step2-tls` changes before it merges.**
   - The printed fingerprint becomes the public key's, and its tests compare it with
     `openssl`'s hash of the public key instead of its certificate fingerprint.
   - `--tls-generate` gives way to the one-time command.

   Nothing has been paired or deployed, so nothing outside the branch changes.
2. **New code, each piece with tests seen to fail first:**
   - the opt-out flag and its warning (decision 1);
   - automatic re-issue and the expiry warning (decision 3);
   - the one-time command (decision 4);
   - SIGHUP handling (decision 5);
   - the fingerprint command (decision 6).
3. **One deploy carries the first installation's part.** Its unit gains
   `--insecure-plain-http` and `ExecReload=` in the same release as decisions 1 and 5's code.
   That is one ordinary deploy, and afterwards it still serves plain HTTP. Nothing else
   changes there until the connector.
4. **Turning TLS on in the first installation later needs three more things:**
   - the key and certificate, made once by the command;
   - write access for nervus wherever it keeps a re-issued certificate, since the unit
     makes `/opt/nervus/secrets` read-only;
   - uvicorn 0.47 or later there.
5. **ADR-0008 is amended** (applied 2026-10-02):
   - Decision 2: the key, not the certificate, and decision 6's caveat about the UI.
   - Decision 9: made at setup; replacing the key, not the certificate, breaks pairings.
   - Verification 3: the pairing fingerprint is compared with the console or the local
     command rather than the interface.
6. **ADR-0007 is amended** (applied 2026-10-02): verification 6 is reworded as decision 1
   says, and decision 3's "TLS off loopback is required" notes the explicit opt-out.
7. **A lost volume stops nervus instead of silently giving it a new key.** The cost is a
   refusal to start that a person must read. The gain is that no paired connector is ever
   invalidated without anyone noticing.

## Verification

Moves to Accepted when the following are observed, as for every ADR here. Observed means
seen on a machine, or in a test that was first seen to fail; it does not mean read in
code.

1. **Decision 1:**
   - Off loopback with no certificate, nervus refuses to start, and its message names both
     remedies.
   - With its own certificate, it serves only HTTPS.
   - With `--insecure-plain-http`, it serves plain HTTP and logs the warning at every
     start.
   - On loopback with no certificate, it serves plain HTTP as today.
2. **Decision 2:** the fingerprint nervus prints equals `openssl`'s SHA-256 of the
   certificate's public key. Re-issuing the certificate for the same key leaves it
   unchanged; a new key changes it.
3. **Decision 3:** a certificate nervus made, with fewer than 30 days left, is re-issued
   for the same key without a restart, and the next handshake presents it with the same
   key fingerprint. A given certificate within 30 days of expiry produces the warning.
4. **Decision 4:** starting with the files missing never creates them, and the message
   says how to make them. The one-time command makes both, 0600, and refuses if either
   exists.
5. **Decision 5:** SIGHUP triggers an immediate check and does not stop nervus, with TLS
   on or off. On the first installation, `systemctl reload nervus` leaves the same main
   process running.
6. **Decision 6:** the fingerprint command, run on the nervus host, prints what the
   console printed.
7. **The first installation, after the deploy that carries decisions 1 and 5:**
   - it serves plain HTTP as before, and its journal shows the warning;
   - this repository's sessions still reach nervus without being reconnected by hand, as
     procedure 015 checked.

## Sources

Provenance is stated per rule 2. **None of the outside practice below was checked against
its source when this was written.** The session's network blocked vendor documentation on
2026-10-01, and nothing was fetched on 2026-10-02. Each such claim is the drafting
session's knowledge, so read it as reported, not observed. Only the last three rows were
read, from this repository and from PyPI.

| claim | used in | status |
|---|---|---|
| Proxmox VE makes its own CA and node certificate at install | principle 1; alternatives | reported; consistent with `pve-root-ca.pem` (procedure 010) |
| Cockpit makes a self-signed certificate on first start; Elasticsearch 8 sets up TLS on first start | principle 1 | reported |
| certbot (since 2.0) and Caddy generate ECDSA P-256 keys by default | decision 3 | reported |
| Browsers do not accept Ed25519 certificates | decision 3; alternatives | reported |
| Apple's platforms refuse TLS server certificates valid more than 825 days, including ones trusted by hand; mkcert's lifetime stays below it for that reason | decision 3; alternatives | reported; Apple's page was blocked on 2026-10-01 |
| Public certificate lifetimes fall to 200 days (March 2026), 100 (March 2027) and 47 (March 2029), under CA/Browser Forum ballot SC-081 | decision 3 | reported |
| Android's network security configuration pins the SHA-256 of a certificate's public key (SPKI) | decision 2 | reported |
| nginx and sshd re-read their configuration on SIGHUP; certbot hooks commonly run `systemctl reload` | decision 5 | reported |
| systemd's `Restart=on-failure` treats death by SIGHUP as a clean exit | decision 5 | reported; systemd's page was blocked on 2026-10-01 |
| Cloud images print SSH host-key fingerprints to the console at first boot | decision 6 | reported |
| Vault serves nothing until `vault operator init`; PostgreSQL refuses an uninitialised data directory, which `initdb` creates | decision 4 | reported |
| The unit: `ProtectSystem=strict`, secrets not writable | consequences 3, 4 | read: `deploy/nervus.service` |
| The first installation's deploy installs the unit from the release, and the wheel with `--no-deps` | consequence 3 | read: its deploy script |
| TLS mode needs uvicorn 0.47 or later | consequence 4 | read: uvicorn 0.46.0 and 0.47.0 wheels from PyPI, 2026-10-01 |
