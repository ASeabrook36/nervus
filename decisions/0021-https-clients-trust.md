# ADR-0021: HTTPS that clients trust — nervus's own certificate authority, limited to its own names

**Status:** **Accepted 2026-10-18** at the operator's word.
- Verification items 1 to 5 are observed in tests first seen to fail (`ebb35d2`, `775114b`,
  `0ae4b81`, `eb6bba4`, `08183c0`).
- Item 6 is observed on a fresh install from the docs (procedure 032): Claude Code's desktop app
  on macOS and Codex's desktop app each ran a command on a host over HTTPS, and
  `tools/nervus-status` was green, with certificate checking on throughout.
- Two points are accepted at the operator's word: Claude Code's Linux binary connected but did
  not run a command, since that copy was not signed in; and Cursor is untested.
- It was Proposed, accepted when the verification below is observed.

**Decided by the operator on 2026-10-17**, in a Claude Code session: 0 and B as recommended,
each on its own; A as recommended, provided the two layers do not make the build hard, which the
session judged they do not (A); E option 2, not as recommended; C, D, F and G as recommended. Each
question keeps its options, so the record shows what was not chosen.
**Date:** 2026-10-17
**Decided by:** the operator, 2026-10-17
**Asked for by:** the operator, 2026-10-17, item 1 of the order before friends are invited
(`CURRENT_STATE.md`): "make HTTPS the path that works for a new nervus user", tested, not taken
from documentation alone.
**Amends** (decided 2026-10-17; not yet marked in the records amended):
- ADR-0010 decision 3 (the certificate nervus makes, and where a renewal is written), its
  alternative "a certificate authority of nervus's own", rejected there and adopted here, and
  decision 6 (which fingerprint a user compares).
- ADR-0008 Context ("Claude Code … ignores `NODE_EXTRA_CA_CERTS`", no longer true) and decision 8
  (the paths v1 ships).

**Builds on:** ADR-0007 decision 3 (no network is trusted); ADR-0010 decisions 1, 2 and 4 (HTTPS
off loopback, the key is the identity, made once on purpose); ADR-0018 (the friends preview);
ADR-0019 (this record names no installation)
**Evidence:** procedure 030, the trial this draft rests on.

## Context

### Why this matters now

A fresh install (`docs/install.md`) serves MCP over HTTPS with nervus's own certificate, and the
clients refuse it. So in practice a new user adds `--insecure-plain-http`, and their bearer token
crosses their network unencrypted. That token reaches every machine nervus does, as root. On a home
network, any compromised device — a camera, a television, a guest's laptop — can read a token sent
in the clear. Encryption with real certificate checking stops that, and that is the job here.

The operator's aim, 2026-10-17: a good experience for one person at home with a couple of machines
and some AI clients, not an organisation with an IT team. "It just feels like this is getting a
bit more complicated than it needs to be." So the test of every option below is what it asks of
that person, and what it costs them if something goes wrong.

### Why the home-lab habit does not carry over

At home, a self-signed certificate is normal: a browser warns once, the user accepts, and the
browser remembers that exception. That is trust on first use, as with an SSH fingerprint, and it
is sound at home. **AI clients have no such button.** Claude Code, Codex and Cursor either trust a
certificate through a setting or refuse it. Claude Code's request for a per-server TLS setting was
closed (Sources). The home-lab "accept" therefore becomes: save one file, and point each client at
it, once.

### What testing showed (procedure 030)

On macOS, with Claude Code 2.1.299 and Codex CLI 0.163, against nervus serving HTTPS on loopback.
Certificate checking was never turned off. nervus's own log was the evidence that a connection got
through; a client's own message was not.

| | Claude Code | Codex |
|---|---|---|
| told nothing | refused | refused |
| told to trust today's certificate (`tls-init`) | **refused**: the certificate's key usage lacks certificate signing, so Claude Code's TLS library will not take it as its own anchor | connects |
| the setting | `NODE_EXTRA_CA_CERTS` is honoured, which ADR-0008 says it is not | `CODEX_CA_CERTIFICATE` adds to Codex's usual roots; `SSL_CERT_FILE` **replaces** them, which broke Codex's own connection to OpenAI |

**The cost of trusting a certificate directly.** For every certificate a client was told to trust
directly — today's shape fixed, one marked as a CA, and one carrying a name limit — a certificate
signed by the same key **for any other name** was accepted, by Claude Code and by curl. Both
libraries ignore a name limit on a certificate trusted directly. Claude Code's setting covers the
whole process, its own connection to Anthropic included. So whoever steals that key could
impersonate any site to that client.

**Two layers keep the trust to nervus.** A root, whose private key is never saved, signs once an
*issuer* that is limited to nervus's names, and the issuer signs nervus's certificate. With the
client trusting the root:
- nervus is accepted by name and by address, by Claude Code, Codex and curl;
- a certificate the issuer signed for a name outside its limit is refused by all three;
- Claude Code's library cannot apply a limit written as an IP address ("unsupported name
  constraint type"), so the limit names DNS names only, and addresses stay unlimited;
- a certificate subject that reads as a host name outside the limit is refused too (by OpenSSL),
  so nervus's certificate carries its names only in its alternative names.

Not yet tested: Claude Code on Linux, Cursor, and a real tool call (Codex's `exec` mode refused
the call by its own approval policy, after the tool list came back over TLS).

### What is already true

- **nervus's renewal cannot write today.** ADR-0010 decision 3 re-issues nervus's certificate
  inside the service, but the unit makes `secrets/` read-only, so on a standard install it would
  fail when due, about 825 days after `tls-init` (`CURRENT_STATE.md`, Phase 2 step 2). The unit's
  state directory, `/var/lib/nervus`, is writable (ADR-0011).
- **ADR-0010 rejected a CA of nervus's own** as "more machinery than one server needs: a CA key is
  a second secret, more powerful than the server key it signs". Question A answers that: the root's
  key never exists on disk, and the issuer's is less powerful than a directly trusted server key,
  not more.

## Questions

### 0. The normal transport

1. **HTTPS, with each client told to trust nervus's root.** `docs/install.md` and
   `docs/clients.md` show it as the way; `--insecure-plain-http` stays, described as a fallback
   for a network the user controls, with its warning.
2. Plain HTTP stays the documented normal until the connector (ADR-0008) exists.

*Recommended: 1.* It costs a friend one file and one line per client, once, and keeps their token
off the wire. Waiting for the connector leaves every friend on plain HTTP for an unknown time.
**Decided by the operator, 2026-10-17: 1**, on its own.

### A. The shape of the certificate nervus makes

1. **Two layers.** `tls-init` makes a root and an issuer and nervus's certificate. The root's
   private key exists only in memory, signs the issuer once, and is never written anywhere. The
   issuer is limited to nervus's names (B), and its key is kept to renew nervus's certificate.
   Clients trust the root.
2. **One self-signed certificate, fixed so clients accept it** (no key usage extension, or marked as
   a CA). The least code. But a client that trusts it trusts that key for every name (tested), and
   the key sits in nervus's running process.
3. **A root used once, then nervus's certificate under it, with no issuer.** Limited trust, as 1,
   but nervus cannot renew, so every client needs a new file every 825 days.

*Recommended: 1.* What a friend does is the same in all three. The difference is all on nervus's
side: about one more function in `tls.py`. In return, a stolen key can impersonate only nervus,
which the thief could already do. ADR-0010's objection was to a second, more powerful secret; here
the powerful one is never kept, and the kept one is limited.
**Decided by the operator, 2026-10-17: 1**, "IF you think it's not going to make life to difficult
or complicated to implement". The session's judgment, given then: it does not. Renewal into the
state directory (D) is needed whatever the shape; making three certificates is about 40 lines, as
the trial's own scripts did; renewal signs with the issuer's key instead of nervus's own. The one
catch, found in the trial, is that nervus's certificate carries its names only in its alternative
names.

### B. What the issuer is limited to

1. **The DNS names given to `tls-init`, and its machine's hostname. Never `localhost`.** The
   addresses `tls-init` names go into nervus's certificate, unlimited, so a client may still use one.
2. Names and addresses both. Claude Code refuses every certificate under such an issuer (tested).
3. A whole domain the user names, such as `home.example.net`, so a machine can be renamed later
   without a new root. A stolen issuer key could then impersonate any name in that domain.

*Recommended: 1.* `localhost` is left out because no client elsewhere reaches nervus by it, and
allowing it would let the issuer impersonate every client's own local services. The names cannot be
added later, as today (ADR-0010 decision 4). A rename means a new root, and every client saves the
new file. The remaining gap: a site the client reaches by bare address could be impersonated with
the issuer's key. Anthropic, OpenAI and GitHub are reached by name.
**Decided by the operator, 2026-10-17: 1** ("no question").

### C. Lifetimes

1. **Root and issuer 20 years; nervus's certificate 825 days, renewed when 30 remain**, as
   ADR-0010 decision 3. A friend saves the file once in 20 years.
2. Root and issuer 10 years.

*Recommended: 1.* Apple's 825-day limit applies to server certificates, not to a root or issuer.
Nothing here is revoked. If a key is stolen, the remedy is a new root, whatever the dates say.
**Decided by the operator, 2026-10-17: 1.**

### D. Where a renewal is written

1. **nervus's renewed certificate goes in the state directory** (`/var/lib/nervus/tls/`), which the
   unit already makes writable, and nervus serves it when it is newer and for the same key. The
   issuer's key stays in `secrets/`, read by nervus, never written by it.
2. Make `secrets/` writable by nervus. This loosens the rule that keeps nervus's secrets read-only to
   the service (ADR-0014 decision A).
3. Renew outside the service, from a root timer, so the issuer's key can be root's alone.

*Recommended: 1.* It fixes the renewal that cannot write today, with no new permission. Option 3
protects a key that, limited by B, gives a thief nothing beyond what nervus's own key already does.
**Decided by the operator, 2026-10-17: 1.**

### E. How the root reaches a client, and what the user compares

1. **For the preview, copied off nervus's machine.** `tls-init` writes `nervus-root.pem`
   (not secret) and prints its SHA-256. On each client machine the user saves the file, checks that
   the same SHA-256 comes out, and points the clients at it. `nervus tls-fingerprint` prints both
   fingerprints, labelled: the root's, for this, and nervus's key's, for a connector (ADR-0010
   decision 2). First-run setup (ADR-0015) may offer the file in the UI later.
2. nervus serves the root at a fixed address. It is easy, but it invites skipping the comparison,
   and ADR-0010 decision 6 already says a fingerprint read over the connection being checked proves
   nothing.

*Recommended: 1.* The comparison is the "I trust this machine" moment. During install the user is
already at nervus's machine, where the reference value is.

**Decided by the operator, 2026-10-17: 2.** The case for it, put to the operator that day: a friend's
own agent will set up each new client, and "fetch this, show me the fingerprint, I confirm it" is a
cleaner job for an agent than copying a file between machines, months after the install.

**How it is served, as the session proposed when recording the answer:** in nervus's TLS handshake,
not by a new route. nervus sends the root after the issuer in the chain it already presents, which
TLS allows (a client that does not trust the root is not helped by it). A client-side tool,
`tools/nervus-trust <url>`, reads the root from the handshake, prints its SHA-256, and on the user's
confirmation saves it and prints each client's setting. Nothing is fetched over a connection that
pretends to be checked: the read is openly unchecked, and the comparison is the check. The
reference value is the one `tls-init` printed, which the install doc says to keep with the token,
or `nervus tls-fingerprint` run on nervus's machine (ADR-0010 decision 6). Decision 6's rule
stands: no MCP tool or HTTP endpoint shows a fingerprint for checking.

### F. Where a client is told

1. **In each client's own setting, never the operating system's trust store.** Claude Code:
   `NODE_EXTRA_CA_CERTS` in the `env` block of `~/.claude/settings.json`, which the desktop app
   reads too. Codex: `CODEX_CA_CERTIFICATE` in its environment, never `SSL_CERT_FILE`, which
   replaces Codex's usual roots. curl, and `tools/nervus-status`: `--cacert`, and `NERVUS_CACERT`.
2. Install the root into the operating system. Every program on the machine would then trust
   nervus's issuer, and it needs administrator rights.

*Recommended: 1.* The trust stays with the programs that use nervus. Cursor is not tested;
`docs/clients.md` says so until it is.
**Decided by the operator, 2026-10-17: 1.**

### G. An installation made with today's `tls-init`

1. **`nervus tls-init --upgrade`** keeps nervus's existing key, so its fingerprint and anything
   pinned to it survive. It makes the root and issuer and re-issues nervus's certificate under them.
   Browsers that accepted the old certificate are asked once more.
2. Start over with a new key.

*Recommended: 1.* It follows ADR-0010 decision 2: the key is the identity, and the certificate
around it can change.
**Decided by the operator, 2026-10-17: 1.**

## Consequences

1. **For a friend:** one command per client machine (`tools/nervus-trust`), one fingerprint
   compared, and one line per client. Nothing more until the root expires, 20 years on (C1). No domain, no account,
   no service run alongside nervus.
2. **For nervus:** `tls-init` makes three certificates and keeps two keys. Renewal signs with the
   issuer and writes to the state directory. The chain nervus presents ends with the root (E2).
   `tls-fingerprint` prints two fingerprints.
   `tools/nervus-status` gains `NERVUS_CACERT`, and `https://` URLs, addresses and names outside
   DNS; that is this item's step 3, and it does not depend on A to G.
3. **What a stolen issuer key allows:** impersonating nervus by name, which nervus's own key
   already allows, and impersonating any site a client reaches by bare address.
4. **Trust on first copy is only as good as the comparison**, as ADR-0008 consequence 5 says of
   pairing.
5. **The connector (ADR-0008) remains after v1,** an improvement rather than the only way to avoid
   a domain. It would remove the one-file step. ADR-0008 decision 8's three v1 paths gain a fourth:
   nervus elsewhere, with nervus's own root trusted by each client.

## Order of work

Each step is one module with its tests, and waits for the operator (rule 1).

0. ~~The operator's decisions on 0 and A to G.~~ Done 2026-10-17.
1. `tools/nervus-status`: `https://` with `NERVUS_CACERT`, addresses, names outside DNS; tests on
   macOS and Debian.
2. `tls.py`: the two layers (A1, B1, C1), with tests that a real TLS client accepts nervus and
   refuses an issuer-signed certificate for an outside name.
3. Renewal into the state directory (D1), and `tls-init --upgrade` (G1).
4. `tools/nervus-trust` (E2): the root read from the handshake, its fingerprint, saved on
   confirmation; tests on macOS and Debian.
5. A trial on a throwaway VM, from `docs/install.md` as changed: Claude Code on macOS and on Linux,
   and Codex, set up from `docs/clients.md`, each making a real call; `nervus-status` green. Written
   up as a procedure.
6. `docs/install.md` steps 7 to 9, `docs/clients.md` and the preview README.

## Verification

Moves to Accepted when observed, in tests first seen to fail, or on a machine:

1. `tls-init` writes exactly nervus's key and certificate, the issuer's key and certificate, and the
   root certificate, and no root key, by any path.
2. A real TLS client trusting only the root accepts nervus by each of its names and addresses, and
   refuses a certificate the issuer signed for a name outside its limit.
3. Renewal with 30 days left writes to the state directory, keeps nervus's key fingerprint, and the
   next handshake presents it, under the unit's own sandbox.
4. `tls-init --upgrade` on today's certificate keeps the key fingerprint.
5. nervus's handshake carries the root, and `tools/nervus-trust` saves exactly the root whose
   SHA-256 `tls-init` printed. A client that has not saved it still refuses nervus.
6. On a fresh install from `docs/install.md`, Claude Code (macOS and Linux) and Codex, configured
   from `docs/clients.md`, run a command on a host over HTTPS, and `tools/nervus-status` is green,
   with certificate checking on throughout.

## Sources

Per rule 2, each claim is marked with how it is known.

| claim | used in | status |
|---|---|---|
| Claude Code 2.1.299 honours `NODE_EXTRA_CA_CERTS`; refuses today's certificate; accepts the two layers; refuses an outside-name impostor; cannot apply an IP limit | Context; A, B | observed, procedure 030 |
| Codex CLI 0.163 honours `CODEX_CA_CERTIFICATE`, which adds to its roots; `SSL_CERT_FILE` replaces them; refuses an outside-name impostor | Context; F | observed, procedure 030 (run by the operator) |
| Claude Code and curl accept any certificate signed by the key of a certificate trusted directly, a name limit on it included | Context; A | observed, procedure 030 |
| Claude Code reads `NODE_EXTRA_CA_CERTS` from `~/.claude/settings.json`, desktop app included | F | read: code.claude.com/docs/en/network-config, 2026-10-17 |
| Claude Code has no per-server TLS setting; the request was closed | Context | read: claude-code issue 44754, as mirrored, 2026-10-17 |
| A report of Claude Code's Linux binary failing MCP over HTTPS concerned an outdated public bundle, not a private root | Order of work 4 | read: claude-code issue 82202, as mirrored, 2026-10-17 |
| Apple's 825-day limit applies to server certificates | C | reported, as in ADR-0010 |
