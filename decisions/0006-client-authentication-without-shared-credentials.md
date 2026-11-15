# ADR-0006: clients sign in with OAuth, so no credential sits where every app can read it

**Status:** Proposed (Accepted when the verification below is observed)
**Date:** 2026-09-16
**Extends:** ADR-0001 s6 (clients and tokens) and s7 (consumer integration); ADR-0005 s4
(client management in the web UI)
**Decided by:** the operator, 2026-09-15 and 2026-09-16 — prevent rather than detect;
per-app confinement is enough; build it as part of ADR-0005's enrollment work
**Rewritten:** 2026-10-16, under ADR-0019 F, to name no installation. No decision changed.
**Read alongside:** ADR-0003, whose per-client switch becomes revocation of what this
ADR issues; procedures 005 and 006, which record the exposure this answers

## Context

### What went wrong

ADR-0001 s6 gives each (client, project) pair its own token, and s7 has the client
config reference it by environment variable. On macOS, GUI apps inherit nothing from a
shell, so the first installation used a helper script (now its own, outside nervus) that
puts every token into the login session with `launchctl setenv`. Every GUI app then holds every token, and the Claude app hands its
whole environment to every project's session.

On 2026-09-12 a Claude Code session in this repository — no token of its own, no client
config, no password-manager session — printed all three token values with one `env`
call. They were rotated (procedure 006).

The harm is not extra authority: every token allowlisted the same two hosts. It is
**attribution**. Any session could act as any client in the audit log, and ADR-0001's
consequences make that log the justification for standing access at all. Token-per-pair
was delivering attribution by convention only.

### The operator's constraints

- No approving the same thing over and over.
- No esoteric changes to the user's computer, to the container environment, or to
  enrolled hosts.
- The expected deployment is the container running on the same machine as the clients —
  Claude Code, Codex, Cursor — that use it.

### The limit, stated first

On one machine, under one operating-system user, **nothing short of OS-level isolation
stops a determined process from taking another client's credential.** Whatever one app
can use, another program running as the same user can in principle extract. Separate
OS users or sandboxes would close that, and are exactly the esoteric change ruled out.

What can be prevented is what actually happened: a credential sitting in a place every
app reads by default. So in this ADR **"prevent" means no credential is ambient, and
using another client's access requires a deliberate act** — extracting it from that
client's credential store, or getting a human to approve a new sign-in. That is
narrower than the word suggests, and it is said here so no README later claims more.

### What the clients support

Researched on 2026-09-16 from each client's documentation and, for Codex, its source.
**Nothing below has been observed on a machine yet**; the verification section exists
to do that.

| | Claude Code | Codex (CLI and desktop app) | Cursor |
|---|---|---|---|
| OAuth for HTTP MCP servers | yes — on `401`/`403`, via `/mcp` or `claude mcp login` | yes — `codex mcp login`, an **Authenticate** button in the desktop app, discovery at connect | yes |
| Client registration | dynamic registration by default; client ID metadata documents detected automatically; pre-configured client IDs | `AUTO`, `CIMD` or `DCR` | static client credentials documented as the option "instead of dynamic client registration" for providers that lack it — implying dynamic registration otherwise, though not stated outright |
| Callback | `http://localhost:PORT/callback`, port fixable | local port, configurable | fixed `http://localhost:8787/callback` on desktop |
| Where the credential lives | macOS keychain; a credentials file on other platforms | keyring first; **on a keyring write failure, falls back** to `~/.codex/.credentials.json`, mode 0600 | not documented |
| What it is filed under | the endpoint URL | server name plus URL (`compute_store_key`) | not documented |
| Refresh | automatic | automatic | not documented |
| Known problems | — | [openai/codex#41071](https://github.com/openai/codex/issues/41071), open: keychain writes fail on macOS in at least one desktop app build, leaving no usable login | — |

Two things follow for this ADR. Every client files credentials per app at minimum, so
**per-app confinement comes without extra machinery**. And per-project confinement is
unavailable in Codex's desktop app, which ignores project-scoped MCP configuration
(procedure 005), and would need a URL per project in Claude Code.

### What the specification and the SDK require

The MCP authorization specification (version 2026-07-28):

- OAuth 2.1, with PKCE using `S256`; Protected Resource Metadata; resource indicators
  on every authorization and token request; servers **MUST** accept only tokens issued
  for themselves.
- Client ID metadata documents **SHOULD** be supported. Dynamic client registration
  **MAY** be, and is marked deprecated, "retained for backwards compatibility".
- Access tokens **SHOULD** be short-lived. Refresh tokens **MUST** rotate for public
  clients — which these desktop apps are.
- "All authorization server endpoints **MUST** be served over HTTPS." Redirect URIs
  must be `localhost` or HTTPS. **The HTTPS requirement has no loopback exception** for
  the authorization server itself.

The pinned SDK, `mcp` 2.2.0, read on 2026-09-16:

- Provides the authorize, token, dynamic registration, revocation and metadata
  endpoints, and bearer-token middleware. nervus supplies a provider: storage, the
  consent page, and what each grant may reach.
- **Refuses a non-HTTPS issuer unless the host is `localhost`, `127.0.0.1` or `[::1]`**
  (`mcp/server/auth/routes.py`).
- Has no client ID metadata document support in its server auth module.

## Decision

**1. Clients authenticate with OAuth 2.1, as the MCP authorization specification
defines.** nervus is both the MCP server and the authorization server, in the same
container, built on the SDK's auth routes.

**2. Confinement is per app, not per project.** One grant per client application per
nervus instance. Per-project is not pursued: Codex's desktop app cannot express it and
Claude Code would need a URL per project. The operator judged per-app sufficient.

**3. Approval is one click, once per app.** The first connection opens nervus's consent
page, showing the client's name as it presents itself, the redirect hostname (which the
specification requires be displayed), and the hosts and access level being granted. The
user approves, and may rename the grant; **that label is what the audit log records.**
From then on the client refreshes silently. There is no approval per session or per
call.

Under dynamic registration a client's name is self-asserted — anything can call itself
"Claude Code". The human approving, in the moment, from the app they just used, is the
identity check. That is the deliberate act the limit above depends on.

**4. Dynamic client registration in v1; client ID metadata documents later.** Dynamic
registration is what all three clients can use today, the SDK implements it, and it
needs no outbound internet access from the container. Relying on a deprecated mechanism
is accepted knowingly, for these reasons:

- **The deprecation is recent and has a floor.** Metadata documents became the
  specification's recommendation in version 2025-11-25. Dynamic registration was only
  marked deprecated in 2026-07-28, and that same version adopted a feature lifecycle
  policy with a minimum twelve-month deprecation window. It stays in the specification
  until at least July 2027.
- **The SDK has the client half only.** The Python SDK added metadata-document support
  for *clients* in PR #1652, which the `mcp` 2.2.0 wheel confirms
  (`mcp/client/auth/oauth2.py`).
  The authorization-server half is tracked in
  [python-sdk#1801](https://github.com/modelcontextprotocol/python-sdk/issues/1801),
  open since 2025-12-18 with no linked pull request. A plausible reason, not a confirmed
  one: most MCP servers delegate sign-in to an external identity provider rather than
  run the SDK's own authorization server, so the server half serves few users — and it
  is the harder half, since it fetches URLs chosen by the client.

**Adding metadata documents later means, in nervus:**

1. Advertise `client_id_metadata_document_supported` in authorization server metadata.
2. Accept a client ID that is an HTTPS URL, in both the authorization and token
   endpoints.
3. Fetch that URL, check the document's `client_id` matches it exactly, check the
   redirect URI against its `redirect_uris`, and cache it per its HTTP cache headers.
4. Guard that fetch against server-side request forgery — refusing private and loopback
   addresses, redirects to them, and oversized responses.
5. Give the container outbound HTTPS, which dynamic registration does not need.
6. Show the client's domain on the consent page, with the specification's warning when
   its only redirect URIs are `localhost`.
7. Keep dynamic registration alongside it until the specification removes it, for
   installations without internet access.

Either nervus implements these itself, or it adopts the SDK's server half when
python-sdk#1801 lands. Nothing in the rest of this ADR changes either way.

**5. Token rotation must never look like a re-approval.** Access tokens are short-lived
and refresh tokens rotate, as the specification requires. Several sessions of one app
share one stored credential, so two refreshing at once would, under strict rotation,
revoke each other and force the user back to the consent page. nervus therefore accepts
a just-rotated refresh token for a short grace window. The constraint is the heading;
the defaults, chosen so that an app in regular use never asks again, are:

| | default | effect |
|---|---|---|
| access token | 1 hour | a renewal at most once an hour, invisible to the user |
| refresh token | rotated on every use | as the specification requires |
| grace window for a just-rotated refresh token | 60 seconds | two sessions renewing together both succeed |
| refresh token idle expiry | 90 days, reset on every use | an app used at least once every 90 days never re-approves |
| absolute grant lifetime | none | ending a grant is suspension or revocation (decision 8), not a timer |

**6. Plain HTTP on loopback only; HTTPS everywhere else.** This applies ADR-0005
consequence 1 to the authorization server, and matches what the SDK already enforces.

On loopback it is a **knowing departure** from the specification's HTTPS requirement,
acceptable only for clients observed to accept it (verification 2). A client that
refuses uses the fallback below. Users are **not** asked to install a local certificate
authority to make HTTPS work on `localhost`.

**nervus serves TLS itself; it does not require a reverse proxy.** Given a certificate
and key, it listens on HTTPS directly. This needs no new dependency: the SDK exposes the
web application through `streamable_http_app()`, and uvicorn, which already ships with
the SDK, takes a certificate and key. `src/nervus/__main__.py` currently calls
`run(transport="streamable-http", host, port)`, which exposes neither, so this is a
contained change to how nervus starts, not new machinery.

**Obtaining the certificate is deployment, not design.** nervus takes a path to a
certificate and a key and does not care where they came from: a certificate tool on the
same machine, an existing reverse proxy, or a file copied in by hand. No third-party
program is part of nervus's design, and none is required to run it. An automatic
certificate client inside nervus — the ACME protocol plus one DNS provider's API — is a
possible later addition for self-hosters with a domain, deliberately not in v1, because
it is the one part that carries ongoing maintenance as provider APIs change.

**The first installation is that path**: nervus on a machine of its own, its clients on
another. It stays on the fallback until it has a certificate.

**7. A static token remains as a fallback, labelled as not confined, everywhere it
appears.** For clients whose OAuth does not work, and for deployments without TLS. It is
issued with one button in the UI, shown once, and placed in the client's config through
that client's own header or environment mechanism. The UI marks it in the client list,
and the audit log marks every call made with it. The label is part of this decision:
the fallback reintroduces exactly the exposure this ADR exists to remove, and must not
pass for the real thing.

**8. Revocation is ADR-0003's per-client switch.** Suspending a grant refuses its tokens
without deleting it, so switching it back needs no new sign-in — the reversibility
ADR-0003 asks for. Revoking a grant deletes it; the app's next call gets `401` and it
must be approved again.

**9. What changes from ADR-0001.** The per-credential host allowlist of s6 carries over,
now held by the grant. For OAuth clients, s7's "reference the token by environment
variable" is superseded: the client config holds only the URL. Delivery by environment
variable, `launchctl` included, survives only for fallback tokens.

## Alternatives considered

- **Detect rather than prevent** — record something about the caller and flag a
  mismatch with the credential's owner. Rejected by the operator: it guards a
  load-bearing record with a check a careful impostor avoids, and it only helps if
  someone reads the flags.
- **Per-project confinement.** Rejected: Codex's desktop app cannot express it, Claude
  Code needs a URL per project, and per-app meets the need.
- **OS-level isolation** — a separate user or sandbox per client. The only option that
  stops a determined process running as the same user. Rejected on the operator's
  constraint against esoteric changes.
- **Per-project static tokens in untracked project settings.** Removes ambient exposure
  for one client, but leaves a plaintext secret per project, differs per client, has no
  refresh or revocation story, and still needs minting by hand. Kept only in the shape of
  the fallback.
- **Credential helpers** — Claude Code's `headersHelper`, Codex's
  `http_headers_helper`. Client-specific, gated on workspace trust, and still a
  secret-fetching script on the user's machine.
- **Client ID metadata documents only**, as the specification prefers. Rejected for v1:
  no SDK support, outbound fetches from the container, and less uniform client support
  than dynamic registration today.
- **A local certificate authority for HTTPS on `localhost`.** Rejected: installing a
  trusted root is precisely the esoteric change ruled out, and a mishandled local root
  is a larger risk than the one it addresses.

## Consequences

1. **"Prevent" is narrower than it sounds**, and the documentation must say so in the
   terms used above. A process running as the same user can still extract a client's
   credential deliberately.
2. **nervus becomes an authorization server.** Consent page, grant store, issuance,
   rotation with a grace window, suspension and revocation — all persisted in the
   volume. ADR-0005 consequence 6 already made the volume load-bearing; losing it now
   also signs out every client, which costs one click per app to recover.
3. **Confinement strength varies by client and platform.** The macOS keychain
   (Claude Code; Codex when its keyring works) is meaningfully stronger than a 0600 file
   (Claude Code off macOS; Codex after a keyring failure), which any process running as
   the user can read. The documentation records, per client, where its credential
   actually lives.
4. **Client bugs become nervus's support load.** Codex issue #41071 directly
   contradicts "no approving over and over". Verification either observes it absent or
   records Codex as fallback-only until it is fixed.
5. **The operator's own instance does not benefit until it has TLS.** Until then it runs
   on fallback tokens, labelled unconfined — today's exposure, named rather than hidden.
6. **A departure from the specification is on record.** Plain HTTP for the
   authorization server on loopback. Revisit if clients start enforcing HTTPS there, or
   if the specification adds a loopback exception.
7. **The public threat model** (ADR-0005 consequence 2) must state that malicious code
   running as the same user as the clients is out of scope for credential confinement,
   and why. It must also settle how nervus is packaged and run on a single machine,
   because no operating system keystore helps a container: the macOS keychain and the
   Windows credential store are unreachable from inside a Linux container, and both
   treat every program the user runs as the same principal in any case.
8. **nervus reloads a renewed certificate by itself.** uvicorn reads the certificate
   once, at startup, so without this a renewal every couple of months would need someone
   to restart nervus — recurring work for the user, and an expired certificate whenever
   it is forgotten. nervus therefore watches the certificate and key it was given and
   reloads them when they change. Renewal then costs the user nothing after setup. This
   is part of the decision, not an implementation detail, because the alternative fails
   silently two months later.
9. **Dynamic client registration has to be tracked, not forgotten.** Its removal is
   twelve months away at the earliest, but the trigger for revisiting this ADR is
   whichever comes first: python-sdk#1801 landing, any client dropping support, or
   July 2027.
10. **Confining client credentials does not protect nervus's own secrets.** When the
   container runs on the same machine as the clients and under the same user — Docker
   Desktop, or rootless Podman — any program running as that user can open a shell in
   the container and read the fleet SSH key and the audit log directly, bypassing nervus
   entirely. That is the more serious exposure of the local deployment this ADR assumes,
   and it is a question of where and as whom nervus runs, not of client authentication.
   The threat model must answer it.
11. **Procedure 005 changes shape.** Its launchctl step becomes fallback-only, and
   onboarding an OAuth client is "add the URL, approve once".

## Verification

Moves to Accepted when all of the following are observed — not read in documentation —
on a machine that has never seen nervus, with the container running locally, for each
of Claude Code, the Codex desktop app, and Cursor. A client that fails 1–4 is recorded
here as fallback-only, with the reason.

1. Adding nervus by URL alone and then using it opens nervus's consent page. One
   approval, and the tools work. No token copied, no environment variable set, no file
   edited by hand.
2. That works against plain HTTP on `localhost`.
3. After quitting and relaunching the app, and again after a period longer than the
   access-token lifetime, calls succeed with no further approval.
4. Two sessions of the same app, used concurrently across several refreshes, never
   return the user to the consent page.
5. No credential appears in any session's environment, or in any file inside the
   project. Where each client actually stored it is recorded.
6. Audit log entries carry the grant label chosen at approval. A call made with a
   fallback token is marked unconfined, in the log and in the UI.
7. Suspending one app's grant refuses its next call and resuming it restores access
   without a new sign-in; revoking it forces re-approval. Other apps are unaffected
   throughout.
8. nervus bound to a non-loopback address without TLS refuses to offer OAuth.
9. A fallback token is issued from the UI and used by one client without editing any of
   nervus's files, and is labelled unconfined wherever it appears.

## Sources

Read on 2026-09-16.

- MCP authorization specification, 2026-07-28 —
  [overview](https://modelcontextprotocol.io/specification/latest/basic/authorization),
  [client registration](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration),
  [security considerations](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations)
- [Claude Code: MCP](https://code.claude.com/docs/en/mcp)
- [Codex: MCP](https://learn.chatgpt.com/docs/extend/mcp?surface=cli),
  [`codex-rs/rmcp-client/src/oauth.rs`](https://github.com/openai/codex/blob/main/codex-rs/rmcp-client/src/oauth.rs),
  [openai/codex#41071](https://github.com/openai/codex/issues/41071),
  [DeepWiki summary of Codex MCP OAuth](https://deepwiki.com/openai/codex/6.5-oauth-authentication-for-mcp)
  (secondary; its key-construction claim was checked against the source)
- [Cursor: MCP](https://cursor.com/docs/mcp)
- [MCP specification 2026-07-28 changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)
  — deprecation of dynamic registration, and the twelve-month lifecycle policy
- [python-sdk#1801: server-side metadata document support](https://github.com/modelcontextprotocol/python-sdk/issues/1801)
- `mcp` 2.2.0 wheel from PyPI: `mcp/server/auth/`, `mcp/server/mcpserver/tools/base.py`
