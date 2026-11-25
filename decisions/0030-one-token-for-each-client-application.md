# ADR-0030: one token for each client application, and the project recorded as the client says it

**Status:** **Decided by the operator, 2026-11-19; Accepted when its verification is observed.**
Each question keeps its options, so the record shows what was not chosen.
- **Question 1: a, one token for each client application.** In the operator's words: "one token
  per client application is fine … I've decided that's the way I want to go. I just haven't had
  time to make the one Claude code key." Issuing that token and moving the projects to it is the
  operator's, order of work step 4.
- **Question 2: a, recorded as the client says it, "Yes, but later".** Built in a later release
  than 0.2.2; until then the log names the application's token and no project. Order of work steps
  1 to 3 wait for it.
- **Order of work step 4, begun 2026-11-24** on the first installation: the application's token
  issued and delivered by the operator, and its first calls seen in the audit log (procedure 070).
  Its projects not yet moved, so verification 4 is not yet observed.
**Date:** 2026-11-19
**Asked for by:** the operator, on 2026-11-19: "i really need to just create one key for claude
code. managing them all has become quite annoying."
**Would amend:** ADR-0001 s6 ("One static bearer token per (client, project) pair") and s11's
consumer onboarding, each to be marked where it stands once this is decided.
**Builds on:** ADR-0006 decision 2 (confinement is per application, not per project, decided on
2026-09-16 for sign-in) and decision 7 (a static token is a fallback, labelled unconfined);
ADR-0003 (the off switch, one per token); ADR-0009 decisions 3 and 5 (the full level is one token's
alone, kept in the keystore); ADR-0013 (the audit log viewer); ADR-0014 (tokens issued in the web
UI, their hosts fixed when issued); ADR-0016 and ADR-0020 (exports and uploads kept per token).
**Evidence:** the first installation's tokens, their use and its clients' settings, read on
2026-11-19 from this repository, the installation's own copy of its audit log and the client
machine. Kept in the deployment record (deployment note 0030); nothing was read off nervus's own
machine, whose connection was refused to the drafting session.
**Written to the policy of ADR-0019:** this record names no system.

## Context

### What a token per client and project was for

Every client reaches a machine as the same account, so nervus's audit log is the only thing that
tells one client's work from another's (ADR-0001 s4 and s10). ADR-0001 s6 therefore gave each pair
of client and project a token of its own: Claude Code in project A, Claude Code in project B and
Codex in project A are three tokens, and the log names the pair on every call.

### What it never gave

A token delivered in an environment variable is readable by every program that runs as the same
person (ADR-0006, Context; ADR-0009 decision 5). On a client machine with a desktop app, every
session of every project is handed every token. So a project's token names the project **by
convention**: each project's settings name their own variable, and nothing stops a session naming
another's. ADR-0006 said so on 2026-09-16, "Token-per-pair was delivering attribution by convention
only", and decided that sign-in, when it is built, confines **per application, not per project**
(decision 2).

Static tokens, which are what every client uses until then, kept the older rule.

### What it costs

Each new project is: a token issued in the web UI, an item in the password manager, a variable in
the login session, the application quit and reopened, and one more secret in every program's reach.
The first installation held five such tokens for one application, two of them in use on the day
this was written, every one reaching the same machines (deployment note 0030). The work grows with
the projects and buys a label that was never proof.

### One client already lives without it

Codex's desktop app ignores a project's own MCP settings, so its token cannot be tied to a project.
`docs/clients.md` gives the way out the first installation took: a token named for what it is,
whose project says it is not scoped to one. It has worked that way since 2026-09-11.

### What can still say the project

A client's own settings can send a header with every request. Claude Code's `.mcp.json` takes any
header beside `Authorization`, and the file is the project's own, committed in the project, holding
no secret. So a project can say its name on every call at the cost of one line, with nothing to
issue, store or deliver.

What nervus is told that way is a claim, exactly as the per-project token was: a session can send
another project's name as easily as it could name another project's variable.

## Questions

### 1. The unit of a static token

- **a. One token for each client application: Claude Code has one, Codex has one, used from every
  project on that person's machines.** Its id names the application, and its project says it is
  not scoped to one. A token for one project stays possible, since nothing in the code tells the
  two apart: it is for a project that must reach different machines from the rest, or be switched
  off by itself.
- b. Keep one token for each client and project, as ADR-0001 s6 has it.
- c. One token for everything, every application sharing it. The log could then not tell Claude
  Code from Codex, and one switch would stop both.

*Recommended: a.* It is what ADR-0006 decision 2 already decided for sign-in, brought forward to
the tokens in use until sign-in is built. It gives up nothing the log could vouch for, and ends
work that grows with every project. c goes further than was asked and loses the one distinction
that is real: an application keeps its own credential, and the switch is per token.

### 2. Whether a call still says which project it came from

- **a. A client may send a header, `Nervus-Project: <name>`, from its project's own settings.
  nervus records it on every record of that call as `project_said`, and uses it for nothing else.**
  It decides no allowlist, switches nothing off and owns no export. The audit page shows it beside
  the client and filters by it; `hosts` answers with what nervus recorded, so a session can check
  its own settings. A name is letters, digits, `.`, `_` and `-`, at most 64 characters; anything
  else is not recorded, and the call goes on as if nothing were said. A call that says nothing
  works as it does today.
- b. Record nothing more: the log names the application's token, and no project.
- c. Keep a token per project for the sake of the log alone. This is question 1b.

*Recommended: a.* The audit log is why standing access is acceptable at all (ADR-0001,
Consequences), and "which project's session did this" is the first thing asked when two projects
collide on one machine. One line in a file the project already has keeps the answer, and the
field's name says what it is: said, not proved. It is as trustworthy as the per-project token
was. Recording it for every token, not only an application's, costs nothing and means a
per-project token's calls can say it too.

## Settled already

- **What the one token may reach** is its allowlist, as for any token (ADR-0001 s6): the machines
  the application's projects need. It is fixed when the token is issued (ADR-0014 decision D).
- **Never the full level.** An inventory entry marked `issue: never` is not offered when a token is
  issued (ADR-0009 decision 3, ADR-0014 decision G), so an application's token cannot hold it. A
  token that does hold a full level stays a token of its own, in the keystore, fetched with its
  owner's approval at every connection (ADR-0009 decision 5), for the one project it was made for.
  An application's token lives in an environment variable, where every program can read it: the
  very reason that level was kept out of one.
- **It is a static token**, labelled unconfined wherever it appears (ADR-0006 decision 7).
- **The switch is per token** (ADR-0003). Nothing about it changes.

## Consequences

What this closes off, said plainly:

1. **Switching off one project's sessions alone.** The switch stops the application in every
   project. What a client says of its project cannot be switched on, since a session could say
   anything.
2. **A different allowlist for each project of one application.** One token, one allowlist. A
   project that needs otherwise is given a token of its own.
3. **The log naming a project on nervus's own word.** It records what the client said. It never
   could do more.
4. **Exports and uploads apart for each project.** They are kept per token (ADR-0016, ADR-0020), so
   an application's projects share one set of request keys: a key one project used is taken, for
   that export's or upload's life, for the others, and would answer with the first project's file.
   `docs/clients.md` will say to put the project in the key.

And what it gives:

5. **One secret for an application, not one for each project**, to issue, store, deliver and
   replace.
6. **A new project needs nothing from nervus's owner:** its settings name the application's
   variable and its own name.

## Order of work

Each step waits for the operator (rule 1), unless they say otherwise.

0. The operator's decisions on 1 and 2.
1. If 2a: the header read where the token is, `project_said` in every record's attribution and in
   `hosts`' answer, with tests, each guarantee broken on purpose and seen caught. Then the audit
   page: the project beside the client, and a filter that finds a call by the project it said or,
   for a token made for one project, by that token's project.
2. `docs/clients.md`: one token for each application, both ways to supply it unchanged; the header
   line in the Claude Code example; what Codex, whose settings are not a project's, can and cannot
   say; request keys that name the project. The example settings the export carries. `CHANGES.md`.
3. ADR-0001 s6 and s11 marked amended; ADR-0006 noted.
4. On the first installation, by a procedure written as executed: the token issued, delivered, each
   project moved, then the old tokens switched off, and later revoked.

## Verification

1. One token used from two projects: each call's record carries the token's id and the project
   that call said; the audit page shows both and filters by either.
2. A call that says no project, or a name outside the alphabet, is recorded without one and is
   answered as any other.
3. What a call says changes nothing else: saying another project's name reaches the same machines,
   is stopped by the same switch, and finds the same exports.
4. On an installation: an application's projects moved to one token, the tokens they had switched
   off, and a call from each found on the audit page under the one token with its project.
