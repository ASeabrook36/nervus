# ADR-0028: what nervus's own log may hold

**Status:** **Accepted 2026-11-01, at the operator's word** ("Yes, accept it", to "Mark ADR-0028
Accepted?"): its one verification item observed the same day. **Decided by the operator on
2026-11-01**, in a Claude Code session: question 1 as c, nervus's log left as it is with its rule
written down, and questions 2 and 3 as recommended ("Yes, record it", to "Record ADR-0028 as
decided, with the log left as it is?"). The draft recommended 1a.
Asked "is there any need to even change the log then?", the session weighed who can read the log,
not only what reaches it, and withdrew that recommendation (question 1). Each question keeps its
options, so the record shows what was not chosen. **Proposed 2026-11-01** the same day. Nothing
built, and nothing to build: the words it corrects were corrected the same day.
**Date:** 2026-11-01
**Raised by:** ADR-0027's deploy (procedure 048, step 11), which found the system's journal on
nervus's machine in a copy of that machine, with nervus's own log in it, and in that log the SSH
library naming each command nervus sent a machine. The operator settled the copy ("Yes, leave it
out", ADR-0027 step 8, amended); what the log may hold was reported, not resolved (AGENTS.md rule 6).
**Builds on:** ADR-0001 s10 (the audit log, mandatory); ADR-0007 decision 8 as amended by ADR-0025
(nervus's audit log is the record of which client did what, out of every client's reach); ADR-0012
decision 4 (the UI keeps no request log, so no sign-in link reaches the journal); ADR-0024 and
ADR-0026 (an enrollment code kept out of the journal, found there twice and hidden each time;
ADR-0026 decision 4, no password there); ADR-0027 (what nervus keeps; step 8, the copy leaves the
journal out).
**Corrects:** the reason ADR-0027 step 8's amendment gave, and the install guide's sentence that
repeated it (question 3), the same day.
**Evidence:** procedure 049, read-only, on the first installation: every line nervus wrote to the
journal in its first seven weeks, counted by kind, none printed.
**Written to the policy of ADR-0019:** this record names no system.

## Context

### What nervus's own log is

nervus runs as a service. What it writes to standard output and standard error, the service manager
keeps in the system's journal, beside every other service's lines. nervus itself writes little
there: its start lines, its warnings and its faults. Three libraries write the rest, at levels no
one in nervus chose:

- **The MCP library** sets Python's logging to INFO for the whole process when nervus builds its
  server, so every library's INFO lines reach the journal. Its own: a line for each MCP session
  opened, ended or refused, naming the session's id; the error text of each tool call that fails;
  the names, never the values, of arguments it rejects; a traceback for an unexpected exception.
- **The web server** writes its start and stop, and on MCP's port one request line per HTTP request:
  the client's address and port, the method, the path with its query string, and the status. The
  UI's port keeps none (ADR-0012 decision 4).
- **The SSH library** writes about ten lines for each connection (the machine, the addresses and
  ports, the account, the login's success, the close) and, for each command nervus sends, the
  command line itself, its exit status, and each file transfer with both paths. It writes nothing
  above INFO.

### What it held on the first installation (procedure 049)

- **About half the lines are the SSH library's and nearly a third are request lines**; a tenth are
  the MCP library's. nervus's own lines are a few dozen in seven weeks.
- **No client's command.** `exec` and `exec_bg` send nervus's script, the client's command inside
  it, on the SSH channel's standard input to `bash -s`, and the SSH library names only `bash -s`.
  Two thirds of the commands it names are that one.
- **The shape of nervus's activity.** Which machine nervus connected to, as which account, when and
  from which local port; the commands nervus composes itself, naming the paths a client gave (the
  file an export reads, an upload's destination and its temporary file) and job ids; each request's
  address, route and status, an upload's destination in its query string; session ids; the error a
  failed call returned. The audit log holds most of this by design. The journal holds it by
  accident.
- **Secrets reached it twice, by one route:** a one-time enrollment code in a URL nervus built,
  written once by the request log (found by ADR-0024's trial) and once in an SSH command line (by
  ADR-0026's deploy). A filter now hides that code in each, and only that code. No other secret was
  found: no key, no token, no password.
- **Who can read it:** root on nervus's machine, and members of the groups the system lets read the
  journal (`adm`, `systemd-journal`). Some systems put the first administrator's account in `adm`.
  The audit log can be read by nervus's own account, root, and the account a copy reads it with,
  where a copy is set up (ADR-0009 decision 4).
- **How long it is kept:** as long as the journal's size limit allows. That limit is the system's
  default (a tenth of the file system, at most 4 GB), shared with every service, and no one chose
  it. On the first installation, other accounts' logins wrote most of the journal and filled it
  within weeks, so they decide how long nervus's lines last. Where a syslog daemon copies the
  journal into files, those keep it by their own rotation.

### Why it matters

1. **A secret nervus puts in an SSH command line or a URL reaches the journal by default.** The two
   filters each hide one secret, added after a trial or a deploy found it. The next feature that
   passes a secret as a command's argument, not on standard input as `exec` does, writes it to the
   journal until someone searches for it.
2. **It is a second record that no one designed.** The audit log is the record of what clients did
   (ADR-0007 decision 8): append-only against clients, read in its viewer, copied by pull, its
   retention a question of its own (ADR-0027 question 8). The journal holds part of the same story,
   with other readers, another retention, and no rule for what goes in.
3. **Noise.** nervus's warnings, the lines a person reads when nervus misbehaves, are a few dozen
   among a hundred thousand.

## Questions

### 1. What nervus's log may hold

- **a. No SSH library lines.** At start, nervus sets the SSH library's logger to WARNING. That
  library writes nothing above INFO, so none of its lines reach the journal. The request log, the
  MCP library's lines and nervus's own stay. Half the lines go, with every command line nervus
  composes and every path in them, and a secret in an SSH command line no longer reaches the
  journal, whoever adds it. Lost: the SSH library's account of each connection. The audit log
  records each call and its result. A call that cannot connect leaves its intent there, and its
  reason in the MCP library's line for the failed call, which stays.
- b. Nothing of what clients do. As a, and also no request log on MCP's port (the UI's has none) and
  the MCP library's logger at WARNING: its session lines and failed calls' texts go, tracebacks
  stay. The journal holds nervus's own lines, start and stop, and faults. Lost besides: the request
  log, the one place a request refused before any tool runs shows (a client's 404 or 400), which
  helps when a client's setup is wrong; and the reason a connection failed, which the audit log does
  not record. So b needs the audit log to record a failed connection's result first.
- c. As now, with a rule written down: nothing secret goes into a URL or an SSH command line; where
  it must, it is hidden at the line, with a test, and the next deploy searches the journal for it,
  as ADR-0024's and ADR-0026's did.

*Recommended in the draft: a.* One setting closes the SSH side, where commands are composed in many
places, and halves the volume. URLs are few, each designed in an ADR, and the one that holds a secret
is already hidden. b costs a diagnostic and needs an audit-log change first; c leaves each future
author to notice.

**Decided 2026-11-01: c, the log left as it is.** The draft weighed what could reach the log, not who
can read it. The journal is read by root and by the accounts in the groups the system lets read it,
usually its administrators: accounts that can already read nervus's secrets, its SSH key among them.
A secret that reached the log would reach no one new, and procedure 049 found none there. a would
have kept out one of the two enrollment codes that reached it, the one in an SSH command line; the
other came through the request log, which a keeps. The trial or the deploy of the feature that added
each found it, and the rule below makes that the practice. The audit log holds each client's command
as sent, by design, and more accounts read it than read the journal. Less noise, a's other gain, buys
little: nervus's own lines are found by searching for them, as the deploys do. This holds while
whoever can read the journal can read nervus's secrets too. An installation that lets another account
read the journal shows it the shape of nervus's activity, and still no secret.

**The rule:** nothing secret goes into a URL nervus serves or builds, or into an SSH command line
nervus composes. A secret travels in a header or on standard input, as a client's token and `exec`'s
command do. Where one must go in a URL or a command line, it is hidden at that line, with a test, and
the trial or the deploy of the feature that adds it searches the journal for it, as ADR-0024's and
ADR-0026's did.

### 2. How long the journal keeps it

- **a. Left to the system.** After question 1's a or b, nothing a client gave is left there. The docs
  say where nervus's log is and who can read it.
- b. A limit set by nervus's installer in the journal's settings (`MaxRetentionSec=`). It applies to
  every service on the machine: nervus's installer would decide how long the machine keeps every
  other service's log too.
- c. A journal of nervus's own: a log namespace for the unit (`LogNamespace=`), with its own limits
  and folder. Every `journalctl -u nervus` in the installer, the docs and the deploy tools changes to
  name it.

*Recommended: a.* How long a log is kept matters for what a client gave, and after question 1 none of
it is there. c is worth its cost only if question 1 stays c.

**Decided 2026-11-01: a.** Question 1 stayed c, so the paths a client gave stay in the log, and
question 1's ground answers this too: no secret is there, and those who read it can already read
nervus's secrets. Keeping it for less time would hide nothing from anyone; c changes how long, not who
reads it. The install guide says where nervus's log is and, corrected (question 3), what it holds; who
reads it is the system's own rule for its journal.

### 3. The reason ADR-0027 step 8 gives

ADR-0027's amendment leaves the journal out of the copy because "nervus's own log names each command
it runs". Procedure 049 shows that it names the commands nervus composes, not a client's.

- **a. The reason corrected** to what procedure 049 found, the decision unchanged: the journal holds
  the shape of nervus's activity, file paths a client named, and whatever a fault puts there, and a
  copy has no use for any of it.
- b. Left as written.

*Recommended: a.* A reason that overstates a risk misleads the next reader as surely as one that
understates it.

**Decided 2026-11-01: a.** Corrected the same day in ADR-0027 step 8, and in the install guide, which
repeated it as "with any secret a client put in one". Procedure 048 stays as written; procedure 049
reads its step 11 again.

## Settled already

- **The copy of nervus's machine leaves the journal out** (ADR-0027 step 8), whatever is chosen
  here: the journal holds every service's lines, and a copy needs none of them.
- **No password in nervus's journal** (ADR-0026 decision 4). The admin password goes as the login's
  password and on `sudo`'s standard input, and neither library writes either.
- **No sign-in link** (ADR-0012 decision 4) **and no enrollment code** (ADR-0024, ADR-0026) in
  nervus's journal. Both filters stay under every option here: they cost nothing, and they still
  guard a level raised by hand for a diagnosis.
- **`exec` and `exec_bg` send the command on standard input**, as they have since the first commit.
  This record relies on it.

## Not chosen

- **Treating the journal as a record**, with the audit log's protections: the audit log is that
  record.
- **Clearing what the journal holds now:** the journal removes whole files, every service's lines
  together. nervus's lines age out with the rest.

## Not settled here

- nervus's warnings reach the journal at its ordinary priority, so a search for warnings misses them
  (an open item since procedure 020). Separate, and unchanged by any option here.

## Consequences

1. **For nervus:** nothing built. Its log stays as it is: the SSH library's account of each
   connection, the request log, the MCP library's lines and nervus's own.
2. **For a feature that must carry a secret:** the rule of question 1. Its ADR says how the secret
   travels, and its trial or deploy searches the journal for it.
3. **For a person reading nervus's journal:** as before. nervus's own lines are found by searching
   for them; the SSH library's lines are there for a diagnosis.
4. **ADR-0027 step 8's reason corrected** (question 3), and the install guide's sentence that
   repeated it. Procedure 048's step 11 is read again by procedure 049; its decision stands.

## Order of work

For the decision: words only, nothing built.

1. **The words**, done 2026-11-01: ADR-0027 step 8's reason, and the install guide's sentence that
   repeated it, say what procedure 049 found.

The draft's steps for 1a (the SSH library's logger at WARNING, its test, its deploy) are not done:
question 1 is c.

## Verification

Moves to Accepted at the operator's word when observed:

1. ADR-0027 step 8 and the install guide say what procedure 049 found, not that the log holds a
   client's command, and the install guide's tests pass. **Observed 2026-11-01, `ad499d8`:** both
   say it, and the install guide's 20 tests pass.
