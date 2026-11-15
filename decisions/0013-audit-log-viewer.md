# ADR-0013: the audit log viewer

**Status:** **Accepted 2026-10-12, at the operator's word** ("mark ADR-0013 accepted"), every
verification item observed in tests or on the first installation (procedure 021). **Decided by the
operator on 2026-10-11**, in a Claude Code session: questions A to I, each as the session
recommended in a draft of this ADR ("all as recommended"). Each question keeps its options,
so the record shows what was not chosen. **Built on `main`, 2026-10-11** (`96ab898` to
`861fc0f`), and **deployed to the first installation on 2026-10-12** at `2740c30` (procedure
021). Every verification item is observed, in tests first seen to fail or on that
installation; "Where each stands" says which, and what rests on the operator's report.
**Date:** 2026-10-11
**Rewritten:** 2026-10-17, under ADR-0019 F, to name no installation. No decision changed. The
original, with the first installation's log as read, is deployment note 0013.
**Decided by:** the operator, 2026-10-11
**Builds on:** ADR-0011 (the order of step 3: this is piece 3), ADR-0012 (how the UI is
built, and why every page escapes what it shows), ADR-0007 decision 8 and verification 7
(the log is read only through the UI, and follows its configured location), ADR-0005
decision 4 and verification 4, ADR-0001 s10 (what a record holds), ADR-0003 decision 6
(operator actions are audited)

## Context

The UI exists and the operator can sign in (ADR-0012). The audit log is to be read there
and nowhere else (ADR-0005 decision 4, ADR-0007 decision 8). No ADR says how the viewer
works: what it reads, what one row is, how it shows text an agent chose, or how the
operator finds anything.

### What the real log holds

Read off the first installation's real log, through nervus, read-only, on 2026-10-12. The figures
as read are in deployment note 0013. What they showed:

- **Every line is valid JSON**, the file ends with a newline, and the timestamps never go
  backwards. Reading and searching every record costs microseconds a record: well under a second
  for a log of a megabyte or so, and seconds per hundred megabytes. On a machine with one CPU, MCP
  calls slow down while a long search runs.
- **Four kinds of record**, by `phase`:

  | phase | what it is | its own fields |
  |---|---|---|
  | `intent` | a call about to run | `token_id`, `client`, `project`, then by tool: `host`, `user`, `cwd`, `command`; `method`, `path`, `params` (an object); `job_id`, `action` |
  | `result` | how that call ended, same `id` | `exit_code`, `duration_s`, `output_bytes`, `truncated`, `timed_out`, `log_path`; or `status`, `reason`, `body_bytes`; or `count`, `hosts` (a list); or `session_name`; or `running` |
  | `refused` | a call refused before it ran | `token_id`, `client`, `project`, `reason`, sometimes `host` or `local_path`; for the UI, `actor`, `action`, `address`, `link` |
  | `operator` | something the operator did, by `nervus-ctl` or in the UI | `actor`, `action`, then `target`, `kill_work`, `outcome` (a list), `ended`, `link`, `session`, `expires`, `address` |

  Every tool appears, and refused MCP methods also appear as tools: `initialize`,
  `tools/call`, `tools/list`, `server/discover`.
- **Pairs:** in that log every result directly followed its intent. Some intents have no
  result. One was a status check sent to a host while it was down for a reboot. A call nervus
  cannot connect for writes its intent and no result (`server.py`: the connection is made after
  the intent, with no record if it fails). **"No result" therefore means "still running" or
  "never finished", and the log cannot say which.** *Since 2026-11-07 (procedure 054, finding 3):* a
  call that fails after its intent, the connection included, writes a result naming its `error`, as
  the proxmox tool's always did; "no result" now means still running, or nervus stopped mid-call.
- **Refusals come in floods:** most of them were one switched-off client retrying `initialize`,
  on the day the refusal timing was measured (procedure 019).
- **A few records are huge**, every one an `exec` sending a file in pieces as commands: tens of
  kilobytes each, one-line base64 or a command over some 175 lines, and between them most of the
  file's bytes. Otherwise a record is small: half are under 256 bytes, 90% under 520.
- **Text that is not one plain line:** commands span several lines; refusal reasons contain
  newlines, quotes and file paths; a command can hold a non-ASCII character such as an em dash.
  No value held a control character.
- **What is not in the log: the output of a command.** An `exec` result holds the exit code,
  the output's size, whether it was cut short, and `log_path`, where the full output sits *on
  the target*. The viewer can show that a command ran and how it ended, not what it printed.
  (ADR-0001 s10 says the same; "what came back" in nervus's client instructions means only
  that.)

### What the viewer must guard against

ADR-0012 explains the first hazard: an agent steered by hostile text (ADR-0007, adversary A)
chooses the commands, paths and parameters that land in the log, so any of it may be
written to attack the page that shows it. Escaping every value (ADR-0012 decision 2) stops
it running as code. It does not stop text that **misleads**: characters a browser draws as
nothing, or that reorder the text around them, so that a command reads on screen as
something other than what ran. Question D is about that.

The second hazard is size. One record can be tens of kilobytes, the log grows without limit
(retention is undecided), and on a small machine every search shares the CPU with MCP.

## Questions, and what was decided

### A. What the viewer reads

1. **The log file itself, at each request.** The newest page is read from the end of the
   file backwards, so it costs the same however large the file grows. A search reads
   further back, until it fills a page or reaches the start.
2. **A copy in the SQLite database**, kept up to date as records are written, and indexed
   for searching.
3. **An index held in memory**, built when nervus starts and extended as records arrive.

**Recommended: 1.** The log stays the one record, with nothing beside it that could
disagree with it. It also follows the configured location for free, since it reads
`--audit-log` (ADR-0007 verification 7), and reads exactly what an off-host copy receives
(ADR-0009 decision 4).
Options 2 and 3 make searching fast at any size, but they add a second copy to keep
correct, a startup cost, and code. A log of a megabyte or so reads whole in milliseconds. The cost
of 1 is that a search of a very large log is slow, which question E bounds.

**Decided: 1.**

### B. What one row is

1. **One row per record**, exactly as written.
2. **One row per call.** An intent and its result, matched by `id`, make one row; a
   refusal is one row; an operator action is one row. Each row opens a page of its own
   showing every record it came from, field by field, in full.

**Recommended: 2.** The operator's question is "what did this client do, and how did it
end", which is one call, not two records. Reading backwards, a result is always met before
its intent, so pairing needs no lookahead. An intent with no result is shown as **"no
result recorded"**, not as a failure, because the log cannot tell a running call from one
that never finished. Option 1 is simpler and shows the log as written, but doubles the
rows and leaves the operator to pair them by eye.

**Decided: 2.** *How the session builds it, not decided by the operator:* a row sits in
the list where its newest record is, so each page is one stretch of the file. That
corrects the recommendation's "pairing needs no lookahead": to show a result with its
intent, the reader looks back for the intent, which is almost always the line just before.
Without that, a page ending between the two would show the result's call as "no result
recorded".

### C. How long values are shown

1. **In full, in the list.** One command of tens of kilobytes fills several screens.
2. **The list shows the first line of a value, cut at about 160 characters, and says how
   much is hidden** ("… 32,855 characters", "… 12 lines"). The call's own page shows every
   field in full, wrapped, line breaks kept.
3. **As 2, with the call's own page also cut** at some size.

**Recommended: 2.** The list stays readable, and nothing is ever unreachable: the full
value is one click away, which matters because a long command is exactly where something
can hide. Option 3 would make the log's largest records the only ones the operator cannot
read in full. A page of tens of kilobytes is small.

**Decided: 2.**

### D. Characters that hide what a command is

Escaping makes `<script>` harmless. It does nothing about these, all of which an agent can
put into a command:
- **direction controls** (such as U+202E), which make the browser draw the text after them
  in reverse order, so that `rm -rf /tmp/x` and a different command look alike. This is the
  "Trojan Source" attack on code review;
- **zero-width and other invisible characters**, which make two different strings look
  identical;
- **control characters**, such as the escape codes that colour a terminal.

None appear in this log today.

1. **Show them as they are**, escaped. The browser draws or hides them as it would.
2. **Show each one as a visible, highlighted code**, such as `⟨U+202E⟩` or `⟨ESC⟩`, and
   leave all other text alone: letters in any script, the em dashes already in the log, and
   ordinary punctuation. The set is every character Unicode classes as a control, a format
   character, a line or paragraph separator, private-use or unassigned, except newline and
   tab.
3. **Show every non-ASCII character as a code.** Nothing can hide, but an em dash or a
   name in another script becomes unreadable.

**Recommended: 2.** The viewer's whole job is to show the operator what ran. A command that
displays as something else defeats it as surely as a script would, and adversary A is the
one writing commands. Option 2 makes the trick visible without harming honest text. A test
pushes each kind through every page, as ADR-0012's test does for markup.

**Decided: 2.** *How the session builds it, not decided by the operator:* inside the
escaping every page already uses, so it holds on every page by default, as escaping does.
A limit that follows from the set: combining
marks, variation selectors among them, are not in it, since they are ordinary in many
scripts; they cannot reorder text, but can be stacked invisibly on a visible character.

### E. Finding things

1. **Paging only**, newest first.
2. **Paging, and filters** by client (token), host, tool, and kind (calls, refusals,
   operator actions).
3. **As 2, and a text search**: rows where any field contains the given text, ignoring
   case. Plain text, not patterns.

**Recommended: 3.** Filters answer "what has this client done" and "what was refused"; the
refusal floods make the kind filter necessary from day one. Search answers "did anything
ever run `rm -rf`", which is what an audit log is for. Filters and search are part of the
page's address, so a view can be bookmarked, and since they change nothing they need no
form token.

- **Paging:** 100 rows a page. "Older" carries a position in the file (a byte offset). The
  log only grows, so a position stays valid; one that does not fit the file, or does not
  fall at the start of a record, is ignored and the viewer starts from the newest.
- **One sub-choice: bounding a search.** A search of a log of a megabyte or so takes
  milliseconds. At 100 MB it would take seconds of one CPU. Either **(a)** no bound, to be
  revisited when retention is decided; or **(b)** a search stops after reading some amount
  (say 50 MB) and offers "keep looking". **Recommended: (a).** The bound would be code for a
  size this log is years from, and retention, still open, decides that size.

**Decided: 3, with (a).** *How the session builds it, not decided by the operator:* an
unreadable line has no client, host or tool, so only a text
search, or no filter, can find it.

### F. A live view

ADR-0012 decision 2 left this to piece 3: "if the audit viewer wants a live tail, that is
one small script, decided then".

1. **None.** The page shows the log as it was when loaded; reloading shows what is new.
2. **The page reloads itself** every so often, by an HTML instruction, with no script.
3. **One small script** that fetches new rows as they arrive. The pages' protection that no
   script runs (ADR-0012, standard browser protections) would loosen to allow nervus's own.

**Recommended: 1.** The log serves accountability after the fact (ADR-0007 decision 1). A
page that reloads itself loses the operator's place while they read back. A script reopens
the protection that keeps the escaping question to "is it escaped". Watching the log as it
grows is already possible on the nervus machine, and wherever the log is copied (ADR-0009
decision 4).

**Decided: 1.** The pages' content security policy is unchanged.

### G. Is reading the log audited?

1. **No.**
2. **One record for each page viewed.**
3. **One record for each search.**

**Recommended: 1.** Every view happens inside a session whose sign-in is already recorded,
with the browser's address (ADR-0012 decision 6). A view changes nothing. Recording views
would fill the log with the viewer's own traffic, each view showing itself. The cost: a
session cookie stolen from the operator's browser could read the log and leave no trace of
its own. Nothing in the threat model relies on catching that; a stolen session is bounded
by its 12 hours and `nervus-ctl signout --all`.

**Decided: 1.**

### H. A line that is not a readable record

None exist today. They would appear if the file were damaged, a write were cut off, or the
file were edited by hand.

1. **Skip it.**
2. **Show it as a row of its own**, "unreadable record at byte N", with its text shown as
   question D shows any text.
3. **Refuse to show the page.**

**Recommended: 2,** with one exception: a last line without its newline is a record still
being written, and is left out until it is complete. Skipping would hide exactly the lines
that show a damaged or edited log. Refusing would make the whole log unreadable because of
one line, in the moment the operator most needs it.

**Decided: 2.**

### I. Smaller choices, which can be taken together

- **Where it sits:** at `audit`, linked from every signed-in page's header. The home page
  links to it too.
- **Times** in the viewer in UTC, as every page already shows them, and to the second,
  where the other pages show minutes.
- **What a row shows:** the time, the client (its token id, or `operator`), the tool, the
  host, the command, path or reason, and the outcome: an exit code and duration, an HTTP
  status, "refused", or "no result recorded".

**Recommended:** all three as written.

**Decided: all three.**

## Not proposed here

- **Showing what a command printed.** The output is on the target, at the result's
  `log_path`. Fetching it would give the UI a way into the fleet, which is a different
  piece's question.
- **Downloading the log** from the UI. An installation that keeps an off-host copy (ADR-0009
  decision 4) already has one.
- **Retention.** Still open (`CURRENT_STATE.md`). The viewer's cost grows with the file, and
  question E's bound is the place the two meet.

## Found while reading, for the record

**A token with the full level can read the log through an MCP tool.** ADR-0005 verification
4 and ADR-0007 verification 7 say no MCP tool reaches it. The full level on nervus's own host
(ADR-0009 decision 3) reaches nervus's machine as root, and the first installation's reads for
this ADR went that way (deployment note 0013). That is ADR-0009's grant, made knowingly, and
not changed here.
Those two verification items should name it as the exception when they are observed.

## Consequences

1. **Piece 3 builds, one commit each, every new test seen to fail first:**
   1. a reader of the log (`audit_view.py`): newest first from the end, calls paired, a
      position to page from, filters and search, unreadable lines kept, a line still being
      written left out;
   2. hidden characters shown as marked codes, inside the escaping every page uses (D);
   3. the viewer's two pages, the list and one call, and a link to them in every signed-in
      page's header;
   4. the UI serving them at `audit`, signed in only, the log read in a worker thread so a
      long read does not stop nervus answering.
2. **The new pages join `PAGES`**, so ADR-0012's hostile-text test covers them, with hostile
   text in every field of every kind of record.
3. **Test data is written for the tests**, in the shapes above. No real record enters the
   repository (rule 7: a command can hold anything).
4. **An existing test changes meaning.** ADR-0012's hostile-text test expects every hostile
   value back as it was given. One of its values is a line separator, a paragraph separator
   and an invisible format character; under D those come back as marked codes, which is the
   point of D.
5. **The deploy changes nothing on an installation but the code.** The UI already reads
   `--audit-log`, and the unit already lets nervus read `/var/log/nervus`. The deploy is its
   own procedure, approved by the operator before anything runs.
6. **The viewer slows as the log grows** (A, E), with no bound until retention is decided.

## Verification

Moves to Accepted when observed in tests first seen to fail, or on an installation.

1. Opening the viewer on a large log reads about one page of records from its end, not the
   whole file (A).
2. An intent and its result show as one row, also when other records come between them or a
   page ends between them. An intent with no result shows "no result recorded"; a result
   whose intent is missing is still shown (B).
3. A value longer than 160 characters, or than one line, is cut in the list, which says what
   is hidden; the call's own page shows it whole (C).
4. Each kind of hidden character, put through every page, comes out as a visible marked
   code. An em dash and letters in other scripts come out unchanged (D).
5. Each filter and the text search show exactly the rows that match. Paging with "Older"
   shows every row once, also when records are appended between pages (E).
6. No page of the viewer runs a script (F), and viewing it writes no audit record (G).
7. A line that is not a record shows as a row of its own, with its position in the file. A
   last line without its newline is not shown until it is complete (H).
8. Without a session, the viewer shows only how to sign in. With one, it shows the file
   `--audit-log` names (ADR-0007 verification 7, its first and last parts).
9. On an installation, the operator reads its real log in the viewer: one of its largest
   records whole, and a flood of refusals filtered away.

**Where each stands, 2026-10-12, after procedure 021.** Item 8, on the first installation:
signed out, the viewer showed only how to sign in (step 3); signed in, it showed its real log,
the file the unit's `--audit-log` names (step 4). Item 9, there: the largest records cut in the
list, by screenshot; one shown whole, by the operator's report; Refusals showing the flood
and Calls showing calls only, by screenshot, though the Calls screenshots do not reach the
flood's own hour. Decision G there: four and a half minutes of reading wrote nothing
(step 5).

**Where each stood, 2026-10-11.** Items 1 to 7: observed in tests, each first seen to fail
with the code missing or broken on purpose; the commit messages say how. Item 8: observed
in tests that the viewer shows nothing signed out, and shows the log the UI is given. That
nervus gives the UI the file `--audit-log` names is read from `__main__.py`, where MCP and
the UI share one `AuditLog`; no test covers it, and the deploy will observe it. Item 9:
needs the deploy. Also seen in a browser, on the developer's machine against the UI on loopback
over a made-up log in the real one's shapes: the list, marked codes, a long command cut and
whole, filters, search, and the layout at phone width.

## Amendment 2026-11-13: what a call asks for is recorded whole, or the call does not run (procedures 056 and 058)

**Finding 3, recorded here.** The security review before the 0.2.0 export (procedure 056, finding
3) found that a few client calls could drive one record to megabytes — a character outside the Basic
Multilingual Plane costs twelve bytes once JSON-escaped — wedging the off-box copy, which refuses a
line over 8 MiB, and the viewer. Commit 8dbca55 bounded every record: each client string was cut to
4096 characters with a marker, a record still over 256 KiB kept only nervus's own fields, and the
viewer's backward scan was bounded.

**What that cost, and the change.** An intent cut to fit records only the start of what the call
asked for, so a call could hide its end: 4096 harmless characters, then the part that matters, was
recorded as the harmless part and a count. ADR-0001 section 10 — the record is written before the
effect — held in form, not in substance. So intents are no longer cut. An intent is written whole;
one whose record would be over 256 KiB as the log writes it is not written at all. nervus writes a
refusal in its place — the call's own fields cut as before, the record's size, and the SHA-256 of
the arguments — and the call does not run (`AuditRefused`, an `AuditError`, which every caller
already treats as "do not proceed"). A client with that much to send uses an upload (ADR-0020).
Results, refusals and operator records are still cut: a result describes what happened, and an
`exec`'s whole output stays on the target. Every line stays bounded, so finding 3's denial of
service stays fixed, and the list already shows a long value cut, whole only when opened (decision
C).

**Verification gains:** *a call whose arguments are too large to record whole is refused before it
runs, the refusal carrying the arguments' hash; a command longer than 4096 characters but under the
limit is recorded whole, its end included (tests in `test_audit.py`, seen to fail first; procedure 058, on
a real install: a 300 KB command refused before it ran, a padded one recorded whole).*
