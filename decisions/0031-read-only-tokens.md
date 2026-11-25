# ADR-0031: a client can be read-only on a machine, through a second account the machine keeps read-only

**Status:** **Accepted 2026-11-23, at the operator's word** ("Yes, accept it"). Every verification
item was observed on throwaway machines by the trial (procedure 068, section 11). Items 1, 2's second
half, 4's `put`, 6 and 8 were observed again on the first installation, deployed 2026-11-21, with its
first read-only token (procedure 068, sections 16 to 18). Item 3 was seen on the trial alone, since
that token is read-only on every machine it names. Its amendments to ADR-0001 s6 and ADR-0024 are
marked there. **Decided by the operator, 2026-11-20: the model below, in their words.** Step 1 of the order of work tries it on machines before any
code. The file keeps the name it was proposed under. **Three questions the record did not answer
were put to the operator before the build and answered the same day (questions 4 to 6, procedure
067).** **Two more, found at the start of the build, were answered the same day (questions 7 and 8,
procedure 068): the accounts nervus makes are named for nervus, `nervusagent` and
`nervusagent-readonly`, and the person adding a machine may give other names.** **Three more, found
by the independent review before 0.3.0, were answered the same day (questions 9 to 11, procedure
068): removing a machine takes only nervus's parts off an account that was there before nervus; a
rollback reaching a machine as `agent` is accepted and recorded; and the old accounts keep nervus's
line until nervus has accepted the new ones.**
**Two more, found while building those answers, were answered the same day (questions 12 and
13, procedure 068): an add nervus refuses leaves the machine exactly as it was, and nervus
remembers every account it made on a machine until the machine is removed.**
**Date:** 2026-11-19, proposed; rewritten around the operator's model 2026-11-20 (procedure 066).
**Asked for by:** the operator, on 2026-11-19, of the first token for a client still being built:
it "is going to be read-only at the nervus level". Such a client should look and not change on
machines other clients work on, and be given more later by one act of the operator's.
**Builds on:** ADR-0001 s4 to s6 (one `agent` account; the boundary is SSH's; a token is an
allowlist); ADR-0005 decision 5 and ADR-0024 decision 1 (levels, each enforced by the machine;
read-only by a forced command and the kernel); ADR-0007 decisions 5 and 6 (a client's credential
"carries an allowlist and a level"; a compromised nervus is total, and read-only machines stay
read-only); ADR-0009 decision 1 (one machine as two entries, behind two accounts); ADR-0014
(tokens issued in the web UI; decision F, changing the database without breaking a rollback);
ADR-0024 and ADR-0026 (a machine added from the web UI, its level chosen then); ADR-0025 (a
certificate nervus signs for each connection, naming the account).
**Amends:** ADR-0001 s6 (a token says which machines, and now what level on each) and ADR-0024
(what enrollment asks and makes), each marked there, 2026-11-23.
**Written to the policy of ADR-0019:** this record names no system.

## The decision, in the operator's words (2026-11-20)

> I'm just now realizing that we have it set up to be read-write. The granularity isn't really on
> the machine side because there's only one account and it can do anything. And because Nervous
> doesn't inspect—I mean, Nervous logs what you do, but Nervous isn't able to keep track of every
> command you're going to run on. Nervous isn't going to be able to practically check every single
> command and determine whether it's read or write. I guess the way that this has to then work is
> that every machine gets two accounts on it: one read-write agent and one read-only agent. Which
> means that Nervous can then direct the traffic in that manner based on a per-key basis. This has
> to change the way Nervous works a little bit in that we now have to have two accounts on each
> machine: read-only and read-write. During enrollment, you would decide whether you want this to
> be a machine with read-write and read-only capabilities, and we would call out during the
> install or the enrollment, "Do you want this agent—do you want this machine to be both read-
> write capable and read-only capable?" or "Do you want agents to be able to read-write on this
> machine?" and make it clear that you can assign clients individually to be read-only or read-
> write if you do this. But you could still make it read-only, in which case it's a moot point; no
> agent would be able to be read-write on that machine. And so that security then sits at the
> machine level. Two accounts. Now, Nervous will then have to maintain the list of clients and the
> list of machines it has access to, and on a per-machine basis, it can route the requests or it
> can route what account uses the requests. The agent, the client app, doesn't get a choice. If
> it's assigned to a machine at a read-write level, it'll use the read-write account, but if it's
> assigned to a machine at a read level, the account will go through the read-only account to the
> machine, and the machine itself will refuse it. Nervous is just in charge of making sure that
> clients and agents are only able to use whichever account they are assigned to in the Nervous
> management page. Does that take care of it?

Answered the same day: yes. Their word on having it written here: "record it".

### What it comes to

1. **A machine that clients may change has two accounts of nervus's:** the read-write one, `agent`,
   as today, and a read-only one, `agent-readonly`, set up as a read-only machine's `agent` is. The
   machine keeps the second read-only, by the sandbox its kernel enforces (Context). **Since question
   8 they are named `nervusagent` and `nervusagent-readonly`, or as the person adding the machine
   chooses;** where this record says `agent-readonly`, that is the read-only account.
2. **The choice is made when the machine is enrolled:** read-only alone, where no client can change
   it whatever nervus says, as today; or read-write and read-only both. Enrollment asks, says that
   clients can then be assigned one or the other each, and makes the second account.
3. **A level belongs to a client on a machine,** not to a token as a whole: one client can be
   read-only on one machine and read-write on another. It is set in the web UI.
4. **nervus chooses the account from that assignment, and the client has no say.** nervus does not
   sort commands into reading and writing (ADR-0001 s5); the machine refuses the writes.
5. **The machine checks nervus's choice too.** The certificate nervus signs for a read-only call
   names the read-only account alone, so the machine admits it to no other (Context).

### How the record got here

Proposed on 2026-11-19 as a property of a whole token, the account made by hand at first. Walked
through with the operator on 2026-11-20 (procedure 066, section 11). Their first answer to question
1 kept one level per machine for every client, which is what nervus does now; the question that
separated the two got no preference. Then the message above. Their answer to question 2 was "Look
and run only (Recommended)", and to question 3, "I think my earlier answers might alter the
premises of this question, so check those out before we decide this": their model answers it, as
3b.

## Context

### Where a level lives today

A level, read-only, standard or full, belongs to a machine. Its owner chooses it when the machine
is added, the machine enforces it, and nervus cannot raise it (ADR-0024). A token says which
machines a client may reach, and nothing about what it may do there (ADR-0001 s6). So today a
"read-only token" can only mean a token that names machines added read-only.

That is not what is wanted when the machines are shared. A machine other clients build and deploy
on is at standard or full, for them. A new client, or one still being tested, should be able to
read that same machine without being able to change it.

### How a machine keeps read-only now

A read-only machine's `agent` has one line in `authorized_keys`: trust nervus's certificate
authority, `restrict`, and a forced command, nervus's read-only shell. The machine's own SSH server
runs that shell whatever nervus asks. The shell runs every command inside bubblewrap, a sandbox the
kernel enforces: every file read-only except `agent`'s own `~/.nervus`; file transfer is the SFTP
server in its read-only mode. Observed on Debian 13 and Ubuntu 24.04 and 26.04 (procedures 036,
037, 054, 055 and 057).

Two things about it matter here:

- **It was built for an account that has nothing.** At read-only, enrollment makes `agent` with no
  `sudo` and in no group but its own. The sandbox then adds one thing: `agent` cannot change even
  its own files.
- **Inside the sandbox `sudo` does nothing**, at any level: bubblewrap sets the kernel's
  no-new-privileges flag, under which a setuid program gains nothing. (bubblewrap's documented
  behaviour; to be seen at step 1.)

### Why the same account will not do

The smallest change would keep one account: for a read-only token, nervus would put the read-only
shell into the certificate it signs, as its forced command, and the machine's SSH server would run
`agent`'s commands inside the sandbox for that connection. On a machine whose `agent` is bare, that
holds. On a shared machine at full it does not, for three reasons:

1. **Groups.** A full machine's `agent` often belongs to its owner's groups; the install guide's
   hand steps suggest it, and the first installation's hosts were set up so. A group like `docker`
   lets its members ask the container daemon for anything, and the daemon runs as root. The
   sandbox does not stop that: it keeps the account's groups, since an unprivileged program cannot
   shed them, and a read-only mount stops writes to files, not a connection to a socket. So a
   command in the sandbox could start a container with the machine's disk mounted and change any
   file on it. Read-only would be a promise nervus could not keep, on exactly the machines where
   it is most wanted. (From Docker's documentation, that its group is root-equivalent, and the
   kernel's rule that a read-only mount refuses writes to files, folders and links; not yet tried
   on a machine: step 1.)
2. **One scratch folder.** `~/.nervus` holds every call's saved output and every job's log, and it
   is the one folder the sandbox leaves writable. A read-only token could rewrite what a full
   token's call saved there, and the full token's client would read it back as its own command's
   output.
3. **One account's processes.** Programs of one account can signal each other. A read-only token
   could stop other clients' jobs.

Each is what separate accounts are for.

### What the certificate already decides

Since ADR-0025 nervus signs a certificate for every connection. A certificate names the accounts it
may log in to, and an SSH server admits it to no other. So which account a connection gets is
decided by what nervus signs, never by anything a client sends: a client holds a bearer token and
no key. A certificate can also carry a forced command, which the server enforces as it enforces a
line's own; where both are present it admits the certificate only if the two are the same
(OpenSSH's documented behaviour; the mismatch seen from a real server in ADR-0025's tests).

One installation already runs one machine behind two accounts, chosen by the token's allowlist: a
hypervisor host, with a bare account for every client beside `agent` (ADR-0009 decision 1). Both
log in by certificate (procedure 044).

## Questions

Each keeps its options, so the record shows what was not chosen.

### 1. What makes a client read-only on a machine whose own level is higher

- **a. A second account on the machine, `agent-readonly`, set up as a read-only machine's `agent`
  is: no `sudo`, no group that reaches a service able to change the machine, and the read-only line
  in its `authorized_keys`. For a client assigned read-only there, nervus signs only a certificate
  that names that account and carries the read-only shell as its forced command, and offers no
  plain key.** The machine's SSH server admits it to that account alone and runs that shell; the
  kernel keeps every file read-only inside it. On a machine that is itself read-only, `agent` is
  already such an account and is used as it is, so nothing is added there. A machine with no such
  account refuses the login, and nervus tells the client so: nothing runs.
- b. The same account, the certificate forcing the read-only shell. No second account. Not
  read-only where `agent` reaches a privileged service, and it shares `agent`'s scratch folder and
  processes with clients that can change the machine (Context).
- c. No level on a client. A second inventory entry for each machine, written by hand and naming a
  second account; a read-only client is then one whose allowlist names only such entries. Two
  names for each machine, and ticking the wrong one gives everything.
- d. nervus refusing commands that write. ADR-0001 s5 rejected filtering commands: a shell cannot
  be told to only read.

**Decided: a, and the level set for each client on each machine** (the operator's model; the
proposal had one level for the whole token).

The forced command in the certificate is a second lock on the same door: if the account's line
were written without it, the sandbox would still be forced, and if the shell is missing nothing
runs. It cannot lift a machine's own read-only line, since OpenSSH admits a certificate whose
command differs from the line's to nothing.

### 2. What a client may call on a machine where it is read-only

- **a. `exec`, `exec_bg`, `job`, `get`, `export` and its download work. `put` and uploads to that
  machine are refused by nervus before anything is sent, saying the client is read-only there. On a
  hypervisor machine where the client is read-only, the `proxmox` tool and a VM named by its id are
  refused too, saying why.** The hypervisor's API is one credential of nervus's for every client,
  with no look-only half; and a VM nervus enrolls has one account, with `sudo`.
- b. As a, and the `proxmox` tool for `GET` requests only. A filter nervus keeps on another
  program's API, where some reads are privileged ones.
- c. As a, and a second, look-only credential at the hypervisor, in its own auditor role. The same
  shape as 1a, enforced by the hypervisor. A later step if a read-only client needs to see VMs.

**Decided: a**, the operator's "Look and run only (Recommended)"; c is not closed off.

### 3. How a machine gets the account

- a. By hand, as root on the machine, from a short block in `docs/install.md`.
- **b. Enrollment makes it, when the machine's owner chooses read-write and read-only both.**
- c. nervus makes it itself over the full access it has. It is nervus changing a machine's
  accounts from afar, which ADR-0024 decision 5 left to the person at the machine.

**Decided: b** (the operator's model), **and a for a machine described by hand**, which never goes
through enrollment. How such a machine's short step is given, and how nervus learns the account is
there, is question 4.

## Three questions the record did not answer, put before the build (2026-11-20, procedure 067)

Found by reading the record against the code before step 1, and put to the operator in one batch,
each with its options. Their answers are quoted as given.

### 4. How a machine described by hand gets the account, and how nervus learns it has it

Question 3 gave such a machine a short documented step, run as root on it. It did not say how
nervus comes to know the account is there, which the token form (order of work, step 6) and
`nervus-ctl` (step 7) both need.

- **a. From the Machines page. Beside each machine described by hand that a token may be issued
  for, a button gives two lines to run as root on it, as adding a machine does (ADR-0024 decision
  2). The script makes the read-only account alone and leaves the account the machine is described
  with as it is. nervus then logs in as the read-only account, checks that it is read-only, and
  records it in the database. No file is edited and nervus is not restarted.**
- b. A block of commands in `docs/install.md`, run as root on the machine; then a field on the
  machine's entry in the inventory, and nervus restarted to read it, which drops every client's
  connection for a moment. nervus takes the field's word that the account is there.

**Decided: a**, "From the Machines page (Recommended)". The short documented step of question 3a
and of detail 2 is those two lines, tested as written.

### 5. A machine added at standard or full where the sandbox cannot start

Detail 4 gives such a machine what a read-only machine needs today (ADR-0024 question 9). It did
not say what happens where that is not enough, and no read-only account can be made.

- **a. The machine is added with its read-write account alone, exactly as it would be today. The
  script's output and the Machines page say that it has no read-only account and why, and no
  client can be assigned read-only there until it is added again.**
- b. The enrollment is refused until read-only can be made there. A machine that enrolls without
  trouble today could be turned away.

Put first as "that sandbox cannot start there … what should happen?", which the operator read as
a limit on read-write: "I'm not quite sure I understand. Are you saying there are machine types out
there that we simply will be unable to make read right like it seems like we have one way of making
certain machines rewrite if they have this thing called bubble wrap but like we should, we should
find a way of any machine that we let people enroll. We should find a way of allowing them to
enroll it as read right and I don't quite understand why we don't have that pathway yet." Put
again, saying that every machine can be added read-write with no bubblewrap, which only the
read-only account needs.

**Decided: a**, "Yes, add it read-write (Recommended)". Their rule stands with it: any machine
that can be enrolled can be enrolled read-write.

### 6. Whether a machine added at standard or full always gets the read-only account

The operator's model has two outcomes, read-only alone, or read-write and read-only both; the
consequences below speak of a script that "may" make the second account.

- **a. Always both. Choosing standard or full makes both accounts, and the form says that each
  client can then be assigned read-only or read-write there.**
- b. A tick-box, on by default, which the owner can clear to get the read-write account alone, as
  machines added before this release have.

**Decided: a**, "Always both (Recommended)". A machine has the read-write account alone only
where it was added before this release, or by question 5.

## Two questions found at the start of the build (2026-11-20, procedure 068)

### 7. An account nervus would use read-only that already exists, in a group that reaches a root service

Found reading the record against the code before step 1. The read-only account has "no group that
reaches a service able to change the machine" (question 1a), and its owner may give it groups for
reading logs ("What read-only means"). Enrollment makes it in no group but its own; but an account
of that name may already exist, in a group such as a container daemon's, whose members can have
that daemon, running as root, change any file. The same holds today of `agent` on a machine added
read-only: enrollment never looks at its groups. Put with these options:

- a. The account not used read-only: at standard or full the machine added read-write alone, as in
  question 5; at read-only the script stops; the script and the Machines page name the group and
  how to take the account out of it; groups for reading logs kept as the owner gave them.
  (Recommended.)
- b. Its groups listed by the script, and the account used read-only all the same.
- c. The account taken out of those groups by the script.

The operator's answer, in their words: "We could avoid this issue by just changing the name we use
for the account we create. We create to something that includes the word nervus, example below. If
we want to get really flexible we could give the person enrolling the machine, the opportunity to
set what the name is going to be, and this way we could allow them to set it to an already existing
account, but we would auto fill the text box with our version (nervusagent/nervusagent-readonly)"

**Decided: the accounts are renamed (question 8).** An account of a name only nervus uses exists
only if nervus made it, or its owner made or named it for nervus on purpose. So where one exists,
the script lists its groups and uses it as it is, which is b for that case alone.

### 8. How far the rename goes

Put with these options, each word of the question defined in it:

- a. Both accounts renamed, no box for the names (Recommended).
- **b. Both accounts renamed, and a box for each name on the form that adds a machine, filled in
  with nervus's names, where the owner may name an existing account instead.**
- c. Only the new account renamed; `agent` everywhere as today.

**Decided: b**, "Both renamed, with a name box". What it comes to, as it was put:

- From this release a machine added from the web UI gets **`nervusagent`**, the read-write account,
  at standard or full, and **`nervusagent-readonly`**, the read-only account, at every level. At
  read-only alone it keeps only `nervusagent-readonly`, so a change of level adds or takes off
  `nervusagent`.
- **The form's two boxes** are filled in with those names, and its owner may name an existing
  account instead. The script replaces that account's SSH keys with nervus's line alone, as it does
  `agent`'s today, so naming a person's own account shuts their own keys out. nervus refuses root
  and the machine's system accounts, and the same account for both. **The operator added, the same
  day:** "We should include a warning on that name box when a user tries to reuse their own name
  about the whole keys being locked out thing if it's a pre-existing account". nervus cannot see
  the machine's accounts from its page, so a name other than nervus's own is asked about first, as
  a raised level is (ADR-0024 question 8): the page says that if that account already exists, its
  own SSH keys are replaced by nervus's line and whoever logs in to it with a key, its owner too,
  is shut out, and goes on only when the name is typed again. The script says so when it replaces
  an existing account's keys.
- **A machine added before this release** keeps `agent` until it is added again. Adding it again
  moves it to the names given, and takes nervus's line and its sudo line off the old `agent`.
- **A machine described by hand** keeps the account its entry names, and gains the read-only
  account by the two lines of question 4. Applied by the session that built it, and said to the
  operator: those two lines' form has the read-only account's box too.
- **A VM used by its id** keeps `agent`.

### Said to the operator with these, and not objected to

- **The token form asks for an explicit pick** for each machine that has both accounts: not on
  this token, read-only, or read-write, with nothing chosen beforehand (order of work, step 6).

## Three questions found by the review before 0.3.0 (2026-11-20, procedure 068)

Found by the independent review of the build (procedure 068, section 12), and put to the operator
the same day, each with its options. Their choices are recorded as given.

### 9. What removing a machine does to an account that was there before nervus

Question 8 lets the person adding a machine name an existing account, their own included. When a
machine is removed, the Machines page showed commands that deleted every account nervus had recorded
there, home folder included. nervus could not tell which accounts its script had made.

- **a. "Take nervus's parts off" (Recommended).** For an account that was already there, only
  nervus's line and nervus's sudo file are removed, so the account and its home stay. Accounts
  nervus made are deleted as now. The script tells nervus which accounts it made, and nervus
  records it.
- b. "Delete it like the others".

**Decided: a.** What it comes to:
- Where nervus cannot tell, the account is treated as one that was there before, so nothing an
  owner made is deleted. That includes every account of a machine added before this release, and
  every account whose record says nothing.
- For an account that stays, the commands remove nervus's line and its sudo file, and nothing else:
  not its processes, and not what nervus's calls saved in its `~/.nervus`.

### 10. A machine this release added, reached by 0.2.2 after a rollback

0.2.2 does not know the record of a machine's accounts, so it logs in to every machine this release
added as `agent`. Normally no `agent` there trusts nervus, and nothing runs. The exception is a VM
nervus also uses by its id, where `agent` already has root by design (ADR-0022). Read-only tokens
are refused by 0.2.2 anyway ("Settled already").

- **a. "Accept it, and record it" (Recommended).**
- b. "Build a guard against it".

**Decided: a.** Nothing is built: this is a limit of rolling back to a release before this one.

### 11. When nervus's line comes off the old accounts, when a machine is added again under the new names

Question 8 takes nervus's line and its sudo line off the accounts nervus used on a machine before,
when the machine is added again under the new names. The script did that before nervus had checked
the new accounts. A re-add nervus then refused left the machine with no account nervus could use.

The question was first put in this record's terms. The operator asked: "I don't understand this
question please explain in more plain terms and what these lines are that you're talking about".
It was put again, a line being nervus's key to an account. The option they chose:

- **"Only after it passes" (Recommended).** The old accounts keep nervus's line until nervus has
  accepted the new ones, so a refused re-add leaves the machine as it was.

The other option was the order as built: the line comes off before nervus's check.

**Decided: only after it passes.** What it comes to: the script takes nervus's line, and its sudo
file, off the accounts nervus used there before only once nervus has answered that it added the
machine. Where nervus refuses, or cannot be reached, those accounts stay as they were.

## Two questions found while building the review's answers (2026-11-20, procedure 068)

### 12. What a refused add leaves, where question 11 does not reach

Question 11 keeps nervus's line on the accounts nervus used before, under other names, until nervus
has added the machine. Building it showed three cases it does not reach:
- **The same names.** Where the names stay, as when only the level changes, the accounts nervus used
  before are the new ones. Undo took nervus's line off them, and at full their sudo file, so a
  refused re-add left nervus no access there.
- **nervus's copy of bubblewrap**, where AppArmor needs it, is one copy for one group. The script
  made it again for the new read-only account before nervus checked that account, so a refused
  re-add under a new read-only name left the old read-only account unable to start its sandbox.
- **Accounts the refused run made** stayed, with no line of nervus's.

The question was first put in these terms. The operator answered: "I need more help with this
question because I don't think I quite understand whether you're presenting me with a problem or
whether you're just describing behavior like what's the decision I need to make here and try to
make it in terms of plain language your description I think was not descriptive enough". It was
put again as an example: a machine nervus uses at standard, added again at full, the add failing
near its end, and nervus locked out of a machine it could use a minute earlier. The options:

- **a. "Put it all back" (Recommended).** A failed add or re-add leaves the machine exactly as
  before it ran: nervus keeps whatever access it had, read-only keeps working, and accounts the
  failed run created are deleted.
- b. "Put back access only": as a, but accounts the failed run created stay.
- c. "Leave it as built".

**Decided: a.** What it comes to:
- Before it changes anything, the script notes nervus's lines on each account it will use, each
  one's sudo file, nervus's read-only shell, and the group of nervus's copy of bubblewrap. Where
  nervus refuses, or cannot be reached, it puts each back as it was, takes off what it put there
  new, and deletes the accounts it made.
- The packages it installed stay, as removal leaves them: they give no account any access.

### 13. The accounts nervus made, once a re-add has moved the machine to other names

Question 9 deletes, when a machine is removed, the accounts nervus made there, and only those. A
machine added again under other names kept in nervus's record only the accounts of its new names.
The old accounts nervus had made were forgotten, and after question 11 they stay on the machine
with no line of nervus's, so removing the machine would have left them.

- **a. "Remember them" (Recommended).** nervus keeps a record of every account it made on a
  machine until the machine is removed, and the removal commands delete those too. The operator
  runs those commands, so any line can be skipped.
- b. "Leave them, and record it".

**Decided: a.** What it comes to: the record keeps what nervus made on the same machine, by its
machine id, whatever names the machine has since. Another machine under the same name starts with
none, as question 9 has it.

## Four details, put to the operator with the model and recorded at their word

1. **Full stays.** A machine's read-write account is at standard or full, as its owner chooses
   today; a client assigned read-write gets that.
2. **A machine described by hand** gets the read-only account by a short documented step, run as
   root on it, tested as written (question 3a).
3. **A VM used by its id, and the `proxmox` tool,** are refused to a read-only assignment in the
   first version (question 2a).
4. **A machine where the sandbox cannot start,** for want of bubblewrap or because its AppArmor
   keeps programs from making user namespaces, needs for this account what a read-only machine
   needs today (ADR-0024 question 9).

## Settled already

- **Read-only can only lower.** The machine's level is still its owner's, enforced by the machine.
  On a machine enrolled read-only, every client is read-only.
- **A machine enrolled before this,** at standard or full, has no read-only account. It gains one
  as a change of level is made today: by being added again through its admin login (ADR-0026).
  Until then a read-only assignment there is refused, and nothing runs.
- **Fixed when issued**, as a token's machines are (ADR-0014 decision D): to give a client more,
  issue another token and revoke the first. Changing an assignment in place is not built by this
  record and not closed off. Only a token issued in the web UI can carry a read-only assignment;
  the token file's stay as they are.
- **An older release must refuse it, not widen it.** A token with any read-only assignment is kept
  in a table of its own. A release before this one does not know the table, so after a rollback it
  refuses the token as unknown. A column added to the issued tokens' table would be read by that
  release as a token without the limit, which is ADR-0014 decision F's hazard turned around.
- **Audited.** Issuing records each assignment, every record of a call carries the level it ran
  at, and the clients page shows it. The machine's own log names the account: `Accepted publickey
  for agent-readonly`.
- **How a client knows.** `hosts` gives, for each machine, the level this client has there. A write
  a command attempts is refused by the machine, as "Read-only file system"; a tool the client may
  not call there is refused by nervus in words.
- **nervus's scratch folder is its account's alone, at every level.** Today `~/.nervus` under a
  full or standard `agent` is made with the account's ordinary permissions, so on a machine whose
  home folders are open to other accounts, any of them can read what clients' calls saved there.
  A read-only client is such an account. nervus makes the folder its owner's alone whenever it
  uses it, as the read-only shell already does.

## What read-only means, said plainly

A client that is read-only on a machine cannot change its files, cannot use `sudo`, and reaches
nothing that only `agent`'s groups reach. It can read what any account on the machine can read, and
whatever its owner lets the read-only account read, such as the system's logs through their groups.
It can run programs, use the network from there, and write in its own `~/.nervus`, which is not
`agent`'s.

It does not see what takes privilege to see. Containers are the plain case: a container daemon's
socket has no look-only side, so the read-only account is not in its group and cannot list
containers or read their logs through it.

**Against the client, the machine enforces all of this. Against nervus itself it is nervus's
promise:** a nervus that was taken over could sign a certificate for `agent`. Only a machine
enrolled read-only stays read-only then (ADR-0007 decision 6, unchanged).

## Consequences

1. **One token can be read-only on one machine and read-write on another.**
2. **A machine that takes both has two accounts of nervus's**, the second made at enrollment.
3. **A read-only client sees less than `agent` does**, by the groups `agent` has and it has not.
4. **Enrollment changes at standard and full:** one more question, and a script that may make a
   second account. That is every such machine's script, so it has a trial of its own.
5. **For nervus:** a level for each client on each machine, carried to the certificate, and one
   place where the account is chosen, which every connection made for a client goes through.
6. **`nervus-ctl`** learns the second account, so that listing and stopping a client's jobs reaches
   a read-only client's.

## Order of work

Each step waits for the operator (rule 1), unless they say otherwise. When it starts is theirs.

1. **Tried on throwaway machines first, before any code**, since question 1 rests on it: as a
   member of a container daemon's group, inside the read-only sandbox, whether a command changes a
   file through the daemon; that `sudo` does nothing there; that a bare second account with the
   read-only line is refused the same; that a certificate naming it is refused for `agent`; that a
   certificate's forced command equal to the line's is admitted, and one alone is enforced.
2. The assignment: a level for each machine of a token, in the database, in a table of its own;
   issued, listed and revoked; on every record. An older release's own code refusing such a token,
   as ADR-0014 verification 5 did.
3. The connection: the level on the caller for that machine; the certificate naming the read-only
   account and carrying the shell; no plain key; the one place the account is chosen; a connection
   for a read-only caller that did not come through it refused. `~/.nervus` made its account's
   alone wherever nervus uses it.
4. The tools: what question 2 refuses, each with a record; `hosts`' answer.
5. Enrollment: the question, the second account made by the script, the machine recorded as having
   it; adding a machine again to gain it. For a machine described by hand, the Machines page's two
   lines, nervus's check and its record (question 4). A machine where no read-only account can be
   made, added read-write alone and saying so (question 5). The accounts named as question 8
   decides, from the form's boxes; a machine added before moved to them when it is added again.
6. The web UI: the choice for each machine when a token is issued, offered only where the machine
   has both accounts; the Machines page, the clients page and the audit page.
7. `nervus-ctl`: jobs under the read-only account listed and stopped.
8. `docs/clients.md` and `docs/install.md`, the hand block run as written; `CHANGES.md`.
9. A trial on throwaway machines of the whole, then the deploy, each a procedure for approval.
10. On the first installation: the account on the machines the operator names, by a procedure, and
    the token issued.

Every step with tests, each guarantee broken on purpose and seen caught.

## Verification

1. A client read-only on a machine at full whose `agent` belongs to a container daemon's group:
   a write outside `~/.nervus` is refused by the machine, `sudo` is refused, and the daemon's
   socket is refused; `exec`, `exec_bg`, `job`, `get` and `export` work.
2. That client cannot be made to log in as the read-write account there: a certificate signed for
   a read-only call is refused at that account by the machine, and nervus signs no other for it.
3. One token, read-only on one machine and read-write on another: each call runs under the account
   its assignment names, and the record of each says which.
4. `put`, an upload, and on a hypervisor machine the `proxmox` tool and a VM by its id, are refused
   to a read-only assignment by nervus, each with a record and its reason; another client on the
   same machine is unchanged.
5. A machine enrolled with both has both accounts and is offered with the choice when a token is
   issued; one enrolled read-only has one and offers none. On a machine with no read-only account,
   a read-only call is refused, nothing runs, and the client is told how its owner adds one.
6. `hosts` tells a client its level on each machine. The clients page and every audit record of
   its calls say so. The machine's own log names the read-only account and the client.
7. A release before this one, given the database, refuses a token with a read-only assignment as
   unknown.
8. A read-only client cannot read or write what another account's calls saved in `~/.nervus`, and
   cannot signal that account's jobs.
9. `nervus-ctl` lists a read-only client's running job and stops it.
10. An add nervus refuses leaves the machine as it was (questions 11 and 12): after a refused re-add
    under the same names, and after one under new names, every call that worked before still works,
    read-only included where AppArmor needs nervus's copy of bubblewrap; an account that was there
    before keeps its own keys; and the accounts the refused run made are gone.
11. Removing a machine deletes the accounts nervus made there, those of names it had before
    included, and no other; an account that was there before nervus keeps itself, its home and its
    own keys, and loses nervus's line and sudo file (questions 9 and 13).
