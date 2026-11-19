# ADR-0031: a token can be read-only, through a second account the machine keeps read-only

**Status:** **Proposed 2026-11-19.** Not decided, nothing built, and nothing here yet tried on a
machine: the drafting session's connection to nervus was refused, so its Context rests on the
code, on earlier procedures and on OpenSSH's, Docker's and the kernel's documented behaviour, each
marked where it stands. Step 1 of the order of work tries it before any code. Questions 1 to 3 are
the operator's; each keeps its options, so the record shows what was not chosen.
**Date:** 2026-11-19
**Asked for by:** the operator, on 2026-11-19, of the first token for a client still being built:
it "is going to be read-only at the nervus level". Such a client should look and not change on
machines other clients work on, and be given more later by one act of the operator's.
**Builds on:** ADR-0001 s4 to s6 (one `agent` account; the boundary is SSH's; a token is an
allowlist); ADR-0005 decision 5 and ADR-0024 decision 1 (levels, each enforced by the machine;
read-only by a forced command and the kernel); ADR-0007 decisions 5 and 6 (a client's credential
"carries an allowlist and a level"; a compromised nervus is total, and read-only machines stay
read-only); ADR-0009 decision 1 (one machine as two entries, behind two accounts); ADR-0014
(tokens issued in the web UI; decision F, changing the database without breaking a rollback);
ADR-0025 (a certificate nervus signs for each connection, naming the account).
**Written to the policy of ADR-0019:** this record names no system.

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

### 1. What makes a token read-only on a machine whose own level is higher

- **a. A second account on the machine, `agent-readonly`, set up as a read-only machine's `agent`
  is: no `sudo`, no group that reaches a service able to change the machine, and the read-only line
  in its `authorized_keys`. For a read-only token nervus signs only a certificate that names that
  account and carries the read-only shell as its forced command, and offers no plain key.** The
  machine's SSH server admits it to that account alone and runs that shell; the kernel keeps every
  file read-only inside it. On a machine that is itself read-only, `agent` is already such an
  account and is used as it is, so nothing is added there. A machine with no such account refuses
  the login, and nervus tells the client so: nothing runs.
- b. The same account, the certificate forcing the read-only shell. No second account. Not
  read-only where `agent` reaches a privileged service, and it shares `agent`'s scratch folder and
  processes with tokens that can change the machine (Context).
- c. No level on a token. A second inventory entry for each machine, written by hand and naming a
  second account, as the hypervisor host has; a "read-only token" is then one whose allowlist
  names only such entries. It needs no code. It needs the same account on the machine as a, two
  names for each machine, a restart of nervus for each entry, and care when a token is issued:
  ticking the wrong one of a machine's two names gives it everything.
- d. nervus refusing commands that write. ADR-0001 s5 rejected filtering commands: a shell cannot
  be told to only read.

*Recommended: a.* The machine still does the enforcing, with the mechanism ADR-0024 already
proved, on an account that has nothing to misuse. A token carries the property, so a client
cannot be given more by a slip of the hand, and a machine keeps one name. The account is made once
for each machine, whoever the clients are; this is not the account for each client that ADR-0025
set aside.

The forced command in the certificate is a second lock on the same door: if the account's line
were written without it, the sandbox would still be forced, and if the shell is missing nothing
runs. It cannot lift a machine's own read-only line, since OpenSSH admits a certificate whose
command differs from the line's to nothing.

### 2. What a read-only token may call

- **a. `hosts`, `exec`, `exec_bg`, `job`, `get`, `export` and its download work. `put` and uploads
  are refused by nervus before anything is sent, saying the token is read-only. The `proxmox` tool
  and a VM named by its id are refused too, saying why.** The hypervisor's API is one credential of
  nervus's for every client, with no look-only half; and a VM nervus enrolls has one account, with
  `sudo`.
- b. As a, and the `proxmox` tool for `GET` requests only. A filter nervus keeps on another
  program's API, where some reads are privileged ones: a file read as root inside any VM, through
  its guest agent.
- c. As a, and a second, look-only credential at the hypervisor, in its own auditor role, chosen
  by the token as the account is. The same shape as 1a, enforced by the hypervisor. More to set
  up; a later step if a read-only client needs to see VMs.

*Recommended: a* now, and c later if it is wanted. A read-only token on a hypervisor host still
has the read-only account's shell there: processes, disks and logs.

### 3. How a machine gets the account, in the first version

- **a. By hand, as root on the machine: a short block in `docs/install.md`, tested as written, for
  a machine where bubblewrap starts as installed.** A machine without the account is not reached by
  a read-only token, and nervus says how to add one. The Machines page and the enrollment script
  learn to make the account in a later step, with a trial of its own, since that changes what
  every level's script does on a machine, and a machine whose AppArmor keeps programs from making
  user namespaces needs ADR-0024 question 9's files made for this account.
- b. The enrollment script makes it at standard and full from the start.
- c. nervus makes it itself over the full access it has. Possible only at full, and it is nervus
  changing a machine's accounts from afar, which ADR-0024 decision 5 left to the person at the
  machine.

*Recommended: a.* It delivers a read-only token on machines described by hand, which is every
machine other clients already share on the first installation, without touching enrollment. b is
the natural next step and is not closed off.

## Settled already

- **A token's read-only can only lower.** The machine's level is still its owner's, enforced by the
  machine. On a read-only machine a read-only token changes nothing.
- **Fixed when issued**, as a token's hosts are (ADR-0014 decision D): to give a client more, issue
  another token and revoke the first. Only a token issued in the web UI can be read-only; the token
  file's stay as they are.
- **An older release must refuse it, not widen it.** A read-only token is kept in a table of its
  own. A release before this one does not know the table, so after a rollback it refuses the token
  as unknown. A column added to the issued tokens' table would be read by that release as a token
  without the limit, which is ADR-0014 decision F's hazard turned around.
- **Audited.** Issuing records it, every record of the token's calls carries it, and the clients
  page shows it. The machine's own log names the account: `Accepted publickey for agent-readonly`.
- **How a client knows.** `hosts` says the token is read-only and gives each machine's level as
  read-only. A write a command attempts is refused by the machine, as "Read-only file system"; a
  tool the token may not call is refused by nervus in words.
- **nervus's scratch folder is its account's alone, at every level.** Today `~/.nervus` under a
  full or standard `agent` is made with the account's ordinary permissions, so on a machine whose
  home folders are open to other accounts, any of them can read what clients' calls saved there.
  A read-only client is such an account. nervus makes the folder its owner's alone whenever it
  uses it, as the read-only shell already does.

## What read-only means, said plainly

A read-only token cannot change a machine's files, cannot use `sudo`, and reaches nothing that
only `agent`'s groups reach. It can read what any account on the machine can read, and whatever
its owner lets the read-only account read, such as the system's logs through their groups. It can
run programs, use the network from there, and write in its own `~/.nervus`, which is not `agent`'s.

It does not see what takes privilege to see. Containers are the plain case: a container daemon's
socket has no look-only side, so the read-only account is not in its group and cannot list
containers or read their logs through it.

**Against the client, the machine enforces all of this. Against nervus itself it is nervus's
promise:** a nervus that was taken over could sign a certificate for `agent`. Only a machine
enrolled read-only stays read-only then (ADR-0007 decision 6, unchanged).

## Consequences

1. **One token cannot be read-only on one machine and more on another.** That takes two tokens.
2. **A machine that takes read-only tokens has two accounts of nervus's**, the second made once.
3. **A read-only client sees less than `agent` does**, by the groups `agent` has and it has not.
4. **For nervus:** a level on the caller, carried from the token to the certificate, and one place
   where the account is chosen, which every connection made for a client goes through.
5. **`nervus-ctl`** learns the second account, so that listing and stopping a client's jobs reaches
   a read-only client's.

## Order of work

Each step waits for the operator (rule 1), unless they say otherwise.

0. The operator's decisions on 1 to 3.
1. **Tried on throwaway machines first, before any code**, since it decides question 1: as a member
   of a container daemon's group, inside the read-only sandbox, whether a command changes a file
   through the daemon; that `sudo` does nothing there; that a bare second account with the
   read-only line is refused the same; that a certificate naming it is refused for `agent`; that a
   certificate's forced command equal to the line's is admitted, and one alone is enforced.
2. The token: read-only in the database, in a table of its own; issued, listed and revoked; on
   every record. An older release's own code refusing it, as ADR-0014 verification 5 did.
3. The connection: read-only on the caller; the certificate naming the read-only account and
   carrying the shell; no plain key; the one place the account is chosen; a connection for a
   read-only caller that did not come through it refused. `~/.nervus` made its account's alone
   wherever nervus uses it.
4. The tools: what question 2 refuses, each with a record; `hosts`' answer.
5. The web UI: the box when a token is issued; the clients page; the audit page.
6. `nervus-ctl`: jobs under the read-only account listed and stopped.
7. `docs/clients.md` and `docs/install.md`, the hand block run as written; `CHANGES.md`.
8. A trial on throwaway machines of the whole, then the deploy, each a procedure for approval.
9. On the first installation: the account on the machines the operator names, by a procedure, and
   the token issued.

Every step with tests, each guarantee broken on purpose and seen caught.

## Verification

1. A read-only token, on a machine at full whose `agent` belongs to a container daemon's group:
   a write outside `~/.nervus` is refused by the machine, `sudo` is refused, and the daemon's
   socket is refused; `exec`, `exec_bg`, `job`, `get` and `export` work.
2. The same token cannot be made to log in as `agent`: a certificate signed for a read-only caller
   is refused there by the machine, and nervus signs no other for it.
3. `put`, an upload, the `proxmox` tool and a VM by its id are refused to it by nervus, each with
   a record and its reason; another token on the same machine is unchanged.
4. On a machine with no read-only account, its call is refused, nothing runs, and the client is
   told how the machine's owner adds one. On a read-only machine it works as any token does.
5. `hosts` tells a read-only token that it is one. The clients page and every audit record of its
   calls say so. The machine's own log names the read-only account and the client.
6. A release before this one, given the database, refuses a read-only token as unknown.
7. A read-only token cannot read or write what another account's calls saved in `~/.nervus`, and
   cannot signal that account's jobs.
8. `nervus-ctl` lists a read-only client's running job and stops it.
