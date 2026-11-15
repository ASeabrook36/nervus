# ADR-0025: the machine records which client acted, by a certificate nervus signs for each call

**Status:** **Decided by the operator on 2026-10-21**, in a Claude Code session: the direction
first (see "Decided already"), then questions 1 to 3, each as the drafting session recommended
("ADR-0025: questions 1 to 3, all as recommended"). Each question keeps its options, so the record
shows what was not chosen. **Accepted 2026-10-28, at the operator's word** ("ADR-0025 Accepted"),
every verification item observed: on throwaway machines (procedure 042), at the deploy (procedure
043) and on the first installation's machines (procedure 044). Built 2026-10-27, deployed and on
every machine 2026-10-28 (see "Order of work"). One question the record did not answer, what a
certificate names when no client asked, decided by the operator on 2026-10-27 (step 3). ADR-0001 s4
and s5 and ADR-0007 decisions 6 and 8 amended as below says.
**Date:** 2026-10-21
**Asked for by:** the operator: "ideally we'd want the host to be able to identify which client or
agent took activity on it, even if it's just logs... without multiple accounts on the host"; and,
for the threat model, to be clear "that the logs of which agent did that exist on nervus... are
very secure, and that agents can't mess with those on nervus or how they're logged elsewhere. We
can't assume people will do the second."
**Builds on:** ADR-0001 s4, s5 and s10 (one `agent` account, one key; attribution from the audit
log; an intent record before every call); ADR-0003 (the off switch); ADR-0005 decision 5 and
ADR-0024 decision 1 (each level enforced by a forced command on the machine); ADR-0007 decisions 6
to 9 (the threat model); ADR-0009 decision 4 (a copy of the audit log where a full level cannot
reach); ADR-0022 decision 3 and ADR-0024 decision 2 (what enrollment writes on the machine);
ADR-0023 question 4 and ADR-0024 decision 6 (never root for nervus on its own machine).
**Amends, now Accepted:** ADR-0001 s4 ("`authorized_keys` contains exactly one key, `nervus`'s")
and s5 (the separate `agent` user "provides attribution in host journals"); ADR-0007 decisions 6
and 8, as decision 5 below says.
**Written to the policy of ADR-0019:** this record names no system.

## Context

### What a machine records today

Read off a full-level machine through nervus on 2026-10-21. Every call nervus makes logs in that
machine's `sshd` journal as one line:

```
Accepted publickey for agent from <nervus's address> port <port> ssh2: ED25519 SHA256:<nervus's key>
```

The account, the address and the key are the same for every client. The session's environment
carries nothing about the client, and `authorized_keys` holds one line, nervus's key. So the machine
cannot tell clients apart; only nervus's audit log can (ADR-0003 decision 4 says the same). The one
thing that differs per call is the port nervus connected from: the two calls read differed, so
nervus appears to open one connection per call, though two calls do not prove it never reuses one.

### Why a label the machine's own commands could write is not enough

`agent` has `sudo` at the full level, so anything nervus runs there can write any text into the
journal, and edit or delete the journal afterwards. The journal stamps each line with the real
process and account, but not the truth of its text. A line nervus has a command write is a
convenience; it proves nothing against a client that wants to blame another.

A line the machine's SSH server writes, at login, before any command runs, cannot be written by the
command. That is the line to put the client in.

### SSH certificates

OpenSSH lets an account trust a certificate authority instead of a key: one line in
`authorized_keys`,

```
cert-authority,<the level's options> ssh-ed25519 <nervus's CA public key>
```

and any key carrying a certificate that authority signed, naming `agent`, logs in. A certificate
carries a free-text **key ID**, a **serial number**, and a **validity window**, and `sshd` logs the
key ID and serial when it accepts one (from OpenSSH's documented behaviour; seen on 2026-10-27 from
a real OpenSSH `sshd` in step 1's tests, and on a machine at the trial):

```
Accepted publickey for agent from ... port ... ssh2: ED25519-CERT SHA256:... ID <key ID> (serial <n>) CA ED25519 SHA256:<CA>
```

So if nervus signs a short-lived certificate for each call, with the client and the run in its key
ID, the machine writes the client into its own journal, in a line no command can forge, with one
account and no change on the machine when a client is added or removed. This is common practice
for fleets (an SSH CA issuing short certificates), not something nervus invents.

Two facts make it fit what is built:
- **It changes only the `authorized_keys` line enrollment already writes.** No `sshd_config` edit
  and no reload: `cert-authority` is an `authorized_keys` option, as `restrict` and `command=` are.
- **The level's forced command stays on the machine.** The read-only level's `command=` stays in
  that line. OpenSSH refuses a login when a certificate's own forced command and the line's
  disagree (from its source; seen on 2026-10-27 from a real `sshd` in step 1's tests, which logs
  "forced command options do not match"), and nervus never puts one in a certificate, so a
  compromised nervus still cannot lift read-only (ADR-0007 decision 6).

### What a compromised nervus gains

Nothing new. Whoever holds the CA key can sign any certificate, exactly as whoever holds today's key
can log in anywhere it is trusted. The certificate makes a forged attribution need nervus itself,
rather than any client with `sudo`; that is the property the operator asked for.

## Decided already

Decided by the operator on 2026-10-21, after the options were laid out in the session: "I'm fine
with the changes being certificates, the host side label, the port correlation, the validity window,
the enrollment flow change, the CA key, and we need to just be clear about the threat model".

1. **A certificate for every SSH connection nervus makes**, signed by a CA key nervus holds, valid
   for a short window, naming `agent`, its key ID carrying the token id and the run id, both
   nervus-made and of a fixed alphabet, so a client cannot put text of its own into a machine's
   log. No forced command and no extra permissions in the certificate: what a machine allows stays
   in its own `authorized_keys`.
2. **A label line too:** `exec` and `exec_bg` start with
   `logger -t nervus "token=<id> run=<run>"`, so a reader of the journal sees the client beside the
   command's own lines. A convenience, forgeable as the Context says; the certificate line is the
   one that counts. The audit record keeps the command as the client sent it, without the label.
3. **The port in the audit record:** each record of a call over SSH carries the local port nervus
   connected from, so a journal line can be matched to a record even on a machine not yet moved to
   certificates.
4. **Enrollment writes the CA line instead of the key line**, for hosts (ADR-0024 decision 2) and
   VMs (ADR-0022 decision 3), each level's options unchanged.
   *Amended 2026-10-28, decided by the operator:* and for a hypervisor host's two accounts (ADR-0009
   decisions 1 to 3), set up by the tool made for them: the same line, with no options.
5. **The threat model says plainly what protects the record of which client did what**, and that it
   holds with nothing configured elsewhere. Wording for ADR-0007:
   - **nervus's audit log is the record, and it is out of every client's reach.** The intent record
     is written before anything reaches a machine (ADR-0001 s10), so a command cannot remove the
     record of itself, an attempt to tamper with logs included. No MCP tool reads or writes it
     (ADR-0005 s4, ADR-0007 decision 8). No client reaches nervus's own machine as root
     (ADR-0024 decision 6), and read-only or standard there cannot read the log's folder.
   - **This needs no copy anywhere.** A copy elsewhere (ADR-0009 decision 4, ADR-0007 decision 8's
     forwarding) defends against root on nervus's machine, a compromised nervus or its operator,
     not against clients. Many people will never set one up, and nervus must not lean on it.
   - **Where a copy exists, no client may reach it** (ADR-0009 decision 4 already requires this:
     pulled, not pushed, by a key that can only read). The docs say that a copy on a machine
     enrolled at full access is not a copy.
   - **A machine's own journal is a second witness, not a protected one.** Its certificate line is
     written by the machine and names the client, but a client with full access there can edit the
     journal afterwards. nervus does not manage machines' logs; forwarding them is the machine
     owner's choice, outside nervus.

## Not chosen

Raised in the same session and set aside by the operator:
- **One key per client**, each in every machine's `authorized_keys`: every client added or removed
  would be a change on every machine. "My bigger issue would be the requirement to change something
  on every host every single time a client program was added or removed."
- **One account per client** on each machine: the same cost, and more of it.
- **Forwarding machines' logs, and watching them for tampering (`auditd` rules, a cutoff through
  ADR-0003's switch):** host management, which nervus is not. "Setting up some sort of remote logging
  system from the host is really scope creep." It is standard practice, and the owner's to choose.
- **Refusing commands that look like log tampering:** a shell with `sudo` can disguise any command,
  so a filter on command text would stop only careless clients and break real work, which is why
  ADR-0001 s5 performs no command filtering. Unchanged.

## Questions

### 1. Which key nervus presents with the certificate

- **a. nervus's existing key, with a new CA key signing a certificate for it at each connection.**
  A machine not yet moved still accepts the bare key, so every machine works throughout the move;
  once all are moved, the bare-key lines are gone and the key alone opens nothing.
- b. The CA key only, and a fresh key made in memory for each connection, never on disk. One secret
  fewer in the end, but every machine must move at once, or nervus keeps the old key for the
  stragglers anyway.

*Recommended: a.* **Decided 2026-10-21: a.** The move is machine by machine (consequence 4); a now, b later as a small change
if wanted. The CA key is made where nervus's key is, by the installer (ADR-0023), kept as it is
(`0600`, read-only to nervus), and like it has no export path (ADR-0007 decision 7).

### 2. The validity window

- **a. From five minutes before signing to five minutes after.** OpenSSH checks the window only at
  login, so a long command or transfer is unaffected; the five minutes before allow for a machine
  whose clock is behind. A refused login says the machine's clock is a likely cause.
- b. One minute either side. Tighter, and a machine a minute out refuses nervus.
- c. An hour, reused across calls. Fewer signatures, but the run id could no longer be in it.

*Recommended: a.* **Decided 2026-10-21: a.** A certificate is useless to anyone once its window passes, and the window must be
per call for the run id to be in the journal.

### 3. A machine underneath nervus

Decision 5's first point holds only if no client has root over nervus's machine. ADR-0024
decision 6 refuses full access to the machine nervus runs on, but checks its machine id, and a
hypervisor or container host under nervus has another. A client with full access there, or a
hypervisor API that reaches nervus's own guest, can stop nervus and rewrite its disk, the log
included. ADR-0009 decision 4 met this for one installation with a copy first; that is the copy
people cannot be assumed to make.

- **a. Say it, everywhere the guarantee is stated, and ask at the moment it matters:** the README's
  non-goals, `docs/install.md` where it says where nervus may run, and the Machines page when full
  access is chosen ("Does nervus run on this machine, as a VM or container? Then a client given full
  access here can rewrite nervus's audit log"). A hypervisor connection is set up by hand, and its
  docs say to exclude nervus's own guest, as ADR-0009 does.
- b. As a, and nervus refuses full access where it can tell it is a guest of that machine (for
  example, nervus's address among the machine's guests). Not reliable across hypervisors; a
  refusal that misses cases may be trusted more than it deserves.
- c. Leave it to ADR-0009's pattern: a copy required first. Not something nervus can enforce on a
  friend's machine.

*Recommended: a.* **Decided 2026-10-21: a.** It is the one honest statement nervus can make everywhere, and it asks at the
point where the person can still choose otherwise.

## Consequences

1. **For someone reading a machine's journal:** each nervus login names the token and the run,
   written by the machine; the run finds the call in nervus's audit log.
2. **For enrolling:** the same two lines and the same guest-agent step, writing a different line.
   No step per client, ever.
3. **For nervus:** a second key to make and keep; signing at each connection; the label and the
   port in `exec`, `exec_bg` and the audit record.
4. **For machines already given nervus's key** (described by hand in `hosts.yaml`, or enrolled
   before this): they keep working with the bare key until moved, and their journal names no client
   until then. Moving one is re-enrolling it, or one line changed by hand, given in
   `docs/install.md`; an installation's own machines are moved by a deployment procedure.
5. **For the docs:** decision 5's wording in the README's non-goals, and question 3's where it
   lands.

## Order of work

Each step waits for the operator (rule 1). Placed by the operator on 2026-10-21: after ADR-0015's
deploy procedure, before the next preview export.

0. ~~The operator's decisions on questions 1 to 3.~~ Done 2026-10-21: all as recommended.
1. ~~The CA key: made by the installer, read at start-up; nervus signs a certificate per connection,
   key ID and validity as decided; the port in the audit record. With tests, a real `sshd` included.~~
   **Done 2026-10-27.** First read through nervus off a full-level throwaway VM: every nervus login
   the same line, account, address and key, the port alone differing, as Context says. Built:
   - **The CA key** is `--ssh-ca-key`, by default `secrets/nervus_ca_ed25519`, made by the installer
     with `ssh-keygen` beside nervus's key (and by the hand steps in `docs/install.md`). nervus reads
     it once at start and refuses to start without it, or with it readable by others, as it does
     for its key.
   - **The certificate** (`nervus.certs`), signed at each connection made on a client's call: key ID
     `token=<id> run=<run>`, the run being the intent record's id; principal the target's account;
     valid five minutes either side of signing; a random serial; no forced command, no extensions
     (nervus runs commands and SFTP only, which need none). A token id outside letters, digits,
     `.`, `_` and `-` is percent-encoded, since the token file's ids are checked by nothing.
     nervus's plain key is offered after the certificate, so a machine not yet moved works as before.
   - **The call** is set once per call, after its intent record, and carried into the work it starts
     (an export's copy, an upload's delivery), so those connections name it too.
   - **The port:** the result records of `exec`, `exec_bg`, `job`, `put`, `get`, `export` and an
     upload's delivery carry `ssh_ports`, the local port of each SSH connection the call made, in order
     (more than one when a VM was enrolled on the way).
   - **Tests** (`tests/test_certs.py`), against a real OpenSSH `sshd` run as the testing account: the
     journal line names the token and the run, and its port is the recorded one (verification 1);
     two tokens appear under their own names (2); a `restrict,command=` line runs its own command for
     a certificate without one, and refuses one with another (4); a certificate past its window is
     refused (5, first half); a bare-key line still accepts nervus, its port matching (6); and an
     `exec` through nervus end to end. `ssh-keygen -L` reads the certificate's fields.
   - **Not signed yet**, having no client's call to name: enrollment's own SSH check (step 3), and
     `nervus-ctl`'s listing and killing of jobs, and the clean-up of uploads a restart interrupted.
     These offer the plain key, as before; what their key ID should name is for the operator
     (decided at step 3).
2. ~~The label line in `exec` and `exec_bg`, kept out of the audit record's command.~~
   **Done 2026-10-27.** Each script `exec` and `exec_bg` send now starts with
   `logger -t nervus -- 'token=<id> run=<run>' >/dev/null 2>&1 || true`, the certificate's key ID
   word for word; for `exec_bg` it runs as the job starts, beside the tmux session. Its output and
   failure are discarded, so a machine without `logger`, or a sandbox it cannot log from, runs the
   command as before, with the command's own exit code and output. The audit record's `command` is
   still what the client sent. Outside a client's call there is no label. Tested with a stand-in
   `logger` that records its arguments (`tests/test_certs.py`), since a test cannot read this
   machine's system log back: the label names the token and the intent record's run, for `exec` and
   for `exec_bg`'s job; a `logger` that fails changes neither output nor exit code. The real journal,
   and `logger` inside the read-only sandbox, are the trial's (step 5).
3. ~~Enrollment for hosts and VMs writes the CA line; nervus's SSH check after enrolling uses the
   certificate.~~ **Done 2026-10-27.**
   - **A question this record did not answer**, raised before building (rule 6): the check after a
     machine added from nervus's page reports back is made for no client, so what does its
     certificate name? **Decided by the operator on 2026-10-27:** `operator run=<record>`, the
     record being that report's audit record, which already says `actor: operator`. A client's key
     ID always begins `token=`, so the two cannot be confused. The same form is to serve
     `nervus-ctl` and the clean-up after a restart when they are signed.
   - **What enrollment writes:** nervus hands the scripts its CA's public key (`<type> <key>
     nervus-ca`) where it handed its own. The host script writes `cert-authority,restrict,command=
     "…/readonly-shell" <CA>` at read-only and `cert-authority <CA>` at standard and full, each
     level's options as before; the VM script writes `cert-authority <CA>`. A machine so enrolled
     admits only certificates nervus signs, never nervus's plain key.
   - **The check:** after a machine's report, under that report's audit record, signed as
     `operator`; its result record carries `ssh_ports`. A VM is enrolled during a client's call, so
     its check names that client and run, as step 1 made it.
   - **Tests:** the host script, run for read-only and standard, writes a line that a real OpenSSH
     `sshd` reads as written (the read-only shell's path pointed at a stand-in): it admits nervus's
     certificate, logs `ID operator run=<run>`, runs the level's command, and refuses the plain key
     (`tests/test_certs.py`). The report's check signs as the operator under its own record, its
     port recorded (`tests/test_host_enrollment_route.py`). The VM tests' stand-in machines now read
     `cert-authority` lines as `sshd` does, and enroll inside a client's call.
   - **Consequence, until those are signed:** on a machine enrolled this way, the clean-up of an
     upload a restart interrupted is refused, so its temporary file, named as nervus's, stays.
     `nervus-ctl` reaches only the machines `hosts.yaml` describes, which keep the bare key until
     moved. **Both signed the same day, at the operator's word (3a, below).**
3a. **Done 2026-10-27, asked for by the operator before step 4:** what no client asks for is
   signed too, so nothing nervus does still needs the plain key.
   - **The clean-up after a restart:** each interrupted upload's clean-up writes its own intent
     record (`tool: upload`, `actor: operator`, `action: cleanup`, the upload's id), logs in signed
     `operator run=<that record>`, and writes a result carrying `ssh_ports`. If the record cannot
     be written, that upload's machine is not asked.
   - **`nervus-ctl`:** it reads the CA key from nervus's unit (`--ssh-ca-key`). Listing jobs, for
     `status` and for `lock --kill-work`, first writes an operator record `list_jobs`, naming the
     machines it asks; its logins are signed for that record. **The operator chose on 2026-10-27**
     that `status` write this record, though it had written nothing before; the other choice left
     `status` unable to list jobs on a machine enrolled with the CA. If the record cannot be written,
     `status` still shows the switches and says no machine was asked. Killing jobs is signed for the
     `lock` record that asked for it; the `kill_work` record carries `ssh_ports`.
   - **Tests:** against a real `sshd` whose line admits nervus's CA alone, `nervus-ctl lock --all
     --kill-work` lists and kills, and the machine logs `ID operator run=` the `list_jobs` record,
     then the `lock` record; the plain key is refused there. The clean-up removes the leftover on
     such a machine, logging `ID operator run=` its own record, whose result has that login's port.
     Without a record, no clean-up connects; `status` without one asks no machine
     (`tests/test_certs.py`, `tests/test_ctl.py`).
4. ~~ADR-0007's wording (decision 5), the README, `docs/install.md` (moving a machine; question 3).~~
   **Done 2026-10-27.**
   - **ADR-0007:** amended in its header and in decisions 6 and 8 with decision 5's wording and
     question 3's exception, "Not deployed yet". ADR-0001 s4 and s5 are amended when this record
     is Accepted, as its header says.
   - **Question 3a, everywhere the guarantee is stated:** the public README's non-goals and the
     setup page's (one list, checked to match) gain "A client with full access to the machine
     underneath nervus"; the README says what keeps the record of which client did what, and that
     it needs no copy; `docs/install.md`'s "Where nervus may run" and its hypervisor section say
     the same; and the Machines page's full-access choice asks "Does nervus run on this machine, as
     a VM or container? Then a client given full access here can rewrite nervus's audit log."
   - **Moving a machine** (consequence 4), in `docs/install.md`: a machine from the Machines page
     is added again under its name at the same level; any other has its line replaced by hand, at
     standard or full `cert-authority <CA>`, at read-only with the read-only shell's options kept.
     "By hand: a machine nervus reaches" now writes the CA line, and its check signs a certificate
     for five minutes in a folder of its own (key ID `operator check-by-hand`, no audit record:
     nervus makes no call), and the plain key must be refused.
   - **Tests:** the docs' own move lines and check, run against a real `sshd` as written but for
     paths, port and account: the certificate logs in and is logged, the read-only line runs its
     own command, and the plain key is refused (`tests/test_certs.py`); the Machines page asks its
     question (`tests/test_ui_machines.py`).
5. A trial on throwaway machines, each level: the journal line's form; a certificate's forced
   command against the line's; a clock out by more than the window; a machine still on the bare
   key; the label inside the read-only sandbox. Then a deploy procedure, and one to move this
   installation's machines, each for approval.
   **Written 2026-10-27, not run:** procedures 042 (the trial), 043 (the deploy; the deploy tool
   now refuses a release that names the CA key where the key is missing) and 044 (moving the
   machines, each through both lines before the key's is removed). **Procedure 042 done
   2026-10-28:** every verification item below observed on throwaway machines (Debian 13, OpenSSH
   10.0p2) through a throwaway nervus installed from this branch, item 7 by search; four findings,
   none blocking, recorded there. **Procedure 043 done 2026-10-28** (deployed; it found the deploy
   tool's new check skipping itself, fixed the same day) and **procedure 044 done 2026-10-28**: every
   machine of this installation trusts nervus's CA alone. Every verification item is observed;
   Accepted at the operator's word. Whether the tool that sets up
   a hypervisor host's accounts should write the CA line too was not answered here; raised with the
   operator. **Decided by the operator on 2026-10-28: yes** ("yes, change it"), decision 4 below
   amended. Built the same day: the tool writes `cert-authority <CA>` for both accounts, asks for
   the CA's fingerprint in place of nervus's key's, stops on a nervus with no CA, and checks its
   work with a certificate signed for five minutes as the operator's, then checks nervus's key
   alone is refused. Not yet run anywhere: this installation's hypervisor was moved by procedure
   044.

## Verification

1. A call through nervus to an enrolled machine logs, in that machine's `sshd` journal, a
   certificate login whose key ID names the calling token and the run, and the run is the audit
   record's.
2. Two clients calling the same machine appear in its journal under their own token ids.
3. Adding or removing a client changes nothing on any machine.
4. A read-only machine stays read-only with a certificate that carries no forced command, and
   refuses one that carries a different one.
5. A certificate past its window is refused; a machine whose clock is four minutes behind accepts
   one.
6. A machine still on the bare key works, and its audit records carry the port that matches its
   journal line.
7. The CA key is readable by no MCP tool, UI page or transfer path (ADR-0007 verification 5).
8. A command's own `logger` line naming another token appears in the journal, and the certificate
   line beside it names the true one.
