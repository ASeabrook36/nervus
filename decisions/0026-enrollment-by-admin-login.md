# ADR-0026: adding a machine from nervus's page, with an admin login its owner gives once

**Status:** **Accepted 2026-10-24, at the operator's word** ("mark ADR-0015 and ADR-0026 Accepted"):
verification items 1 to 11 observed by procedure 040 on throwaway machines, but plain HTTP, which the
tests show; 1, 4 and 9 again on the installation procedure 041 deployed it to. Its amendments to
ADR-0024 and ADR-0007 are in force. **Decided by the operator on 2026-10-22**, in a Claude Code session, the day it was
drafted: questions 1 to 6, each as the drafting session recommended ("Accepted 1-6 as
recommended"). Each question keeps its options, so the record shows what was not chosen.
**Questions 7 and 8 added 2026-10-23**, raised while building steps 3 and 4, and **decided by the operator the
same day, each as recommended** ("Ask again", "Same 'another key' words"). **Question 9 added 2026-10-24**, found
by procedure 040's trial, and **decided by the operator the same day, as recommended** ("Prefer ed25519"). Every
step of the order of work done; deployed 2026-10-24 (procedure 041).
**Date:** 2026-10-22
**Asked for by:** the operator, 2026-10-22: from nervus's web page, give a machine's "IP address or
the host name … and nervus would just reach out to that machine and attempt to make a connection
over SSH … if the host challenges them for a login, they could supply credentials with root access
and then nervus takes over … and we obviously wouldn't store them", with "a little loading box"
while it works and the machine then in the list; the level chosen at the start, or asked for if it
was not; the two lines kept as an advanced way; and this "the way that we enroll stuff by default".
**Builds on:** ADR-0024, all of it (the levels, the script, the route, the check, the store,
question 8); ADR-0022 decision 3 (a VM made ready as root through a channel nervus trusts for that
moment, the guest agent); ADR-0005 decisions 2 and 5 (agentless push; each level enforced by the
machine); ADR-0007 decisions 3, 6, 7 and 10; ADR-0012 (the UI's form token and origin check; no
script runs on its pages); ADR-0025 decision 4 (what the script writes, changed in one place).
**Amends, once Accepted:** ADR-0024 decision 2 and consequence 1 (the two lines become the advanced
way, no longer the only one); ADR-0007 decision 3, for the moment of first contact only
(question 2).
**Prior art:** `ssh-copy-id`, which logs in with a password, trusting the machine's host key on
first use, and installs a key. Cockpit's web console, whose release 235 notes say its login page
explains an unknown host key and how to check it (from a search's summary of those notes; the page
itself could not be fetched). `research/2026-10-15-prior-art.md` idea 4 refuses borrowing the
owner's own keys; this ADR borrows none (question 3).
**Written to the policy of ADR-0019:** this record names no system.

## Context

### What changes, and what does not

ADR-0024 enrolls a machine with a script nervus writes for one code. Today the owner carries it to
the machine: they run two lines as root there, the first fetching the script from nervus over HTTPS
pinned to nervus's key, the second showing it and running it. The script makes `agent` and its
level, writes nervus's key last, and sends the machine's own host keys and machine id back over the
same pinned connection. nervus then logs in as `agent` with only those keys pinned, checks the
level, and only then adds the machine.

What the operator asks for changes only who carries the script. **nervus logs in to the machine with
an admin account and password the owner types once, becomes root, and runs the same two lines there
itself.** From the moment the script runs, everything is ADR-0024's, unchanged: the same script,
report, check and row, the same refusals, and the script's own undo when nervus refuses. ADR-0025's
change to the line the script writes (its decision 4) is made once and holds for both ways.

This is the pattern ADR-0022 decision 3 already uses for VMs: a channel nervus trusts for one moment
gives root on the machine; one fixed script runs as root; the host keys come back; nervus pins them
and checks over SSH as `agent`. For a VM the channel is the hypervisor's guest agent. Here it is the
owner's admin login.

### What the owner gives up, against the two lines

Three things, stated so they are chosen knowingly.

1. **Who vouches that the address is the machine.** With the two lines, the owner runs them on the
   machine; its host keys come from the machine itself, over a connection pinned to nervus, and
   nothing on the network can stand in for it. From nervus's page, nervus first meets the machine
   over the network, and the first host key it is shown is its only evidence. This is *trust on
   first use*: the first key seen is believed, and later ones must match it. `ssh` works this way
   on a first login, and so did the owner's own first login to that machine. Against someone on the
   network between nervus and the machine at that moment (ADR-0007 adversary C), it means:
   - **they can see the password**, since SSH hands a password to whoever holds the host key that
     answered;
   - **if they relay to the real machine**, the real machine is enrolled, pinned to its own keys,
     and they keep the password;
   - **if they run the script themselves**, their machine is enrolled in its place, and agents'
     commands go to them.

   Showing the key before the password is typed, and comparing afterwards, closes part of this
   (question 2); only checking the key's fingerprint closes all of it.
2. **A password passes through nervus.** Under the two lines nervus never sees one. A nervus
   compromised at that moment gains root on that machine, which it gains under the two lines too,
   since the owner runs as root the script it serves; and root wherever else that password works.
   The new exposure is password reuse. A nervus compromised later gains nothing from it, since
   nervus keeps it nowhere (question 4), and ADR-0005 decision 5 holds as before: a read-only
   machine stays read-only against a nervus compromised after it was enrolled.
3. **The script is not read first.** The two lines' second line shows it with `less`. From the
   page, nervus runs it; the page says what it does, and the two lines stay one click away for
   anyone who wants to read it before it runs.

### What logging in needs on the machine

Read off asyncssh 2.24.0's source (the version `pyproject.toml` pins) and observed against real
asyncssh SSH servers on loopback in the drafting session (a prototype, not kept):
- **An SSH server that takes a password**, by `password` or `keyboard-interactive`; asyncssh
  answers both from one password. A wrong password and a server that takes only keys fail alike
  (`PermissionDenied`), but asking the server which methods it offers sends no credential and tells
  them apart: `get_server_auth_methods` answered `['keyboard-interactive', 'password']` from one,
  `['publickey']` from the other.
- **Root's password is refused by default:** OpenSSH 7.0 changed `PermitRootLogin`'s default from
  `yes` to `prohibit-password` (its release notes). On most machines the admin account is therefore
  the owner's own, using `sudo` with its password. A machine where only `su` reaches root is left to
  the two lines (question 3).
- **The host key can be fetched before anything is sent** (`get_server_host_key`), and a login
  pinned to that key alone is refused by any other server before authentication begins: in the
  prototype, a server at that address with another key received no password.
- **nervus's own account must lend nothing.** By default asyncssh offers the running account's keys
  and its SSH agent, and reads its `~/.ssh/config`, which could send the connection elsewhere.
  `client_keys=None`, `agent_path=None` and `config=None` stop all three; in the prototype a
  hostile `~/.ssh/config` in the account's home was ignored by both calls.
- **The machine must reach nervus over HTTPS**, as the two lines' first line does today, at the
  address the two-line page already names nervus by: `--ui-url`'s host, which the installer always
  sets, else the one the browser used. The script's report goes there too.

How nervus becomes root, also tried in the drafting session, in `sh`, `dash` and `bash` with a
stand-in `curl`: the two lines run as `sh -c`, the script with its standard input from `/dev/null`.
The script's exit status passed through unchanged (0, 1 and 3), and a password left unread on
standard input, as `sudo` leaves it when it needs none, never reached the script. Whether the
script's temporary copy is removed on every way out was not tried there; step 3's tests check it.

### How the page can show progress

No script runs on nervus's pages: every response carries `default-src 'none'` (ADR-0012). A page
can still reload itself, with `<meta http-equiv="refresh">`, which that policy does not govern
(from the standard; step 4 sees it in a browser). So the "loading box" is a page that reloads every
two seconds and lists each step: nervus's own (connecting, logged in, root) and each line the script
reports ("installing bubblewrap", "agent has nervus's key").

### Names and the household's DNS

nervus keeps the name or address typed, and its own machine's resolver looks a name up at every
connection, as it already does for every enrolled machine. Whatever DNS the household uses, nervus's
machine uses too. A `.local` name resolves only where nervus's machine runs mDNS (on Debian,
`avahi-daemon` with `libnss-mdns`), and the page says so when a name does not resolve.

## Questions

### 1. Which way is the default

- **a. From nervus's page, by admin login: the add form's first button, "Connect".** The two lines
  stay, as a second button on the same form ("Advanced: two lines to run on the machine yourself"),
  and the page offers them wherever logging in cannot work: a machine that takes only keys, or one
  where only `su` reaches root.
- b. The two lines stay the default; the admin login is the second button.
- c. The admin login only; the two lines removed.

*Recommended: a.* **Decided 2026-10-22: a.** It is what the operator asked for, and what most home machines allow. The two
lines remain the stronger way, for a network the owner does not trust; c would leave a machine that
takes only keys no way in from the page.

### 2. How nervus trusts the machine at first contact

- **a. Show the key, send the password only to it, and compare afterwards.** Before asking for any
  login, nervus fetches the machine's host key and shows its fingerprint, with how to check it: on a
  computer that has logged in to the machine, `ssh-keygen -lF <address>`; on the machine,
  `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`. The login is then pinned to exactly that key,
  so the password goes to nothing else. Afterwards, the enrollment route refuses the report if that
  key is not among the host keys the machine itself sends through the script. An interceptor that
  relayed to the real machine is caught there; the script takes nervus's key back off, as for any
  refusal; and the page says the password may have been seen and should be changed.
- b. As a, and the fingerprint must be pasted to go on. Exact, but the owner must have it to hand,
  and by then the two lines are as quick.
- c. Accept whatever key answers, and show nothing.

*Recommended: a.* **Decided 2026-10-22: a.** It is `ssh`'s own first-login model, made visible, and the comparison turns a
quiet password theft into a loud refusal for one table and one comparison in the route. It does not catch
an interceptor that runs the script itself; only checking the fingerprint does, and the page says
so. This amends ADR-0007 decision 3 for the moment of first contact, knowingly, and the docs say: on
a network you do not trust, use the two lines. c is refused by ADR-0007 decision 3 as it stands.

### 3. Which logins nervus takes

- **a. An account name and its password: root's, where the machine allows it, or an account that
  can use `sudo` with that password.** Nothing else: no private key pasted, no `su`.
- b. Also a private key, pasted into the page. A private key in a web form is a habit nervus should
  not teach, and prior-art idea 4 refused borrowing the owner's keys.
- c. Also `su` with root's password. It needs a terminal on the machine and nervus answering its
  prompts: more code, more ways to fail, and the two lines already cover it.

*Recommended: a.* **Decided 2026-10-22: a.**

### 4. What nervus keeps of the login

- **a. The account name, and never the password.** The account name goes into the audit record and
  beside the code: the machine's own journal records it anyway, and matching the two needs it. The
  password is held in memory for that one enrollment only. It is never written to the database, the
  audit log or nervus's journal; never put back into a page, a refused form included; and anything
  the machine prints is shown with it replaced, in case something there echoes it. Python cannot
  promise memory is wiped at once, so the docs say "not kept", not "erased".
- b. Nothing of the login, the account name included.

*Recommended: a.* **Decided 2026-10-22: a.**

### 5. When the level is chosen

- **a. On the first form, read-only already chosen (ADR-0005 decision 5), and again on the login
  page, where it can still be changed before anything is sent.** The login page is the dialog the
  operator described: the level is in front of the owner at the moment they commit. There is never
  a machine with no level to ask about.
- b. No level on the first form; the login page asks, and nothing goes on without one. The operator's
  first idea. It adds a state, "no level yet", that every step must handle, and turns ADR-0005's
  default into a choice made every time.

*Recommended: a.* **Decided 2026-10-22: a.**

### 6. How progress shows

- **a. nervus works in the background, and the browser goes to a page that reloads itself every two
  seconds**, listing each step, then the outcome. Leaving the page does not stop the enrollment; the
  Machines page's "Codes made lately" shows what became of it, as for the two lines.
- b. The form's request waits until the end, which can be minutes, the browser's own spinner
  standing for the loading box. One page and one in-memory list fewer; nothing is shown until the
  end, and a dropped connection loses the answer, though the Machines page still has it.

*Recommended: a.* **Decided 2026-10-22: a.** It is what the operator asked for, and an enrollment should not hang on one request
living for minutes.

### 7. A level raised on the login page after the name was typed

*Added 2026-10-23, raised while building step 4.* ADR-0024 question 8 asks before a reused name or a
raised level reaches the tokens that name the machine, and goes on only with the name typed. With
Connect the level can still be changed on the login page (question 5), and the login page carries the
name typed, so it is not asked twice. As built in step 4 it carried the name and not the level: a name
typed for read-only to standard, then full chosen on the login page, gave those tokens full access with
nothing said.

- **a. Carry the level the name was typed at; if the login page's level is higher, ask again before
  anything is sent.** The same or a lower level goes on.
- b. Leave it: the name typed once covers whatever level the login page has.
- c. Once the name is typed, the login page's level can only be kept or lowered.

*Recommended: a.* **Decided 2026-10-23: a.** It asks at the moment the tokens would gain something not
shown, as question 8 does everywhere else; c would take away question 5's choice.

### 8. A server whose host key is of another type than the one shown

*Added 2026-10-23, raised while building step 3.* The login is pinned to exactly the key shown, so
asyncssh offers only that key's type. A server at the address with another key of the same type is
refused as `HostKeyNotVerifiable`, and the owner reads that something else may be answering there. A
server with a key of another type fails the key exchange first (`KeyExchangeFailed`), before any login
and without the password, but the owner read only `cannot log in … (KeyExchangeFailed: …)`.

- **a. The same words as for another key: nervus sent it no password, and something else may be
  answering at that address.**
- b. Keep the generic message.

*Recommended: a.* **Decided 2026-10-23: a.** To the owner both are the same event: the machine at that
address is not the one whose key they were shown.

### 9. Which of the machine's keys Connect shows

*Added 2026-10-24, found by procedure 040 step 4.2.* A machine has several host keys, one of each
type. asyncssh asks for RSA first, so Connect showed a Debian machine's RSA key, while the page and
`docs/install.md` tell the owner to check `/etc/ssh/ssh_host_ed25519_key.pub` on the machine, which
prints another fingerprint: the owner, told that a mismatch means "stop", would stop for nothing, or
learn to ignore the check. The key shown was the machine's own; nothing reached anything else.

- **a. Ask for the ed25519 key first, and take another type only from a machine that has none; the
  page names the key file of the type it shows.** Most machines then show the key the docs name.
- b. Keep asyncssh's choice, and name the file of whatever type was shown.
- c. Fetch every key the machine offers, show each fingerprint, and pin the login to all of them.

*Recommended: a.* **Decided 2026-10-24: a.** ed25519 is what OpenSSH makes on every current system
and what `ssh-keygen -lF` shows first; b leaves most owners checking an RSA key, and c gives them
more to compare for no more safety, since the comparison after the script covers every key.

## Settled already

- **The address is required** this way: nervus must know where to connect. ADR-0024 decision 4a's
  blank address, the one the report comes from, stays for the two lines.
- **What ADR-0024 refuses is refused here too, by the same code:** plain HTTP, lockdown, a name in
  `hosts.yaml`, full access to nervus's own machine (the script stops before changing anything), a
  machine that is not its level. ADR-0024 question 8's question about tokens is asked before the
  login page, as before the two lines.
- **What cannot be audited does not happen** (ADR-0001 s10): the login is recorded before nervus
  connects, and nothing is attempted without the record.
- **The password crosses no network in clear:** the UI is served over HTTPS, or on loopback only
  (ADR-0011 question B); from nervus to the machine it is SSH, to the key shown.
- **The machine's own journal records the login and `sudo`'s use**, the independent witness
  ADR-0005 chose push for.
- **The code is never shown on nervus's page.** nervus makes one for the enrollment, as for the two
  lines, so the route, the report and the record are the same; it stops working when the enrollment
  ends, however it ends. It does appear on the machine, in the command nervus runs there and so in
  `sudo`'s log, as it appears in the root shell's history with the two lines; by the time anyone
  reads it there, it works for nothing.

## Not chosen

- **Keeping the login**, to enroll again or remove a machine later: a stored admin password is the
  asset this design exists not to create.
- **The owner's own SSH key or agent**, forwarded from their computer: borrowing the owner's keys
  (prior-art idea 4).
- **A permanent program on the machine:** ADR-0005 decision 2.
- **Removing a machine by admin login too.** It could reuse this login later; it was not asked for,
  and ADR-0024 decision 5a's commands stand.

## Consequences

1. **For a friend:** on the Machines page, a name, an address and a level; Connect; check the
   fingerprint; an admin account and its password; watch it finish, and the machine is in the list.
   The two lines are under "Advanced".
2. **For nervus:** one module (the login and the run), one table (the account and key a code was
   made with), one comparison in the enrollment route, two pages and one route in the UI. The
   script, the store and the check are unchanged.
3. **For ADR-0025:** nothing more. Its change to the script's line, and its question 3 at full
   access, land on what both ways share.
4. **For the threat model:** a password in nervus's memory for one enrollment, and trust on first
   use at first contact, both said on the page, in `docs/install.md`, and in the README's non-goals.
5. **Not changed:** machines enrolled before, `hosts.yaml`'s machines, and VMs.

## Order of work

Each step waits for the operator (rule 1). **Placed by the operator on 2026-10-22: built now, in a
session of its own.** Written so that an agent that has read `AGENTS.md`, this record and ADR-0024
can build it. Questions 1 to 6 were decided as recommended, so it stands as written. Where this
section and the questions disagree, the questions win.

How to build each step, as the code around it is built: a module docstring that lists what the
module holds to; tests named for the guarantee they show; each guarantee broken on purpose and seen
caught before its test is kept; the whole suite passing at the end of each step (`pytest`, both
folders), its count recorded in `CURRENT_STATE.md` with the step. Record the suite's result before
the first change, where it is built, and judge each step against that. In the cloud container this
record was drafted in, running as root, 21 tests failed and 38 errored before any change, the same
with and without this record; among them three in `tests/test_host_enrollment_route.py`, which play
a read-only machine by taking write permission away, which root ignores. Run the suite as an
ordinary user where possible.

0. ~~The operator's decisions on questions 1 to 6.~~ Done 2026-10-22: all as recommended.

1. ~~**The login beside a code.** `src/nervus/database.py`, `src/nervus/enrollment_codes.py`; tests in
   `tests/test_enrollment_codes.py`.~~ Built 2026-10-22, not deployed: 28 tests, each guarantee broken on
   purpose and caught. One difference from the text below: `host_keys([host_key])` keeps the first key of a
   text holding several and drops the rest, so it cannot by itself refuse "not exactly one key"; `make()`
   also refuses a host key text of more than one line.
   - A table in `ADDED`, not `SCHEMA`; the version stays 1, as the comment above `SCHEMA_VERSION`
     requires:
     ```sql
     CREATE TABLE IF NOT EXISTS enrollment_login (
         code_id TEXT PRIMARY KEY,
         login TEXT NOT NULL,
         host_key TEXT NOT NULL
     );
     ```
   - In `enrollment_codes.py`: `LOGIN = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}")`; a frozen
     dataclass `CodeLogin(login: str, host_key: str)`; `make()` gains keyword arguments
     `login: str | None = None, host_key: str | None = None`. Both or neither, else
     `HostRefused("bad_login", ...)`. `login` must fullmatch `LOGIN`, else `HostRefused("bad_login",
     ...)`. `host_key` is normalised by `enrollments.host_keys([host_key])` and must give exactly one
     key, else `HostRefused("bad_host_keys", ...)`. The code's row and its login's row are written in
     the one transaction `make()` already opens. `make()`'s purge of old codes also runs
     `DELETE FROM enrollment_login WHERE code_id NOT IN (SELECT id FROM enrollment_code)`.
   - `login_of(code_id: str) -> CodeLogin | None`.
   - The docstring's "What it holds to" gains: a code made from nervus's page keeps the account it
     logs in as and the host key that answered, never a password.
   - Tests: a code made with a login keeps the account and the key, the key as `host_keys` keeps it;
     a code made without one has none; one of the two without the other is refused and nothing is
     made; an account name that is not one is refused; a host key that is not exactly one key is
     refused; a code purged takes its login with it; a version-1 database made before this table
     gains it when opened, and keeps its codes.

2. ~~**The comparison in the route.** `src/nervus/host_enrollment.py`; tests in
   `tests/test_host_enrollment_route.py`.~~ Built 2026-10-23, not deployed: as written below; 8 tests, each
   guarantee and the place of the check broken on purpose and caught.
   - In `HostEnrollment._enroll`, immediately after `keys = pinned_keys(lines)`, before the address
     is checked and before any SSH:
     ```python
     made = self.codes.login_of(code.id)
     if made is not None and made.host_key not in keys:
         raise Refused(409, NOT_ITS_OWN.format(address=code.address, login=made.login))
     ```
     with the constant
     ```python
     NOT_ITS_OWN = ("the key that answered nervus's login at {address} is not one of this machine's own "
                    "host keys, so something between nervus and the machine may have answered instead and "
                    "seen {login}'s password. nervus did not add the machine. Change that password, then add "
                    "the machine with the two lines.")
     ```
   - Nothing else in the route changes. The refusal reaches the script as a status that is not 200,
     so the script's existing `undo` takes nervus's key off, and the existing
     `codes.finish(code.id, f"refused: {exc.message}")` records it.
   - "What the route holds to" gains one bullet saying this.
   - Tests: a code made with a login whose key is among those reported is enrolled; one whose key is
     not is refused with 409 and `NOT_ITS_OWN`, nothing is added, no SSH connection is made
     (`world.connects` stays empty), the code's outcome and the audit result carry the message; a
     code made without a login is unaffected (every existing test passes unchanged).

3. ~~**The login and the run.** A new module `src/nervus/host_login.py`; tests in a new
   `tests/test_host_login.py`.~~ Built 2026-10-23, not deployed: 98 tests, each guarantee broken on purpose and
   caught. Differences from the text below, none a design choice: a password holding a line break is refused
   before anything is attempted; a pin must have the shape of one (`sha256//` and a key's hash), so a missing pin
   cannot make `curl` skip its check; the machine's output is read in pieces of bounded size, not by line, so one
   endless line cannot fill nervus's memory; a failed `id` or `sudo` says which command did not answer. A server
   whose host key is of another type than the one pinned fails the key exchange before any login; it said
   `cannot log in … (KeyExchangeFailed …)` until question 8 (decided 2026-10-23: a) gave it the "another key" words.
   - Constants: `TOOL = "enroll"` (the route's, so the audit viewer shows both together);
     `CONNECT_SECONDS = 10.0`; `CHECK_SECONDS = 20.0`; `RUN_SECONDS = 600.0` (installing
     packages on a slow machine); `KEEP_SECONDS = 3600.0`; `MAX_LINES = 200`; `LINE_CHARS = 500`;
     `TAIL_LINES = 20`; `SUDO_CHECK = "sudo -S -p '' true"`.
   - `fingerprint(host_key: str) -> str`: from `asyncssh.import_public_key(host_key)`,
     `f"{key.get_algorithm()} {key.get_fingerprint('sha256')}"`, as in `ssh-ed25519
     SHA256:…`; the `SHA256:…` part is what `ssh-keygen -l` prints.
   - `root_command(url: str, pin: str, shown: str) -> str`, the two lines as nervus runs them as
     root, exactly:
     ```
     t=$(mktemp) || exit 1; trap 'rm -f "$t"' EXIT; curl -fsSk --pinnedpubkey <pin> -o "$t" <url> || { echo <message> >&2; exit 1; }; sh "$t" </dev/null
     ```
     with `<pin>`, `<url>` and `<message>` each `shlex.quote`d, `<message>` being `f"nervus
     enrollment: this machine could not reach nervus at {shown}, so nothing here was changed"`.
     `shown` is the URL with `<code>` in place of the code (`enroll_url(host, port, "<code>")`), so
     the code is never shown. Why each part: `mktemp`, so no copy is left in a folder for a later run
     to find (procedure 037's fault); the trap, so the copy is removed on every way out; `</dev/null`,
     so whatever `sudo` leaves unread on standard input, the password included, reaches nothing the
     script runs.
   - `login_command(root: str, *, sudo: bool) -> str`: `f"sudo -S -p '' sh -c {shlex.quote(root)}"`
     with sudo, `f"sh -c {shlex.quote(root)}"` without.
   - `class LoginRefused(Exception)`, with `.message`, words for the owner.
   - `@dataclass class LoginRun`: `code_id, name, address, level, login, fingerprint: str`,
     `started_at: float`, `lines: list[str]` (empty), `finished_at: float | None = None`,
     `enrolled: bool = False`, `outcome: str = ""`, and a property `done`. It never holds the
     password.
   - `class LoginEnrollment(codes: EnrollmentCodes, audit: AuditLog, *, port: int = 22,
     locked: Callable[[], bool] = lambda: False, connect_seconds=CONNECT_SECONDS,
     run_seconds=RUN_SECONDS)`, keeping `self._runs: dict[str, LoginRun]` and
     `self._tasks: set[asyncio.Task]`. Store calls are made directly, as `host_enrollment.py` makes
     them.
     - `async host_key(address) -> str`: `asyncio.wait_for(asyncssh.get_server_host_key(address,
       self.port, config=None), self.connect_seconds)`; returns the key as `host_keys` keeps it
       (type and base64). Each failure becomes `LoginRefused`, checked in this order, since each is a
       kind of the next: `socket.gaierror`: "nervus's machine cannot find {address}: its DNS does not
       know that name. Give the machine's address, or, for a .local name, install avahi-daemon and
       libnss-mdns on nervus's machine."; `ConnectionRefusedError`: "nothing answers SSH at
       {address}, port {port}: is its SSH server running?"; `TimeoutError`: "{address} did not answer
       within {n} seconds"; any other `OSError`: "cannot reach {address}: {exc}" (cut to 120
       characters); `asyncssh.Error`: "{address} did not answer as an SSH server ({exc.reason})"; a
       `None` key: "{address} showed no host key, so nervus cannot know it is that machine".
     - `start(code, *, url, pin, host_key, login, password, shown) -> LoginRun`: makes the run,
       keeps it under `code.id`, starts `_run` with `asyncio.create_task`, keeps the task in
       `self._tasks` until it is done (`add_done_callback(self._tasks.discard)`), forgets runs that
       finished more than `KEEP_SECONDS` ago, and returns the run. Called from the UI's handler,
       inside the event loop.
     - `get(code_id) -> LoginRun | None`; `async finished()`, which waits for every run now going
       (for tests).
     - `_run`, every step bounded by `run_seconds` overall:
       1. If `locked()`: refused, "nervus is locked down, so it enrolls nothing", recorded with
          `audit.record_refusal(TOOL, {..., "reason": "lockdown"})` as the route records one. Then
          `run_id = audit.record_intent(TOOL, {"actor": "operator", "action": "login",
          "code_id", "name", "address", "level", "login", "host_key": <fingerprint>})`; an
          `AuditError` there means nervus connects to nothing: "nervus cannot write its audit log, so
          it did nothing".
       2. Step line "connecting to {address} as {login}, trusting only the key {fingerprint}";
          then `asyncssh.connect(address, self.port, username=login, password=password,
          known_hosts=pinned_known_hosts(address, self.port, (host_key,)), client_keys=None,
          agent_path=None, gss_auth=False, host_based_auth=False,
          preferred_auth="keyboard-interactive,password", config=None,
          connect_timeout=self.connect_seconds)`, with `pinned_known_hosts` from `enroller.py`.
          `HostKeyNotVerifiable`: "the SSH server at {address} now answers with another key than the
          one shown, so nervus sent it no password. If the machine was reinstalled since, start
          again; if not, something else may be answering at that address." `PermissionDenied`: ask
          `get_server_auth_methods(address, port, login, config=None)` (bounded; any failure counts
          as no methods). Neither `password` nor `keyboard-interactive` among them: "{address} takes
          no password for {login}, only keys, so nervus cannot log in. Add it with the two lines
          (Advanced)." Else, for `root`: "{address} refused root with that password. Most machines
          refuse root's password over SSH (PermitRootLogin); use an account that can use sudo."
          Else: "{address} refused {login} with that password." Anything else: "cannot log in to
          {address} ({type}: {reason})".
       3. "logged in as {login}". `id -u` (bounded by `CHECK_SECONDS`): `0` is root, "{login} is
          root". Otherwise `SUDO_CHECK` with `input=password + "\n"`: exit 0, "{login} can use sudo";
          127 or "not found": "{login} is not root, and this machine has no sudo: give root's login,
          or add it with the two lines from a root shell"; anything else: "{login} cannot use sudo
          with that password (sudo said: {its last line})".
       4. "running nervus's enrollment script for {level} as root; the machine fetches it from
          {shown}". `conn.create_process(login_command(root_command(url, pin, shown),
          sudo=not root))`; with sudo, write `password + "\n"` to its standard input; then
          `write_eof()`. Read its output and its errors at once, line by line, each line first
          scrubbed (below) and cut to `LINE_CHARS`. A line starting `nervus enrollment: ` or
          `nervus: ` is a step: kept in `run.lines` without that prefix, up to `MAX_LINES`, the last
          one remembered. Any other line goes to a tail of the last `TAIL_LINES`, shown only if the
          run fails.
       5. The outcome. The code's own record says it first: once the route has judged the report,
          `codes.get(code_id).outcome` is "enrolled …" or "refused: …", and that is the run's
          outcome, `enrolled` true only for an exit status of 0 and "enrolled …". Without one, the
          last step line the script wrote to its errors, else the tail's last line, else "the
          script ended with status {n}".
       6. However it ends, the timeout and any exception included: close the connection;
          `codes.cancel(code_id)`, so the code works for nothing more; if the code has no outcome,
          `codes.finish(code_id, outcome)`; `audit.record_result(run_id, TOOL, {"enrolled",
          "outcome", "exit_status"})` if the intent was written; `finished_at`; drop the password.
          On the timeout the outcome is "did not finish within {run_seconds // 60} minutes. nervus stopped waiting,
          and the code no longer works, so if the script still reaches nervus it takes nervus's key
          off again". An unexpected exception is "nervus failed ({type})", printed to standard
          error, scrubbed.
     - **Scrubbing:** every text that reaches a step line, the tail, the outcome, the code's record,
       the audit log or standard error first has each occurrence of the password replaced by
       `<password>`.
   - Tests. A real asyncssh server on loopback plays the machine: an `asyncssh.SSHServer` that takes
     one account and password, records every password and every public key it is offered, and runs
     each command with `tests/sshd_shell.py`'s real shell. `id`, `sudo` and `curl` are stood in on
     `PATH`, as `tests/test_host_enrollment_route.py` stands in `id` and `sudo`. The stand-in `sudo`
     takes `-S -p ''`, reads one line and compares it with the account's password (or, playing a
     machine with passwordless sudo, reads nothing), then runs the rest. The stand-in `curl` records
     its arguments and writes a small script to `-o`'s path, or fails with 22 to play a machine that
     cannot reach nervus. Where a test needs the route's judgement, it plays it on the code's record
     (`codes.spend`, then `codes.finish(code.id, "enrolled web, standard")` or `"refused: …"`).
     The tests:
     - the host key shown is the server's own; a name that does not resolve, a port nothing answers
       on, and a server that is not SSH each say which;
     - **the password goes only to the key shown:** a second server, with another key, at the
       address used, refuses the login before any password reaches it, and it records none;
     - **nervus lends nothing of its own account:** with a key the server would accept in
       `$HOME/.ssh/id_ed25519`, and a `$HOME/.ssh/config` that sends every host to another port and
       account, the server is offered no public key and the login reaches it as the account given;
     - root runs the two lines without `sudo`; an account with `sudo` runs them through `sudo`,
       with its password on standard input; `curl` is given exactly the pin and the URL;
     - a wrong `sudo` password, an account without `sudo` and a machine without `sudo` each stop
       before `curl` runs, saying which;
     - a wrong password, a server that takes only keys, and root refused each say which, and
       nothing runs;
     - **the password is never kept:** after a run that enrolls and after one that fails, it is in
       none of the database file and its `-wal` file read as bytes, the audit log's text, the run's
       lines and outcome, or the code's outcome; a stand-in `sudo` that prints its standard input to
       its errors is shown with `<password>` instead;
     - the script's step lines appear in the run as they come, before it ends;
     - a machine that cannot reach nervus says so, naming the URL without its code;
     - **the code dies with the run:** after an enrollment, a refusal and a timeout,
       `codes.find(value)` is `None`;
     - a run longer than `run_seconds` (set to 1, the stand-in script sleeping) is stopped and says
       so;
     - without an audit log, and in lockdown, the server sees no connection at all;
     - the route's word is the outcome: "enrolled …" with status 0 is enrolled, "refused: …" is not;
     - **`root_command` in real `sh`, `dash` and `bash`** (each skipped if missing), with the stand-in
       `curl`: the script's exit status passes through (0, 1 and 3); a line on standard input never
       reaches the script; the temporary copy is gone afterwards when the script succeeds, fails,
       and when the fetch fails; values holding quotes reach `curl` exactly;
     - a run that finished more than an hour ago is forgotten.

4. ~~**The pages.** `src/nervus/pages.py`, `src/nervus/ui.py`, `src/nervus/__main__.py`; tests in a
   new `tests/test_ui_machines_login.py`. `tests/test_ui_machines.py` changes only where it reads a
   button's old wording; none of its tests is removed.~~ Built 2026-10-23, not deployed: 81 tests, each guarantee
   broken on purpose and caught, and seen working in a real browser. `tests/test_ui_machines.py` needed no change.
   Where the build goes beyond or reads the text below, none a design choice except the first, which is reported:
   the question-8 page that the login asks goes on with `connect`, so the key is shown afresh and the password typed
   again; a host key that is not one key is refused on the Machines page, an account name that is not one or an
   empty password brings the login page back with a notice, its password field empty; the account typed is taken
   without spaces round it; the progress page's way on from a failure is a link to try again and a button for the
   two lines; `tests/test_pages.py` learns to make a `LoginRun`, and `tests/test_main.py` checks the wiring. Found in
   the browser and fixed: Machines showed a run that ended before the route saw a report as "expired, unused"
   (its code is cancelled and never used), hiding why; a code's outcome is now shown whenever it has one.
   A level raised on the login page after the name was typed went on unasked; question 7 (decided 2026-10-23: a)
   makes it ask again.
   - `ui.Machines` gains a last field `login: LoginEnrollment | None = None`, so every construction
     of it today still works. `__main__.py` makes `LoginEnrollment(codes, audit,
     port=settings.ssh_port, locked=lambda: locked(settings.switches_path))` and passes it.
   - `pages._document` and `pages._frame` gain `refresh_seconds: int | None = None`; given, the
     page's head carries `<meta http-equiv="refresh" content="{n}">`.
   - `page_machines` gains `can_login: bool = False`, which `ui.machines_page` passes as
     `machines.login is not None`. The add form loses its hidden `action` field
     and gets two buttons, Connect first, since Enter in a field presses the first:
     `<button type="submit" name="action" value="connect">Connect</button>`, shown only with
     `can_login`, then `<button type="submit" name="action" value="add" class="secondary">Advanced:
     two lines to run on the machine yourself</button>`. The address's label says "a name or address
     nervus can reach". The help below says: Connect shows the key the machine answers with, then
     asks once for an admin login, root or an account that can use sudo, and does the rest, keeping
     no password; Advanced gives the two lines, as before (the sentences about a blank address, a
     reinstall and a new level kept).
   - `page_enroll_confirm` gains `action: str = "add"`; its hidden action follows it, and its button
     says "Connect" for `connect`.
   - A new `page_enroll_login(name, address, level, host_key, fingerprint, confirm, until,
     form_token, standing, notice="")`: the heading "Log in to {name}"; "nervus reached {address}.
     Its SSH server answered with this key:" and the fingerprint; "If you have logged in to {name}
     before, check it matches: on that computer, `ssh-keygen -lF {address}`; on {name} itself,
     `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`. nervus sends the login below only to the
     machine holding this key. If it does not match, stop: something else may be answering at
     {address}." A form posting `action=login` with `name`, `address`, `host_key` and `confirm`
     hidden; the level's radio buttons, the one chosen before already chosen; `<input type="text"
     name="login" autocomplete="off" autocapitalize="none" spellcheck="false">` labelled "Admin
     account (root, or one that can use sudo)"; `<input type="password" name="password"
     autocomplete="off">`; a button "Enroll". Then: "nervus logs in once, becomes root, directly or
     with sudo and this password, and runs its enrollment script: it makes the account agent with
     nervus's key and sets up the level. nervus keeps no password. Whoever controls this nervus right
     now could see it; if you would rather nervus never saw it, or you do not trust this network,
     use the two lines." And a second form, posting `action=add` with the name, address and level:
     "Advanced: two lines to run on the machine yourself instead".
   - A new `page_enrolling(run: LoginRun, until, form_token, standing)`, with `refresh_seconds=2`
     while the run is not done and none once it is. Heading "Enrolling {name}", then "{name} is
     enrolled, {level}" or "{name} was not enrolled"; the steps as an ordered list; once done, the
     outcome, and either "In Clients, give a token this machine to let a client use it" or links to
     try again and to the two lines; a link to Machines throughout.
   - In `ui.manage_machines`, ADR-0024 question 8's block moves into a helper both actions use, so
     the question is asked the same way before Connect, the login and the two lines. Then:
     - **`connect`:** refused as "not an action nervus knows" without `machines.login`; with
       `PLAIN_HTTP` when `pin()` is `None`; in lockdown (`machines.login.locked()`), "nervus is
       locked down, so it enrolls nothing"; for what `check()` refuses; and without an
       address, "Give the address nervus should connect to." Then the question-8 helper, with
       `action="connect"`; then `await machines.login.host_key(address)`, a `LoginRefused` shown on
       the Machines page as "Not connected: {message}"; then `page_enroll_login`.
     - **`login`:** every check `connect` makes, made again, the question-8 helper included (a raised
       level asks again, and the password is typed again); `host_key` must normalise to exactly one
       key; `login` must fullmatch `LOGIN`; the password must not be empty, else `page_enroll_login`
       again with a notice and the password field empty. Then `codes.make(..., login=login,
       host_key=key)`; `recorded("enrollment_code", {"target", "code_id", "level", "tokens_shown",
       "machine_address", "method": "login", "login", "host_key": <fingerprint>, **where},
       undo=lambda: codes.cancel(code.id))`, and if that fails, the Machines page with its notice
       and nothing started; then `machines.login.start(code, url=enroll_url(host, port, value),
       pin=pin, host_key=key, login=login, password=password, shown=enroll_url(host, port,
       "<code>"))`, `host` found as for the two lines; then `303` to `enrolling?id={code.id}`. The
       password goes into no response and no record.
   - A route `GET /enrolling?id=<code id>`, signed in; the id must be 16 lowercase hex digits. A run
     nervus has: `page_enrolling`. None, but a code by that id: a page with what its record says, or
     that it is no longer running and Machines shows what became of it. Neither: 404. The module
     docstring's list of routes gains it.
   - Tests, with `LoginEnrollment` stood in by an object that returns a fixed key or raises
     `LoginRefused` from `host_key`, and records `start`'s arguments, returning a `LoginRun`:
     - the add form offers Connect first and the two lines as Advanced, read-only already chosen;
       without `machines.login`, only the two lines;
     - Connect shows the fingerprint and asks for a login, the level kept;
     - Connect without an address, over plain HTTP, in lockdown, and for a name in `hosts.yaml`
       connects to nothing (`host_key` not called);
     - a machine that cannot be reached says why, on the Machines page;
     - a reused name or a raised level is asked about before Connect; the login page carries the
       name typed; a login posted without it is asked again and makes nothing;
     - the login makes a code with the account and key, records it with the account and fingerprint,
       starts the run with the password, and sends the browser to its progress page;
     - **the password is in no response, no audit record and no database row**, and a refused login
       page shows its password field empty;
     - a host key that is not one key, an account name that is not one, and an empty password are
       refused, and nothing is made or started;
     - a code whose record cannot be written is cancelled, and nothing starts;
     - a login posted from another site, or without the form token, is refused;
     - the progress page reloads itself while the run goes on and stops once it ends, showing the
       outcome; for an id nervus no longer runs, it shows what the code's record says;
     - Advanced still makes the two lines, and every test in `tests/test_ui_machines.py` passes.
   - **Seen working in a browser**, as ADR-0024 step 4 was: the UI against a scratch database and a
     loopback SSH server playing the machine, in a real browser, to see that the progress page
     reloads itself under nervus's content security policy and stops when done. The policy's effect
     on `refresh` is from the standard until then.

5. ~~**The words.** `docs/install.md`, `preview/README.md`, `src/nervus/pages.py` (`NON_GOALS`), the
   docs' tests, and the status lines of ADR-0024, ADR-0007 and this record.~~ Done 2026-10-23: as written
   below, the docs tested as written. One difference: `ssh-keygen` finds `~` from the account's password entry,
   not from `HOME`, so the test gives `-lF` its `known_hosts` with `-f`, the file it reads by default.
   - `docs/install.md` step 3: name and level as now; the address, "the name or address nervus
     connects to; nervus's machine looks a name up in your network's DNS; a .local name needs mDNS
     on nervus's machine"; **Connect**, nervus showing the key the machine answered with and the two
     commands that check it, under a marker `<!-- install:fingerprint -->`; **log in once**, as root
     or an account that can use `sudo`, nervus doing the rest and showing each step, the machine
     then in the list; what nervus keeps (the account name, never the password). Then a heading
     "Advanced: two lines run on the machine yourself", under which the present text of the two
     lines moves unchanged, its `<!-- install:enroll -->` block included, opening with when to use
     it: a machine that takes only SSH keys; one where only `su` reaches root; a network you do not
     trust; or to read the script before it runs. "What a machine needs" adds, for Connect, a
     password login for root or an account that can use `sudo`.
   - `preview/README.md`: the "Works" line says machines are added from the web UI by an admin
     login given once, or with two lines run on them. The non-goal "Whoever runs this nervus" ends
     "…, rewrite its audit log, and see a password you type to add a machine." `pages.NON_GOALS`
     gains the same words, so `tests/test_first_run_docs.py` still finds each.
   - `tests/test_enrollment_docs.py`: the two commands under `install:fingerprint`, run as written
     against a key it generates (`HOME` pointed at a temporary folder holding `.ssh/known_hosts` for
     `-lF`; skipped without `ssh-keygen`), print the `SHA256:` fingerprint `host_login.fingerprint`
     gives for the same key. The `install:enroll` and `install:remove` blocks keep their tests.
   - ADR-0024 and ADR-0007 gain "Amended … by ADR-0026" lines in their headers, in the form those
     records already use; this record's status moves on.

6. **A trial on throwaway machines, then a deploy procedure**, each written for the operator's
   approval and run where AGENTS.md rule 9 says, numbered as the next free procedures. The trial
   observes the verification below that tests cannot: a real `sshd`, `sudo` and script, from a
   throwaway nervus installed from a clone, against at least a VM with a `sudo` account (standard),
   a container allowing root's password (read-only), and a machine that takes only keys; the
   fingerprint against `ssh-keygen -lf` on the machine; a server with another key at the address
   between Connect and the login, whose own log shows no password offered; nervus's own machine at
   full; and nervus's state folder, journal and audit log searched for the password.

   **The trial done 2026-10-24** (procedure 040): verification 1 to 11 observed on throwaway machines but plain
   HTTP, which the tests show. It found question 9's fault, decided and built the same day. **Deployed
   2026-10-24** (procedure 041), with ADR-0015's first-run setup, and shown on that installation with one
   throwaway machine. It found that asyncssh's own log wrote a run's code into nervus's journal; fixed the same
   day at the operator's word, to ship with the next release.

## Verification

1. On a machine that has never seen nervus, with an account that can use `sudo` with its password:
   Connect shows the fingerprint `ssh-keygen -lf` prints on the machine; the login enrolls it at the
   level chosen; the progress page shows each step and stops at the end; the machine is in the list;
   and a client runs a command there.
2. Root's password, on a machine that allows it, enrolls a machine the same way, without `sudo`.
3. Each level is the machine's own, as ADR-0024 verification 2 and 3 say, whichever way the machine
   was enrolled.
4. The password is in none of nervus's database, audit log or journal, nor in a page served after
   the login; the account name is in the audit record; the machine's own journal shows the login.
5. A server answering at the address with a key other than the one shown is given no password.
6. A report whose host keys do not include the key that answered the login is refused, saying the
   password may have been seen, and the script takes nervus's key off again.
7. A wrong password, an account that cannot use `sudo`, a machine that takes only keys, root refused
   by `PermitRootLogin`, a name nervus's machine cannot resolve, and a machine that cannot reach
   nervus each end saying which, with nothing changed on the machine.
8. Full access to nervus's own machine by login is refused before anything there changes; read-only
   is allowed.
9. Leaving the progress page does not stop an enrollment, and the Machines page shows its outcome;
   the code made for it works for nothing once the enrollment ends.
10. Over plain HTTP, in lockdown, and without the audit log, nervus connects to nothing.
11. The two lines still do everything ADR-0024's verification says.
