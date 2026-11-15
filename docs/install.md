# Installing nervus

**This is an early preview.** There is no container image yet (ADR-0005 decision 1). One script,
`install.sh`, installs nervus on its machine; then, in its web UI, you choose where it runs, give it
the machines it reaches, and connect your clients. Plan on half an hour. The steps are written to
be followed by a person or by their own AI agent, and say at each what should be true before the
next. What the script does is also written out by hand, at the end, for reading or for a Linux it
does not know.

What you will have at the end: nervus running as a service where you chose to run it, an SSH
account it can use on each machine you give it, tokens for your clients, its web UI to switch
clients off and read the audit log, and a backup of itself once a day that only you can open.

## Where nervus may run

Choose this first: it decides how safe nervus is, and you declare it in nervus's setup.

**The one question.** Think of your **everyday computer**: the one where you run Claude Code or
Codex, and where any program you run might turn out to be hostile. **Can a program there get
inside nervus without going through nervus's front door?** The answer is nervus's **tier**
(ADR-0007 decision 2):

- **Tier 1, recommended: nervus lives on a different physical computer from your everyday one.**
  Nothing on your everyday computer can get in. The form it takes there does not matter: a
  container or a VM on a hypervisor host such as Proxmox, or nervus installed straight onto a
  small always-on box (a mini PC, a single-board computer).
- **Tier 2: nervus lives on your everyday computer, under an account of its own** (`nervus`), as a
  system service. Your programs cannot read its files without admin rights: the operating system
  is the wall.
- **Tier 3: nervus lives on your everyday computer, and your own account can get into it.** Run as
  you, in Docker Desktop, or **in a VM your everyday computer hosts** (UTM, OrbStack, Multipass,
  Parallels, VMware). That last one looks like a machine of its own and is not: the VM is a program
  running as you, and its disk is a file in your home folder, so anything running as you can open
  that file or take over the VM.

So **which computer hosts nervus decides the tier**, not whether it is a VM or a container:

| nervus runs as | on a separate computer | on your everyday computer |
|---|---|---|
| a VM | tier 1 | tier 3 |
| a container | tier 1 | tier 3 |
| a service under its own `nervus` account | tier 1 | tier 2 |
| a program run as you | — | tier 3 |

**What this preview supports** (ADR-0023):

| where | tier | in this preview |
|---|---|---|
| Linux on a separate computer: a VM or container on a hypervisor host, or a small box | 1 | **yes, recommended** |
| Linux on your everyday computer, under nervus's own account | 2 | yes |
| Linux in a VM your everyday computer hosts | 3 | yes; declare it as tier 3 |
| macOS natively | 2 or 3 | not yet: on a Mac with nothing else, run Linux in a VM the Mac hosts, tier 3 |
| Windows (WSL2) | 3 | not tested |
| a container image | 1 or 3 | not yet (ADR-0005 decision 1) |

**Never give nervus root on the machine it runs on.** If nervus's own machine is also one of the
machines it reaches, with root (the `agent` account and its `sudo`, step 3), then any agent can, through
nervus itself, read nervus's SSH key, its tokens and its audit log, and reach every other machine
as nervus. So do not put nervus on a server you also want agents to work on, unless that server is
not one of nervus's hosts, or is added read-only or standard: nervus refuses full access to its own
machine (ADR-0024).

**Nor full access to the machine underneath nervus.** If nervus runs as a VM or container, the
machine that hosts it can stop it and rewrite its disk, the audit log included. nervus cannot tell
which machine that is, so it cannot refuse: the Machines page asks you when you choose full access.
Add the host read-only or standard, and keep any hypervisor connection away from nervus's own guest,
as the `proxmox` tool does. nervus's audit log is out of every client's reach without that, and
needs no copy anywhere else (ADR-0007 decision 8, as ADR-0025 amended it).

## What you need

- **A machine for nervus, where the table above says**: on a separate computer, a small container
  or VM is enough. Linux with systemd, and Python 3.11 or later; tested on Debian 13 with Python
  3.13, Ubuntu 24.04 with Python 3.12 and Ubuntu 26.04 with Python 3.14. Root there, once, to run
  the installer.
- **This repository on that machine**: a clone, or a copy (see "By hand" for an archive). The
  installer installs exactly the committed tree it sits in.
- **An admin login on each machine nervus will reach, once**: root's, or an account that can use
  `sudo`, with its password, given in the web UI (step 3); or root there, to run two lines
  instead. Linux with an SSH server and `curl`; nervus installs what else the level needs, and
  `tmux` for background jobs. After that nervus needs no password anywhere, and keeps none.
- **SSH from nervus's machine to each of them.**
- **A client:** Claude Code, Codex or Cursor (`docs/clients.md`).
- **A place to keep the recovery key**, which opens nervus's backups: a password manager, or paper.

Commands below marked **on nervus** run on nervus's machine; **on a host**, as root on a machine
nervus will reach.

## 1. Make nervus's machine

**Tier 2, on your everyday Linux computer:** nothing to make; the installer gives nervus its own
account there. Go on to "Decide how clients will reach it".

Otherwise, a small unprivileged container or VM: one CPU and 512 MB of memory is plenty. On Proxmox, an
LXC container from the Debian 13 template works; give it **nesting** (`--features nesting=1`),
or systemd 257 inside it starts degraded and the service's sandboxing fails with it.

Make sure it starts on boot.

**Decide how clients will reach it, before step 2: by a name, or by its address.** Clients reach
nervus over HTTPS, which checks that nervus's certificate is for the name or address they asked
for. The certificate holds the names the installer is given, and its issuer can vouch for no
other DNS name, so a name must be chosen first. An address can be added later (see "If nervus's
address changes"). Whichever you choose, **reserve nervus's address in your router** (a fixed DHCP
lease), so it stays put.

- **By name, where your network can give it one.** A new machine taking an address by DHCP
  usually has no name your other machines can find, and a `.local` name does not cross a VPN.
  Either a DNS record on your router, which every machine on your network then finds, or a line in
  `/etc/hosts` on each client machine (macOS or Linux), replacing the address and name:

  ```bash
  sudo sh -c 'printf "%s %s\n" "<nervus's address>" "<nervus's name>" >> /etc/hosts'
  ```

  Check from each client machine: `dscacheutil -q host -a name <nervus's name>` on macOS, or
  `getent hosts <nervus's name>` on Linux, prints nervus's address.
- **By address, where nothing answers for a name.** Nothing to set up on any client: use
  `https://<nervus's address>:8000/mcp` wherever this guide and `docs/clients.md` say
  `<nervus's name>`. The installer names the machine's own addresses in the certificate.

Only nervus's own machine needs either: the VMs and hosts it reaches are reached through nervus,
never by name from a client.

## 2. Run the installer

**On nervus**, in your copy of this repository:

<!-- install:installer -->
```bash
cd <your copy of this repository> && sudo ./install.sh --address <nervus's address> --name <nervus's name>
```

It runs as root: in a root shell, as on a fresh container with no `sudo`, leave `sudo` off and run
`./install.sh` with the same arguments. Leave out `--name` if your network gives nervus none;
`--name` may be given more than once. Then:

- It reads the machine first and changes nothing if anything it needs is missing (it names what),
  if your clone has uncommitted changes, or if nervus is already installed there, when it says which
  release runs and how to upgrade ("Upgrading"). Where `apt-get` exists, it installs what is missing
  itself.
- If it stops partway, it says so and gives the commands that remove what it made, so that you can
  put right what stopped it and run it again. Run again before that, it says the same.
- It shows what it will do and waits for `yes`.
- It installs nervus as the hand steps below do: its own account, the code and its venv, its
  folders, its SSH key, its TLS certificate for the address and names given and the machine's own
  addresses, its service, and its off switch, with no hosts and no tokens yet. Then it starts it.
- It makes **the recovery key** every backup of nervus is locked to (ADR-0027), and prints its
  private half **once**, after "nervus is installed and running". Keep it in a password manager or
  on paper, never on nervus's machine and never on a machine a client reaches at full access. It is
  the only thing that opens a backup: nervus keeps the public half, which can lock a backup but not
  open one. Lose it and every backup is lost with it; "Backups" below says how to make a new one.
- It sets up a backup once a day (`nervus-backup.timer`).
- It ends by printing **the root certificate's SHA-256**: keep it with your tokens, since each
  client machine compares it once. It also prints the command each client machine runs to trust
  nervus, and a sign-in link for the web UI.

`systemctl status nervus` then shows it active, and `journalctl -u nervus -n 20 --no-pager` shows it
serving on port 8000 (clients) and 8443 (web UI).

## 3. Sign in, choose the tier, and add the machines nervus reaches

**Sign in to the web UI** with the link the installer printed, in a browser on your network. It
works once, within 5 minutes; **on nervus**, `/opt/nervus/.venv/bin/nervus-ctl signin` prints
another.

**Choose nervus's tier** on the setup page, the first page you see (ADR-0015). Until you do, every
other page waits; your clients are not held back. The page says first what nervus does not defend
against, then asks which tier this installation is ("Where nervus may run"). nervus takes your word
for it and shows the tier at the top of every page, in its log at every start, and in `nervus-ctl
status`. If you move nervus, change it there.

The page also says which of the addresses nervus listens on look public. **Never forward a port on
your router to nervus**: nervus cannot see a forwarded port, so no warning can tell you about one;
to reach it from outside, use an overlay network such as Tailscale or WireGuard. If an address looks
public but the internet cannot reach it, because your network uses such addresses inside, declare
its range internal on the same page: the warning at the top of every page becomes a note naming
your declaration. An address in no declared range is still warned about.

Then, for each machine, on the UI's **Machines** page (ADR-0024, ADR-0026):

1. **Give it a name**, which your tokens will use, and **choose its level**:

   | level | what nervus can do there | what stops it doing more |
   |---|---|---|
   | read-only | read, and run programs, but not change any file outside its own folder `~/.nervus` | the machine's kernel (bubblewrap) |
   | standard | change only what its own account owns | no `sudo` |
   | full | anything, with `sudo` and no password | nothing |

   Read-only is the default. It means exactly what it says: nervus can still read anything its
   account can read, run programs, and reach the network from there; it cannot change the
   machine's files. Full makes nervus root-equivalent there; never choose it for the machine nervus
   runs on, which nervus refuses anyway ("Where nervus may run").
2. **Give the address**: the name or address nervus connects to. nervus's machine looks a name up
   in your network's DNS, as your other machines do; a `.local` name works only where nervus's
   machine runs mDNS (on Debian, `avahi-daemon` and `libnss-mdns`). On a network that hands out
   addresses, give the machine a name or a reserved address first; if it moves, the page lets you
   change it.
3. **Connect.** nervus connects to the machine's SSH server and shows the key it answered with,
   before you give it anything. If you have logged in to the machine before, check the key with
   either of these: the first on a computer that has logged in to it, the second on the machine
   itself.

   <!-- install:fingerprint -->
   ```bash
   ssh-keygen -lF <the machine's address>
   ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
   ```

   Each prints a `SHA256:` fingerprint, which must be the one the page shows. nervus shows the
   machine's ed25519 key, the one these name; a machine with none shows another type, and the page
   names the file to check in place of the second's. nervus sends your login only to the machine
   holding that key. If it does not match, stop: something else may be
   answering at that address.
4. **Log in once**, as root or as an account that can use `sudo`, with its password. nervus logs
   in, becomes root, directly or with `sudo` and that password, and runs its enrollment script
   there, the same script the two lines below run: the account `agent` with exactly nervus's key,
   the level, and the machine's SSH host keys sent back to nervus, which checks the level and only
   then adds the machine. A page shows each step as it happens, then the outcome, and the machine
   is in the list. Leaving that page does not stop it; Machines shows what became of it.

   **What nervus keeps:** the account name, in its audit log and beside the one-time code it made;
   never the password, which it holds in memory for that one enrollment. Whoever controls nervus
   at that moment could see it. If the host keys the machine sends back do not include the one
   that answered the login, something between nervus and the machine may have answered instead:
   nervus refuses it, the script takes nervus's key off again, and the page tells you to change
   that password.

### Advanced: two lines run on the machine yourself

Use these instead of Connect where the machine takes only SSH keys, no password; where only `su`
reaches root there; where you do not trust the network between nervus and the machine (Connect
trusts the first key it is shown, and the password passes through nervus); or where you want to
read the script before it runs. On the Machines page, give the name and level, and choose
**Advanced: two lines to run on the machine yourself**. The address may be left blank here, to use
the one the machine reaches nervus from. The page shows two lines, once. **On the machine, as
root**, run them:

<!-- install:enroll -->
```bash
curl -fsSk --pinnedpubkey 'sha256//<nervus's key>' -o nervus-enroll.sh 'https://<nervus>:8000/enroll/<one-time code>'
less nervus-enroll.sh && sh nervus-enroll.sh
```

The first fetches nervus's enrollment script, and refuses any server whose key is not nervus's (`-k`
only stops curl asking the machine's own certificate authorities, which do not know nervus's). The
second shows you the script; read it, quit with `q`, and it runs. It makes the account `agent` with
exactly nervus's key, sets up the level (installing bubblewrap for read-only, or `sudo` for full,
with `apt-get` if missing, and `tmux` for background jobs at every level), and sends the machine's
SSH host keys back to nervus. Where the machine's AppArmor keeps bubblewrap from making user
namespaces, as Ubuntu 24.04's does (26.04 lets it through, by a profile of Ubuntu's own), read-only
also gives nervus its own copy of bubblewrap, which only `agent` may run, an AppArmor profile
letting that copy alone make them, and an apt hook keeping the copy up to date (ADR-0024 question
9); another level, or removal, takes all three off. nervus then logs in with those keys, checks the
level, and only then adds the machine. The script ends by saying so, and the Machines page lists it.
The lines work once, within 15 minutes; the script checks its code first, so a used or expired one,
or a copy left from an earlier try, changes nothing. If anything fails, the script says why, and you
make new ones. If nervus does not add the machine, the script takes nervus's key off again; at full,
on the machine nervus runs on, it refuses before changing anything.

**What a machine needs:** Linux with an SSH server and `curl`. For Connect, also a password login
over SSH for root or for an account that can use `sudo`; most machines refuse root's password over
SSH (OpenSSH's `PermitRootLogin`), so an account with `sudo` is the usual one. A machine you would
rather set up yourself is done by hand ("By hand: a machine nervus reaches"); a Mac is not covered
yet.

**This needs nervus over HTTPS**, as the installer sets it up: the machine checks nervus's key
before it runs anything nervus sends. Over plain HTTP the page says so, and neither connects nor
makes commands.

**Later:**
- **To reinstall a machine, or change its level**, add it again under its name, by Connect or the
  two lines. Don't remove it first: the tokens that name it keep reaching it. If the change gives
  tokens something new (a higher level, or a name a removed machine had), the page lists them and
  asks you to type the name.
- **To remove a machine**, use Remove on the Machines page. nervus forgets it at once, and the page
  shows these commands to run on the machine as root, which take nervus's account and key off it:

  <!-- install:remove -->
  ```bash
  pkill -KILL -u agent; sleep 1
  userdel -r agent
  rm -f /etc/sudoers.d/nervus-agent
  apparmor_parser -R /etc/apparmor.d/nervus-bwrap 2>/dev/null; rm -f /etc/apparmor.d/nervus-bwrap /etc/apt/apt.conf.d/99nervus-bwrap
  rm -rf /usr/local/lib/nervus
  ```

  It also lists the tokens that still name the machine; revoke them on the Clients page if a machine
  given that name later should not be reachable by them.

## 4. Connect your clients

- **Issue a token for each client and project**, on the UI's Clients page, choosing the machines it
  may reach (ADR-0001 s6, ADR-0014). The UI shows it once; keep it where you keep secrets: it goes
  to the client, never into a repository.
- **On each client machine**, in your clone of this repository: save nervus's root, comparing it
  with the value the installer printed, then run `tools/nervus-status` (`docs/clients.md`, "Trust
  nervus's certificate" and "Check it"). Green there means a client will work.

  ```bash
  tools/nervus-trust https://<nervus's name or address>:8000/mcp --expect '<the root certificate SHA-256 the installer printed>'
  ```
- **Wire up the clients:** `docs/clients.md`. After a client's first call, find it in the UI's audit
  log under its token id.

## 5. Check that your recovery key opens a backup

A backup nobody can open is the usual way backups fail, and only you, holding the recovery key,
can show yours is not that. On the UI's **Backups** page, press **Make a backup now**, and note its
name. Then **on nervus**, with the recovery key to hand, paste it when asked; it is not shown or
saved:

<!-- install:backup-check -->
```bash
sudo /opt/nervus/.venv/bin/nervus-ctl backup --check <the backup's name>
```

"the check passed" means the key opens it, it is whole, and its audit log is the start of nervus's.
It changes nothing. Do it again after each upgrade; the Backups page shows when one last passed.

It reads the key from the terminal whenever there is one, even when the key is piped in, so at a
terminal, paste it. Only where there is no terminal, a script run by a timer say, does it read it
from standard input: a pipe, never a file. A restore run that way needs `--yes` as well, or it reads
its go-ahead from the same place.

## A Proxmox host, if you have one

nervus can reach a Proxmox host at two levels (ADR-0009): a shell without sudo, with the `proxmox`
tool for the API, for every client; and root, for one client at most. This preview supports nervus
running as a container on that same host. Three scripts do the root work, each run once **on the
Proxmox host**, each saying at its top what it does and stopping at the first thing that is not as
expected:

- `tools/proxmox-access`: nervus's scoped API user, role and token, kept out of nervus's own
  container, and written into it as `secrets/proxmox.yaml`.
- `tools/proxmox-accounts`: the `observer` and `agent` accounts, each trusting nervus's certificate
  authority alone, as a machine added on the Machines page does (ADR-0025), and the host's keys pinned
  in nervus. It asks for the authority's fingerprint, read somewhere other than this host so a
  wrong one stops it: `ssh-keygen -lf ~agent/.ssh/authorized_keys` on a machine nervus already
  reaches, or, before there is one, `ssh-keygen -lf /opt/nervus/secrets/nervus_ca_ed25519.pub` on
  nervus as the installer left it. The root level is the machine underneath nervus ("Where nervus may run"): a client given
  it can stop nervus and rewrite its audit log, so give it to none, or to the one you would trust
  with nervus itself.
- `tools/proxmox-template`: a VM template agents can clone and use through the API alone
  (ADR-0017).

Then mark the hypervisor entry in the inventory (`hypervisor: proxmox`, as the example shows; and
`issue: never` on a root entry, if you made one), and **on nervus**, once `tools/proxmox-access`
has written `secrets/proxmox.yaml`:

<!-- install:installer-proxmox -->
```bash
cd <your copy of this repository> && sudo ./install.sh --proxmox --address <nervus's address>
```

It adds two flags to nervus's drop-in and restarts it: `--proxmox`, and `--upload-pull-url`, which
is where a VM fetches a file a client uploads to it, at network speed: by the address the installer
put in the certificate, checked against nervus's root, which nervus hands the VM with each file
(ADR-0022). Without it, every file goes through Proxmox's guest agent, at about 0.17 MB/s and at
most 32 MiB. If you serve MCP over plain HTTP ("By hand", the service), make the address `http://`
in the drop-in by hand.

## If nervus's address changes

Clients that reach nervus by name need nothing, once the name points to the new address. For
clients and VMs that use the address, add the new one to nervus's certificate **on nervus**. It is
re-issued from the same issuer, so every client keeps the root it saved, and a running nervus
loads it by itself; a browser asks once more:

<!-- install:tls-reissue -->
```bash
cd /opt/nervus && runuser -u nervus -- .venv/bin/nervus tls-reissue --name <nervus's new address>
```

Then change the address in each client's URL, and in your drop-in's `--upload-pull-url`, and
restart nervus for the drop-in. Only an address can be added this way: a name nervus's issuer was
not made for can never be vouched for.

## Backups

**What a backup holds** (ADR-0027 question 1): everything nervus cannot make again without
touching your machines or your clients: its SSH key and certificate authority, its TLS keys and
certificates, its token file, inventory and pinned host keys, any Proxmox settings, the off switch,
the recovery key's public half, its unit's drop-in, its database, and its whole audit log, all taken
at one moment. Not the code, which a newer tree installs again, and not files passing through
(exports, uploads, `transfer/`).

**How it is kept.** nervus writes each backup into `/var/lib/nervus/backups`, readable by nervus
alone, locked to the recovery key, once a day and whenever you press the button. It keeps one a day
for a week, one a week for a month and one a month for a year, and nothing older. Each carries the
whole audit log, so they grow with it; `nervus-ctl status` says how much space they take. A day
without a new backup is a warning on every page of the web UI and in `nervus-ctl status`.

**Where to keep copies.** A backup beside nervus survives a mistake on nervus's machine, not the
machine itself. Since each is locked to the recovery key, a copy can go anywhere; only the key needs
a careful home:

| nervus's tier | a backup beside nervus survives | keep copies |
|---|---|---|
| 1 | a mistake on nervus's machine | on your everyday computer, or anywhere: download one from the Backups page now and then |
| 2 or 3 | a mistake on nervus, **not losing your computer** | on another disk, or storage elsewhere |

**A backup of nervus's whole machine**, by its hypervisor or anything else, carries the backups
folder too. As it comes, though, it also holds every secret of nervus's **unlocked**, and its
records: whoever can read it can act as nervus. Leave out nervus's secrets and records, and the
files passing through it, each folder by its contents, so the folders stay, owned and permissioned,
for a restore to write into. Its records include its own log, in the system's journal: which
machines nervus reached and when, and the paths of files clients sent or fetched, but not a client's
command. A restore needs none of it.

<!-- install:machine-backup-leaves-out -->
```
/opt/nervus/secrets/*       keys, tokens, certificates, a hypervisor's credentials
/opt/nervus/transfer/*      clients' files in passing
/var/lib/nervus/nervus.db*  the database and its write-ahead files
/var/lib/nervus/tls/*       a renewed certificate
/var/lib/nervus/exports/*   clients' files in passing
/var/lib/nervus/uploads/*   clients' files in passing
/var/lib/nervus/replaced-*  what a restore replaced: secrets in clear
/var/log/nervus/*           the audit log
/var/log/journal/*          the system's journal: nervus's own log
```

Where the system also copies its journal into files, as `rsyslog` does into `/var/log/syslog` or
`/var/log/messages`, leave those out too. What stays is the rest of the system, nervus's code, its
inventory and off switch, and its backups, each locked to the recovery key. A machine brought back
from such a copy holds a nervus that refuses to start, for want of its secrets, until `nervus-ctl
restore` puts one of those backups in place with the recovery key, as on the same machine (below).
Keep the copy out of every client's reach all the same.

**On Proxmox**, each line is one `--exclude-path`, to `vzdump` or in a backup job:

<!-- install:vzdump-leaves-out -->
```bash
vzdump <nervus's container> --tmpdir <its scratch folder> --exclude-path '/opt/nervus/secrets/*' --exclude-path '/opt/nervus/transfer/*' --exclude-path '/var/lib/nervus/nervus.db*' --exclude-path '/var/lib/nervus/tls/*' --exclude-path '/var/lib/nervus/exports/*' --exclude-path '/var/lib/nervus/uploads/*' --exclude-path '/var/lib/nervus/replaced-*' --exclude-path '/var/log/nervus/*' --exclude-path '/var/log/journal/*'
```

Proxmox writes its dumps readable by every account on the host, so keep them in a folder only root
can open. Then give an unprivileged container's dump a scratch folder of its own, `--tmpdir`:
`0700`, owned by the container's root as the host sees it (`100000`, unless the container maps its
ids otherwise). In suspend mode, which a container whose storage cannot take a snapshot falls back
to, the dump is copied into the scratch folder and packed from it as that id. Left in its default
place, inside the folder only root can open, the scratch folder shuts the packing out, and every
dump fails.

**Restoring on the same machine**, after an upgrade or a mistake. **On nervus**, the backup's name
as the Backups page or `ls /var/lib/nervus/backups` shows it:

<!-- install:restore -->
```bash
sudo /opt/nervus/.venv/bin/nervus-ctl restore <the backup's name>
```

It asks for the recovery key, from the terminal, as step 5 says, then checks the backup whole
before it changes anything: a damaged
backup, the wrong key, or a database from a newer release of nervus is refused there. Then it stops
nervus, moves what it replaces into a dated folder beside the database (`replaced-…`), never
deleting it, puts the backup in place, ends every sign-in, and starts nervus **in lockdown**: it
acts for no client until you have looked and lifted it, on the Clients page or with `nervus-ctl
unlock --all`. A client you had switched off stays off. Machines added and tokens issued after the
backup was made are not in it: the Machines page says so until the next backup; add them again.

**Restoring onto a new machine**, when nervus's machine is lost. Make the new one as in step 1,
**at the same name**: clients trust nervus by its name. Its address may change. Then, in place of
step 2, give the installer the backup, copied onto the new machine:

<!-- install:installer-restore -->
```bash
cd <your copy of this repository> && sudo ./install.sh --restore <the backup> --address <nervus's address> --name <nervus's name>
```

It installs as step 2 does but makes no keys: it runs the restore above, which asks for the
recovery key. Your clients and machines then trust the restored nervus as before. If clients reach
it by an address the old one did not have, add it ("If nervus's address changes").

**If nervus will not start**, it says why, in its journal (`journalctl -u nervus -n 20 --no-pager`).
After a restore that left a piece out, or a mistake, it refuses rather than start as someone else:

- **a key that is missing, or not the one its database was made with:** restore that key, or the
  whole backup. If you replaced it on purpose, `sudo /opt/nervus/.venv/bin/nervus-ctl accept-keys`
  shows what differs and what replacing it costs, and asks you to name it.
- **no database, where its audit log shows it has run; or a database without its audit log:**
  restore a backup, or, to start empty on purpose, `sudo /opt/nervus/.venv/bin/nervus-ctl
  start-empty`. Each is recorded.

**A new recovery key**, if you lose yours or want another: `sudo /opt/nervus/.venv/bin/nervus-ctl
recovery-key --replace`. Backups made before it stay locked to the old key: keep it as long as you
keep them, and check a backup made after.

**The last resort, without nervus.** A backup is a standard `age` file holding a `tar.gz`: on any
machine with `age` and the recovery key in a file, `age -d -i <key file> <backup> | tar -xz` gives
`manifest.json`, which says where each piece lived, its mode and its SHA-256, and `pieces/`, each
piece by its role. Put each back by hand, owned by `nervus`, with that mode, and delete the key file
and what you unpacked once you are done: they hold every secret of nervus's.

**What a backup is not for:** recovering from a compromised nervus. A backup brings back the same
keys, and so whatever an attacker took with them. That needs new keys and every machine and client
enrolled again.

## Upgrading

A newer release goes over the one you have with one command, and keeps everything of yours: nervus's
address, keys, tokens and machines, its database and its audit log. No client's configuration
changes. Any release goes to any newer one in one upgrade, so you may skip some (ADR-0029). This is
shown by tests and by a trial on throwaway machines.

**First, read what changed.** `CHANGES.md`, at the top of this repository, says for each release
what you will see, what each client must do, and what the upgrade does on nervus's machine.

**Then bring the newer release to nervus's machine**, as you brought the first:

- **A clone:** `git pull` in it. On tier 1 that needs your access to this repository from nervus's
  machine, as cloning it did.
- **An archive**, made on your own computer and copied over ("By hand", The code): unpack it in a
  folder of its own, not over the old copy. Check its SHA-256 before you unpack it, since the upgrade
  runs from the folder and cannot see the archive.

The upgrade runs as root what that copy holds, as the install did. On tiers 2 and 3 the copy is
within reach of your own account, so a program running as you could change it first: no weaker than
the install was, and no stronger. On tier 2, a package the upgrade adds goes onto your everyday
computer.

**On nervus**, in that copy:

<!-- install:installer-upgrade -->
```bash
cd <your copy of this repository> && sudo ./install.sh --upgrade
```

As at install, in a root shell leave `sudo` off. Then:

- It reads the machine first and changes nothing if this copy holds an older release, or the one
  installed already ("nothing to do"); if your clone has uncommitted changes; if something it needs
  is missing with no `apt-get` to install it; if this installer did not install nervus here; if its
  drop-in has been changed by hand (it says where); if the database is newer than this release
  knows; or if nervus's off switch cannot be read, since nervus refuses every client then, and only
  you can say what the file should hold.
- It shows what it will do and waits for `yes`: which release to which, each by the name of its
  folder and, from a clone, its commit; each release's section of `CHANGES.md` in between; the
  packages it adds; the drop-in, if it changes; whether the database's version moves; what the off
  switch says; and when the recovery key last opened a backup.
- It builds the new release beside the running one, in `/opt/nervus/releases/`, while nervus serves
  on. If its libraries cannot be fetched it stops there, with nervus running as it was. Anything the
  new release needs that this installation lacks, such as a key, is made here too.
- It makes a backup, by the running release, and goes no further without one.
- It stops nervus, switches to the new release and starts it, which takes a few seconds. What
  clients see then is in `docs/clients.md`, "After nervus is upgraded".
- It checks that nervus is up as its clients need it, not merely running: steady under systemd,
  answering MCP and its web UI over HTTPS checked against its own root, within a minute of starting,
  and saying nothing at its start about refusing clients.
  **If it is not, it goes back to the release before by itself**, says why with nervus's last lines,
  and leaves the new release's folder and its journal for reading. So it does if a step after the
  stop fails, or the run is interrupted, by Ctrl-C or a dropped connection. The audit log records the
  upgrade's start and how it ended.

**Afterwards**, as it ends by saying: check the backup it made with the recovery key, as step 5 says,
and do what `CHANGES.md` says each client must do, which is often nothing.

**Going back**, if the new release is up but not what you want. In the same copy, or any with this
script, since it installs nothing from it:

<!-- install:installer-back -->
```bash
cd <your copy of this repository> && sudo ./install.sh --back
```

It shows what it will do and waits for `yes`, then puts back the release kept from the last upgrade,
as going back after a failed start does, and returns by itself if that release does not come up. Only
the one release before is kept. The database stays as it is: the older release ignores any table it
does not know, and the newer finds them as it left them if you upgrade again, which is the way
forward. **It is refused once a release has raised the database's version**, as the upgrade's plan
says one is about to, since the older release could not read it: only the backup made before the
upgrade holds a database it can use, and restoring that loses everything done since ("Backups"). It
is refused too while nervus's off switch cannot be read, since every release refuses every client then.

Never install a newer tree over an installation in any other way: its release's folder would then
hold other code than its name says, which the upgrade relies on.

## Rough edges in this preview

- No container image.
- Each client machine saves nervus's root once (`tools/nervus-trust`); the connector that would
  remove even that step is later work (ADR-0008). Cursor is not yet tested with it.
- The machines nervus reaches must be Linux: a Mac is not covered, from the UI or by hand.
  Read-only is tried on Debian 13, on Ubuntu 24.04, whose AppArmor has nervus give its own copy of
  bubblewrap a profile (step 3), and on Ubuntu 26.04, which lets bubblewrap through itself; Ubuntu's
  other releases are not tried.
- The installer is meant for Debian and Ubuntu; elsewhere it says what it needs, and "By hand"
  says what it does.

## By hand: what the installer does

For reading, for a Linux the installer does not know, or to install from an archive rather than a
clone. **On your own machine**, the archive, then the steps **on nervus**. An installation made by
hand is upgraded by hand: the installer's upgrade takes only installations the installer made
(ADR-0029).

### The code

What runs should be exactly a committed state, so take a `git archive` of a commit, not a
working copy. **On your own machine**, in your clone of this repository:

<!-- install:by-hand-archive -->
```bash
git archive --format=tar.gz -o nervus.tar.gz HEAD
shasum -a 256 nervus.tar.gz
```

Copy `nervus.tar.gz` to nervus's machine however you copy files there, and check that the same
SHA-256 comes out there. Then, **on nervus:**

<!-- install:by-hand-code -->
```bash
umask 022
apt-get install -y python3-venv
install -d -m 0755 /opt/nervus /opt/nervus/releases /opt/nervus/releases/new
tar -xzf nervus.tar.gz -C /opt/nervus/releases/new --no-same-owner && rm -f /opt/nervus/releases/new/hosts.yaml
release=$(python3 -I /opt/nervus/releases/new/tools/release-name /opt/nervus/releases/new) && mv /opt/nervus/releases/new "/opt/nervus/releases/$release"
useradd --system --home-dir /opt/nervus --shell /usr/sbin/nologin nervus
python3 -m venv "/opt/nervus/releases/$release/.venv"
"/opt/nervus/releases/$release/.venv/bin/pip" install "/opt/nervus/releases/$release"
ln -s "releases/$release/.venv" /opt/nervus/.venv
install -d -m 0700 -o nervus -g nervus /opt/nervus/secrets
install -d -m 0750 -o nervus -g nervus /opt/nervus/transfer
install -d -m 0750 -o nervus -g nervus /var/log/nervus
```

Stay in this root shell for the steps below: the first line keeps a stricter umask of yours from
making the venv something only root can read, and the installer sets the same one for itself. The
code goes in a folder of its own, as the installer puts it (ADR-0029 question 3a), named by
the installer's own `tools/release-name` for the release's number and a code worked out from its
files, such as `0.2.0-42c0b5a132ef`. Below, `<release>` is that name: `ls /opt/nervus/releases`
prints it. The tree's own `hosts.yaml` is not the installation's, which is written below. The venv
is built inside the release's folder and filled by its own `pip`, since a venv's scripts name the
path they were installed at and it cannot be moved; `/opt/nervus/.venv` is a link to it, so the
service and every command in this guide keep their paths. The code is root's, unpacked as root's
whoever owned the archive, and the account `nervus` can read it but change none of it, nor the link
(ADR-0029 question 12): the account owns only its folders above, the inventory and token file
below, and the keys it makes.

`python3-venv` is Debian's name; without it, `python3 -m venv` fails on Debian 13. Other
distributions name it differently or include it.

If a line fails, put right what it says, then start the block again from a clean slate:
`rm -rf /opt/nervus`, and `userdel nervus` if the account was made. Run again over what a failed
run left, the block would put a second copy of the tree inside the release's folder, without an
error.

Check: `readlink /opt/nervus/.venv` prints `releases/<release>/.venv`, and
`/opt/nervus/.venv/bin/nervus --help` prints nervus's options.

### nervus's SSH key

The one credential that reaches your machines. It lives on nervus's machine and nowhere an agent
can read it (ADR-0001 s3). **On nervus:**

```bash
runuser -u nervus -- ssh-keygen -t ed25519 -N '' -C nervus -f /opt/nervus/secrets/nervus_ed25519
cat /opt/nervus/secrets/nervus_ed25519.pub
```

Beside it, the certificate authority nervus signs a short certificate with for each call, so each
machine's own log names the client behind every login (ADR-0025). Kept the same way; nervus will
not start without it. **On nervus:**

```bash
runuser -u nervus -- ssh-keygen -t ed25519 -N '' -C nervus-ca -f /opt/nervus/secrets/nervus_ca_ed25519
cat /opt/nervus/secrets/nervus_ca_ed25519.pub
```

Machines trust the certificate authority's public line, not the key's: keep it for "By hand: a
machine nervus reaches"; enrolling from the UI puts it in the script itself. Revoking nervus later
is removing that line from each machine's `authorized_keys` (or the key's own line, on a machine
not yet moved: "Moving a machine to nervus's certificate authority").

### An empty inventory and token file

<!-- install:by-hand-empty -->
```bash
printf 'hosts: []\n' > /opt/nervus/hosts.yaml && chown nervus:nervus /opt/nervus/hosts.yaml
(umask 077; printf 'tokens: []\n' > /opt/nervus/secrets/tokens.yaml) && chown nervus:nervus /opt/nervus/secrets/tokens.yaml
```

The web UI issues tokens (ADR-0014). The token file can also hold them, one per client and project,
which nervus reads at start:

```yaml
tokens:
  - token: <a long random value>
    id: claude-code-project-a
    client: claude-code
    project: project-a
    hosts: [node-a, node-b]
```

Make each value with `python3 -c 'import secrets; print(secrets.token_urlsafe(32))'`.

### nervus's TLS certificate, once

Off loopback nervus serves HTTPS (ADR-0010), with a certificate from a small certificate authority
of its own (ADR-0021): a root, an issuer that can vouch for no DNS name but nervus's own (it does
not limit addresses; `docs/clients.md`, "Trust nervus's certificate", says what that means), and
nervus's certificate under it. Each client machine trusts the root, one file, once ("Connect your clients"). Making them is
a deliberate act: nervus never makes them by itself, and the root's own key is never saved, so
nothing can ever sign with it again. **On nervus**, naming every name clients and browsers will
use to reach it (a name cannot be added later), and its address:

<!-- install:tls-init -->
```bash
cd /opt/nervus && runuser -u nervus -- .venv/bin/nervus tls-init --bind-host 0.0.0.0 --name <nervus's name> --name <nervus's address>
```

- It needs at least one DNS name. The machine's hostname counts; `--name` adds the one your
  clients use, whether it is in DNS, in `/etc/hosts` or a `.local` name. It never names
  `localhost`.
- It also names the machine's own addresses, as `ip address` shows them, and prints every name and
  address it used. `--name <nervus's address>` makes sure the one your clients and VMs use is among
  them: VMs fetch files from nervus by it (see "A Proxmox host"), so they need no name.
- It writes five files in `secrets/`: nervus's key and certificate, the issuer's key and
  certificate, and the root, `tls-root.crt`.
- It prints two fingerprints. **Keep the root's, "root certificate SHA-256", with your tokens:**
  each client machine compares it once ("Connect your clients"), and `nervus tls-fingerprint` prints it again here.
  The other, the public key's, is what a connector will compare (ADR-0008).
- A browser shows a third value, nervus's own certificate's fingerprint; `nervus-ctl signin`
  ("Connect your clients") prints that one.

**Installed before ADR-0021?** If `tls-init` made a single self-signed certificate,
`runuser -u nervus -- .venv/bin/nervus tls-init --upgrade --name <nervus's name>` puts it under
nervus's own authority and keeps its key. Browsers that accepted the old certificate ask once
more; a running nervus loads the new one by itself.

### The service

The unit is `deploy/nervus.service`: secure by default, every address, HTTPS, no Proxmox tool
(ADR-0019 D2). Your installation's own flags go in a drop-in that restates its `ExecStart`. **On
nervus:**

```bash
install -m 0644 /opt/nervus/releases/<release>/deploy/nervus.service /etc/systemd/system/nervus.service
install -d -m 0755 /etc/systemd/system/nervus.service.d
```

Then `/etc/systemd/system/nervus.service.d/instance.conf`, mode `0644` since each backup reads it as
nervus's account: `[Service]`, an empty `ExecStart=`, and the unit's whole `ExecStart` again with your
flags added, at least `--ui-url https://<nervus's name>:8443`, where sign-in links point.

**MCP is HTTPS.** As the unit has it, MCP and the UI are both served over HTTPS with the
certificate above, and a client trusts it once its machine has saved the root.
nervus renews its own certificate before it expires, writing the renewal to
`/var/lib/nervus/tls/`; there is nothing to do. On a private network you control you may instead
add `--insecure-plain-http` to the drop-in, which serves MCP, not the UI, over plain HTTP. Tokens
then cross your network unencrypted, readable by any device on it that has been compromised, and
nervus warns about it at every start.

The off switch must exist before nervus starts, or it refuses every client (ADR-0003, question A):

```bash
/opt/nervus/.venv/bin/python /opt/nervus/releases/<release>/tools/ensure-switches --owner nervus /var/lib/nervus/switches.yaml
systemctl daemon-reload && systemctl enable --now nervus
journalctl -u nervus -n 20 --no-pager
```

The journal should show nervus serving MCP on port 8000 and the UI on 8443, and nothing that says
it refused to start.

### The recovery key and the daily backup

`age` must be installed (Debian and Ubuntu: `apt-get install age`). Once the journal shows nervus
serving, make the recovery key; it prints the private half once, to keep as step 2 says. Not before:
nervus makes its database as it first starts, and the key's record in the audit log, written before
that, would stop nervus starting, as if its database had been lost. Then the backup's service and timer:

```bash
/opt/nervus/.venv/bin/nervus-ctl recovery-key
install -m 0644 /opt/nervus/releases/<release>/deploy/nervus-backup.service /opt/nervus/releases/<release>/deploy/nervus-backup.timer /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now nervus-backup.timer
```

### With a Proxmox host

`install.sh --proxmox` adds these two lines at the end of the drop-in's `ExecStart`:

<!-- install:proxmox-flags -->
```
    --proxmox /opt/nervus/secrets/proxmox.yaml \
    --upload-pull-url https://<nervus's address>:8000/upload-pull
```

## By hand: a machine nervus reaches

For a machine you would rather set up yourself, instead of step 3's Machines page. This gives
nervus full access there. The commands are Linux's; a Mac needs the same account, key and sudoers
line made with its own tools, which this preview does not cover.

What to put on each is nervus's certificate authority, not its key (ADR-0025): the machine then
admits only the short certificates nervus signs for each call, and its own log names the client
behind every login. Its public line, **on nervus**: `cat /opt/nervus/secrets/nervus_ca_ed25519.pub`.

nervus logs in as `agent`: locked password, one line trusting nervus's certificate authority, and passwordless sudo
(`sudo` must be installed; `visudo` below comes with it),
which makes it root-equivalent, named as such (ADR-0001 s4). Every client shares it; the audit
log, not the account, tells them apart. **On a host**, keeping a root session open until the last
check passes, so a bad sudoers file cannot lock you out:

```bash
useradd --create-home --shell /bin/bash agent
passwd --lock agent
# optional: the same supplementary groups as your own account, e.g. usermod -aG docker agent
printf 'agent ALL=(ALL) NOPASSWD: ALL\n' > /tmp/agent.sudoers
visudo -cqf /tmp/agent.sudoers && install -m 0440 -o root -g root /tmp/agent.sudoers /etc/sudoers.d/agent
visudo -cq
install -d -m 0700 -o agent -g agent ~agent/.ssh
printf 'cert-authority %s\n' '<certificate authority line>' > ~agent/.ssh/authorized_keys
chown agent:agent ~agent/.ssh/authorized_keys && chmod 0600 ~agent/.ssh/authorized_keys
```

Check that sshd lets the account in: `sshd -T | grep -iE '^(usepam|pubkeyauthentication|allowusers|allowgroups)'`
should show `usepam yes`, `pubkeyauthentication yes`, and no `AllowUsers` or `AllowGroups` that
leave `agent` out.

**Pin each host's key on nervus.** Read the host's public keys off the host itself (`cat
/etc/ssh/ssh_host_*_key.pub` in the root session you trust), not by asking the network, and write
them to `/opt/nervus/secrets/known_hosts` as `<address> <type> <key>`, one line each, `0600
nervus`. `<address>` is the one you will put in the inventory.

**Check, on nervus,** as nervus will connect: with a certificate signed for five minutes, kept
in a folder of its own and removed after.

<!-- install:by-hand-check -->
```bash
d=$(mktemp -d) && cp /opt/nervus/secrets/nervus_ed25519.pub "$d/" && chown -R nervus "$d" && \
runuser -u nervus -- ssh-keygen -q -s /opt/nervus/secrets/nervus_ca_ed25519 -I 'operator check-by-hand' \
  -n agent -V -5m:+5m "$d/nervus_ed25519.pub" && \
runuser -u nervus -- ssh -F /dev/null -i /opt/nervus/secrets/nervus_ed25519 \
  -o CertificateFile="$d/nervus_ed25519-cert.pub" -o IdentitiesOnly=yes \
  -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/opt/nervus/secrets/known_hosts \
  agent@<address> 'id -un; sudo -n id -un'; rm -rf "$d"
```

It must print `agent`, then `root`, with no prompt. nervus's key without the certificate must be
refused: the same `ssh` line without `CertificateFile` says `Permission denied`.

**Then the inventory, on nervus:** describe each machine in `/opt/nervus/hosts.yaml`, as
`docs/hosts.example.yaml` shows, and restart nervus, which reads the inventory at start:

```bash
systemctl restart nervus
```

**Never one of these with root: nervus's own machine** ("Where nervus may run").

A machine described here keeps full access, and the Machines page does not change it; a name in
`hosts.yaml` cannot also be enrolled there.

## Moving a machine to nervus's certificate authority

A machine given nervus's key itself, by hand or enrolled before ADR-0025, still works: nervus offers
its key after the certificate. But that machine's log cannot tell one client from another. Moving it
changes one line, and needs a nervus that signs certificates (this version on); before that, the
machine would refuse nervus.

- **Added on the Machines page:** add it again under its name, at the same level, as step 3 does.
  Its tokens keep reaching it; the new line replaces the old.
- **Described in `hosts.yaml`, or any machine by hand:** **on the machine**, as root, replace
  `agent`'s line, then run the check above from nervus.

At standard or full access:

<!-- install:move-standard -->
```bash
printf 'cert-authority %s\n' '<certificate authority line>' > ~agent/.ssh/authorized_keys
```

At read-only, keeping the forced command that makes it read-only:

<!-- install:move-read-only -->
```bash
printf 'cert-authority,restrict,command="/usr/local/lib/nervus/readonly-shell" %s\n' '<certificate authority line>' > ~agent/.ssh/authorized_keys
```

Its log then names the client and the run behind every nervus login, as
`ID token=<id> run=<run>`; the run finds the call in nervus's audit log.
