# Connecting a client to nervus

How an AI client (Claude Code, Codex, Cursor) reaches your machines through nervus: connecting,
checking, saving a file from a host or VM onto your own machine, and making a VM to work in.
Replace `<nervus>` with the name your clients reach nervus by. Each section says which decision
record (`decisions/`) explains why it works this way.

## What a client needs

```
URL     https://<nervus>:8000/mcp
Auth    Authorization: Bearer <token>
Trust   nervus's root, saved once on the client's machine (below)
```

**One token per client and project**, for example Claude Code in project A and Codex in project
A each get their own (ADR-0001 s6). Every client reaches a host as the same `agent` account, so
the audit log is the only thing that tells their work apart, and it can only do that if no two
share a token.

Use the name of the nervus machine, one its certificate is for, not an address a DHCP server may
move.

## Trust nervus's certificate, once per machine (ADR-0021)

nervus serves HTTPS with a certificate from a small certificate authority of its own. A client's
machine trusts its root, one file, and each client is told about it in its own setting, never in
the operating system's trust store, so the trust stays with the programs that use nervus. The
root's own key was thrown away when it was made, and the issuer under it can vouch for no DNS
name but nervus's, so the file cannot be used to impersonate any other site your clients reach by
name. It does not limit addresses, because Claude Code's TLS library refuses a limit written as
one: whoever held the issuer's key could impersonate, to your clients, a site they reach by an IP
address. That key is kept in nervus's `secrets/`, beside nervus's SSH key, and nervus lets it out
only inside a backup locked to your recovery key: anyone who has it has nervus's SSH key as well,
a far greater loss.

Save it once on each machine, in your clone of this repository:

```bash
tools/nervus-trust https://<nervus>:8000/mcp --expect '<root certificate SHA-256>'
```

`<root certificate SHA-256>` is the value `nervus tls-init` printed, or that `nervus
tls-fingerprint` prints on nervus's machine. Never take it from anything shown over the network:
that is what it checks. Without `--expect`, it shows the value and asks. It reads the root from
nervus's own handshake, saves it only on a match, checks nervus against it under the name given,
and prints each client's setting, below. It saves `~/.config/nervus/root-<nervus>.pem`; set
`NERVUS_CACERT` to that path in your shell too, since `tools/nervus-status` and the download
commands below read it. Beside it, it keeps `~/.config/nervus/roots.pem`, every nervus's root
saved there, for Claude Code, which takes one file. Cursor is not yet tested with it.

**Plain HTTP** remains possible on a network you control: nervus started with
`--insecure-plain-http` serves MCP over `http://`, and warns at every start, since tokens then
cross the network unencrypted. Use `http://` in the examples below, and leave out the root.

## Where the token lives

**Never in a repository.** The client's configuration names an environment variable or a
helper, and the token is supplied from outside.

There are two ways to supply it, each with a cost:

- **An environment variable.** The simplest. But it is readable by every process running as the
  same user (`ps -E` on macOS shows another process's environment), so a token delivered that way
  is delivered to everything on that machine (ADR-0006). **GUI apps on macOS inherit nothing from a
  terminal**, so for the Claude or Cursor desktop app the variable has to go into the login session
  (`launchctl setenv`, then quit and reopen the app; it lasts until logout). **For a client in a
  terminal,** on Linux or macOS, keep the token in a file only you can read, for example
  `~/.config/nervus/token-claude-code` (`chmod 600`), and export it from your login shell's file,
  `~/.profile` on Linux or `~/.zprofile` on macOS:
  `export NERVUS_CLAUDE_CODE="$(cat ~/.config/nervus/token-claude-code)"`. Log in again, or open a
  new terminal on macOS, and it is set.
- **The operating system's keystore, fetched by a helper when the client connects**
  (`tools/nervus-headers`, macOS's keychain). The token is never in any process's environment, and
  every read asks you first. The cost is that prompt: on every new session and every reconnect.
  Worth it for a token that reaches a lot (ADR-0009 decision 5).

To see whether a variable is set, print its length, never its value:
`printenv NERVUS_CODEX | wc -c`.

## Claude Code

A project-scoped `.mcp.json`, committed in the project that uses nervus.

**With an environment variable:**

```json
{
  "mcpServers": {
    "nervus": {
      "type": "http",
      "url": "https://<nervus>:8000/mcp",
      "headers": {"Authorization": "Bearer ${NERVUS_CLAUDE_CODE}"}
    }
  }
}
```

**With the token in the keystore.** Store it once, in the macOS keychain:
`security add-generic-password -a nervus -s <item> -w -T ""`, where `<item>` names the token, for
example `nervus-token-claude-code-project-a`. The `-T ""` trusts no application to read the item
without asking, so every read prompts you, as `tools/nervus-headers` relies on (procedure 009);
without it the keychain would let some programs read the token silently. Then:

```json
{
  "mcpServers": {
    "nervus": {
      "type": "http",
      "url": "https://<nervus>:8000/mcp",
      "headersHelper": "<path to nervus>/tools/nervus-headers <item>"
    }
  }
}
```

Claude Code runs the helper when it connects, and sends what it prints as the request headers.
The token then lives only in that Claude Code process's memory. macOS asks before each read;
never click "Always Allow", which would make the item readable by anything, silently.

**Trusting nervus's root**, either way: in `~/.claude/settings.json`, on macOS and Linux alike,
add

```json
{"env": {"NODE_EXTRA_CA_CERTS": "<the path nervus-trust printed for Claude Code>"}}
```

and start a new session: Claude Code reads it only when a session starts. Claude's desktop app
reads the same file, and a new session there is enough; the app itself need not be restarted.

The path is `~/.config/nervus/roots.pem`, written out in full: every nervus's root saved on this
machine. Claude Code takes one file, and this setting wins over the environment, so a file holding
one nervus's root alone shuts out every other nervus (`SELF_SIGNED_CERT_IN_CHAIN`). With
`roots.pem`, trusting another nervus later, a friend's or yours restored at another address, is
`tools/nervus-trust` for it and a new session; this line stays as it is. If `NODE_EXTRA_CA_CERTS`
is already set, for a company's root say, add nervus's roots to that file instead;
`tools/nervus-trust` says when a setting names another file. Tested on macOS, by a real call from a
new session in the desktop app, and on Linux, by a connection; one file holding two nervus roots,
by Claude Code 2.1.312 connecting to both (procedure 047).

**The first time you start Claude Code in the project**, it asks whether you trust the folder, and
to approve the project's `nervus`: say yes. Until you have, `claude mcp list` shows nervus as
"Pending approval", and a run with `claude -p` goes without it. Seen with Claude Code 2.1.319 on
Linux, whose first call through nervus then worked (procedure 054).

## Codex

**Codex's desktop app ignores MCP servers in a project's `.codex/config.toml`**, silently (openai/
codex issue 13025, open). The server has to be in the global `~/.codex/config.toml`, so it
applies in every project. That breaks "one token per client and project": a token named for one
project would be used from every project, and the audit log would say the wrong project, which is
worse than saying none. Three ways out:

1. **Name the token for what it is**, for example `codex-unscoped`, so the log never claims a
   project it cannot vouch for. The simplest; you lose telling Codex's projects apart.
2. **Use one project's token**, and only use Codex with nervus from that project. Nothing
   enforces it.
3. **Give each project its own Codex settings folder** (`CODEX_HOME`), which Codex does honour.
   Each project then has its own token, at the cost of separating all of Codex's state per
   project and launching it from a terminal with the folder set.

```toml
[mcp_servers.nervus]
url = "https://<nervus>:8000/mcp"
bearer_token_env_var = "NERVUS_CODEX"
```

Or, without editing the file: `codex mcp add nervus --url https://<nervus>:8000/mcp
--bearer-token-env-var NERVUS_CODEX`. The ChatGPT desktop app's "Connect to a custom MCP" dialog
writes the same file; choose its **Streamable HTTP** type.

**Trusting nervus's root:** `CODEX_CA_CERTIFICATE=<path to the root>` in Codex's environment. It
adds the root to the ones Codex already trusts. **Not `SSL_CERT_FILE`:** Codex then trusts that file
alone, and its own connection to OpenAI fails.

- **Codex's command line:** export it in the terminal Codex starts from.
- **The ChatGPT desktop app**, where Codex also runs, sees no terminal's variables. Put this one in
  the login session, as its token variable is, then quit the app completely (⌘Q) and reopen it. It
  lasts until you log out:

  ```bash
  launchctl setenv CODEX_CA_CERTIFICATE '<path to the root>'
  ```

Tested: the desktop app made a real call, approved; the command line connected and listed nervus's
tools, but made no call, since `codex exec` refuses any tool call that needs approval.

Codex asks for approval on every nervus call, and its default time limit per tool call is 60
seconds: longer work belongs in `exec_bg` (ADR-0001 consequences).

## Check it

`tools/nervus-status` speaks MCP exactly as a client does: name, port, certificate, token,
session, `hosts`, then a real command on every host in the inventory. Green there means a client
will work. It finds nervus as a client does, by a name in DNS, in `/etc/hosts` or a `.local` name,
or by address, and checks nervus's certificate against `NERVUS_CACERT` before it sends the token.

```bash
NERVUS_URL=https://<nervus>:8000/mcp NERVUS_CACERT=<path to the root> NERVUS_TOKEN_COMMAND='<a command that prints the token>' tools/nervus-status
```

Then make one call from the client and find it in the audit log, in nervus's web UI: it should
show the token id you just wired up. A call writes two records, an intent before it runs and a
result after, joined by their `id`. If it failed, the result's `error` says why.

**Things that will bite:**
- **An unauthorised request still returns HTTP 200.** MCP carries errors in the body, so a status
  code proves nothing; `nervus-status` checks the body.
- **A client's own error text is not evidence about nervus.** A client has reported "nervus
  rejects the command" when nervus received nothing. The audit log is the evidence.
- **`exec` does not run as root.** It runs as `agent`. On a machine at full, `agent` has
  passwordless sudo, so a privileged command needs `sudo -n`. Without it, nothing can answer a
  password prompt: a bare `reboot` is refused; `sudo -n systemctl reboot` works. At any other level
  there is no `sudo` (below).

## After nervus is upgraded (ADR-0029)

**Nothing in your client's configuration changes.** An upgrade keeps nervus's address, its root and
every token, so what you set up above stays as it is.

**At the restart**, which takes a few seconds:

- The session your client holds with nervus ends, and nervus turns it away until the client begins a
  new one: reconnect it to nervus, or start a new session.
- A call in flight then is cut. Its client sees an error it can retry, and the audit log holds its
  intent without a result.
- A background job (`exec_bg`) runs on, on its own machine: `job` finds it as before. An export or
  upload in progress is marked failed; start it again.

**What a release adds, a client learns when a session starts.** A session open across the upgrade
keeps the tool descriptions it was given. It still works, since each release keeps the last one's
tools working as clients called them, but it does not see what is new until you start a new session.
`CHANGES.md` says when that matters, under what each client must do, and `install.sh --upgrade` prints
that as it ends. If a release changes something on the client's own side, such as `tools/nervus-trust`,
it says so there too: pull this repository on each client machine, and run what it says.

## What each machine lets you do (ADR-0024)

`hosts` lists the machines your token may reach, each with the `level` you have there. One added
on nervus's Machines page has the level its owner chose, which the machine itself enforces; nervus
cannot raise it. A machine described by hand in nervus's inventory shows `read-write`: it is as
nervus's operator set it up, usually full.

**Your token may be read-only on a machine whose own level is higher** (ADR-0031). A machine that
clients may change has two accounts of nervus's, one read-write and one read-only, and the
operator chose one of them for your token on each machine when they issued it; you have no say,
and nervus chooses the account. There `hosts` says `read-only`, and you have what a read-only
machine gives, below, through the read-only account, which is not the read-write one: it cannot
see the read-write account's files, jobs or saved output, nor use its groups, such as `docker`.
Where you are read-only on the Proxmox host, `hosts` lists no VMs, and the `proxmox` tool and a VM
by its `vmid` are refused, saying why. Where the machine has no read-only account yet, every call
is refused, nothing runs, and the answer says how its owner adds one.

| level | `exec`, `exec_bg`, `job` | `get`, `export` | `put`, uploads | `sudo` |
|---|---|---|---|---|
| read-only | yes, but no file outside `~/.nervus` can change | yes | refused | no |
| standard | yes, changing only what `agent` owns | yes | into `agent`'s own folders | no |
| full | yes | yes | anywhere, `root=1` through `sudo` | yes, `sudo -n` |

**On a read-only machine, or one you are read-only on:**
- **A write is refused by the machine**: a command's write fails with "Read-only file system". `put`
  and uploads are refused by nervus before anything is sent, saying you are read-only there; an
  upload answers `403` with the code `read_only`.
  That is the machine doing its job, not a fault in nervus; don't try to work around it. There is
  no `sudo` here, nor at standard, so `root=1` cannot help.
- **`~/.nervus` is the one folder a command can write**, and it lasts between calls. Use it for scratch
  files and build output.
- **`/tmp` is private to each command and empty at the start of the next.** Anything a later call
  needs goes in `~/.nervus`.
- You can still read anything `agent` can read, run programs, and reach the network.

## Save a file from a host or VM onto your own machine (ADR-0016)

A file moves in two halves. The `export` tool copies it from a host or a VM into nervus, checked
against the source's own SHA-256. Then your own shell downloads it, straight to disk, so the bytes
never pass through the model.

**1. Export it.** Call `export` with a `request_key` you make up, unique to this file, and the
source: `host` and `remote_path` for a host (your token's allowlist decides), or `vmid` and `path`
for a VM (your token needs the Proxmox host). A VM is read over SFTP, enrolled first if nervus has
not used it yet (see "Make a VM"), or through Proxmox's guest agent, much more slowly, if it cannot
be enrolled; `route` in the answer says which. One regular file, by default at most 256 MiB:
archive a directory at the source first.

**2. Wait for it.** The call waits up to 30 seconds. If `state` is `measuring` or `staging`, call
`export` again with the **same** `request_key`: it never copies twice, so this is also how to retry
after a timeout. Through the guest agent a VM is read at about 1.3 MB/s. When `state` is `ready`, the answer has `size`,
`sha256`, `download_path` and `expires_at`, 24 hours on. `failed` has a `failure` with a code and a
reason; a new attempt needs a new key.

**3. Download it with your own token, from standard input.** The token goes into curl through a
pipe, so it is never in a command's arguments, where other processes could list it, and never in
the URL. `NERVUS_CACERT` names nervus's root, as above. Replace `<export_id>` and `<file>`:

Codex, with its token in `NERVUS_CODEX`:

<!-- download:codex -->
```bash
printf 'Authorization: Bearer %s\n' "$NERVUS_CODEX" | curl -fsS -C - --cacert "$NERVUS_CACERT" -H @- -o '<file>' 'https://<nervus>:8000/exports/<export_id>'
```

Claude Code, with its token in the keystore (the same prompt as connecting, approved the same
way), run from the nervus repository:

<!-- download:claude-code -->
```bash
tools/nervus-headers <item> | sed -E 's/^\{"(Authorization)": "(.*)"\}$/\1: \2/' | curl -fsS -C - --cacert "$NERVUS_CACERT" -H @- -o '<file>' 'https://<nervus>:8000/exports/<export_id>'
```

A client whose token is in an environment variable uses the Codex form with its own variable.

**4. Check it before using it.** `shasum -a 256 '<file>'` must print the `sha256` the export gave.
Nothing else proves you have the file: nervus records whether it sent every byte, not whether they
arrived.

**5. If it was cut off, run the same command again.** `-C -` continues from the end of the partial
file. Run on a file that is already whole, it exits 0 and changes nothing. A finished export never
changes, so a resume cannot mix two versions.

**6. Delete it when it checks out:** `export` with `action: "delete"`, the `export_id`, and any
`request_key`. Otherwise it is deleted 24 hours after it was made.

**Codex's sandbox.** Codex runs commands without network access, so each download is a request to
run outside the sandbox, which Codex's approval reviewer may refuse. nervus cannot remove that step.
Say in the request that it downloads one named export from nervus with the client's own token.

**What the answers mean.** 401: no token, a wrong one, or this client is switched off; nervus does
not say which. 404: no ready export with this id **for this token**: another client's, still
copying, expired, or deleted. Call `export` with the same key to see which. 416: the partial file
is already whole, or longer than the export.

**Never** run the download with `-v` or `--trace`: curl prints request headers, the token
included. Never put the token in the URL.

## Send a file from your machine to a host or VM (ADR-0020)

One command from your own shell sends the file. nervus checks it against the SHA-256 you give,
writes it beside the destination under a temporary name, has the target hash what it wrote, and
only then renames it into place. The bytes never pass through the model, and the answer is one line
of JSON. Use this instead of pasting a file into `exec`.

**Send it.** Replace `<file>` (on your machine), `<host>`, `<path>` (the absolute path to write)
and `<key>` (a request key you make up, unique to this file). `NERVUS_CACERT` names nervus's root,
as above.

Codex, with its token in `NERVUS_CODEX`:

<!-- upload:codex -->
```bash
f='<file>'; printf 'Authorization: Bearer %s\n' "$NERVUS_CODEX" | curl -sS --fail-with-body --cacert "$NERVUS_CACERT" -H @- -T "$f" --url-query 'host=<host>' --url-query 'path=<path>' --url-query "sha256=$(shasum -a 256 "$f" | cut -c1-64)" --url-query 'key=<key>' 'https://<nervus>:8000/uploads'
```

Claude Code, with its token in the keystore, run from the nervus repository:

<!-- upload:claude-code -->
```bash
f='<file>'; tools/nervus-headers <item> | sed -E 's/^\{"(Authorization)": "(.*)"\}$/\1: \2/' | curl -sS --fail-with-body --cacert "$NERVUS_CACERT" -H @- -T "$f" --url-query 'host=<host>' --url-query 'path=<path>' --url-query "sha256=$(shasum -a 256 "$f" | cut -c1-64)" --url-query 'key=<key>' 'https://<nervus>:8000/uploads'
```

Where `shasum` is missing, as on some Linux, use `sha256sum "$f"` in its place. `--url-query` needs curl 7.87
or later (`curl --version`).

**Options**, each one more `--url-query`:
- **A VM** instead of a host: `vmid=<vmid>` in place of `host=<host>` (your token needs the Proxmox
  host). The VM fetches the file from nervus over the network, fast. If it cannot (no `curl`, no
  route to nervus), nervus sends it over SFTP, enrolling the VM if it needs to, at network speed
  and without a size limit of its own; only if it cannot do that either does it push the file
  through the guest agent, slowly, and then at most 32 MiB. The answer's route says which.
- **`replace=1`** to replace an existing file. Without it, an existing file is refused, and so is a
  file that appears while yours is on its way.
- **`root=1`** on a host, to write where only root may, through the host's `sudo`. In a VM the file
  is always written as root, whichever route it takes.
- **`mode=0755`**, or any octal mode. Otherwise the target's default (`0644` with `root=1`).
- **`wait=<seconds>`**, how long the command waits for delivery, 30 by default, at most 55.

The directory must exist. One file, by default at most 256 MiB: send an archive, then unpack it with
one `exec`.

**What the answer means.** `"state": "delivered"` (HTTP 200): the file is in place, and `sha256` is
the target's own hash of it. `"delivering"` (202): still going; ask again, below. `"failed"` (422) or
`"refused"` (4xx, or 507 when nervus is short of space): `failure` has a code and the reason in
words, and curl exits 22 having printed it. Common codes: `exists` (send `replace=1`),
`not_writable` (send `root=1`), `no_directory`, `hash_mismatch` (the file changed, or the hash is
wrong), `not_allowed` (your token does not reach that destination), `key_reused` (a new file needs
a new key). 401: no token, a wrong one, or this client is switched off.

**Ask again, or retry.** Sending the same file with the same key never delivers it twice: it
answers with that upload. To only ask, without sending the file again:

<!-- upload-status:codex -->
```bash
printf 'Authorization: Bearer %s\n' "$NERVUS_CODEX" | curl -sS --fail-with-body --cacert "$NERVUS_CACERT" -H @- 'https://<nervus>:8000/uploads/<key>'
```

**Codex's sandbox** asks to run each upload outside it, as for downloads. Say in the request that
it sends one named file to nervus with the client's own token.

**Never** run it with `-v` or `--trace`: curl prints request headers, the token included.

## Make a VM, use it, and destroy it (ADR-0017)

For a nervus whose inventory has a Proxmox host (`hypervisor: proxmox`) with a template built by
`tools/proxmox-template`, and a token that reaches that host. Everything is a `proxmox` tool call:
no root, no SSH into the VM, no password or key. Paths are relative to `/api2/json`; `{node}` is
the node's name, from `GET /nodes`; `<t>` is the template's id, `<id>` your VM's.

A VM may be a 60-second test or something the user keeps for years. **Decide which before you make
it**: `ephemeral` (you destroy it when your task ends) or `long-lived` (it stays, and you tell the
user its id and name).

**1. Find the template.** `GET /cluster/resources` with `type=vm`. Templates have `template: 1` and
the tag `nervus-template`; take the one whose name, `nervus-debian-13-<YYYYMMDD>`, has the newest
date. It is genuine if `GET /nodes/{node}/qemu/<t>/config` shows `protection: 1` and
`GET /access/acl` lists role `NervusTemplateUse` on `/vms/<t>`: only root can set both. Template
ids start at 9000 by default.

**2. Clone it into `agents`.** `GET /cluster/nextid` gives `<id>`. Then
`POST /nodes/{node}/qemu/<t>/clone` with `newid=<id>`, `name=<a short DNS name>`, `pool=agents`. A
linked clone is ready in about a second: poll `GET /nodes/{node}/tasks/<UPID>/status` until
`status` is `stopped` and `exitstatus` is `OK`. If another client took the id first, the clone
fails with "config file already exists": ask `nextid` again.

**3. Label it, in one call.** `PUT /nodes/{node}/qemu/<id>/config` with `tags=ephemeral` or
`tags=long-lived`, a `description` saying what it is for, for which client and project, and the
date, and **`protection=0` if it is `ephemeral`**. A clone inherits the template's `protection: 1`
and its description; without `protection=0` the destroy in step 7 is refused. The same call may
change `cores` or `memory` (the defaults are 2 and 2048); to grow the 16 GiB disk,
`PUT /nodes/{node}/qemu/<id>/resize` with `disk=scsi0` and, for example, `size=+16G`.

**4. Start it and wait for its agent.** `POST /nodes/{node}/qemu/<id>/status/start`, then
`POST /nodes/{node}/qemu/<id>/agent/ping` every 10 seconds until it answers 200 rather than 500
"QEMU guest agent is not running". About 25 seconds; give up after five minutes.

**5. Use it by its id.** Every tool that takes `host` also takes `vmid` in its place: `exec`,
`exec_bg`, `job`, `put` and `get`, and `export` and uploads (above). Commands run as `agent`, with
root by `sudo -n`, as on a host. Nothing has to be set up first:
- **The first call that names it enrolls it**, through its guest agent: nervus makes the `agent`
  account with nervus's key and passwordless `sudo`, pins the VM's host key as the guest agent
  reports it, and checks it over SSH. That takes a few seconds, and the answer's `vm_note` says
  so. No address, name or key is yours to handle.
- **Later calls repair what changed**, and `vm_note` says what: an address that moved, or a VM
  rebuilt under the same id. A VM that is gone is forgotten, and the call says so.
- **`hosts` lists the VMs nervus has enrolled**, each with its `vmid`, name and address.
- **A failed enrollment says why** (a VM with no `sudo`, or one nervus cannot reach over the
  network), and the next call tries again. Until it works, use the guest agent:

**The guest agent**, for a VM nervus cannot enroll, for recovery, or for a single short command.
Commands run as root in the VM.
- **Run:** `POST /nodes/{node}/qemu/<id>/agent/exec` with `command=/bin/sh` and the script in
  `input-data`. It answers with a `pid`. Then `GET /nodes/{node}/qemu/<id>/agent/exec-status` with
  `pid=<pid>` until `exited` is 1; that answer has `exitcode`, `out-data` and `err-data`.
- **Every command costs two calls**, so put a whole job in one script rather than one command per
  call.
- **A script is at most 64 KiB** (65,536 characters of `input-data`, Proxmox's own limit). Anything
  longer is refused with 400 "Parameter verification failed." and nothing runs.
- **Output that may be large goes to a file**, which you then `export`. A status answer carries all
  of the output, and the `proxmox` tool refuses any answer over 256 KiB, so a command with large
  output gives you either a lot or nothing.
- **Long work:** for work of many minutes, start it in the background
  (`nohup <command> > /root/job.log 2>&1 &`) and read the log later with a short command.
- **Its address:** `GET /nodes/{node}/qemu/<id>/agent/network-get-interfaces`.

**6. Long-lived: stop here.** Leave it running, and tell the user its id, its name and what it is
for. It stays in `agents` with its tag.

**7. Ephemeral: destroy it.** `POST /nodes/{node}/qemu/<id>/status/stop`, poll that task until it
is `stopped`, then `DELETE /nodes/{node}/qemu/<id>` with `purge=1` and
`destroy-unreferenced-disks=1`, and poll that task to `OK`. "protection mode enabled" means step 3
missed `protection=0`: set it, then destroy.

**What you cannot do, and should not try.** Change, start, snapshot or destroy a template: Proxmox
refuses. Touch nervus's own container: you hold nothing there. **And leave alone any VM you did not
make** unless the user asks: your token reaches every VM's guest agent as root, and so does every
other client's (ADR-0017 consequence 2).
