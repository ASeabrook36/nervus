"""Tests for tools/proxmox-accounts, the root script that makes `observer` and
`agent` on a Proxmox host for nervus (ADR-0009 decisions 1 to 3).

It runs as root on a Proxmox node, which no test can be. So every command it
uses to read or change the host (id, hostname, getent, useradd, install,
visudo, sshd, pct, pvesm, runuser, pgrep, ...) is one stand-in that answers as a
fresh Proxmox host would, keeps what it was told in a state file, and logs
every call. Files the script would write as root land under the test's own
directory. Keys are real: ssh-keygen makes them, and the script fingerprints
them with the real ssh-keygen. The tests check what it did, with which names,
and that no name, id or key of any one installation is built in (ADR-0019).
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

TOOL = Path(__file__).resolve().parent.parent / "tools" / "proxmox-accounts"

STANDIN = r'''#!/usr/bin/env python3
import json, os, shutil, sys
from pathlib import Path

name, args = Path(sys.argv[0]).name, sys.argv[1:]
state_dir = Path(os.environ["STATE"])
state_file = state_dir / "state.json"
state = json.loads(state_file.read_text())
with open(os.environ["LOG"], "a") as log:
    log.write(" ".join([name, *args]) + "\n")

def save():
    state_file.write_text(json.dumps(state))

def rooted(path):  # where a file the script writes as root lands
    return state_dir / "root" / path.lstrip("/")

if name == "id":
    if args == ["-u"]:
        print(0)
    elif args[:1] == ["-Gn"]:
        print(" ".join(state["groups"].get(args[1], [])))
    else:
        print("uid=0(root)")
elif name == "hostname":
    print(os.environ["FAKE_NODE"])
elif name == "getent":
    db, key = args[0], args[1]
    if db == "passwd":
        if key not in state["users"]:
            sys.exit(2)
        print(f"{key}:x:1001:1001::{state_dir / 'home' / key}:/bin/bash")
    elif db == "shadow":
        if key not in state["users"]:
            sys.exit(2)
        print(f"{key}:!:20000::::::")
    elif db == "group":
        print(f"{key}:x:4:") if key in ("adm", "systemd-journal") else sys.exit(2)
    elif db == "hosts":
        print(f"192.0.2.10 {key}")
elif name == "useradd":
    user = args[-1]
    groups = [user] + (args[args.index("-G") + 1].split(",") if "-G" in args else [])
    state["users"].append(user)
    state["groups"][user] = groups
    (state_dir / "home" / user).mkdir(parents=True, exist_ok=True)
    save()
elif name == "install":
    rest = [a for i, a in enumerate(args) if not (a.startswith("-") or args[i - 1] in ("-m", "-o", "-g"))]
    if "-d" in args:
        Path(rest[-1]).mkdir(parents=True, exist_ok=True)
    else:
        src, dst = rest[-2], rest[-1]
        dst = Path(dst) if dst.startswith(str(state_dir)) else rooted(dst)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(src, dst)
elif name in ("visudo", "sudo", "apt-get"):
    pass
elif name == "dpkg-query":
    print("1.9.16")
elif name == "sshd":
    print("usepam yes\npubkeyauthentication yes")
elif name == "pgrep":
    print(4242)
elif name == "runuser":
    sys.exit(1)  # `nobody` cannot read the container's disk
elif name == "pvesm":
    print(state_dir / "images" / "123" / "vm-123-disk-0.raw")
elif name == "pct":
    ct, rest = args[1], args[2:]
    if args[0] == "config":
        print(f"arch: amd64\nrootfs: fast:{ct}/vm-{ct}-disk-0.raw,size=8G")
    elif args[0] == "exec":
        cmd = rest[1:]
        ca = state_dir / "nervus_ca_ed25519"  # nervus's CA, in the container
        nervus = cmd[:4] == ["runuser", "-u", "nervus", "--"]  # run as nervus inside the container
        command = cmd[4:] if nervus else cmd
        if command[:1] == ["timeout"]:  # a read given a time: what is timed is what answers
            command = command[3:] if command[1] == "--foreground" else command[2:]
        if command[:2] == ["test", "-f"] and command[2].endswith("/known_hosts"):
            sys.exit(0 if (state_dir / "known_hosts").is_file() else 1)
        if command[0] == "test":
            sys.exit(0 if ca.exists() else 1)
        elif command[0] == "ssh-keygen" and command[1] == "-y":
            print(" ".join(Path(f"{ca}.pub").read_text().split()[:2]))
        elif command[0] == "cat":  # nervus reads its known_hosts
            sys.stdout.write((state_dir / "known_hosts").read_text())
        elif nervus and command[:2] == ["sh", "-c"]:  # nervus writes its known_hosts from standard input
            data = sys.stdin.read()
            if not data:
                sys.exit(1)
            (state_dir / "known_hosts").write_text(data)
        elif cmd[:2] == ["sh", "-c"] and "ssh-keygen -q -s" in cmd[2]:
            words = cmd[2].split()
            with open(os.environ["LOG"], "a") as log:
                log.write(f"signed by {words[words.index('-s') + 1]} for {words[words.index('-n') + 1]} "
                          f"{words[words.index('-V') + 1]}\n")
            print("/tmp/tmp.cert0042")
        elif cmd[:2] == ["sh", "-c"]:
            print("/usr/bin/ssh")
        elif cmd[0] == "rm":
            pass
        elif command[0] == "stat":
            print("600 nervus")
        elif nervus:  # nervus's ssh login: user@host is the last but one argument
            user, host = cmd[-2].split("@")
            cert = any(a.startswith("CertificateFile=") for a in cmd)
            with open(os.environ["LOG"], "a") as log:
                log.write(f"login {user} {host} {'certificate' if cert else 'key alone'}\n")
            if not cert and not os.environ.get("PLAIN_KEY_OPENS"):
                sys.exit(255)  # the account trusts nervus's CA alone
            if user == "agent":
                print("agent\nroot")
            else:
                print("observer\nobserver adm systemd-journal\nsudo=1\njournal=0\nprocesses=42\n"
                      "pvepriv=1\nctdisk=1\nctroot=1")
'''

COMMANDS = ["id", "hostname", "getent", "useradd", "install", "visudo", "sudo", "apt-get", "dpkg-query",
            "sshd", "pgrep", "runuser", "pvesm", "pct"]


def keygen(path: Path) -> str:
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "nervus", "-f", str(path)], check=True)
    out = subprocess.run(["ssh-keygen", "-lf", f"{path}.pub"], capture_output=True, text=True, check=True)
    return out.stdout.split()[1]


@pytest.fixture
def host(tmp_path):
    bin_dir, state = tmp_path / "bin", tmp_path / "state"
    bin_dir.mkdir()
    state.mkdir()
    standin = bin_dir / "standin"
    standin.write_text(STANDIN)
    standin.chmod(0o755)
    for c in COMMANDS:
        (bin_dir / c).symlink_to(standin)
    (state / "state.json").write_text('{"users": [], "groups": {}}')
    (state / "known_hosts").write_text("node-a.example.net ssh-ed25519 AAAAexisting\n")
    disk = state / "images" / "123" / "vm-123-disk-0.raw"
    disk.parent.mkdir(parents=True)
    disk.write_bytes(b"\0")
    keys = tmp_path / "hostkeys"
    keys.mkdir()
    host_fp = keygen(keys / "ssh_host_ed25519_key")
    for t in ("ecdsa", "rsa"):
        subprocess.run(["ssh-keygen", "-q", "-t", t, "-N", "", "-f", str(keys / f"ssh_host_{t}_key")], check=True)
    keygen(state / "nervus_ed25519")
    ca_fp = keygen(state / "nervus_ca_ed25519")
    return tmp_path, {"NODE": "hv", "SSH_HOST": "hv.example.net", "NERVUS_CT": "123",
                      "NERVUS_CA_FP": ca_fp, "HOST_KEY_FP": host_fp}


def run(host, node="hv", **names) -> subprocess.CompletedProcess:
    tmp, _ = host
    env = {**os.environ, "PATH": f"{tmp / 'bin'}:{os.environ['PATH']}", "LOG": str(tmp / "log"),
           "STATE": str(tmp / "state"), "FAKE_NODE": node, "PROXMOX_HOST_KEYS": str(tmp / "hostkeys"),
           **names}
    return subprocess.run(["bash", str(TOOL)], env=env, capture_output=True, text=True, timeout=60)


def log(host) -> str:
    path = host[0] / "log"
    return path.read_text() if path.exists() else ""


def test_it_runs_through_and_uses_only_the_names_it_is_given(host):
    tmp, names = host
    done = run(host, **names)
    assert done.returncode == 0, done.stdout + done.stderr
    assert "done. Nothing reaches these accounts" in done.stdout
    assert "agent: logs in with a certificate nervus's CA signed, strict host check; 'sudo -n id -un' is root" in done.stdout
    assert "agent and observer refuse nervus's key without a certificate" in done.stdout
    calls = log(host)
    assert "useradd" in calls and "-G adm,systemd-journal observer" in calls
    assert "pct config 123" in calls and "pvesm path fast:123/vm-123-disk-0.raw" in calls
    assert "login agent hv.example.net certificate" in calls and "login observer hv.example.net certificate" in calls
    assert "login agent hv.example.net key alone" in calls and "login observer hv.example.net key alone" in calls
    assert "signed by /opt/nervus/secrets/nervus_ca_ed25519 for observer,agent -5m:+5m" in calls
    sudoers = (tmp / "state" / "root" / "etc" / "sudoers.d" / "agent").read_text()
    assert sudoers == "agent ALL=(ALL) NOPASSWD: ALL\n"
    # ADR-0025 decision 4: nervus's CA, not its key, as enrollment writes it.
    ca = " ".join((tmp / "state" / "nervus_ca_ed25519.pub").read_text().split()[:2])
    for user in ("observer", "agent"):
        keys = (tmp / "state" / "home" / user / ".ssh" / "authorized_keys").read_text().splitlines()
        assert keys == [f"cert-authority {ca} nervus-ca"]
    pinned = (tmp / "state" / "known_hosts").read_text().splitlines()
    assert pinned[0] == "node-a.example.net ssh-ed25519 AAAAexisting"  # untouched
    assert [line.split()[0] for line in pinned[1:]] == ["hv.example.net"] * 3
    # Nothing built in: every container id and login host it used is one it was given.
    assert set(re.findall(r"pct \w+ (\d+)", calls)) == {"123"}
    assert set(re.findall(r"^login \w+ (\S+) ", calls, re.M)) == {"hv.example.net"}


@pytest.mark.parametrize("missing", ["NODE", "SSH_HOST", "NERVUS_CT", "NERVUS_CA_FP", "HOST_KEY_FP"])
def test_each_name_is_required_and_nothing_is_touched_without_it(host, missing):
    names = {k: v for k, v in host[1].items() if k != missing}
    done = run(host, **names)
    assert done.returncode != 0 and "name all five" in done.stdout
    assert log(host) == ""


def test_a_malformed_fingerprint_is_refused_before_anything(host):
    done = run(host, **{**host[1], "HOST_KEY_FP": "uXlu1M8M"})
    assert done.returncode != 0 and "a fingerprint is SHA256:" in done.stdout
    assert log(host) == ""


@pytest.mark.parametrize("which, why", [
    ("NERVUS_CA_FP", "nervus's CA in CT 123 is"),
    ("HOST_KEY_FP", "this host's ED25519 host key is"),
])
def test_a_key_that_is_not_the_one_given_stops_it_before_any_account_is_made(host, which, why):
    wrong = "SHA256:" + "A" * 43
    done = run(host, **{**host[1], which: wrong})
    assert done.returncode != 0 and why in done.stdout and wrong in done.stdout
    assert "useradd" not in log(host)


def test_it_stops_on_the_wrong_node_having_changed_nothing(host):
    done = run(host, node="elsewhere", **host[1])
    assert done.returncode != 0 and "this is 'elsewhere', not 'hv'" in done.stdout
    assert "useradd" not in log(host)


def test_a_nervus_without_its_ca_stops_it_before_any_account_is_made(host):
    """A nervus from before ADR-0025 has no CA to trust; the accounts would
    otherwise get nothing nervus can log in with."""
    (host[0] / "state" / "nervus_ca_ed25519").unlink()
    done = run(host, **host[1])
    assert done.returncode != 0 and "CT 123 has no /opt/nervus/secrets/nervus_ca_ed25519" in done.stdout
    assert "useradd" not in log(host)


def test_inside_nervus_s_container_root_reads_and_writes_nothing_under_its_secrets(host):
    """Procedure 056. install.sh gives nervus /opt/nervus/secrets, so a process running as nervus can put a
    symbolic link there. Root following one, as its `cp` of nervus's public key did, would copy a file only
    root can read into a folder then handed to nervus; `pct pull` and `pct push` run as root and are not
    used on those paths either. Every command naming them runs as nervus, so a link there reaches only what
    nervus could reach already."""
    done = run(host, **host[1])
    assert done.returncode == 0, done.stdout + done.stderr
    calls = log(host).splitlines()
    assert not [c for c in calls if c.startswith(("pct pull", "pct push"))]
    named = [c for c in calls if c.startswith("pct exec") and "/opt/nervus/secrets" in c]
    assert len(named) >= 6, named  # the CA, nervus's key, and known_hosts read, written and checked
    for call in named:
        command = call.split(" -- ", 1)[1]
        if command.startswith("runuser -u nervus -- "):
            continue
        assert command.startswith("sh -c "), call  # root's own shell: each step naming the secrets is nervus's
        for step in command[len("sh -c "):].split("&&"):
            if "/opt/nervus/secrets" in step:
                assert step.strip().startswith("runuser -u nervus -- "), call


def test_an_account_that_lets_nervus_key_in_alone_stops_it(host):
    """The check after: nervus's key without a certificate must be refused,
    or the line written is not the CA's alone."""
    done = run(host, **host[1], PLAIN_KEY_OPENS="1")
    assert done.returncode != 0 and "agent let nervus's key in without a certificate" in done.stdout


def test_every_file_nervus_opens_for_it_is_given_a_time(host):
    """nervus's account owns the folder its key, its CA and its known_hosts are in, and can put a
    pipe where any of them was. A plain cat, ssh-keygen or ssh waits on one for ever, and this
    script with it (procedure 062). So nervus runs nothing here that opens one of those names
    but under `timeout`; what else it runs opens none: a look (test, stat), and the write, which
    makes a new name and renames it over the old."""
    tmp, names = host
    done = run(host, **names)
    assert done.returncode == 0, done.stdout + done.stderr
    runs = re.findall(r"runuser -u nervus -- (\S+)", log(host))
    assert {"timeout", "test", "stat", "sh"} == set(runs), sorted(set(runs))
    assert runs.count("timeout") >= 6  # the CA's key twice, known_hosts twice, the key, each login
    # Always --foreground. A person runs this from a terminal, and a plain timeout puts what it
    # times where a read of that terminal stops it, and timeout with it, for good: seen on Ubuntu
    # 26.04, where such a command was still there when killed from outside (procedure 062).
    assert set(re.findall(r"timeout (\S+)", log(host))) == {"--foreground"}


def test_a_pipe_at_known_hosts_stops_it_by_name_and_is_not_waited_on(host):
    tmp, names = host
    (tmp / "state" / "known_hosts").unlink()
    os.mkfifo(tmp / "state" / "known_hosts")
    done = run(host, **names)  # which fails the test if it is still running after a minute
    assert done.returncode == 1 and "STOP" in done.stderr, done.stdout + done.stderr
    assert "/opt/nervus/secrets/known_hosts in CT 123 is not a file" in done.stderr
    assert "could not read" not in done.stdout  # it stopped at the look, and read nothing
