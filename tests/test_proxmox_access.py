"""Tests for tools/proxmox-access, the root script that gives nervus its scoped
Proxmox API access (ADR-0009 decision 2).

It runs as root on a Proxmox node, which no test can be. So each Proxmox
command it calls (pveum, pvesh, pct, pveversion) and the host commands whose
answers it depends on (id, hostname, getent, curl) are replaced by stand-ins
that answer as a fresh Proxmox host would and log every call. The script runs
from start to finish against them; the tests check what it asked Proxmox to
do, and that no name or id of any one installation is built in (ADR-0019).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

import pytest

TOOL = Path(__file__).resolve().parent.parent / "tools" / "proxmox-access"

WITHHELD = ("Permissions.Modify User.Modify Group.Allocate Realm.Allocate Realm.AllocateUser Sys.Console "
            "Sys.Modify Sys.PowerMgmt Sys.Incoming Datastore.Allocate Mapping.Modify Mapping.Use "
            "SDN.Allocate").split()
GRANTED = [f"Stand.In{i:02}" for i in range(34)]  # Proxmox's other 34, by count

# Each stand-in logs "name args..." and answers from $STATE.
STANDINS = {
    "id": 'echo "id $*" >> "$LOG"; [ "${1:-}" = -u ] && echo 0 || echo "uid=0(root)"',
    "hostname": 'echo "hostname $*" >> "$LOG"; echo "$FAKE_NODE"',
    "pveversion": 'echo pve-manager/9.2.3/stand-in',
    "getent": 'echo "getent $*" >> "$LOG"; echo "192.0.2.10 $3"',
    "pvesh": r'''echo "pvesh $*" >> "$LOG"
case "$2" in
  /access/users) cat "$STATE/users.json" ;;
  /access/roles) cat "$STATE/roles.json" ;;
  *) echo "[]" ;;
esac''',
    "pveum": r'''echo "pveum $*" >> "$LOG"
case "$1 $2" in
  "role add")
    python3 - "$STATE/roles.json" "$3" "$5" <<'PY'
import json, sys
path, role, privs = sys.argv[1:]
roles = json.load(open(path)); roles.append({"roleid": role, "privs": privs})
json.dump(roles, open(path, "w"))
PY
    ;;
  "user add") echo "[{\"userid\": \"$3\"}]" > "$STATE/users.json" ;;
  "user token")
    case "$3" in
      add) echo '{"value": "01234567-89ab-cdef-0123-456789abcdef"}' ;;
      permissions)
        path=""; while [ $# -gt 0 ]; do [ "$1" = --path ] && path=$2; shift; done
        python3 - "$path" "$STATE/granted" <<'PY'
import json, sys
path, granted = sys.argv[1], open(sys.argv[2]).read().split()
print(json.dumps({path: {p: 1 for p in granted} if path == "/" else {}}))
PY
        ;;
    esac ;;
esac''',
    "pct": r'''echo "pct $*" >> "$LOG"
case "$1" in
  status) echo "status: running" ;;
  push) cp "$3" "$STATE/pushed-$(basename "$4")" ;;
  exec)
    case "$*" in
      *python*) echo TLSv1.3 ;;
      *stat*) echo "/opt/nervus/secrets/proxmox.yaml 600 nervus:nervus" ;;
      # "Is this name free?" It is, unless a test lists the name in $STATE/taken.
      *"test ! -e"*) ! grep -qxF "${@: -1}" "$STATE/taken" 2>/dev/null ;;
      # A file written inside the container from standard input: kept, by its name, as a push is.
      *"cat >"*) cat > "$STATE/pushed-$(basename "${@: -1}")" ;;
      # Read back and compared with standard input. A test lists in $STATE/elsewhere a name the
      # service's account took meanwhile: the file is not there to read.
      *"cmp -s"*)
        grep -qxF "$(basename "${@: -1}")" "$STATE/elsewhere" 2>/dev/null && exit 2
        cmp -s - "$STATE/pushed-$(basename "${@: -1}")" ;;
    esac ;;
esac''',
    "curl": r'''out=""; url=""
while [ $# -gt 0 ]; do
  case "$1" in -o) out=$2; shift 2 ;; -w|-H|--cacert) shift 2 ;; -*) shift ;; *) url=$1; shift ;; esac
done
echo "curl $url" >> "$LOG"
case "$url" in
  */version) echo '{"data": {"version": "9.2.3"}}' > "$out"; printf 200 ;;
  */lxc/*) echo '{}' > "$out"; printf 403 ;;
  */cluster/resources*) echo '{"data": [{"vmid": 100}, {"vmid": 9000}]}' > "$out"; printf 200 ;;
  *) echo '{}' > "$out"; printf 404 ;;
esac''',
}


@pytest.fixture
def host(tmp_path):
    bin_dir, state = tmp_path / "bin", tmp_path / "state"
    bin_dir.mkdir()
    state.mkdir()
    for name, body in STANDINS.items():
        f = bin_dir / name
        f.write_text("#!/bin/bash\n" + body + "\n")
        f.chmod(0o755)
    (state / "users.json").write_text("[]")
    (state / "roles.json").write_text(json.dumps([{"roleid": "Administrator",
                                                   "privs": ",".join(sorted(WITHHELD + GRANTED))}]))
    (state / "granted").write_text(" ".join(GRANTED))
    ca = tmp_path / "pve-root-ca.pem"
    ca.write_text("-----BEGIN CERTIFICATE-----\nstand-in\n-----END CERTIFICATE-----\n")
    return tmp_path


def run(host: Path, node="hv", **names) -> subprocess.CompletedProcess:
    env = {**os.environ, "PATH": f"{host / 'bin'}:{os.environ['PATH']}", "LOG": str(host / "log"),
           "STATE": str(host / "state"), "FAKE_NODE": node, "PROXMOX_CA": str(host / "pve-root-ca.pem"),
           **names}
    return subprocess.run(["bash", str(TOOL)], env=env, capture_output=True, text=True, timeout=60)


NAMES = {"NODE": "hv", "API_HOST": "hv.example.net", "NERVUS_CT": "123"}


def log(host: Path) -> str:
    path = host / "log"
    return path.read_text() if path.exists() else ""


def test_it_runs_through_and_uses_only_the_names_it_is_given(host):
    done = run(host, **NAMES)
    assert done.returncode == 0, done.stdout + done.stderr
    calls = log(host)
    assert "pveum role add NervusScoped" in calls
    assert "pveum acl modify / --roles NervusScoped --users nervus@pve --tokens nervus@pve!nervus" in calls
    assert "pveum acl modify /vms/123 --roles NoAccess" in calls
    assert "pct exec 123 -- runuser -u nervus -- " in calls and "curl https://hv.example.net:8006/api2/json/nodes/hv/lxc/123/" in calls
    # Nothing built in: every container id, VM path, node and address it used is one it was given.
    assert set(re.findall(r"pct \w+ (\d+)", calls)) == {"123"}
    assert set(re.findall(r"/vms/(\d+)", calls)) == {"123"}
    assert set(re.findall(r"https://([^:/]+)", calls)) == {"hv.example.net"}
    assert set(re.findall(r"/nodes/([^/]+)/", calls)) == {"hv"}
    settings = (host / "state" / "pushed-proxmox.yaml").read_text()
    assert "url: https://hv.example.net:8006" in settings
    assert 'token_id: "nervus@pve!nervus"' in settings
    assert "the role will hold 34 and withhold 13" in done.stdout
    assert "token's effective permissions: 34 on /, 0 on /vms/123" in done.stdout


def test_root_writes_nothing_by_path_in_nervus_secrets_folder(host):
    # nervus's account owns its secrets folder. Root, with `pct push`, wrote the settings and the CA
    # there by path and gave them to nervus: a link planted at either name would carry root's
    # write, and its chown, to whatever the link names (procedure 056's proxmox-accounts row;
    # procedure 058). Both are written inside the container by the nervus account itself.
    done = run(host, **NAMES)
    assert done.returncode == 0, done.stdout + done.stderr
    calls = log(host)
    assert "pct push" not in calls
    writes = [line for line in calls.splitlines() if line.startswith("pct exec 123") and "cat >" in line]
    assert len(writes) == 2 and all("-- runuser -u nervus -- " in line for line in writes), writes
    assert {line.rsplit(" ", 1)[1] for line in writes} == {"/opt/nervus/secrets/proxmox.yaml",
                                                         "/opt/nervus/secrets/pve-root-ca.pem"}
    assert (host / "state" / "pushed-pve-root-ca.pem").read_text() == (host / "pve-root-ca.pem").read_text()
    # And each is read back there by the nervus account, not by root.
    reads = [line for line in calls.splitlines() if line.startswith("pct exec 123") and "cmp -s" in line]
    assert len(reads) == 2 and all("-- runuser -u nervus -- " in line for line in reads), reads
    assert {line.rsplit(" ", 1)[1] for line in reads} == {"/opt/nervus/secrets/proxmox.yaml",
                                                        "/opt/nervus/secrets/pve-root-ca.pem"}


@pytest.mark.parametrize("name", ["proxmox.yaml", "pve-root-ca.pem"])
def test_a_name_already_taken_stops_it_before_it_makes_anything(host, name):
    # Either name taken in nervus's folder, by a file, a folder or a link that leads nowhere, is a
    # thing not as expected, and the script stops before it makes a role, a user or a token. Until
    # procedure 060 it asked only about proxmox.yaml: on a Proxmox host, a folder at pve-root-ca.pem
    # took the CA inside it, was reported "ok", and the run ended in a traceback from its last check.
    (host / "state" / "taken").write_text(f"/opt/nervus/secrets/{name}\n")
    done = run(host, **NAMES)
    assert done.returncode != 0
    assert f"CT 123 already has /opt/nervus/secrets/{name}; nothing changed" in done.stdout
    assert "pveum role add" not in log(host) and "pveum user" not in log(host)


@pytest.mark.parametrize("name", ["proxmox.yaml", "pve-root-ca.pem"])
def test_it_does_not_call_written_what_the_nervus_account_cannot_read_back(host, name):
    # nervus's account owns the folder and can put a link or a folder at a name while the script
    # runs: the file then lands somewhere else, or nowhere. Each file is read back by the nervus
    # account and compared with what was sent, so the run stops there and says so, with how to undo
    # what it has made by then (procedure 060).
    (host / "state" / "elsewhere").write_text(name + "\n")
    done = run(host, **NAMES)
    assert done.returncode != 0
    assert f"what the nervus account reads at /opt/nervus/secrets/{name} is not what was written" in done.stdout
    assert "done." not in done.stdout and "5. verifying" not in done.stdout
    assert "to undo:" in done.stdout


@pytest.mark.parametrize("missing", ["NODE", "API_HOST", "NERVUS_CT"])
def test_each_name_is_required_and_nothing_is_touched_without_it(host, missing):
    names = {k: v for k, v in NAMES.items() if k != missing}
    done = run(host, **names)
    assert done.returncode != 0
    assert "name all three" in done.stdout
    assert log(host) == ""


@pytest.mark.parametrize("names, why", [
    ({**NAMES, "NERVUS_CT": "12"}, "NERVUS_CT must be a container id"),
    ({**NAMES, "NERVUS_CT": "123; rm -rf /"}, "NERVUS_CT must be a container id"),
    ({**NAMES, "API_HOST": "hv.example.net; id"}, "API_HOST must be a host name"),
])
def test_malformed_names_are_refused_before_anything(host, names, why):
    done = run(host, **names)
    assert done.returncode != 0 and why in done.stdout
    assert log(host) == ""


def test_it_stops_on_the_wrong_node_having_changed_nothing(host):
    done = run(host, node="elsewhere", **NAMES)
    assert done.returncode != 0
    assert "this is 'elsewhere', not 'hv'" in done.stdout
    assert "pveum" not in log(host) and "pct push" not in log(host)


def test_every_file_it_has_opened_in_nervus_s_folder_is_given_a_time(host):
    """nervus's account can put a pipe where a file of its own was, which a plain cmp, or a TLS
    library handed the CA's name, waits on for ever, and this script with it (procedure 062)."""
    done = run(host, **NAMES)
    assert done.returncode == 0, done.stdout + done.stderr
    calls = log(host).splitlines()
    reads = [line for line in calls if line.startswith("pct exec 123") and "cmp -s" in line]
    assert len(reads) == 2 and all("-- runuser -u nervus -- timeout --foreground 30 cmp -s - " in line for line in reads), reads
    handshake = [line for line in calls if line.startswith("pct exec 123") and "python" in line]
    assert len(handshake) == 1 and handshake[0].startswith("pct exec 123 -- timeout --foreground 60 /opt/nervus/.venv/bin/python"), handshake
