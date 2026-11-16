"""Tests for tools/proxmox-template, the root script that builds a VM template (ADR-0017).

The script runs as root on a Proxmox host, which no test can be. What these tests
can hold is everything it would write into the guest and every value the
protection rests on: the script prints its own seed files and settings, so the
tests check exactly what it would use, not a copy. A real build is observed
on the machine, as procedure 025 did.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

TOOL = Path(__file__).resolve().parent.parent / "tools" / "proxmox-template"


def run(*args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(TOOL), *args], capture_output=True, text=True, env=env, timeout=30
    )


def printed(flag: str) -> str:
    done = run(flag)
    assert done.returncode == 0, done.stderr
    return done.stdout


def user_data() -> dict:
    return yaml.safe_load(printed("--print-user-data"))


def settings() -> dict[str, str]:
    lines = printed("--print-settings").splitlines()
    return dict(line.split("=", 1) for line in lines if "=" in line)


def test_the_script_parses():
    done = subprocess.run(["bash", "-n", str(TOOL)], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr


def test_user_data_is_cloud_config():
    # cloud-init reads a user-data file as cloud-config only when its first
    # line is exactly this; anything else is treated as a script or ignored.
    assert printed("--print-user-data").splitlines()[0] == "#cloud-config"
    assert isinstance(user_data(), dict)


def test_meta_data_names_an_instance():
    meta = yaml.safe_load(printed("--print-meta-data"))
    assert meta["instance-id"]
    assert meta["local-hostname"]


def test_the_guest_agent_is_installed_and_started():
    data = user_data()
    assert "qemu-guest-agent" in data["packages"]
    assert ["systemctl", "start", "qemu-guest-agent"] in data["runcmd"]


def test_the_seed_creates_no_account_and_no_credential():
    # ADR-0017 F1: no user, password or SSH key, in the builder or any clone.
    data = user_data()
    assert data["users"] == []
    assert data["disable_root"] is True
    assert data["ssh_pwauth"] is False
    text = printed("--print-user-data").lower()
    for word in ("password", "passwd", "chpasswd", "ssh_authorized_keys", "ssh-ed25519", "ssh-rsa"):
        assert word not in text, word


def test_automatic_security_updates_are_switched_on_after_install():
    # ADR-0017 F1: a clone that lives a year keeps patching itself. The file is
    # written in the final stage (defer), after the package is installed, so the
    # package's own setup cannot replace it.
    data = user_data()
    assert "unattended-upgrades" in data["packages"]
    (entry,) = [f for f in data["write_files"] if f["path"] == "/etc/apt/apt.conf.d/20auto-upgrades"]
    assert entry["defer"] is True
    assert 'APT::Periodic::Update-Package-Lists "1";' in entry["content"]
    assert 'APT::Periodic::Unattended-Upgrade "1";' in entry["content"]


def test_the_template_role_holds_only_audit_and_clone():
    # ADR-0017 E1: on the template's own path the scoped token may look and
    # clone, nothing else. One more privilege here would undo the protection.
    assert settings()["ROLE_PRIVS"] == "VM.Audit,VM.Clone"


def test_the_image_is_pinned_by_url_and_sha512():
    s = settings()
    assert s["IMAGE_URL"].startswith("https://cloud.debian.org/images/cloud/trixie/")
    assert s["IMAGE_URL"].endswith("/" + s["IMAGE_FILE"])
    assert re.fullmatch(r"[0-9a-f]{128}", s["IMAGE_SHA512"])
    # The build date in the name is the image's, so an agent can see its age (D1).
    build = re.search(r"-(\d{8})-\d+\.qcow2$", s["IMAGE_FILE"]).group(1)
    assert s["TEMPLATE_NAME"] == f"nervus-debian-13-{build}"


def test_storage_and_bridge_default_to_proxmoxs_own_and_can_be_chosen():
    s = settings()
    assert (s["DISK_STORAGE"], s["BRIDGE"]) == ("local-lvm", "vmbr0")
    env = dict(os.environ, DISK_STORAGE="fast", BRIDGE="vmbr1")
    lines = run("--print-settings", env=env).stdout.splitlines()
    assert "DISK_STORAGE=fast" in lines and "BRIDGE=vmbr1" in lines


def test_a_clone_gets_the_hosts_own_processor_unless_another_model_is_chosen():
    # ADR-0017 question F, amended 2026-11-15. The template set no model, so a clone got the
    # hypervisor's old default, on which newer programs cannot run (procedure 032).
    assert settings()["CPU_MODEL"] == "host"
    chosen = run("--print-settings", env={**os.environ, "CPU_MODEL": "x86-64-v3"})
    assert "CPU_MODEL=x86-64-v3" in chosen.stdout.splitlines()
    script = TOOL.read_text()
    create = script[script.index("qm create"):script.index("|| die \"qm create failed\"")]
    assert '--cpu "$CPU_MODEL"' in create  # the VM is built with it, so every clone has it
    assert "grep -qx \"cpu: $CPU_MODEL\"" in script  # and the build checks that the template does


@pytest.mark.parametrize("model", ["host; rm -rf /", "host,flags=+aes", "x86 64", "-cpu", "a" * 65])
def test_a_processor_model_that_is_not_one_word_is_refused(model):
    done = run("--print-settings", env={**os.environ, "CPU_MODEL": model})
    assert done.returncode == 1 and "CPU_MODEL" in done.stdout


def test_no_node_name_is_built_in():
    """ADR-0019: the node it must run on is named by whoever runs it."""
    assert "EXPECTED_NODE=${NODE:-}" in TOOL.read_text()


def test_the_template_id_defaults_to_9000_and_can_be_chosen():
    assert settings()["TEMPLATE_ID"] == "9000"
    env = dict(os.environ, TEMPLATE_ID="9001")
    done = run("--print-settings", env=env)
    assert "TEMPLATE_ID=9001" in done.stdout.splitlines()


def test_a_template_id_that_is_not_a_number_is_refused():
    env = dict(os.environ, TEMPLATE_ID="9000; rm -rf /")
    done = run("--print-settings", env=env)
    assert done.returncode != 0
    assert "TEMPLATE_ID" in done.stdout + done.stderr


@pytest.mark.skipif(os.geteuid() == 0, reason="the refusal is for anyone but root")
def test_building_refuses_anyone_but_root_before_doing_anything():
    done = run()
    assert done.returncode != 0
    assert "must run as root" in done.stdout + done.stderr
    # It stopped at the first check: no step past reading was announced.
    assert "2." not in done.stdout


def test_an_unknown_option_is_refused():
    done = run("--frobnicate")
    assert done.returncode != 0


# Proxmox names the cloud-init drive by the kind of storage: `<storage>:vm-<id>-cloudinit` on a
# block storage (lvm-thin, ZFS), `<storage>:<id>/vm-<id>-cloudinit.qcow2` on a directory. The
# verification step must find either, or a template built on a directory storage stops as if it
# had none (procedure 058, on a nested Proxmox VE with only `local`).
@pytest.mark.parametrize("storage, line", [
    ("local-lvm", "ide2: local-lvm:vm-9000-cloudinit,media=cdrom"),
    ("local", "ide2: local:9000/vm-9000-cloudinit.qcow2,media=cdrom"),
])
def test_the_cloud_init_drive_is_found_on_either_kind_of_storage(tmp_path, storage, line):
    config = tmp_path / "config"
    config.write_text(f"agent: enabled=1\n{line}\ntemplate: 1\n")
    done = run("--check-cloudinit-drive", str(config), env=dict(os.environ, DISK_STORAGE=storage))
    assert done.returncode == 0, done.stderr


@pytest.mark.parametrize("line", [
    "ide2: local:iso/nervus-template-seed-9000.iso,media=cdrom",  # the seed disc, not Proxmox's drive
    "ide2: other:vm-9000-cloudinit,media=cdrom",                    # another storage
    "ide2: local-lvm:vm-9001-cloudinit,media=cdrom",                # another VM's
    "ide2: local-lvm:vm-90000-cloudinit,media=cdrom",
    "scsi0: local-lvm:base-9000-disk-0,size=16G",                   # none at all
])
def test_anything_else_is_not_the_cloud_init_drive(tmp_path, line):
    config = tmp_path / "config"
    config.write_text(f"{line}\n")
    done = run("--check-cloudinit-drive", str(config), env=dict(os.environ, DISK_STORAGE="local-lvm"))
    assert done.returncode != 0
