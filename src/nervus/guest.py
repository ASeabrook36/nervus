"""nervus's own work inside a VM, through Proxmox's guest agent (ADR-0017 L2):
run a fixed script as root there, and read the VM's addresses. The guest agent
is a virtual serial line between the hypervisor and the VM, with no network,
so what it reports can only be lied about by root in that VM (ADR-0022 3a).

`api` is a ProxmoxClient, or anything with its `request`. Uploads have their
own copy of the run-and-wait loop (upload_targets.VMDelivery), from before
this module existed.
"""

from __future__ import annotations

import asyncio


class GuestError(Exception):
    """A guest-agent call that failed. `code` is for the client and the audit
    log; the message says what happened in words."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


# Waiting for a guest command: at once, then a little longer each time.
FIRST_POLL, MAX_POLL = 0.05, 0.5


class Guest:
    """One VM, as its guest agent sees it."""

    def __init__(self, api, vmid: int, *, poll: float = FIRST_POLL, max_poll: float = MAX_POLL):
        self.api = api
        self.vmid = vmid
        self.poll = poll
        self.max_poll = max_poll
        self._agent: str | None = None

    async def _call(self, method: str, path: str, params: dict | None = None):
        resp = await self.api.request(method, path, params or {})
        if resp.status != 200:
            reason = f"{resp.reason} {resp.errors}" if resp.errors else resp.reason
            raise GuestError("guest_agent_error", f"VM {self.vmid}: Proxmox answered {resp.status} {reason}")
        return resp.data

    async def agent(self) -> str:
        """The VM's guest-agent path. A guest the token cannot see, or that is
        not a QEMU VM (a container has no guest agent), is refused."""
        if self._agent is None:
            guests = await self._call("GET", "/cluster/resources", {"type": "vm"}) or []
            match = [g for g in guests if isinstance(g, dict) and g.get("vmid") == self.vmid]
            if not match or match[0].get("type") != "qemu":
                raise GuestError("no_such_vm", f"no QEMU VM {self.vmid} that nervus's Proxmox token can see")
            self._agent = f"/nodes/{match[0]['node']}/qemu/{self.vmid}/agent"
        return self._agent

    async def sh(self, script: str, args: list[str], *, stdin: str | None = None,
                 timeout: float = 60.0) -> tuple[int | None, str, str]:
        """Run `script` with `sh -c` as root in the VM, `args` as its $1, $2...
        Never through a shell on nervus's side: the command is a list. Returns
        the exit code, standard output and standard error."""
        agent = await self.agent()
        params: dict = {"command": ["sh", "-c", script, "sh", *args]}
        if stdin is not None:
            params["input-data"] = stdin
        started = await self._call("POST", f"{agent}/exec", params)
        pid = started.get("pid") if isinstance(started, dict) else None
        if not isinstance(pid, int):
            raise GuestError("guest_agent_error", f"VM {self.vmid}: the guest agent started no command: {started!r}")
        waited, pause = 0.0, 0.0
        while True:
            if pause:
                await asyncio.sleep(pause)
                waited += pause
            status = await self._call("GET", f"{agent}/exec-status", {"pid": pid})
            if isinstance(status, dict) and status.get("exited"):
                return status.get("exitcode"), str(status.get("out-data", "")), str(status.get("err-data", ""))
            if waited >= timeout:
                raise GuestError("guest_agent_error", f"VM {self.vmid}: the guest command took over {timeout:.0f} s")
            pause = min(max(pause * 2, self.poll), self.max_poll)

    async def addresses(self) -> list[str]:
        """Every IP address the VM's interfaces report, IPv4 first, each in
        the order the guest agent gave it. Unfiltered: loopback included."""
        data = await self._call("GET", f"{await self.agent()}/network-get-interfaces")
        interfaces = data.get("result") if isinstance(data, dict) else data
        v4, v6 = [], []
        for interface in interfaces if isinstance(interfaces, list) else []:
            for entry in (interface.get("ip-addresses") or []) if isinstance(interface, dict) else []:
                if not isinstance(entry, dict) or not isinstance(entry.get("ip-address"), str):
                    continue
                (v6 if entry.get("ip-address-type") == "ipv6" else v4).append(entry["ip-address"])
        return list(dict.fromkeys(v4 + v6))
