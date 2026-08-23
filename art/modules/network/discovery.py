"""network: host discovery via TCP ping sweep."""
from __future__ import annotations

import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from socket import create_connection

from art.core.base import BaseModule, Finding, Severity

PING_PORTS = [80, 443, 22, 445, 3389]


def _probe(args):
    ip, port = args
    try:
        with create_connection((str(ip), port), timeout=1.0):
            return (str(ip), port)
    except OSError:
        return None


class HostDiscovery(BaseModule):
    NAME = "host_discovery"
    CATEGORY = "network"
    DESCRIPTION = "Discover live hosts in a CIDR range via TCP-ping sweep."
    OPTIONS = {
        "ports": {"default": ",".join(map(str, PING_PORTS)), "help": "TCP ports to probe"},
        "threads": {"default": 100, "help": "concurrent probes"},
    }

    def run(self) -> list[Finding]:
        self.ctx.assert_authorized()
        net = ipaddress.ip_network(self.ctx.target, strict=False)
        if net.num_addresses > 4096:
            raise ValueError("Range too large for quick sweep (> /20). Narrow the CIDR.")
        ports = [int(p) for p in str(self.opt("ports")).split(",") if p.strip()]
        jobs = [(ip, p) for ip in net.hosts() or [net.network_address] for p in ports]
        self.ctx.log(f"probing {net.num_addresses} addresses x {len(ports)} ports")
        live: dict[str, list[int]] = {}
        with ThreadPoolExecutor(max_workers=int(self.opt("threads"))) as pool:
            for res in pool.map(_probe, jobs):
                if res:
                    live.setdefault(res[0], []).append(res[1])
                    print(f"    [host_discovery] {res[0]} alive (port {res[1]})")
        findings = []
        if live:
            listing = "\n".join(f"{h} - ports {','.join(map(str, ps))}"
                                for h, ps in sorted(live.items()))
            findings.append(self.finding(
                f"{len(live)} live hosts discovered", Severity.INFO,
                detail="Hosts responded on at least one probed TCP port.",
                evidence=listing))
            findings.append(self.finding(
                "Internal services reachable from scan position", Severity.LOW,
                detail="Hosts listening on management ports inside this range widen "
                       "lateral movement options after any foothold.",
                remediation="Segment networks; restrict management ports to admin VLANs."))
        else:
            findings.append(self.finding("No live hosts found", Severity.INFO))
        return findings
