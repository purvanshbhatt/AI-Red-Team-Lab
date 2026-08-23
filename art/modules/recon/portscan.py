"""recon: TCP port scanning and service banner grabbing."""
from __future__ import annotations

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed

from art.core.base import BaseModule, Finding, Severity

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9200, 27017,
]
BANNER_PORTS = {21: None, 22: None, 25: b"QUIT\r\n", 80: b"GET / HTTP/1.0\r\n\r\n",
                443: b"GET / HTTP/1.0\r\n\r\n", 110: b"QUIT\r\n", 143: b"a LOGOUT\r\n"}
SERVICE_NAMES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 135: "msrpc", 139: "netbios", 143: "imap", 443: "https",
    445: "smb", 3306: "mysql", 3389: "rdp", 5432: "postgres", 6379: "redis",
    8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb",
}


def _host_only(target: str) -> str:
    t = target.strip()
    if "://" in t:
        t = t.split("://", 1)[1]
    return t.split("/")[0].split(":")[0]


def tcp_connect(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


class PortScan(BaseModule):
    NAME = "port_scan"
    CATEGORY = "recon"
    DESCRIPTION = "Full TCP connect scan of the top 26 ports (threaded)."
    OPTIONS = {
        "ports": {"default": ",".join(map(str, TOP_PORTS)), "help": "comma-separated port list"},
        "timeout": {"default": 2.0, "help": "connect timeout seconds"},
        "threads": {"default": 50, "help": "concurrent connections"},
    }

    def run(self) -> list[Finding]:
        self.ctx.assert_authorized()
        host = _host_only(self.ctx.target)
        ports = sorted({int(p) for p in str(self.opt("ports")).split(",") if p.strip()})
        open_ports = []
        with ThreadPoolExecutor(max_workers=int(self.opt("threads"))) as pool:
            futures = {pool.submit(tcp_connect, host, p, float(self.opt("timeout"))): p
                       for p in ports}
            for fut in as_completed(futures):
                if fut.result():
                    p = futures[fut]
                    open_ports.append(p)
                    self.ctx.log(f"open  {host}:{p} ({SERVICE_NAMES.get(p, '?')})")
        open_ports.sort()
        findings = []
        if open_ports:
            risky = [p for p in open_ports if p in (21, 23, 445, 3389, 6379, 27017)]
            listing = "\n".join(f"{p}/tcp open  {SERVICE_NAMES.get(p, 'unknown')}" for p in open_ports)
            findings.append(self.finding(
                f"{len(open_ports)} open TCP ports", Severity.INFO,
                detail="Ports accepting TCP connections.",
                evidence=listing))
            if risky:
                findings.append(self.finding(
                    f"Risky services exposed: {', '.join(SERVICE_NAMES.get(p, str(p)) for p in risky)}",
                    Severity.MEDIUM,
                    detail="Legacy or administration protocols are reachable. "
                           "These frequently expose unauthenticated attack surface.",
                    evidence="\n".join(str(p) for p in risky),
                    remediation="Restrict with firewall rules / VPN; disable unused services."))
        else:
            findings.append(self.finding("No open ports found in scanned range", Severity.INFO))
        return findings


class BannerGrab(BaseModule):
    NAME = "banner_grab"
    CATEGORY = "recon"
    DESCRIPTION = "Grab service banners on common ports to identify software/versions."
    OPTIONS = {"timeout": {"default": 3.0, "help": "socket timeout"}}

    def run(self) -> list[Finding]:
        self.ctx.assert_authorized()
        host = _host_only(self.ctx.target)
        timeout = float(self.opt("timeout"))
        banners = {}
        for port, probe in BANNER_PORTS.items():
            try:
                sock = socket.create_connection((host, port), timeout=timeout)
            except OSError:
                continue
            banner = ""
            try:
                if port == 443:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with ctx.wrap_socket(sock, server_hostname=host) as tls:
                        tls.settimeout(timeout)
                        if probe:
                            tls.sendall(probe)
                        banner = tls.recv(1024).decode("utf-8", "replace").strip()
                        cert_bin = tls.getpeercert(binary_form=True)
                    del cert_bin
                else:
                    sock.settimeout(timeout)
                    if probe:
                        sock.sendall(probe)
                    banner = sock.recv(1024).decode("utf-8", "replace").strip()
            except (OSError, ssl.SSLError) as e:
                banner = f"<{type(e).__name__}>"
            finally:
                sock.close()
            if banner:
                banners[port] = banner[:300]
                self.ctx.log(f"{host}:{port} -> {banner[:120]}")
        findings = []
        for port, banner in banners.items():
            low = banner.lower()
            sev = Severity.INFO
            title = f"Banner on port {port}"
            remediation = ""
            if any(x in low for x in ("openssh_4", "openssh_5", "openssh_6.", "vsftpd 2", "apache/2.2")):
                sev = Severity.LOW
                title += " (potentially outdated)"
                remediation = "Verify the service version is patched and current."
            findings.append(self.finding(title, sev, evidence=f"{port}/tcp:\n{banner}",
                                         remediation=remediation))
        if not banners:
            findings.append(self.finding("No banners retrieved", Severity.INFO))
        return findings

