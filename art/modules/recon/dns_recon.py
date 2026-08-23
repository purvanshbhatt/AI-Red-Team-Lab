"""recon: DNS enumeration + subdomain discovery."""
from __future__ import annotations

import socket
from pathlib import Path

from art.core.base import BaseModule, Finding, Severity

WL_DIR = Path(__file__).resolve().parents[2] / "wordlists"


def _host_only(target: str) -> str:
    """Strip scheme/port/path so DNS modules get a bare hostname."""
    t = target.strip()
    if "://" in t:
        t = t.split("://", 1)[1]
    return t.split("/")[0].split(":")[0]


class DnsEnum(BaseModule):
    NAME = "dns_enum"
    CATEGORY = "recon"
    DESCRIPTION = "Resolve the target and enumerate common hostnames via DNS."
    ACTIVE = False  # passive: public DNS lookups only
    OPTIONS = {
        "wordlist": {"default": "subs_common.txt", "help": "wordlist file under art/wordlists/"},
    }

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        domain = _host_only(self.ctx.target)
        try:
            ip = socket.gethostbyname(domain)
            self.ctx.log(f"{domain} resolves to {ip}")
            findings.append(self.finding(
                f"Host resolves to {ip}", Severity.INFO, detail=f"A record for {domain}."))
        except socket.gaierror:
            return [self.finding("Host does not resolve", Severity.LOW,
                                 detail=f"No A record found for {domain}.")]

        wl = WL_DIR / self.opt("wordlist")
        hosts = [l.strip() for l in wl.read_text(encoding="utf-8").splitlines()
                 if l.strip() and not l.startswith("#")]
        found = []
        for sub in hosts:
            fqdn = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(fqdn)
                found.append((fqdn, ip))
                self.ctx.log(f"found {fqdn} -> {ip}")
            except (socket.gaierror, OSError):
                continue
        if found:
            listing = "\n".join(f"{h} -> {i}" for h, i in found)
            findings.append(self.finding(
                f"{len(found)} subdomains resolved via DNS", Severity.INFO,
                detail="Hostnames discovered through DNS resolution of a common-name wordlist.",
                evidence=listing,
                remediation="Review whether these hosts were intended to be publicly resolvable."))
        else:
            findings.append(self.finding("No subdomains found from wordlist", Severity.INFO))
        return findings


class SubdomainOsint(BaseModule):
    NAME = "subdomain_osint"
    CATEGORY = "recon"
    DESCRIPTION = "Passive subdomain discovery via Certificate Transparency logs (crt.sh)."
    ACTIVE = False
    OPTIONS = {}

    def run(self) -> list[Finding]:
        domain = self.ctx.target
        try:
            resp = self.ctx.http.get(
                f"https://crt.sh/?q=%25.{domain}&output=json", timeout=20)
            if resp.status_code != 200:
                return [self.finding("CT log lookup failed", Severity.INFO,
                                     detail=f"crt.sh returned HTTP {resp.status_code}")]
            rows = resp.json()
        except Exception as e:  # noqa: BLE001
            return [self.finding("CT log lookup unavailable (offline?)", Severity.INFO,
                                 detail=str(e))]
        names = set()
        for row in rows:
            for n in str(row.get("name_value", "")).split("\n"):
                n = n.strip().lower()
                if n and (n == domain or n.endswith("." + domain)):
                    names.add(n)
        if names:
            findings = [self.finding(
                f"{len(names)} unique hostnames in CT logs", Severity.INFO,
                detail="Subdomains harvested from public certificate transparency logs.",
                evidence="\n".join(sorted(names)))]
        else:
            findings = [self.finding("No CT entries found", Severity.INFO)]
        return findings
