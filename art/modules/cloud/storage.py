"""cloud: anonymous-access checks for object storage (S3 / Azure / GCS)."""
from __future__ import annotations

from art.core.base import BaseModule, Finding, Severity

PROBES = {
    "aws_s3": "https://{name}.s3.amazonaws.com/",
    "azure_blob": "https://{name}.blob.core.windows.net/",
    "gcs": "https://{name}.storage.googleapis.com/",
}


class StorageMisconfig(BaseModule):
    NAME = "storage_misconfig"
    CATEGORY = "cloud"
    DESCRIPTION = "Check whether named cloud storage buckets allow anonymous listing/access."
    OPTIONS = {
        "names": {"default": "", "help": "comma-separated bucket names", "required": True},
        "providers": {"default": "aws_s3,azure_blob,gcs", "help": "providers to test"},
    }

    def run(self) -> list[Finding]:
        names = [n.strip() for n in str(self.opt("names")).split(",") if n.strip()]
        providers = [p.strip() for p in str(self.opt("providers")).split(",") if p.strip()]
        findings: list[Finding] = []
        for name in names:
            for prov in providers:
                url_tpl = PROBES.get(prov)
                if not url_tpl:
                    continue
                url = url_tpl.format(name=name)
                try:
                    resp = self.ctx.http.get(url, timeout=8)
                except Exception as e:  # noqa: BLE001
                    self.ctx.log(f"{prov}:{name} unreachable ({type(e).__name__})")
                    continue
                status = resp.status_code
                self.ctx.log(f"{prov}:{name} -> HTTP {status}")
                if prov == "aws_s3" and "ListBucketResult" in resp.text:
                    findings.append(self.finding(
                        f"Public S3 bucket allows anonymous listing: {name}", Severity.HIGH,
                        detail="Anyone can enumerate all objects in the bucket.",
                        evidence=url,
                        remediation="Disable public ACLs; enable Block Public Access."))
                elif status == 200:
                    findings.append(self.finding(
                        f"Anonymous access allowed on {prov}:{name}", Severity.MEDIUM,
                        evidence=url,
                        remediation="Restrict anonymous read access unless intended."))
                elif status in (403, 401):
                    findings.append(self.finding(
                        f"{prov}:{name} correctly denies anonymous access", Severity.INFO,
                        evidence=f"HTTP {status}"))
        if not findings:
            findings.append(self.finding("No storage endpoints responded", Severity.INFO))
        return findings
