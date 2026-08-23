"""postexp: safe re-validation of previously recorded findings."""
from __future__ import annotations

from art.core.base import BaseModule, Finding, Severity


class ValidateFindings(BaseModule):
    NAME = "validate_findings"
    CATEGORY = "postexp"
    DESCRIPTION = ("Re-check that previously discovered HIGH/CRITICAL findings are "
                   "still present by replaying the same non-destructive modules.")
    OPTIONS = {}

    def run(self) -> list[Finding]:
        if self.ctx.store is None:
            return [self.finding("No findings store attached to context", Severity.LOW)]
        prior = [f for f in self.ctx.store.all()
                 if f.severity.rank >= Severity.MEDIUM.rank
                 and f.target == self.ctx.target]
        seen_modules = sorted({f.module for f in prior})
        self.ctx.log(f"{len(seen_modules)} module(s) previously reported medium+ findings")

        from art.core import registry

        # load the options each module was originally run with (if recorded)
        import json
        opts_path = self.ctx.workspace_dir / "last_options.json"
        try:
            saved_opts = json.loads(opts_path.read_text(encoding="utf-8")) \
                if opts_path.exists() else {}
        except Exception:  # noqa: BLE001
            saved_opts = {}

        findings: list[Finding] = []
        retested = []
        for mod_name in seen_modules:
            cls = registry.get(mod_name)
            if cls is None or not cls.ACTIVE:
                continue
            self.ctx.log(f"re-running {mod_name}")
            fresh_ctx = type(self.ctx)(
                mod_name, self.ctx.target, saved_opts.get(mod_name, {}),
                self.ctx.scope, self.ctx.workspace_dir, self.ctx.http)
            result = cls(fresh_ctx).safe_run()
            still_vuln = any(f.severity.rank >= Severity.MEDIUM.rank
                             for f in result.findings)
            status = "STILL PRESENT" if still_vuln else "resolved"
            retested.append(f"{mod_name}: {status}")
            if still_vuln:
                findings.append(self.finding(
                    f"Finding still exploitable in {mod_name}", Severity.HIGH,
                    detail="Re-validation reproduced the vulnerability.",
                    remediation="Apply remediation guidance from the original finding; "
                                "re-test after the fix is deployed."))
            else:
                findings.append(self.finding(
                    f"Finding resolved in {mod_name}", Severity.INFO,
                    detail="Re-validation no longer reproduces the issue."))
        summary = "\n".join(retested) or "no active findings to retest"
        findings.append(self.finding("Validation sweep complete", Severity.INFO,
                                     evidence=summary))
        return findings
