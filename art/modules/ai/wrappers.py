"""ai: wrappers that expose the existing garak and PyRIT pipelines as ART modules."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from art.core.base import BaseModule, Finding, Severity

LAB_DIR = Path(__file__).resolve().parents[3]  # .../AI Red Team Lab/garak-lab/art -> lab root
VENV = LAB_DIR / ".venv"


def _venv_exe(name: str) -> Path:
    if sys.platform == "win32":
        return VENV / "Scripts" / name
    return VENV / "bin" / name


class GarakScan(BaseModule):
    NAME = "garak_scan"
    CATEGORY = "ai"
    DESCRIPTION = "Run a full garak vulnerability scan against the configured LLM target."
    OPTIONS = {
        "probes": {"default": "promptinject", "help": "garak probe class or 'all'"},
        "config": {"default": str(LAB_DIR / "garak-lab" / "garak_gemini.yaml"),
                   "help": "garak YAML config"},
    }

    def run(self) -> list[Finding]:
        exe = _venv_exe("garak.exe" if sys.platform == "win32" else "garak")
        if not exe.exists():
            return [self.finding("garak not installed in .venv", Severity.LOW)]
        cmd = [str(exe), "--config", str(self.opt("config")),
               "--probes", str(self.opt("probes")), "--generations", "1"]
        self.ctx.log("running: " + " ".join(cmd))
        env = os.environ.copy()
        env["PYTHONUTF8"] = "1"
        env["OPENAICOMPATIBLE_API_KEY"] = os.environ.get("GEMINI_API_KEY", "")
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=3600, encoding="utf-8", errors="replace",
                              env=env)
        report_line = ""
        for line in (proc.stdout or "").splitlines():
            if "report.jsonl" in line:
                report_line = line.strip()
        ok = proc.returncode == 0
        findings = [self.finding(
            "garak scan finished " + ("successfully" if ok else f"with code {proc.returncode}"),
            Severity.INFO if ok else Severity.LOW,
            evidence=(report_line or "\n".join((proc.stdout or "").splitlines()[-10:])))
        ]
        # parse attempt results from stdout summary lines like: probes.x: FAIL  ok on 12/256
        fails = 0
        for line in (proc.stdout or "").splitlines():
            if "FAIL" in line:
                fails += 1
        if fails:
            findings.append(self.finding(
                f"garak reported {fails} failing detector combinations", Severity.MEDIUM,
                detail="Probes found responses the detectors flagged as vulnerable.",
                remediation="Review the HTML/JSONL report for details."))
        return findings


class PyritPayloads(BaseModule):
    NAME = "pyrit_payloads"
    CATEGORY = "ai"
    DESCRIPTION = "Replay the PyRIT adversarial payload suite against the LLM target."
    OPTIONS = {}

    def run(self) -> list[Finding]:
        script = LAB_DIR / "garak-lab" / "run_pyrit_demo.py"
        py = _venv_exe("python.exe" if sys.platform == "win32" else "python")
        if not script.exists() or not py.exists():
            return [self.finding("PyRIT demo script/venv missing", Severity.LOW)]
        self.ctx.log(f"running {script.name}")
        try:
            proc = subprocess.run([str(py), str(script)], capture_output=True,
                                  text=True, timeout=1800,
                                  encoding="utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            return [self.finding("PyRIT run timed out", Severity.LOW)]
        errors = (proc.stdout + proc.stderr).count("ERROR") 
        findings = [self.finding(
            "PyRIT payload run complete", Severity.INFO,
            evidence=f"exit={proc.returncode}\n{(proc.stdout or '')[-800:]}")]
        if errors:
            findings.append(self.finding(
                "Some PyRIT payloads produced ERROR output", Severity.LOW,
                detail="Check the SQLite memory DB / console log for details."))
        return findings
