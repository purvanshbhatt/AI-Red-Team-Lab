"""Findings persistence + report export (SQLite -> HTML/JSON/Markdown)."""
from __future__ import annotations

import html
import json
import sqlite3
import time
from pathlib import Path

from art.core.base import Finding, Severity, SEVERITY_ORDER

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    module TEXT, title TEXT, severity TEXT, target TEXT,
    detail TEXT, evidence TEXT, remediation TEXT, timestamp REAL,
    UNIQUE(module, title, target)
);
"""


class FindingsStore:
    def __init__(self, workspace_dir: Path):
        self.workspace_dir = workspace_dir
        self.db_path = workspace_dir / "findings.db"
        self.conn = sqlite3.connect(self.db_path)
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def add(self, f: Finding) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO findings (module,title,severity,target,detail,evidence,"
            "remediation,timestamp) VALUES (?,?,?,?,?,?,?,?)",
            (f.module, f.title, f.severity.value, f.target, f.detail, f.evidence,
             f.remediation, f.timestamp),
        )
        self.conn.commit()

    def add_many(self, findings: list[Finding]) -> int:
        for f in findings:
            self.add(f)
        return len(findings)

    def all(self) -> list[Finding]:
        cur = self.conn.execute(
            "SELECT module,title,severity,target,detail,evidence,remediation,timestamp "
            "FROM findings ORDER BY timestamp"
        )
        return [
            Finding(m, t, Severity(s), tg, d, e, r, ts)
            for m, t, s, tg, d, e, r, ts in cur.fetchall()
        ]

    def counts_by_severity(self) -> dict[str, int]:
        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in self.all():
            counts[f.severity.value] += 1
        return counts

    # -- exports -----------------------------------------------------------
    def export_json(self, path: Path | None = None) -> Path:
        path = path or self.workspace_dir / "report.json"
        data = [f.as_dict() for f in self.all()]
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return path

    def export_markdown(self, path: Path | None = None) -> Path:
        path = path or self.workspace_dir / "report.md"
        findings = sorted(self.all(), key=lambda x: -x.severity.rank)
        lines = [
            "# ART Engagement Report",
            "",
            f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "| Severity | Module | Finding | Target |",
            "|---|---|---|---|",
        ]
        for f in findings:
            lines.append(
                f"| **{f.severity.value.upper()}** | {f.module} | {f.title} | {f.target} |"
            )
        lines.append("")
        for i, f in enumerate(findings, 1):
            lines += [
                f"## {i}. [{f.severity.value.upper()}] {f.title}",
                f"- **Module:** `{f.module}`  ",
                f"- **Target:** {f.target}",
                "",
                f"{f.detail}",
                "",
                f"**Evidence**\n\n```\n{f.evidence}\n```",
                "",
                f"**Remediation:** {f.remediation}",
                "",
            ]
        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    def export_html(self, path: Path | None = None) -> Path:
        path = path or self.workspace_dir / "report.html"
        esc = html.escape
        findings = sorted(self.all(), key=lambda x: -x.severity.rank)
        counts = self.counts_by_severity()
        badges = " &middot; ".join(
            f"<span class='badge sev-{s}'>{counts[s]} {s}</span>"
            for s in ("critical", "high", "medium", "low", "info")
        )
        rows = []
        for f in findings:
            rows.append(
                "<tr>"
                f"<td><span class='badge sev-{f.severity.value}'>{f.severity.value.upper()}</span></td>"
                f"<td>{esc(f.title)}<div class='detail'>{esc(f.detail)}</div>"
                f"<div class='evidence'><pre>{esc(f.evidence)}</pre></div>"
                f"<div class='rem'><b>Remediation:</b> {esc(f.remediation)}</div></td>"
                f"<td><code>{esc(f.module)}</code></td>"
                f"<td>{esc(f.target)}</td>"
                "</tr>"
            )
        doc = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>ART Report</title>
<style>
 body {{ font-family: 'Segoe UI', sans-serif; margin: 2rem; background:#0d1117; color:#c9d1d9; }}
 h1 {{ color:#58a6ff; }}
 .badge {{ padding:2px 8px; border-radius:4px; font-size:.75em; font-weight:bold; }}
 .sev-critical {{ background:#da3633; color:#fff; }}
 .sev-high {{ background:#e36209; color:#fff; }}
 .sev-medium {{ background:#d29922; color:#111; }}
 .sev-low {{ background:#1f6feb; color:#fff; }}
 .sev-info {{ background:#30363d; color:#c9d1d9; }}
 table {{ border-collapse: collapse; width:100%; }}
 td, th {{ border:1px solid #30363d; padding:10px; vertical-align:top; text-align:left;}}
 tr:nth-child(even) {{ background:#161b22; }}
 pre {{ background:#010409; padding:8px; overflow-x:auto; white-space:pre-wrap; }}
 .detail, .rem {{ margin-top:6px; }}
 code {{ color:#79c0ff; }}
</style></head><body>
<h1>ART — AI Red Team / VAPT Report</h1>
<p>Generated {time.strftime('%Y-%m-%d %H:%M:%S')} &middot; {len(findings)} findings</p>
<p>{badges}</p>
<table><tr><th>Severity</th><th>Finding</th><th>Module</th><th>Target</th></tr>
{''.join(rows)}
</table></body></html>"""
        path.write_text(doc, encoding="utf-8")
        return path
