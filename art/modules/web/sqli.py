"""web: injection detection - SQLi (error/boolean/time).

All payloads are non-destructive: benign markers, boolean comparisons,
and short sleeps only.
"""
from __future__ import annotations

import time
import urllib.parse

from art.core.base import BaseModule, Finding, Severity

SQLI_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "sqlite3.operationalexception",
    "pg_query(): query failed",
    "ora-01756",
    "sql syntax error",
    "syntax error at or near",
]
SQLI_TIME_PAYLOAD = "' OR SLEEP(3)-- -"
SQLI_BOOL_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND 1=1-- -", "' AND 1=2-- -"),
]


def _url_with_param(base: str, param: str, value: str) -> str:
    sep = "&" if "?" in base else "?"
    return base + sep + urllib.parse.quote(param, safe="") + "=" + urllib.parse.quote(value, safe="")


def _base_url(target: str) -> str:
    return target if target.startswith("http") else "http://" + target


class SqliDetect(BaseModule):
    NAME = "sqli_detect"
    CATEGORY = "web"
    DESCRIPTION = "Detect SQL injection via error signatures, boolean diffing and timing."
    OPTIONS = {
        "param": {"default": "id", "help": "query parameter to test"},
        "path": {"default": "/", "help": "base path containing the parameter"},
        "time_threshold_s": {"default": 2.5, "help": "latency indicating blind SQLi"},
    }

    def run(self) -> list[Finding]:
        url = _base_url(self.ctx.target).rstrip("/") + str(self.opt("path"))
        param = str(self.opt("param"))
        findings: list[Finding] = []

        r0 = self.ctx.http.get(url)
        len0 = len(r0.text)

        # 1. error-based
        err_payload = "'"
        try:
            r = self.ctx.http.get(_url_with_param(url, param, err_payload))
            low = r.text.lower()
            matched = [sig for sig in SQLI_ERRORS if sig in low]
            if matched:
                findings.append(self.finding(
                    "SQL error message disclosed (possible error-based SQLi)",
                    Severity.HIGH,
                    detail="Database error text returned in the response leaks schema "
                           "details and confirms input reaches a SQL parser.",
                    evidence="payload=%r\nmatched signature: %s" % (err_payload, matched[0]),
                    remediation="Use parameterized queries; disable verbose DB errors."))
        except Exception:  # noqa: BLE001
            pass

        # 2. boolean-based
        for true_p, false_p in SQLI_BOOL_PAIRS:
            try:
                rt = self.ctx.http.get(_url_with_param(url, param, true_p))
                rf = self.ctx.http.get(_url_with_param(url, param, false_p))
                diff = abs(len(rt.text) - len(rf.text))
                if diff > max(32, len0 * 0.05):
                    findings.append(self.finding(
                        "Boolean-based SQL injection suspected", Severity.HIGH,
                        detail="TRUE and FALSE conditions return significantly different "
                               "responses, indicating the payload altered query logic.",
                        evidence=("TRUE payload %r -> %d bytes\n"
                                  "FALSE payload %r -> %d bytes\n"
                                  "baseline -> %d bytes") % (true_p, len(rt.text),
                                                             false_p, len(rf.text), len0),
                        remediation="Parameterize all queries; validate input server-side."))
                    break
            except Exception:  # noqa: BLE001
                continue

        # 3. time-based
        try:
            t_start = time.time()
            self.ctx.http.get(_url_with_param(url, param, SQLI_TIME_PAYLOAD), timeout=30)
            elapsed = time.time() - t_start
            threshold = float(self.opt("time_threshold_s"))
            if elapsed > threshold:
                findings.append(self.finding(
                    "Time-based blind SQL injection suspected", Severity.HIGH,
                    detail="Response delayed %.1fs after SLEEP() payload "
                           "(threshold %.1fs)." % (elapsed, threshold),
                    evidence="elapsed=%.2fs payload=%r" % (elapsed, SQLI_TIME_PAYLOAD),
                    remediation="Parameterize queries; enforce statement timeouts."))
        except Exception:  # noqa: BLE001
            pass

        if not findings:
            findings.append(self.finding(
                "No SQLi indicators on parameter '%s'" % param, Severity.INFO))
        return findings
