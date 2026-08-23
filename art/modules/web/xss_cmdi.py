"""web: reflected XSS and OS command injection probes (benign markers only)."""
from __future__ import annotations

import urllib.parse

from art.core.base import BaseModule, Finding, Severity

XSS_MARKERS = [
    '<script>alert("art")</script>',
    '"><svg/onload=alert("art")>',
    "<img src=x onerror=alert('art')>",
]
CMDI_PAYLOADS = [
    ("; id", ["uid=", "gid="]),
    ("| id", ["uid=", "gid="]),
    ("`id`", ["uid=", "gid="]),
]


def _url_with_param(base: str, param: str, value: str) -> str:
    sep = "&" if "?" in base else "?"
    return base + sep + urllib.parse.quote(param) + "=" + value


def _base_url(target: str) -> str:
    return target if target.startswith("http") else "http://" + target


class XssReflect(BaseModule):
    NAME = "xss_reflect"
    CATEGORY = "web"
    DESCRIPTION = "Check whether user input is reflected unencoded into responses (XSS)."
    OPTIONS = {"param": {"default": "name", "help": "parameter to test"},
               "path": {"default": "/", "help": "path containing the parameter"}}

    def run(self) -> list[Finding]:
        url = _base_url(self.ctx.target).rstrip("/") + str(self.opt("path"))
        param = str(self.opt("param"))
        findings = []
        for marker in XSS_MARKERS:
            probe_url = _url_with_param(url, param, marker)
            try:
                resp = self.ctx.http.get(probe_url)
            except Exception:  # noqa: BLE001
                continue
            if marker in resp.text:
                findings.append(self.finding(
                    "Reflected XSS confirmed", Severity.HIGH,
                    detail="Injected markup is echoed back unencoded - attacker-controlled "
                           "HTML/JS executes in victims' browsers.",
                    evidence="url: %s\nmarker reflected verbatim: %s" % (probe_url[:500], marker),
                    remediation="Contextually encode output; add CSP; use auto-escaping templates."))
                break
        if not findings:
            findings.append(self.finding(
                "No unencoded reflection found on parameter '%s'" % param, Severity.INFO))
        return findings


class CmdInjectProbe(BaseModule):
    NAME = "cmd_inject_probe"
    CATEGORY = "web"
    DESCRIPTION = "Probe for OS command injection using harmless `id` output markers."
    OPTIONS = {"param": {"default": "host", "help": "parameter to test"},
               "path": {"default": "/", "help": "path containing the parameter"}}

    def run(self) -> list[Finding]:
        url = _base_url(self.ctx.target).rstrip("/") + str(self.opt("path"))
        param = str(self.opt("param"))
        findings = []
        for payload, markers in CMDI_PAYLOADS:
            probe_url = _url_with_param(url, param, urllib.parse.quote(payload, safe=""))
            try:
                resp = self.ctx.http.get(probe_url)
            except Exception:  # noqa: BLE001
                continue
            if any(m in resp.text for m in markers):
                findings.append(self.finding(
                    "Command injection confirmed", Severity.CRITICAL,
                    detail="The harmless `id` command executed on the server; arbitrary "
                           "OS command execution is possible.",
                    evidence="payload=%r\nresponse contained uid=/gid= output" % payload,
                    remediation="Never pass user input to shells; use strict allow-lists "
                                "and library APIs instead of shell commands."))
                break
        if not findings:
            findings.append(self.finding(
                "No command injection detected on parameter '%s'" % param, Severity.INFO))
        return findings
