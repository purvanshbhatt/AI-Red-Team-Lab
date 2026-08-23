"""recon: HTTP technology fingerprinting."""
from __future__ import annotations

import re

from art.core.base import BaseModule, Finding, Severity


class TechFingerprint(BaseModule):
    NAME = "tech_fingerprint"
    CATEGORY = "recon"
    DESCRIPTION = "Fingerprint web server, framework, and exposed tech markers."
    OPTIONS = {"path": {"default": "/", "help": "path to fingerprint"},
               "use_tls_hint": {"default": "auto", "help": "auto|http|https"}}

    MARKERS = {
        "WordPress": ["wp-content", "wp-includes"],
        "Drupal": ["drupal", "sites/default/files"],
        "Joomla": ["joomla", "/media/jui/"],
        "React": ["__NEXT_DATA__", "data-reactroot"],
        "Angular": ["ng-version="],
        "Vue.js": ["data-v-app", "__VUE__"],
        "PHP": [".php", "x-powered-by: php"],
        "ASP.NET": ["asp.net", "x-aspnet-version", "__viewstate"],
        "Express/Node": ["x-powered-by: express"],
        "Django": ["csrfmiddlewaretoken"],
        "Flask/Werkzeug": ["werkzeug"],
        "Jenkins": ["x-jenkins"],
    }

    def run(self) -> list[Finding]:
        target = self.ctx.target
        if target.startswith("http"):
            base = target.rstrip("/")
        else:
            scheme = "https" if self.opt("use_tls_hint") == "https" else "http"
            if self.opt("use_tls_hint") == "auto" and ":" not in target:
                scheme = "https"
            base = f"{scheme}://{target}"
        url = base + str(self.opt("path"))
        try:
            resp = self.ctx.http.get(url)
        except Exception as e:  # noqa: BLE001
            return [self.finding("Target not reachable over HTTP(S)", Severity.LOW,
                                 detail=f"{url}: {e}")]
        headers_blob = "\n".join(f"{k.lower()}: {v.lower()}" for k, v in resp.headers.items())
        body = resp.text[:100_000].lower()
        blob = headers_blob + "\n" + body

        findings = [
            self.finding(
                f"HTTP {resp.status_code} on {url}", Severity.INFO,
                detail="Baseline response.",
                evidence=f"Server: {resp.headers.get('Server', 'n/a')}\n"
                         f"X-Powered-By: {resp.headers.get('X-Powered-By', 'n/a')}")
        ]
        server_hdr = resp.headers.get("Server")
        if server_hdr and re.search(r"\d+\.\d+", server_hdr):
            findings.append(self.finding(
                "Server version disclosed in header", Severity.LOW,
                detail=f"'Server' header exposes version info, aiding targeted attacks.",
                evidence=server_hdr,
                remediation="Suppress or genericize the Server header (e.g. server_tokens off)."))
        xpb = resp.headers.get("X-Powered-By")
        if xpb:
            findings.append(self.finding(
                "X-Powered-By discloses stack", Severity.LOW,
                evidence=xpb,
                remediation="Remove the X-Powered-By header."))

        detected = []
        for tech, needles in self.MARKERS.items():
            for n in needles:
                if n in blob:
                    detected.append(tech)
                    break
        if detected:
            findings.append(self.finding(
                "Technologies identified: " + ", ".join(sorted(set(detected))), Severity.INFO,
                evidence=", ".join(sorted(set(detected)))))
        return findings
