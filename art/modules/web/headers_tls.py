"""web: security header audit, CORS misconfig, TLS audit."""
from __future__ import annotations

import socket
import ssl

from art.core.base import BaseModule, Finding, Severity


def _base_url(target: str) -> str:
    if target.startswith("http"):
        return target.rstrip("/")
    return f"http://{target}"


class SecurityHeaders(BaseModule):
    NAME = "security_headers"
    CATEGORY = "web"
    DESCRIPTION = "Audit HTTP security headers and cookie flags."
    OPTIONS = {"path": {"default": "/", "help": "path to check"}}

    REQUIRED = {
        "strict-transport-security": ("HSTS missing", Severity.MEDIUM,
            "Add Strict-Transport-Security to enforce HTTPS."),
        "content-security-policy": ("CSP missing", Severity.MEDIUM,
            "Define a Content-Security-Policy to mitigate XSS."),
        "x-content-type-options": ("X-Content-Type-Options missing", Severity.LOW,
            "Set X-Content-Type-Options: nosniff."),
        "x-frame-options": ("X-Frame-Options missing", Severity.LOW,
            "Set X-Frame-Options (or frame-ancestors in CSP) to prevent clickjacking."),
    }

    def run(self) -> list[Finding]:
        url = _base_url(self.ctx.target) + str(self.opt("path"))
        resp = self.ctx.http.get(url, allow_redirects=True)
        findings = [self.finding(
            f"Fetched {url} (HTTP {resp.status_code})", Severity.INFO)]
        lower = {k.lower(): v for k, v in resp.headers.items()}
        for header, (title, sev, rem) in self.REQUIRED.items():
            if header not in lower:
                findings.append(self.finding(title, sev, evidence=f"Missing: {header}",
                                             remediation=rem))
        for name, value in resp.cookies.items():
            # requests jar doesn't expose flags; re-read raw Set-Cookie
            pass
        set_cookies = resp.headers.get("Set-Cookie", "")
        if set_cookies:
            low = set_cookies.lower()
            issues = []
            if "httponly" not in low:
                issues.append("HttpOnly flag missing")
            if "secure" not in low:
                issues.append("Secure flag missing")
            if "samesite" not in low:
                issues.append("SameSite attribute missing")
            if issues:
                findings.append(self.finding(
                    "Cookie hardening issues", Severity.MEDIUM,
                    detail="Session cookies without proper flags are exposed to "
                           "JS theft or CSRF.",
                    evidence=f"Set-Cookie: {set_cookies}\n" + "\n".join(issues),
                    remediation="Set HttpOnly; Secure; SameSite=Lax on all session cookies."))
        return findings


class CorsMisconfig(BaseModule):
    NAME = "cors_misconfig"
    CATEGORY = "web"
    DESCRIPTION = "Test whether the server reflects arbitrary Origin headers (CORS bypass)."
    OPTIONS = {"evil_origin": {"default": "https://evil.example.com",
                               "help": "attacker origin used in the probe"}}

    def run(self) -> list[Finding]:
        evil = str(self.opt("evil_origin"))
        url = _base_url(self.ctx.target)
        resp = self.ctx.http.get(url, headers={"Origin": evil})
        acao = resp.headers.get("Access-Control-Allow-Origin")
        acac = resp.headers.get("Access-Control-Allow-Credentials")
        findings = []
        if acao and (acao == evil or acao == "*"):
            creds = acac and acac.lower() == "true"
            sev = Severity.HIGH if creds else Severity.LOW
            findings.append(self.finding(
                "CORS reflects arbitrary Origin" + (" with credentials" if creds else ""),
                sev,
                detail="Any website can read responses from this origin in a victim's browser"
                       + (" including credentialed responses." if creds else "."),
                evidence=f"Sent Origin: {evil}\nGot ACAO: {acao}\nACAC: {acac}",
                remediation="Use an allow-list of trusted origins; never reflect arbitrary Origins."))
        else:
            findings.append(self.finding(
                "CORS configuration looks safe", Severity.INFO,
                evidence=f"ACAO: {acao}"))
        return findings


class TlsAudit(BaseModule):
    NAME = "tls_audit"
    CATEGORY = "web"
    DESCRIPTION = "Inspect TLS certificate validity and protocol support."
    OPTIONS = {"port": {"default": 443, "help": "TLS port"},
               "hostname": {"default": "", "help": "SNI hostname (defaults to target host)"}}

    def run(self) -> list[Finding]:
        host = str(self.opt("hostname")) or self.ctx.target.split("://")[-1].split("/")[0]
        port = int(self.opt("port"))
        findings = []
        try:
            ctx_strict = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=8) as sock:
                with ctx_strict.wrap_socket(sock, server_hostname=host):
                    pass
            findings.append(self.finding("TLS certificate chains to a public CA", Severity.INFO))
        except ssl.SSLCertVerificationError as e:
            findings.append(self.finding(
                "TLS certificate fails public validation", Severity.MEDIUM,
                detail="Self-signed, expired, hostname-mismatched, or untrusted chain. "
                       "Users get warnings; MITM becomes trivial.",
                evidence=str(e.verify_message if hasattr(e, 'verify_message') else e),
                remediation="Install a valid certificate from a trusted CA."))
        except OSError as e:
            return [self.finding(f"No TLS service on {host}:{port}", Severity.INFO,
                                 detail=str(e))]

        weak_protocols = []
        for proto_name, proto in (("TLSv1", ssl.PROTOCOL_TLSv1), ("TLSv1_1", ssl.PROTOCOL_TLSv1_1)):
            try:
                c = ssl.SSLContext(proto)
                c.check_hostname = False
                c.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, port), timeout=6) as sock:
                    with c.wrap_socket(sock, server_hostname=host):
                        weak_protocols.append(proto_name)
            except Exception:  # noqa: BLE001
                continue
        if weak_protocols:
            findings.append(self.finding(
                "Deprecated TLS protocols accepted: " + ", ".join(weak_protocols),
                Severity.MEDIUM,
                detail="Legacy protocol versions have known weaknesses (POODLE etc.).",
                remediation="Disable TLS < 1.2; prefer TLS 1.3."))
        else:
            findings.append(self.finding("No deprecated TLS versions accepted", Severity.INFO))
        return findings
