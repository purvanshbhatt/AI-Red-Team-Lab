"""web: authentication audit - JWT flaws (none-alg, weak secret) and session flags."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json

from art.core.base import BaseModule, Finding, Severity


def _b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _parse_jwt(token: str):
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("not a JWS compact token")
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    sig = _b64url_decode(parts[2])
    return header, payload, sig, parts


class JwtAudit(BaseModule):
    NAME = "jwt_audit"
    CATEGORY = "web"
    DESCRIPTION = "Analyze a JWT for none-alg, missing expiry, and weak HMAC secrets."
    ACTIVE = False  # offline analysis of a supplied token
    OPTIONS = {
        "token": {"default": "", "help": "JWT to analyze", "required": True},
        "secret_wordlist": {"default": "", "help": "optional path to candidate secrets"},
    }

    WEAK_SECRETS = ["secret", "password", "jwt_secret", "changeme", "key",
                    "supersecret", "123456", "test", "admin"]

    def run(self) -> list[Finding]:
        token = str(self.opt("token")).strip()
        findings: list[Finding] = []
        try:
            header, payload, _sig, parts = _parse_jwt(token)
        except Exception as e:  # noqa: BLE001
            return [self.finding("Invalid JWT supplied", Severity.LOW, detail=str(e))]

        alg = str(header.get("alg", "?")).lower()
        self.ctx.log(f"alg={alg} claims={list(payload.keys())}")

        if alg == "none":
            findings.append(self.finding(
                "JWT accepts 'alg: none'", Severity.CRITICAL,
                detail="Unsigned tokens mean anyone can forge arbitrary identities.",
                evidence=json.dumps(header),
                remediation="Reject unsigned tokens; pin expected algorithms server-side."))

        if "exp" not in payload:
            findings.append(self.finding(
                "JWT has no expiry claim", Severity.MEDIUM,
                detail="Tokens never expire; theft yields permanent access.",
                remediation="Always set a short-lived exp claim."))
        else:
            findings.append(self.finding(
                f"JWT expires at ts={payload['exp']}", Severity.INFO))

        if alg.startswith("hs"):
            candidates = list(self.WEAK_SECRETS)
            wl = self.opt("secret_wordlist")
            if wl:
                try:
                    candidates += [l.strip() for l in open(wl, encoding="utf-8")
                                   .read().splitlines()[:5000] if l.strip()]
                except OSError:
                    pass
            signing_input = (parts[0] + "." + parts[1]).encode()
            for secret in candidates:
                digest = hmac.new(secret.encode(), signing_input,
                                  hashlib.sha256).digest()
                if hmac.compare_digest(digest, _sig_bytes(token)):
                    findings.append(self.finding(
                        f"JWT HMAC secret cracked: '{secret}'", Severity.CRITICAL,
                        detail="Attackers can mint arbitrary valid tokens.",
                        evidence="forged with secret: %s" % secret,
                        remediation="Use a long random secret (256-bit); consider RS256."))
                    break
        if not findings or all(f.severity == Severity.INFO for f in findings):
            findings.insert(0, self.finding("No critical JWT flaws found", Severity.INFO))
        return findings


def _sig_b64(token: str) -> str:
    return token.split(".")[2]


def _sig_bytes(token: str) -> bytes:
    seg = _sig_b64(token)
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)
