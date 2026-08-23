"""web: content discovery (directory brute force) and rate-limit detection."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from art.core.base import BaseModule, Finding, Severity

WL_DIR = Path(__file__).resolve().parents[2] / "wordlists"

INTERESTING_CODES = {200: "OK", 301: "redirect", 302: "redirect", 401: "auth req.",
                     403: "forbidden"}


class DirBruteforce(BaseModule):
    NAME = "dir_bruteforce"
    CATEGORY = "web"
    DESCRIPTION = "Discover hidden files/directories with a compact wordlist."
    OPTIONS = {
        "wordlist": {"default": "dirs_common.txt", "help": "wordlist under art/wordlists/"},
        "threads": {"default": 10, "help": "concurrent requests"},
        "extensions": {"default": "", "help": "comma-separated extra extensions, e.g. .php,.bak"},
    }

    def run(self) -> list[Finding]:
        base = self.ctx.target if self.ctx.target.startswith("http") else f"http://{self.ctx.target}"
        base = base.rstrip("/")
        wl = WL_DIR / str(self.opt("wordlist"))
        words = [l.strip() for l in wl.read_text(encoding="utf-8").splitlines()
                 if l.strip() and not l.startswith("#")]
        exts = [e for e in str(self.opt("extensions")).split(",") if e]
        paths = list(words)
        for ext in exts:
            paths += [w + ext for w in words]

        # baseline: hash of a random nonexistent path to filter soft-404s
        baseline_path = f"/nonexistent-art-{time.time_ns()}"
        try:
            base_resp = self.ctx.http.get(base + baseline_path)
            baseline_len = len(base_resp.content)
            baseline_code = base_resp.status_code
        except Exception as e:  # noqa: BLE001
            return [self.finding("Target unreachable", Severity.LOW, detail=str(e))]

        hits = []

        def probe(path: str):
            try:
                r = self.ctx.http.get(f"{base}/{path}")
                return path, r.status_code, len(r.content)
            except Exception:  # noqa: BLE001
                return path, 0, 0

        with ThreadPoolExecutor(max_workers=int(self.opt("threads"))) as pool:
            futures = [pool.submit(probe, p) for p in paths]
            for fut in as_completed(futures):
                path, code, size = fut.result()
                if code in INTERESTING_CODES and not (
                        code == baseline_code and abs(size - baseline_len) < 32):
                    hits.append((path, code, size))
                    self.ctx.log(f"/{path} -> {code} ({size}b)")

        findings = []
        sensitive = [h for h in hits if any(k in h[0].lower() for k in
                     ("admin", "backup", ".git", "config", "secret", "private",
                      "dump", ".env", "debug", "install"))]
        if hits:
            listing = "\n".join(f"/{p} -> {c} ({s} bytes)" for p, c, s in sorted(hits))
            findings.append(self.finding(
                f"{len(hits)} resources discovered via content brute force", Severity.INFO,
                detail="Paths that returned interesting status codes.",
                evidence=listing))
        if sensitive:
            findings.append(self.finding(
                f"{len(sensitive)} potentially sensitive paths exposed",
                Severity.MEDIUM,
                detail="Administrative, backup, VCS or config endpoints are reachable. "
                       "These often leak source code or grant unauthorized access.",
                evidence="\n".join(f"/{p} -> {c}" for p, c, s in sorted(sensitive)),
                remediation="Restrict access to admin/backup/VCS paths; return 404 externally; "
                            "never deploy .git or backups to the webroot."))
        if not hits:
            findings.append(self.finding("Nothing discovered from wordlist", Severity.INFO))
        return findings


class RateLimitCheck(BaseModule):
    NAME = "rate_limit_check"
    CATEGORY = "web"
    DESCRIPTION = "Send a burst of identical safe requests to detect missing rate limiting."
    OPTIONS = {
        "count": {"default": 30, "help": "number of requests"},
        "path": {"default": "/", "help": "endpoint to test"},
        "delay_ms": {"default": 20, "help": "delay between requests in ms"},
    }

    def run(self) -> list[Finding]:
        base = self.ctx.target if self.ctx.target.startswith("http") else f"http://{self.ctx.target}"
        url = base.rstrip("/") + str(self.opt("path"))
        n = int(self.opt("count"))
        delay = int(self.opt("delay_ms")) / 1000.0
        codes = []
        throttled_at = None
        for i in range(n):
            try:
                resp = self.ctx.http.get(url)
                codes.append(resp.status_code)
                if resp.status_code == 429:
                    throttled_at = i + 1
                    break
            except Exception:  # noqa: BLE001
                codes.append(0)
            time.sleep(delay)
        findings = []
        if throttled_at is None and codes and all(c in (200, 301, 302, 404) or c >= 500 for c in codes):
            findings.append(self.finding(
                "No rate limiting observed", Severity.LOW,
                detail=f"{n} rapid requests were served without throttling (no HTTP 429). "
                       "Enables credential stuffing and resource exhaustion.",
                evidence=f"status codes: {codes[:15]}...",
                remediation="Apply rate limiting / account lockout on sensitive endpoints."))
        else:
            findings.append(self.finding(
                f"Rate limiting present (throttled at request {throttled_at})",
                Severity.INFO, evidence=str(codes)))
        return findings
