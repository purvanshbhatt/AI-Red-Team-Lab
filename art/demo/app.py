"""Deliberately vulnerable local demo app for safe ART testing.

Stdlib-only. Binds 127.0.0.1 by default. NEVER expose this beyond localhost.
Start: python -m art.cli demo-target --port 8006
"""
from __future__ import annotations

import base64
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


class DemoHandler(BaseHTTPRequestHandler):
    server_version = "VulnDemo/1.0"  # intentionally discloses software

    def log_message(self, fmt, *args):  # quiet
        pass

    # -- helpers ----------------------------------------------------------
    def _send(self, body: str, status: int = 200,
              headers: dict | None = None):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _page(self, title: str, body: str, status: int = 200) -> None:
        self._send(
            f"<html><head><title>{title}</title></head><body>"
            f"<h1>{title}</h1>{body}</body></html>", status)

    # -- routes -----------------------------------------------------------
    def do_GET(self):
        u = urlparse(self.path)
        path = u.path
        qs = parse_qs(u.query)

        if path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            # deliberately NO security headers + unflagged cookie
            self.send_header("Set-Cookie", "session=abc123")
            self.send_header("Content-Length", "0")
            self.end_headers()
            body = ("<h1>Vulnerable Demo Shop</h1>"
                    "<a href='/item?id=1'>product</a> <a href='/reflected?name=guest'>greet</a>")
            self.wfile.write(body.encode())

        elif path == "/reflected":
            name = qs.get("name", [""])[0]
            # XSS: reflected completely unencoded
            self._page("Hello",
                       f"<p>Hello {name}!</p>")

        elif path == "/item":
            item_id = qs.get("id", [""])[0]
            # simulated SQL injection surface
            if "SLEEP" in item_id.upper():
                time.sleep(3)
            catalog = {
                "1": ("Widget", "$9.99 - a fine widget."),
                "2": ("Gadget", "$19.99 - a grand gadget."),
                "3": ("Doohickey", "$4.99 - mysterious."),
            }
            if "'1'='1" in item_id or "1=1--" in item_id:
                # boolean-based: TRUE condition dumps whole catalog
                rows = "".join(f"<li>{k}: {v[0]} {v[1]}</li>" for k, v in catalog.items())
                self._page("Catalog", f"<ul>{rows}</ul>")
                return
            if "'" in item_id:
                self._page("Error", "<pre>You have an error in your SQL syntax; "
                                    "check the manual near ''</pre>", 500)
                return
            entry = catalog.get(item_id)
            if entry:
                self._page(entry[0], f"<p>{entry[0]} costs {entry[1]}</p>")
            else:
                self._page("Not found", "<p>No such product.</p>", 404)

        elif path == "/admin":
            self._page("Admin Panel",
                       "<p>Welcome, anonymous administrator! User table:</p>"
                       "<pre>admin / SuperSecret123</pre>")

        elif path in ("/backup.zip", "/dump.sql"):
            self._send("fake-backup-data", 200)

        elif path == "/.git/config":
            self._send("[core]\nrepositoryformatversion = 0\n", 200)

        elif path == "/api/token":
            self._page("API", "<p>POST JSON {'token': '...'} to verify JWT.</p>")

        else:
            self._page("404", "<p>not found</p>", 404)

    def do_POST(self):
        u = urlparse(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace")
        try:
            data = json.loads(raw or "{}")
        except ValueError:
            data = {}

        if u.path == "/login":
            token = str(data.get("token", ""))
            # deliberately accepts alg:none JWTs
            try:
                head_b64 = token.split(".")[0]
                head_b64 += "=" * (-len(head_b64) % 4)
                header = json.loads(base64.urlsafe_b64decode(head_b64))
                if str(header.get("alg", "")).lower() == "none":
                    self._send(json.dumps({"status": "authenticated (alg none!)"}), 200,
                               {"Content-Type": "application/json"})
                    return
            except Exception:  # noqa: BLE001
                pass
            self._send(json.dumps({"status": "rejected"}),
                       401, {"Content-Type": "application/json"})
        else:
            self._page("404", "", 404)


def serve(host: str = "127.0.0.1", port: int = 8006) -> None:
    print(f"[demo-target] serving vulnerable app on http://{host}:{port} (Ctrl+C to stop)")
    print("[demo-target] endpoints: / /reflected?name= /item?id= /admin "
          "/backup.zip /.git/config POST /login {{\"token\": ...}}")
    ThreadingHTTPServer((host, port), DemoHandler).serve_forever()
