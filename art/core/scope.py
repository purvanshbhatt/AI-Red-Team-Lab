"""Target scoping + authorization gate."""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse


def _normalize(entry: str) -> str:
    entry = entry.strip().lower()
    if "://" in entry:
        entry = urlparse(entry).netloc or entry
    # CIDR ranges are stored verbatim
    if "/" in entry:
        return entry.split("/")[0] + "/" + entry.split("/")[1]
    return entry.split("/")[0].split(":")[0]


class ScopeManager:
    """Tracks explicitly authorized targets for a workspace.

    A target is only authorized if the operator ran `scope add` for it —
    this is the consent record that gates all active modules.
    """

    def __init__(self, workspace_dir: Path):
        self.path = workspace_dir / "scope.json"
        self.entries: set[str] = set()
        if self.path.exists():
            try:
                self.entries = set(json.loads(self.path.read_text(encoding="utf-8")))
            except Exception:
                self.entries = set()

    def save(self) -> None:
        self.path.write_text(json.dumps(sorted(self.entries), indent=2), encoding="utf-8")

    def add(self, entry: str) -> str:
        norm = _normalize(entry)
        if not norm:
            raise ValueError("Empty scope entry")
        self.entries.add(norm)
        self.save()
        return norm

    def remove(self, entry: str) -> bool:
        norm = _normalize(entry)
        if norm in self.entries:
            self.entries.discard(norm)
            self.save()
            return True
        return False

    def is_authorized(self, host: str) -> bool:
        host = _normalize(host)
        # strip scheme/port from the incoming host too
        if host in self.entries:
            return True
        # allow wildcard-style entries like "*.example.com" stored as ".example.com"
        for e in self.entries:
            if e.startswith(".") and host.endswith(e):
                return True
            if e.startswith("*."):
                if host.endswith(e[1:]):
                    return True
        return False

    def sorted_entries(self) -> list[str]:
        return sorted(self.entries)
