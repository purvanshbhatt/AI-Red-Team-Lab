"""Core data model: modules, findings, context."""
from __future__ import annotations

import time
import traceback
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return SEVERITY_ORDER[self.value]


@dataclass
class Finding:
    module: str
    title: str
    severity: Severity
    target: str
    detail: str = ""
    evidence: str = ""
    remediation: str = ""
    timestamp: float = field(default_factory=time.time)

    def as_dict(self) -> dict:
        d = self.__dict__.copy()
        d["severity"] = self.severity.value
        return d


class AuthorizationError(Exception):
    pass


class ModuleContext:
    """Everything a module needs at runtime."""

    def __init__(self, module_name: str, target: str, options: dict,
                 scope, workspace_dir, http_client, store=None):
        self.module_name = module_name
        self.target = target
        self.options = options or {}
        self.scope = scope
        self.workspace_dir = workspace_dir
        self.http = http_client
        self.store = store
        self.log_lines: list[str] = []

    # -- authorization ----------------------------------------------------
    def assert_authorized(self, host: Optional[str] = None) -> None:
        host = host or self.target
        if not self.scope.is_authorized(host):
            raise AuthorizationError(
                f"'{host}' is not in the authorized scope for this workspace. "
                f"Add it first: art scope add {host} (only for systems you own/have permission to test)."
            )

    # -- options ----------------------------------------------------------
    def opt(self, name: str, default: Any = None) -> Any:
        if name in self.options:
            return self.options[name]
        return default

    # -- logging ----------------------------------------------------------
    def log(self, msg: str) -> None:
        line = f"[{self.module_name}] {msg}"
        print("    " + line)
        self.log_lines.append(line)


@dataclass
class ModuleResult:
    findings: list[Finding] = field(default_factory=list)
    logs: list[str] = field(default_factory=list)
    error: Optional[str] = None
    duration_s: float = 0.0


class BaseModule:
    """Base class every ART module inherits from."""
    NAME: str = ""            # e.g. "port_scan" (registry uses CATEGORY/NAME)
    CATEGORY: str = ""        # e.g. "recon"
    DESCRIPTION: str = ""
    ACTIVE: bool = True       # active modules touch the target and require authorization
    OPTIONS: dict = {}        # name -> {"default": x, "help": str, "required": bool}

    def __init__(self, ctx: ModuleContext):
        self.ctx = ctx

    @classmethod
    def full_name(cls) -> str:
        return f"{cls.CATEGORY}/{cls.NAME}"

    def run(self) -> list[Finding]:
        raise NotImplementedError

    def opt(self, name: str) -> Any:
        spec = self.OPTIONS.get(name, {})
        return self.ctx.options.get(name, spec.get("default"))

    def finding(self, title: str, severity: Severity | str, detail: str = "",
                evidence: str = "", remediation: str = "") -> Finding:
        if isinstance(severity, str):
            severity = Severity(severity.lower())
        return Finding(
            module=self.full_name(), title=title, severity=severity,
            target=self.ctx.target, detail=detail, evidence=evidence[:2000],
            remediation=remediation,
        )

    def safe_run(self) -> ModuleResult:
        start = time.time()
        result = ModuleResult()
        try:
            if self.ACTIVE:
                self.ctx.assert_authorized()
            findings = self.run()
            result.findings = list(findings)
        except AuthorizationError as e:
            result.error = str(e)
        except Exception as e:  # noqa: BLE001 - modules must never kill the framework
            result.error = f"{type(e).__name__}: {e}"
            traceback.print_exc()
        result.logs = self.ctx.log_lines
        result.duration_s = round(time.time() - start, 2)
        return result
