"""ART command-line interface."""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from art import __version__
from art.core.base import BaseModule, ModuleContext, ModuleResult, Severity, SEVERITY_ORDER
from art.core.registry import by_category, categories, discover, get
from art.core.reporting import FindingsStore
from art.core.scope import ScopeManager
from art.http import HttpClient

LAB_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_WORKSPACE = LAB_ROOT / "reports" / "default"


def workspace_dir(name: str) -> Path:
    p = LAB_ROOT / "reports" / name
    p.mkdir(parents=True, exist_ok=True)
    return p


def make_context(mod_cls: type[BaseModule], args) -> tuple[ModuleContext, ScopeManager, FindingsStore | None]:
    ws = workspace_dir(args.workspace)
    scope = ScopeManager(ws)
    store = FindingsStore(ws)
    http = HttpClient(rate_limit=float(getattr(args, "rate_limit", 0.0) or 0.0))
    options = {}
    if getattr(args, "set", None):
        for kv in args.set:
            k, _, v = kv.partition("=")
            options[k] = v
    ctx = ModuleContext(mod_cls.full_name(), args.target or "", options,
                        scope, ws, http, store)
    return ctx, scope, store


def print_result(result: ModuleResult) -> None:
    if result.error:
        print(f"  !! {result.error}")
        return
    counts: dict[str, int] = {}
    for f in result.findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        marker = {"critical": "[!]", "high": "[!]", "medium": "[-]",
                  "low": "[.]", "info": "[ ]"}[f.severity.value]
        print(f"  {marker} ({f.severity.value:>8}) {f.title}")
    if not result.findings:
        print("  (no findings)")
    summary = ", ".join(f"{v} {k}" for k, v in sorted(
        counts.items(), key=lambda kv: -SEVERITY_ORDER[kv[0]]) if v)
    print(f"  done in {result.duration_s}s - {summary or 'nothing found'}")


# ─── subcommands ─────────────────────────────────────────────────────────────

def cmd_list(args):
    registry = by_category(args.category)
    cats = categories()
    width = max((len(n) for n in registry), default=10)
    for cat in cats:
        if args.category and cat != args.category:
            continue
        print(f"\n{cat}:")
        for name, cls in sorted(registry.items()):
            if cls.CATEGORY != cat:
                continue
            active = "" if cls.ACTIVE else " (passive)"
            print(f"  {name:<{width}}  {cls.DESCRIPTION}{active}")


def cmd_info(args):
    cls = get(args.module)
    if cls is None:
        sys.exit(f"Unknown module: {args.module}")
    print(f"{cls.full_name()}\n{'=' * len(cls.full_name())}")
    print(cls.DESCRIPTION)
    print(f"active (touches target): {'yes' if cls.ACTIVE else 'no'}")
    if cls.OPTIONS:
        print("\nOptions:")
        for k, spec in cls.OPTIONS.items():
            req = " required" if spec.get("required") else ""
            print(f"  --set {k}=...   default={spec.get('default')!r}{req}"
                  f"  # {spec.get('help', '')}")


def cmd_scope(args):
    ws = workspace_dir(args.workspace)
    scope = ScopeManager(ws)
    if args.action == "list":
        entries = scope.sorted_entries()
        print("Authorized targets:" if entries else "Scope is empty.")
        for e in entries:
            print(f"  {e}")
    elif args.action == "add":
        norm = scope.add(args.target)
        print(f"Authorized '{norm}' in workspace '{args.workspace}'.")
        print("Confirm you own this system / have written permission to test it.")
    elif args.action == "remove":
        ok = scope.remove(args.target)
        print(f"Removed '{args.target}'." if ok else f"'{args.target}' was not in scope.")


def run_module(module_name: str, args, save: bool = True,
               extra_options: dict | None = None) -> ModuleResult | None:
    cls = get(module_name)
    if cls is None:
        print(f"Unknown module: {module_name}")
        return None
    ctx, _scope, _store = make_context(cls, args)
    if extra_options:
        ctx.options.update(extra_options)
    # remember options so postexp/validation can replay with identical inputs
    opts_path = Path(ctx.workspace_dir) / "last_options.json"
    try:
        all_opts = json.loads(opts_path.read_text(encoding="utf-8")) \
            if opts_path.exists() else {}
    except Exception:  # noqa: BLE001
        all_opts = {}
    all_opts[cls.full_name()] = ctx.options
    opts_path.write_text(json.dumps(all_opts), encoding="utf-8")
    print(f"[*] Running {cls.full_name()} against {args.target!r}")
    result = cls(ctx).safe_run()
    print_result(result)
    if save and ctx.store is not None and not result.error:
        ctx.store.add_many(result.findings)
    return result


def cmd_run(args):
    cls = get(args.module)
    if cls is None:
        sys.exit(f"Unknown module: {args.module}")
    if not args.target and cls.ACTIVE:
        sys.exit("--target is required for active modules")
    run_module(args.module, args)


PIPELINE = [
    ("recon/dns_enum", {}),
    ("recon/tech_fingerprint", {}),
    ("web/security_headers", {}),
    ("web/cors_misconfig", {}),
    ("web/sqli_detect", {"path": "/item", "param": "id"}),
    ("web/xss_reflect", {"path": "/reflected", "param": "name"}),
    ("web/dir_bruteforce", {}),
]


def cmd_pipeline(args):
    if not args.target:
        sys.exit("--target is required")
    if args.modules:
        mods = [(m.strip(), {}) for m in args.modules.split(",") if m.strip()]
    else:
        mods = list(PIPELINE)
    t0 = time.time()
    total = 0
    for name, opts in mods:
        res = run_module(name, args, extra_options=opts)
        total += len(res.findings) if res else 0
        print()
    print(f"[+] Pipeline finished in {time.time() - t0:.0f}s - "
          f"{total} findings stored in workspace '{args.workspace}'")
    print(f"    Generate a report: python -m art.cli report --workspace {args.workspace}")


def cmd_report(args):
    ws = workspace_dir(args.workspace)
    store = FindingsStore(ws)
    counts = store.counts_by_severity()
    total = sum(counts.values())
    print(f"Workspace '{args.workspace}': {total} findings "
          f"({counts['critical']} crit / {counts['high']} high / "
          f"{counts['medium']} med / {counts['low']} low)")
    fmt = args.format
    path = {"json": store.export_json, "md": store.export_markdown,
            "html": store.export_html}[fmt]()
    print(f"[+] Wrote {path}")


def cmd_shell(args):
    from art.shell import ArtShell
    ArtShell(args).cmdloop()


def cmd_demo_target(args):
    from art.demo.app import serve
    serve(host=args.host, port=args.port)


# ─── parser ──────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="art",
        description="ART - AI Red Team & VAPT framework. Only test systems you are "
                    "authorized to assess.")
    p.add_argument("--version", action="version", version=f"art {__version__}")

    def add_common(sp):
        sp.add_argument("-t", "--target", default="", help="target host/URL/CIDR")
        sp.add_argument("-w", "--workspace", default="default", help="workspace name")
        sp.add_argument("-s", "--set", action="append", metavar="KEY=VALUE",
                        help="module option (repeatable)")
        sp.add_argument("--rate-limit", type=float, default=0.0,
                        help="min seconds between HTTP requests")

    sub = p.add_subparsers(dest="cmd")

    sp = sub.add_parser("list", help="list modules")
    sp.add_argument("category", nargs="?", default=None,
                    choices=[None] + ["recon", "web", "network", "cloud", "ai", "postexp"])
    sp.set_defaults(fn=cmd_list)

    sp = sub.add_parser("info", help="show module details")
    sp.add_argument("module")
    sp.set_defaults(fn=cmd_info)

    sp = sub.add_parser("scope", help="manage authorized targets")
    sp.add_argument("action", choices=["list", "add", "remove"])
    sp.add_argument("target", nargs="?", default="")
    add_common(sp)
    sp.set_defaults(fn=cmd_scope)

    sp = sub.add_parser("run", help="run one module")
    sp.add_argument("module")
    add_common(sp)
    sp.set_defaults(fn=cmd_run)

    sp = sub.add_parser("pipeline", help="run recon->web module chain")
    sp.add_argument("--modules", default="", help="comma-separated module list")
    add_common(sp)
    sp.set_defaults(fn=cmd_pipeline)

    sp = sub.add_parser("report", help="export findings report")
    sp.add_argument("--format", choices=["html", "json", "md"], default="html")
    sp.add_argument("-w", "--workspace", default="default")
    sp.set_defaults(fn=cmd_report)

    sp = sub.add_parser("shell", help="interactive console")
    add_common(sp)
    sp.set_defaults(fn=cmd_shell)

    sp = sub.add_parser("demo-target", help="start local vulnerable demo app")
    sp.add_argument("--host", default="127.0.0.1")
    sp.add_argument("--port", type=int, default=8006)
    sp.set_defaults(fn=cmd_demo_target)

    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if not hasattr(args, "fn"):
        build_parser().print_help()
        return 1
    discover()
    try:
        args.fn(args)
    except KeyboardInterrupt:
        print("\n[!] interrupted")
    return 0


if __name__ == "__main__":
    sys.exit(main())
