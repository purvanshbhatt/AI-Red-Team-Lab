"""ART interactive shell (Metasploit-style)."""
from __future__ import annotations

import cmd
import shlex
from pathlib import Path

from art.cli import (LAB_ROOT, build_parser, cmd_list, make_context, print_result,
                     run_module, workspace_dir)
from art.core.registry import discover, get, by_category, categories
from art.core.reporting import FindingsStore
from art.core.scope import ScopeManager

BANNER = r"""
    _    ____ _____ ____  __  __
   / \  |  _ \_   _|  _ \|  \/  |
  / _ \ | |_) || | | |_) | |\/| |
 / ___ \|  _ < | | |  _ <| |  | |
/_/   \_\_| \_\|_| |_| \_\_|  |_|
 AI Red Team & VAPT framework - authorized use only
 Type 'help' for commands.
"""


class ArtShell(cmd.Cmd):
    prompt = "art> "

    def __init__(self, args):
        super().__init__()
        self.args = args
        self.current = None       # selected module class
        self.options = {}         # option overrides
        self.target = args.target or ""
        discover()
        self.intro = BANNER
        self.use_rawinput = True

    def cmdloop(self, intro=None):
        # custom loop: pyreadline3 shims break stdlib cmd.cmdloop on 3.13
        if intro is not None:
            print(intro)
        else:
            print(self.intro)
        stop = None
        while not stop:
            try:
                line = input(self.prompt)
            except (EOFError, KeyboardInterrupt):
                print()
                break
            stop = self.onecmd(line)
        return True

    # -- helpers ----------------------------------------------------------
    def _ws(self) -> Path:
        return workspace_dir(self.args.workspace)

    def _scope(self) -> ScopeManager:
        return ScopeManager(self._ws())

    def _run_current(self):
        if self.current is None:
            print("No module selected. Use 'use category/name'.")
            return
        if not self.target:
            print("No target set. Use 'set target <host>'.")
            return

        class _Args:
            pass

        a = _Args()
        a.workspace = self.args.workspace
        a.target = self.target
        a.rate_limit = self.args.rate_limit
        a.set = [f"{k}={v}" for k, v in self.options.items()]
        run_module(self.current.full_name(), a)

    # -- commands ---------------------------------------------------------
    def do_list(self, arg):
        """List modules: list [category]"""
        class _A:
            category = arg.strip() or None
        cmd_list(_A())

    def do_use(self, arg):
        """Select a module: use recon/port_scan"""
        cls = get(arg.strip())
        if cls is None:
            print(f"Unknown module: {arg}")
        else:
            self.current = cls
            self.prompt = f"art ({cls.full_name()})> "
            print(cls.DESCRIPTION)

    def do_set(self, arg):
        """Set an option or the target: set target example.com / set param id"""
        parts = shlex.split(arg)
        if len(parts) != 2:
            print("usage: set KEY VALUE")
            return
        k, v = parts
        if k == "target":
            self.target = v
        else:
            self.options[k] = v
        print(f"{k} => {v}")

    def do_show(self, arg):
        """Show current config: show options|scope|findings"""
        what = arg.strip()
        if what == "options":
            print(f"target     = {self.target}")
            if self.current and self.current.OPTIONS:
                for k, spec in self.current.OPTIONS.items():
                    val = self.options.get(k, spec.get("default"))
                    req = "*" if spec.get("required") else " "
                    print(f"{req}{k:<10} = {val}")
        elif what == "scope":
            entries = self._scope().sorted_entries()
            print("\n".join(entries) or "(empty)")
        elif what == "findings":
            store = FindingsStore(self._ws())
            counts = store.counts_by_severity()
            print({k: v for k, v in counts.items() if v})
        else:
            print("usage: show options|scope|findings")

    def do_run(self, arg):
        """Run the selected module against the target."""
        self._run_current()

    def do_scope(self, arg):
        """Authorize a target: scope add host (only if you have permission!)"""
        parts = shlex.split(arg)
        if len(parts) == 2 and parts[0] == "add":
            norm = self._scope().add(parts[1])
            print(f"Authorized '{norm}'.")
        else:
            print("usage: scope add <host>")

    def do_report(self, arg):
        """Generate report: report html|json|md"""
        fmt = arg.strip() or "html"
        store = FindingsStore(self._ws())
        path = {"html": store.export_html, "json": store.export_json,
                "md": store.export_markdown}.get(fmt, store.export_html)()
        print(f"[+] Wrote {path}")

    def do_back(self, arg):
        """Deselect module."""
        self.current = None
        self.prompt = "art> "

    def do_exit(self, arg):
        """Quit."""
        return True

    do_quit = do_exit
