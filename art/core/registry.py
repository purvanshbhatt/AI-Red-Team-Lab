"""Plugin registry — auto-discovers modules under art/modules/."""
from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path

from art.core.base import BaseModule

_REGISTRY: dict[str, type[BaseModule]] = {}


def discover(force: bool = False) -> dict[str, type[BaseModule]]:
    global _REGISTRY
    if _REGISTRY and not force:
        return _REGISTRY
    import art.modules as modules_pkg

    for minfo in pkgutil.walk_packages(modules_pkg.__path__, modules_pkg.__name__ + "."):
        if minfo.ispkg:
            continue
        try:
            mod = importlib.import_module(minfo.name)
        except Exception as e:  # noqa: BLE001
            print(f"[registry] failed to import {minfo.name}: {e}")
            continue
        for attr in vars(mod).values():
            if (
                isinstance(attr, type)
                and issubclass(attr, BaseModule)
                and attr is not BaseModule
                and getattr(attr, "NAME", "")
                and getattr(attr, "CATEGORY", "")
            ):
                _REGISTRY[attr.full_name()] = attr
    return _REGISTRY


def get(module_name: str) -> type[BaseModule] | None:
    registry = discover()
    if module_name in registry:
        return registry[module_name]
    # allow shorthand without category if unique
    matches = [c for n, c in registry.items() if n.split("/", 1)[-1] == module_name]
    if len(matches) == 1:
        return matches[0]
    return None


def by_category(category: str | None = None) -> dict[str, type[BaseModule]]:
    registry = discover()
    if category is None:
        return dict(registry)
    return {n: c for n, c in registry.items() if c.CATEGORY == category}


def categories() -> list[str]:
    return sorted({c.CATEGORY for c in discover().values()})
