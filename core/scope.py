"""Target scope: host include/exclude rules that bound what gets tested.

Rules are simple substring/wildcard host matches. When any include rule
exists, a host must match one to be in scope; exclude rules always win.
"""
from __future__ import annotations

import fnmatch
import threading


class Scope:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.include: list[str] = []
        self.exclude: list[str] = []

    def set_rules(self, include: list[str], exclude: list[str]) -> None:
        with self._lock:
            self.include = [r.strip() for r in include if r.strip()]
            self.exclude = [r.strip() for r in exclude if r.strip()]

    def rules(self) -> dict[str, list[str]]:
        with self._lock:
            return {"include": list(self.include), "exclude": list(self.exclude)}

    def _match(self, host: str, pattern: str) -> bool:
        pattern = pattern.lower()
        host = host.lower()
        if pattern.startswith("*") or "*" in pattern:
            return fnmatch.fnmatch(host, pattern)
        return pattern == host or host.endswith("." + pattern)

    def in_scope(self, host: str) -> bool:
        with self._lock:
            include = list(self.include)
            exclude = list(self.exclude)
        if any(self._match(host, p) for p in exclude):
            return False
        if not include:
            return True
        return any(self._match(host, p) for p in include)
