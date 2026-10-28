"""Extension system.

An extension is a Python module (file in the extensions dir, or registered
at runtime) that may define any of these top-level callables:

    NAME = "My Extension"
    DESCRIPTION = "..."

    def on_request(ctx, flow):   ...   # flow is a mutable dict
    def on_response(ctx, flow):  ...
    def passive_scan(ctx, flow): return [finding, ...]

`ctx` exposes helpers (ctx.log, ctx.finding) and the shared store. Hooks
run synchronously inside the proxy loop and are wrapped so a buggy
extension can never take the proxy down.
"""
from __future__ import annotations

import importlib.util
import os
import traceback
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


@dataclass
class ExtensionContext:
    name: str
    _log_sink: Callable[[str, str], None]
    _findings: list[dict] = field(default_factory=list)

    def log(self, msg: str) -> None:
        self._log_sink(self.name, str(msg))

    def finding(
        self, *, name: str, severity: str = "info", confidence: str = "firm",
        detail: str = "", evidence: str = "", flow: Optional[dict] = None,
        check_id: Optional[str] = None,
    ) -> None:
        host = flow["request"]["host"] if flow else ""
        url = flow["request"]["url"] if flow else ""
        cid = check_id or f"ext:{self.name}"
        self._findings.append({
            "check_id": cid, "name": name, "severity": severity,
            "confidence": confidence, "detail": detail, "evidence": evidence,
            "host": host, "url": url,
            "flow_id": flow["id"] if flow else None,
            "dedup_key": f"{cid}|{host}|{url}|{name}",
        })


@dataclass
class LoadedExtension:
    id: str
    name: str
    description: str
    filename: str
    module: Any
    enabled: bool = True
    error: str = ""


class ExtensionManager:
    def __init__(self, log_sink: Callable[[str, str], None]) -> None:
        self._exts: dict[str, LoadedExtension] = {}
        self._log_sink = log_sink

    def load_dir(self, path: str) -> None:
        if not os.path.isdir(path):
            return
        for fn in sorted(os.listdir(path)):
            if fn.endswith(".py") and not fn.startswith("_"):
                self.load_file(os.path.join(path, fn))

    def load_file(self, filepath: str) -> LoadedExtension:
        ext_id = uuid.uuid4().hex[:8]
        name = os.path.basename(filepath)
        try:
            spec = importlib.util.spec_from_file_location(f"ext_{ext_id}", filepath)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)  # type: ignore
            ext = LoadedExtension(
                id=ext_id,
                name=getattr(module, "NAME", name),
                description=getattr(module, "DESCRIPTION", ""),
                filename=os.path.basename(filepath),
                module=module,
            )
            self._log_sink("extensions", f"loaded {ext.name}")
        except Exception:
            ext = LoadedExtension(
                id=ext_id, name=name, description="", filename=os.path.basename(filepath),
                module=None, enabled=False, error=traceback.format_exc(limit=3),
            )
            self._log_sink("extensions", f"FAILED to load {name}")
        self._exts[ext_id] = ext
        return ext

    def list(self) -> list[dict]:
        return [
            {"id": e.id, "name": e.name, "description": e.description,
             "filename": e.filename, "enabled": e.enabled, "error": e.error}
            for e in self._exts.values()
        ]

    def set_enabled(self, ext_id: str, enabled: bool) -> None:
        if ext_id in self._exts:
            self._exts[ext_id].enabled = enabled

    def _call(self, hook: str, flow: dict) -> list[dict]:
        findings: list[dict] = []
        for ext in self._exts.values():
            if not ext.enabled or ext.module is None:
                continue
            fn = getattr(ext.module, hook, None)
            if fn is None:
                continue
            ctx = ExtensionContext(name=ext.name, _log_sink=self._log_sink)
            try:
                result = fn(ctx, flow)
                findings.extend(ctx._findings)
                if hook == "passive_scan" and isinstance(result, list):
                    findings.extend(result)
            except Exception:
                self._log_sink(ext.name, "hook error:\n" + traceback.format_exc(limit=3))
        return findings

    def run_request(self, flow: dict) -> None:
        self._call("on_request", flow)

    def run_response(self, flow: dict) -> list[dict]:
        return self._call("on_response", flow) + self._call("passive_scan", flow)
