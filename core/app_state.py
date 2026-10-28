"""Shared application state wired into both the proxy and the web server."""
from __future__ import annotations

import collections
import time
from typing import Any, Optional

from .events import EventBus
from .extensions import ExtensionManager
from .intruder import IntruderEngine
from .scanner import ScannerEngine
from .scope import Scope
from .store import Store
from .targets import TargetManager


class AppState:
    def __init__(self, db_path: str = ":memory:") -> None:
        self.events = EventBus()
        self.store = Store(db_path)
        self.scope = Scope()
        self.logs: collections.deque = collections.deque(maxlen=500)
        self.ext = ExtensionManager(self._log)
        self.scanner = ScannerEngine(self.store, self.events, self.ext)
        self.intruder = IntruderEngine(self.events)
        self.targets = TargetManager(self.store, self.events, self.scanner, self.scope)

        # intercept state
        self.intercept_enabled = False
        self._held: "collections.OrderedDict[str, Any]" = collections.OrderedDict()

        # settings
        self.passive_auto = True

        # built-in browser launcher (configured by run.py once ports are known)
        self.browser = None

    def _log(self, source: str, msg: str) -> None:
        entry = {"ts": time.time(), "source": source, "msg": msg}
        self.logs.append(entry)
        self.events.publish("log", entry)

    # ---- intercept ---------------------------------------------------
    def hold(self, flow_id: str, flow_obj: Any) -> None:
        self._held[flow_id] = flow_obj

    def held_ids(self) -> list[str]:
        return list(self._held.keys())

    def get_held(self, flow_id: str) -> Optional[Any]:
        return self._held.get(flow_id)

    def release(self, flow_id: str) -> Optional[Any]:
        return self._held.pop(flow_id, None)
