"""Scanner engine: passive scanning on capture, active auditing on demand.

Active auditing enumerates insertion points (query params, form-body
params, JSON string values), sends one baseline request, then one probe
per (insertion point x payload) and runs each active check's detector.
"""
from __future__ import annotations

import json as jsonlib
import urllib.parse
from dataclasses import dataclass
from typing import Any, Callable, Optional

from .. import sender
from .active import ALL_ACTIVE
from .passive import ALL_PASSIVE


@dataclass
class InsertionPoint:
    location: str   # 'query' | 'body-form' | 'json'
    param: str

    def describe(self) -> str:
        return f"{self.location}:{self.param}"


def _split_path(path: str) -> tuple[str, str]:
    if "?" in path:
        p, q = path.split("?", 1)
        return p, q
    return path, ""


def enumerate_points(flow: dict) -> list[InsertionPoint]:
    points: list[InsertionPoint] = []
    _, query = _split_path(flow["request"]["path"])
    for k, _v in urllib.parse.parse_qsl(query, keep_blank_values=True):
        points.append(InsertionPoint("query", k))

    ctype = ""
    for k, v in flow["request"]["headers"]:
        if k.lower() == "content-type":
            ctype = v.lower()
            break
    body = flow["request"].get("body", "")
    if not flow["request"].get("body_is_base64") and body:
        if "application/x-www-form-urlencoded" in ctype:
            for k, _v in urllib.parse.parse_qsl(body, keep_blank_values=True):
                points.append(InsertionPoint("body-form", k))
        elif "application/json" in ctype:
            try:
                obj = jsonlib.loads(body)
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        if isinstance(v, (str, int, float)):
                            points.append(InsertionPoint("json", k))
            except ValueError:
                pass
    return points


def _apply(flow: dict, point: InsertionPoint, payload: str) -> tuple[str, str, bool]:
    """Return (new_path, new_body, body_is_base64) with the payload injected."""
    req = flow["request"]
    path_only, query = _split_path(req["path"])
    body = req.get("body", "")

    if point.location == "query":
        pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
        pairs = [(k, payload if k == point.param else v) for k, v in pairs]
        new_q = urllib.parse.urlencode(pairs)
        return (path_only + ("?" + new_q if new_q else ""), body, req.get("body_is_base64", False))

    if point.location == "body-form":
        pairs = urllib.parse.parse_qsl(body, keep_blank_values=True)
        pairs = [(k, payload if k == point.param else v) for k, v in pairs]
        return (req["path"], urllib.parse.urlencode(pairs), False)

    if point.location == "json":
        try:
            obj = jsonlib.loads(body)
            obj[point.param] = payload
            return (req["path"], jsonlib.dumps(obj), False)
        except ValueError:
            return (req["path"], body, req.get("body_is_base64", False))

    return (req["path"], body, req.get("body_is_base64", False))


class ScannerEngine:
    def __init__(self, store, events, ext_manager) -> None:
        self.store = store
        self.events = events
        self.ext = ext_manager
        self.passive_checks = list(ALL_PASSIVE)
        self.active_checks = list(ALL_ACTIVE)
        self._enabled_active = {c.check_id for c in self.active_checks}

    # ---- passive -----------------------------------------------------
    def passive_scan(self, flow: dict) -> int:
        count = 0
        for check in self.passive_checks:
            try:
                for f in check.run(flow):
                    if self._save(f.to_dict()):
                        count += 1
            except Exception:
                pass
        for f in self.ext.run_response(flow):
            if self._save(f):
                count += 1
        return count

    # ---- active ------------------------------------------------------
    async def active_audit(self, flow: dict, check_ids: Optional[set] = None) -> dict:
        points = enumerate_points(flow)
        checks = [c for c in self.active_checks
                  if (check_ids is None or c.check_id in check_ids)]
        if not points:
            return {"points": 0, "requests": 0, "findings": 0,
                    "note": "No insertion points (no query/body params) found."}

        req = flow["request"]
        base_path, _ = _split_path(req["path"])
        baseline = await self._send(flow, req["path"], req.get("body", ""),
                                    req.get("body_is_base64", False))
        requests = 1
        found = 0
        for point in points:
            for check in checks:
                for payload in check.payloads:
                    new_path, new_body, b64 = _apply(flow, point, payload)
                    probe = await self._send(flow, new_path, new_body, b64)
                    requests += 1
                    if "error" in probe:
                        continue
                    res = check.detect(payload, probe, baseline, flow)
                    if res:
                        finding = {
                            "check_id": check.check_id,
                            "name": check.name,
                            "severity": check.severity,
                            "confidence": res.confidence,
                            "detail": f"Parameter '{point.param}' ({point.location}) is injectable. {res.evidence}",
                            "evidence": f"{point.describe()} <= {payload}",
                            "host": req["host"], "url": req["url"], "flow_id": flow["id"],
                            "dedup_key": f"{check.check_id}|{req['host']}|{base_path}|{point.describe()}",
                        }
                        if self._save(finding):
                            found += 1
                        break  # one payload confirming this point is enough
        return {"points": len(points), "requests": requests, "findings": found}

    async def _send(self, flow: dict, path: str, body: str, b64: bool) -> dict:
        req = flow["request"]
        url = sender.build_url(req["scheme"], req["host"], req["port"], path)
        return await sender.send(
            method=req["method"], url=url, headers=req["headers"],
            body=body, body_is_base64=b64, verify=False, follow_redirects=False,
        )

    def _save(self, finding: dict) -> bool:
        rid = self.store.save_finding(finding)
        if rid is not None:
            self.events.publish("finding", {**finding, "id": rid})
            return True
        return False
