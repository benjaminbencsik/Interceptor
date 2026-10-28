"""Target list + light crawler.

Lets the tester work from a list of subdomains/URLs instead of only
proxied traffic: each target is fetched, stored as a flow (so it shows in
history and gets passively scanned), and can be queued for active audit.
The crawler harvests in-scope links from HTML responses to grow the list.
"""
from __future__ import annotations

import re
import uuid
from urllib.parse import urljoin, urlsplit

from . import sender
from .models import body_to_bytes

_LINK = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'#]+)["']""", re.I)


def _flow_from_exchange(method: str, url: str, headers, resp: dict) -> dict:
    """Build a store-compatible flow dict from a sent request + response."""
    parts = urlsplit(url)
    scheme = parts.scheme or "http"
    host = parts.hostname or ""
    port = parts.port or (443 if scheme == "https" else 80)
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    mime = ""
    length = 0
    response = None
    if resp and "error" not in resp:
        for k, v in resp["headers"]:
            if k.lower() == "content-type":
                mime = v.split(";")[0]
        length = resp.get("length", 0)
        response = {
            "status_code": resp["status_code"], "reason": resp.get("reason", ""),
            "http_version": resp.get("http_version", "HTTP/1.1"),
            "headers": resp["headers"], "body": resp.get("body", ""),
            "body_is_base64": resp.get("body_is_base64", False),
        }
    return {
        "id": uuid.uuid4().hex,
        "request": {
            "method": method, "scheme": scheme, "host": host, "port": port,
            "path": path, "url": url, "http_version": "HTTP/1.1",
            "headers": [list(h) for h in headers], "body": "", "body_is_base64": False,
        },
        "response": response,
        "status_code": response["status_code"] if response else None,
        "response_length": length, "mime_type": mime, "comment": "", "marked": "",
    }


class TargetManager:
    def __init__(self, store, events, scanner, scope) -> None:
        self.store = store
        self.events = events
        self.scanner = scanner
        self.scope = scope
        self.targets: dict[str, dict] = {}  # url -> {url, status, last_flow_id}

    def add(self, urls: list[str]) -> int:
        added = 0
        for u in urls:
            u = u.strip()
            if not u:
                continue
            if not u.startswith(("http://", "https://")):
                u = "https://" + u
            if u not in self.targets:
                self.targets[u] = {"url": u, "status": None, "last_flow_id": None}
                added += 1
        self.events.publish("targets", list(self.targets.values()))
        return added

    def list(self) -> list[dict]:
        return list(self.targets.values())

    async def seed(self, *, crawl: bool = False, headers=None, max_crawl: int = 50) -> dict:
        """Fetch every target once, store + passive-scan. Optionally crawl
        in-scope links discovered in responses (bounded)."""
        headers = headers or [["User-Agent", "interceptor-scanner/1.0"]]
        queue = [t["url"] for t in self.targets.values()]
        seen: set[str] = set()
        fetched = 0
        crawl_budget = max_crawl

        while queue:
            url = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            resp = await sender.send(method="GET", url=url, headers=headers,
                                     verify=False, follow_redirects=False)
            flow = _flow_from_exchange("GET", url, headers, resp)
            host = flow["request"]["host"]
            in_scope = self.scope.in_scope(host)
            self.store.save_flow(flow, in_scope=in_scope)
            self.events.publish("flow", {
                "id": flow["id"], "host": host, "method": "GET",
                "path": flow["request"]["path"],
                "status_code": flow["status_code"],
                "mime_type": flow["mime_type"], "length": flow["response_length"],
                "in_scope": in_scope, "seq": None,
            })
            if url in self.targets:
                self.targets[url]["status"] = flow["status_code"]
                self.targets[url]["last_flow_id"] = flow["id"]
            self.scanner.passive_scan(flow)
            fetched += 1

            if crawl and crawl_budget > 0 and flow["response"] and not flow["response"]["body_is_base64"]:
                for m in _LINK.finditer(flow["response"]["body"]):
                    link = urljoin(url, m.group(1))
                    lhost = urlsplit(link).hostname or ""
                    if link not in seen and self.scope.in_scope(lhost):
                        if link not in self.targets:
                            self.targets[link] = {"url": link, "status": None, "last_flow_id": None}
                        queue.append(link)
                        crawl_budget -= 1
                        if crawl_budget <= 0:
                            break

        self.events.publish("targets", list(self.targets.values()))
        return {"fetched": fetched, "targets": len(self.targets)}

    async def audit_all(self, check_ids=None) -> dict:
        """Active-audit every target's last stored flow."""
        total = {"points": 0, "requests": 0, "findings": 0, "targets": 0}
        for t in self.targets.values():
            fid = t.get("last_flow_id")
            if not fid:
                continue
            flow = self.store.get_flow(fid)
            if not flow:
                continue
            res = await self.scanner.active_audit(flow, check_ids)
            total["points"] += res.get("points", 0)
            total["requests"] += res.get("requests", 0)
            total["findings"] += res.get("findings", 0)
            total["targets"] += 1
        return total
