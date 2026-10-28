"""Outbound HTTP sender for Repeater and Intruder.

Sends a request the user fully controls and returns the raw-ish response
without re-interpreting it, so the tester sees what the server actually
sent back.
"""
from __future__ import annotations

import time
from typing import Any

import httpx

from .models import body_to_bytes


def build_url(scheme: str, host: str, port: int, path: str) -> str:
    # host may already be a full netloc with a port (e.g. from a Host header).
    if ":" in host and not host.startswith("["):
        netloc = host
    else:
        default = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
        netloc = host if default else f"{host}:{port}"
    return f"{scheme}://{netloc}{path}"


async def send(
    *,
    method: str,
    url: str,
    headers: list[list[str]],
    body: str = "",
    body_is_base64: bool = False,
    timeout: float = 20.0,
    verify: bool = False,
    follow_redirects: bool = False,
) -> dict[str, Any]:
    """Send one request. Returns a response dict or an {error} dict."""
    content = body_to_bytes(body, body_is_base64)
    # Strip hop-by-hop / length headers httpx must recompute itself.
    drop = {"content-length", "host", "connection", "transfer-encoding"}
    hdrs = [(k, v) for k, v in headers if k.lower() not in drop]
    host_hdr = next((v for k, v in headers if k.lower() == "host"), None)
    if host_hdr:
        hdrs.append(("Host", host_hdr))

    start = time.perf_counter()
    try:
        async with httpx.AsyncClient(
            verify=verify, follow_redirects=follow_redirects, timeout=timeout
        ) as client:
            req = client.build_request(method, url, headers=hdrs, content=content or None)
            resp = await client.send(req)
            raw = resp.content
            elapsed_ms = round((time.perf_counter() - start) * 1000, 1)
            try:
                text = raw.decode("utf-8")
                b64 = False
            except UnicodeDecodeError:
                import base64
                text = base64.b64encode(raw).decode("ascii")
                b64 = True
            return {
                "status_code": resp.status_code,
                "reason": resp.reason_phrase,
                "http_version": resp.http_version,
                "headers": [[k, v] for k, v in resp.headers.items()],
                "body": text,
                "body_is_base64": b64,
                "length": len(raw),
                "elapsed_ms": elapsed_ms,
            }
    except Exception as e:
        return {
            "error": str(e),
            "elapsed_ms": round((time.perf_counter() - start) * 1000, 1),
        }
