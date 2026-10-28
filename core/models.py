"""Serialization helpers for HTTP flows.

Converts mitmproxy flow objects to/from plain dicts and raw HTTP message
bytes, so the rest of the app never has to depend on mitmproxy internals.
"""
from __future__ import annotations

import base64
from typing import Any
from urllib.parse import urlsplit


def _decode_body(raw: bytes) -> tuple[str, bool]:
    """Return (text, is_base64). Text bodies come back as utf-8; binary
    bodies are base64-encoded so the UI can still round-trip them."""
    if not raw:
        return "", False
    try:
        return raw.decode("utf-8"), False
    except UnicodeDecodeError:
        return base64.b64encode(raw).decode("ascii"), True


def body_to_bytes(text: str, is_base64: bool) -> bytes:
    if text == "":
        return b""
    if is_base64:
        return base64.b64decode(text)
    return text.encode("utf-8")


def request_to_dict(req) -> dict[str, Any]:
    text, b64 = _decode_body(req.raw_content or b"")
    return {
        "method": req.method,
        "scheme": req.scheme,
        "host": req.pretty_host,
        "port": req.port,
        "path": req.path,
        "url": req.pretty_url,
        "http_version": req.http_version,
        "headers": [[k, v] for k, v in req.headers.items(multi=True)],
        "body": text,
        "body_is_base64": b64,
    }


def response_to_dict(resp) -> dict[str, Any] | None:
    if resp is None:
        return None
    text, b64 = _decode_body(resp.raw_content or b"")
    return {
        "status_code": resp.status_code,
        "reason": resp.reason,
        "http_version": resp.http_version,
        "headers": [[k, v] for k, v in resp.headers.items(multi=True)],
        "body": text,
        "body_is_base64": b64,
    }


def flow_to_dict(flow, *, include_bodies: bool = True) -> dict[str, Any]:
    req = request_to_dict(flow.request)
    resp = response_to_dict(flow.response)
    if not include_bodies:
        # Trim bodies for the history list to keep payloads small.
        req = {**req, "body": "", "body_is_base64": False}
        if resp is not None:
            resp = {**resp, "body": "", "body_is_base64": False}
    length = 0
    mime = ""
    if flow.response is not None:
        length = len(flow.response.raw_content or b"")
        mime = flow.response.headers.get("content-type", "").split(";")[0]
    return {
        "id": flow.id,
        "request": req,
        "response": resp,
        "status_code": flow.response.status_code if flow.response else None,
        "response_length": length,
        "mime_type": mime,
        "comment": getattr(flow, "comment", "") or "",
        "marked": getattr(flow, "marked", "") or "",
    }


def raw_request_bytes(req) -> bytes:
    """Reconstruct the raw HTTP request (start line + headers + body)."""
    split = urlsplit(req.pretty_url)
    target = split.path or "/"
    if split.query:
        target += "?" + split.query
    lines = [f"{req.method} {target} {req.http_version}"]
    for k, v in req.headers.items(multi=True):
        lines.append(f"{k}: {v}")
    head = "\r\n".join(lines).encode("utf-8", "replace")
    return head + b"\r\n\r\n" + (req.raw_content or b"")


def raw_response_bytes(resp) -> bytes:
    if resp is None:
        return b""
    lines = [f"{resp.http_version} {resp.status_code} {resp.reason}"]
    for k, v in resp.headers.items(multi=True):
        lines.append(f"{k}: {v}")
    head = "\r\n".join(lines).encode("utf-8", "replace")
    return head + b"\r\n\r\n" + (resp.raw_content or b"")
