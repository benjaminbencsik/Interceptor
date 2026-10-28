"""Encode / decode / hash transforms for the Decoder tab."""
from __future__ import annotations

import base64
import hashlib
import html
import urllib.parse


def _b(s: str) -> bytes:
    return s.encode("utf-8", "surrogatepass")


def transform(mode: str, op: str, text: str) -> str:
    """mode in {base64,url,html,hex,gzip,ascii-hex}; op in {encode,decode}.
    Hash modes (md5/sha1/sha256) ignore op and always hash."""
    try:
        if mode in ("md5", "sha1", "sha256", "sha512"):
            return hashlib.new(mode, _b(text)).hexdigest()

        if mode == "base64":
            if op == "encode":
                return base64.b64encode(_b(text)).decode("ascii")
            return base64.b64decode(text + "=" * (-len(text) % 4)).decode("utf-8", "replace")

        if mode == "base64url":
            if op == "encode":
                return base64.urlsafe_b64encode(_b(text)).decode("ascii")
            return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4)).decode("utf-8", "replace")

        if mode == "url":
            if op == "encode":
                return urllib.parse.quote(text, safe="")
            return urllib.parse.unquote(text)

        if mode == "html":
            if op == "encode":
                return html.escape(text)
            return html.unescape(text)

        if mode == "hex":
            if op == "encode":
                return _b(text).hex()
            return bytes.fromhex(text.strip().replace(" ", "")).decode("utf-8", "replace")

        if mode == "gzip":
            import gzip
            if op == "encode":
                return base64.b64encode(gzip.compress(_b(text))).decode("ascii")
            return gzip.decompress(base64.b64decode(text)).decode("utf-8", "replace")

        return "unsupported mode: " + mode
    except Exception as e:  # decoder input is user-controlled; never crash
        return f"[decode error: {e}]"


MODES = [
    "base64", "base64url", "url", "html", "hex", "gzip",
    "md5", "sha1", "sha256", "sha512",
]
