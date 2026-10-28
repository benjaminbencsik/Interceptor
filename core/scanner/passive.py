"""Passive checks — analyse captured responses, generate no new traffic."""
from __future__ import annotations

import re

from .base import Finding, PassiveCheck


def _hdr(headers: list[list[str]], name: str) -> str | None:
    name = name.lower()
    for k, v in headers:
        if k.lower() == name:
            return v
    return None


class MissingSecurityHeaders(PassiveCheck):
    check_id = "passive.security-headers"
    name = "Missing security header"
    _wanted = {
        "content-security-policy": ("low", "No Content-Security-Policy; page has weaker XSS mitigation."),
        "x-content-type-options": ("info", "Missing X-Content-Type-Options: nosniff."),
        "strict-transport-security": ("low", "No HSTS on an HTTPS response."),
        "x-frame-options": ("info", "No X-Frame-Options / frame-ancestors; clickjacking risk."),
    }

    def run(self, flow):
        resp = flow.get("response")
        if not resp:
            return []
        ctype = (_hdr(resp["headers"], "content-type") or "").lower()
        if "text/html" not in ctype:
            return []
        out = []
        for h, (sev, detail) in self._wanted.items():
            if h == "strict-transport-security" and flow["request"]["scheme"] != "https":
                continue
            if _hdr(resp["headers"], h) is None:
                out.append(Finding(
                    self.check_id, f"Missing header: {h}", sev, "certain",
                    detail, evidence=h, host=flow["request"]["host"],
                    url=flow["request"]["url"], flow_id=flow["id"],
                ))
        return out


class InsecureCookies(PassiveCheck):
    check_id = "passive.cookie-flags"
    name = "Cookie without Secure/HttpOnly"

    def run(self, flow):
        resp = flow.get("response")
        if not resp:
            return []
        out = []
        for k, v in resp["headers"]:
            if k.lower() != "set-cookie":
                continue
            cookie_name = v.split("=", 1)[0].strip()
            low = v.lower()
            missing = [f for f in ("secure", "httponly") if f not in low]
            if missing:
                out.append(Finding(
                    self.check_id, "Cookie missing flags", "low", "firm",
                    f"Set-Cookie '{cookie_name}' missing: {', '.join(missing)}.",
                    evidence=cookie_name, host=flow["request"]["host"],
                    url=flow["request"]["url"], flow_id=flow["id"],
                ))
        return out


class ServerBanner(PassiveCheck):
    check_id = "passive.server-banner"
    name = "Server version disclosure"
    _ver = re.compile(r"\d+\.\d+")

    def run(self, flow):
        resp = flow.get("response")
        if not resp:
            return []
        out = []
        for h in ("server", "x-powered-by", "x-aspnet-version"):
            val = _hdr(resp["headers"], h)
            if val and self._ver.search(val):
                out.append(Finding(
                    self.check_id, "Version disclosure", "info", "certain",
                    f"{h} header reveals software version.",
                    evidence=f"{h}: {val}", host=flow["request"]["host"],
                    url=flow["request"]["url"], flow_id=flow["id"],
                ))
        return out


class ErrorMessageLeak(PassiveCheck):
    check_id = "passive.error-leak"
    name = "Verbose error / stack trace"
    _patterns = [
        re.compile(r"(?i)stack trace"),
        re.compile(r"(?i)SQL syntax.*MySQL"),
        re.compile(r"(?i)org\.springframework\."),
        re.compile(r"(?i)Traceback \(most recent call last\)"),
        re.compile(r"(?i)Warning: \w+\(\) \[function"),  # PHP
    ]

    def run(self, flow):
        resp = flow.get("response")
        if not resp or resp.get("body_is_base64"):
            return []
        body = resp.get("body", "")
        for p in self._patterns:
            m = p.search(body)
            if m:
                return [Finding(
                    self.check_id, "Verbose error message", "low", "firm",
                    "Response contains an error/stack trace that may leak internals.",
                    evidence=m.group(0)[:80], host=flow["request"]["host"],
                    url=flow["request"]["url"], flow_id=flow["id"],
                )]
        return []


class DirectoryListing(PassiveCheck):
    check_id = "passive.dir-listing"
    name = "Directory listing"

    def run(self, flow):
        resp = flow.get("response")
        if not resp or resp.get("body_is_base64"):
            return []
        body = resp.get("body", "")
        if "Index of /" in body and "<title>Index of" in body:
            return [Finding(
                self.check_id, "Directory listing enabled", "low", "firm",
                "Server returned an automatic directory index.",
                evidence="Index of /", host=flow["request"]["host"],
                url=flow["request"]["url"], flow_id=flow["id"],
            )]
        return []


ALL_PASSIVE = [
    MissingSecurityHeaders(), InsecureCookies(), ServerBanner(),
    ErrorMessageLeak(), DirectoryListing(),
]
