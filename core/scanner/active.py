"""Active checks — send crafted probes into insertion points and inspect
the responses. Each check declares a payload set and a detector; the engine
owns insertion-point enumeration and sending, so checks stay small.

Detectors compare the probe response against a clean baseline to cut false
positives (e.g. a SQL error already present on the untouched page is not
evidence of injection).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class ActiveResult:
    evidence: str
    confidence: str = "firm"


class ActiveCheck:
    check_id = "active.base"
    name = "Active check"
    severity = "medium"
    payloads: list[str] = []

    def detect(self, payload, probe, baseline, flow) -> Optional[ActiveResult]:
        raise NotImplementedError


MARKER = "qzx9"  # unique, unlikely to occur naturally


class ReflectedXSS(ActiveCheck):
    check_id = "active.xss-reflected"
    name = "Reflected XSS"
    severity = "high"
    payloads = [f"{MARKER}<svg/onload=alert(1)>"]

    def detect(self, payload, probe, baseline, flow):
        if probe.get("body_is_base64"):
            return None
        ctype = _ctype(probe)
        body = probe.get("body", "")
        # The angle brackets must survive unencoded for this to be exploitable.
        needle = f"{MARKER}<svg/onload"
        if needle in body and "text/html" in ctype:
            return ActiveResult(f"Unencoded reflection of '{needle}' in HTML response", "firm")
        return None


class SQLInjectionError(ActiveCheck):
    check_id = "active.sqli-error"
    name = "SQL injection (error-based)"
    severity = "high"
    payloads = ["'", "''", "' OR '1'='1"]
    _errors = re.compile(
        r"(?i)(SQL syntax.*MySQL|valid MySQL result|PostgreSQL.*ERROR|"
        r"ORA-\d{5}|Microsoft OLE DB Provider for SQL Server|"
        r"SQLite/JDBCDriver|Unclosed quotation mark after the character string|"
        r"you have an error in your sql syntax)"
    )

    def detect(self, payload, probe, baseline, flow):
        if probe.get("body_is_base64"):
            return None
        pbody = probe.get("body", "")
        bbody = (baseline or {}).get("body", "") if baseline else ""
        m = self._errors.search(pbody)
        if m and not self._errors.search(bbody):
            return ActiveResult(f"DB error surfaced by payload {payload!r}: {m.group(0)[:60]}", "firm")
        return None


class OpenRedirect(ActiveCheck):
    check_id = "active.open-redirect"
    name = "Open redirect"
    severity = "medium"
    _host = "evil.example"
    payloads = [f"https://{_host}/", f"//{_host}/"]

    def detect(self, payload, probe, baseline, flow):
        if probe.get("status_code") not in (301, 302, 303, 307, 308):
            return None
        loc = _hdr(probe, "location") or ""
        # Must redirect to the injected external host, not merely contain it.
        if re.match(rf"^(https?:)?//{re.escape(self._host)}", loc):
            return ActiveResult(f"Location header redirects to injected host: {loc[:80]}", "firm")
        return None


class PathTraversal(ActiveCheck):
    check_id = "active.path-traversal"
    name = "Path traversal / LFI"
    severity = "high"
    payloads = ["../../../../../../../../etc/passwd", "....//....//....//etc/passwd"]
    _passwd = re.compile(r"root:.*?:0:0:")

    def detect(self, payload, probe, baseline, flow):
        if probe.get("body_is_base64"):
            return None
        m = self._passwd.search(probe.get("body", ""))
        if m:
            return ActiveResult(f"/etc/passwd contents returned: {m.group(0)[:60]}", "firm")
        return None


class SSTI(ActiveCheck):
    check_id = "active.ssti"
    name = "Server-side template injection"
    severity = "high"
    # 1337*1337 = 1787569 — a value that won't appear by chance.
    payloads = ["{{1337*1337}}", "${1337*1337}", "#{1337*1337}", "<%= 1337*1337 %>"]

    def detect(self, payload, probe, baseline, flow):
        if probe.get("body_is_base64"):
            return None
        pbody = probe.get("body", "")
        bbody = (baseline or {}).get("body", "") if baseline else ""
        if "1787569" in pbody and "1787569" not in bbody and payload not in pbody:
            return ActiveResult(f"Template expression {payload!r} evaluated to 1787569", "firm")
        return None


def _hdr(resp, name):
    name = name.lower()
    for k, v in resp.get("headers", []):
        if k.lower() == name:
            return v
    return None


def _ctype(resp):
    return (_hdr(resp, "content-type") or "").lower()


ALL_ACTIVE = [
    ReflectedXSS(), SQLInjectionError(), OpenRedirect(), PathTraversal(), SSTI(),
]
