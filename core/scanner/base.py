"""Scanner primitives: Finding, Check base classes, payload helpers."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

SEVERITIES = ("high", "medium", "low", "info")


@dataclass
class Finding:
    check_id: str
    name: str
    severity: str
    confidence: str
    detail: str
    evidence: str
    host: str
    url: str
    flow_id: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id, "name": self.name, "severity": self.severity,
            "confidence": self.confidence, "detail": self.detail,
            "evidence": self.evidence, "host": self.host, "url": self.url,
            "flow_id": self.flow_id,
            # dedup on check + location + the specific parameter in evidence
            "dedup_key": f"{self.check_id}|{self.host}|{self.url}|{self.evidence[:60]}",
        }


class PassiveCheck:
    """Runs on an already-captured flow. No new traffic is generated."""
    check_id = "passive.base"
    name = "Passive check"

    def run(self, flow: dict) -> list[Finding]:
        raise NotImplementedError


class ActiveCheck:
    """Mutates a parameter, sends probes, inspects responses."""
    check_id = "active.base"
    name = "Active check"

    # payloads injected per parameter
    payloads: list[str] = []

    async def run(self, ctx: "ActiveContext") -> list[Finding]:
        raise NotImplementedError


@dataclass
class ActiveContext:
    """Everything an active check needs to probe one base request."""
    base_flow: dict
    send: Any  # async callable -> response dict
    baseline: Optional[dict] = None
