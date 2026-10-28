"""Intruder: payload-driven request automation.

Works on a raw request template with payload positions marked by the §
character (two § per position). Supports the four classic
attack types. Results stream over the event bus so the UI updates live.
"""
from __future__ import annotations

import asyncio
import itertools
import uuid
from typing import Any, Iterator

from . import sender

MARKER = "§"  # §
MAX_REQUESTS = 20000


def count_positions(template: str) -> int:
    return template.count(MARKER) // 2


def _split_template(template: str) -> list[str]:
    """Split into alternating literal / position segments.
    Even indexes are literals, odd indexes are position placeholders."""
    return template.split(MARKER)


def _assemble(parts: list[str], payloads: list[str]) -> str:
    out = []
    pi = 0
    for i, seg in enumerate(parts):
        if i % 2 == 0:
            out.append(seg)
        else:
            out.append(payloads[pi] if pi < len(payloads) else seg)
            pi += 1
    return "".join(out)


def _combinations(attack: str, n_pos: int, sets: list[list[str]]) -> Iterator[list[str]]:
    if n_pos == 0:
        return iter([])
    if attack == "sniper":
        base = sets[0] if sets else [""]
        # vary one position at a time, others get empty/original handled by caller
        def gen():
            for pos in range(n_pos):
                for pl in base:
                    combo = ["" for _ in range(n_pos)]
                    combo[pos] = pl
                    combo.append(f"__sniper_pos__{pos}")  # sentinel, stripped later
                    yield combo
        return gen()
    if attack == "battering_ram":
        base = sets[0] if sets else [""]
        return ([pl] * n_pos for pl in base)
    if attack == "pitchfork":
        use = sets[:n_pos] if sets else [[""]]
        return (list(t) for t in zip(*use))
    if attack == "cluster_bomb":
        use = sets[:n_pos] if sets else [[""]]
        return (list(t) for t in itertools.product(*use))
    return iter([])


def _parse_raw(raw: str) -> tuple[str, str, list[list[str]], str]:
    """Parse a raw HTTP request into (method, target, headers, body)."""
    if "\r\n\r\n" in raw:
        head, body = raw.split("\r\n\r\n", 1)
    elif "\n\n" in raw:
        head, body = raw.split("\n\n", 1)
    else:
        head, body = raw, ""
    lines = head.replace("\r\n", "\n").split("\n")
    request_line = lines[0].split(" ")
    method = request_line[0] if request_line else "GET"
    target = request_line[1] if len(request_line) > 1 else "/"
    headers = []
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers.append([k.strip(), v.strip()])
    return method, target, headers, body


class IntruderEngine:
    def __init__(self, events) -> None:
        self.events = events
        self._results: dict[str, list[dict]] = {}

    async def run(
        self, *, template: str, scheme: str, host: str, port: int,
        attack: str, payload_sets: list[list[str]], sniper_original: str = "",
        concurrency: int = 10,
    ) -> dict[str, Any]:
        attack_id = uuid.uuid4().hex[:8]
        self._results[attack_id] = []
        n_pos = count_positions(template)
        parts = _split_template(template)

        combos = list(_combinations(attack, n_pos, payload_sets))
        if len(combos) > MAX_REQUESTS:
            combos = combos[:MAX_REQUESTS]

        sem = asyncio.Semaphore(concurrency)
        self.events.publish("intruder_start",
                            {"attack_id": attack_id, "total": len(combos)})

        async def one(idx: int, combo: list[str]):
            # strip sniper sentinel if present
            payloads = [c for c in combo if not str(c).startswith("__sniper_pos__")]
            if attack == "sniper":
                # non-targeted positions use the original value
                payloads = [p if p != "" else sniper_original for p in payloads]
            raw = _assemble(parts, payloads)
            method, target, headers, body = _parse_raw(raw)
            host_hdr = next((v for k, v in headers if k.lower() == "host"), host)
            url = sender.build_url(scheme, host_hdr, port, target)
            async with sem:
                resp = await sender.send(
                    method=method, url=url, headers=headers, body=body, verify=False,
                )
            row = {
                "attack_id": attack_id, "index": idx,
                "payloads": payloads,
                "status": resp.get("status_code"),
                "length": resp.get("length", 0),
                "elapsed_ms": resp.get("elapsed_ms"),
                "error": resp.get("error"),
            }
            self._results[attack_id].append(row)
            self.events.publish("intruder_result", row)
            return row

        await asyncio.gather(*(one(i, c) for i, c in enumerate(combos)))
        self.events.publish("intruder_done",
                            {"attack_id": attack_id, "count": len(combos)})
        return {"attack_id": attack_id, "count": len(combos),
                "results": self._results[attack_id]}

    def results(self, attack_id: str) -> list[dict]:
        return self._results.get(attack_id, [])
