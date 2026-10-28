"""SQLite-backed storage for captured flows and scan findings.

Kept deliberately simple: one row per flow with a JSON blob plus a few
indexed columns for fast history filtering. A single connection is used
from the asyncio loop; SQLite serialises writes internally.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from typing import Any, Optional

_SCHEMA = """
CREATE TABLE IF NOT EXISTS flows (
    id          TEXT PRIMARY KEY,
    seq         INTEGER,
    ts          REAL,
    host        TEXT,
    method      TEXT,
    path        TEXT,
    status_code INTEGER,
    mime_type   TEXT,
    length      INTEGER,
    in_scope    INTEGER DEFAULT 1,
    data        TEXT
);
CREATE INDEX IF NOT EXISTS idx_flows_seq ON flows(seq);
CREATE INDEX IF NOT EXISTS idx_flows_host ON flows(host);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL,
    flow_id     TEXT,
    check_id    TEXT,
    name        TEXT,
    severity    TEXT,
    confidence  TEXT,
    host        TEXT,
    url         TEXT,
    detail      TEXT,
    evidence    TEXT,
    dedup_key   TEXT UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_find_sev ON findings(severity);
"""


class Store:
    def __init__(self, path: str = ":memory:") -> None:
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._seq = 0
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()
            row = self._conn.execute("SELECT MAX(seq) AS m FROM flows").fetchone()
            if row and row["m"] is not None:
                self._seq = row["m"]

    # ---- flows -------------------------------------------------------
    def save_flow(self, flow_dict: dict[str, Any], *, in_scope: bool = True) -> int:
        with self._lock:
            self._seq += 1
            seq = self._seq
            req = flow_dict["request"]
            self._conn.execute(
                "INSERT OR REPLACE INTO flows "
                "(id, seq, ts, host, method, path, status_code, mime_type, length, in_scope, data) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    flow_dict["id"], seq, time.time(), req["host"], req["method"],
                    req["path"], flow_dict.get("status_code"),
                    flow_dict.get("mime_type", ""), flow_dict.get("response_length", 0),
                    1 if in_scope else 0, json.dumps(flow_dict),
                ),
            )
            self._conn.commit()
            return seq

    def list_flows(
        self,
        *,
        limit: int = 500,
        offset: int = 0,
        host: Optional[str] = None,
        search: Optional[str] = None,
        in_scope_only: bool = False,
    ) -> list[dict[str, Any]]:
        q = ("SELECT id, seq, ts, host, method, path, status_code, mime_type, "
             "length, in_scope FROM flows WHERE 1=1")
        args: list[Any] = []
        if host:
            q += " AND host LIKE ?"
            args.append(f"%{host}%")
        if search:
            q += " AND (path LIKE ? OR host LIKE ?)"
            args.extend([f"%{search}%", f"%{search}%"])
        if in_scope_only:
            q += " AND in_scope = 1"
        q += " ORDER BY seq DESC LIMIT ? OFFSET ?"
        args.extend([limit, offset])
        with self._lock:
            rows = self._conn.execute(q, args).fetchall()
        return [dict(r) for r in rows]

    def get_flow(self, flow_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            row = self._conn.execute(
                "SELECT data FROM flows WHERE id = ?", (flow_id,)
            ).fetchone()
        return json.loads(row["data"]) if row else None

    def clear_flows(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM flows")
            self._conn.commit()
            self._seq = 0

    # ---- findings ----------------------------------------------------
    def save_finding(self, f: dict[str, Any]) -> Optional[int]:
        try:
            with self._lock:
                cur = self._conn.execute(
                    "INSERT INTO findings "
                    "(ts, flow_id, check_id, name, severity, confidence, host, url, detail, evidence, dedup_key) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        time.time(), f.get("flow_id"), f["check_id"], f["name"],
                        f["severity"], f.get("confidence", "firm"), f.get("host", ""),
                        f.get("url", ""), f.get("detail", ""), f.get("evidence", ""),
                        f["dedup_key"],
                    ),
                )
                self._conn.commit()
                return cur.lastrowid
        except sqlite3.IntegrityError:
            return None  # duplicate finding, silently skipped

    def list_findings(self) -> list[dict[str, Any]]:
        order = ("CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 "
                 "WHEN 'low' THEN 2 WHEN 'info' THEN 3 ELSE 4 END")
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM findings ORDER BY {order}, ts DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def clear_findings(self) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM findings")
            self._conn.commit()
