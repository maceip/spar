"""The live attack graph blackboard: surfaces, intents, verified facts.

Deterministic Python owns every mutation. Workers propose; the coordinator
disposes. Persisted in the run's state.db so external viewers can attach.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS surfaces (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,          -- endpoint | tool | prompt | memory | auth | route
    detail TEXT NOT NULL,
    source TEXT NOT NULL,        -- recon | repo-index | plan
    discovered REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS intents (
    id TEXT PRIMARY KEY,
    surface_id TEXT,
    objective TEXT NOT NULL,
    technique TEXT NOT NULL,
    risk_tier TEXT NOT NULL,
    rank REAL NOT NULL,
    state TEXT NOT NULL DEFAULT 'planned',  -- planned | attacking | proven | refuted | exhausted
    k INTEGER NOT NULL DEFAULT 0,
    n INTEGER NOT NULL DEFAULT 0,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS facts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,          -- canary_observed | tool_log | state_diff | prompt_hash | cost
    body TEXT NOT NULL,
    verified INTEGER NOT NULL DEFAULT 0,
    origin_id TEXT,
    recorded REAL NOT NULL
);
"""


class AttackGraph:
    def __init__(self, db_path: Path):
        self._db = sqlite3.connect(str(db_path), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._db.executescript(_SCHEMA)
            self._db.commit()

    def add_surface(self, surface_id: str, kind: str, detail: dict, source: str) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO surfaces(id, kind, detail, source, discovered) VALUES(?,?,?,?,?)",
                (surface_id, kind, json.dumps(detail, default=str), source, time.time()),
            )
            self._db.commit()

    def surfaces(self, kind: str | None = None) -> list[dict]:
        with self._lock:
            if kind:
                rows = self._db.execute("SELECT * FROM surfaces WHERE kind=? ORDER BY discovered", (kind,)).fetchall()
            else:
                rows = self._db.execute("SELECT * FROM surfaces ORDER BY discovered").fetchall()
        return [
            {"id": r["id"], "kind": r["kind"], "detail": json.loads(r["detail"]), "source": r["source"]}
            for r in rows
        ]

    def add_intent(self, intent_id: str, surface_id: str | None, objective: str, technique: str, risk_tier: str, rank: float, detail: dict | None = None) -> None:
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO intents(id, surface_id, objective, technique, risk_tier, rank, state, detail) "
                "VALUES(?,?,?,?,?,?,'planned',?)",
                (intent_id, surface_id, objective, technique, risk_tier, rank, json.dumps(detail or {}, default=str)),
            )
            self._db.commit()

    def set_intent_state(self, intent_id: str, state: str, k: int | None = None, n: int | None = None) -> None:
        with self._lock:
            if k is None:
                self._db.execute("UPDATE intents SET state=? WHERE id=?", (state, intent_id))
            else:
                self._db.execute("UPDATE intents SET state=?, k=?, n=? WHERE id=?", (state, k, n, intent_id))
            self._db.commit()

    def intents(self) -> list[dict]:
        with self._lock:
            rows = self._db.execute("SELECT * FROM intents ORDER BY rank DESC").fetchall()
        return [
            {
                "id": r["id"],
                "surface_id": r["surface_id"],
                "objective": r["objective"],
                "technique": r["technique"],
                "risk_tier": r["risk_tier"],
                "rank": r["rank"],
                "state": r["state"],
                "k": r["k"],
                "n": r["n"],
                "detail": json.loads(r["detail"] or "{}"),
            }
            for r in rows
        ]

    def add_fact(self, kind: str, body: dict, *, verified: bool = False, origin_id: str | None = None) -> int:
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO facts(kind, body, verified, origin_id, recorded) VALUES(?,?,?,?,?)",
                (kind, json.dumps(body, default=str), 1 if verified else 0, origin_id, time.time()),
            )
            self._db.commit()
            return int(cur.lastrowid)

    def facts(self, kind: str | None = None, verified_only: bool = False) -> list[dict]:
        q = "SELECT * FROM facts WHERE 1=1"
        args: list = []
        if kind:
            q += " AND kind=?"
            args.append(kind)
        if verified_only:
            q += " AND verified=1"
        with self._lock:
            rows = self._db.execute(q + " ORDER BY recorded", args).fetchall()
        return [
            {"id": r["id"], "kind": r["kind"], "body": json.loads(r["body"]), "verified": bool(r["verified"]), "origin_id": r["origin_id"]}
            for r in rows
        ]

    def close(self) -> None:
        with self._lock:
            self._db.close()
