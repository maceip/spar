"""Fenced task leases (pattern from provos/tasklease, local SQLite).

- Own(task) claims a task and ROTATES its fence token; a stale worker
  holding the old token can never write results back.
- Consume(task, results, follow_ons) atomically retires the task and posts
  up to 16 follow-on chaining/critic tasks, preserving immutable origin_id
  provenance.
- Explicit scope boundaries: every task carries the objective and technique
  it is allowed to pursue; the guard layer enforces them per tool call.
"""

from __future__ import annotations

import json
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path

MAX_FOLLOW_ONS = 16

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'open',   -- open | leased | done | failed | cancelled
    fence TEXT,
    lease_expires REAL,
    origin_id TEXT,
    payload TEXT NOT NULL,
    result TEXT,
    created REAL NOT NULL,
    updated REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tasks_state ON tasks(state, kind);
"""


@dataclass
class Lease:
    task_id: str
    fence: str
    kind: str
    origin_id: str | None
    payload: dict


class StaleFenceError(Exception):
    pass


class TaskBoard:
    def __init__(self, db_path: Path):
        self._db = sqlite3.connect(str(db_path), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._db.executescript(_SCHEMA)
            self._db.commit()

    def post(self, kind: str, payload: dict, *, origin_id: str | None = None, task_id: str | None = None) -> str:
        tid = task_id or f"{kind}-{secrets.token_hex(6)}"
        now = time.time()
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO tasks(id, kind, state, origin_id, payload, created, updated) "
                "VALUES(?, ?, 'open', ?, ?, ?, ?)",
                (tid, kind, origin_id, json.dumps(payload, default=str), now, now),
            )
            self._db.commit()
        return tid

    def own(self, kind: str, lease_seconds: float = 300.0) -> Lease | None:
        """Claim the next open task of a kind, rotating its fence token."""
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM tasks WHERE kind=? AND state='open' ORDER BY created LIMIT 1",
                (kind,),
            ).fetchone()
            if row is None:
                # reclaim expired leases
                expired = self._db.execute(
                    "SELECT * FROM tasks WHERE state='leased' AND lease_expires < ? ORDER BY created LIMIT 1",
                    (time.time(),),
                ).fetchone()
                if expired is None:
                    return None
                row = expired
            fence = secrets.token_hex(8)
            now = time.time()
            self._db.execute(
                "UPDATE tasks SET state='leased', fence=?, lease_expires=?, updated=? WHERE id=?",
                (fence, now + lease_seconds, now, row["id"]),
            )
            self._db.commit()
            return Lease(
                task_id=row["id"],
                fence=fence,
                kind=row["kind"],
                origin_id=row["origin_id"],
                payload=json.loads(row["payload"]),
            )

    def consume(self, lease: Lease, result: dict, follow_ons: list[tuple[str, dict]] | None = None) -> list[str]:
        """Atomically retire the task and post up to 16 follow-on tasks."""
        follow_ons = follow_ons or []
        if len(follow_ons) > MAX_FOLLOW_ONS:
            raise ValueError(f"consume may post at most {MAX_FOLLOW_ONS} follow-ons, got {len(follow_ons)}")
        posted: list[str] = []
        now = time.time()
        with self._lock:
            row = self._db.execute("SELECT fence, state FROM tasks WHERE id=?", (lease.task_id,)).fetchone()
            if row is None or row["fence"] != lease.fence:
                raise StaleFenceError(f"lease {lease.task_id} fence was rotated; result rejected")
            if row["state"] != "leased":
                raise StaleFenceError(f"lease {lease.task_id} is {row['state']}, not leased")
            self._db.execute(
                "UPDATE tasks SET state='done', result=?, updated=? WHERE id=?",
                (json.dumps(result, default=str), now, lease.task_id),
            )
            for kind, payload in follow_ons:
                tid = f"{kind}-{secrets.token_hex(6)}"
                self._db.execute(
                    "INSERT INTO tasks(id, kind, state, origin_id, payload, created, updated) "
                    "VALUES(?, ?, 'open', ?, ?, ?, ?)",
                    (tid, kind, lease.origin_id or lease.task_id, json.dumps(payload, default=str), now, now),
                )
                posted.append(tid)
            self._db.commit()
        return posted

    def fail(self, lease: Lease, error: str) -> None:
        with self._lock:
            row = self._db.execute("SELECT fence FROM tasks WHERE id=?", (lease.task_id,)).fetchone()
            if row and row["fence"] == lease.fence:
                self._db.execute(
                    "UPDATE tasks SET state='failed', result=?, updated=? WHERE id=?",
                    (json.dumps({"error": error}), time.time(), lease.task_id),
                )
                self._db.commit()

    def cancel_all(self, reason: str) -> int:
        """Kill switch: revoke every active lease immediately."""
        now = time.time()
        with self._lock:
            cur = self._db.execute(
                "UPDATE tasks SET state='cancelled', result=?, updated=? WHERE state IN ('open','leased')",
                (json.dumps({"cancelled": reason}), now),
            )
            self._db.commit()
            return cur.rowcount

    def counts(self) -> dict:
        with self._lock:
            rows = self._db.execute("SELECT state, COUNT(*) c FROM tasks GROUP BY state").fetchall()
        return {r["state"]: r["c"] for r in rows}

    def close(self) -> None:
        with self._lock:
            self._db.close()
