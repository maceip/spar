"""Append-only reducer event stream: .spar/attempts.jsonl.

Every request, response witness, tool-log event, lease transition, cost
record, and critic verdict is appended with a SHA-256 content hash and
origin_id lineage, chained to the previous entry so tampering is detectable.
Payloads > 256 KiB are externalized to .spar/blobs/<sha256>.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path
from typing import Any

BLOB_THRESHOLD = 256 * 1024


class Ledger:
    def __init__(self, run_dir: Path):
        self.run_dir = Path(run_dir)
        self.blobs = self.run_dir / "blobs"
        self.blobs.mkdir(parents=True, exist_ok=True)
        self.path = self.run_dir / "attempts.jsonl"
        self._lock = threading.Lock()
        self._seq = 0
        self._prev_hash = "0" * 64
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    try:
                        rec = json.loads(line)
                        self._seq = max(self._seq, int(rec.get("seq", 0)))
                        self._prev_hash = rec.get("hash", self._prev_hash)
                    except (json.JSONDecodeError, ValueError):
                        pass

    def _externalize(self, obj: Any) -> Any:
        """Replace oversized string payloads with blob references."""
        if isinstance(obj, str) and len(obj.encode("utf-8")) > BLOB_THRESHOLD:
            digest = hashlib.sha256(obj.encode("utf-8")).hexdigest()
            (self.blobs / digest).write_text(obj, encoding="utf-8")
            return {"$blob": digest, "bytes": len(obj.encode("utf-8"))}
        if isinstance(obj, dict):
            return {k: self._externalize(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._externalize(v) for v in obj]
        return obj

    def append(self, event_type: str, payload: dict, *, origin_id: str | None = None, task_id: str | None = None) -> dict:
        with self._lock:
            self._seq += 1
            body = self._externalize(payload)
            content = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
            entry_hash = hashlib.sha256((self._prev_hash + content).encode("utf-8")).hexdigest()
            rec = {
                "seq": self._seq,
                "ts": time.time(),
                "type": event_type,
                "task_id": task_id,
                "origin_id": origin_id,
                "payload": body,
                "content_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
                "prev_hash": self._prev_hash,
                "hash": entry_hash,
            }
            self._prev_hash = entry_hash
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, default=str) + "\n")
            return rec

    def events(self, event_type: str | None = None) -> list[dict]:
        out = []
        if not self.path.exists():
            return out
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            if event_type is None or rec.get("type") == event_type:
                out.append(rec)
        return out

    def verify_chain(self) -> bool:
        prev = "0" * 64
        for rec in self.events():
            if rec.get("prev_hash") != prev:
                return False
            body = json.dumps(rec["payload"], sort_keys=True, separators=(",", ":"), default=str)
            expect = hashlib.sha256((prev + body).encode("utf-8")).hexdigest()
            if rec.get("hash") != expect:
                return False
            prev = rec["hash"]
        return True
