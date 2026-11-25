"""Hash-chained append-only JSONL evidence ledger with externalized blobs.

Stage 1 Core Security Plane:
- Multi-process safe via OS-level `fcntl.flock` on `run.jsonl.lock` combined
  with an in-process `threading.Lock`.
- Reads the latest tail sequence/hash from disk under lock so concurrent
  processes appending to the same `run_dir` preserve an unbroken hash chain.
- Externalizes string payloads > 256 KiB to `blobs/<sha256>` (`0o600`).
- Scans both blobs and every serialized JSONL line with `scan_for_secrets`
  before writing to disk.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import threading
import time
from typing import Any, Iterable

from .policy import _flock_acquire, _flock_release, safe_mkdir, safe_write_text, scan_for_secrets

GENESIS_HASH = "0" * 64
BLOB_THRESHOLD_BYTES = 256 * 1024


class Ledger:
    """Append-only hash-chained event ledger backed by `run_dir/run.jsonl`."""

    def __init__(self, run_dir: Path | str, secrets: Iterable[str] = ()) -> None:
        self.run_dir = safe_mkdir(Path(run_dir), mode=0o700)
        self.blobs_dir = safe_mkdir(self.run_dir / "blobs", mode=0o700)
        self.path = self.run_dir / "run.jsonl"
        self.lock_path = self.run_dir / "run.jsonl.lock"
        self._thread_lock = threading.Lock()
        self._secrets: list[str] = []
        self.add_secrets(secrets)

        if not self.path.exists():
            fd = os.open(str(self.path), os.O_CREAT | os.O_RDWR, 0o600)
            os.close(fd)
        os.chmod(self.path, 0o600)

        self._last_size: int = -1
        self._last_seq: int = 0
        self._last_hash: str = GENESIS_HASH

    def add_secrets(self, secrets: Iterable[str]) -> None:
        for s in secrets:
            if isinstance(s, str) and s and s not in self._secrets:
                self._secrets.append(s)

    def _externalize_value(self, value: Any) -> Any:
        if isinstance(value, str):
            raw = value.encode("utf-8")
            if len(raw) > BLOB_THRESHOLD_BYTES:
                scan_for_secrets(value, self._secrets)
                sha = hashlib.sha256(raw).hexdigest()
                blob_path = self.blobs_dir / sha
                if not blob_path.exists():
                    safe_write_text(blob_path, value, secrets=self._secrets)
                return {
                    "_blob_sha256": sha,
                    "blob_ref": f"blobs/{sha}",
                    "bytes": len(raw),
                }
            return value
        if isinstance(value, list):
            return [self._externalize_value(item) for item in value]
        if isinstance(value, tuple):
            return [self._externalize_value(item) for item in value]
        if isinstance(value, dict):
            return {str(k): self._externalize_value(v) for k, v in value.items()}
        return value

    @staticmethod
    def _read_tail_state(path: Path) -> tuple[int, int, str]:
        """Read (file_size, last_seq, last_hash) from the last non-empty JSONL line."""
        if not path.exists():
            return 0, 0, GENESIS_HASH
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            if size == 0:
                return 0, 0, GENESIS_HASH
            chunk_size = 4096
            pos = size
            buf = b""
            while pos > 0:
                step = min(chunk_size, pos)
                pos -= step
                fh.seek(pos, os.SEEK_SET)
                buf = fh.read(step) + buf
                lines = [ln for ln in buf.splitlines() if ln.strip()]
                if len(lines) >= 2 or (pos == 0 and lines):
                    last_line = lines[-1].decode("utf-8")
                    evt = json.loads(last_line)
                    return size, int(evt["seq"]), str(evt["hash"])
                chunk_size *= 2
        return size, 0, GENESIS_HASH

    @staticmethod
    def _compute_content_sha256(
        seq: int,
        ts: float,
        event_type: str,
        origin_id: str | None,
        task_id: str | None,
        payload: Any,
    ) -> str:
        canonical = json.dumps(
            {
                "seq": seq,
                "ts": ts,
                "type": event_type,
                "origin_id": origin_id,
                "task_id": task_id,
                "payload": payload,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def _compute_event_hash(prev_hash: str, content_sha256: str) -> str:
        return hashlib.sha256(f"{prev_hash}:{content_sha256}".encode("utf-8")).hexdigest()

    def append(
        self,
        event_type: str,
        payload: Any,
        *,
        origin_id: str | None = None,
        task_id: str | None = None,
    ) -> dict[str, Any]:
        """Append a secret-scanned, hash-chained event to run.jsonl."""
        ext_payload = self._externalize_value(payload)

        with self._thread_lock:
            lock_fd = os.open(str(self.lock_path), os.O_CREAT | os.O_RDWR, 0o600)
            try:
                _flock_acquire(lock_fd, exclusive=True)
                try:
                    current_size = self.path.stat().st_size if self.path.exists() else 0
                    if current_size != self._last_size:
                        _, prev_seq, prev_hash = self._read_tail_state(self.path)
                    else:
                        prev_seq, prev_hash = self._last_seq, self._last_hash

                    seq = prev_seq + 1
                    ts = time.time()
                    content_sha256 = self._compute_content_sha256(
                        seq, ts, event_type, origin_id, task_id, ext_payload
                    )
                    event_hash = self._compute_event_hash(prev_hash, content_sha256)
                    event: dict[str, Any] = {
                        "seq": seq,
                        "ts": ts,
                        "type": event_type,
                        "origin_id": origin_id,
                        "task_id": task_id,
                        "payload": ext_payload,
                        "prev_hash": prev_hash,
                        "content_sha256": content_sha256,
                        "hash": event_hash,
                    }
                    line = json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                    scan_for_secrets(line, self._secrets)

                    with open(self.path, "a", encoding="utf-8") as fh:
                        fh.write(line + "\n")
                        fh.flush()
                        os.fsync(fh.fileno())
                    try:
                        os.chmod(self.path, 0o600)
                    except OSError:
                        pass

                    self._last_size = self.path.stat().st_size
                    self._last_seq = seq
                    self._last_hash = event_hash
                    return event
                finally:
                    _flock_release(lock_fd)
            finally:
                os.close(lock_fd)

    def _read_all_events(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        with self._thread_lock:
            lock_fd = os.open(str(self.lock_path), os.O_CREAT | os.O_RDWR, 0o600)
            try:
                _flock_acquire(lock_fd, exclusive=False)
                try:
                    raw = self.path.read_text(encoding="utf-8")
                finally:
                    _flock_release(lock_fd)
            finally:
                os.close(lock_fd)
        out: list[dict[str, Any]] = []
        for line in raw.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            out.append(json.loads(stripped))
        return out

    def events(self, event_type: str | None = None) -> list[dict[str, Any]]:
        all_events = self._read_all_events()
        if event_type is None:
            return all_events
        return [evt for evt in all_events if evt.get("type") == event_type]

    def get_by_seq(self, seq: int) -> dict[str, Any] | None:
        for evt in self._read_all_events():
            if evt.get("seq") == seq:
                return evt
        return None

    def _verify_blobs_in_value(self, value: Any) -> bool:
        if isinstance(value, dict):
            if "_blob_sha256" in value:
                sha = str(value["_blob_sha256"])
                blob_path = self.blobs_dir / sha
                if not blob_path.exists():
                    return False
                actual = hashlib.sha256(blob_path.read_bytes()).hexdigest()
                if not hmac.compare_digest(actual, sha):
                    return False
            return all(self._verify_blobs_in_value(v) for v in value.values())
        if isinstance(value, list):
            return all(self._verify_blobs_in_value(v) for v in value)
        return True

    def verify_chain(self) -> bool:
        try:
            all_events = self._read_all_events()
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            return False

        expected_prev = GENESIS_HASH
        for idx, evt in enumerate(all_events):
            if not isinstance(evt, dict):
                return False
            if evt.get("seq") != idx + 1:
                return False
            if evt.get("prev_hash") != expected_prev:
                return False
            try:
                expected_content_sha = self._compute_content_sha256(
                    evt["seq"],
                    evt["ts"],
                    evt["type"],
                    evt.get("origin_id"),
                    evt.get("task_id"),
                    evt.get("payload"),
                )
            except (KeyError, TypeError):
                return False
            if not hmac.compare_digest(str(evt.get("content_sha256", "")), expected_content_sha):
                return False
            expected_hash = self._compute_event_hash(expected_prev, expected_content_sha)
            if not hmac.compare_digest(str(evt.get("hash", "")), expected_hash):
                return False
            if not self._verify_blobs_in_value(evt.get("payload")):
                return False
            expected_prev = expected_hash
        return True

    def _resolve_blob_or_text(self, val: Any) -> tuple[str | None, str | None]:
        """Return (text, sha256) if val is inline string or externalized blob ref."""
        if isinstance(val, str):
            return val, hashlib.sha256(val.encode("utf-8")).hexdigest()
        if isinstance(val, dict) and "_blob_sha256" in val:
            sha = str(val["_blob_sha256"])
            blob_path = self.blobs_dir / sha
            if not blob_path.exists():
                return None, None
            raw = blob_path.read_bytes()
            actual = hashlib.sha256(raw).hexdigest()
            if not hmac.compare_digest(actual, sha):
                return None, None
            return raw.decode("utf-8", errors="replace"), sha
        return None, None

    def _collect_verified_strings(self, value: Any) -> list[str]:
        texts: list[str] = []
        if isinstance(value, str):
            texts.append(value)
        elif isinstance(value, dict):
            if "_blob_sha256" in value:
                txt, _ = self._resolve_blob_or_text(value)
                if txt is not None:
                    texts.append(txt)
            else:
                for v in value.values():
                    texts.extend(self._collect_verified_strings(v))
        elif isinstance(value, list):
            for item in value:
                texts.extend(self._collect_verified_strings(item))
        return texts

    def has_quote_hash(self, quote: str) -> tuple[bool, int | None]:
        """Verify quote appears verbatim in an integrity-checked response/witness body or blob."""
        if not quote:
            return False, None
        try:
            all_events = self._read_all_events()
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            return False, None

        for evt in all_events:
            etype = str(evt.get("type", ""))
            if not (
                etype == "http.response"
                or "witness" in etype
                or "tool_log" in etype
                or etype.startswith("target.")
            ):
                continue

            # Verify event content hash before trusting its payload.
            try:
                expected_content_sha = self._compute_content_sha256(
                    evt["seq"],
                    evt["ts"],
                    evt["type"],
                    evt.get("origin_id"),
                    evt.get("task_id"),
                    evt.get("payload"),
                )
            except (KeyError, TypeError):
                continue
            if not hmac.compare_digest(str(evt.get("content_sha256", "")), expected_content_sha):
                continue

            payload = evt.get("payload")
            if not isinstance(payload, dict):
                continue

            # If body_sha256 is recorded, verify the body text or blob matches it.
            recorded_body_sha = payload.get("body_sha256")
            if "text" in payload or "body" in payload:
                body_field = payload["text"] if "text" in payload else payload["body"]
                text_val, actual_sha = self._resolve_blob_or_text(body_field)
                if text_val is None or actual_sha is None:
                    continue
                if recorded_body_sha and not hmac.compare_digest(actual_sha, str(recorded_body_sha)):
                    continue
                if quote in text_val:
                    return True, int(evt["seq"])

            # Also inspect structured witness fields / externalized blobs.
            if not self._verify_blobs_in_value(payload):
                continue
            for candidate in self._collect_verified_strings(payload):
                if quote in candidate:
                    return True, int(evt["seq"])

        return False, None
