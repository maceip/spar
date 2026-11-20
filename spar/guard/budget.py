"""Dollar / request / rate / wall-clock budget enforcement.

Every consumption is recorded; the coordinator persists totals to the
evidence ledger so the run report shows real measured cost.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass

from .scope import GuardViolation


@dataclass
class BudgetState:
    usd_spent: float = 0.0
    requests: int = 0
    llm_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0


class Budget:
    def __init__(self, max_usd: float, max_requests: int, max_duration_s: int, rate_per_min: int):
        self.max_usd = max_usd
        self.max_requests = max_requests
        self.max_duration_s = max_duration_s
        self.rate_per_min = rate_per_min
        self.state = BudgetState()
        self.started_at = time.time()
        self._hits: deque[float] = deque()
        self._lock = threading.Lock()

    def elapsed_s(self) -> float:
        return time.time() - self.started_at

    def charge_request(self) -> None:
        with self._lock:
            now = time.time()
            if self.elapsed_s() > self.max_duration_s:
                raise GuardViolation(
                    f"wall-clock budget exhausted ({self.max_duration_s}s); kill switch engaged"
                )
            if self.state.requests >= self.max_requests:
                raise GuardViolation(f"request budget exhausted ({self.max_requests} requests)")
            while self._hits and now - self._hits[0] > 60.0:
                self._hits.popleft()
            if len(self._hits) >= self.rate_per_min:
                sleep_for = 60.0 - (now - self._hits[0])
                if sleep_for > 0:
                    time.sleep(min(sleep_for, 5.0))
                    now = time.time()
                    while self._hits and now - self._hits[0] > 60.0:
                        self._hits.popleft()
                if len(self._hits) >= self.rate_per_min:
                    raise GuardViolation(f"rate limit exceeded ({self.rate_per_min} req/min)")
            self._hits.append(now)
            self.state.requests += 1

    def charge_llm(self, input_tokens: int, output_tokens: int, usd_per_1k_in: float, usd_per_1k_out: float) -> float:
        cost = (input_tokens / 1000.0) * usd_per_1k_in + (output_tokens / 1000.0) * usd_per_1k_out
        with self._lock:
            if self.state.usd_spent + cost > self.max_usd:
                raise GuardViolation(
                    f"dollar budget exhausted: ${self.state.usd_spent + cost:.4f} > ${self.max_usd}"
                )
            self.state.usd_spent += cost
            self.state.llm_calls += 1
            self.state.input_tokens += input_tokens
            self.state.output_tokens += output_tokens
        return cost

    def summary(self) -> dict:
        return {
            "usd_spent": round(self.state.usd_spent, 4),
            "requests": self.state.requests,
            "llm_calls": self.state.llm_calls,
            "input_tokens": self.state.input_tokens,
            "output_tokens": self.state.output_tokens,
            "elapsed_s": round(self.elapsed_s(), 1),
        }
