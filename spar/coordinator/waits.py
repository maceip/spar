"""Durable event waits.

Replay-safe waiting for asynchronous, second-order effects: memory/RAG
indexing delays, blind OOB canary callbacks, and wake-on-patch triggers.
A wait is a deterministic poll loop owned by the coordinator; every wake
and timeout is recorded in the evidence ledger so a replay can skip it.
"""

from __future__ import annotations

import time
from typing import Callable


def wait_for_event(
    predicate: Callable[[], bool],
    *,
    timeout_s: float,
    poll_s: float = 0.25,
    label: str = "event",
    ledger=None,
    kill=None,
) -> bool:
    """Poll until predicate() is true or timeout. Returns True on wake."""
    deadline = time.time() + timeout_s
    polls = 0
    while time.time() < deadline:
        if kill is not None:
            kill.check()
        polls += 1
        if predicate():
            if ledger:
                ledger.append("wait.wake", {"label": label, "polls": polls})
            return True
        time.sleep(poll_s)
    if ledger:
        ledger.append("wait.timeout", {"label": label, "polls": polls, "timeout_s": timeout_s})
    return False
