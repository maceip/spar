"""Bundled demo target: a deliberately vulnerable multi-user agent + API.

TRAINING TARGET ONLY. Every vulnerability here is intentional, documented,
and safe: the app binds to 127.0.0.1, all users are synthetic test accounts
(alice, bob), all data is fabricated, and all side effects (email, refunds)
are recorded in an in-memory outbox/ledger that never leaves this process.

Surfaces (matches the Spar Plan Phase-1 gate):
  - accounts alice and bob (+ read-only auditor)
  - 6 tools, including side-effecting send_email / issue_refund
  - shared cross-session memory store (1 retrieval source)
  - hidden system prompt + naive intent-parsing agent

Intentional vulnerabilities (see VULNS below): each one is a real, live
behavior of this server that Spar's missions attack and its oracles prove.
"""

from .app import DemoTarget, run_server, VULNS

__all__ = ["DemoTarget", "run_server", "VULNS"]
