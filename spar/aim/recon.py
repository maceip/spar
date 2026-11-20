"""Black-box reconnaissance probes.

When no --repo is provided, Spar actively enumerates endpoints, tools,
prompts, and permissions against the live target before planning
objectives. Every probe goes through the guard hooks (scope, rate,
budget) and is recorded in the evidence ledger.
"""

from __future__ import annotations

import json
from typing import Any, Callable

# (method, path, auth_account, description)
PROBE_ROUTES = [
    ("GET", "/health", None, "health banner"),
    ("GET", "/", None, "root"),
    ("GET", "/agent/manifest", "alice", "agent tool manifest"),
    ("GET", "/openapi.json", None, "openapi schema"),
    ("GET", "/memory", "alice", "shared memory store"),
    ("GET", "/users/alice/outbox", "alice", "own outbox (permission baseline)"),
    ("GET", "/users/bob/outbox", "alice", "cross-user outbox (permission probe)"),
    ("GET", "/audit/tool-log", "alice", "audit log as user (permission probe)"),
    ("GET", "/audit/tool-log", "auditor", "audit log as auditor (oracle channel)"),
    ("GET", "/refunds", "auditor", "refund ledger (oracle channel)"),
]


def run_recon(http: Callable[..., Any], graph, accounts: dict[str, str], base_url: str) -> dict:
    """Probe the live target; record surfaces + permission facts in the
    attack graph. `http` is the guarded HTTP tool from spar.fire.tools."""
    results = {"probes": [], "tools": [], "retrieval_sources": [], "permission_anomalies": []}
    for method, path, acct, desc in PROBE_ROUTES:
        headers = {}
        if acct and acct in accounts:
            headers["Authorization"] = f"Bearer {accounts[acct]}"
        try:
            status, body = http(method, base_url.rstrip("/") + path, headers=headers)
        except Exception as exc:  # probe failures are facts too
            graph.add_fact("recon.probe_error", {"path": path, "error": str(exc)})
            results["probes"].append({"path": path, "account": acct, "error": str(exc)})
            continue
        text = body if isinstance(body, str) else json.dumps(body, default=str)
        results["probes"].append({"path": path, "account": acct, "status": status, "bytes": len(text)})
        if status >= 400:
            if path == "/users/bob/outbox" and status == 200:
                pass
            continue
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            data = None
        if path == "/agent/manifest" and isinstance(data, dict):
            for tool in data.get("tools", []):
                results["tools"].append(tool)
                graph.add_surface(
                    f"tool:{tool.get('name')}",
                    "tool",
                    tool,
                    "recon",
                )
            for src in data.get("retrieval_sources", []):
                results["retrieval_sources"].append(src)
                graph.add_surface(f"memory:{src}", "memory", {"source": src}, "recon")
        if path == "/memory" and isinstance(data, dict):
            graph.add_surface("memory:shared-memory", "memory", {"passages": len(data.get("passages", [])), "shared": True}, "recon")
        if path == "/health" and isinstance(data, dict):
            graph.add_surface("app:health", "endpoint", data, "recon")
        # permission anomalies: a user-role account reaching auditor or
        # cross-user data is itself a finding-worthy surface fact.
        if acct == "alice" and status == 200 and path in ("/users/bob/outbox", "/audit/tool-log"):
            results["permission_anomalies"].append({"path": path, "account": acct, "status": status})
            graph.add_fact("recon.permission_anomaly", {"path": path, "account": acct}, verified=True)
    return results
