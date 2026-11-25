"""Tests for Spar's instant stdio MCP server (spar/mcp_server.py)."""

from __future__ import annotations

import io
import json
from pathlib import Path

from spar.mcp_server import handle_jsonrpc_message, run_self_test, serve_stdio


def test_mcp_self_test_passes() -> None:
    assert run_self_test() == 0


def test_mcp_stdio_handshake_and_unknown_tool() -> None:
    stream = "\n".join(
        [
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}}),
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
            json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "nonexistent_tool", "arguments": {}}}),
        ]
    ) + "\n"
    out = io.StringIO()
    rc = serve_stdio(io.StringIO(stream), out)
    assert rc == 0
    responses = [json.loads(line) for line in out.getvalue().splitlines() if line.strip()]
    assert len(responses) == 3
    assert responses[0]["result"]["protocolVersion"] == "2025-03-26"
    assert responses[0]["result"]["serverInfo"]["name"] == "spar-mcp"
    tool_names = {t["name"] for t in responses[1]["result"]["tools"]}
    assert tool_names == {"spar_demo", "spar_run", "spar_replay", "spar_inspect_run"}
    assert responses[2]["error"]["code"] == -32601


def test_mcp_spar_run_enforces_scope_guard(tmp_path: Path) -> None:
    resp = handle_jsonrpc_message(
        {
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {
                "name": "spar_run",
                "arguments": {
                    "target_url": "http://evil.example:9999",
                    "spar_dir": str(tmp_path / ".spar"),
                },
            },
        }
    )
    assert resp is not None
    assert resp["result"]["isError"] is True
    assert resp["result"]["structuredContent"]["error"] == "GuardViolation"


def test_mcp_spar_demo_and_inspect_run(tmp_path: Path) -> None:
    spar_dir = tmp_path / ".spar"
    demo_resp = handle_jsonrpc_message(
        {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "spar_demo",
                "arguments": {"trials": 1, "spar_dir": str(spar_dir)},
            },
        }
    )
    assert demo_resp is not None
    assert demo_resp["result"]["isError"] is False
    data = demo_resp["result"]["structuredContent"]
    assert data["integrity_passed"] is True
    assert data["findings_count"] >= 5
    assert data["report_path"] and Path(data["report_path"]).is_file()

    inspect_resp = handle_jsonrpc_message(
        {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "spar_inspect_run",
                "arguments": {"spar_dir": str(spar_dir)},
            },
        }
    )
    assert inspect_resp is not None
    assert inspect_resp["result"]["isError"] is False
    inspected = inspect_resp["result"]["structuredContent"]
    assert inspected["run_id"] == data["run_id"]
    assert inspected["findings_count"] == data["findings_count"]
