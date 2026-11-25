"""Instant stdio MCP server for Spar (Model Context Protocol, JSON-RPC 2.0).

Zero extra runtime dependencies beyond Spar's own package: communicates over
newline-delimited JSON-RPC 2.0 on stdin/stdout (MCP protocol versions
2024-11-05 and 2025-03-26) so the compiled standalone executable starts
instantly on macOS, Linux, and Windows.

Usage:
  spar-mcp                 Start the stdio MCP server (default)
  spar-mcp --version       Print version and exit
  spar-mcp --self-test     Run in-process MCP initialize + tools/list handshake
  spar-mcp cli <args...>   Run the Spar CLI (demo, run, replay) from the same binary
"""

from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import sys
import traceback
from typing import Any

from . import __version__
from .guard import GuardViolation, ScopeGuard
from .loop import run_campaign, run_replay
from .policy import CampaignPolicy, ConfigError, CredentialStore, load_frozen_policy, load_policy

SUPPORTED_PROTOCOL_VERSIONS = ("2025-03-26", "2024-11-05")
SERVER_INFO = {"name": "spar-mcp", "version": __version__}

TOOLS: list[dict[str, Any]] = [
    {
        "name": "spar_demo",
        "description": (
            "Launch Spar's bundled localhost-only deliberately vulnerable target with "
            "ephemeral in-memory tokens, execute a full guarded red-team campaign, and "
            "return proven findings, report path, SARIF 2.1.0 path, and integrity status."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "trials": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 50,
                    "default": 3,
                    "description": "Trials per objective (default 3 for interactive MCP use).",
                },
                "spar_dir": {
                    "type": "string",
                    "default": ".spar",
                    "description": "Root directory for Spar run artifacts.",
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "spar_run",
        "description": (
            "Run a guarded Spar red-team campaign against an explicitly allowlisted live "
            "HTTP target (optionally aiming with --repo). Enforces spar.yaml scope, DNS "
            "SSRF guards, risk tiers, budgets, and zero-secret artifact rules."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["target_url"],
            "properties": {
                "target_url": {
                    "type": "string",
                    "description": "Base URL of the allowlisted target (e.g. http://127.0.0.1:8000).",
                },
                "repo": {
                    "type": "string",
                    "description": "Optional local repository path for white-box AST aiming.",
                },
                "config_path": {
                    "type": "string",
                    "default": "spar.yaml",
                    "description": "Path to spar.yaml policy file.",
                },
                "trials": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                    "description": "Optional override for trials per objective.",
                },
                "spar_dir": {
                    "type": "string",
                    "default": ".spar",
                    "description": "Root directory for Spar run artifacts.",
                },
                "allow_risky": {
                    "type": "boolean",
                    "default": False,
                    "description": "Permit state-changing techniques (default false).",
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "spar_replay",
        "description": (
            "Replay saved findings from a Spar run under its frozen policy.json to verify "
            "whether fixes hold against rotated identifiers, held-out variants, and benign tasks."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "run_dir": {
                    "type": "string",
                    "description": "Path to a specific run directory (defaults to .spar/runs/<latest>).",
                },
                "spar_dir": {
                    "type": "string",
                    "default": ".spar",
                    "description": "Root directory used to resolve .spar/latest when run_dir is omitted.",
                },
                "finding_id": {
                    "type": "string",
                    "description": "Optional single finding ID to replay.",
                },
                "apply_fix": {
                    "type": "boolean",
                    "default": False,
                    "description": "Apply synthesized fix diffs before re-attacking.",
                },
                "target_override": {
                    "type": "string",
                    "description": "Optional target URL override (must satisfy frozen allowlist).",
                },
                "trials": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                    "description": "Optional override for replay trials per finding.",
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "spar_inspect_run",
        "description": (
            "Inspect a completed Spar run directory: returns frozen policy metadata (no secrets), "
            "finding summaries, SARIF path, and report excerpt."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "run_dir": {
                    "type": "string",
                    "description": "Path to a specific run directory (defaults to .spar/runs/<latest>).",
                },
                "spar_dir": {
                    "type": "string",
                    "default": ".spar",
                    "description": "Root directory used to resolve .spar/latest when run_dir is omitted.",
                },
            },
            "additionalProperties": False,
        },
    },
]


def _resolve_run_dir(run_dir: str | None, spar_dir: str = ".spar") -> Path:
    if run_dir:
        return Path(run_dir)
    latest = Path(spar_dir) / "latest"
    if not latest.is_file():
        raise FileNotFoundError(f"No run_dir provided and {latest} does not exist; run spar_demo or spar_run first.")
    run_id = latest.read_text(encoding="utf-8").strip()
    if not run_id:
        raise ConfigError(f"{latest} is empty.")
    return Path(spar_dir) / "runs" / run_id


def _serialize_finding(f: Any) -> dict[str, Any]:
    return {
        "id": f.id,
        "objective": f.objective,
        "technique": f.technique,
        "severity": f.severity,
        "k": f.k,
        "n": f.n,
        "wilson_ci": [round(float(f.wilson_ci_low), 4), round(float(f.wilson_ci_high), 4)],
        "outcome": f.outcome,
        "trust_tier": f.trust_tier,
        "witness": f.witness,
        "fix_status": f.fix_status,
        "label": f.label,
    }


def _tool_spar_demo(args: dict[str, Any]) -> dict[str, Any]:
    from .demo_target import generate_ephemeral_tokens, run_server

    trials = int(args.get("trials", 3))
    if trials < 1:
        raise ValueError("trials must be >= 1")
    spar_dir = Path(str(args.get("spar_dir") or ".spar"))

    ephemeral_tokens = generate_ephemeral_tokens()
    token_envs = {
        "alice": "SPAR_DEMO_TOKEN_ALICE",
        "bob": "SPAR_DEMO_TOKEN_BOB",
        "auditor": "SPAR_DEMO_TOKEN_AUDITOR",
    }
    overrides = {token_envs[name]: tok for name, tok in ephemeral_tokens.items()}

    srv, _thread, port, _target = run_server(port=0, tokens=ephemeral_tokens)
    base_url = f"http://127.0.0.1:{port}"
    policy = CampaignPolicy.default_demo(base_url, token_envs, allow_risky=True, trials_n=trials)
    for acct in policy.accounts:
        if acct.name in ephemeral_tokens and not acct.token_fingerprint:
            acct.token_fingerprint = CredentialStore.fingerprint(ephemeral_tokens[acct.name])

    cred_store = CredentialStore(policy.accounts, overrides=overrides)
    repo = Path(__file__).resolve().parent / "demo_target"
    if not repo.exists():
        repo = None

    try:
        summary = run_campaign(
            policy,
            cred_store,
            spar_root=spar_dir,
            repo=repo,
            tests_dir=spar_dir / "spar_tests",
        )
    finally:
        srv.shutdown()
        srv.server_close()

    sarif_path = getattr(summary, "sarif_path", None) or (summary.run_dir / "findings.sarif.json")
    return {
        "run_id": summary.run_id,
        "run_dir": str(summary.run_dir),
        "overall_outcome": summary.overall_outcome.value,
        "integrity_passed": bool(summary.integrity.passed),
        "findings_count": len(summary.findings),
        "rejected_count": len(summary.rejected),
        "findings": [_serialize_finding(f) for f in summary.findings],
        "report_path": str(summary.report_path) if summary.report_path else None,
        "sarif_path": str(sarif_path) if Path(sarif_path).exists() else None,
        "tests_path": str(summary.tests_path) if summary.tests_path else None,
        "budget": summary.budget,
    }


def _tool_spar_run(args: dict[str, Any]) -> dict[str, Any]:
    target_url = str(args.get("target_url") or "").strip()
    if not target_url:
        raise ValueError("target_url is required")
    cfg_path = Path(str(args.get("config_path") or "spar.yaml"))
    if cfg_path.exists():
        policy = load_policy(cfg_path, target_url=target_url)
    elif cfg_path.name != "spar.yaml":
        raise ConfigError(f"Config file not found: {cfg_path}")
    else:
        policy = CampaignPolicy(target_url=target_url)

    if args.get("allow_risky"):
        policy.allow_risky = True
    if args.get("trials") is not None:
        trials = int(args["trials"])
        if trials < 1:
            raise ValueError("trials must be >= 1")
        policy.trials_n = trials

    repo = Path(str(args["repo"])).resolve() if args.get("repo") else None
    if repo is not None and not repo.exists():
        raise ConfigError(f"repo path does not exist: {repo}")

    ScopeGuard(policy.allowlist_hosts, allow_risky=policy.allow_risky).check_url(policy.target_url)
    cred_store = CredentialStore(policy.accounts)
    spar_dir = Path(str(args.get("spar_dir") or ".spar"))
    summary = run_campaign(
        policy,
        cred_store,
        spar_root=spar_dir,
        repo=repo,
        tests_dir=spar_dir / "spar_tests",
    )
    sarif_path = getattr(summary, "sarif_path", None) or (summary.run_dir / "findings.sarif.json")
    return {
        "run_id": summary.run_id,
        "run_dir": str(summary.run_dir),
        "overall_outcome": summary.overall_outcome.value,
        "integrity_passed": bool(summary.integrity.passed),
        "findings_count": len(summary.findings),
        "rejected_count": len(summary.rejected),
        "findings": [_serialize_finding(f) for f in summary.findings],
        "report_path": str(summary.report_path) if summary.report_path else None,
        "sarif_path": str(sarif_path) if Path(sarif_path).exists() else None,
        "tests_path": str(summary.tests_path) if summary.tests_path else None,
        "budget": summary.budget,
    }


def _tool_spar_replay(args: dict[str, Any]) -> dict[str, Any]:
    run_dir = _resolve_run_dir(args.get("run_dir"), str(args.get("spar_dir") or ".spar"))
    trials = int(args["trials"]) if args.get("trials") is not None else None
    summary = run_replay(
        run_dir,
        finding_id=args.get("finding_id"),
        apply_fix=bool(args.get("apply_fix", False)),
        target_override=args.get("target_override"),
        trials_override=trials,
        run_pytest=False,
    )
    return {
        "run_dir": str(summary.run_dir),
        "overall_outcome": summary.overall_outcome.value,
        "integrity_passed": bool(summary.integrity.passed),
        "results": summary.results,
        "report_path": str(summary.report_path) if summary.report_path else None,
    }


def _tool_spar_inspect_run(args: dict[str, Any]) -> dict[str, Any]:
    run_dir = _resolve_run_dir(args.get("run_dir"), str(args.get("spar_dir") or ".spar"))
    policy = load_frozen_policy(run_dir)
    findings_dir = run_dir / "findings"
    findings: list[dict[str, Any]] = []
    if findings_dir.is_dir():
        for fp in sorted(findings_dir.glob("*.json")):
            data = json.loads(fp.read_text(encoding="utf-8"))
            findings.append(
                {
                    "id": data.get("id"),
                    "objective": data.get("objective"),
                    "technique": data.get("technique"),
                    "severity": data.get("severity"),
                    "k": data.get("k"),
                    "n": data.get("n"),
                    "outcome": data.get("outcome"),
                    "label": data.get("label"),
                    "fix_status": data.get("fix_status"),
                    "witness": data.get("witness"),
                }
            )
    report_path = run_dir / "report.md"
    sarif_path = run_dir / "findings.sarif.json"
    return {
        "run_id": policy.run_id,
        "run_dir": str(run_dir),
        "target_url": policy.target_url,
        "allow_risky": policy.allow_risky,
        "allowlist_hosts": policy.allowlist_hosts,
        "findings_count": len(findings),
        "findings": findings,
        "report_path": str(report_path) if report_path.exists() else None,
        "sarif_path": str(sarif_path) if sarif_path.exists() else None,
        "report_excerpt": report_path.read_text(encoding="utf-8")[:4000] if report_path.exists() else "",
    }


_TOOL_HANDLERS = {
    "spar_demo": _tool_spar_demo,
    "spar_run": _tool_spar_run,
    "spar_replay": _tool_spar_replay,
    "spar_inspect_run": _tool_spar_inspect_run,
}


def handle_jsonrpc_message(msg: dict[str, Any]) -> dict[str, Any] | None:
    """Process one MCP JSON-RPC 2.0 message and return a response dict (or None for notifications)."""
    method = msg.get("method")
    msg_id = msg.get("id")
    params = msg.get("params") if isinstance(msg.get("params"), dict) else {}

    # Notifications have no id and must not receive a response.
    if msg_id is None and method in ("notifications/initialized", "notifications/cancelled"):
        return None

    if method == "initialize":
        client_ver = str(params.get("protocolVersion") or SUPPORTED_PROTOCOL_VERSIONS[0])
        negotiated = client_ver if client_ver in SUPPORTED_PROTOCOL_VERSIONS else SUPPORTED_PROTOCOL_VERSIONS[0]
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": negotiated,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": SERVER_INFO,
            },
        }

    if method == "ping":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS}}

    if method == "tools/call":
        tool_name = str(params.get("name") or "")
        arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        handler = _TOOL_HANDLERS.get(tool_name)
        if handler is None:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"},
            }
        # Never let tool print statements corrupt JSON-RPC stdout framing.
        with contextlib.redirect_stdout(sys.stderr):
            try:
                result_obj = handler(arguments)
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(result_obj, indent=2, default=str)}],
                        "structuredContent": result_obj,
                        "isError": False,
                    },
                }
            except (GuardViolation, ConfigError, FileNotFoundError, ValueError) as exc:
                err_payload = {"error": type(exc).__name__, "message": str(exc)}
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(err_payload, indent=2)}],
                        "structuredContent": err_payload,
                        "isError": True,
                    },
                }
            except Exception as exc:
                err_payload = {
                    "error": type(exc).__name__,
                    "message": str(exc),
                    "traceback": traceback.format_exc()[-1500:],
                }
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(err_payload, indent=2)}],
                        "structuredContent": err_payload,
                        "isError": True,
                    },
                }

    if msg_id is None:
        return None
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


def serve_stdio(stdin: Any = None, stdout: Any = None) -> int:
    """Run the newline-delimited JSON-RPC 2.0 MCP server loop on stdio."""
    in_stream = stdin or sys.stdin
    out_stream = stdout or sys.stdout
    for raw_line in in_stream:
        line = raw_line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as exc:
            resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {exc}"},
            }
            out_stream.write(json.dumps(resp) + "\n")
            out_stream.flush()
            continue
        if not isinstance(msg, dict):
            continue
        resp = handle_jsonrpc_message(msg)
        if resp is not None:
            out_stream.write(json.dumps(resp, default=str) + "\n")
            out_stream.flush()
    return 0


def run_self_test() -> int:
    """Verify the bundled MCP server answers initialize, ping, and tools/list cleanly."""
    requests = "\n".join(
        [
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}}),
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "ping"}),
            json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}),
        ]
    ) + "\n"
    out = io.StringIO()
    serve_stdio(io.StringIO(requests), out)
    responses = [json.loads(line) for line in out.getvalue().splitlines() if line.strip()]
    assert len(responses) == 3, f"Expected 3 responses, got {len(responses)}"
    assert responses[0]["result"]["serverInfo"]["name"] == "spar-mcp"
    assert responses[1]["result"] == {}
    tool_names = {t["name"] for t in responses[2]["result"]["tools"]}
    expected = {"spar_demo", "spar_run", "spar_replay", "spar_inspect_run"}
    assert expected <= tool_names, f"Missing MCP tools: {expected - tool_names}"
    print(f"spar-mcp self-test PASS: {sorted(tool_names)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] in ("-V", "--version"):
        print(f"spar-mcp {__version__}")
        return 0
    if args and args[0] == "--self-test":
        return run_self_test()
    if args and args[0] == "cli":
        from .cli import main as cli_main

        return cli_main(args[1:])
    if args and args[0] in ("-h", "--help"):
        print(__doc__.strip())
        return 0
    return serve_stdio()


if __name__ == "__main__":
    raise SystemExit(main())
