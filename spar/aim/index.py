"""White-box aiming: Python AST indexer for --repo.

Parses the target repository (no LLM required) and extracts the surfaces
attacks are aimed at: routes, tool schemas and side-effect handlers, long
string constants (system prompts, with SHA-256 for the prompt-hash oracle),
auth handlers, and retrieval/memory paths.
"""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path

PROMPT_MIN_LEN = 80
SKIP_DIRS = {".git", ".venv", "__pycache__", "node_modules", ".spar", "spar_tests", "dist", "build"}


def _iter_py_files(repo: Path):
    for p in sorted(repo.rglob("*.py")):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        yield p


def index_repo(repo_path: Path) -> dict:
    repo = Path(repo_path)
    index = {
        "repo": str(repo),
        "files": 0,
        "routes": [],
        "tools": [],
        "prompts": [],
        "auth_handlers": [],
        "memory_paths": [],
        "functions": [],
    }
    for path in _iter_py_files(repo):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (SyntaxError, UnicodeDecodeError):
            continue
        index["files"] += 1
        rel = str(path.relative_to(repo))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                s = node.value
                if s.startswith("/") and len(s) > 1 and " " not in s:
                    index["routes"].append({"path": s, "file": rel, "line": node.lineno})
                if len(s) >= PROMPT_MIN_LEN:
                    index["prompts"].append(
                        {
                            "file": rel,
                            "line": node.lineno,
                            "sha256": hashlib.sha256(s.encode("utf-8")).hexdigest(),
                            "preview": s[:60],
                            "len": len(s),
                        }
                    )
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fname = node.name
                args = [a.arg for a in node.args.args if a.arg not in ("self", "cls")]
                index["functions"].append({"name": fname, "file": rel, "line": node.lineno, "args": args})
                src_names = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
                src_attrs = {n.attr for n in ast.walk(node) if isinstance(n, ast.Attribute)}
                if fname.startswith("tool_"):
                    side = bool(src_attrs & {"append", "write", "extend"} and src_attrs & {"outbox", "refunds", "memory", "tool_log"} or "send_email" in fname or "refund" in fname or "add_memory" in fname)
                    index["tools"].append(
                        {"name": fname.removeprefix("tool_"), "handler": fname, "file": rel, "line": node.lineno, "args": args, "side_effect": side}
                    )
                if "Authorization" in {n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)} or fname in ("auth", "_user"):
                    index["auth_handlers"].append({"name": fname, "file": rel, "line": node.lineno})
                if src_attrs & {"memory"} and fname not in ("tool_add_memory",):
                    index["memory_paths"].append({"name": fname, "file": rel, "line": node.lineno})
            # tool schema dict literals: {"name": ..., "params": ...}
            if isinstance(node, ast.Dict):
                keys = {k.value for k in node.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)}
                if {"name", "params"} <= keys or {"name", "description", "side_effect"} <= keys:
                    try:
                        schema = ast.literal_eval(node)
                        if isinstance(schema, dict) and "name" in schema:
                            index["tools"].append({"schema": schema, "file": rel, "line": node.lineno})
                    except (ValueError, SyntaxError):
                        pass
    # de-dup routes and tool schemas
    seen = set()
    uniq_routes = []
    for r in index["routes"]:
        if r["path"] not in seen:
            seen.add(r["path"])
            uniq_routes.append(r)
    index["routes"] = uniq_routes
    seen_tools = set()
    uniq_tools = []
    for t in index["tools"]:
        key = t.get("name") or (t.get("schema") or {}).get("name")
        if key and key not in seen_tools:
            seen_tools.add(key)
            uniq_tools.append(t)
    index["tools"] = uniq_tools
    return index
