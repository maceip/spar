"""Core worker tools, wrapped in deterministic PreToolUse / PostToolUse hooks.

The worker tool ceiling keeps agent tool sprawl out: a mission gets at most
these core tools. Optional adapters (LLM-driven multi-turn attacks) are
registered ONLY when actually configured/available — never as dead entries.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from ..config import LLMConfig
from ..guard.hooks import HookContext, guard_violation_event, post_tool_use, pre_tool_use
from ..guard.scope import GuardViolation


class ToolUnavailable(Exception):
    pass


class ToolKit:
    def __init__(
        self,
        hook_ctx: HookContext,
        accounts: dict[str, str],
        repo: Path | None = None,
        llm_cfg: LLMConfig | None = None,
    ):
        self.ctx = hook_ctx
        self.accounts = accounts  # name -> token
        self.repo = Path(repo) if repo else None
        self.llm_cfg = llm_cfg or LLMConfig()

    def available_tools(self) -> list[str]:
        tools = ["code_reader", "http", "sandbox"]
        if self.llm_cfg.enabled:
            tools.append("llm")
        return tools

    # -- 1. code reader ----------------------------------------------------
    def code_reader(self, rel_path: str) -> str:
        """Read a source file from the indexed target repo (white-box aim)."""
        if self.repo is None:
            raise ToolUnavailable("no --repo provided; code_reader unavailable (black-box mode)")
        pre_tool_use(self.ctx, "code_reader", {"path": rel_path}, risk_tier="read-only")
        target = (self.repo / rel_path).resolve()
        if not str(target).startswith(str(self.repo.resolve())):
            raise GuardViolation(f"path escapes repo scope: {rel_path!r}")
        text = target.read_text(encoding="utf-8", errors="replace")
        self.ctx.ledger.append("tool.result", {"tool": "code_reader", "path": rel_path, "bytes": len(text)})
        return text

    # -- 2. HTTP / API driver ----------------------------------------------
    def http(
        self,
        method: str,
        url: str,
        *,
        headers: dict | None = None,
        json_body: Any = None,
        account: str | None = None,
        technique: str = "",
        risk_tier: str = "read-only",
        timeout: float = 15.0,
    ) -> tuple[int, str]:
        """Guarded HTTP request. Returns (status, body_text). The reply is
        fenced as untrusted data before it is returned to any caller."""
        hdrs = dict(headers or {})
        if account:
            if account not in self.accounts:
                raise GuardViolation(f"account {account!r} not in spar.yaml")
            hdrs["Authorization"] = f"Bearer {self.accounts[account]}"
        args = {"url": url, "method": method, "account": account}
        try:
            pre_tool_use(self.ctx, "http", args, technique=technique, risk_tier=risk_tier)
        except GuardViolation as exc:
            guard_violation_event(self.ctx, "http", exc)
            raise
        data = None
        if json_body is not None:
            data = json.dumps(json_body, default=str).encode("utf-8")
            hdrs["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, method=method.upper(), headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status, body = resp.status, resp.read().decode("utf-8", errors="replace")
                resp_headers = dict(resp.headers.items())
        except urllib.error.HTTPError as exc:
            status, body = exc.code, exc.read().decode("utf-8", errors="replace")
            resp_headers = dict(exc.headers.items()) if exc.headers else {}
        reply = post_tool_use(self.ctx, "http", body, status=status, headers=resp_headers)
        self.ctx.ledger.append(
            "tool.result",
            {"tool": "http", "method": method, "url": url, "account": account, "status": status,
             "body_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
             "canaries": reply.canaries, "injection_flags": reply.injection_flags},
        )
        return status, reply.text

    def http_json(self, method: str, url: str, **kw) -> tuple[int, Any]:
        status, text = self.http(method, url, **kw)
        try:
            return status, json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return status, text

    # -- 3. sandboxed PoC runner --------------------------------------------
    def sandbox(self, python_src: str, timeout: float = 20.0) -> dict:
        """Run a PoC snippet in a subprocess with a stripped environment.
        Used for deterministic proof replay, never for target I/O (target
        I/O goes through the guarded http tool)."""
        pre_tool_use(self.ctx, "sandbox", {"bytes": len(python_src)}, risk_tier="read-only")
        proc = subprocess.run(
            [sys.executable, "-c", python_src],
            capture_output=True, text=True, timeout=timeout,
            env={"PATH": "/usr/bin:/bin", "PYTHONIOENCODING": "utf-8"},
            cwd="/",
        )
        result = {"rc": proc.returncode, "stdout": proc.stdout[-8192:], "stderr": proc.stderr[-4096:]}
        self.ctx.ledger.append("tool.result", {"tool": "sandbox", "rc": result["rc"]})
        return result

    # -- 4. optional LLM adapter ---------------------------------------------
    def llm(self, messages: list[dict], max_tokens: int = 1024) -> str:
        """OpenAI-compatible chat completion. Registered only when llm is
        configured in spar.yaml AND the API key env var is set. Spend is
        charged against the dollar budget before the reply is accepted."""
        if not self.llm_cfg.enabled:
            raise ToolUnavailable(
                "llm tool not configured (set llm.base_url/llm.model in spar.yaml "
                f"and export {self.llm_cfg.api_key_env}); this run uses deterministic scripted missions"
            )
        pre_tool_use(self.ctx, "llm", {"model": self.llm_cfg.model, "messages": len(messages)}, risk_tier="read-only")
        req = urllib.request.Request(
            self.llm_cfg.base_url.rstrip("/") + "/chat/completions",
            data=json.dumps({"model": self.llm_cfg.model, "messages": messages, "max_tokens": max_tokens}).encode(),
            headers={"Authorization": f"Bearer {self.llm_cfg.api_key}", "Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read())
        usage = data.get("usage", {})
        self.ctx.budget.charge_llm(
            int(usage.get("prompt_tokens", 0)),
            int(usage.get("completion_tokens", 0)),
            self.llm_cfg.usd_per_1k_input,
            self.llm_cfg.usd_per_1k_output,
        )
        text = data["choices"][0]["message"]["content"]
        self.ctx.ledger.append("tool.result", {"tool": "llm", "model": self.llm_cfg.model, "usage": usage})
        return text
