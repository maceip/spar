"""Generic contract-driven HTTP target client built on GuardedHTTPClient.

Stage 1 Core Security Plane:
- All HTTP traffic goes exclusively through `GuardedHTTPClient` (`spar/guard.py`).
- All endpoint paths, HTTP methods, and JSON field names are resolved from
  `TargetContractConfig` (`spar.yaml`), with zero hardcoded target-specific
  routes, account names, or credential prefixes.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any
import urllib.parse

from .guard import GuardedHTTPClient, UntrustedReply
from .policy import AccountRef, ConfigError, TargetContractConfig

_PATH_PARAM_RE = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


@dataclass
class TargetResponse:
    status: int
    text: str
    data: Any
    reply: UntrustedReply
    log_seq: int | None = None


class TargetClient:
    """Contract-driven client for interacting with any target HTTP agent."""

    def __init__(
        self,
        http: GuardedHTTPClient,
        contract: TargetContractConfig,
        base_url: str,
        accounts: list[AccountRef] | None = None,
    ) -> None:
        self.http = http
        self.contract = contract
        self.base_url = base_url.rstrip("/")
        self.accounts = list(accounts or [])
        self._accounts_by_name: dict[str, AccountRef] = {a.name: a for a in self.accounts}

    def _build_url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        clean = path if path.startswith("/") else f"/{path}"
        return f"{self.base_url}{clean}"

    def _require_section(self, name: str, cfg: dict[str, Any] | None) -> dict[str, Any]:
        if not cfg or not cfg.get("path"):
            raise ConfigError(f"Target contract section {name!r} does not define 'path'")
        return cfg

    def call_endpoint(
        self,
        method: str,
        path: str,
        *,
        account: str | None = None,
        json_body: Any = None,
        headers: dict[str, str] | None = None,
        technique: str = "",
        risk_tier: str = "read-only",
        timeout: float = 15.0,
    ) -> TargetResponse:
        status, data, reply = self.http.json_request(
            method,
            self._build_url(path),
            headers=headers,
            json_body=json_body,
            account=account,
            technique=technique,
            risk_tier=risk_tier,
            timeout=timeout,
        )
        return TargetResponse(
            status=status,
            text=reply.text,
            data=data,
            reply=reply,
            log_seq=reply.ledger_seq,
        )

    def chat(
        self,
        account: str | None,
        message: str,
        *,
        image_b64: str | None = None,
        session_id: str | None = None,
        technique: str = "",
        risk_tier: str = "read-only",
    ) -> TargetResponse:
        cfg = self._require_section("chat", self.contract.chat)
        method = str(cfg.get("method", "POST"))
        path = str(cfg["path"])
        msg_field = str(cfg.get("message_field") or "message")
        body: dict[str, Any] = {msg_field: message}
        if image_b64 is not None:
            img_field = str(cfg.get("image_field") or "image_b64")
            body[img_field] = image_b64
        if session_id is not None:
            sess_field = str(cfg.get("session_field") or "session_id")
            body[sess_field] = session_id
        return self.call_endpoint(
            method,
            path,
            account=account,
            json_body=body,
            technique=technique,
            risk_tier=risk_tier,
        )

    def extract_chat_reply(self, response: TargetResponse) -> str:
        """Extract the contract's reply field from a chat TargetResponse."""
        cfg = self.contract.chat or {}
        reply_field = str(cfg.get("reply_field") or "reply")
        if isinstance(response.data, dict) and reply_field in response.data:
            val = response.data[reply_field]
            return "" if val is None else str(val)
        return response.text

    def invoke_tool(
        self,
        account: str | None,
        tool: str,
        args: dict[str, Any] | None = None,
        *,
        technique: str = "",
        risk_tier: str = "read-only",
    ) -> TargetResponse:
        cfg = self._require_section("invoke", self.contract.invoke)
        method = str(cfg.get("method", "POST"))
        path = str(cfg["path"])
        tool_field = str(cfg.get("tool_field") or "tool")
        args_field = str(cfg.get("args_field") or "args")
        body = {tool_field: tool, args_field: dict(args or {})}
        return self.call_endpoint(
            method,
            path,
            account=account,
            json_body=body,
            technique=technique,
            risk_tier=risk_tier,
        )

    def mcp_call(
        self,
        account: str | None,
        method: str,
        params: dict[str, Any] | None = None,
        req_id: int = 1,
        *,
        technique: str = "",
        risk_tier: str = "read-only",
    ) -> TargetResponse:
        cfg = self._require_section("mcp", self.contract.mcp)
        http_method = str(cfg.get("method", "POST"))
        path = str(cfg["path"])
        body: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": dict(params or {}),
        }
        return self.call_endpoint(
            http_method,
            path,
            account=account,
            json_body=body,
            technique=technique,
            risk_tier=risk_tier,
        )

    def fetch_manifest(self, account: str | None = None) -> dict[str, Any]:
        cfg = self.contract.manifest or {}
        if not cfg.get("path"):
            return {}
        resp = self.call_endpoint(
            str(cfg.get("method", "GET")),
            str(cfg["path"]),
            account=account,
            technique="recon.manifest",
            risk_tier="read-only",
        )
        if 200 <= resp.status < 300 and isinstance(resp.data, dict):
            return resp.data
        return {}

    def fetch_openapi(self, account: str | None = None) -> dict[str, Any]:
        cfg = (self.contract.witnesses or {}).get("openapi") or {}
        method = str(cfg.get("method", "GET"))
        path = str(cfg.get("path", "/openapi.json"))
        resp = self.call_endpoint(
            method,
            path,
            account=account,
            technique="recon.openapi",
            risk_tier="read-only",
        )
        if 200 <= resp.status < 300 and isinstance(resp.data, dict):
            return resp.data
        return {}

    def fetch_version(self) -> dict[str, Any]:
        cfg = self.contract.version or {}
        if not cfg.get("path"):
            return {"commit": None, "verified": False, "raw": {}}
        resp = self.call_endpoint(
            str(cfg.get("method", "GET")),
            str(cfg["path"]),
            account=None,
            technique="recon.version",
            risk_tier="read-only",
        )
        raw = resp.data if isinstance(resp.data, dict) else {}
        if not (200 <= resp.status < 300 and isinstance(resp.data, dict)):
            return {"commit": None, "verified": False, "raw": raw}
        commit_val = raw.get("commit") or raw.get("git_sha") or raw.get("sha")
        commit = str(commit_val).strip() if isinstance(commit_val, str) and commit_val.strip() else None
        verified = commit is not None
        return {"commit": commit, "verified": verified, "raw": raw}

    def fetch_tool_log(
        self,
        auditor_account: str,
        *,
        technique: str = "witness.tool_log",
        risk_tier: str = "read-only",
    ) -> TargetResponse:
        cfg = self._require_section(
            "witnesses.tool_log", (self.contract.witnesses or {}).get("tool_log")
        )
        return self.call_endpoint(
            str(cfg.get("method", "GET")),
            str(cfg["path"]),
            account=auditor_account,
            technique=technique,
            risk_tier=risk_tier,
        )

    def fetch_state(
        self,
        witness_key: str,
        account: str | None,
        path_params: dict[str, str] | None = None,
        *,
        technique: str = "",
        risk_tier: str = "read-only",
    ) -> TargetResponse:
        cfg = self._require_section(
            f"witnesses.{witness_key}", (self.contract.witnesses or {}).get(witness_key)
        )
        method = str(cfg.get("method", "GET"))
        path_tmpl = str(cfg["path"])

        params = {str(k): str(v) for k, v in (path_params or {}).items()}
        if account is not None and "account" not in params:
            params["account"] = str(account)

        def _subst(match: re.Match[str]) -> str:
            key = match.group(1)
            if key not in params:
                raise ConfigError(
                    f"Missing path parameter {key!r} for witness {witness_key!r} ({path_tmpl!r})"
                )
            return urllib.parse.quote(params[key], safe="")

        resolved_path = _PATH_PARAM_RE.sub(_subst, path_tmpl)
        return self.call_endpoint(
            method,
            resolved_path,
            account=account,
            technique=technique or f"witness.{witness_key}",
            risk_tier=risk_tier,
        )

    def extract_witness_items(self, witness_key: str, response: TargetResponse) -> list[Any]:
        """Extract list items from a witness TargetResponse using contract events_field/items_field."""
        cfg = (self.contract.witnesses or {}).get(witness_key) or {}
        if not isinstance(response.data, dict):
            return []
        for key in (cfg.get("events_field"), cfg.get("items_field"), "events", "items", "records"):
            if key and isinstance(response.data.get(key), list):
                return list(response.data[key])
        return []

    def positive_control_ping(
        self,
        control_id: str,
        account: str,
        *,
        technique: str = "witness.positive_control",
        risk_tier: str = "read-only",
    ) -> TargetResponse:
        cfg = self._require_section(
            "witnesses.positive_control", (self.contract.witnesses or {}).get("positive_control")
        )
        method = str(cfg.get("method", "POST"))
        path = str(cfg["path"])
        control_field = str(cfg.get("control_field") or "control_id")
        return self.call_endpoint(
            method,
            path,
            account=account,
            json_body={control_field: control_id},
            technique=technique,
            risk_tier=risk_tier,
        )

    def reset(
        self,
        auditor_account: str,
        *,
        technique: str = "audit.reset",
    ) -> tuple[bool, int, str]:
        cfg = self._require_section("reset", self.contract.reset)
        method = str(cfg.get("method", "POST"))
        path = str(cfg["path"])
        resp = self.call_endpoint(
            method,
            path,
            account=auditor_account,
            json_body={},
            technique=technique,
            risk_tier="state-changing",
        )
        ok = False
        if 200 <= resp.status < 300:
            if isinstance(resp.data, dict):
                if "ok" in resp.data:
                    ok = bool(resp.data["ok"])
                elif "reset" in resp.data:
                    ok = bool(resp.data["reset"])
                else:
                    ok = True
            else:
                ok = True
        return ok, resp.status, resp.text


__all__ = ["TargetClient", "TargetResponse"]
