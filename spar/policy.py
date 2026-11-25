"""Policy configuration, credential resolution, secret scanning, and atomic I/O.

Stage 1 Core Security Plane:
- Secrets are stored by environment-variable reference (`token_env`) only;
  plaintext `token:` keys in YAML or frozen policy artifacts are rejected.
- All artifact writes go through `safe_write_text` which scans for secrets
  before touching disk and enforces `0o600` permissions via atomic replace.
- `freeze_policy` / `load_frozen_policy` lock campaign policy with a canonical
  SHA-256 integrity digest.
"""

from __future__ import annotations

import base64
import binascii
import copy
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from typing import Any, Iterable, Mapping
import urllib.parse
import uuid

if sys.platform == "win32":  # pragma: no cover - Windows locking fallback
    import msvcrt  # type: ignore[import-not-found]
    fcntl = None  # type: ignore[assignment]
else:
    import fcntl
    msvcrt = None  # type: ignore[assignment]


def _flock_acquire(fd: int, *, exclusive: bool = True, nonblocking: bool = False) -> None:
    """Cross-platform advisory file lock (fcntl.flock on POSIX, msvcrt.locking on Windows)."""
    if fcntl is not None:
        flags = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        if nonblocking:
            flags |= fcntl.LOCK_NB
        fcntl.flock(fd, flags)
        return
    # Windows: msvcrt.locking locks byte 0..1 at current offset.
    os.lseek(fd, 0, os.SEEK_SET)
    mode = msvcrt.LK_NBLCK if nonblocking else msvcrt.LK_LOCK
    try:
        msvcrt.locking(fd, mode, 1)
    except OSError as exc:
        if nonblocking:
            raise BlockingIOError(str(exc)) from exc
        raise


def _flock_release(fd: int) -> None:
    """Release an advisory file lock acquired via _flock_acquire."""
    if fcntl is not None:
        fcntl.flock(fd, fcntl.LOCK_UN)
        return
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    except OSError:
        pass

try:
    import yaml  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]


class ConfigError(Exception):
    """Raised when policy, config, or credential setup is invalid or tampered."""


class SecretLeakError(Exception):
    """Raised when a secret value is detected in text destined for disk or logs."""


class GuardViolation(Exception):
    """Raised when a security, scope, budget, risk-tier, or lock guard triggers."""


class RunLockError(TimeoutError, GuardViolation):
    """Raised when an exclusive run lock cannot be acquired before timeout."""


def _default_auth_contract() -> dict[str, Any]:
    return {"header": "Authorization", "prefix": "Bearer "}


def _default_chat_contract() -> dict[str, Any]:
    return {
        "method": "POST",
        "path": "/agent/chat",
        "message_field": "message",
        "image_field": "image_b64",
        "session_field": "session_id",
        "reply_field": "reply",
    }


def _default_invoke_contract() -> dict[str, Any]:
    return {
        "method": "POST",
        "path": "/agent/invoke",
        "tool_field": "tool",
        "args_field": "args",
    }


def _default_mcp_contract() -> dict[str, Any]:
    return {"method": "POST", "path": "/mcp/rpc"}


def _default_manifest_contract() -> dict[str, Any]:
    return {"method": "GET", "path": "/agent/manifest"}


def _default_version_contract() -> dict[str, Any]:
    return {"method": "GET", "path": "/version"}


def _default_reset_contract() -> dict[str, Any]:
    return {"method": "POST", "path": "/audit/reset"}


def _default_witnesses_contract() -> dict[str, dict[str, Any]]:
    return {
        "tool_log": {"method": "GET", "path": "/audit/tool-log", "events_field": "events"},
        "positive_control": {"method": "POST", "path": "/audit/ping", "control_field": "control_id"},
        "outbox": {"method": "GET", "path": "/users/{account}/outbox", "items_field": "emails"},
        "refunds": {"method": "GET", "path": "/refunds", "items_field": "refunds"},
        "memory": {"method": "GET", "path": "/memory", "items_field": "passages"},
        "shared_docs": {"method": "POST", "path": "/docs/shared"},
    }


@dataclass
class AccountRef:
    name: str
    role: str = "user"
    token_env: str = ""
    token_fingerprint: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": str(self.name),
            "role": str(self.role),
            "token_env": str(self.token_env),
            "token_fingerprint": str(self.token_fingerprint),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], *, resolve_env_fingerprint: bool = True) -> AccountRef:
        if not isinstance(data, Mapping):
            raise ConfigError("Account entry must be a mapping")
        if "token" in data:
            raise ConfigError(
                f"Account {data.get('name', '<unknown>')!r} specifies plaintext 'token:'; "
                "use 'token_env:' (secrets by reference only)"
            )
        name = str(data.get("name", "")).strip()
        if not name:
            raise ConfigError("Account entry missing non-empty 'name'")
        token_env = str(data.get("token_env", "")).strip()
        if not token_env:
            raise ConfigError(
                f"Account {name!r} missing 'token_env:' (secrets must be referenced by env var name)"
            )
        role = str(data.get("role", "user")).strip() or "user"
        fp = str(data.get("token_fingerprint", "")).strip()
        if resolve_env_fingerprint and "token_fingerprint" not in data and not fp:
            env_val = os.environ.get(token_env)
            if env_val:
                fp = CredentialStore.fingerprint(env_val)
        return cls(name=name, role=role, token_env=token_env, token_fingerprint=fp)


@dataclass
class BudgetPolicy:
    max_usd: float = 10.0
    max_requests: int = 5000
    max_duration_s: float = 1800.0
    rate_per_min: float = 600.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_usd": float(self.max_usd),
            "max_requests": int(self.max_requests),
            "max_duration_s": float(self.max_duration_s),
            "rate_per_min": float(self.rate_per_min),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> BudgetPolicy:
        if not data:
            return cls()
        if not isinstance(data, Mapping):
            raise ConfigError("budget section must be a mapping")
        return cls(
            max_usd=float(data.get("max_usd", 10.0)),
            max_requests=int(data.get("max_requests", 5000)),
            max_duration_s=float(data.get("max_duration_s", 1800.0)),
            rate_per_min=float(data.get("rate_per_min", 600.0)),
        )


@dataclass
class LLMProviderConfig:
    base_url: str = ""
    api_key_env: str = "OPENAI_API_KEY"
    model: str = ""
    usd_per_1k_input: float = 0.0
    usd_per_1k_output: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "base_url": str(self.base_url),
            "api_key_env": str(self.api_key_env),
            "model": str(self.model),
            "usd_per_1k_input": float(self.usd_per_1k_input),
            "usd_per_1k_output": float(self.usd_per_1k_output),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None, *, default_env: str = "OPENAI_API_KEY") -> LLMProviderConfig:
        if not data:
            return cls(api_key_env=default_env)
        if not isinstance(data, Mapping):
            raise ConfigError("llm section must be a mapping")
        if "api_key" in data:
            raise ConfigError("LLM config specifies plaintext 'api_key:'; use 'api_key_env:'")
        return cls(
            base_url=str(data.get("base_url", "")),
            api_key_env=str(data.get("api_key_env", default_env)),
            model=str(data.get("model", "")),
            usd_per_1k_input=float(data.get("usd_per_1k_input", 0.0)),
            usd_per_1k_output=float(data.get("usd_per_1k_output", 0.0)),
        )


@dataclass
class TargetContractConfig:
    auth: dict[str, Any] = field(default_factory=_default_auth_contract)
    chat: dict[str, Any] = field(default_factory=_default_chat_contract)
    invoke: dict[str, Any] = field(default_factory=_default_invoke_contract)
    mcp: dict[str, Any] = field(default_factory=_default_mcp_contract)
    manifest: dict[str, Any] = field(default_factory=_default_manifest_contract)
    version: dict[str, Any] = field(default_factory=_default_version_contract)
    reset: dict[str, Any] = field(default_factory=_default_reset_contract)
    witnesses: dict[str, dict[str, Any]] = field(default_factory=_default_witnesses_contract)

    def to_dict(self) -> dict[str, Any]:
        return {
            "auth": copy.deepcopy(dict(self.auth)),
            "chat": copy.deepcopy(dict(self.chat)),
            "invoke": copy.deepcopy(dict(self.invoke)),
            "mcp": copy.deepcopy(dict(self.mcp)),
            "manifest": copy.deepcopy(dict(self.manifest)),
            "version": copy.deepcopy(dict(self.version)),
            "reset": copy.deepcopy(dict(self.reset)),
            "witnesses": {k: copy.deepcopy(dict(v)) for k, v in (self.witnesses or {}).items()},
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> TargetContractConfig:
        if data is None:
            return cls()
        if not isinstance(data, Mapping):
            raise ConfigError("target.contract must be a mapping")
        if not data:
            return cls()

        auth_raw = data.get("auth")
        auth = _default_auth_contract()
        if isinstance(auth_raw, Mapping):
            auth.update(dict(auth_raw))

        def _section(key: str, default_fn, *, allow_absent_empty: bool = False) -> dict[str, Any]:
            if key not in data:
                return {} if allow_absent_empty else default_fn()
            val = data[key]
            if val is None or val == {}:
                return {}
            if not isinstance(val, Mapping):
                raise ConfigError(f"target.contract.{key} must be a mapping")
            return copy.deepcopy(dict(val))

        witnesses_raw = data.get("witnesses")
        if "witnesses" in data:
            if witnesses_raw is None:
                witnesses: dict[str, dict[str, Any]] = {}
            elif not isinstance(witnesses_raw, Mapping):
                raise ConfigError("target.contract.witnesses must be a mapping")
            else:
                witnesses = {}
                for k, v in witnesses_raw.items():
                    if not isinstance(v, Mapping):
                        raise ConfigError(f"target.contract.witnesses.{k} must be a mapping")
                    witnesses[str(k)] = copy.deepcopy(dict(v))
        else:
            witnesses = {}

        return cls(
            auth=auth,
            chat=_section("chat", _default_chat_contract),
            invoke=_section("invoke", _default_invoke_contract),
            mcp=_section("mcp", _default_mcp_contract, allow_absent_empty=True),
            manifest=_section("manifest", _default_manifest_contract),
            version=_section("version", _default_version_contract),
            reset=_section("reset", _default_reset_contract),
            witnesses=witnesses,
        )


@dataclass
class CampaignPolicy:
    run_id: str = field(default_factory=lambda: f"run-{uuid.uuid4().hex[:12]}")
    target_url: str = "http://127.0.0.1:8765"
    allowlist_hosts: list[str] = field(default_factory=lambda: ["127.0.0.1", "localhost"])
    allow_risky: bool = False
    accounts: list[AccountRef] = field(default_factory=list)
    budget: BudgetPolicy = field(default_factory=BudgetPolicy)
    trials_n: int = 20
    min_distinct_techniques: int = 3
    llm: LLMProviderConfig = field(default_factory=LLMProviderConfig)
    critic_llm: LLMProviderConfig = field(
        default_factory=lambda: LLMProviderConfig(api_key_env="SPAR_CRITIC_API_KEY")
    )
    target_contract: TargetContractConfig = field(default_factory=TargetContractConfig)
    demo_mode: bool = False
    scope_signature: str = ""
    scope_public_key_env: str = "SPAR_SCOPE_PUBKEY"
    created_at: float = field(default_factory=time.time)
    policy_sha256: str = ""

    def to_dict(self, *, include_hash: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "run_id": str(self.run_id),
            "target_url": str(self.target_url),
            "allowlist_hosts": [str(h) for h in self.allowlist_hosts],
            "allow_risky": bool(self.allow_risky),
            "accounts": [a.to_dict() for a in self.accounts],
            "budget": self.budget.to_dict(),
            "trials_n": int(self.trials_n),
            "min_distinct_techniques": int(self.min_distinct_techniques),
            "llm": self.llm.to_dict(),
            "critic_llm": self.critic_llm.to_dict(),
            "target_contract": self.target_contract.to_dict(),
            "demo_mode": bool(self.demo_mode),
            "scope_signature": str(self.scope_signature),
            "scope_public_key_env": str(self.scope_public_key_env),
            "created_at": float(self.created_at),
        }
        if include_hash:
            payload["policy_sha256"] = str(self.policy_sha256)
        return payload

    def compute_sha256(self) -> str:
        canonical = json.dumps(
            self.to_dict(include_hash=False),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @classmethod
    def from_dict(
        cls,
        data: Mapping[str, Any],
        *,
        target_url: str | None = None,
        resolve_env_fingerprint: bool = True,
    ) -> CampaignPolicy:
        if not isinstance(data, Mapping):
            raise ConfigError("Policy configuration must be a YAML/JSON mapping")

        # Support both frozen policy.json (flat) and spar.yaml (nested) formats.
        if "target" in data or "scope" in data or "trials" in data:
            target_sec = data.get("target") or {}
            if not isinstance(target_sec, Mapping):
                raise ConfigError("target section must be a mapping")
            scope_sec = data.get("scope") or {}
            if not isinstance(scope_sec, Mapping):
                raise ConfigError("scope section must be a mapping")
            trials_sec = data.get("trials") or {}
            if not isinstance(trials_sec, Mapping):
                raise ConfigError("trials section must be a mapping")

            resolved_url = str(target_url or target_sec.get("base_url") or "http://127.0.0.1:8765")
            allowlist_raw = scope_sec.get("allowlist_hosts", ["127.0.0.1", "localhost"])
            if not isinstance(allowlist_raw, list):
                raise ConfigError("scope.allowlist_hosts must be a list")
            allowlist_hosts = [str(h) for h in allowlist_raw]
            allow_risky = bool(scope_sec.get("allow_risky", False))
            scope_signature = str(scope_sec.get("signature", "") or "")
            scope_public_key_env = str(scope_sec.get("public_key_env", "SPAR_SCOPE_PUBKEY") or "SPAR_SCOPE_PUBKEY")
            contract = TargetContractConfig.from_dict(target_sec.get("contract"))
            trials_n = int(trials_sec.get("n", 20))
            min_distinct = int(trials_sec.get("min_distinct_techniques", 3))
            demo_mode = bool(data.get("demo_mode", False))
            run_id = str(data.get("run_id") or f"run-{uuid.uuid4().hex[:12]}")
            created_at = float(data.get("created_at", time.time()))
            policy_sha256 = str(data.get("policy_sha256", ""))
        else:
            resolved_url = str(target_url or data.get("target_url") or "http://127.0.0.1:8765")
            allowlist_raw = data.get("allowlist_hosts", ["127.0.0.1", "localhost"])
            if not isinstance(allowlist_raw, list):
                raise ConfigError("allowlist_hosts must be a list")
            allowlist_hosts = [str(h) for h in allowlist_raw]
            allow_risky = bool(data.get("allow_risky", False))
            scope_signature = str(data.get("scope_signature", "") or "")
            scope_public_key_env = str(
                data.get("scope_public_key_env", "SPAR_SCOPE_PUBKEY") or "SPAR_SCOPE_PUBKEY"
            )
            contract = TargetContractConfig.from_dict(data.get("target_contract"))
            trials_n = int(data.get("trials_n", 20))
            min_distinct = int(data.get("min_distinct_techniques", 3))
            demo_mode = bool(data.get("demo_mode", False))
            run_id = str(data.get("run_id") or f"run-{uuid.uuid4().hex[:12]}")
            created_at = float(data.get("created_at", time.time()))
            policy_sha256 = str(data.get("policy_sha256", ""))

        accounts_raw = data.get("accounts") or []
        if not isinstance(accounts_raw, list):
            raise ConfigError("accounts section must be a list")
        accounts = [
            AccountRef.from_dict(item, resolve_env_fingerprint=resolve_env_fingerprint)
            for item in accounts_raw
        ]

        budget = BudgetPolicy.from_dict(data.get("budget"))
        llm = LLMProviderConfig.from_dict(data.get("llm"), default_env="OPENAI_API_KEY")
        critic_llm = LLMProviderConfig.from_dict(
            data.get("critic_llm"), default_env="SPAR_CRITIC_API_KEY"
        )

        return cls(
            run_id=run_id,
            target_url=resolved_url,
            allowlist_hosts=allowlist_hosts,
            allow_risky=allow_risky,
            accounts=accounts,
            budget=budget,
            trials_n=trials_n,
            min_distinct_techniques=min_distinct,
            llm=llm,
            critic_llm=critic_llm,
            target_contract=contract,
            demo_mode=demo_mode,
            scope_signature=scope_signature,
            scope_public_key_env=scope_public_key_env,
            created_at=created_at,
            policy_sha256=policy_sha256,
        )

    @classmethod
    def from_yaml(cls, path: Path | str, *, target_url: str | None = None) -> CampaignPolicy:
        p = Path(path)
        if not p.exists():
            raise ConfigError(f"Policy file does not exist: {p}")
        text = p.read_text(encoding="utf-8")
        data = _parse_yaml_safe(text)
        return cls.from_dict(data, target_url=target_url)

    @classmethod
    def from_file(cls, path: Path | str, *, target_url: str | None = None) -> CampaignPolicy:
        return cls.from_yaml(path, target_url=target_url)

    @classmethod
    def default_demo(
        cls,
        base_url: str = "http://127.0.0.1:8765",
        token_envs: Mapping[str, str] | Iterable[tuple[str, str, str]] | None = None,
        *,
        allow_risky: bool = False,
        trials_n: int = 20,
    ) -> CampaignPolicy:
        if token_envs is None:
            env_map: dict[str, str] = {
                "alice": "SPAR_DEMO_TOKEN_ALICE",
                "bob": "SPAR_DEMO_TOKEN_BOB",
                "auditor": "SPAR_DEMO_TOKEN_AUDITOR",
            }
            accounts = [
                AccountRef(
                    name=name,
                    role="auditor" if name == "auditor" else "user",
                    token_env=env_name,
                    token_fingerprint=CredentialStore.fingerprint(os.environ[env_name])
                    if os.environ.get(env_name)
                    else "",
                )
                for name, env_name in env_map.items()
            ]
        elif isinstance(token_envs, Mapping):
            accounts = [
                AccountRef(
                    name=str(name),
                    role="auditor" if str(name) == "auditor" else "user",
                    token_env=str(env_name),
                    token_fingerprint=CredentialStore.fingerprint(os.environ[str(env_name)])
                    if os.environ.get(str(env_name))
                    else "",
                )
                for name, env_name in token_envs.items()
            ]
        else:
            accounts = []
            for item in token_envs:
                if isinstance(item, AccountRef):
                    accounts.append(item)
                elif isinstance(item, (tuple, list)) and len(item) >= 3:
                    name, role, env_name = str(item[0]), str(item[1]), str(item[2])
                    accounts.append(
                        AccountRef(
                            name=name,
                            role=role,
                            token_env=env_name,
                            token_fingerprint=CredentialStore.fingerprint(os.environ[env_name])
                            if os.environ.get(env_name)
                            else "",
                        )
                    )
                else:
                    raise ConfigError("token_envs entries must be name->env mapping or (name, role, token_env)")

        parsed_host = (urllib.parse.urlsplit(base_url).hostname or "").strip().rstrip(".").lower()
        allowlist = ["127.0.0.1", "localhost"]
        if parsed_host and parsed_host not in allowlist:
            allowlist.append(parsed_host)

        return cls(
            run_id=f"demo-{uuid.uuid4().hex[:12]}",
            target_url=base_url,
            allowlist_hosts=allowlist,
            allow_risky=allow_risky,
            accounts=accounts,
            budget=BudgetPolicy(),
            trials_n=trials_n,
            min_distinct_techniques=3,
            llm=LLMProviderConfig(),
            critic_llm=LLMProviderConfig(api_key_env="SPAR_CRITIC_API_KEY"),
            target_contract=TargetContractConfig(),
            demo_mode=True,
        )


def load_policy(path: Path | str, *, target_url: str | None = None) -> CampaignPolicy:
    """Load a CampaignPolicy from a YAML file."""
    return CampaignPolicy.from_yaml(path, target_url=target_url)


def _strip_yaml_comment(line: str) -> str:
    in_sq = False
    in_dq = False
    for idx, ch in enumerate(line):
        if ch == "'" and not in_dq:
            in_sq = not in_sq
        elif ch == '"' and not in_sq:
            in_dq = not in_dq
        elif ch == "#" and not in_sq and not in_dq:
            if idx == 0 or line[idx - 1].isspace():
                return line[:idx]
    return line


def _parse_yaml_scalar(raw: str) -> Any:
    s = raw.strip()
    if s in ("", "null", "Null", "NULL", "~"):
        return None
    if s in ("true", "True", "TRUE"):
        return True
    if s in ("false", "False", "FALSE"):
        return False
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        if s.startswith('"'):
            try:
                return json.loads(s)
            except json.JSONDecodeError:
                return s[1:-1]
        return s[1:-1].replace("''", "'")
    if s == "[]":
        return []
    if s == "{}":
        return {}
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return float(s)
    except ValueError:
        pass
    return s


def _fallback_parse_yaml(text: str) -> dict[str, Any]:
    """Minimal safe indentation-based YAML parser used only when PyYAML is absent."""
    tokens: list[tuple[int, str]] = []
    for raw_line in text.splitlines():
        cleaned = _strip_yaml_comment(raw_line).rstrip()
        if not cleaned.strip():
            continue
        indent = len(cleaned) - len(cleaned.lstrip(" "))
        tokens.append((indent, cleaned.strip()))
    if not tokens:
        return {}

    def _parse_block(idx: int, min_indent: int) -> tuple[Any, int]:
        _, first = tokens[idx]
        if first.startswith("- "):
            items: list[Any] = []
            while idx < len(tokens):
                ind, txt = tokens[idx]
                if ind < min_indent or not txt.startswith("- "):
                    break
                rest = txt[2:].strip()
                if ":" in rest and not rest.startswith(('"', "'")):
                    key, val = rest.split(":", 1)
                    obj: dict[str, Any] = {}
                    val_s = val.strip()
                    if val_s:
                        obj[key.strip()] = _parse_yaml_scalar(val_s)
                        idx += 1
                    else:
                        idx += 1
                        if idx < len(tokens) and tokens[idx][0] > ind:
                            sub, idx = _parse_block(idx, tokens[idx][0])
                            obj[key.strip()] = sub
                        else:
                            obj[key.strip()] = {}
                    while idx < len(tokens) and tokens[idx][0] > ind and not tokens[idx][1].startswith("- "):
                        sub_ind, sub_txt = tokens[idx]
                        if ":" not in sub_txt:
                            raise ConfigError(f"Invalid YAML line: {sub_txt!r}")
                        k2, v2 = sub_txt.split(":", 1)
                        v2_s = v2.strip()
                        if v2_s:
                            obj[k2.strip()] = _parse_yaml_scalar(v2_s)
                            idx += 1
                        else:
                            idx += 1
                            if idx < len(tokens) and tokens[idx][0] > sub_ind:
                                sub2, idx = _parse_block(idx, tokens[idx][0])
                                obj[k2.strip()] = sub2
                            else:
                                obj[k2.strip()] = {}
                    items.append(obj)
                else:
                    items.append(_parse_yaml_scalar(rest))
                    idx += 1
            return items, idx

        mapping: dict[str, Any] = {}
        while idx < len(tokens):
            ind, txt = tokens[idx]
            if ind < min_indent or txt.startswith("- "):
                break
            if ":" not in txt:
                raise ConfigError(f"Invalid YAML mapping line: {txt!r}")
            key, val = txt.split(":", 1)
            k = key.strip()
            val_s = val.strip()
            if val_s:
                mapping[k] = _parse_yaml_scalar(val_s)
                idx += 1
            else:
                idx += 1
                if idx < len(tokens) and tokens[idx][0] > ind:
                    sub, idx = _parse_block(idx, tokens[idx][0])
                    mapping[k] = sub
                else:
                    mapping[k] = {}
        return mapping, idx

    parsed, _ = _parse_block(0, tokens[0][0])
    if not isinstance(parsed, dict):
        raise ConfigError("YAML root must be a mapping")
    return parsed


def _parse_yaml_safe(text: str) -> dict[str, Any]:
    if yaml is not None:
        try:
            loaded = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ConfigError(f"Failed to parse YAML: {exc}") from exc
        if loaded is None:
            return {}
        if not isinstance(loaded, dict):
            raise ConfigError("YAML root must be a mapping")
        return loaded
    return _fallback_parse_yaml(text)


class CredentialStore:
    """Resolves account secrets at request time from os.environ or memory overrides."""

    def __init__(
        self,
        accounts: Iterable[AccountRef] = (),
        overrides: Mapping[str, str] | None = None,
        *,
        extra_secrets: Iterable[str] = (),
    ) -> None:
        self._accounts: dict[str, AccountRef] = {a.name: a for a in accounts}
        self._overrides: dict[str, str] = {str(k): str(v) for k, v in (overrides or {}).items()}
        self._extra_secrets: list[str] = [str(s) for s in extra_secrets if s]

    @staticmethod
    def fingerprint(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]

    def get_account(self, account_name: str) -> AccountRef:
        acct = self._accounts.get(account_name)
        if acct is None:
            raise ConfigError(f"Unknown account {account_name!r}")
        return acct

    def add_secret(self, secret: str) -> None:
        if secret and secret not in self._extra_secrets:
            self._extra_secrets.append(secret)

    def get_token(self, account_name: str) -> str:
        acct = self._accounts.get(account_name)
        if account_name in self._overrides:
            tok = self._overrides[account_name]
            if not tok:
                raise ConfigError(f"Empty override token for account {account_name!r}")
            return tok
        if acct is None:
            raise ConfigError(f"Unknown account {account_name!r}")
        if acct.token_env and acct.token_env in self._overrides:
            tok = self._overrides[acct.token_env]
            if not tok:
                raise ConfigError(f"Empty override token for env {acct.token_env!r}")
            return tok
        if not acct.token_env:
            raise ConfigError(f"Account {account_name!r} has no token_env configured")
        val = os.environ.get(acct.token_env, "")
        if not val:
            raise ConfigError(
                f"Missing environment variable {acct.token_env!r} for account {account_name!r}"
            )
        return val

    def secret_values(self) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []

        def _add(val: str | None) -> None:
            if val and val not in seen:
                seen.add(val)
                out.append(val)

        for val in self._overrides.values():
            _add(val)
        for acct in self._accounts.values():
            if acct.token_env:
                _add(os.environ.get(acct.token_env))
        for val in self._extra_secrets:
            _add(val)
        return out


def scan_for_secrets(text: str, secrets: Iterable[str]) -> None:
    """Reject text containing any secret >= 6 chars verbatim, URL-encoded, or base64-encoded."""
    if not text:
        return
    for secret in secrets:
        if not isinstance(secret, str) or len(secret) < 6:
            continue
        fp = CredentialStore.fingerprint(secret)
        if secret in text:
            raise SecretLeakError(
                f"Refusing write: secret detected verbatim (fingerprint={fp})"
            )
        url_enc = urllib.parse.quote(secret, safe="")
        if url_enc and len(url_enc) >= 6 and url_enc in text:
            raise SecretLeakError(
                f"Refusing write: URL-encoded secret detected (fingerprint={fp})"
            )
        raw_bytes = secret.encode("utf-8")
        b64_std = base64.b64encode(raw_bytes).decode("ascii")
        b64_url = base64.urlsafe_b64encode(raw_bytes).decode("ascii")
        candidates = [b64_std, b64_url]
        for b64_cand in (b64_std.rstrip("="), b64_url.rstrip("=")):
            if len(b64_cand) >= 8:
                candidates.append(b64_cand)
        for cand in candidates:
            if cand and cand in text:
                raise SecretLeakError(
                    f"Refusing write: base64-encoded secret detected (fingerprint={fp})"
                )


def safe_mkdir(path: Path | str, mode: int = 0o700) -> Path:
    """Create directory if missing and enforce restrictive permissions."""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    os.chmod(p, mode)
    return p


def safe_write_text(path: Path | str, content: str, secrets: Iterable[str] = ()) -> Path:
    """Scan content for secrets, then atomically write with 0o600 permissions."""
    secret_list = tuple(secrets)
    scan_for_secrets(content, secret_list)
    p = Path(path)
    if not p.parent.exists():
        safe_mkdir(p.parent, mode=0o700)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{p.name}.", suffix=".tmp", dir=str(p.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, p)
    except BaseException:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return p


def freeze_policy(policy: CampaignPolicy, run_dir: Path | str, secrets: Iterable[str] = ()) -> Path:
    """Compute canonical policy_sha256 and atomically write run_dir/policy.json (0o600)."""
    rd = safe_mkdir(Path(run_dir), mode=0o700)
    if not policy.run_id:
        policy.run_id = f"run-{uuid.uuid4().hex[:12]}"
    digest = policy.compute_sha256()
    policy.policy_sha256 = digest
    payload = policy.to_dict(include_hash=True)
    content = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    out_path = rd / "policy.json"
    safe_write_text(out_path, content, secrets=secrets)
    return out_path


def load_frozen_policy(run_dir: Path | str) -> CampaignPolicy:
    """Load run_dir/policy.json and verify canonical policy_sha256 integrity."""
    p = Path(run_dir) / "policy.json"
    if not p.exists():
        raise ConfigError(f"Frozen policy missing: {p}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"Failed to read frozen policy {p}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"Frozen policy must be a JSON object: {p}")

    recorded_sha = str(data.get("policy_sha256", "") or "")
    if not recorded_sha:
        raise ConfigError(f"Frozen policy missing policy_sha256: {p}")

    policy = CampaignPolicy.from_dict(data, resolve_env_fingerprint=False)
    computed_sha = policy.compute_sha256()
    if not hmac.compare_digest(computed_sha, recorded_sha):
        raise ConfigError(
            f"Frozen policy integrity check failed for {p}: policy_sha256 mismatch"
        )
    policy.policy_sha256 = recorded_sha
    return policy


class RunLock:
    """OS-level exclusive advisory lock on run_dir/run.lock via fcntl.flock."""

    def __init__(self, run_dir: Path | str, timeout_s: float = 30.0) -> None:
        self.run_dir = Path(run_dir)
        self.lock_path = self.run_dir / "run.lock"
        self.timeout_s = float(timeout_s)
        self._fd: int | None = None

    def acquire(self) -> RunLock:
        if self._fd is not None:
            return self
        safe_mkdir(self.run_dir, mode=0o700)
        fd = os.open(str(self.lock_path), os.O_CREAT | os.O_RDWR, 0o600)
        try:
            os.chmod(self.lock_path, 0o600)
        except OSError:
            pass
        deadline = time.monotonic() + max(0.0, self.timeout_s)
        while True:
            try:
                _flock_acquire(fd, exclusive=True, nonblocking=True)
                break
            except BlockingIOError as exc:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    os.close(fd)
                    raise RunLockError(
                        f"Timed out after {self.timeout_s:.2f}s waiting for run lock {self.lock_path}"
                    ) from exc
                time.sleep(min(0.05, remaining))
            except OSError:
                os.close(fd)
                raise
        try:
            os.ftruncate(fd, 0)
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, f"pid={os.getpid()} acquired_at={time.time():.3f}\n".encode("utf-8"))
        except OSError:
            pass
        self._fd = fd
        return self

    def release(self) -> None:
        fd = self._fd
        if fd is None:
            return
        self._fd = None
        try:
            _flock_release(fd)
        finally:
            os.close(fd)

    def __enter__(self) -> RunLock:
        return self.acquire()

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.release()


def scope_signing_bytes(allowlist_hosts: Iterable[str]) -> bytes:
    """Canonical byte payload signed by Ed25519 scope signatures."""
    normalized = sorted({str(h).strip().rstrip(".").lower() for h in allowlist_hosts if str(h).strip()})
    return json.dumps(normalized, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign_scope_allowlist(allowlist_hosts: Iterable[str], private_key: Any) -> str:
    """Sign allowlist_hosts with an Ed25519PrivateKey (or PEM/raw base64) and return base64."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key_obj: Ed25519PrivateKey
    if isinstance(private_key, Ed25519PrivateKey):
        key_obj = private_key
    elif isinstance(private_key, (str, bytes)):
        raw = private_key.encode("utf-8") if isinstance(private_key, str) else private_key
        if b"BEGIN" in raw:
            loaded = serialization.load_pem_private_key(raw, password=None)
            if not isinstance(loaded, Ed25519PrivateKey):
                raise ConfigError("Private key is not Ed25519")
            key_obj = loaded
        else:
            raw_bytes = base64.b64decode(raw)
            key_obj = Ed25519PrivateKey.from_private_bytes(raw_bytes)
    else:
        raise ConfigError("Unsupported private key type for Ed25519 signing")

    sig = key_obj.sign(scope_signing_bytes(allowlist_hosts))
    return base64.b64encode(sig).decode("ascii")


def _load_ed25519_public_key(pubkey_pem_or_b64: Any):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if isinstance(pubkey_pem_or_b64, Ed25519PublicKey):
        return pubkey_pem_or_b64
    if not isinstance(pubkey_pem_or_b64, (str, bytes)):
        raise ConfigError("Public key must be PEM string, base64 string, bytes, or Ed25519PublicKey")
    raw_text = pubkey_pem_or_b64.decode("utf-8") if isinstance(pubkey_pem_or_b64, bytes) else pubkey_pem_or_b64
    stripped = raw_text.strip()
    if not stripped:
        raise ConfigError("Empty Ed25519 public key")
    if "BEGIN " in stripped:
        try:
            loaded = serialization.load_pem_public_key(stripped.encode("utf-8"))
        except Exception as exc:
            raise ConfigError(f"Invalid PEM public key: {exc}") from exc
        if not isinstance(loaded, Ed25519PublicKey):
            raise ConfigError("PEM public key is not Ed25519")
        return loaded
    try:
        key_bytes = base64.b64decode(stripped, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ConfigError(f"Invalid base64 Ed25519 public key: {exc}") from exc
    if len(key_bytes) == 32:
        return Ed25519PublicKey.from_public_bytes(key_bytes)
    try:
        loaded = serialization.load_der_public_key(key_bytes)
    except Exception as exc:
        raise ConfigError(f"Invalid Ed25519 public key bytes: {exc}") from exc
    if not isinstance(loaded, Ed25519PublicKey):
        raise ConfigError("DER public key is not Ed25519")
    return loaded


def verify_scope_signature(
    allowlist_hosts: Iterable[str],
    signature_b64: str,
    pubkey_pem_or_b64: Any,
) -> bool:
    """Verify Ed25519 signature over canonical allowlist_hosts."""
    from cryptography.exceptions import InvalidSignature

    if not signature_b64 or not isinstance(signature_b64, str):
        return False
    pub = _load_ed25519_public_key(pubkey_pem_or_b64)
    try:
        sig = base64.b64decode(signature_b64.strip(), validate=True)
    except (binascii.Error, ValueError):
        return False
    msg = scope_signing_bytes(allowlist_hosts)
    try:
        pub.verify(sig, msg)
        return True
    except InvalidSignature:
        return False
