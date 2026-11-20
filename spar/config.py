"""spar.yaml loading.

Zero required dependencies: a minimal YAML-subset parser handles the flat
mappings, lists, and scalars Spar config files use. If PyYAML is installed
it is preferred (full YAML support).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class ConfigError(Exception):
    pass


def _coerce_scalar(text: str) -> Any:
    t = text.strip()
    if t == "":
        return ""
    if (t.startswith('"') and t.endswith('"')) or (t.startswith("'") and t.endswith("'")):
        return t[1:-1]
    low = t.lower()
    if low in ("true", "yes"):
        return True
    if low in ("false", "no"):
        return False
    if low in ("null", "none", "~"):
        return None
    try:
        return int(t)
    except ValueError:
        pass
    try:
        return float(t)
    except ValueError:
        pass
    return t


def _strip_comment(line: str) -> str:
    out = []
    in_q = None
    for ch in line:
        if in_q:
            out.append(ch)
            if ch == in_q:
                in_q = None
            continue
        if ch in ('"', "'"):
            in_q = ch
            out.append(ch)
            continue
        if ch == "#":
            break
        out.append(ch)
    return "".join(out)


def parse_yaml_subset(text: str) -> dict:
    """Parse the YAML subset used by spar.yaml: nested mappings via
    indentation, '- ' lists, inline scalars. No anchors, no flow style
    beyond plain scalars, no multi-line strings."""
    root: dict = {}
    # stack of (indent, container). Container is dict or list.
    stack: list[tuple[int, Any]] = [(-1, root)]

    def container_at(indent: int) -> Any:
        while len(stack) > 1 and stack[-1][0] >= indent:
            stack.pop()
        return stack[-1][1]

    lines = text.splitlines()
    i = 0
    while i < len(lines):
        raw = lines[i]
        i += 1
        line = _strip_comment(raw)
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        body = line.strip()
        cont = container_at(indent)
        if body.startswith("- "):
            item_text = body[2:].strip()
            if not isinstance(cont, list):
                raise ConfigError(f"list item at unexpected position: {raw!r}")
            if ":" in item_text and not item_text.startswith(('"', "'")):
                # list of mappings: '- key: value' then deeper keys follow
                key, _, val = item_text.partition(":")
                item: dict = {key.strip(): _coerce_scalar(val)}
                cont.append(item)
                stack.append((indent + 2, item))
                # subsequent more-indented lines belong to this item; the
                # pseudo-indent keeps them attached even when written at
                # indent+2 exactly.
                stack.append((indent, item))
            else:
                cont.append(_coerce_scalar(item_text))
            continue
        if body == "-":
            raise ConfigError(f"bare '-' not supported: {raw!r}")
        if ":" not in body:
            raise ConfigError(f"cannot parse line: {raw!r}")
        key, _, val = body.partition(":")
        key = key.strip()
        val = val.strip()
        if not isinstance(cont, dict):
            raise ConfigError(f"mapping key at unexpected position: {raw!r}")
        if val == "":
            # look ahead: list or nested mapping?
            j = i
            while j < len(lines):
                nxt = _strip_comment(lines[j])
                if nxt.strip():
                    break
                j += 1
            if j < len(lines):
                nline = lines[j]
                nindent = len(nline) - len(nline.lstrip(" "))
                nbody = nline.strip()
                if nindent > indent and nbody.startswith("- "):
                    lst: list = []
                    cont[key] = lst
                    stack.append((indent, lst))
                    continue
                if nindent > indent:
                    sub: dict = {}
                    cont[key] = sub
                    stack.append((indent, sub))
                    continue
            cont[key] = None
            continue
        cont[key] = _coerce_scalar(val)
    return root


def load_yaml(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore

        return yaml.safe_load(text) or {}
    except ImportError:
        return parse_yaml_subset(text)


@dataclass
class Account:
    name: str
    token: str
    role: str = "user"


@dataclass
class LLMConfig:
    base_url: str = ""
    api_key_env: str = "SPAR_LLM_API_KEY"
    model: str = ""
    usd_per_1k_input: float = 0.0
    usd_per_1k_output: float = 0.0

    @property
    def enabled(self) -> bool:
        return bool(self.base_url and self.model and os.environ.get(self.api_key_env))

    @property
    def api_key(self) -> str:
        return os.environ.get(self.api_key_env, "")


@dataclass
class SparConfig:
    base_url: str = "http://127.0.0.1:8765"
    allowlist_hosts: list[str] = field(default_factory=lambda: ["127.0.0.1", "localhost"])
    allow_risky: bool = False
    accounts: list[Account] = field(default_factory=list)
    max_usd: float = 10.0
    max_requests: int = 5000
    max_duration_s: int = 1800
    rate_per_min: int = 600
    trials_n: int = 20
    llm: LLMConfig = field(default_factory=LLMConfig)
    source_path: str | None = None

    def account(self, name: str) -> Account:
        for a in self.accounts:
            if a.name == name:
                return a
        raise ConfigError(f"account {name!r} not found in spar.yaml")

    @classmethod
    def from_file(cls, path: Path) -> "SparConfig":
        data = load_yaml(path)
        cfg = cls(source_path=str(path))
        tgt = data.get("target") or {}
        if tgt.get("base_url"):
            cfg.base_url = str(tgt["base_url"])
        scope = data.get("scope") or {}
        hosts = scope.get("allowlist_hosts") or []
        cfg.allowlist_hosts = [str(h) for h in hosts] or ["127.0.0.1", "localhost"]
        cfg.allow_risky = bool(scope.get("allow_risky", False))
        for acct in data.get("accounts") or []:
            cfg.accounts.append(
                Account(name=str(acct["name"]), token=str(acct["token"]), role=str(acct.get("role", "user")))
            )
        budget = data.get("budget") or {}
        cfg.max_usd = float(budget.get("max_usd", cfg.max_usd))
        cfg.max_requests = int(budget.get("max_requests", cfg.max_requests))
        cfg.max_duration_s = int(budget.get("max_duration_s", cfg.max_duration_s))
        cfg.rate_per_min = int(budget.get("rate_per_min", cfg.rate_per_min))
        trials = data.get("trials") or {}
        cfg.trials_n = int(trials.get("n", cfg.trials_n))
        llm = data.get("llm") or {}
        cfg.llm = LLMConfig(
            base_url=str(llm.get("base_url") or ""),
            api_key_env=str(llm.get("api_key_env") or "SPAR_LLM_API_KEY"),
            model=str(llm.get("model") or ""),
            usd_per_1k_input=float(llm.get("usd_per_1k_input") or 0.0),
            usd_per_1k_output=float(llm.get("usd_per_1k_output") or 0.0),
        )
        return cfg

    @classmethod
    def default_demo(cls, base_url: str) -> "SparConfig":
        """Safe defaults for `spar demo`: localhost scope, synthetic accounts."""
        cfg = cls(base_url=base_url, allow_risky=True, trials_n=20)
        cfg.accounts = [
            Account("alice", "token-alice", "user"),
            Account("bob", "token-bob", "user"),
            Account("auditor", "token-auditor", "auditor"),
        ]
        return cfg

    def to_yaml_dict(self) -> dict:
        return {
            "target": {"base_url": self.base_url},
            "scope": {"allowlist_hosts": self.allowlist_hosts, "allow_risky": self.allow_risky},
            "accounts": [{"name": a.name, "token": a.token, "role": a.role} for a in self.accounts],
            "budget": {
                "max_usd": self.max_usd,
                "max_requests": self.max_requests,
                "max_duration_s": self.max_duration_s,
                "rate_per_min": self.rate_per_min,
            },
            "trials": {"n": self.trials_n},
        }

    def dump_yaml(self, path: Path) -> None:
        """Emit subset-YAML text round-trippable by parse_yaml_subset."""

        def emit(obj: Any, indent: int) -> list[str]:
            pad = " " * indent
            out: list[str] = []
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(v, (dict, list)) and v:
                        out.append(f"{pad}{k}:")
                        out.extend(emit(v, indent + 2))
                    elif isinstance(v, list):
                        out.append(f"{pad}{k}: []")
                    else:
                        out.append(f"{pad}{k}: {json.dumps(v) if isinstance(v, str) else v}")
            elif isinstance(obj, list):
                for item in obj:
                    if isinstance(item, dict):
                        first = True
                        for k, v in item.items():
                            prefix = f"{pad}- " if first else f"{pad}  "
                            first = False
                            out.append(f"{prefix}{k}: {json.dumps(v) if isinstance(v, str) else v}")
                    else:
                        out.append(f"{pad}- {json.dumps(item) if isinstance(item, str) else item}")
            return out

        path.write_text("\n".join(emit(self.to_yaml_dict(), 0)) + "\n", encoding="utf-8")
