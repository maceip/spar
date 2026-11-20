"""Deterministic security plane & sole HTTP transport (`http.client` only).

Stage 1 Core Security Plane:
- `ScopeGuard`: strict http/https allowlist, hostname canonicalization, DNS
  rebinding / SSRF protection (loopback vs non-loopback rules), and risk tiers.
- `Budget`: thread-safe request pacing, request cap, wall-clock cap, USD cap.
- `KillSwitch`: STOP file and SIGINT handler.
- `UntrustedReply`: canary extraction, reverse-prompt-injection detection, and
  `.fenced()` prompt-injection isolation.
- `GuardedHTTPClient`: sole HTTP transport (`http.client` directly, zero auto-
  redirects, manual hop-by-hop redirect validation and cross-origin credential
  stripping, request-time secret injection, secret-free ledger logging, and
  isolated `llm_chat`).
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import threading
import time
from typing import Any, Callable
import urllib.parse

from .policy import (
    CampaignPolicy,
    ConfigError,
    CredentialStore,
    GuardViolation,
    LLMProviderConfig,
    SecretLeakError,
    scan_for_secrets,
)

CANARY_RE = re.compile(r"\bSPAR-[A-Za-z0-9]{4,16}\b")

_INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "instruction_override",
        re.compile(
            r"(?i)\b(?:ignore|disregard|forget|override|bypass)\b.{0,32}"
            r"\b(?:previous|prior|above|all|system|safety)\b.{0,24}"
            r"\b(?:instructions?|prompts?|rules?|policies|policy)\b"
        ),
    ),
    (
        "role_hijack",
        re.compile(
            r"(?i)\b(?:you are now|from now on you are|enter developer mode|"
            r"new system prompt|system override|act as root)\b"
        ),
    ),
    (
        "delimiter_breakout",
        re.compile(
            r"(?i)(?:<\s*/?\s*(?:system|assistant|untrusted_target_reply|target_reply|instructions?)\s*>|"
            r"<\|im_start\|>|<\|system\|>|<<\s*SYS\s*>>|\[/?INST\])"
        ),
    ),
    (
        "judge_manipulation",
        re.compile(
            r"(?i)\b(?:mark\s+(?:this|the\s+finding)\s+as\s+(?:safe|benign|false\s+positive)|"
            r"report\s+no\s+vulnerabilities|score\s+this\s+0|return\s+safe)\b"
        ),
    ),
    (
        "tool_hijack",
        re.compile(
            r"(?i)\b(?:call|invoke|execute|run)\s+(?:the\s+)?(?:shell|bash|exec|eval|curl|wget)\b"
        ),
    ),
)

_LOOPBACK_NAMES = frozenset({"localhost", "localhost.localdomain", "127.0.0.1", "::1"})
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_SENSITIVE_HEADERS = frozenset(
    {"authorization", "cookie", "proxy-authorization", "x-api-key", "x-auth-token", "x-agent-token"}
)


def _normalize_host(raw: str) -> str:
    h = raw.strip().rstrip(".").lower()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    if not h:
        return ""
    try:
        ip = ipaddress.ip_address(h)
        return str(ip)
    except ValueError:
        return h


def _parse_ip(raw: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    stripped = raw.split("%", 1)[0].strip()
    if stripped.startswith("[") and stripped.endswith("]"):
        stripped = stripped[1:-1]
    try:
        return ipaddress.ip_address(stripped)
    except ValueError:
        return None


def _unwrap_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def _extract_resolved_ips(entries: Any) -> list[str]:
    ips: list[str] = []
    seen: set[str] = set()
    for entry in entries or ():
        if isinstance(entry, str):
            ip_raw = entry
        elif isinstance(entry, (tuple, list)) and len(entry) >= 5:
            sockaddr = entry[4]
            if not isinstance(sockaddr, (tuple, list)) or not sockaddr:
                continue
            ip_raw = str(sockaddr[0])
        else:
            continue
        ip_clean = ip_raw.split("%", 1)[0].strip()
        if ip_clean and ip_clean not in seen:
            seen.add(ip_clean)
            ips.append(ip_clean)
    return ips


class ScopeGuard:
    """Enforces URL scheme, host allowlist, DNS rebinding / SSRF checks, and risk tiers."""

    def __init__(self, allowlist_hosts: list[str] | tuple[str, ...] | set[str], allow_risky: bool = False) -> None:
        self.allow_risky = bool(allow_risky)
        self._allowlist_hosts: set[str] = set()
        self._allowlist_ips: set[str] = set()
        for raw in allowlist_hosts or ():
            norm = _normalize_host(str(raw))
            if norm:
                self._allowlist_hosts.add(norm)
                ip_obj = _parse_ip(norm)
                if ip_obj is not None:
                    self._allowlist_ips.add(str(ip_obj))

    @property
    def allowlist_hosts(self) -> list[str]:
        return sorted(self._allowlist_hosts)

    def _is_loopback_host(self, host: str) -> bool:
        if host in _LOOPBACK_NAMES:
            return True
        ip_obj = _parse_ip(host)
        if ip_obj is not None:
            return _unwrap_ip(ip_obj).is_loopback
        return False

    def check_url(
        self,
        url: str,
        *,
        resolver: Callable[[str, int], Any] = socket.getaddrinfo,
    ) -> tuple[str, int, str, list[str]]:
        """Validate URL scheme, allowlisted host, and DNS resolution against SSRF/rebinding."""
        if not url or not isinstance(url, str):
            raise GuardViolation("Empty or invalid URL")
        if any(ch.isspace() or ord(ch) < 32 for ch in url):
            raise GuardViolation("URL contains control or whitespace characters")

        parsed = urllib.parse.urlsplit(url)
        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            raise GuardViolation(f"Disallowed URL scheme {scheme!r}; only http/https permitted")
        if parsed.username is not None or parsed.password is not None:
            raise GuardViolation("Userinfo credentials in URL are prohibited")

        raw_hostname = parsed.hostname or ""
        host = _normalize_host(raw_hostname)
        if not host:
            raise GuardViolation(f"URL missing valid hostname: {url!r}")

        try:
            explicit_port = parsed.port
        except ValueError as exc:
            raise GuardViolation(f"Invalid port in URL {url!r}: {exc}") from exc
        port = explicit_port if explicit_port is not None else (443 if scheme == "https" else 80)
        if not (1 <= port <= 65535):
            raise GuardViolation(f"Port out of range in URL {url!r}")

        if host not in self._allowlist_hosts:
            raise GuardViolation(f"Target host {host!r} is not in allowlist_hosts")

        try:
            raw_addrs = resolver(host, port)
        except OSError as exc:
            raise GuardViolation(f"DNS resolution failed for {host!r}: {exc}") from exc

        ips = _extract_resolved_ips(raw_addrs)
        if not ips:
            raise GuardViolation(f"DNS resolution returned no addresses for {host!r}")

        is_loopback_allowlisted = self._is_loopback_host(host)
        for ip_str in ips:
            raw_addr = _parse_ip(ip_str)
            if raw_addr is None:
                raise GuardViolation(f"Invalid resolved IP {ip_str!r} for {host!r}")
            addr = _unwrap_ip(raw_addr)
            if is_loopback_allowlisted:
                if not addr.is_loopback or (
                    isinstance(raw_addr, ipaddress.IPv6Address) and raw_addr.ipv4_mapped is not None
                ):
                    raise GuardViolation(
                        f"Loopback allowlisted host {host!r} resolved to non-loopback IP {ip_str!r}"
                    )
            else:
                disallowed = (
                    (not addr.is_global)
                    or addr.is_loopback
                    or addr.is_private
                    or addr.is_link_local
                    or addr.is_multicast
                    or addr.is_reserved
                    or addr.is_unspecified
                )
                if disallowed and str(raw_addr) not in self._allowlist_ips:
                    raise GuardViolation(
                        f"Host {host!r} resolved to disallowed IP {ip_str!r} not explicitly in allowlist_hosts"
                    )

        return host, port, scheme, ips

    def check_risk(self, technique: str, risk_tier: str) -> None:
        if risk_tier == "read-only":
            return
        if risk_tier == "state-changing":
            if not self.allow_risky:
                raise GuardViolation(
                    f"Risk tier 'state-changing' blocked for technique {technique!r}: allow_risky is False"
                )
            return
        raise GuardViolation(f"Invalid risk tier {risk_tier!r} for technique {technique!r}")


class Budget:
    """Thread-safe budget enforcer with rate pacing, request cap, duration cap, and USD cap."""

    def __init__(
        self,
        max_usd: float,
        max_requests: int,
        max_duration_s: float,
        rate_per_min: float,
    ) -> None:
        self.max_usd = float(max_usd)
        self.max_requests = int(max_requests)
        self.max_duration_s = float(max_duration_s)
        self.rate_per_min = float(rate_per_min)

        self._lock = threading.Lock()
        self._started_mono = time.monotonic()
        self._next_slot: float | None = None
        self._requests = 0
        self._llm_calls = 0
        self._usd_spent = 0.0
        self._input_tokens = 0
        self._output_tokens = 0

    def _check_caps_locked(self, now: float) -> None:
        if self.max_duration_s >= 0 and (now - self._started_mono) > self.max_duration_s:
            raise GuardViolation(
                f"Duration budget exceeded ({now - self._started_mono:.2f}s > {self.max_duration_s:.2f}s)"
            )
        if self.max_usd > 0 and self._usd_spent >= self.max_usd:
            raise GuardViolation(f"USD budget exhausted (${self._usd_spent:.4f} >= ${self.max_usd:.4f})")

    def charge_request(self) -> None:
        interval = (60.0 / self.rate_per_min) if self.rate_per_min > 0 else 0.0
        sleep_s = 0.0
        with self._lock:
            now = time.monotonic()
            self._check_caps_locked(now)
            if self.max_requests >= 0 and self._requests >= self.max_requests:
                raise GuardViolation(
                    f"Request count budget exceeded ({self._requests} >= {self.max_requests})"
                )
            if interval > 0:
                if self._next_slot is None or self._next_slot <= now:
                    self._next_slot = now + interval
                else:
                    sleep_s = self._next_slot - now
                    if self.max_duration_s >= 0 and ((now + sleep_s) - self._started_mono) > self.max_duration_s:
                        raise GuardViolation("Duration budget would be exceeded while rate pacing")
                    self._next_slot = self._next_slot + interval
            self._requests += 1
        if sleep_s > 0:
            time.sleep(sleep_s)

    def check_llm_allowed(self) -> None:
        with self._lock:
            self._check_caps_locked(time.monotonic())

    def charge_llm(
        self,
        input_tokens: int = 0,
        output_tokens: int = 0,
        *,
        usd_per_1k_input: float = 0.0,
        usd_per_1k_output: float = 0.0,
        cost_usd: float | None = None,
    ) -> float:
        in_tok = max(0, int(input_tokens))
        out_tok = max(0, int(output_tokens))
        if cost_usd is None:
            cost = (in_tok / 1000.0) * float(usd_per_1k_input) + (out_tok / 1000.0) * float(
                usd_per_1k_output
            )
        else:
            cost = max(0.0, float(cost_usd))

        with self._lock:
            now = time.monotonic()
            if self.max_duration_s >= 0 and (now - self._started_mono) > self.max_duration_s:
                raise GuardViolation("Duration budget exceeded")
            if self.max_usd >= 0 and (self._usd_spent + cost) > self.max_usd + 1e-12:
                raise GuardViolation(
                    f"USD budget exceeded (${self._usd_spent + cost:.6f} > ${self.max_usd:.6f})"
                )
            self._usd_spent += cost
            self._llm_calls += 1
            self._input_tokens += in_tok
            self._output_tokens += out_tok
        return cost

    def summary(self) -> dict[str, Any]:
        with self._lock:
            return {
                "usd_spent": round(self._usd_spent, 6),
                "max_usd": self.max_usd,
                "requests": self._requests,
                "max_requests": self.max_requests,
                "llm_calls": self._llm_calls,
                "input_tokens": self._input_tokens,
                "output_tokens": self._output_tokens,
                "elapsed_s": round(time.monotonic() - self._started_mono, 3),
                "max_duration_s": self.max_duration_s,
                "rate_per_min": self.rate_per_min,
            }


class KillSwitch:
    """Emergency stop via STOP file on disk or SIGINT signal."""

    def __init__(self, stop_file: Path | str | None = None, *, install_sigint: bool = True) -> None:
        self.stop_file = Path(stop_file) if stop_file is not None else None
        self._triggered = threading.Event()
        self._reason = ""
        self._prev_sigint: Any = None
        self._installed = False
        if install_sigint and threading.current_thread() is threading.main_thread():
            self._prev_sigint = signal.getsignal(signal.SIGINT)
            signal.signal(signal.SIGINT, self._handle_sigint)
            self._installed = True

    def _handle_sigint(self, signum: int, frame: Any) -> None:
        self._reason = "SIGINT received"
        self._triggered.set()
        raise KeyboardInterrupt("Spar kill switch activated by SIGINT")

    def trigger(self, reason: str = "manual kill switch") -> None:
        self._reason = reason
        self._triggered.set()

    def is_triggered(self) -> bool:
        if self._triggered.is_set():
            return True
        if self.stop_file is not None and self.stop_file.exists():
            self._reason = f"STOP file present at {self.stop_file}"
            self._triggered.set()
            return True
        return False

    def check(self) -> None:
        if self.is_triggered():
            raise GuardViolation(f"Kill switch active: {self._reason or 'stopped'}")

    def restore(self) -> None:
        if self._installed and threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGINT, self._prev_sigint)
            self._installed = False


def inspect_untrusted_text(text: str) -> tuple[list[str], list[str]]:
    """Extract canary tokens and reverse-prompt-injection flags from untrusted text."""
    if not text:
        return [], []
    seen_c: set[str] = set()
    canaries: list[str] = []
    for match in CANARY_RE.findall(text):
        if match not in seen_c:
            seen_c.add(match)
            canaries.append(match)
    flags = [name for name, pat in _INJECTION_PATTERNS if pat.search(text)]
    return canaries, flags


@dataclass
class UntrustedReply:
    text: str
    status: int
    headers: dict[str, str] | None = None
    canaries: list[str] | None = None
    injection_flags: list[str] | None = None
    ledger_seq: int | None = None
    body_sha256: str = ""

    def __post_init__(self) -> None:
        self.headers = dict(self.headers) if self.headers is not None else {}
        if self.canaries is None or self.injection_flags is None:
            detected_c, detected_f = inspect_untrusted_text(self.text)
            if self.canaries is None:
                self.canaries = detected_c
            if self.injection_flags is None:
                self.injection_flags = detected_f
        if not self.body_sha256:
            self.body_sha256 = hashlib.sha256(self.text.encode("utf-8")).hexdigest()

    def fenced(self, label: str = "target_reply") -> str:
        """Wrap untrusted target text in a non-escapable data fence before LLM inspection."""
        safe_label = re.sub(r"[^A-Za-z0-9_-]", "_", label) or "target_reply"
        tag = f"untrusted_{safe_label}"
        safe_text = (
            self.text.replace("</untrusted_", "<\\/untrusted_")
            .replace("<|im_start|>", "<\\|im_start\\|>")
            .replace("<|system|>", "<\\|system\\|>")
            .replace("```", "`\u200b``")
        )
        flags_attr = (
            f' injection_flags="{",".join(self.injection_flags)}"'
            if self.injection_flags
            else ""
        )
        return (
            f'<{tag} status="{self.status}"{flags_attr} trust="UNTRUSTED_DATA_ONLY">\n'
            f"{safe_text}\n"
            f"</{tag}>"
        )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection that connects strictly to validated IPs while keeping SNI host."""

    def __init__(self, host: str, port: int, connect_ips: list[str], timeout: float) -> None:
        super().__init__(host, port=port, timeout=timeout)
        self._connect_ips = list(connect_ips)

    def connect(self) -> None:
        last_err: OSError | None = None
        for ip in self._connect_ips:
            try:
                sock = socket.create_connection((ip, self.port), self.timeout, self.source_address)
                if self._tunnel_host:
                    self.sock = sock
                    self._tunnel()
                self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
                return
            except OSError as exc:
                last_err = exc
        if last_err is not None:
            raise last_err
        raise OSError("No validated IP addresses available to connect")


def _get_header_ci(headers: dict[str, str], name: str) -> str | None:
    target = name.lower()
    for k, v in headers.items():
        if k.lower() == target:
            return v
    return None


def _set_header_ci(headers: dict[str, str], name: str, value: str) -> None:
    target = name.lower()
    for existing in [k for k in headers if k.lower() == target]:
        del headers[existing]
    headers[name] = value


def _delete_header_ci(headers: dict[str, str], name: str) -> None:
    target = name.lower()
    for existing in [k for k in headers if k.lower() == target]:
        del headers[existing]


def _format_host_header(host: str, port: int, scheme: str) -> str:
    formatted = f"[{host}]" if ":" in host else host
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        return formatted
    return f"{formatted}:{port}"


class GuardedHTTPClient:
    """Sole HTTP transport in Spar. Uses http.client directly with strict guard hooks."""

    def __init__(
        self,
        policy: CampaignPolicy,
        cred_store: CredentialStore,
        ledger: Any,
        budget: Budget,
        kill: KillSwitch,
        *,
        resolver: Callable[[str, int], Any] = socket.getaddrinfo,
    ) -> None:
        self.policy = policy
        self.cred_store = cred_store
        self.ledger = ledger
        self.budget = budget
        self.kill = kill
        self.resolver = resolver
        self.scope = ScopeGuard(policy.allowlist_hosts, allow_risky=policy.allow_risky)

        auth_cfg = (policy.target_contract.auth if policy.target_contract else None) or {}
        self._auth_header = str(auth_cfg.get("header", "Authorization") or "Authorization")
        self._auth_prefix = str(auth_cfg.get("prefix", "Bearer ") if auth_cfg.get("prefix") is not None else "Bearer ")

    def _redact_headers_for_log(self, headers: dict[str, str], secrets: list[str]) -> dict[str, str]:
        sensitive_names = set(_SENSITIVE_HEADERS)
        sensitive_names.add(self._auth_header.lower())
        sensitive_names.add("set-cookie")
        redacted: dict[str, str] = {}
        for k, v in headers.items():
            kl = k.lower()
            if kl in sensitive_names:
                redacted[k] = "[REDACTED]"
                continue
            try:
                scan_for_secrets(v, secrets)
                redacted[k] = v
            except SecretLeakError:
                redacted[k] = "[REDACTED]"
        return redacted

    def _send_once(
        self,
        *,
        scheme: str,
        host: str,
        port: int,
        ips: list[str],
        method: str,
        req_path: str,
        body_bytes: bytes | None,
        headers: dict[str, str],
        timeout: float,
    ) -> tuple[int, dict[str, str], bytes]:
        if scheme == "https":
            conn: http.client.HTTPConnection = _PinnedHTTPSConnection(host, port, ips, timeout)
            try:
                conn.request(method, req_path, body=body_bytes, headers=headers)
                resp = conn.getresponse()
                raw = resp.read()
                resp_headers = {k: v for k, v in resp.getheaders()}
                return int(resp.status), resp_headers, raw
            finally:
                conn.close()

        last_err: OSError | None = None
        for ip in ips:
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)
            try:
                conn.request(method, req_path, body=body_bytes, headers=headers)
                resp = conn.getresponse()
            except OSError as exc:
                last_err = exc
                conn.close()
                continue
            try:
                raw = resp.read()
                resp_headers = {k: v for k, v in resp.getheaders()}
                return int(resp.status), resp_headers, raw
            finally:
                conn.close()
        if last_err is not None:
            raise last_err
        raise OSError(f"Failed to connect to {host}:{port}")

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        json_body: Any = None,
        account: str | None = None,
        technique: str = "",
        risk_tier: str = "read-only",
        timeout: float = 15.0,
        max_redirects: int = 5,
    ) -> UntrustedReply:
        self.kill.check()
        self.scope.check_risk(technique, risk_tier)

        current_url = url
        current_method = method.upper()
        current_headers = dict(headers or {})
        current_account = account
        current_body: bytes | None = None
        if json_body is not None:
            current_body = json.dumps(json_body, ensure_ascii=False).encode("utf-8")
            if _get_header_ci(current_headers, "Content-Type") is None:
                _set_header_ci(current_headers, "Content-Type", "application/json")

        prev_origin: tuple[str, str, int] | None = None

        for hop in range(max_redirects + 1):
            self.kill.check()
            host, port, scheme, ips = self.scope.check_url(current_url, resolver=self.resolver)
            origin = (scheme, host, port)

            if prev_origin is not None and origin != prev_origin:
                for hdr_name in _SENSITIVE_HEADERS | {self._auth_header.lower()}:
                    _delete_header_ci(current_headers, hdr_name)
                current_account = None

            self.budget.charge_request()

            secrets = self.cred_store.secret_values()
            if self.ledger is not None and hasattr(self.ledger, "add_secrets"):
                self.ledger.add_secrets(secrets)

            wire_headers = dict(current_headers)
            if _get_header_ci(wire_headers, "Host") is None:
                _set_header_ci(wire_headers, "Host", _format_host_header(host, port, scheme))

            if current_account is not None:
                token = self.cred_store.get_token(current_account)
                if token and token not in secrets:
                    secrets.append(token)
                    if self.ledger is not None and hasattr(self.ledger, "add_secrets"):
                        self.ledger.add_secrets([token])
                _set_header_ci(wire_headers, self._auth_header, f"{self._auth_prefix}{token}")

            parsed = urllib.parse.urlsplit(current_url)
            req_path = parsed.path or "/"
            if parsed.query:
                req_path = f"{req_path}?{parsed.query}"

            if self.ledger is not None:
                req_payload: dict[str, Any] = {
                    "method": current_method,
                    "url": current_url,
                    "host": host,
                    "port": port,
                    "hop": hop,
                    "account": current_account,
                    "technique": technique,
                    "risk_tier": risk_tier,
                    "headers": self._redact_headers_for_log(wire_headers, secrets),
                }
                if current_body is not None:
                    req_payload["body_sha256"] = hashlib.sha256(current_body).hexdigest()
                self.ledger.append("http.request", req_payload, task_id=technique or None)

            status, resp_headers, raw_bytes = self._send_once(
                scheme=scheme,
                host=host,
                port=port,
                ips=ips,
                method=current_method,
                req_path=req_path,
                body_bytes=current_body,
                headers=wire_headers,
                timeout=timeout,
            )

            location = _get_header_ci(resp_headers, "Location")
            if status in _REDIRECT_STATUSES and location is not None:
                if hop >= max_redirects:
                    raise GuardViolation(
                        f"Exceeded max_redirects={max_redirects} starting from {url!r}"
                    )
                next_url = urllib.parse.urljoin(current_url, location.strip())
                if status == 303 or (status in (301, 302) and current_method == "POST"):
                    current_method = "GET"
                    current_body = None
                    _delete_header_ci(current_headers, "Content-Length")
                    _delete_header_ci(current_headers, "Content-Type")
                prev_origin = origin
                current_url = next_url
                continue

            body_sha256 = hashlib.sha256(raw_bytes).hexdigest()
            text = raw_bytes.decode("utf-8", errors="replace")
            canaries, injection_flags = inspect_untrusted_text(text)

            ledger_seq: int | None = None
            if self.ledger is not None:
                safe_text = text
                secret_redacted = False
                try:
                    scan_for_secrets(text, secrets)
                except SecretLeakError:
                    safe_text = "[REDACTED:SECRET_DETECTED]"
                    secret_redacted = True

                resp_payload: dict[str, Any] = {
                    "method": current_method,
                    "url": current_url,
                    "status": status,
                    "body_sha256": body_sha256,
                    "text": safe_text,
                    "secret_redacted": secret_redacted,
                    "headers": self._redact_headers_for_log(resp_headers, secrets),
                    "canaries": canaries,
                    "injection_flags": injection_flags,
                    "technique": technique,
                    "risk_tier": risk_tier,
                }
                evt = self.ledger.append("http.response", resp_payload, task_id=technique or None)
                ledger_seq = int(evt["seq"])

            return UntrustedReply(
                text=text,
                status=status,
                headers=resp_headers,
                canaries=canaries,
                injection_flags=injection_flags,
                ledger_seq=ledger_seq,
                body_sha256=body_sha256,
            )

        raise GuardViolation(f"Exceeded max_redirects={max_redirects} starting from {url!r}")

    def json_request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        json_body: Any = None,
        account: str | None = None,
        technique: str = "",
        risk_tier: str = "read-only",
        timeout: float = 15.0,
        max_redirects: int = 5,
    ) -> tuple[int, Any, UntrustedReply]:
        reply = self.request(
            method,
            url,
            headers=headers,
            json_body=json_body,
            account=account,
            technique=technique,
            risk_tier=risk_tier,
            timeout=timeout,
            max_redirects=max_redirects,
        )
        if not reply.text:
            return reply.status, "", reply
        try:
            parsed = json.loads(reply.text)
        except json.JSONDecodeError:
            parsed = reply.text
        return reply.status, parsed, reply

    def llm_chat(
        self,
        messages: list[dict[str, Any]],
        *,
        provider: LLMProviderConfig,
        max_tokens: int = 1024,
        temperature: float = 0.0,
        timeout: float = 60.0,
    ) -> tuple[str, dict[str, Any]]:
        """Call OpenAI-compatible LLM endpoint via http.client without sending target secrets."""
        self.kill.check()
        self.budget.check_llm_allowed()

        base_url = (provider.base_url or "").strip()
        if not base_url:
            raise ConfigError("LLM provider base_url is not configured")
        model = (provider.model or "").strip()
        if not model:
            raise ConfigError("LLM provider model is not configured")

        api_key = ""
        api_key_env = (provider.api_key_env or "").strip()
        if api_key_env:
            api_key = os.environ.get(api_key_env, "")
            if not api_key:
                raise ConfigError(f"Missing LLM API key environment variable: {api_key_env!r}")
            if self.ledger is not None and hasattr(self.ledger, "add_secrets"):
                self.ledger.add_secrets([api_key])

        base = base_url.rstrip("/")
        endpoint = base if base.endswith("/chat/completions") else f"{base}/chat/completions"
        parsed = urllib.parse.urlsplit(endpoint)
        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            raise GuardViolation(f"Disallowed LLM provider URL scheme: {scheme!r}")
        host = _normalize_host(parsed.hostname or "")
        if not host:
            raise ConfigError(f"Invalid LLM provider base_url: {base_url!r}")
        try:
            explicit_port = parsed.port
        except ValueError as exc:
            raise ConfigError(f"Invalid port in LLM base_url {base_url!r}: {exc}") from exc
        port = explicit_port if explicit_port is not None else (443 if scheme == "https" else 80)

        try:
            raw_addrs = self.resolver(host, port)
        except OSError as exc:
            raise GuardViolation(f"DNS resolution failed for LLM host {host!r}: {exc}") from exc
        ips = _extract_resolved_ips(raw_addrs)
        if not ips:
            raise GuardViolation(f"DNS resolution returned no addresses for LLM host {host!r}")

        is_local = host in _LOOPBACK_NAMES or (
            (_parse_ip(host) is not None) and _unwrap_ip(_parse_ip(host)).is_loopback  # type: ignore[arg-type]
        )
        for ip_str in ips:
            raw_addr = _parse_ip(ip_str)
            if raw_addr is None:
                raise GuardViolation(f"Invalid resolved IP {ip_str!r} for LLM host {host!r}")
            addr = _unwrap_ip(raw_addr)
            if addr.is_link_local or addr.is_multicast or addr.is_unspecified:
                raise GuardViolation(f"LLM host {host!r} resolved to disallowed IP {ip_str!r}")
            if is_local and not addr.is_loopback:
                raise GuardViolation(f"Loopback LLM host {host!r} resolved to non-loopback IP {ip_str!r}")

        req_path = parsed.path or "/chat/completions"
        if parsed.query:
            req_path = f"{req_path}?{parsed.query}"

        req_body = json.dumps(
            {
                "model": model,
                "messages": list(messages),
                "max_tokens": int(max_tokens),
                "temperature": float(temperature),
            },
            ensure_ascii=False,
        ).encode("utf-8")

        wire_headers = {
            "Host": _format_host_header(host, port, scheme),
            "Content-Type": "application/json",
        }
        if api_key:
            wire_headers["Authorization"] = f"Bearer {api_key}"

        status, _, raw_bytes = self._send_once(
            scheme=scheme,
            host=host,
            port=port,
            ips=ips,
            method="POST",
            req_path=req_path,
            body_bytes=req_body,
            headers=wire_headers,
            timeout=timeout,
        )
        raw_text = raw_bytes.decode("utf-8", errors="replace")
        if status >= 400:
            preview = raw_text[:400]
            try:
                scan_for_secrets(preview, [api_key] if api_key else ())
            except SecretLeakError:
                preview = "[REDACTED:SECRET_DETECTED]"
            raise RuntimeError(f"LLM provider returned HTTP {status}: {preview}")

        try:
            data = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"LLM provider returned invalid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise RuntimeError("LLM provider JSON response must be an object")

        choices = data.get("choices") or []
        content = ""
        if isinstance(choices, list) and choices:
            msg = choices[0].get("message") if isinstance(choices[0], dict) else None
            if isinstance(msg, dict) and msg.get("content") is not None:
                content = str(msg["content"])

        usage = data.get("usage") if isinstance(data.get("usage"), dict) else {}
        prompt_tokens = int(usage.get("prompt_tokens", 0) or 0)
        completion_tokens = int(usage.get("completion_tokens", 0) or 0)

        cost_usd = self.budget.charge_llm(
            prompt_tokens,
            completion_tokens,
            usd_per_1k_input=provider.usd_per_1k_input,
            usd_per_1k_output=provider.usd_per_1k_output,
        )

        if self.ledger is not None:
            self.ledger.append(
                "llm.call",
                {
                    "model": model,
                    "base_url": base_url,
                    "prompt_tokens": prompt_tokens,
                    "completion_tokens": completion_tokens,
                    "cost_usd": cost_usd,
                    "usage": usage,
                },
            )

        meta = dict(data)
        meta["usage"] = usage
        meta["cost_usd"] = cost_usd
        meta["prompt_tokens"] = prompt_tokens
        meta["completion_tokens"] = completion_tokens
        return content, meta


__all__ = [
    "Budget",
    "CANARY_RE",
    "GuardViolation",
    "GuardedHTTPClient",
    "KillSwitch",
    "ScopeGuard",
    "SecretLeakError",
    "UntrustedReply",
    "inspect_untrusted_text",
]
