"""Scope enforcement: only allowlisted hosts may be touched, ever."""

from __future__ import annotations

from urllib.parse import urlparse


class GuardViolation(Exception):
    """Raised by deterministic hooks when a tool call violates scope,
    budget, rate, or risk-tier policy. The call is blocked before execution."""


class ScopeGuard:
    def __init__(self, allowlist_hosts: list[str], allow_risky: bool = False):
        self.allowlist = {h.lower() for h in allowlist_hosts}
        self.allow_risky = allow_risky

    def check_url(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https", "ws", "wss"):
            raise GuardViolation(f"scheme not allowed: {parsed.scheme!r} in {url!r}")
        host = (parsed.hostname or "").lower()
        if not host:
            raise GuardViolation(f"no host in url: {url!r}")
        if host not in self.allowlist:
            raise GuardViolation(
                f"host {host!r} is not in spar.yaml scope.allowlist_hosts {sorted(self.allowlist)}"
            )

    def check_risk(self, technique: str, risk_tier: str, sandboxed: bool) -> None:
        """Read-only recon and non-destructive probes run unattended.
        State-changing actions require sandboxed test doubles, an explicit
        --allow-risky policy in spar.yaml, or operator approval."""
        if risk_tier == "read-only":
            return
        if risk_tier == "state-changing":
            if sandboxed or self.allow_risky:
                return
            raise GuardViolation(
                f"technique {technique!r} is state-changing and neither sandboxed "
                "nor permitted by scope.allow_risky in spar.yaml"
            )
        raise GuardViolation(f"unknown risk tier: {risk_tier!r}")
