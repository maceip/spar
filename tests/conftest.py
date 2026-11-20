"""Shared pytest configuration and test fixtures for Spar Stage 3 test suite."""

from __future__ import annotations

from collections.abc import Iterator
import hashlib
from pathlib import Path
import shutil
import secrets
from typing import Any

import pytest

from spar.demo_target import generate_ephemeral_tokens, run_server
from spar.policy import AccountRef, CampaignPolicy, CredentialStore, TargetContractConfig
from tests.fixtures.hostile_targets import RedirectHostileServers, start_redirect_hostile_servers


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    """Fail the entire pytest session if any test was skipped (zero-skip CI policy)."""
    reporter = session.config.pluginmanager.get_plugin("terminalreporter")
    if reporter is not None:
        skipped = reporter.stats.get("skipped", [])
        if skipped:
            session.exitstatus = 1


@pytest.fixture
def demo_server() -> Iterator[tuple[str, dict[str, str], Any, Any]]:
    """Start an isolated localhost DemoTarget server with ephemeral tokens and always clean up."""
    tokens = generate_ephemeral_tokens()
    srv, _thread, port, target = run_server(port=0, tokens=tokens)
    base_url = f"http://127.0.0.1:{port}"
    try:
        yield base_url, tokens, srv, target
    finally:
        srv.shutdown()
        srv.server_close()


@pytest.fixture
def redirect_servers() -> Iterator[RedirectHostileServers]:
    """Start hostile redirect servers and ensure socket/thread teardown."""
    srvs = start_redirect_hostile_servers()
    try:
        yield srvs
    finally:
        srvs.shutdown()


def make_demo_policy_and_creds(
    base_url: str,
    tokens: dict[str, str],
    *,
    allow_risky: bool = True,
    trials_n: int = 1,
    min_distinct_techniques: int = 3,
    env_prefix: str = "SPAR_TEST_TOKEN",
) -> tuple[CampaignPolicy, CredentialStore]:
    """Build an ephemeral CampaignPolicy + CredentialStore for a DemoTarget-compatible server."""
    token_envs = {
        "alice": f"{env_prefix}_ALICE_{secrets.token_hex(4)}",
        "bob": f"{env_prefix}_BOB_{secrets.token_hex(4)}",
        "auditor": f"{env_prefix}_AUDITOR_{secrets.token_hex(4)}",
    }
    overrides = {token_envs[name]: tok for name, tok in tokens.items()}
    accounts = [
        AccountRef(
            name=name,
            role="auditor" if name == "auditor" else "user",
            token_env=env_name,
            token_fingerprint=CredentialStore.fingerprint(tokens[name]),
        )
        for name, env_name in token_envs.items()
    ]
    policy = CampaignPolicy(
        target_url=base_url,
        allowlist_hosts=["127.0.0.1", "localhost"],
        allow_risky=allow_risky,
        accounts=accounts,
        trials_n=trials_n,
        min_distinct_techniques=min_distinct_techniques,
        target_contract=TargetContractConfig(),
        demo_mode=False,
    )
    cred_store = CredentialStore(accounts, overrides=overrides)
    return policy, cred_store


def copy_demo_target_tree(dest_dir: Path) -> Path:
    """Copy spar/demo_target to an isolated temporary directory without touching the repo."""
    src = Path(__file__).resolve().parent.parent / "spar" / "demo_target"
    dst = dest_dir / "demo_target"
    shutil.copytree(src, dst)
    return dst


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
