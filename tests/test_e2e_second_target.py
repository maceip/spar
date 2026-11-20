"""Stage 3 end-to-end tests against TicketBot (`tests/fixtures/second_target`) in white-box and black-box modes."""

from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import subprocess
import sys

from spar.integrity import audit_run_integrity
from spar.ledger import Ledger
from spar.policy import scan_for_secrets
from spar.report import Finding
from tests.fixtures.second_target.app import run_server as run_ticketbot_server


def _scan_tree_for_secrets(root: Path, secret_values: list[str]) -> None:
    for fp in root.rglob("*"):
        if fp.is_file():
            content = fp.read_bytes().decode("utf-8", errors="replace")
            scan_for_secrets(content, secret_values)


def test_e2e_second_target_whitebox_and_blackbox(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parent.parent
    second_dir = repo_root / "tests" / "fixtures" / "second_target"
    config_path = second_dir / "spar_second.yaml"

    tokens = {
        "maya": f"tb-maya-secret-{secrets.token_urlsafe(12)}",
        "liam": f"tb-liam-secret-{secrets.token_urlsafe(12)}",
        "secops": f"tb-secops-secret-{secrets.token_urlsafe(12)}",
    }
    secret_list = list(tokens.values())

    srv, _thread, port, _target = run_ticketbot_server(host="127.0.0.1", port=0, seed=42, tokens=tokens)
    base_url = f"http://127.0.0.1:{port}"
    try:
        env = dict(os.environ)
        env["SPAR_SECOND_TOKEN_MAYA"] = tokens["maya"]
        env["SPAR_SECOND_TOKEN_LIAM"] = tokens["liam"]
        env["SPAR_SECOND_TOKEN_SECOPS"] = tokens["secops"]

        # 1. White-box mode (--repo tests/fixtures/second_target)
        wb_cwd = tmp_path / "wb"
        wb_cwd.mkdir()
        wb_spar_dir = wb_cwd / ".spar"
        wb_proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "spar",
                "run",
                "--target",
                base_url,
                "--repo",
                str(second_dir),
                "--config",
                str(config_path),
                "--trials",
                "2",
                "--allow-risky",
                "--spar-dir",
                str(wb_spar_dir),
            ],
            cwd=wb_cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=180,
        )
        assert wb_proc.returncode == 1, f"stdout={wb_proc.stdout}\nstderr={wb_proc.stderr}"
        assert "outcome reproduced (integrity=pass)" in wb_proc.stdout

        wb_run_id = (wb_spar_dir / "latest").read_text(encoding="utf-8").strip()
        wb_run_dir = wb_spar_dir / "runs" / wb_run_id
        wb_findings = [
            Finding.from_dict(json.loads(fp.read_text(encoding="utf-8")))
            for fp in sorted((wb_run_dir / "findings").glob("*.json"))
        ]
        wb_techs = {f.technique for f in wb_findings}
        assert {"cross_tenant_access", "tool_misuse", "memory_poison", "prompt_extraction", "false_completion"} <= wb_techs
        assert all(f.trust_tier == "machine_confirmed" and f.critic_confirmed for f in wb_findings)

        wb_plan = json.loads((wb_run_dir / "plan.json").read_text(encoding="utf-8"))
        assert wb_plan["snapshot_id"]["system_prompt_sha256"]
        wb_integrity = audit_run_integrity(
            wb_run_dir,
            (wb_run_dir / "report.md").read_text(encoding="utf-8"),
            wb_findings,
            wb_plan,
            secrets=secret_list,
            tests_path=wb_cwd / "spar_tests" / "test_attacks.py",
        )
        assert wb_integrity.passed is True, f"failures={wb_integrity.failures}"
        assert Ledger(wb_run_dir).verify_chain() is True
        _scan_tree_for_secrets(wb_spar_dir, secret_list)
        _scan_tree_for_secrets(wb_cwd / "spar_tests", secret_list)

        # Emitted test_attacks.py reproduces findings against live TicketBot (exit 1).
        wb_test_env = dict(env)
        wb_test_env["SPAR_POLICY_PATH"] = str((wb_run_dir / "policy.json").resolve())
        wb_test_env["SPAR_TARGET_URL"] = base_url
        wb_pytest = subprocess.run(
            [sys.executable, "-m", "pytest", str(wb_cwd / "spar_tests" / "test_attacks.py"), "-q", "--tb=line"],
            cwd=wb_cwd,
            env=wb_test_env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert wb_pytest.returncode == 1, f"stdout={wb_pytest.stdout}\nstderr={wb_pytest.stderr}"

        # 2. Black-box mode (no --repo)
        bb_cwd = tmp_path / "bb"
        bb_cwd.mkdir()
        bb_spar_dir = bb_cwd / ".spar"
        bb_proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "spar",
                "run",
                "--target",
                base_url,
                "--config",
                str(config_path),
                "--trials",
                "2",
                "--allow-risky",
                "--spar-dir",
                str(bb_spar_dir),
            ],
            cwd=bb_cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=180,
        )
        assert bb_proc.returncode == 1, f"stdout={bb_proc.stdout}\nstderr={bb_proc.stderr}"
        assert "outcome reproduced (integrity=pass)" in bb_proc.stdout

        bb_run_id = (bb_spar_dir / "latest").read_text(encoding="utf-8").strip()
        bb_run_dir = bb_spar_dir / "runs" / bb_run_id
        bb_findings = [
            Finding.from_dict(json.loads(fp.read_text(encoding="utf-8")))
            for fp in sorted((bb_run_dir / "findings").glob("*.json"))
        ]
        bb_techs = {f.technique for f in bb_findings}
        assert {"cross_tenant_access", "tool_misuse", "memory_poison", "false_completion"} <= bb_techs
        # Without repo prompt SHA-256 ground truth, prompt_extraction must NOT be falsely confirmed.
        assert "prompt_extraction" not in bb_techs

        bb_plan = json.loads((bb_run_dir / "plan.json").read_text(encoding="utf-8"))
        assert not bb_plan["snapshot_id"]["system_prompt_sha256"]
        bb_integrity = audit_run_integrity(
            bb_run_dir,
            (bb_run_dir / "report.md").read_text(encoding="utf-8"),
            bb_findings,
            bb_plan,
            secrets=secret_list,
            tests_path=bb_cwd / "spar_tests" / "test_attacks.py",
        )
        assert bb_integrity.passed is True, f"failures={bb_integrity.failures}"
        assert Ledger(bb_run_dir).verify_chain() is True
        _scan_tree_for_secrets(bb_spar_dir, secret_list)
        _scan_tree_for_secrets(bb_cwd / "spar_tests", secret_list)
    finally:
        srv.shutdown()
        srv.server_close()
