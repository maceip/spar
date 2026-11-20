"""Stage 3 end-to-end tests for `spar demo` and `run_replay(..., apply_fix=True)` against DemoTarget."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys

from spar.integrity import audit_run_integrity
from spar.ledger import Ledger
from spar.loop import run_replay
from spar.oracles import Outcome
from spar.policy import load_frozen_policy
from spar.report import Finding
from tests.conftest import copy_demo_target_tree, file_sha256

EXPECTED_ALL_11_TECHNIQUES = frozenset(
    {
        "tool_misuse",
        "cross_tenant_access",
        "unauthorized_refund",
        "memory_poison",
        "prompt_extraction",
        "mcp_abuse",
        "indirect_injection",
        "multi_agent_chain",
        "multimodal_image_injection",
        "multilingual_bypass",
        "false_completion",
    }
)


def test_e2e_spar_demo_all_11_techniques_then_replay_apply_fix_hardens(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parent.parent
    repo_demo_app = repo_root / "spar" / "demo_target" / "app.py"
    demo_app_sha_before = file_sha256(repo_demo_app)

    spar_dir = tmp_path / ".spar"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "spar",
            "demo",
            "--trials",
            "5",
            "--spar-dir",
            str(spar_dir),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=240,
    )
    assert proc.returncode == 0, f"stdout={proc.stdout}\nstderr={proc.stderr}"
    assert "outcome reproduced (integrity=pass)" in proc.stdout
    assert "Suite failed as expected (exit 1)" in proc.stdout

    latest_id = (spar_dir / "latest").read_text(encoding="utf-8").strip()
    run_dir = spar_dir / "runs" / latest_id
    assert run_dir.is_dir()

    findings_files = sorted((run_dir / "findings").glob("*.json"))
    findings = [Finding.from_dict(json.loads(fp.read_text(encoding="utf-8"))) for fp in findings_files]
    found_techniques = {f.technique for f in findings}
    assert found_techniques == EXPECTED_ALL_11_TECHNIQUES
    for f in findings:
        assert f.k >= 1
        assert f.n == 5
        assert f.trust_tier == "machine_confirmed"
        assert f.critic_confirmed is True
        assert f.fix_status == "suggested"

    plan = json.loads((run_dir / "plan.json").read_text(encoding="utf-8"))
    report_before = (run_dir / "report.md").read_text(encoding="utf-8")
    assert "Suggested fix" in report_before
    assert "Verified fix" not in report_before

    integrity_before = audit_run_integrity(
        run_dir,
        report_before,
        findings,
        plan,
        secrets=(),
        tests_path=tmp_path / "spar_tests" / "test_attacks.py",
    )
    assert integrity_before.passed is True, f"failures={integrity_before.failures}"

    # Verify emitted test_attacks.py directly fails (exit 1) while vulnerable.
    tests_path = tmp_path / "spar_tests" / "test_attacks.py"
    assert tests_path.is_file()
    vuln_pytest_env = dict(os.environ)
    vuln_pytest_env.pop("SPAR_TARGET_URL", None)
    vuln_pytest_env["SPAR_POLICY_PATH"] = str((run_dir / "policy.json").resolve())
    vuln_pytest = subprocess.run(
        [sys.executable, "-m", "pytest", str(tests_path), "-q", "--no-header", "--tb=line"],
        cwd=tmp_path,
        env=vuln_pytest_env,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert vuln_pytest.returncode == 1, f"stdout={vuln_pytest.stdout}\nstderr={vuln_pytest.stderr}"

    # Copy demo_target into isolated tmp_path (NEVER mutate repo spar/demo_target/app.py!).
    tmp_demo_copy = copy_demo_target_tree(tmp_path)
    replay = run_replay(
        run_dir,
        apply_fix=True,
        repo=tmp_demo_copy,
        trials_override=2,
        tests_path=tests_path,
    )

    assert replay.overall_outcome == Outcome.NOT_REPRODUCED
    assert replay.pytest_status == "passed"
    assert replay.pytest_returncode == 0
    assert replay.integrity.passed is True, f"failures={replay.integrity.failures}"
    assert len(replay.results) == 11

    for r in replay.results:
        assert r["label"] == "hardened", f"finding did not harden: {r}"
        assert r["verified"] is True
        assert r["k"] == 0
        assert r["held_out_hits"] == 0
        assert r["held_out_total"] >= 2
        assert r["benign_total"] >= 1
        assert r["benign_passed"] == r["benign_total"]
        assert r["over_refusal_rate"] == 0.0

    # Reload persisted findings and report to verify suggested -> verified upgrade.
    upgraded_findings = [
        Finding.from_dict(json.loads(fp.read_text(encoding="utf-8")))
        for fp in sorted((run_dir / "findings").glob("*.json"))
    ]
    assert all(f.fix_status == "verified" and f.label == "hardened" for f in upgraded_findings)

    report_after = replay.report_path.read_text(encoding="utf-8")
    assert "Verified fix" in report_after
    assert len(Ledger(run_dir).events("fix.verified")) == 11

    # Confirm zero ephemeral tokens leaked in artifacts and repo demo_target/app.py is untouched.
    policy = load_frozen_policy(run_dir)
    assert policy.demo_mode is True
    token_leak_re = re.compile(r"\bspar-demo-[a-z0-9_-]+-[A-Za-z0-9_-]{6,}\b")
    for root_dir in (spar_dir, tmp_path / "spar_tests"):
        for fp in root_dir.rglob("*"):
            if fp.is_file():
                assert not token_leak_re.search(fp.read_bytes().decode("utf-8", errors="replace"))

    assert file_sha256(repo_demo_app) == demo_app_sha_before
