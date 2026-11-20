"""Deterministic security mutation testing harness for Spar (`spar/guard.py` & `spar/oracles.py`).

Copies `spar/` and `tests/` into an isolated temporary directory per mutant
(never modifying live repository files), applies targeted security regressions,
runs the relevant pytest suite under `PYTHONPATH=<tmp_repo>`, prints per-mutant
KILLED / SURVIVED status, and exits 0 ONLY if 100% of mutants are killed.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time


@dataclass(frozen=True)
class Mutant:
    name: str
    rel_file: str
    old: str
    new: str
    test_targets: tuple[str, ...]
    description: str


MUTANTS: tuple[Mutant, ...] = (
    Mutant(
        name="guard_allowlist_bypass",
        rel_file="spar/guard.py",
        old='        if host not in self._allowlist_hosts:\n            raise GuardViolation(f"Target host {host!r} is not in allowlist_hosts")',
        new='        if False and host not in self._allowlist_hosts:\n            raise GuardViolation(f"Target host {host!r} is not in allowlist_hosts")',
        test_targets=("tests/test_guard.py",),
        description="Disable ScopeGuard host allowlist check",
    ),
    Mutant(
        name="guard_redirect_recheck_bypass",
        rel_file="spar/guard.py",
        old="            host, port, scheme, ips = self.scope.check_url(current_url, resolver=self.resolver)",
        new=(
            "            if hop == 0:\n"
            "                host, port, scheme, ips = self.scope.check_url(current_url, resolver=self.resolver)\n"
            "            else:\n"
            "                _p = urllib.parse.urlsplit(current_url)\n"
            '                host = _normalize_host(_p.hostname or "")\n'
            "                scheme = _p.scheme.lower()\n"
            '                port = _p.port or (443 if scheme == "https" else 80)\n'
            '                ips = ["127.0.0.1"]'
        ),
        test_targets=("tests/test_guard.py::test_redirect_off_allowlist_blocked_before_connect",),
        description="Skip ScopeGuard.check_url re-validation on redirect hops",
    ),
    Mutant(
        name="guard_origin_header_strip_disabled",
        rel_file="spar/guard.py",
        old="            if prev_origin is not None and origin != prev_origin:",
        new="            if False and prev_origin is not None and origin != prev_origin:",
        test_targets=("tests/test_guard.py::test_redirect_origin_change_strips_all_sensitive_headers",),
        description="Disable credential/auth header stripping on cross-origin redirect",
    ),
    Mutant(
        name="guard_dns_private_ssrf_bypass",
        rel_file="spar/guard.py",
        old="                if disallowed and str(raw_addr) not in self._allowlist_ips:",
        new="                if False and disallowed and str(raw_addr) not in self._allowlist_ips:",
        test_targets=("tests/test_guard.py",),
        description="Disable private/link-local/loopback DNS IP rejection for non-loopback hosts",
    ),
    Mutant(
        name="guard_dns_loopback_nonloopback_bypass",
        rel_file="spar/guard.py",
        old="            if is_loopback_allowlisted:",
        new="            if False and is_loopback_allowlisted:",
        test_targets=("tests/test_guard.py",),
        description="Disable non-loopback IP rejection when resolving loopback hostnames",
    ),
    Mutant(
        name="guard_risk_tier_gate_bypass",
        rel_file="spar/guard.py",
        old='        if risk_tier == "state-changing":\n            if not self.allow_risky:',
        new='        if risk_tier == "state-changing":\n            if False and not self.allow_risky:',
        test_targets=("tests/test_guard.py::test_risk_tier_enforcement",),
        description="Bypass ScopeGuard allow_risky=False gate for state-changing actions",
    ),
    Mutant(
        name="guard_kill_switch_bypass",
        rel_file="spar/guard.py",
        old="    def check(self) -> None:\n        if self.is_triggered():",
        new="    def check(self) -> None:\n        if False and self.is_triggered():",
        test_targets=("tests/test_guard.py::test_kill_switch_stop_file_halts_immediately",),
        description="Bypass KillSwitch.check() STOP-file abort",
    ),
    Mutant(
        name="oracle_auditor_auth_status_bypass",
        rel_file="spar/oracles.py",
        old='    if resp.status in (401, 403):\n        return None, resp.log_seq, "expired_auditor_credential"',
        new="    if resp.status in (401, 403):\n        return [], resp.log_seq, None",
        test_targets=("tests/test_oracles_and_witnesses.py::test_hostile_witness_modes_yield_inconclusive_unit_and_cli",),
        description="Treat HTTP 401/403 on witness endpoint as empty events instead of error",
    ),
    Mutant(
        name="oracle_witness_down_malformed_bypass",
        rel_file="spar/oracles.py",
        old=(
            '    if resp.status >= 500 or resp.status == 0 or resp.status != 200:\n'
            '        return None, resp.log_seq, "witness_endpoint_down"\n'
            '    if not isinstance(resp.data, dict):\n'
            '        return None, resp.log_seq, "malformed_witness_response"'
        ),
        new=(
            "    if resp.status >= 500 or resp.status == 0 or resp.status != 200:\n"
            "        return [], resp.log_seq, None\n"
            "    if not isinstance(resp.data, dict):\n"
            "        return [], resp.log_seq, None"
        ),
        test_targets=("tests/test_oracles_and_witnesses.py::test_hostile_witness_modes_yield_inconclusive_unit_and_cli",),
        description="Treat 5xx/malformed witness responses as empty events instead of INCONCLUSIVE",
    ),
    Mutant(
        name="oracle_positive_control_bypass",
        rel_file="spar/oracles.py",
        old="        if not any(_contains_substring(evt, control_id) for evt in events_after):",
        new="        if False and not any(_contains_substring(evt, control_id) for evt in events_after):",
        test_targets=("tests/test_oracles_and_witnesses.py::test_hostile_witness_modes_yield_inconclusive_unit_and_cli",),
        description="Skip positive-control visibility verification in WitnessHealthChecker",
    ),
    Mutant(
        name="oracle_reset_failure_bypass",
        rel_file="spar/oracles.py",
        old='            if status != 200 or not ok:\n                return WitnessHealth(healthy=False, reasons=["failed_reset"])',
        new='            if False and (status != 200 or not ok):\n                return WitnessHealth(healthy=False, reasons=["failed_reset"])',
        test_targets=("tests/test_oracles_and_witnesses.py::test_hostile_witness_modes_yield_inconclusive_unit_and_cli",),
        description="Ignore failed target reset in WitnessHealthChecker",
    ),
    Mutant(
        name="oracle_trust_tier_gate_bypass",
        rel_file="spar/oracles.py",
        old='            if judge_hit:\n                return True, TrustTier.HEURISTIC, judge_reason or "llm_judge_only_without_oracle_match"',
        new='            if judge_hit:\n                return True, TrustTier.MACHINE_CONFIRMED, judge_reason or "llm_judge_only_without_oracle_match"',
        test_targets=("tests/test_oracles_and_witnesses.py::test_judge_without_deterministic_oracle_stays_heuristic_and_not_reported",),
        description="Allow LLM judge without deterministic oracle match to upgrade to MACHINE_CONFIRMED",
    ),
    Mutant(
        name="oracle_critic_trust_tier_gate_bypass",
        rel_file="spar/oracles.py",
        old="        if best_oracle.trust_tier in (TrustTier.UNVERIFIED, TrustTier.HEURISTIC) or not best_oracle.matched:",
        new="        if False and (best_oracle.trust_tier in (TrustTier.UNVERIFIED, TrustTier.HEURISTIC) or not best_oracle.matched):",
        test_targets=("tests/test_oracles_and_witnesses.py::test_judge_without_deterministic_oracle_stays_heuristic_and_not_reported",),
        description="Allow IndependentCritic to accept HEURISTIC/UNVERIFIED oracle verdicts",
    ),
    Mutant(
        name="oracle_hidden_control_gate_bypass",
        rel_file="spar/oracles.py",
        old="        passed = passed_count == len(shuffled)",
        new="        passed = True",
        test_targets=("tests/test_oracles_and_witnesses.py::test_broken_judge_misgrading_hidden_control_invalidates_run",),
        description="Ignore misgraded hidden judge controls in JudgeHarness",
    ),
    Mutant(
        name="oracle_false_completion_condition_inverted",
        rel_file="spar/oracles.py",
        old="        if matching_claims and not exec_delete_cancel:",
        new="        if False and matching_claims and not exec_delete_cancel:",
        test_targets=("tests/test_oracles_and_witnesses.py::test_false_completion_oracle_proves_claim_against_empty_tool_log",),
        description="Disable false_completion detection when claim has zero delete/cancel tool_log entries",
    ),
)


def _copy_isolated_repo(repo_root: Path, dest: Path) -> None:
    ignore = shutil.ignore_patterns(
        "__pycache__",
        "*.pyc",
        ".pytest_cache",
        ".spar",
        "spar_tests",
        ".git",
        ".venv",
    )
    shutil.copytree(repo_root / "spar", dest / "spar", ignore=ignore)
    shutil.copytree(repo_root / "tests", dest / "tests", ignore=ignore)
    for fname in ("pyproject.toml", "spar.yaml"):
        src = repo_root / fname
        if src.is_file():
            shutil.copy2(src, dest / fname)


def _run_mutant(repo_root: Path, mutant: Mutant) -> tuple[bool, int, float, str]:
    start = time.monotonic()
    with tempfile.TemporaryDirectory(prefix=f"spar_mut_{mutant.name}_") as tmp_dir:
        tmp_repo = Path(tmp_dir)
        _copy_isolated_repo(repo_root, tmp_repo)

        target_path = tmp_repo / mutant.rel_file
        original_text = target_path.read_text(encoding="utf-8")
        occurrences = original_text.count(mutant.old)
        if occurrences != 1:
            elapsed = time.monotonic() - start
            return (
                False,
                2,
                elapsed,
                f"mutation pattern matched {occurrences} times (expected 1) in {mutant.rel_file}",
            )

        mutated_text = original_text.replace(mutant.old, mutant.new, 1)
        target_path.write_text(mutated_text, encoding="utf-8")

        env = dict(os.environ)
        env["PYTHONPATH"] = str(tmp_repo)
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        # Sanity check: ensure `spar` imports from tmp_repo rather than the live repo.
        import_check = subprocess.run(
            [sys.executable, "-c", "import spar; print(spar.__file__)"],
            cwd=tmp_repo,
            env=env,
            capture_output=True,
            text=True,
        )
        resolved_init = import_check.stdout.strip()
        if import_check.returncode != 0 or not str(Path(resolved_init).resolve()).startswith(str(tmp_repo.resolve())):
            elapsed = time.monotonic() - start
            return (
                False,
                2,
                elapsed,
                f"PYTHONPATH isolation failed: imported {resolved_init!r} instead of {tmp_repo}",
            )

        cmd = [
            sys.executable,
            "-m",
            "pytest",
            f"--rootdir={tmp_repo}",
            "-q",
            "--tb=short",
            "-x",
            *mutant.test_targets,
        ]
        proc = subprocess.run(
            cmd,
            cwd=tmp_repo,
            env=env,
            capture_output=True,
            text=True,
            timeout=180,
        )
        elapsed = time.monotonic() - start
        killed = proc.returncode == 1
        detail = (proc.stdout + "\n" + proc.stderr).strip()
        return killed, int(proc.returncode), elapsed, detail


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    print(f"Running {len(MUTANTS)} security mutations against isolated temp copies of {repo_root}")
    killed_count = 0
    survived: list[str] = []

    for idx, mutant in enumerate(MUTANTS, start=1):
        killed, rc, elapsed, detail = _run_mutant(repo_root, mutant)
        status = "KILLED" if killed else ("SURVIVED" if rc == 0 else f"ERROR(rc={rc})")
        print(f"[{idx:02d}/{len(MUTANTS):02d}] {status:<10} {mutant.name} ({mutant.rel_file}) [{elapsed:.2f}s] - {mutant.description}")
        if killed:
            killed_count += 1
        else:
            survived.append(mutant.name)
            if detail:
                snippet = "\n    ".join(detail.splitlines()[-12:])
                print(f"    {snippet}")

    print(f"\nMutation summary: {killed_count}/{len(MUTANTS)} killed")
    if survived:
        print(f"SURVIVED/FAILED mutants: {', '.join(survived)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
