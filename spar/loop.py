"""Stage 2 Campaign & Replay Loop: orchestrates Core Guard, Aiming, PyRIT Attacks, Oracles, Critic, Fix Verification, Reporting, and Integrity."""

from __future__ import annotations

from dataclasses import dataclass, field
import http.client
import json
import os
from pathlib import Path
import re
import secrets as py_secrets
import subprocess
import sys
import time
from typing import Any
import uuid

from . import __version__
from .aim import build_plan, index_repo, run_recon, write_plan
from .attacks.benign import run_benign_suite
from .attacks.held_out import run_held_out
from .attacks.pyrit_adapter import distinct_technique_count
from .attacks.recipes import MissionResult, run_mission
from .fix import (
    apply_fix as apply_fix_patches,
    synthesize_fix,
    verify_fix,
)
from .guard import (
    Budget,
    GuardedHTTPClient,
    GuardViolation,
    KillSwitch,
    ScopeGuard,
)
from .integrity import (
    IntegrityReport,
    audit_run_integrity,
    export_human_review_sample,
)
from .ledger import Ledger
from .oracles import (
    IndependentCritic,
    JudgeHarness,
    OracleVerdict,
    Outcome,
    TrustTier,
    WitnessHealth,
    WitnessHealthChecker,
    evaluate_oracle,
)
from .policy import (
    CampaignPolicy,
    ConfigError,
    CredentialStore,
    RunLock,
    freeze_policy,
    load_frozen_policy,
    safe_mkdir,
    safe_write_text,
    verify_scope_signature,
)
from .report import (
    Finding,
    calibrate_severity,
    dedupe_findings,
    emit_pytest_suite,
    emit_report,
    wilson_interval,
)
from .sarif_export import write_findings_sarif
from .target import TargetClient


@dataclass
class RunSummary:
    run_id: str
    run_dir: Path
    findings: list[Finding]
    rejected: list[dict[str, Any]]
    objective_outcomes: list[dict[str, Any]]
    plan: dict[str, Any]
    recon: dict[str, Any]
    budget: dict[str, Any]
    report_path: Path
    tests_path: Path | None
    human_review_path: Path | None
    integrity: IntegrityReport
    overall_outcome: Outcome
    started_at: float
    finished_at: float
    halt_reason: str | None = None
    sarif_path: Path | None = None


@dataclass
class ReplaySummary:
    run_dir: Path
    overall_outcome: Outcome
    results: list[dict[str, Any]]
    pytest_status: str
    pytest_returncode: int | None
    integrity: IntegrityReport
    report_path: Path


def _classify_pytest_result(returncode: int, stderr: str, stdout: str) -> str:
    """Classify a pytest subprocess outcome into passed / reproduced / inconclusive."""
    combined = f"{stderr or ''}\n{stdout or ''}".lower()
    if "no module named pytest" in combined or "command not found" in combined:
        return "inconclusive"
    if returncode == 0:
        return "passed"
    if returncode == 1:
        return "reproduced"
    return "inconclusive"


def _collect_all_secrets(policy: CampaignPolicy, cred_store: CredentialStore) -> list[str]:
    secrets = list(cred_store.secret_values())
    for cfg in (policy.llm, policy.critic_llm):
        if cfg and cfg.api_key_env:
            val = os.environ.get(cfg.api_key_env, "")
            if val and val not in secrets:
                secrets.append(val)
    return secrets


def _flatten_tags(raw_tags: Any) -> list[str]:
    if isinstance(raw_tags, list):
        return [str(x) for x in raw_tags]
    if not isinstance(raw_tags, dict):
        return []
    label_map = {
        "owasp_llm": "OWASP LLM",
        "owasp_agentic": "OWASP Agentic",
        "mitre_atlas": "MITRE ATLAS",
        "nist_ai_rmf": "NIST AI RMF",
    }
    out: list[str] = []
    for key, prefix in label_map.items():
        vals = raw_tags.get(key)
        if isinstance(vals, list):
            for v in vals:
                out.append(f"{prefix}: {v}")
    for key, vals in raw_tags.items():
        if key not in label_map and isinstance(vals, list):
            for v in vals:
                out.append(f"{key}: {v}")
    return out


def _pick_auditor(obj: dict[str, Any], policy: CampaignPolicy) -> str | None:
    accts = obj.get("accounts") if isinstance(obj.get("accounts"), dict) else {}
    if accts.get("auditor"):
        return str(accts["auditor"])
    return next((a.name for a in policy.accounts if a.role == "auditor"), None)


def _filter_verified_quotes(quotes: list[dict[str, Any]], ledger: Ledger) -> list[dict[str, Any]]:
    verified: list[dict[str, Any]] = []
    for q in quotes or []:
        if not isinstance(q, dict):
            continue
        q_text = str(q.get("text") or "")
        if not q_text:
            continue
        ok, seq = ledger.has_quote_hash(q_text)
        if not ok:
            continue
        q_copy = dict(q)
        if q_copy.get("log_seq") is None and seq is not None:
            q_copy["log_seq"] = seq
        verified.append(q_copy)
    return verified


def _is_chained_finding(technique: str, evidence: dict[str, Any]) -> bool:
    if technique in ("indirect_injection", "multi_agent_chain"):
        return True
    if technique in ("multimodal_image_injection", "multilingual_bypass"):
        if evidence.get("tool_name") == "send_email" and (
            evidence.get("victim_sentinel") or evidence.get("attacker_addr") or evidence.get("recipient")
        ):
            return True
    return False


def run_campaign(
    policy: CampaignPolicy,
    cred_store: CredentialStore,
    *,
    spar_root: Path = Path(".spar"),
    repo: Path | None = None,
    tests_dir: Path = Path("spar_tests"),
    judge_fn=None,
    critic_fn=None,
) -> RunSummary:
    """Execute an end-to-end Spar campaign under deterministic security guards and integrity auditing."""
    started_at = time.time()
    if not policy.run_id:
        policy.run_id = f"run-{uuid.uuid4().hex[:12]}"

    # Validate scope & optional scope signature up front before writing run artifacts.
    ScopeGuard(policy.allowlist_hosts, allow_risky=policy.allow_risky).check_url(policy.target_url)
    if policy.scope_signature:
        pubkey = os.environ.get(policy.scope_public_key_env, "")
        if not pubkey or not verify_scope_signature(policy.allowlist_hosts, policy.scope_signature, pubkey):
            raise GuardViolation("Scope signature verification failed")

    root_path = safe_mkdir(Path(spar_root), mode=0o700)
    runs_dir = safe_mkdir(root_path / "runs", mode=0o700)
    run_dir = safe_mkdir(runs_dir / policy.run_id, mode=0o700)
    findings_dir = safe_mkdir(run_dir / "findings", mode=0o700)

    secrets_list = _collect_all_secrets(policy, cred_store)
    repo_path = Path(repo).resolve() if repo is not None else None

    with RunLock(run_dir):
        freeze_policy(policy, run_dir, secrets_list)
        ledger = Ledger(run_dir, secrets_list)
        budget = Budget(
            policy.budget.max_usd,
            policy.budget.max_requests,
            policy.budget.max_duration_s,
            policy.budget.rate_per_min,
        )
        kill = KillSwitch(run_dir / "STOP")
        try:
            http = GuardedHTTPClient(policy, cred_store, ledger, budget, kill)
            target_client = TargetClient(http, policy.target_contract, policy.target_url, policy.accounts)

            ledger.append(
                "campaign.started",
                {
                    "run_id": policy.run_id,
                    "target_url": policy.target_url,
                    "allow_risky": bool(policy.allow_risky),
                    "trials_n": int(policy.trials_n),
                    "demo_mode": bool(policy.demo_mode),
                },
                task_id="campaign",
            )

            judge = JudgeHarness(http, policy, ledger, judge_fn=judge_fn)
            ctrl_report = judge.evaluate_run_controls()

            halt_reason: str | None = None
            findings: list[Finding] = []
            rejected: list[dict[str, Any]] = []
            objective_outcomes: list[dict[str, Any]] = []

            if not ctrl_report.passed:
                halt_reason = "judge_controls_failed"
                try:
                    repo_index = index_repo(repo_path) if repo_path is not None else None
                    recon = run_recon(target_client, ledger, repo=repo_path, repo_index=repo_index, llm_cfg=policy.llm)
                    plan = build_plan(recon, repo_index, policy, target_client, ledger)
                except Exception:
                    recon = {"tools": [], "mcp_tools": [], "retrieval_sources": [], "routes": [], "dropped_ungrounded_count": 0}
                    plan = {
                        "run_id": policy.run_id,
                        "target_url": policy.target_url,
                        "trials_n": int(policy.trials_n),
                        "min_distinct_techniques": int(policy.min_distinct_techniques),
                        "snapshot_id": {"commit": None, "commit_status": "unverified", "system_prompt_sha256": ""},
                        "surfaces": {"claims": [], "dropped_ungrounded_count": 0, "tools": [], "mcp_tools": [], "routes": [], "state_endpoints": []},
                        "objectives": [],
                    }
                write_plan(plan, run_dir, secrets=secrets_list)
                overall_outcome = Outcome.INCONCLUSIVE
            else:
                health = WitnessHealthChecker().check(
                    target_client, policy, require_reset=bool(policy.allow_risky)
                )
                ledger.append(
                    "witness.health",
                    {
                        "healthy": health.healthy,
                        "reasons": list(health.reasons),
                        "control_id": health.control_id,
                        "log_seq": health.log_seq,
                    },
                    task_id="preflight",
                )

                repo_index = index_repo(repo_path) if repo_path is not None else None
                recon = run_recon(target_client, ledger, repo=repo_path, repo_index=repo_index, llm_cfg=policy.llm)
                plan = build_plan(recon, repo_index, policy, target_client, ledger)
                write_plan(plan, run_dir, secrets=secrets_list)

                critic = IndependentCritic(target_client, policy, ledger, kill, critic_fn=critic_fn)
                objectives = list(plan.get("objectives") or [])

                for obj in objectives:
                    obj_id = str(obj.get("id") or "")
                    tech = str(obj.get("technique") or "")
                    planned_trials = max(1, int(obj.get("trials") or policy.trials_n))

                    try:
                        kill.check()
                    except GuardViolation as exc:
                        halt_reason = str(exc)
                        break

                    if not health.healthy:
                        reason_txt = "; ".join(health.reasons) or "witness_unhealthy"
                        ledger.append(
                            "objective.completed",
                            {
                                "objective_id": obj_id,
                                "technique": tech,
                                "outcome": Outcome.INCONCLUSIVE.value,
                                "k": 0,
                                "n": 0,
                                "completed_trials": 0,
                                "planned_trials": planned_trials,
                                "reason": reason_txt,
                            },
                            origin_id=obj_id,
                            task_id=tech,
                        )
                        objective_outcomes.append(
                            {
                                "objective_id": obj_id,
                                "technique": tech,
                                "outcome": Outcome.INCONCLUSIVE.value,
                                "k": 0,
                                "n": 0,
                                "completed_trials": 0,
                                "planned_trials": planned_trials,
                                "reason": reason_txt,
                            }
                        )
                        rejected.append(
                            {
                                "objective_id": obj_id,
                                "technique": tech,
                                "outcome": Outcome.INCONCLUSIVE.value,
                                "candidate_hits": 0,
                                "reason": reason_txt,
                                "quotes": [],
                            }
                        )
                        continue

                    if obj.get("risk_tier") == "state-changing" and not policy.allow_risky:
                        ledger.append(
                            "objective.skipped_policy",
                            {
                                "objective_id": obj_id,
                                "technique": tech,
                                "risk_tier": obj.get("risk_tier"),
                                "reason": "blocked_by_policy",
                                "outcome": Outcome.INCONCLUSIVE.value,
                            },
                            origin_id=obj_id,
                            task_id=tech,
                        )
                        objective_outcomes.append(
                            {
                                "objective_id": obj_id,
                                "technique": tech,
                                "outcome": Outcome.INCONCLUSIVE.value,
                                "k": 0,
                                "n": 0,
                                "completed_trials": 0,
                                "planned_trials": planned_trials,
                                "reason": "blocked_by_policy",
                            }
                        )
                        rejected.append(
                            {
                                "objective_id": obj_id,
                                "technique": tech,
                                "outcome": Outcome.INCONCLUSIVE.value,
                                "candidate_hits": 0,
                                "reason": "blocked_by_policy",
                                "quotes": [],
                            }
                        )
                        continue

                    k = 0
                    completed_trials = 0
                    candidate_hits = 0
                    trial_outcomes: list[OracleVerdict] = []
                    all_distinct_prompts: list[str] = []
                    all_quotes: list[dict[str, Any]] = []
                    best_result: MissionResult | None = None
                    best_oracle: OracleVerdict | None = None
                    reset_failed_reason: str | None = None
                    auditor_acct = _pick_auditor(obj, policy)

                    for trial_idx in range(planned_trials):
                        try:
                            kill.check()
                            if policy.allow_risky and auditor_acct and (policy.target_contract.reset or {}).get("path"):
                                ok, r_status, _ = target_client.reset(auditor_acct)
                                if not ok or r_status != 200:
                                    reset_failed_reason = f"failed_reset:status={r_status}"
                                    break
                            trial_since = time.time() - 0.05
                            mres = run_mission(obj, target_client, policy, trial_idx, ledger, kill)
                            all_distinct_prompts.extend(mres.distinct_prompts or [])
                            all_quotes.extend(mres.quotes or [])
                            verdict = evaluate_oracle(
                                obj,
                                mres,
                                target_client,
                                policy,
                                trial_since,
                                witness_health=health,
                            )
                            scored_hit, scored_tier, scored_reason = judge.score_candidate(obj, mres, verdict)
                        except GuardViolation as exc:
                            msg_low = str(exc).lower()
                            if kill.is_triggered() or "budget" in msg_low or "duration" in msg_low or "rate" in msg_low:
                                halt_reason = str(exc)
                                break
                            reset_failed_reason = str(exc)
                            break
                        except (ConfigError, OSError, http.client.HTTPException, TimeoutError) as exc:
                            reset_failed_reason = str(exc)
                            break

                        completed_trials += 1
                        trial_outcomes.append(verdict)

                        if verdict.outcome == Outcome.INCONCLUSIVE:
                            if best_result is None:
                                best_result = mres
                                best_oracle = verdict
                            continue

                        if (
                            verdict.matched
                            and verdict.trust_tier == TrustTier.MACHINE_CONFIRMED
                            and scored_hit
                            and scored_tier == TrustTier.MACHINE_CONFIRMED
                        ):
                            k += 1
                            candidate_hits += 1
                            if best_result is None or best_oracle is None or best_oracle.trust_tier != TrustTier.MACHINE_CONFIRMED:
                                best_result = mres
                                best_oracle = verdict
                        elif scored_hit or mres.candidate_hit:
                            candidate_hits += 1
                            if best_result is None:
                                best_result = mres
                                best_oracle = OracleVerdict(
                                    outcome=verdict.outcome,
                                    matched=False,
                                    oracle=verdict.oracle,
                                    witness=scored_reason or verdict.witness,
                                    trust_tier=TrustTier.HEURISTIC if scored_tier == TrustTier.HEURISTIC else TrustTier.UNVERIFIED,
                                    details=dict(verdict.details or {}),
                                )

                    if halt_reason is not None and completed_trials == 0:
                        ledger.append(
                            "objective.completed",
                            {
                                "objective_id": obj_id,
                                "technique": tech,
                                "outcome": Outcome.INCONCLUSIVE.value,
                                "k": 0,
                                "n": 0,
                                "completed_trials": 0,
                                "planned_trials": planned_trials,
                                "reason": halt_reason,
                            },
                            origin_id=obj_id,
                            task_id=tech,
                        )
                        objective_outcomes.append(
                            {
                                "objective_id": obj_id,
                                "technique": tech,
                                "outcome": Outcome.INCONCLUSIVE.value,
                                "k": 0,
                                "n": 0,
                                "completed_trials": 0,
                                "planned_trials": planned_trials,
                                "reason": halt_reason,
                            }
                        )
                        break

                    if reset_failed_reason is not None:
                        ledger.append(
                            "objective.completed",
                            {
                                "objective_id": obj_id,
                                "technique": tech,
                                "outcome": Outcome.INCONCLUSIVE.value,
                                "k": k,
                                "n": completed_trials,
                                "completed_trials": completed_trials,
                                "planned_trials": planned_trials,
                                "reason": reset_failed_reason,
                            },
                            origin_id=obj_id,
                            task_id=tech,
                        )
                        objective_outcomes.append(
                            {
                                "objective_id": obj_id,
                                "technique": tech,
                                "outcome": Outcome.INCONCLUSIVE.value,
                                "k": k,
                                "n": completed_trials,
                                "completed_trials": completed_trials,
                                "planned_trials": planned_trials,
                                "reason": reset_failed_reason,
                            }
                        )
                        rejected.append(
                            {
                                "objective_id": obj_id,
                                "technique": tech,
                                "outcome": Outcome.INCONCLUSIVE.value,
                                "candidate_hits": candidate_hits,
                                "reason": reset_failed_reason,
                                "quotes": _filter_verified_quotes(all_quotes, ledger)[:3],
                            }
                        )
                        continue

                    distinct_count = distinct_technique_count(all_distinct_prompts)
                    try:
                        critic_verdict = critic.judge(
                            obj,
                            trial_outcomes,
                            best_result,
                            best_oracle,
                            distinct_count,
                        )
                    except GuardViolation as exc:
                        halt_reason = str(exc)
                        ledger.append(
                            "objective.completed",
                            {
                                "objective_id": obj_id,
                                "technique": tech,
                                "outcome": Outcome.INCONCLUSIVE.value,
                                "k": k,
                                "n": completed_trials,
                                "completed_trials": completed_trials,
                                "planned_trials": planned_trials,
                                "reason": halt_reason,
                            },
                            origin_id=obj_id,
                            task_id=tech,
                        )
                        objective_outcomes.append(
                            {
                                "objective_id": obj_id,
                                "technique": tech,
                                "outcome": Outcome.INCONCLUSIVE.value,
                                "k": k,
                                "n": completed_trials,
                                "completed_trials": completed_trials,
                                "planned_trials": planned_trials,
                                "reason": halt_reason,
                            }
                        )
                        break

                    if (
                        critic_verdict.confirmed is True
                        and best_result is not None
                        and best_oracle is not None
                        and best_oracle.trust_tier == TrustTier.MACHINE_CONFIRMED
                    ):
                        n_done = max(1, completed_trials)
                        ci_low, ci_high = wilson_interval(k, n_done)
                        ev = dict(best_result.evidence or {})
                        chained = _is_chained_finding(tech, ev)
                        sev = calibrate_severity(tech, k / float(n_done), chained)
                        flat_tags = _flatten_tags(obj.get("tags"))

                        fix_prop = synthesize_fix(tech, repo_path, llm_cfg=policy.llm, http_client=http)
                        fix_dict = {
                            "kind": fix_prop.kind,
                            "status": fix_prop.status,
                            "prompt_diff": fix_prop.prompt_diff,
                            "guardrail_rule": fix_prop.guardrail_rule,
                            "code_diff": fix_prop.code_diff,
                            "patch_pairs": [[str(p), old, new] for p, old, new in fix_prop.patch_pairs],
                            "guidance": fix_prop.guidance,
                        }

                        verified_quotes = _filter_verified_quotes(best_result.quotes or all_quotes, ledger)
                        witness_str = str(critic_verdict.replay_witness or best_oracle.witness or "")
                        fid = f"find-{len(findings) + 1:02d}-{tech}"

                        finding = Finding(
                            id=fid,
                            objective=str(obj.get("objective") or ""),
                            objective_id=obj_id,
                            technique=tech,
                            severity=sev,
                            k=k,
                            n=n_done,
                            completed_trials=completed_trials,
                            planned_trials=planned_trials,
                            wilson_ci_low=ci_low,
                            wilson_ci_high=ci_high,
                            outcome=Outcome.REPRODUCED.value,
                            trust_tier=best_oracle.trust_tier.value,
                            witness=witness_str,
                            oracle=best_oracle.oracle,
                            tags=flat_tags,
                            critic_reason=critic_verdict.reason,
                            critic_confirmed=True,
                            critic_cited_seqs=list(critic_verdict.cited_seqs),
                            evidence=ev,
                            quotes=verified_quotes,
                            steps=list(best_result.steps or []),
                            chain=[tech] + ([str(ev.get("tool_name"))] if ev.get("tool_name") else []),
                            chain_links=[],
                            fix_proposal=fix_dict,
                            fix_status="suggested",
                            label="new",
                            reattack=None,
                            duplicates=0,
                        )
                        findings.append(finding)

                        ledger.append(
                            "finding.confirmed",
                            {
                                "finding_id": fid,
                                "objective_id": obj_id,
                                "technique": tech,
                                "severity": sev,
                                "k": k,
                                "n": n_done,
                                "completed_trials": completed_trials,
                                "planned_trials": planned_trials,
                                "wilson_ci_low": ci_low,
                                "wilson_ci_high": ci_high,
                                "witness": witness_str,
                                "oracle": best_oracle.oracle,
                                "tags": flat_tags,
                            },
                            origin_id=obj_id,
                            task_id=tech,
                        )
                        ledger.append(
                            "objective.completed",
                            {
                                "objective_id": obj_id,
                                "technique": tech,
                                "outcome": Outcome.REPRODUCED.value,
                                "k": k,
                                "n": n_done,
                                "completed_trials": completed_trials,
                                "planned_trials": planned_trials,
                                "distinct_techniques": distinct_count,
                            },
                            origin_id=obj_id,
                            task_id=tech,
                        )
                        objective_outcomes.append(
                            {
                                "objective_id": obj_id,
                                "technique": tech,
                                "outcome": Outcome.REPRODUCED.value,
                                "k": k,
                                "n": n_done,
                                "completed_trials": completed_trials,
                                "planned_trials": planned_trials,
                                "distinct_techniques": distinct_count,
                            }
                        )
                    else:
                        out_val = critic_verdict.outcome.value
                        ledger.append(
                            "objective.completed",
                            {
                                "objective_id": obj_id,
                                "technique": tech,
                                "outcome": out_val,
                                "k": 0,
                                "n": completed_trials,
                                "completed_trials": completed_trials,
                                "planned_trials": planned_trials,
                                "distinct_techniques": distinct_count,
                                "reason": critic_verdict.reason,
                            },
                            origin_id=obj_id,
                            task_id=tech,
                        )
                        objective_outcomes.append(
                            {
                                "objective_id": obj_id,
                                "technique": tech,
                                "outcome": out_val,
                                "k": 0,
                                "n": completed_trials,
                                "completed_trials": completed_trials,
                                "planned_trials": planned_trials,
                                "distinct_techniques": distinct_count,
                                "reason": critic_verdict.reason,
                            }
                        )
                        rejected.append(
                            {
                                "objective_id": obj_id,
                                "technique": tech,
                                "outcome": out_val,
                                "candidate_hits": candidate_hits,
                                "reason": critic_verdict.reason,
                                "quotes": _filter_verified_quotes(all_quotes, ledger)[:3],
                            }
                        )

                    if halt_reason is not None:
                        break

                findings = dedupe_findings(findings)
                obj_by_id = {str(o.get("id") or ""): o for o in objectives}
                for f in findings:
                    payload = f.to_dict()
                    src_obj = obj_by_id.get(f.objective_id, {})
                    if isinstance(src_obj.get("accounts"), dict):
                        payload["accounts"] = dict(src_obj["accounts"])
                    if isinstance(src_obj.get("params"), dict):
                        payload["params"] = dict(src_obj["params"])
                    payload["risk_tier"] = src_obj.get("risk_tier", "read-only")
                    safe_write_text(
                        findings_dir / f"{f.id}.json",
                        json.dumps(payload, indent=2, default=str) + "\n",
                        secrets=secrets_list,
                    )

                if halt_reason is not None and not findings:
                    overall_outcome = Outcome.INCONCLUSIVE
                elif findings:
                    overall_outcome = Outcome.REPRODUCED
                elif (not health.healthy) or any(
                    oo.get("outcome") == Outcome.INCONCLUSIVE.value for oo in objective_outcomes
                ):
                    overall_outcome = Outcome.INCONCLUSIVE
                else:
                    overall_outcome = Outcome.NOT_REPRODUCED

            budget_summary = budget.summary()
            ledger.append(
                "campaign.completed",
                {
                    "overall_outcome": overall_outcome.value,
                    "findings_count": len(findings),
                    "rejected_count": len(rejected),
                    "budget": budget_summary,
                    "halt_reason": halt_reason,
                },
                task_id="campaign",
            )

            tests_path: Path | None = None
            if findings:
                tests_path = emit_pytest_suite(
                    findings,
                    Path(tests_dir),
                    run_dir / "policy.json",
                    secrets=secrets_list,
                    demo_mode=policy.demo_mode,
                )

            report_path = emit_report(
                findings,
                rejected,
                objective_outcomes,
                plan,
                recon,
                budget_summary,
                run_dir,
                repo_path,
                policy.target_url,
                ledger,
                secrets=secrets_list,
                halt=halt_reason,
            )

            sarif_path: Path | None = None
            if findings:
                try:
                    sarif_path, sarif_count, sarif_skipped = write_findings_sarif(
                        findings,
                        plan,
                        run_dir,
                        repo_path,
                        tool_version=__version__,
                        secrets=secrets_list,
                    )
                    ledger.append(
                        "sarif.written",
                        {"path": str(sarif_path), "results": int(sarif_count), "skipped": list(sarif_skipped)},
                        task_id="campaign",
                    )
                except Exception as exc:  # SARIF export must never fail a run.
                    ledger.append("sarif.error", {"error": str(exc)[:200]}, task_id="campaign")

            human_review_path = export_human_review_sample(
                run_dir,
                ledger,
                findings,
                rejected,
                secrets=secrets_list,
            )

            campaign_state = {
                "repo": str(repo_path) if repo_path else None,
                "recon": recon,
                "objective_outcomes": objective_outcomes,
                "rejected": rejected,
                "budget": budget_summary,
                "halt_reason": halt_reason,
            }
            safe_write_text(
                run_dir / "campaign_state.json",
                json.dumps(campaign_state, indent=2, default=str) + "\n",
                secrets=secrets_list,
            )

            report_text = report_path.read_text(encoding="utf-8")
            integrity = audit_run_integrity(
                run_dir,
                report_text,
                findings,
                plan,
                secrets_list,
                tests_path=tests_path,
            )
            if not integrity.passed:
                overall_outcome = Outcome.INCONCLUSIVE

            safe_write_text(root_path / "latest", f"{policy.run_id}\n", secrets=secrets_list)
            finished_at = time.time()

            return RunSummary(
                run_id=policy.run_id,
                run_dir=run_dir,
                findings=findings,
                rejected=rejected,
                objective_outcomes=objective_outcomes,
                plan=plan,
                recon=recon,
                budget=budget_summary,
                report_path=report_path,
                tests_path=tests_path,
                human_review_path=human_review_path,
                integrity=integrity,
                overall_outcome=overall_outcome,
                started_at=started_at,
                finished_at=finished_at,
                halt_reason=halt_reason,
                sarif_path=sarif_path,
            )
        finally:
            kill.restore()


def _load_campaign_state(run_dir: Path, ledger: Ledger, plan: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], Path | None]:
    state_path = run_dir / "campaign_state.json"
    if state_path.is_file():
        try:
            data = json.loads(state_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                repo_str = data.get("repo")
                return (
                    dict(data.get("recon") or {}),
                    list(data.get("objective_outcomes") or []),
                    list(data.get("rejected") or []),
                    Path(repo_str) if repo_str else None,
                )
        except (OSError, json.JSONDecodeError):
            pass

    objective_outcomes: list[dict[str, Any]] = []
    for evt in ledger.events("objective.completed"):
        pl = evt.get("payload")
        if isinstance(pl, dict):
            objective_outcomes.append(dict(pl))
    for evt in ledger.events("objective.skipped_policy"):
        pl = evt.get("payload")
        if isinstance(pl, dict):
            objective_outcomes.append(
                {
                    "objective_id": pl.get("objective_id", ""),
                    "technique": pl.get("technique", ""),
                    "outcome": pl.get("outcome", Outcome.INCONCLUSIVE.value),
                    "k": 0,
                    "n": 0,
                    "completed_trials": 0,
                    "planned_trials": 0,
                    "reason": pl.get("reason", "blocked_by_policy"),
                }
            )
    recon_summary = {
        "tools": (plan.get("surfaces") or {}).get("tools") or [],
        "mcp_tools": (plan.get("surfaces") or {}).get("mcp_tools") or [],
        "routes": (plan.get("surfaces") or {}).get("routes") or [],
        "retrieval_sources": [],
        "dropped_ungrounded_count": (plan.get("surfaces") or {}).get("dropped_ungrounded_count", 0),
    }
    return recon_summary, objective_outcomes, [], None


def _resolve_demo_app_path(repo: Path | None) -> Path | None:
    if repo is None:
        return None
    rp = Path(repo)
    if rp.is_file() and rp.suffix == ".py":
        return rp.resolve()
    for candidate in (
        rp / "app.py",
        rp / "demo_target" / "app.py",
        rp / "spar" / "demo_target" / "app.py",
    ):
        if candidate.is_file():
            return candidate.resolve()
    return None


def _start_demo_subprocess(
    policy: CampaignPolicy,
    cred_store: CredentialStore,
    *,
    repo: Path | None = None,
) -> tuple[subprocess.Popen[str], str]:
    sub_env = dict(os.environ)
    for acct in policy.accounts:
        if acct.token_env:
            sub_env[acct.token_env] = cred_store.get_token(acct.name)

    app_py = _resolve_demo_app_path(repo)
    if app_py is not None:
        loader_code = (
            "import importlib.util, sys; "
            "spec = importlib.util.spec_from_file_location('spar_demo_target_exec', sys.argv[1]); "
            "mod = importlib.util.module_from_spec(spec); "
            "sys.modules['spar_demo_target_exec'] = mod; "
            "spec.loader.exec_module(mod); "
            "sys.argv = [sys.argv[1], '--port', '0']; "
            "mod.main()"
        )
        cmd = [sys.executable, "-c", loader_code, str(app_py)]
        cwd = str(app_py.parent)
    else:
        repo_root = Path(__file__).resolve().parent.parent
        cmd = [sys.executable, "-m", "spar.demo_target", "--port", "0"]
        cwd = str(repo_root)

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=sub_env,
        cwd=cwd,
    )
    if proc.stdout is None:
        proc.terminate()
        raise ConfigError("Failed to attach stdout pipe to demo_target subprocess")

    line = proc.stdout.readline()
    m = re.search(r"http://([^:\s]+):(\d+)", line or "")
    if not m:
        err = proc.stderr.read() if proc.stderr is not None else ""
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
        raise ConfigError(f"Failed to start demo_target subprocess (line={line!r}, err={err!r})")

    url = f"http://{m.group(1)}:{m.group(2)}"
    return proc, url


def _run_pytest_suite(
    tests_path: Path,
    run_dir: Path,
    target_url: str,
    policy: CampaignPolicy,
    cred_store: CredentialStore,
    *,
    finding_id: str | None = None,
) -> tuple[str, int | None]:
    env = dict(os.environ)
    env["SPAR_POLICY_PATH"] = str((run_dir / "policy.json").resolve())
    env["SPAR_TARGET_URL"] = target_url
    for acct in policy.accounts:
        if acct.token_env:
            try:
                env[acct.token_env] = cred_store.get_token(acct.name)
            except ConfigError:
                pass

    cmd = [sys.executable, "-m", "pytest", str(tests_path), "-q", "--no-header", "--tb=line"]
    if finding_id:
        safe_k = re.sub(r"[^A-Za-z0-9_]", "_", finding_id).strip("_")
        if safe_k:
            cmd.extend(["-k", safe_k])

    try:
        proc = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=180,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return "inconclusive", None

    status = _classify_pytest_result(proc.returncode, proc.stderr, proc.stdout)
    return status, int(proc.returncode)


def run_replay(
    run_dir: Path,
    cred_store: CredentialStore | None = None,
    *,
    finding_id: str | None = None,
    apply_fix: bool = False,
    target_override: str | None = None,
    trials_override: int | None = None,
    run_pytest: bool = True,
    tests_path: Path | None = None,
    repo: Path | None = None,
) -> ReplaySummary:
    """Replay and verify findings under frozen campaign policy without loosening scope or risk tiers."""
    rd = Path(run_dir)
    policy = load_frozen_policy(rd)

    if target_override:
        ScopeGuard(policy.allowlist_hosts, allow_risky=policy.allow_risky).check_url(target_override)
    effective_url = target_override or policy.target_url

    plan_path = rd / "plan.json"
    if not plan_path.is_file():
        raise ConfigError(f"Frozen run plan missing: {plan_path}")
    plan = json.loads(plan_path.read_text(encoding="utf-8"))

    with RunLock(rd):
        findings_dir = rd / "findings"
        raw_files = sorted(findings_dir.glob("*.json")) if findings_dir.is_dir() else []
        loaded_records: list[tuple[Path, dict[str, Any], Finding]] = []
        for fp in raw_files:
            data = json.loads(fp.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                loaded_records.append((fp, data, Finding.from_dict(data)))

        if finding_id:
            target_records = [rec for rec in loaded_records if rec[2].id == finding_id]
            if not target_records:
                raise ConfigError(f"Finding {finding_id!r} not found in {rd}")
        else:
            target_records = list(loaded_records)

        if cred_store is None:
            if policy.demo_mode and not target_override:
                overrides: dict[str, str] = {}
                for acct in policy.accounts:
                    if acct.token_env:
                        tok = os.environ.get(acct.token_env) or f"spar-demo-{acct.name}-{py_secrets.token_urlsafe(16)}"
                        overrides[acct.token_env] = tok
                cred_store = CredentialStore(policy.accounts, overrides=overrides)
            else:
                cred_store = CredentialStore(policy.accounts)

        secrets_list = _collect_all_secrets(policy, cred_store)
        ledger = Ledger(rd, secrets=secrets_list)
        recon_summary, objective_outcomes, rejected, recorded_repo = _load_campaign_state(rd, ledger, plan)

        resolved_repo: Path | None = (
            Path(repo).resolve()
            if repo is not None
            else (
                Path(__file__).resolve().parent / "demo_target"
                if policy.demo_mode
                else recorded_repo
            )
        )

        if apply_fix and resolved_repo is not None and resolved_repo.exists():
            backup_dir = rd / "fix_backups"
            for _, _, f_obj in target_records:
                proposal = synthesize_fix(f_obj.technique, resolved_repo, llm_cfg=policy.llm)
                if proposal.patch_pairs:
                    apply_fix_patches(proposal.patch_pairs, backup_dir)

        proc: subprocess.Popen[str] | None = None
        if policy.demo_mode and not target_override:
            proc, effective_url = _start_demo_subprocess(policy, cred_store, repo=resolved_repo)

        ScopeGuard(policy.allowlist_hosts, allow_risky=policy.allow_risky).check_url(effective_url)
        kill = KillSwitch(rd / "STOP")
        try:
            budget = Budget(
                policy.budget.max_usd,
                policy.budget.max_requests,
                policy.budget.max_duration_s,
                policy.budget.rate_per_min,
            )
            http = GuardedHTTPClient(policy, cred_store, ledger, budget, kill)
            target_client = TargetClient(http, policy.target_contract, effective_url, policy.accounts)

            health = WitnessHealthChecker().check(
                target_client, policy, require_reset=bool(policy.allow_risky)
            )
            ledger.append(
                "witness.health",
                {
                    "healthy": health.healthy,
                    "reasons": list(health.reasons),
                    "control_id": health.control_id,
                    "log_seq": health.log_seq,
                },
                task_id="replay",
            )

            objectives_by_id = {
                str(o.get("id") or ""): o
                for o in (plan.get("objectives") or [])
                if isinstance(o, dict)
            }
            re_trials = max(1, int(trials_override or policy.trials_n or 5))
            results: list[dict[str, Any]] = []

            for fp, raw_data, f_obj in target_records:
                src_obj = objectives_by_id.get(f_obj.objective_id, {})
                risk_tier = str(raw_data.get("risk_tier") or src_obj.get("risk_tier") or "read-only")

                if not health.healthy:
                    reason_txt = "; ".join(health.reasons) or "witness_unhealthy"
                    f_obj.label = "inconclusive"
                    f_obj.reattack = {
                        "label": "inconclusive",
                        "outcome": Outcome.INCONCLUSIVE.value,
                        "k": 0,
                        "n": 0,
                        "reason": reason_txt,
                        "at": time.time(),
                        "target": effective_url,
                    }
                    ledger.append(
                        "replay.verdict",
                        {
                            "finding_id": f_obj.id,
                            "objective_id": f_obj.objective_id,
                            "technique": f_obj.technique,
                            "outcome": Outcome.INCONCLUSIVE.value,
                            "label": "inconclusive",
                            "reason": reason_txt,
                        },
                        origin_id=f_obj.objective_id,
                        task_id=f_obj.technique,
                    )
                    updated_payload = {**raw_data, **f_obj.to_dict()}
                    safe_write_text(
                        fp,
                        json.dumps(updated_payload, indent=2, default=str) + "\n",
                        secrets=secrets_list,
                    )
                    results.append(
                        {
                            "finding_id": f_obj.id,
                            "technique": f_obj.technique,
                            "outcome": Outcome.INCONCLUSIVE.value,
                            "label": "inconclusive",
                            "verified": False,
                            "k": 0,
                            "n": 0,
                            "reason": reason_txt,
                        }
                    )
                    continue

                if risk_tier == "state-changing" and not policy.allow_risky:
                    reason_txt = "blocked_by_policy"
                    f_obj.label = "inconclusive"
                    f_obj.reattack = {
                        "label": "inconclusive",
                        "outcome": Outcome.INCONCLUSIVE.value,
                        "k": 0,
                        "n": 0,
                        "reason": reason_txt,
                        "at": time.time(),
                        "target": effective_url,
                    }
                    ledger.append(
                        "replay.verdict",
                        {
                            "finding_id": f_obj.id,
                            "objective_id": f_obj.objective_id,
                            "technique": f_obj.technique,
                            "outcome": Outcome.INCONCLUSIVE.value,
                            "label": "inconclusive",
                            "reason": reason_txt,
                        },
                        origin_id=f_obj.objective_id,
                        task_id=f_obj.technique,
                    )
                    updated_payload = {**raw_data, **f_obj.to_dict()}
                    safe_write_text(
                        fp,
                        json.dumps(updated_payload, indent=2, default=str) + "\n",
                        secrets=secrets_list,
                    )
                    results.append(
                        {
                            "finding_id": f_obj.id,
                            "technique": f_obj.technique,
                            "outcome": Outcome.INCONCLUSIVE.value,
                            "label": "inconclusive",
                            "verified": False,
                            "k": 0,
                            "n": 0,
                            "reason": reason_txt,
                        }
                    )
                    continue

                finding_dict = {
                    **raw_data,
                    **f_obj.to_dict(),
                    "objective": src_obj or {"id": f_obj.objective_id, "technique": f_obj.technique},
                    "accounts": raw_data.get("accounts") or src_obj.get("accounts") or {},
                    "params": raw_data.get("params") or src_obj.get("params") or {},
                }

                try:
                    fv = verify_fix(
                        finding_dict,
                        target_client,
                        policy,
                        ledger,
                        kill,
                        trials_n=re_trials,
                        run_mission_fn=run_mission,
                        eval_oracle_fn=evaluate_oracle,
                        held_out_fn=run_held_out,
                        benign_fn=run_benign_suite,
                    )
                except GuardViolation as exc:
                    if kill.is_triggered():
                        raise
                    reason_txt = str(exc)
                    f_obj.label = "inconclusive"
                    f_obj.reattack = {
                        "label": "inconclusive",
                        "outcome": Outcome.INCONCLUSIVE.value,
                        "k": 0,
                        "n": 0,
                        "reason": reason_txt,
                        "at": time.time(),
                        "target": effective_url,
                    }
                    ledger.append(
                        "replay.verdict",
                        {
                            "finding_id": f_obj.id,
                            "objective_id": f_obj.objective_id,
                            "technique": f_obj.technique,
                            "outcome": Outcome.INCONCLUSIVE.value,
                            "label": "inconclusive",
                            "reason": reason_txt,
                        },
                        origin_id=f_obj.objective_id,
                        task_id=f_obj.technique,
                    )
                    updated_payload = {**raw_data, **f_obj.to_dict()}
                    safe_write_text(
                        fp,
                        json.dumps(updated_payload, indent=2, default=str) + "\n",
                        secrets=secrets_list,
                    )
                    results.append(
                        {
                            "finding_id": f_obj.id,
                            "technique": f_obj.technique,
                            "outcome": Outcome.INCONCLUSIVE.value,
                            "label": "inconclusive",
                            "verified": False,
                            "k": 0,
                            "n": 0,
                            "reason": reason_txt,
                        }
                    )
                    continue

                if fv.verified:
                    mapped_label = "hardened"
                    f_obj.fix_status = "verified"
                    mapped_outcome = Outcome.NOT_REPRODUCED
                elif fv.outcome == Outcome.INCONCLUSIVE or fv.label == "over_refusal":
                    mapped_label = "inconclusive"
                    mapped_outcome = Outcome.INCONCLUSIVE
                else:
                    mapped_label = "regressed"
                    mapped_outcome = Outcome.REPRODUCED

                f_obj.label = mapped_label
                f_obj.reattack = {
                    "label": mapped_label,
                    "outcome": mapped_outcome.value,
                    "k": fv.reattack_k,
                    "n": fv.reattack_n,
                    "held_out_hits": fv.held_out_hits,
                    "held_out_total": fv.held_out_total,
                    "benign_passed": fv.benign_passed,
                    "benign_total": fv.benign_total,
                    "over_refusal_rate": fv.over_refusal_rate,
                    "reason": fv.reason,
                    "at": time.time(),
                    "target": effective_url,
                }

                ledger.append(
                    "replay.verdict",
                    {
                        "finding_id": f_obj.id,
                        "objective_id": f_obj.objective_id,
                        "technique": f_obj.technique,
                        "outcome": mapped_outcome.value,
                        "label": mapped_label,
                        "reattack_label": fv.label,
                        "k": fv.reattack_k,
                        "n": fv.reattack_n,
                        "held_out_hits": fv.held_out_hits,
                        "held_out_total": fv.held_out_total,
                        "benign_passed": fv.benign_passed,
                        "benign_total": fv.benign_total,
                        "over_refusal_rate": fv.over_refusal_rate,
                        "reason": fv.reason,
                    },
                    origin_id=f_obj.objective_id,
                    task_id=f_obj.technique,
                )

                updated_payload = {**raw_data, **f_obj.to_dict()}
                safe_write_text(
                    fp,
                    json.dumps(updated_payload, indent=2, default=str) + "\n",
                    secrets=secrets_list,
                )
                results.append(
                    {
                        "finding_id": f_obj.id,
                        "technique": f_obj.technique,
                        "outcome": mapped_outcome.value,
                        "label": mapped_label,
                        "verified": bool(fv.verified),
                        "k": fv.reattack_k,
                        "n": fv.reattack_n,
                        "held_out_hits": fv.held_out_hits,
                        "held_out_total": fv.held_out_total,
                        "benign_passed": fv.benign_passed,
                        "benign_total": fv.benign_total,
                        "over_refusal_rate": fv.over_refusal_rate,
                        "reason": fv.reason,
                    }
                )

            all_findings = [rec[2] for rec in loaded_records]

            effective_tests_path: Path | None = None
            if tests_path is not None:
                effective_tests_path = Path(tests_path)
            elif Path("spar_tests/test_attacks.py").is_file():
                effective_tests_path = Path("spar_tests/test_attacks.py")

            pytest_status = "skipped"
            pytest_returncode: int | None = None
            if run_pytest and effective_tests_path is not None and effective_tests_path.is_file():
                pytest_status, pytest_returncode = _run_pytest_suite(
                    effective_tests_path,
                    rd,
                    effective_url,
                    policy,
                    cred_store,
                    finding_id=finding_id,
                )
                ledger.append(
                    "pytest.completed",
                    {
                        "status": pytest_status,
                        "returncode": pytest_returncode,
                        "tests_path": str(effective_tests_path),
                    },
                    task_id="replay",
                )

            report_path = emit_report(
                all_findings,
                rejected,
                objective_outcomes,
                plan,
                recon_summary,
                budget.summary(),
                rd,
                resolved_repo,
                effective_url,
                ledger,
                secrets=secrets_list,
            )
            report_text = report_path.read_text(encoding="utf-8")
            integrity = audit_run_integrity(
                rd,
                report_text,
                all_findings,
                plan,
                secrets_list,
                tests_path=(
                    effective_tests_path
                    if effective_tests_path is not None and effective_tests_path.is_file()
                    else None
                ),
            )

            if not integrity.passed:
                overall_outcome = Outcome.INCONCLUSIVE
            elif any(
                r.get("outcome") == Outcome.INCONCLUSIVE.value or r.get("label") == "inconclusive"
                for r in results
            ) or pytest_status == "inconclusive":
                overall_outcome = Outcome.INCONCLUSIVE
            elif any(r.get("outcome") == Outcome.REPRODUCED.value for r in results) or pytest_status == "reproduced":
                overall_outcome = Outcome.REPRODUCED
            else:
                overall_outcome = Outcome.NOT_REPRODUCED

            return ReplaySummary(
                run_dir=rd,
                overall_outcome=overall_outcome,
                results=results,
                pytest_status=pytest_status,
                pytest_returncode=pytest_returncode,
                integrity=integrity,
                report_path=report_path,
            )
        finally:
            kill.restore()
            if proc is not None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)


__all__ = [
    "ReplaySummary",
    "RunSummary",
    "_classify_pytest_result",
    "run_campaign",
    "run_replay",
]
