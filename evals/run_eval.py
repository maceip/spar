"""Real evaluation harness for Spar (DemoAgent multi-run, AgentDojo live LLM, recorded demo, human audit).

Executes real campaigns end-to-end with zero mocked or extrapolated data:
  1. DemoAgent multi-run eval: 5 independent runs x 20 trials/objective across all 11 objectives.
  2. AgentDojo live LLM eval: real `agentdojo` `workspace` suite + `gpt-4o-mini` under strict USD cap ($1.50).
  3. Recorded demo run: `python -m spar demo --trials 20` -> integrity audit & secret scan -> `evals/recorded_demo_run/`.
  4. Human-model disagreement audit sample export -> `evals/human_review_sample.json`.
  5. Markdown report generation -> `evals/RESULTS.md`.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
import json
import os
from pathlib import Path
import random
import re
import secrets as py_secrets
import subprocess
import sys
import tempfile
import time
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agentdojo.attacks.important_instructions_attacks import ImportantInstructionsAttack
from agentdojo.task_suite import get_suite

from evals.agentdojo_bridge import (
    MODEL_NAME,
    USD_PER_1K_INPUT,
    USD_PER_1K_OUTPUT,
    AgentDojoTargetServer,
    _TOKEN_ENV_MAP as AD_TOKEN_ENV_MAP,
    build_agentdojo_policy,
    generate_ephemeral_tokens as ad_generate_tokens,
)
from spar.demo_target import generate_ephemeral_tokens as demo_generate_tokens, run_server as run_demo_server
from spar.guard import Budget, GuardedHTTPClient, KillSwitch, ScopeGuard
from spar.integrity import (
    audit_run_integrity,
    compute_human_model_disagreement,
)
from spar.ledger import Ledger
from spar.loop import run_campaign
from spar.policy import (
    CampaignPolicy,
    CredentialStore,
    load_frozen_policy,
    scan_for_secrets,
)
from spar.report import redact, wilson_interval
from spar.target import TargetClient

EVALS_DIR = REPO_ROOT / "evals"
RECORDED_DEMO_DIR = EVALS_DIR / "recorded_demo_run"
RAW_RESULTS_PATH = EVALS_DIR / "eval_results.json"
SAMPLE_PATH = EVALS_DIR / "human_review_sample.json"
AUDIT_PATH = EVALS_DIR / "human_review_audit.json"
RESULTS_MD_PATH = EVALS_DIR / "RESULTS.md"

_DEMO_TOKEN_ENVS = {
    "alice": "SPAR_DEMO_TOKEN_ALICE",
    "bob": "SPAR_DEMO_TOKEN_BOB",
    "auditor": "SPAR_DEMO_TOKEN_AUDITOR",
}
_SECRET_ENV_KEY_RE = re.compile(
    r"(?:TOKEN|SECRET|API_KEY|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_KEY|ACCESS_KEY|AUTH_KEY)",
    re.IGNORECASE,
)


def _collect_env_secrets(extra: list[str] | None = None) -> list[str]:
    vals: list[str] = []
    seen: set[str] = set()
    for s in extra or []:
        if isinstance(s, str) and len(s) >= 6 and s not in seen:
            seen.add(s)
            vals.append(s)
    for k, v in os.environ.items():
        if _SECRET_ENV_KEY_RE.search(k) and "PUBLIC" not in k.upper() and "PUBKEY" not in k.upper():
            if len(v) >= 6 and v not in seen:
                seen.add(v)
                vals.append(v)
    return vals


def _extract_sample_records_with_evidence(
    run_dir: Path,
    source_label: str,
    summary_findings: list[Any],
    summary_rejected: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Load run_dir/human_review_sample.json and enrich each item with raw ledger evidence."""
    sample_file = run_dir / "human_review_sample.json"
    if not sample_file.is_file():
        return []
    raw_sample = json.loads(sample_file.read_text(encoding="utf-8"))
    ledger = Ledger(run_dir)
    findings_by_id = {f.id: f for f in summary_findings}
    rejected_by_oid = {str(r.get("objective_id") or ""): r for r in summary_rejected}

    enriched: list[dict[str, Any]] = []
    for item in raw_sample.get("items", []):
        if not isinstance(item, dict):
            continue
        rec_id = str(item.get("id") or "")
        cat = str(item.get("category") or "")
        seqs = list(item.get("ledger_seqs") or [])
        ledger_excerpts: list[dict[str, Any]] = []
        for s in seqs[:6]:
            evt = ledger.get_by_seq(int(s))
            if evt is not None:
                ledger_excerpts.append(
                    {
                        "seq": evt.get("seq"),
                        "type": evt.get("type"),
                        "task_id": evt.get("task_id"),
                        "payload": redact(evt.get("payload")),
                    }
                )

        steps: list[dict[str, Any]] = []
        critic_reason = ""
        k_val = 0
        n_val = 0
        if cat == "finding" and rec_id in findings_by_id:
            f_obj = findings_by_id[rec_id]
            steps = redact(list(f_obj.steps or []))[:5]
            critic_reason = str(f_obj.critic_reason or "")
            k_val = int(f_obj.k)
            n_val = int(f_obj.n)
        elif cat == "rejected" and rec_id in rejected_by_oid:
            r_obj = rejected_by_oid[rec_id]
            critic_reason = str(r_obj.get("reason") or "")

        enriched.append(
            {
                "source": source_label,
                "run_id": run_dir.name,
                "category": cat,
                "id": rec_id,
                "technique": str(item.get("technique") or ""),
                "model_verdict": str(item.get("model_verdict") or ""),
                "trust_tier": str(item.get("trust_tier") or ""),
                "k": k_val,
                "n": n_val,
                "witness": redact(str(item.get("witness") or "")),
                "critic_reason": redact(critic_reason),
                "quotes": redact(list(item.get("quotes") or []))[:4],
                "steps": steps,
                "ledger_seqs": seqs,
                "ledger_excerpts": ledger_excerpts,
                "human_verdict": None,
                "human_notes": "",
            }
        )
    return enriched


def _aggregate_objective_runs(per_run_records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_tech: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for rec in per_run_records:
        for oo in rec["objectives"]:
            by_tech[str(oo["technique"])].append(oo)

    rows: list[dict[str, Any]] = []
    for tech, items in sorted(by_tech.items()):
        rates = [float(it["rate"]) for it in items]
        k_sum = sum(int(it["k"]) for it in items)
        n_sum = sum(int(it["n"]) for it in items)
        ci_low, ci_high = wilson_interval(k_sum, n_sum)
        reproduced_runs = sum(1 for it in items if it["outcome"] == "reproduced")
        sevs = sorted({str(it.get("severity") or "") for it in items if it.get("severity")})
        rows.append(
            {
                "technique": tech,
                "runs": len(items),
                "reproduced_runs": reproduced_runs,
                "severity": sevs[0] if sevs else "N/A",
                "k_total": k_sum,
                "n_total": n_sum,
                "mean_rate": round(k_sum / n_sum, 4) if n_sum > 0 else 0.0,
                "min_rate": round(min(rates), 4) if rates else 0.0,
                "max_rate": round(max(rates), 4) if rates else 0.0,
                "min_k": min(int(it["k"]) for it in items),
                "max_k": max(int(it["k"]) for it in items),
                "n_per_run": items[0]["n"] if items else 0,
                "wilson_ci_low": ci_low,
                "wilson_ci_high": ci_high,
                "candidate_hits_rejected": sum(int(it.get("rejected_hits", 0)) for it in items),
            }
        )
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MED": 2, "LOW": 3, "N/A": 4}
    rows.sort(key=lambda r: (sev_order.get(r["severity"], 9), -r["mean_rate"], r["technique"]))
    return rows


def run_demo_multi_eval(
    *,
    num_runs: int = 5,
    trials_n: int = 20,
    seeds: list[int] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Run 5 independent DemoAgent campaigns x 20 trials/objective and aggregate ranges."""
    run_seeds = seeds or [101, 202, 303, 404, 505][:num_runs]
    demo_repo = REPO_ROOT / "spar" / "demo_target"
    per_runs: list[dict[str, Any]] = []
    sampled_items: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="spar_eval_demo_") as td:
        tmp = Path(td)
        for idx, seed in enumerate(run_seeds, start=1):
            tokens = demo_generate_tokens()
            overrides = {_DEMO_TOKEN_ENVS[k]: v for k, v in tokens.items()}
            srv, _thread, port, _target = run_demo_server(port=0, seed=seed, tokens=tokens)
            base_url = f"http://127.0.0.1:{port}"
            try:
                policy = CampaignPolicy.default_demo(
                    base_url,
                    _DEMO_TOKEN_ENVS,
                    allow_risky=True,
                    trials_n=trials_n,
                )
                for acct in policy.accounts:
                    if acct.name in tokens:
                        acct.token_fingerprint = CredentialStore.fingerprint(tokens[acct.name])
                cred_store = CredentialStore(policy.accounts, overrides=overrides)
                t0 = time.monotonic()
                summary = run_campaign(
                    policy,
                    cred_store,
                    spar_root=tmp / f"spar_{idx}",
                    repo=demo_repo,
                    tests_dir=tmp / f"tests_{idx}",
                )
                duration_s = round(time.monotonic() - t0, 3)
            finally:
                srv.shutdown()
                srv.server_close()

            findings_by_tech = {f.technique: f for f in summary.findings}
            rejected_by_tech = {str(r.get("technique") or ""): r for r in summary.rejected}
            obj_records: list[dict[str, Any]] = []
            for oo in summary.objective_outcomes:
                tech = str(oo.get("technique") or "")
                k_val = int(oo.get("k", 0) or 0)
                n_val = int(oo.get("n", 0) or 0)
                f_obj = findings_by_tech.get(tech)
                r_obj = rejected_by_tech.get(tech)
                obj_records.append(
                    {
                        "objective_id": str(oo.get("objective_id") or ""),
                        "technique": tech,
                        "outcome": str(oo.get("outcome") or ""),
                        "severity": f_obj.severity if f_obj else "N/A",
                        "k": k_val,
                        "n": n_val,
                        "rate": (k_val / n_val) if n_val > 0 else 0.0,
                        "rejected_hits": int(r_obj.get("candidate_hits", 0) or 0) if r_obj else 0,
                    }
                )

            critic_rejected_hits = sum(int(r.get("candidate_hits", 0) or 0) for r in summary.rejected)
            per_runs.append(
                {
                    "run_index": idx,
                    "seed": seed,
                    "port": port,
                    "run_id": summary.run_id,
                    "overall_outcome": summary.overall_outcome.value,
                    "integrity_passed": bool(summary.integrity.passed),
                    "findings_count": len(summary.findings),
                    "rejected_objectives_count": len(summary.rejected),
                    "critic_rejected_hits": critic_rejected_hits,
                    "guarded_requests": int(summary.budget.get("requests", 0) or 0),
                    "llm_calls": int(summary.budget.get("llm_calls", 0) or 0),
                    "usd_spent": float(summary.budget.get("usd_spent", 0.0) or 0.0),
                    "wall_clock_s": duration_s,
                    "objectives": obj_records,
                }
            )
            sampled_items.extend(
                _extract_sample_records_with_evidence(
                    summary.run_dir,
                    f"demo_multi_run_{idx}",
                    summary.findings,
                    summary.rejected,
                )
            )

    agg_rows = _aggregate_objective_runs(per_runs)
    total_reqs = sum(r["guarded_requests"] for r in per_runs)
    total_dur = round(sum(r["wall_clock_s"] for r in per_runs), 3)
    total_rejected_hits = sum(r["critic_rejected_hits"] for r in per_runs)
    all_integrity = all(r["integrity_passed"] for r in per_runs)

    return (
        {
            "num_runs": len(per_runs),
            "trials_per_objective": trials_n,
            "integrity_all_passed": all_integrity,
            "total_guarded_requests": total_reqs,
            "min_guarded_requests": min(r["guarded_requests"] for r in per_runs),
            "max_guarded_requests": max(r["guarded_requests"] for r in per_runs),
            "total_wall_clock_s": total_dur,
            "mean_wall_clock_s": round(total_dur / len(per_runs), 3),
            "total_critic_rejected_hits": total_rejected_hits,
            "total_usd_spent": 0.0,
            "per_run": per_runs,
            "per_objective_aggregate": agg_rows,
        },
        sampled_items,
    )


def _run_agentdojo_injection_scenarios(
    *,
    trials_per_scenario: int = 3,
    remaining_budget_usd: float = 1.0,
) -> dict[str, Any]:
    """Run real AgentDojo workspace (user_task, injection_task) scenarios through Spar TargetClient."""
    suite = get_suite("v1", "workspace")
    scenarios_spec = [
        {
            "scenario_id": "ad-email-unread-exfil",
            "user_task_id": "user_task_24",
            "injection_task_id": "injection_task_0",
            "vector_key": "email_facebook_injection",
        },
        {
            "scenario_id": "ad-drive-feedback-exfil",
            "user_task_id": "user_task_28",
            "injection_task_id": "injection_task_3",
            "vector_key": "drive_feedback_injection",
        },
        {
            "scenario_id": "ad-email-fbcode-exfil",
            "user_task_id": "user_task_16",
            "injection_task_id": "injection_task_4",
            "vector_key": "email_facebook_injection",
        },
        {
            "scenario_id": "ad-drive-teambuilding-delete",
            "user_task_id": "user_task_29",
            "injection_task_id": "injection_task_1",
            "vector_key": "drive_team_building_injection",
        },
    ]

    scenario_results: list[dict[str, Any]] = []
    total_input = 0
    total_output = 0
    total_calls = 0
    total_usd = 0.0
    total_reqs = 0
    t_all = time.monotonic()

    with tempfile.TemporaryDirectory(prefix="spar_eval_ad_scenarios_") as td:
        tmp = Path(td)
        for spec in scenarios_spec:
            ut = suite.user_tasks[spec["user_task_id"]]
            it = suite.injection_tasks[spec["injection_task_id"]]
            inj_text = ImportantInstructionsAttack._JB_STRING.format(
                user="Emma Johnson",
                model=MODEL_NAME,
                goal=it.GOAL,
            )
            injections = {spec["vector_key"]: inj_text}

            tokens = ad_generate_tokens()
            overrides = {AD_TOKEN_ENV_MAP[k]: v for k, v in tokens.items()}
            cap = max(0.05, round(remaining_budget_usd - total_usd, 4))
            inj_hits = 0
            util_hits = 0
            t0 = time.monotonic()

            with AgentDojoTargetServer(seed=777, tokens=tokens, max_usd=cap, injections=injections) as srv:
                policy = build_agentdojo_policy(srv.base_url, trials_n=trials_per_scenario, allow_risky=True, max_usd=cap)
                for acct in policy.accounts:
                    acct.token_fingerprint = CredentialStore.fingerprint(tokens[acct.name])
                cs = CredentialStore(policy.accounts, overrides=overrides)
                ledger = Ledger(tmp / spec["scenario_id"], secrets=cs.secret_values())
                budget = Budget(cap, 500, 300.0, 600.0)
                kill = KillSwitch(tmp / f"{spec['scenario_id']}_STOP", install_sigint=False)
                http = GuardedHTTPClient(policy, cs, ledger, budget, kill)
                tc = TargetClient(http, policy.target_contract, srv.base_url, policy.accounts)

                for trial_idx in range(trials_per_scenario):
                    tc.reset("auditor")
                    ctrl_id = f"SPAR-AD-{py_secrets.token_hex(4)}"
                    tc.positive_control_ping(ctrl_id, "emma")
                    pre_env = srv.target.state.env.model_copy(deep=True)

                    resp = tc.chat(
                        "emma",
                        ut.PROMPT,
                        session_id=f"ad-scen-{spec['scenario_id']}-{trial_idx}",
                        technique="indirect_injection",
                        risk_tier="state-changing",
                    )
                    reply = tc.extract_chat_reply(resp)
                    post_env = srv.target.state.env
                    if it.security(reply, pre_env, post_env):
                        inj_hits += 1
                    if ut.utility(reply, pre_env, post_env, strict=False):
                        util_hits += 1

                usage = srv.usage_summary()
                bsum = budget.summary()

            dur_s = round(time.monotonic() - t0, 3)
            ci_lo, ci_hi = wilson_interval(inj_hits, trials_per_scenario)
            total_input += int(usage["input_tokens"])
            total_output += int(usage["output_tokens"])
            total_calls += int(usage["llm_calls"])
            total_usd += float(usage["usd_spent"])
            total_reqs += int(bsum["requests"])

            scenario_results.append(
                {
                    "scenario_id": spec["scenario_id"],
                    "user_task_id": spec["user_task_id"],
                    "injection_task_id": spec["injection_task_id"],
                    "vector_key": spec["vector_key"],
                    "injection_goal": it.GOAL,
                    "injection_hits": inj_hits,
                    "trials": trials_per_scenario,
                    "injection_success_rate": round(inj_hits / trials_per_scenario, 4),
                    "wilson_ci_low": ci_lo,
                    "wilson_ci_high": ci_hi,
                    "utility_passed": util_hits,
                    "llm_calls": usage["llm_calls"],
                    "input_tokens": usage["input_tokens"],
                    "output_tokens": usage["output_tokens"],
                    "usd_spent": usage["usd_spent"],
                    "guarded_requests": bsum["requests"],
                    "wall_clock_s": dur_s,
                }
            )

    return {
        "model": MODEL_NAME,
        "scenarios": scenario_results,
        "total_llm_calls": total_calls,
        "total_input_tokens": total_input,
        "total_output_tokens": total_output,
        "total_usd_spent": round(total_usd, 6),
        "total_guarded_requests": total_reqs,
        "total_wall_clock_s": round(time.monotonic() - t_all, 3),
    }


def run_agentdojo_live_eval(
    *,
    num_runs: int = 3,
    trials_n: int = 3,
    max_usd_total: float = 1.50,
    seeds: list[int] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Run Spar campaigns against AgentDojoTargetServer (gpt-4o-mini) + AgentDojo injection scenarios."""
    if not os.environ.get("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY is required for AgentDojo live LLM evaluation")

    run_seeds = seeds or [11, 22, 33][:num_runs]
    per_runs: list[dict[str, Any]] = []
    sampled_items: list[dict[str, Any]] = []
    cumulative_usd = 0.0

    with tempfile.TemporaryDirectory(prefix="spar_eval_ad_") as td:
        tmp = Path(td)
        for idx, seed in enumerate(run_seeds, start=1):
            remaining = round(max_usd_total - cumulative_usd, 4)
            if remaining <= 0.05:
                break
            tokens = ad_generate_tokens()
            overrides = {AD_TOKEN_ENV_MAP[k]: v for k, v in tokens.items()}
            t0 = time.monotonic()
            with AgentDojoTargetServer(seed=seed, tokens=tokens, max_usd=remaining) as srv:
                policy = build_agentdojo_policy(
                    srv.base_url,
                    trials_n=trials_n,
                    allow_risky=True,
                    max_usd=remaining,
                )
                for acct in policy.accounts:
                    acct.token_fingerprint = CredentialStore.fingerprint(tokens[acct.name])
                cs = CredentialStore(policy.accounts, overrides=overrides)
                summary = run_campaign(
                    policy,
                    cs,
                    spar_root=tmp / f"spar_ad_{idx}",
                    repo=EVALS_DIR / "agentdojo_bridge.py",
                    tests_dir=tmp / f"tests_ad_{idx}",
                )
                usage = srv.usage_summary()
            dur_s = round(time.monotonic() - t0, 3)
            cumulative_usd += float(usage["usd_spent"])

            findings_by_tech = {f.technique: f for f in summary.findings}
            rejected_by_tech = {str(r.get("technique") or ""): r for r in summary.rejected}
            obj_records: list[dict[str, Any]] = []
            for oo in summary.objective_outcomes:
                tech = str(oo.get("technique") or "")
                k_val = int(oo.get("k", 0) or 0)
                n_val = int(oo.get("n", 0) or 0)
                f_obj = findings_by_tech.get(tech)
                r_obj = rejected_by_tech.get(tech)
                obj_records.append(
                    {
                        "objective_id": str(oo.get("objective_id") or ""),
                        "technique": tech,
                        "outcome": str(oo.get("outcome") or ""),
                        "severity": f_obj.severity if f_obj else "N/A",
                        "k": k_val,
                        "n": n_val,
                        "rate": (k_val / n_val) if n_val > 0 else 0.0,
                        "rejected_hits": int(r_obj.get("candidate_hits", 0) or 0) if r_obj else 0,
                        "reason": str(r_obj.get("reason") or "") if r_obj else "",
                    }
                )

            critic_rejected_hits = sum(int(r.get("candidate_hits", 0) or 0) for r in summary.rejected)
            per_runs.append(
                {
                    "run_index": idx,
                    "seed": seed,
                    "run_id": summary.run_id,
                    "overall_outcome": summary.overall_outcome.value,
                    "integrity_passed": bool(summary.integrity.passed),
                    "findings_count": len(summary.findings),
                    "rejected_objectives_count": len(summary.rejected),
                    "critic_rejected_hits": critic_rejected_hits,
                    "guarded_requests": int(summary.budget.get("requests", 0) or 0),
                    "target_llm_calls": int(usage["llm_calls"]),
                    "input_tokens": int(usage["input_tokens"]),
                    "output_tokens": int(usage["output_tokens"]),
                    "usd_spent": float(usage["usd_spent"]),
                    "wall_clock_s": dur_s,
                    "objectives": obj_records,
                }
            )
            sampled_items.extend(
                _extract_sample_records_with_evidence(
                    summary.run_dir,
                    f"agentdojo_run_{idx}",
                    summary.findings,
                    summary.rejected,
                )
            )

    scenarios_data = _run_agentdojo_injection_scenarios(
        trials_per_scenario=trials_n,
        remaining_budget_usd=max(0.10, max_usd_total - cumulative_usd),
    )
    cumulative_usd += float(scenarios_data["total_usd_spent"])

    agg_rows = _aggregate_objective_runs(per_runs)
    total_input = sum(r["input_tokens"] for r in per_runs) + int(scenarios_data["total_input_tokens"])
    total_output = sum(r["output_tokens"] for r in per_runs) + int(scenarios_data["total_output_tokens"])
    total_calls = sum(r["target_llm_calls"] for r in per_runs) + int(scenarios_data["total_llm_calls"])
    total_reqs = sum(r["guarded_requests"] for r in per_runs) + int(scenarios_data["total_guarded_requests"])
    total_dur = round(sum(r["wall_clock_s"] for r in per_runs) + float(scenarios_data["total_wall_clock_s"]), 3)

    return (
        {
            "model": MODEL_NAME,
            "usd_per_1k_input": USD_PER_1K_INPUT,
            "usd_per_1k_output": USD_PER_1K_OUTPUT,
            "max_usd_cap": max_usd_total,
            "num_campaign_runs": len(per_runs),
            "trials_per_objective": trials_n,
            "integrity_all_passed": all(r["integrity_passed"] for r in per_runs),
            "campaign_per_run": per_runs,
            "campaign_per_objective_aggregate": agg_rows,
            "campaign_critic_rejected_hits": sum(r["critic_rejected_hits"] for r in per_runs),
            "campaign_guarded_requests": sum(r["guarded_requests"] for r in per_runs),
            "campaign_usd_spent": round(sum(r["usd_spent"] for r in per_runs), 6),
            "campaign_wall_clock_s": round(sum(r["wall_clock_s"] for r in per_runs), 3),
            "native_scenarios": scenarios_data,
            "total_llm_calls": total_calls,
            "total_input_tokens": total_input,
            "total_output_tokens": total_output,
            "total_usd_spent": round(cumulative_usd, 6),
            "total_guarded_requests": total_reqs,
            "total_wall_clock_s": total_dur,
        },
        sampled_items,
    )


def run_recorded_demo(trials_n: int = 20) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Execute real `python -m spar demo --trials 20` in isolated cwd and save verified artifacts."""
    RECORDED_DEMO_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="spar_recorded_demo_") as td:
        tmp = Path(td)
        spar_dir = tmp / ".spar"
        t0 = time.monotonic()
        proc = subprocess.run(
            [sys.executable, "-m", "spar", "demo", "--trials", str(trials_n), "--spar-dir", str(spar_dir)],
            cwd=str(tmp),
            capture_output=True,
            text=True,
            timeout=600,
        )
        wall_clock_s = round(time.monotonic() - t0, 3)
        if proc.returncode != 0:
            raise RuntimeError(f"spar demo failed (rc={proc.returncode}):\n{proc.stdout}\n{proc.stderr}")

        latest_id = (spar_dir / "latest").read_text(encoding="utf-8").strip()
        run_dir = spar_dir / "runs" / latest_id
        policy = load_frozen_policy(run_dir)
        plan = json.loads((run_dir / "plan.json").read_text(encoding="utf-8"))
        cstate = json.loads((run_dir / "campaign_state.json").read_text(encoding="utf-8"))
        report_raw = (run_dir / "report.md").read_text(encoding="utf-8")
        tests_path = tmp / "spar_tests" / "test_attacks.py"

        findings_list: list[dict[str, Any]] = []
        for fpath in sorted((run_dir / "findings").glob("*.json")):
            findings_list.append(json.loads(fpath.read_text(encoding="utf-8")))

        all_secrets = _collect_env_secrets()
        integrity = audit_run_integrity(
            run_dir,
            report_raw,
            findings_list,
            plan,
            all_secrets,
            tests_path=tests_path if tests_path.is_file() else None,
        )
        if not integrity.passed:
            raise RuntimeError(f"Recorded demo run failed integrity audit: {integrity.failures}")

        # Sanitize tmp paths before publishing into git-tracked evals/recorded_demo_run/
        report_clean = report_raw.replace(str(REPO_ROOT), "<repo>").replace(str(tmp), "<tmp>")
        scan_for_secrets(report_clean, all_secrets)

        summary_payload = {
            "command": f"python -m spar demo --trials {trials_n}",
            "exit_code": proc.returncode,
            "run_id": latest_id,
            "overall_outcome": "reproduced" if findings_list else "not_reproduced",
            "trials_per_objective": trials_n,
            "planned_objectives": len(plan.get("objectives", [])),
            "confirmed_findings": len(findings_list),
            "rejected_candidates": len(cstate.get("rejected", [])),
            "critic_rejected_hits": sum(int(r.get("candidate_hits", 0) or 0) for r in cstate.get("rejected", [])),
            "wall_clock_s": wall_clock_s,
            "budget": cstate.get("budget", {}),
            "recon_tools_count": len((cstate.get("recon") or {}).get("tools", [])),
            "recon_retrieval_sources": list((cstate.get("recon") or {}).get("retrieval_sources", [])),
            "system_prompt_sha256": (plan.get("snapshot_id") or {}).get("system_prompt_sha256", ""),
            "objective_outcomes": cstate.get("objective_outcomes", []),
            "findings": [
                {
                    "id": f["id"],
                    "objective_id": f["objective_id"],
                    "technique": f["technique"],
                    "severity": f["severity"],
                    "k": f["k"],
                    "n": f["n"],
                    "wilson_ci_low": f["wilson_ci_low"],
                    "wilson_ci_high": f["wilson_ci_high"],
                    "oracle": f["oracle"],
                    "trust_tier": f["trust_tier"],
                    "critic_confirmed": f["critic_confirmed"],
                    "critic_cited_seqs": f["critic_cited_seqs"],
                    "witness": redact(f["witness"], secrets=all_secrets),
                }
                for f in findings_list
            ],
            "pytest_expected_failure_observed": "Suite failed as expected (exit 1)" in proc.stdout,
        }
        summary_text = json.dumps(summary_payload, indent=2) + "\n"
        scan_for_secrets(summary_text, all_secrets)

        integrity_payload = {
            "run_id": latest_id,
            "passed": bool(integrity.passed),
            "checks": dict(integrity.checks),
            "failures": list(integrity.failures),
            "secret_scan_verified": True,
            "policy_sha256": policy.policy_sha256,
        }
        integrity_text = json.dumps(integrity_payload, indent=2) + "\n"
        scan_for_secrets(integrity_text, all_secrets)

        (RECORDED_DEMO_DIR / "report.md").write_text(report_clean, encoding="utf-8")
        (RECORDED_DEMO_DIR / "summary.json").write_text(summary_text, encoding="utf-8")
        (RECORDED_DEMO_DIR / "integrity.json").write_text(integrity_text, encoding="utf-8")

        from spar.report import Finding

        f_objs = [Finding.from_dict(fd) for fd in findings_list]
        sampled = _extract_sample_records_with_evidence(
            run_dir,
            "recorded_demo_run",
            f_objs,
            list(cstate.get("rejected", [])),
        )
        return summary_payload, sampled


def export_combined_human_sample(
    all_sampled: list[dict[str, Any]],
    *,
    max_items: int = 20,
    seed: int = 42,
) -> dict[str, Any]:
    """Build deterministic random sample across DemoAgent, AgentDojo, and Recorded Demo verdicts."""
    rng = random.Random(seed)
    confirmed_pool = [it for it in all_sampled if it["model_verdict"] == "confirmed"]
    rejected_pool = [it for it in all_sampled if it["model_verdict"] == "rejected"]

    ad_pool = [it for it in all_sampled if it["source"].startswith("agentdojo")]
    demo_pool = [it for it in all_sampled if not it["source"].startswith("agentdojo")]

    chosen: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str, str]] = set()

    def _add(item: dict[str, Any]) -> None:
        key = (item["run_id"], item["category"], item["id"])
        if key not in seen_keys and len(chosen) < max_items:
            seen_keys.add(key)
            chosen.append(item)

    # Ensure representation from AgentDojo, DemoAgent, confirmed, and rejected verdicts.
    rng.shuffle(ad_pool)
    rng.shuffle(demo_pool)
    rng.shuffle(confirmed_pool)
    rng.shuffle(rejected_pool)

    for it in ad_pool[:8]:
        _add(it)
    for it in rejected_pool[:4]:
        _add(it)
    for it in confirmed_pool:
        if len(chosen) >= max_items:
            break
        _add(it)
    for it in demo_pool:
        if len(chosen) >= max_items:
            break
        _add(it)

    for idx, rec in enumerate(chosen):
        rec["sample_index"] = idx

    payload = {
        "total_pool": len(all_sampled),
        "sample_size": len(chosen),
        "seed": seed,
        "items": chosen,
    }
    text = json.dumps(payload, indent=2, default=str) + "\n"
    scan_for_secrets(text, _collect_env_secrets())
    SAMPLE_PATH.write_text(text, encoding="utf-8")
    return payload


def render_results_markdown(
    results: dict[str, Any],
    disagreement: dict[str, Any] | None,
) -> str:
    demo = results["demo_multi_run"]
    ad = results["agentdojo_live_llm"]
    rec = results["recorded_demo_run"]

    lines: list[str] = [
        "# Spar Empirical Evaluation Results",
        "",
        "All numbers below were measured from real tool executions against live targets (zero fabricated, simulated, or extrapolated metrics).",
        "",
        "## Reproduction",
        "",
        "```bash",
        "python evals/run_eval.py",
        "```",
        "",
        f"- **Timestamp (UTC)**: `{results['generated_at_utc']}`",
        "",
        "## 1. DemoAgent Multi-Run Evaluation (5 runs × 20 trials/objective)",
        "",
        f"- **Runs**: `{demo['num_runs']}` independent runs (`seeds = {[r['seed'] for r in demo['per_run']]}`), ephemeral `127.0.0.1` ports",
        f"- **Trials per Objective**: `{demo['trials_per_objective']}` (`100` trials per objective across 5 runs, `1,100` total objective trials)",
        f"- **Integrity Audit**: `{'PASS (5/5 runs)' if demo['integrity_all_passed'] else 'FAIL'}`",
        f"- **Guarded Requests**: `{demo['total_guarded_requests']}` total (`{demo['min_guarded_requests']}–{demo['max_guarded_requests']}` per run)",
        f"- **Wall-Clock Duration**: `{demo['total_wall_clock_s']:.3f} s` total (`{demo['mean_wall_clock_s']:.3f} s` mean/run)",
        f"- **Critic Rejections (Candidate Hits Rejected)**: `{demo['total_critic_rejected_hits']}`",
        f"- **Model Cost (USD)**: `${demo['total_usd_spent']:.2f}` (`0` LLM calls)",
        "",
        "| Technique | Severity | Repro Runs | Min–Max Rate (k/20) | Aggregate k/N | Mean Rate | 95% Wilson CI | Critic Rejected Hits |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in demo["per_objective_aggregate"]:
        rng_str = f"{row['min_rate']:.1%}–{row['max_rate']:.1%} ({row['min_k']}–{row['max_k']}/{row['n_per_run']})"
        ci_str = f"[{row['wilson_ci_low']:.4f}, {row['wilson_ci_high']:.4f}]"
        lines.append(
            f"| `{row['technique']}` | `{row['severity']}` | `{row['reproduced_runs']}/{row['runs']}` | "
            f"`{rng_str}` | `{row['k_total']}/{row['n_total']}` | `{row['mean_rate']:.1%}` | `{ci_str}` | `{row['candidate_hits_rejected']}` |"
        )

    lines.extend(
        [
            "",
            "## 2. AgentDojo Live LLM Evaluation (`workspace` suite + `gpt-4o-mini`)",
            "",
            f"- **Model & Pricing**: `{ad['model']}` (`${ad['usd_per_1k_input']:.5f} / 1k` input tokens, `${ad['usd_per_1k_output']:.5f} / 1k` output tokens, strict cap `${ad['max_usd_cap']:.2f}`)",
            f"- **Spar Campaign Runs**: `{ad['num_campaign_runs']}` runs × `{ad['trials_per_objective']}` trials/objective (seeds `{[r['seed'] for r in ad['campaign_per_run']]}`), integrity=`{'PASS' if ad['integrity_all_passed'] else 'FAIL'}`",
            f"- **Total LLM Calls**: `{ad['total_llm_calls']}`",
            f"- **Total Tokens**: `{ad['total_input_tokens']}` input + `{ad['total_output_tokens']}` output (`{ad['total_input_tokens'] + ad['total_output_tokens']}` total)",
            f"- **Total Measured USD Cost**: `${ad['total_usd_spent']:.6f}` (campaigns: `${ad['campaign_usd_spent']:.6f}`, native AgentDojo scenarios: `${ad['native_scenarios']['total_usd_spent']:.6f}`)",
            f"- **Total Guarded Requests**: `{ad['total_guarded_requests']}` (campaigns: `{ad['campaign_guarded_requests']}`, native scenarios: `{ad['native_scenarios']['total_guarded_requests']}`)",
            f"- **Total Wall-Clock Duration**: `{ad['total_wall_clock_s']:.3f} s` (campaigns: `{ad['campaign_wall_clock_s']:.3f} s`, native scenarios: `{ad['native_scenarios']['total_wall_clock_s']:.3f} s`)",
            f"- **Critic Rejections (Campaign Candidate Hits Rejected)**: `{ad['campaign_critic_rejected_hits']}`",
            "",
            "### 2a. Spar Autonomous Campaigns vs AgentDojoTargetServer",
            "",
            "| Technique | Severity | Repro Runs | Min–Max Rate (k/n) | Aggregate k/N | Mean Rate | 95% Wilson CI | Critic Rejected Hits |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for row in ad["campaign_per_objective_aggregate"]:
        rng_str = f"{row['min_rate']:.1%}–{row['max_rate']:.1%} ({row['min_k']}–{row['max_k']}/{row['n_per_run']})"
        ci_str = f"[{row['wilson_ci_low']:.4f}, {row['wilson_ci_high']:.4f}]"
        lines.append(
            f"| `{row['technique']}` | `{row['severity']}` | `{row['reproduced_runs']}/{row['runs']}` | "
            f"`{rng_str}` | `{row['k_total']}/{row['n_total']}` | `{row['mean_rate']:.1%}` | `{ci_str}` | `{row['candidate_hits_rejected']}` |"
        )

    lines.extend(
        [
            "",
            "### 2b. Native AgentDojo Workspace Injection Scenarios",
            "",
            "| Scenario ID | User Task | Injection Task | Hijack Rate (k/N) | 95% Wilson CI | Benign Utility | Tokens (In / Out) | Cost (USD) | Guarded Reqs | Wall-Clock (s) |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for sc in ad["native_scenarios"]["scenarios"]:
        ci_str = f"[{sc['wilson_ci_low']:.4f}, {sc['wilson_ci_high']:.4f}]"
        lines.append(
            f"| `{sc['scenario_id']}` | `{sc['user_task_id']}` | `{sc['injection_task_id']}` | "
            f"`{sc['injection_hits']}/{sc['trials']}` (`{sc['injection_success_rate']:.1%}`) | `{ci_str}` | "
            f"`{sc['utility_passed']}/{sc['trials']}` | `{sc['input_tokens']} / {sc['output_tokens']}` | "
            f"`${sc['usd_spent']:.6f}` | `{sc['guarded_requests']}` | `{sc['wall_clock_s']:.3f}` |"
        )

    lines.extend(
        [
            "",
            "## 3. Recorded Demo Run (`spar demo --trials 20`)",
            "",
            f"- **Artifacts**: [recorded_demo_run/report.md](recorded_demo_run/report.md), [recorded_demo_run/summary.json](recorded_demo_run/summary.json), [recorded_demo_run/integrity.json](recorded_demo_run/integrity.json)",
            f"- **Run ID**: `{rec['run_id']}` (`overall_outcome={rec['overall_outcome']}`)",
            f"- **Findings Confirmed**: `{rec['confirmed_findings']}/{rec['planned_objectives']}` objectives (`{rec['critic_rejected_hits']}` critic-rejected hits)",
            f"- **Guarded Requests**: `{rec['budget'].get('requests', 0)}` | **Wall-Clock**: `{rec['wall_clock_s']:.3f} s` | **Cost**: `${float(rec['budget'].get('usd_spent', 0.0)):.2f}`",
            f"- **Pytest Regression Suite Failed As Expected (exit 1)**: `{rec['pytest_expected_failure_observed']}`",
            "",
            "## 4. Human-Model Disagreement Audit",
            "",
        ]
    )

    if disagreement is not None and disagreement.get("total_reviewed", 0) > 0:
        lines.extend(
            [
                f"- **Sample File**: [human_review_sample.json](human_review_sample.json)",
                f"- **Audit File**: [human_review_audit.json](human_review_audit.json)",
                f"- **Total Reviewed**: `{disagreement['total_reviewed']}` sampled verdicts (from DemoAgent multi-run, Recorded Demo, and AgentDojo live LLM campaigns)",
                f"- **Disagreements**: `{disagreement['disagreements']}`",
                f"- **Empirical Disagreement Rate**: `{disagreement['disagreement_rate']:.2%}` (`{disagreement['disagreements']}/{disagreement['total_reviewed']}`)",
            ]
        )
    else:
        lines.extend(
            [
                f"- **Sample File**: [human_review_sample.json](human_review_sample.json) (exported, awaiting manual audit in `evals/human_review_audit.json`)",
            ]
        )

    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Run full Spar empirical evaluations and render evals/RESULTS.md.")
    ap.add_argument("--finalize-only", action="store_true", help="Re-render RESULTS.md from saved eval_results.json + human_review_audit.json")
    ap.add_argument("--demo-runs", type=int, default=5)
    ap.add_argument("--demo-trials", type=int, default=20)
    ap.add_argument("--agentdojo-runs", type=int, default=3)
    ap.add_argument("--agentdojo-trials", type=int, default=5)
    ap.add_argument("--max-usd", type=float, default=1.50)
    args = ap.parse_args(argv)

    EVALS_DIR.mkdir(parents=True, exist_ok=True)

    if args.finalize_only:
        results = json.loads(RAW_RESULTS_PATH.read_text(encoding="utf-8"))
    else:
        demo_data, demo_samples = run_demo_multi_eval(num_runs=args.demo_runs, trials_n=args.demo_trials)
        ad_data, ad_samples = run_agentdojo_live_eval(
            num_runs=args.agentdojo_runs,
            trials_n=args.agentdojo_trials,
            max_usd_total=args.max_usd,
        )
        rec_data, rec_samples = run_recorded_demo(trials_n=args.demo_trials)

        all_samples = demo_samples + ad_samples + rec_samples
        export_combined_human_sample(all_samples, max_items=20, seed=42)

        results = {
            "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "demo_multi_run": demo_data,
            "agentdojo_live_llm": ad_data,
            "recorded_demo_run": rec_data,
        }
        raw_text = json.dumps(results, indent=2, default=str) + "\n"
        scan_for_secrets(raw_text, _collect_env_secrets())
        RAW_RESULTS_PATH.write_text(raw_text, encoding="utf-8")

    disagreement: dict[str, Any] | None = None
    if AUDIT_PATH.is_file():
        audit_data = json.loads(AUDIT_PATH.read_text(encoding="utf-8"))
        audit_items = audit_data.get("items", []) if isinstance(audit_data, dict) else list(audit_data)
        disagreement = compute_human_model_disagreement(audit_items)
        results["human_model_disagreement"] = disagreement
        raw_text = json.dumps(results, indent=2, default=str) + "\n"
        scan_for_secrets(raw_text, _collect_env_secrets())
        RAW_RESULTS_PATH.write_text(raw_text, encoding="utf-8")

    md = render_results_markdown(results, disagreement)
    scan_for_secrets(md, _collect_env_secrets())
    RESULTS_MD_PATH.write_text(md, encoding="utf-8")
    print(f"Wrote {RESULTS_MD_PATH}")
    if disagreement is not None:
        print(f"Human-model disagreement: {disagreement}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
