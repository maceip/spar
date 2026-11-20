"""The deterministic coordinator run loop.

Owns the live attack graph, enforces spar.yaml scope and budgets, manages
leased task execution (fire → critic → report follow-ons), handles durable
waits, and gates findings. Control flow is code — never an LLM.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..aim import build_plan, index_repo, run_recon
from ..aim.plan import write_plan
from ..config import SparConfig
from ..fire.tools import ToolKit
from ..guard import Budget, GuardViolation, HookContext, KillSwitch, ScopeGuard
from ..report.dedupe import dedupe_findings
from ..report.fixdiff import synthesize_fix
from ..report.model import Finding, calibrate_severity
from ..report.pytest_gen import emit_pytest_suite
from ..report.report import emit_report, redact
from ..prove.critic import Critic
from ..prove.trials import TrialRunner
from .graph import AttackGraph
from .leases import TaskBoard
from .ledger import Ledger


@dataclass
class RunOptions:
    target_url: str
    config: SparConfig
    run_dir: Path = Path(".spar")
    repo: Path | None = None
    demo_mode: bool = False
    trials_n: int | None = None


@dataclass
class RunSummary:
    findings: list[Finding] = field(default_factory=list)
    rejected: list[dict] = field(default_factory=list)
    plan: dict = field(default_factory=dict)
    recon: dict = field(default_factory=dict)
    budget: dict = field(default_factory=dict)
    report_path: Path | None = None
    tests_path: Path | None = None
    run_dir: Path = Path(".spar")
    started_at: float = field(default_factory=time.time)
    finished_at: float = field(default_factory=time.time)


class Campaign:
    def __init__(self, opts: RunOptions):
        self.opts = opts
        self.run_dir = Path(opts.run_dir)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        (self.run_dir / "findings").mkdir(exist_ok=True)
        self.ledger = Ledger(self.run_dir)
        self.board = TaskBoard(self.run_dir / "state.db")
        self.graph = AttackGraph(self.run_dir / "state.db")
        self.kill = KillSwitch(self.run_dir / "STOP")
        self.budget = Budget(
            opts.config.max_usd, opts.config.max_requests,
            opts.config.max_duration_s, opts.config.rate_per_min,
        )
        self.scope = ScopeGuard(opts.config.allowlist_hosts, opts.config.allow_risky or opts.demo_mode)
        self.hook_ctx = HookContext(
            scope=self.scope, budget=self.budget, kill=self.kill,
            ledger=self.ledger, sandboxed_target=opts.demo_mode,
        )
        self.accounts = {a.name: a.token for a in opts.config.accounts}
        self.tk = ToolKit(self.hook_ctx, self.accounts, repo=opts.repo, llm_cfg=opts.config.llm)
        self.trials = TrialRunner(self.tk, opts.target_url, self.ledger, self.kill,
                                  n_default=opts.trials_n or opts.config.trials_n)
        self.critic = Critic(self.tk, opts.target_url, self.ledger, self.kill, self.trials.reset_target)

    # ------------------------------------------------------------------
    def run(self) -> RunSummary:
        opts = self.opts
        summary = RunSummary(run_dir=self.run_dir)
        self.kill.install_signal()
        self.ledger.append("campaign.start", {
            "target": opts.target_url, "repo": str(opts.repo) if opts.repo else None,
            "demo_mode": opts.demo_mode, "trials_n": opts.trials_n or opts.config.trials_n,
            "tools_available": self.tk.available_tools(),
        })
        try:
            # 1. AIM: white-box index (if repo) + live black-box recon.
            index = index_repo(opts.repo) if opts.repo else None
            if index:
                self.ledger.append("aim.index", {k: (len(v) if isinstance(v, list) else v) for k, v in index.items()})
                for p in index.get("prompts", []):
                    self.graph.add_surface(f"prompt:{p['sha256'][:12]}", "prompt", p, "repo-index")
                for r in index.get("routes", []):
                    self.graph.add_surface(f"route:{r['path']}", "route", r, "repo-index")
            recon = run_recon(self.tk.http, self.graph, self.accounts, opts.target_url)
            summary.recon = recon
            self.ledger.append("aim.recon", {
                "probes": len(recon["probes"]), "tools": [t.get("name") for t in recon["tools"]],
                "retrieval_sources": recon["retrieval_sources"],
                "permission_anomalies": recon["permission_anomalies"],
            })

            # 2. PLAN: ranked objectives → plan.json + attack-graph intents.
            plan = build_plan(recon, index, opts.target_url, opts.trials_n or opts.config.trials_n, opts.repo)
            summary.plan = plan
            plan_path = write_plan(plan, self.run_dir)
            self.ledger.append("plan.built", {"path": str(plan_path), "objectives": [o["id"] for o in plan["objectives"]]})
            for obj in plan["objectives"]:
                self.graph.add_intent(obj["id"], obj["surface_ids"][0] if obj["surface_ids"] else None,
                                      obj["objective"], obj["technique"], obj["risk_tier"], obj["rank"], obj)

            # 3. FIRE: post one leased task per objective; deterministic loop.
            #    4. PROVE: independent critic judges every candidate.
            # A budget/scope violation halts attacking gracefully: whatever
            # was already proven still gets a full report.
            findings: list[Finding] = []
            rejected: list[dict] = []
            outcomes: dict[str, object] = {}
            halt_reason: str | None = None
            for obj in plan["objectives"]:
                self.board.post("fire", {"objective_id": obj["id"]}, origin_id=obj["id"])
            fid = 0
            try:
                while True:
                    self.kill.check()
                    lease = self.board.own("fire")
                    if lease is None:
                        break
                    obj_id = lease.payload["objective_id"]
                    obj = next(o for o in plan["objectives"] if o["id"] == obj_id)
                    self.ledger.append("lease.own", {"task": lease.task_id, "kind": "fire", "objective_id": obj_id},
                                       origin_id=obj_id, task_id=lease.task_id)
                    self.graph.set_intent_state(obj_id, "attacking")
                    outcome = self.trials.run(obj)
                    outcomes[obj_id] = outcome
                    follow = [("critic", {"objective_id": obj_id})] if outcome.best is not None else []
                    self.board.consume(
                        lease,
                        {"k": outcome.k, "n": outcome.n, "resettable": outcome.resettable},
                        follow_ons=follow,
                    )
                    self.ledger.append("lease.consume", {
                        "task": lease.task_id, "k": outcome.k, "n": outcome.n,
                        "follow_ons": [k for k, _ in follow],
                    }, origin_id=obj_id, task_id=lease.task_id)
                    if outcome.best is None:
                        self.graph.set_intent_state(obj_id, "exhausted", k=outcome.k, n=outcome.n)

                while True:
                    self.kill.check()
                    lease = self.board.own("critic")
                    if lease is None:
                        break
                    obj_id = lease.payload["objective_id"]
                    obj = next(o for o in plan["objectives"] if o["id"] == obj_id)
                    outcome = outcomes[obj_id]
                    self.ledger.append("lease.own", {"task": lease.task_id, "kind": "critic", "objective_id": obj_id},
                                       origin_id=obj_id, task_id=lease.task_id)
                    verdict = self.critic.judge(obj, outcome)
                    candidate_hits = sum(1 for t in outcome.trials if t.candidate_hit)
                    if verdict.confirmed and outcome.best is not None:
                        fid += 1
                        finding = self._gate_finding(fid, obj, outcome, verdict)
                        findings.append(finding)
                        self.graph.set_intent_state(obj_id, "proven", k=outcome.k, n=outcome.n)
                        self.board.consume(lease, {"confirmed": True, "finding_id": finding.id})
                    else:
                        reason = verdict.reason if not verdict.confirmed else "critic confirmed but no verified trial"
                        rejected.append({"objective_id": obj_id, "reason": reason, "candidate_hits": candidate_hits})
                        self.graph.set_intent_state(obj_id, "refuted", k=outcome.k, n=outcome.n)
                        self.board.consume(lease, {"confirmed": False, "reason": reason})
            except GuardViolation as exc:
                halt_reason = str(exc)
                self.ledger.append("campaign.halt", {"reason": halt_reason})
                self.board.cancel_all(halt_reason)

            # 5. REPORT: dedupe, fix diffs, markdown, failing pytest suite.
            findings = dedupe_findings(findings)
            summary.findings = findings
            summary.rejected = rejected
            summary.budget = self.budget.summary()
            summary.finished_at = time.time()
            summary.report_path = emit_report(
                findings, rejected, plan, recon, summary.budget,
                self.run_dir, str(opts.repo) if opts.repo else None, opts.target_url,
                halt=halt_reason,
            )
            if findings:
                summary.tests_path = emit_pytest_suite(findings, Path("spar_tests"), self.accounts)
            self.ledger.append("campaign.finish", {
                "findings": [f.id for f in findings], "rejected": len(rejected),
                "budget": summary.budget,
                "duration_min": round((summary.finished_at - summary.started_at) / 60, 1),
            })
            return summary
        except KeyboardInterrupt:
            cancelled = self.board.cancel_all("kill switch")
            self.ledger.append("cancellation", {"revoked_leases": cancelled, "reason": "stop file or Ctrl-C"})
            raise
        finally:
            self.kill.uninstall_signal()

    # ------------------------------------------------------------------
    def _gate_finding(self, fid: int, obj: dict, outcome, verdict) -> Finding:
        best = outcome.best
        evidence = dict(best.evidence)
        evidence["attacker_account"] = obj["accounts"]["attacker"]
        evidence["victim_account"] = obj["accounts"]["victim"]
        chained = bool(evidence.get("chain"))
        severity = calibrate_severity(obj["technique"], outcome.success_rate, chained)
        finding_id = f"F-{fid:03d}-{obj['technique'].replace('_', '-')}"
        diff, pairs, guidance = synthesize_fix(obj["technique"], self.opts.repo)
        f = Finding(
            id=finding_id,
            objective=obj["objective"],
            objective_id=obj["id"],
            technique=obj["technique"],
            severity=severity,
            k=outcome.k,
            n=outcome.n,
            witness=verdict.replay_witness or best.evidence.get("witness", "") or self._trial_witness(outcome),
            oracle=obj["oracle"]["type"],
            tags=obj.get("tags", []),
            critic_reason=verdict.reason,
            evidence=evidence,
            steps=best.steps,
            chain=evidence.get("chain", []),
            fix_diff=diff,
            fix_files=[str(p) for p, _, _ in pairs],
        )
        if diff is None:
            f.evidence["remediation_guidance"] = guidance
        # persist finding (redacted) under .spar/findings/<id>.json
        blob = {
            "id": f.id, "objective": f.objective, "objective_id": f.objective_id,
            "technique": f.technique, "severity": f.severity, "k": f.k, "n": f.n,
            "witness": f.witness, "oracle": f.oracle, "tags": f.tags,
            "critic_reason": f.critic_reason, "evidence": redact(f.evidence),
            "steps": f.steps, "chain": f.chain, "fix_diff": f.fix_diff,
            "label": f.label, "snapshot_id": None,
        }
        path = self.run_dir / "findings" / f"{f.id}.json"
        path.write_text(json.dumps(blob, indent=2, default=str), encoding="utf-8")
        try:
            path.chmod(0o600)
        except OSError:
            pass
        self.ledger.append("finding.gated", {
            "finding_id": f.id, "severity": f.severity, "k": f.k, "n": f.n,
            "witness": f.witness, "has_fix_diff": diff is not None,
        }, origin_id=f.objective_id)
        return f

    @staticmethod
    def _trial_witness(outcome) -> str:
        for t in outcome.trials:
            if t.oracle_matched:
                return t.oracle_witness
        return ""
