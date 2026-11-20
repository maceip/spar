"""N-trial runner: empirical k/N success-rate calibration.

Every trial gets a fresh mission context (fresh canary, fresh transcript).
If the target exposes a sandbox reset control (auditor-gated), state is
restored between trials; otherwise trials remain independent via unique
per-trial identifiers.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable

from ..fire.tools import ToolKit
from ..fire.worker import MissionResult, run_mission
from .oracles import OracleVerdict, evaluate_oracle


@dataclass
class TrialRecord:
    index: int
    candidate_hit: bool
    oracle_matched: bool
    oracle_witness: str
    canary: str
    duration_s: float
    result: MissionResult | None = None


@dataclass
class TrialOutcome:
    objective_id: str
    k: int
    n: int
    trials: list[TrialRecord] = field(default_factory=list)
    resettable: bool = False

    @property
    def best(self) -> MissionResult | None:
        for t in self.trials:
            if t.oracle_matched and t.result is not None:
                return t.result
        return None

    @property
    def success_rate(self) -> float:
        return self.k / self.n if self.n else 0.0


class TrialRunner:
    def __init__(self, tk: ToolKit, base_url: str, ledger, kill, n_default: int = 20):
        self.tk = tk
        self.base_url = base_url
        self.ledger = ledger
        self.kill = kill
        self.n_default = n_default
        self._resettable: bool | None = None

    def reset_target(self) -> bool:
        """Try the auditor-gated sandbox reset. Detected once."""
        if self._resettable is None:
            try:
                status, _ = self.tk.http_json(
                    "POST", self.base_url.rstrip("/") + "/audit/reset",
                    account="auditor", technique="sandbox-reset", risk_tier="read-only",
                )
                self._resettable = status == 200
            except Exception:
                self._resettable = False
        if self._resettable:
            self.tk.http_json("POST", self.base_url.rstrip("/") + "/audit/reset",
                              account="auditor", technique="sandbox-reset", risk_tier="read-only")
        return self._resettable

    def run(self, objective: dict) -> TrialOutcome:
        n = int(objective.get("trials", self.n_default))
        outcome = TrialOutcome(objective_id=objective["id"], k=0, n=n)
        for i in range(n):
            self.kill.check()
            self.reset_target()
            since = time.time()
            t0 = time.time()
            result = run_mission(objective, self.tk, self.base_url, i, ledger=self.ledger, kill=self.kill)
            if result.candidate_hit:
                verdict = evaluate_oracle(objective, result, self.tk, self.base_url, since)
            else:
                verdict = OracleVerdict(False, objective["oracle"]["type"], "worker reported no candidate hit")
            rec = TrialRecord(
                index=i,
                candidate_hit=result.candidate_hit,
                oracle_matched=verdict.matched,
                oracle_witness=verdict.witness,
                canary=result.evidence.get("canary", ""),
                duration_s=round(time.time() - t0, 3),
                result=result if verdict.matched else None,
            )
            outcome.trials.append(rec)
            if verdict.matched:
                outcome.k += 1
            self.ledger.append(
                "trial.result",
                {
                    "objective_id": objective["id"],
                    "trial": i,
                    "candidate_hit": result.candidate_hit,
                    "oracle": verdict.oracle,
                    "oracle_matched": verdict.matched,
                    "witness": verdict.witness,
                    "unverified": result.unverified,
                },
                origin_id=objective["id"],
            )
        outcome.resettable = bool(self._resettable)
        return outcome
