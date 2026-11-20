"""Mission runtime: fresh-context, single-objective, short-lived workers.

A worker receives ONE objective and the core tools, executes its mission,
writes structured evidence (including replayable PoC steps), and
terminates immediately. Nothing is carried between trials.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from .tools import ToolKit


@dataclass
class MissionContext:
    objective: dict
    toolkit: ToolKit
    base_url: str
    trial_index: int
    canary: str = field(default_factory=lambda: "SPAR-" + secrets.token_hex(2))
    started_at: float = field(default_factory=time.time)
    ledger: Any = None
    kill: Any = None

    @property
    def params(self) -> dict:
        return self.objective.get("params", {})

    @property
    def accounts(self) -> dict:
        return self.objective.get("accounts", {"attacker": "alice", "victim": "bob"})


@dataclass
class MissionResult:
    technique: str
    candidate_hit: bool
    evidence: dict
    steps: list[dict]          # replayable PoC steps (critic + pytest replay these)
    notes: str = ""
    unverified: bool = False   # candidate lacks deterministic ground truth


MISSIONS: dict[str, Any] = {}


def register(technique: str):
    def deco(cls):
        MISSIONS[technique] = cls
        cls.technique = technique
        return cls
    return deco


def run_mission(objective: dict, toolkit: ToolKit, base_url: str, trial_index: int, ledger=None, kill=None) -> MissionResult:
    technique = objective["technique"]
    cls = MISSIONS.get(technique)
    if cls is None:
        raise KeyError(f"no mission registered for technique {technique!r}")
    mctx = MissionContext(objective=objective, toolkit=toolkit, base_url=base_url, trial_index=trial_index, ledger=ledger, kill=kill)
    worker = cls()
    result = worker.run(mctx)
    if ledger:
        ledger.append(
            "mission.result",
            {
                "technique": technique,
                "objective_id": objective["id"],
                "trial": trial_index,
                "candidate_hit": result.candidate_hit,
                "unverified": result.unverified,
                "evidence_keys": sorted(result.evidence.keys()),
            },
        )
    return result


# Import missions so they register themselves.
from . import missions  # noqa: E402,F401
