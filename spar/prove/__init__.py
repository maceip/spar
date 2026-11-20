"""spar/prove/: verification & re-attack.

An attack worker cannot confirm its own finding. Deterministic oracles and
an independent context-isolated critic attempt to REFUTE every claim, and
the N-trial runner measures empirical k/N success rates.
"""

from .oracles import evaluate_oracle, OracleVerdict
from .trials import TrialRunner, TrialOutcome
from .critic import Critic, CriticVerdict, replay_steps

__all__ = ["evaluate_oracle", "OracleVerdict", "TrialRunner", "TrialOutcome", "Critic", "CriticVerdict", "replay_steps"]
