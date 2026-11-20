"""A PyRIT scorer whose verdict is Spar's deterministic oracle, not a model judge.

This is the bridge that lets a real PyRIT attack executor (Crescendo, TAP, PAIR,
PromptSending) be *driven by Spar's oracles*: PyRIT's multi-turn loop asks its
``objective_scorer`` whether the objective was achieved and whether to keep
escalating. By default that scorer is an LLM judge (``SelfAskScaleScorer``), whose
verdict "always carries a chance of false positives". ``SparOracleScorer`` replaces it
with :func:`spar.oracles.evaluate_oracle` -- a canary / tool-log / state-diff check
against the live target's witness state -- so the executor escalates until a
deterministic oracle confirms success, and a finding rests on reached-sink evidence
rather than a model's opinion.

The scorer returns True only on a ``MACHINE_CONFIRMED`` oracle match; a heuristic or
unverified verdict scores False, keeping PyRIT attacking rather than declaring victory.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pyrit.models import ComponentIdentifier, MessagePiece, Score, ScoringExpectation
from pyrit.score.scorer_prompt_validator import ScorerPromptValidator
from pyrit.score.true_false.true_false_score_aggregator import (
    TrueFalseAggregatorFunc,
    TrueFalseScoreAggregator,
)
from pyrit.score.true_false.true_false_scorer import MessageTrueFalseScorer

from ..oracles import OracleVerdict, TrustTier, evaluate_oracle
from ..policy import CampaignPolicy
from ..target import TargetClient


@dataclass
class _OracleInput:
    """Minimal ``result`` shape that :func:`evaluate_oracle` reads (technique + evidence)."""

    technique: str
    evidence: dict[str, Any] = field(default_factory=dict)


class SparOracleScorer(MessageTrueFalseScorer):
    """PyRIT true/false scorer backed by Spar's deterministic oracle.

    Constructed per attack with the objective and the live evidence context (canary,
    accounts, session id) the oracle needs; scoring a target reply runs the oracle
    against the target's witness state recorded since ``since``.
    """

    _DEFAULT_VALIDATOR: ScorerPromptValidator = ScorerPromptValidator(supported_data_types=["text"])

    def __init__(
        self,
        *,
        objective: dict[str, Any],
        target_client: TargetClient,
        policy: CampaignPolicy,
        since: float,
        evidence: dict[str, Any] | None = None,
        aggregator: TrueFalseAggregatorFunc = TrueFalseScoreAggregator.OR,
        validator: ScorerPromptValidator | None = None,
    ) -> None:
        self._objective = dict(objective)
        self._technique = str(objective.get("technique") or "")
        self._target_client = target_client
        self._policy = policy
        self._since = float(since)
        self._evidence = dict(evidence or {})
        self._last_verdict: OracleVerdict | None = None
        super().__init__(score_aggregator=aggregator, validator=validator or self._DEFAULT_VALIDATOR)

    def _build_identifier(self) -> ComponentIdentifier:
        return self._create_identifier(
            params={"technique": self._technique, "oracle": "spar.evaluate_oracle"},
            score_aggregator=self._score_aggregator.__name__,  # type: ignore[ty:unresolved-attribute]
        )

    @property
    def last_verdict(self) -> OracleVerdict | None:
        """The most recent oracle verdict, for callers that need the evidence/details."""
        return self._last_verdict

    def update_evidence(self, **fields: Any) -> None:
        """Merge new evidence (e.g. a fresh session id or canary) between turns."""
        self._evidence.update(fields)

    async def _score_piece_with_expectation_async(
        self, message_piece: MessagePiece, *, expectation: ScoringExpectation | None
    ) -> list[Score]:
        reply_text = message_piece.converted_value or ""
        evidence = dict(self._evidence)
        evidence.setdefault("reply_text", reply_text)
        result = _OracleInput(technique=self._technique, evidence=evidence)

        verdict = evaluate_oracle(
            self._objective, result, self._target_client, self._policy, self._since
        )
        self._last_verdict = verdict
        succeeded = bool(verdict.matched and verdict.trust_tier == TrustTier.MACHINE_CONFIRMED)

        objective = expectation.objective if expectation else None
        return [
            Score(
                score_value=str(succeeded),
                score_value_description=f"spar oracle {verdict.oracle}: matched={verdict.matched}",
                score_metadata={"trust_tier": verdict.trust_tier.value, "witness": verdict.witness},
                score_type="true_false",
                score_category=[self._technique] if self._technique else [],
                score_rationale=f"witness={verdict.witness}; outcome={verdict.outcome.value}",
                scorer_class_identifier=self.get_identifier(),
                message_piece_id=message_piece.id,
                objective=objective,
            )
        ]
