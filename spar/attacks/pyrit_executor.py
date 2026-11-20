"""Run PyRIT's real attack executors, driven by Spar's deterministic oracle.

This replaces Spar's hand-rolled multi-turn loop with PyRIT's own ``CrescendoAttack``:
PyRIT generates and escalates the prompts through an adversarial LLM, sends them to the
target through Spar's guarded :class:`SparPyRITTarget`, and decides success with a
:class:`SparOracleScorer` (a canary / tool-log / state-diff oracle) instead of an LLM
judge. The attacker model is only used to *write* prompts; whether the objective was
achieved is a deterministic, reached-sink verdict.

Requires an adversarial LLM (``policy.llm`` with base_url + model). When none is
configured -- e.g. the keyless demo and CI -- callers fall back to Spar's deterministic
recipe. :func:`adversarial_configured` reports which path is available.
"""

from __future__ import annotations

import hashlib
import os
import time
from typing import Any

from ..oracles import TrustTier
from ..policy import CampaignPolicy, LLMProviderConfig
from ..target import TargetClient, TargetResponse
from .oracle_scorer import SparOracleScorer
from .pyrit_adapter import SparPyRITTarget, _run_sync, ensure_pyrit_initialized

# The agent proxy terminates TLS with its own CA; PyRIT's httpx/openai client must trust
# it. Set once, without overriding an operator's explicit choice.
_CA_BUNDLE = "/root/.ccr/ca-bundle.crt"
if os.path.exists(_CA_BUNDLE):
    os.environ.setdefault("SSL_CERT_FILE", _CA_BUNDLE)
    os.environ.setdefault("REQUESTS_CA_BUNDLE", _CA_BUNDLE)


def adversarial_configured(policy: CampaignPolicy) -> bool:
    """True when an adversarial attacker LLM is configured, so PyRIT executors can run."""
    llm = getattr(policy, "llm", None)
    return bool(llm and getattr(llm, "base_url", "") and getattr(llm, "model", ""))


def build_adversarial_target(llm: LLMProviderConfig) -> Any:
    """Construct a PyRIT OpenAI-compatible chat target for the attacker LLM."""
    from pyrit.prompt_target.openai.openai_chat_target import OpenAIChatTarget

    api_key = ""
    env = (llm.api_key_env or "").strip()
    if env:
        api_key = os.environ.get(env, "")
    # PyRIT appends "/chat/completions"; pass the base (e.g. https://api.openai.com/v1).
    endpoint = (llm.base_url or "").rstrip("/")
    if endpoint.endswith("/chat/completions"):
        endpoint = endpoint[: -len("/chat/completions")]
    return OpenAIChatTarget(
        endpoint=endpoint,
        api_key=api_key or "unused",
        model_name=llm.model,
        temperature=0.7,
    )


def _responses_to_steps(history: list[TargetResponse], technique: str, account: str | None) -> tuple[
    list[dict[str, Any]], list[dict[str, Any]], list[str]
]:
    steps: list[dict[str, Any]] = []
    quotes: list[dict[str, Any]] = []
    distinct: list[str] = []
    for resp in history:
        reply_text = ""
        try:
            reply_text = resp.reply.text if getattr(resp, "reply", None) else ""
        except Exception:
            reply_text = getattr(resp, "text", "") or ""
        steps.append(
            {
                "action": "chat",
                "account": account,
                "session_id": getattr(resp, "session_id", None),
                "status": getattr(resp, "status", None),
                "log_seq": getattr(resp, "log_seq", None),
                "technique": technique,
            }
        )
        qtxt = reply_text or (getattr(resp, "text", "") or "")[:240]
        quotes.append(
            {
                "text": qtxt,
                "log_seq": getattr(resp, "log_seq", None),
                "sha256": hashlib.sha256(qtxt.encode("utf-8")).hexdigest(),
            }
        )
    return steps, quotes, distinct


def run_crescendo(
    objective: dict[str, Any],
    target_client: TargetClient,
    policy: CampaignPolicy,
    *,
    canary: str,
    session_id: str,
    attacker: str | None,
    max_turns: int = 6,
    max_backtracks: int = 3,
) -> dict[str, Any]:
    """Run PyRIT's CrescendoAttack scored by Spar's oracle. Returns a result dict.

    Keys: ``candidate_hit`` (oracle machine-confirmed), ``verdict`` (OracleVerdict|None),
    ``steps``, ``quotes``, ``distinct_prompts``, ``evidence``, ``turns``.
    """
    from pyrit.executor.attack import AttackAdversarialConfig, AttackScoringConfig
    from pyrit.executor.attack.multi_turn.crescendo import CrescendoAttack

    ensure_pyrit_initialized()
    technique = str(objective.get("technique") or "")
    obj_text = str(objective.get("objective") or technique or "Achieve the stated objective")

    obj_target = SparPyRITTarget(
        target_client=target_client,
        account=attacker,
        session_id=session_id,
        technique=technique,
        risk_tier=str(objective.get("risk_tier") or "read-only"),
    )
    evidence: dict[str, Any] = {
        "canary": canary,
        "session_id": session_id,
        "attacker": attacker,
    }
    params = objective.get("params") if isinstance(objective.get("params"), dict) else {}
    for key in ("expected_sha256", "prompt_truth", "victim", "auditor"):
        if params.get(key) is not None:
            evidence[key] = params[key]

    since = time.time() - 0.05
    scorer = SparOracleScorer(
        objective=objective,
        target_client=target_client,
        policy=policy,
        since=since,
        evidence=evidence,
    )
    adversarial = build_adversarial_target(policy.llm)

    attack = CrescendoAttack(
        objective_target=obj_target,
        attack_adversarial_config=AttackAdversarialConfig(target=adversarial),
        attack_scoring_config=AttackScoringConfig(objective_scorer=scorer),
        max_turns=int(max_turns),
        max_backtracks=int(max_backtracks),
    )

    result = _run_sync(attack.execute_async(objective=obj_text))

    verdict = scorer.last_verdict
    candidate_hit = bool(verdict and verdict.matched and verdict.trust_tier == TrustTier.MACHINE_CONFIRMED)
    steps, quotes, distinct = _responses_to_steps(obj_target.history, technique, attacker)
    return {
        "candidate_hit": candidate_hit,
        "verdict": verdict,
        "steps": steps,
        "quotes": quotes,
        "distinct_prompts": distinct or [s.get("message", "") for s in steps],
        "evidence": evidence,
        "turns": len(obj_target.history),
        "attack_outcome": getattr(result, "outcome", None),
    }
