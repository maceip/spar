"""Run PyRIT's real attack executors, driven by Spar's deterministic oracle.

This replaces Spar's hand-rolled multi-turn loop with PyRIT's own ``CrescendoAttack``:
PyRIT generates and escalates the prompts through an adversarial LLM, sends them to the
target through Spar's guarded :class:`SparPyRITTarget`, and decides success with a
:class:`SparOracleScorer` (a canary / tool-log / state-diff oracle) instead of an LLM
judge. The attacker model only *writes* prompts; whether the objective was achieved is a
deterministic, reached-sink verdict.

Both model paths stay inside Spar's safety envelope:

- The attacker LLM runs through :class:`GuardedAdversarialTarget`, which calls
  ``GuardedHTTPClient.llm_chat`` -- so attacker-model requests are subject to the kill
  switch, USD / request / rate budgets, DNS and scheme safeguards, API-key redaction and
  ledger records, exactly like every other call. Nothing talks to a provider directly, and
  no process-wide TLS trust is mutated.
- The target receives every prompt through the guarded client.

Requires an adversarial LLM (``policy.llm`` with base_url + model). When none is
configured -- the keyless demo and CI -- callers fall back to Spar's deterministic recipe.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any

from pyrit.models import ComponentIdentifier, Message, MessagePiece, construct_response_from_request
from pyrit.prompt_target import PromptTarget, TargetConfiguration

from ..guard import GuardViolation
from ..oracles import TrustTier
from ..policy import CampaignPolicy, ConfigError, LLMProviderConfig
from ..target import TargetClient, TargetResponse
from .oracle_scorer import SparOracleScorer
from .pyrit_adapter import SparPyRITTarget, _run_sync, ensure_pyrit_initialized


def adversarial_configured(policy: CampaignPolicy) -> bool:
    """True when an adversarial attacker LLM is configured, so PyRIT executors can run."""
    llm = getattr(policy, "llm", None)
    return bool(llm and getattr(llm, "base_url", "") and getattr(llm, "model", ""))


class GuardedAdversarialTarget(PromptTarget):
    """A PyRIT chat target whose completions go through ``GuardedHTTPClient.llm_chat``.

    Used as Crescendo's *adversarial* (attacker) model so its calls are accounted,
    rate-limited, kill-switchable, DNS-checked, redacted and ledgered like any other Spar
    egress -- never a direct provider client. PyRIT drives the full adversarial
    conversation and passes it here each turn; this forwards it verbatim to the guard.
    """

    def __init__(
        self,
        *,
        target_client: TargetClient,
        llm_cfg: LLMProviderConfig,
        max_tokens: int = 800,
        temperature: float = 0.7,
        verbose: bool = False,
    ) -> None:
        ensure_pyrit_initialized()
        super().__init__(
            verbose=verbose,
            endpoint=str(llm_cfg.base_url or ""),
            model_name=str(llm_cfg.model or "adversarial"),
            custom_configuration=TargetConfiguration(
                capabilities=self._capabilities(),
            ),
        )
        self._target_client = target_client
        self._llm_cfg = llm_cfg
        self._max_tokens = int(max_tokens)
        self._temperature = float(temperature)

    @staticmethod
    def _capabilities() -> Any:
        from pyrit.models import TargetCapabilities

        return TargetCapabilities(
            supports_multi_turn=True,
            supports_editable_history=True,
            supports_system_prompt=True,
            supports_multi_message_pieces=True,
            input_modalities=frozenset({frozenset({"text"})}),
        )

    def _build_identifier(self) -> ComponentIdentifier:
        return self._create_identifier(params={"role": "adversarial", "via": "guarded_llm_chat"})

    @staticmethod
    def _message_to_dict(msg: Message) -> dict[str, str]:
        pieces = msg.message_pieces
        role = str(pieces[0].role) if pieces else "user"
        text = "\n".join(str(p.converted_value) for p in pieces if p.converted_value)
        return {"role": role, "content": text}

    async def _send_prompt_to_target_async(
        self, *, normalized_conversation: list[Message]
    ) -> list[Message]:
        messages = [self._message_to_dict(m) for m in normalized_conversation]
        content, _raw = self._target_client.http.llm_chat(
            messages,
            provider=self._llm_cfg,
            max_tokens=self._max_tokens,
            temperature=self._temperature,
        )
        last_piece = normalized_conversation[-1].message_pieces[0]
        return [construct_response_from_request(request=last_piece, response_text_pieces=[content or ""])]


def _verbatim_quote(candidate_text: str, resp: TargetResponse) -> dict[str, Any]:
    """A quote whose ``text`` appears verbatim inside the logged raw HTTP body.

    ``evaluate_oracle`` gates on ``_verify_quotes_in_ledger`` -> ``Ledger.has_quote_hash``,
    which searches the raw ``http.response`` body. A decoded reply (real newlines/quotes)
    is JSON-escaped there and would not be found, failing the gate. So the quote is a
    raw-body-verbatim slice (the decoded reply is carried separately as oracle evidence).
    Mirrors ``spar.attacks.recipes.make_quote`` without importing it (circular).
    """
    raw = resp.text or ""
    chosen = ""
    if candidate_text and candidate_text in raw:
        chosen = candidate_text
    elif candidate_text:
        for line in candidate_text.splitlines():
            s = line.strip()
            if s and s in raw:
                chosen = s
                break
        if not chosen:
            import re as _re

            for chunk in _re.split(r"[.!?\n]+", candidate_text):
                c = chunk.strip()
                if len(c) >= 8 and c in raw:
                    chosen = c
                    break
    if not chosen:
        chosen = raw[:280]
    return {
        "text": chosen,
        "log_seq": getattr(resp, "log_seq", None),
        "sha256": hashlib.sha256(chosen.encode("utf-8")).hexdigest(),
    }


def _steps_and_quotes(
    history: list[TargetResponse],
    sent_prompts: list[str],
    target_client: TargetClient,
    technique: str,
    account: str | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str], list[str]]:
    steps: list[dict[str, Any]] = []
    quotes: list[dict[str, Any]] = []
    distinct: list[str] = []
    reply_texts: list[str] = []
    for idx, resp in enumerate(history):
        prompt = sent_prompts[idx] if idx < len(sent_prompts) else ""
        if prompt:
            distinct.append(prompt)
        # Decoded reply: used by the oracle for the SHA-256 prompt match (carried in evidence).
        reply_text = target_client.extract_chat_reply(resp)
        if reply_text:
            reply_texts.append(reply_text)
        steps.append(
            {
                "action": "chat",
                "account": account,
                "message": prompt,
                "reply": reply_text,
                "session_id": getattr(resp, "session_id", None),
                "status": getattr(resp, "status", None),
                "log_seq": getattr(resp, "log_seq", None),
                "technique": technique,
            }
        )
        # Quote: raw-body-verbatim so _verify_quotes_in_ledger passes.
        quotes.append(_verbatim_quote(reply_text, resp))
    return steps, quotes, distinct, reply_texts


def run_multi_turn(
    objective: dict[str, Any],
    target_client: TargetClient,
    policy: CampaignPolicy,
    *,
    canary: str,
    session_id: str,
    attacker: str | None,
    max_turns: int = 6,
) -> dict[str, Any]:
    """Run PyRIT's RedTeamingAttack scored by Spar's oracle. Returns a result dict.

    RedTeamingAttack is used rather than Crescendo because it places *no* capability
    requirement on the objective target and never backtracks: the adversarial model writes
    each next prompt from the target's replies, the target's fixed server-side session is
    only ever appended to, and the Spar oracle decides success each turn. (Crescendo
    requires a target that natively supports editable history so it can rewind -- which a
    real server-side session cannot honor, so it would desync target state.)

    Keys: ``candidate_hit`` (oracle machine-confirmed), ``verdict`` (OracleVerdict|None),
    ``steps``, ``quotes``, ``distinct_prompts``, ``evidence``, ``turns``.
    """
    from pyrit.executor.attack import AttackAdversarialConfig, AttackScoringConfig
    from pyrit.executor.attack.multi_turn.red_teaming import RedTeamingAttack

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
    evidence: dict[str, Any] = {"canary": canary, "session_id": session_id, "attacker": attacker}
    params = objective.get("params") if isinstance(objective.get("params"), dict) else {}
    for key in ("expected_sha256", "prompt_truth", "victim", "auditor"):
        if params.get(key) is not None:
            evidence[key] = params[key]

    since = time.time() - 0.05
    scorer = SparOracleScorer(
        objective=objective, target_client=target_client, policy=policy, since=since, evidence=evidence
    )
    adversarial = GuardedAdversarialTarget(target_client=target_client, llm_cfg=policy.llm)

    attack = RedTeamingAttack(
        objective_target=obj_target,
        attack_adversarial_config=AttackAdversarialConfig(target=adversarial),
        attack_scoring_config=AttackScoringConfig(objective_scorer=scorer),
        max_turns=int(max_turns),
    )

    # Contain adversarial-provider failures at this boundary. A rejected key, a rate limit,
    # or an unavailable attacker endpoint raises PyRIT/OpenAI exceptions the campaign loop
    # does not classify, which would abort the whole campaign. Here any failure degrades to
    # an UNVERIFIED trial over whatever turns completed: the oracle's own target traffic
    # (not the attacker model) already went through the guard, so partial evidence stands,
    # and the trial is marked inconclusive rather than crashing the run.
    error: str | None = None
    result = None
    try:
        result = _run_sync(attack.execute_async(objective=obj_text))
    except (GuardViolation, ConfigError):
        raise  # guard/scope/config failures are the loop's to classify as inconclusive
    except Exception as exc:  # provider/transport failure: record, do not propagate
        error = f"{type(exc).__name__}: {str(exc)[:200]}"

    verdict = scorer.last_verdict
    candidate_hit = bool(verdict and verdict.matched and verdict.trust_tier == TrustTier.MACHINE_CONFIRMED)
    steps, quotes, distinct, reply_texts = _steps_and_quotes(
        obj_target.history, obj_target.sent_prompts, target_client, technique, attacker
    )
    return {
        "candidate_hit": candidate_hit,
        "verdict": verdict,
        "steps": steps,
        "quotes": quotes,
        "distinct_prompts": distinct,
        "reply_texts": reply_texts,
        "evidence": evidence,
        "turns": len(obj_target.history),
        "attack_outcome": getattr(result, "outcome", None),
        "error": error,
    }
