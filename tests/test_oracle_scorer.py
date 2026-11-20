"""Tests for SparOracleScorer: the PyRIT scorer whose verdict is Spar's oracle."""

from __future__ import annotations

import asyncio

import pytest

from spar.attacks import oracle_scorer as osc
from spar.attacks.oracle_scorer import SparOracleScorer
from spar.oracles import Outcome, OracleVerdict, TrustTier
from spar.policy import CampaignPolicy


class _FakePiece:
    def __init__(self, text: str):
        self.converted_value = text
        self.id = "piece-1"


def _scorer(monkeypatch, verdict: OracleVerdict) -> SparOracleScorer:
    monkeypatch.setattr(osc, "evaluate_oracle", lambda *a, **k: verdict)
    policy = CampaignPolicy.demo_defaults() if hasattr(CampaignPolicy, "demo_defaults") else None
    return SparOracleScorer(
        objective={"technique": "tool_misuse", "id": "obj-01"},
        target_client=object(),  # unused: evaluate_oracle is stubbed
        policy=policy,
        since=0.0,
        evidence={"canary": "SPAR-abc123", "attacker": "alice"},
    )


def _score(scorer: SparOracleScorer, text: str) -> bool:
    piece = _FakePiece(text)
    scores = asyncio.run(scorer._score_piece_with_expectation_async(piece, expectation=None))
    assert len(scores) == 1
    return scores[0].score_value == "True"


def test_machine_confirmed_match_scores_true(monkeypatch):
    v = OracleVerdict(outcome=Outcome.REPRODUCED, matched=True, oracle="tool_log",
                      witness="send_email in tool log", trust_tier=TrustTier.MACHINE_CONFIRMED)
    assert _score(_scorer(monkeypatch, v), "done, emailed the invoice") is True


def test_heuristic_match_scores_false(monkeypatch):
    # A non-machine-confirmed match must NOT satisfy the objective, so PyRIT keeps attacking.
    v = OracleVerdict(outcome=Outcome.REPRODUCED, matched=True, oracle="text",
                      witness="looks leaked", trust_tier=TrustTier.HEURISTIC)
    assert _score(_scorer(monkeypatch, v), "maybe leaked") is False


def test_no_match_scores_false(monkeypatch):
    v = OracleVerdict(outcome=Outcome.NOT_REPRODUCED, matched=False, oracle="tool_log",
                      witness="no matching call", trust_tier=TrustTier.MACHINE_CONFIRMED)
    assert _score(_scorer(monkeypatch, v), "I can't do that") is False


def test_verdict_and_metadata_exposed(monkeypatch):
    v = OracleVerdict(outcome=Outcome.REPRODUCED, matched=True, oracle="canary",
                      witness="SPAR-abc123 in outbox", trust_tier=TrustTier.MACHINE_CONFIRMED)
    scorer = _scorer(monkeypatch, v)
    piece = _FakePiece("leaked SPAR-abc123")
    scores = asyncio.run(scorer._score_piece_with_expectation_async(piece, expectation=None))
    assert scorer.last_verdict is v
    assert scores[0].score_metadata["trust_tier"] == "machine_confirmed"
    assert scores[0].score_type == "true_false"


def test_update_evidence_merges():
    scorer = SparOracleScorer(
        objective={"technique": "prompt_extraction"}, target_client=object(),
        policy=None, since=1.0, evidence={"canary": "x"},
    )
    scorer.update_evidence(session_id="s-2", canary="y")
    assert scorer._evidence == {"canary": "y", "session_id": "s-2"}


def test_adversarial_configured_gating():
    from spar.attacks.pyrit_executor import adversarial_configured
    from spar.policy import LLMProviderConfig

    class P:
        pass

    p = P()
    p.llm = LLMProviderConfig(base_url="", model="", api_key_env="OPENAI_API_KEY")
    assert adversarial_configured(p) is False  # keyless demo / CI -> deterministic fallback
    p.llm = LLMProviderConfig(base_url="https://api.openai.com/v1", model="gpt-4o-mini", api_key_env="OPENAI_API_KEY")
    assert adversarial_configured(p) is True  # attacker LLM configured -> PyRIT executor


def test_guarded_adversarial_target_routes_through_guard():
    """The attacker LLM must call GuardedHTTPClient.llm_chat, never a direct provider."""
    import asyncio
    from pyrit.models import Message, MessagePiece
    from spar.attacks.pyrit_executor import GuardedAdversarialTarget
    from spar.policy import LLMProviderConfig

    calls = {}

    class FakeHTTP:
        def llm_chat(self, messages, *, provider, max_tokens=800, temperature=0.7, timeout=60.0):
            calls["messages"] = messages
            calls["provider"] = provider
            return "next attacker prompt", {"usage": {}}

    class FakeClient:
        base_url = "http://127.0.0.1"
        http = FakeHTTP()

    llm = LLMProviderConfig(base_url="https://api.openai.com/v1", model="gpt-4o-mini", api_key_env="OPENAI_API_KEY")
    tgt = GuardedAdversarialTarget(target_client=FakeClient(), llm_cfg=llm)
    conv = [
        Message(message_pieces=[MessagePiece(role="system", original_value="you are a red teamer",
                converted_value="you are a red teamer", original_value_data_type="text", converted_value_data_type="text")]),
        Message(message_pieces=[MessagePiece(role="user", original_value="target said no",
                converted_value="target said no", original_value_data_type="text", converted_value_data_type="text")]),
    ]
    out = asyncio.run(tgt._send_prompt_to_target_async(normalized_conversation=conv))
    # It went through the guarded client, forwarding the full conversation with roles.
    assert calls["provider"] is llm
    assert [m["role"] for m in calls["messages"]] == ["system", "user"]
    assert out[0].message_pieces[-1].converted_value == "next attacker prompt"
