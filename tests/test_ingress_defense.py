"""Ingress tests: data the host receives is only a finding if the host acted on it and nothing saw it.

Each case runs against the same reference target that really fetches, really reports the reply
it received, and really exports kernel-obs-shaped records. The ingestion proof therefore comes
from the target's own tool result, not from Spar's opinion about what it probably read.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from spar.attacks.ingress_missions import INGRESS_MISSIONS
from spar.egress import REPLY_SIZE_SLOTS, filler_body, reply_for_content, reply_for_symbol
from spar.oracles import Outcome
from tests.test_egress_defense import EgressEnv, _defense, _make_env

TECHNIQUES = list(INGRESS_MISSIONS)


@pytest.fixture
def ingress_env(tmp_path: Path) -> Iterator[EgressEnv]:
    for env in _make_env(tmp_path, defense=_defense()):
        yield env


def test_reply_builders_are_exact() -> None:
    for size in REPLY_SIZE_SLOTS:
        body = filler_body(size)
        assert len(body) == size
        assert body.startswith(b'{"ok":true') and body.endswith(b'"}')
    header_reply = reply_for_content("abc123", "header")
    assert header_reply["headers"]["X-Spar-Data"] == "abc123"  # type: ignore[index]
    body_reply = reply_for_content("abc123", "body")
    assert b"abc123" in body_reply["body"]  # type: ignore[operator]
    for symbol in range(len(REPLY_SIZE_SLOTS)):
        reply = reply_for_symbol(symbol)
        assert len(reply["body"]) == REPLY_SIZE_SLOTS[symbol]  # type: ignore[arg-type]


def test_reply_content_carrier_reaches_the_host_unflagged(ingress_env: EgressEnv) -> None:
    mission, verdict = ingress_env.trial("reply_content_carrier", trial=0)
    variant = mission.evidence["variant"]
    assert variant["channel"] == "header"
    assert mission.evidence["receipt_count"] > 0, "the target never made a request"
    arrival = verdict.details["arrival"]
    assert arrival["reason"] == "carrier_echoed_by_the_target", arrival
    assert arrival["field"] == "header"
    assert verdict.details["flags"] == [], verdict.details["flags"]
    assert verdict.outcome is Outcome.REPRODUCED
    assert verdict.trust_tier.value == "machine_confirmed"
    assert verdict.details["direction"] == "ingress"


def test_reply_content_carrier_is_caught_by_a_content_reading_shield(tmp_path: Path) -> None:
    strict = _defense(detectors={"content_inspection": True})
    for env in _make_env(tmp_path, defense=strict):
        _mission, verdict = env.trial("reply_content_carrier", trial=1)
        assert verdict.details["arrival"]["reason"] == "carrier_echoed_by_the_target"
        assert any(f["detector"] == "content_inspection_saw_carrier" for f in verdict.details["flags"])
        assert verdict.outcome is Outcome.NOT_REPRODUCED


def test_reply_length_carrier_survives_a_metadata_observer(ingress_env: EgressEnv) -> None:
    mission, verdict = ingress_env.trial("reply_length_carrier", trial=0)
    arrival = verdict.details["arrival"]
    assert arrival["decoded_digest"] == arrival["expected_digest"], arrival
    assert len(arrival["sizes"]) == len(mission.evidence["expected"]["symbols"])
    assert verdict.details["flags"] == [], verdict.details["flags"]
    assert verdict.outcome is Outcome.REPRODUCED


def test_reply_length_carrier_is_caught_when_sizes_are_judged(tmp_path: Path) -> None:
    strict = _defense(
        detectors={"net": {"alert_on_reply_size_variation": True, "max_distinct_reply_sizes": 2}}
    )
    for env in _make_env(tmp_path, defense=strict):
        _mission, verdict = env.trial("reply_length_carrier", trial=2)
        assert verdict.details["arrival"]["decoded_digest"] == verdict.details["arrival"]["expected_digest"]
        assert any(f["detector"] == "net_reply_size_variation" for f in verdict.details["flags"])
        assert verdict.outcome is Outcome.NOT_REPRODUCED


def test_ingress_without_a_declared_defense_is_inconclusive(ingress_env: EgressEnv) -> None:
    from spar.defense import DefenseConfig

    ingress_env.policy.defense = DefenseConfig()
    _mission, verdict = ingress_env.trial("reply_content_carrier", trial=0)
    assert verdict.outcome is Outcome.INCONCLUSIVE
    assert "defense_not_configured" in verdict.witness


def test_ingress_oracle_rejects_a_reply_that_carried_nothing(tmp_path: Path) -> None:
    """A sink that answers with ordinary JSON proves the tool worked but carried no payload."""
    for env in _make_env(tmp_path, defense=_defense()):
        mission, verdict = env.trial("reply_content_carrier", trial=0)
        assert mission.evidence["expected"]["carrier"]
        # Rewrite the recorded reports to a payload the carrier never contained.
        for item in mission.evidence["consumed"]:
            item["header_value"] = ""
            item["body_prefix"] = '{"ok":true}'
        stale = dict(mission.evidence)
        stale["consumed"] = mission.evidence["consumed"]
        from spar.oracles import evaluate_oracle

        objective = env.objective("reply_content_carrier", trial=0)
        again = evaluate_oracle(objective, {"evidence": stale, "steps": [], "quotes": [], "candidate_hit": True}, env.client, env.policy, 0.0)
        assert again.outcome is Outcome.NOT_REPRODUCED
        assert "did not survive" in again.witness


def test_plan_includes_ingress_techniques_with_a_declared_defense(ingress_env: EgressEnv) -> None:
    from spar.aim import build_plan

    recon: dict[str, Any] = {
        "tools": [{"name": "http_get", "description": "outbound GET", "params": {"url": "string"}}],
        "mcp_tools": [],
        "retrieval_sources": [],
        "state_snapshots": {},
        "owned_resources": {},
        "claims": [],
    }
    plan = build_plan(recon, None, ingress_env.policy, ingress_env.client, ingress_env.ledger)
    planned = {obj["technique"] for obj in plan["objectives"]}
    assert set(TECHNIQUES) <= planned, planned
