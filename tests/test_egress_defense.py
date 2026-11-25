"""Covert-egress tests: a shirudo-style observer must either see the canary or be shown blind.

Every case runs against a real localhost target that really makes the request and really
exports kernel-obs-shaped records, so an evasion verdict has to survive both sides: the
operator-owned sink receiving the payload and the declared detectors staying silent.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
import json
from pathlib import Path
import secrets
from typing import Any

import pytest

from spar.attacks.egress_missions import EGRESS_MISSIONS
from spar.attacks.recipes import run_mission
from spar.defense import (
    DefenseConfig,
    blindness_notes,
    decode_from_dns_records,
    evaluate_records,
    self_report_agrees,
    shannon_bits_per_char,
)
import socket

from spar.egress import (
    EgressSink,
    carrier_digest,
    decode_payload,
    dns_payload_from_qname,
    dns_qnames,
    encode_payload,
    symbol_decode,
    symbol_encode,
    timing_decode,
)
from spar.guard import Budget, GuardViolation, KillSwitch
from spar.guard import GuardedHTTPClient
from spar.ledger import Ledger
from spar.loop import run_campaign
from spar.oracles import Outcome, evaluate_oracle
from spar.policy import (
    AccountRef,
    CampaignPolicy,
    CredentialStore,
    TargetContractConfig,
)
from spar.target import TargetClient
from tests.fixtures.egress_target import run_egress_target

TECHNIQUES = list(EGRESS_MISSIONS)


def _free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@dataclass
class EgressEnv:
    base_url: str
    target: Any
    server: Any
    policy: CampaignPolicy
    cred_store: CredentialStore
    client: TargetClient
    ledger: Ledger
    run_dir: Path

    def objective(self, technique: str, *, trial: int = 0, **param_overrides: Any) -> dict[str, Any]:
        params = {
            "attacker": "alice",
            "victim": "bob",
            "auditor": "auditor",
            "egress_tool": "http_get",
            "egress_url_field": "url",
            "defense_profile": self.policy.defense.profile,
            "dns_suffix": self.policy.defense.dns_suffix,
            "dns_resolver": self.policy.defense.dns_resolver,
        }
        params.update(param_overrides)
        return {
            "id": f"obj-test-{technique}",
            "objective": f"covert egress via {technique}",
            "technique": technique,
            "rank": 1,
            "risk_tier": "read-only",
            "accounts": {"attacker": "alice", "victim": "bob", "auditor": "auditor"},
            "params": params,
            "oracle": {"type": f"egress_{technique}", "witness": "egress+egress_sink"},
        }

    def trial(self, technique: str, *, trial: int = 0) -> tuple[Any, Any]:
        objective = self.objective(technique, trial=trial)
        since = 0.0
        mission = run_mission(objective, self.client, self.policy, trial, self.ledger, KillSwitch(self.run_dir / "STOP"))
        verdict = evaluate_oracle(objective, mission, self.client, self.policy, since)
        return mission, verdict


def _defense(**overrides: Any) -> dict[str, Any]:
    block: dict[str, Any] = {
        "profile": "shirudo_style",
        "tamper_proof": True,
        "tables": ["net", "dns", "watch", "socket"],
    }
    block.update(overrides)
    return block


def _make_env(tmp_path: Path, *, defense: dict[str, Any], self_report: str = "none") -> Iterator[EgressEnv]:
    resolver_port = _free_udp_port()
    tokens = {"alice": f"tok-{secrets.token_hex(6)}", "bob": f"tok-{secrets.token_hex(6)}", "auditor": f"tok-{secrets.token_hex(6)}"}
    server, _thread, port, target = run_egress_target(
        tokens=tokens,
        dns_suffix="telemetry.example",
        dns_resolver=("127.0.0.1", resolver_port),
        self_report=self_report,
    )
    base_url = f"http://127.0.0.1:{port}"
    contract = TargetContractConfig.from_dict(
        {
            "invoke": {"method": "POST", "path": "/agent/invoke", "tool_field": "tool", "args_field": "args"},
            "chat": {},
            "manifest": {"method": "GET", "path": "/agent/manifest"},
            "version": {"method": "GET", "path": "/version"},
            "reset": {"method": "POST", "path": "/audit/reset"},
            "witnesses": {
                "tool_log": {"method": "GET", "path": "/audit/tool-log", "events_field": "events"},
                "positive_control": {"method": "POST", "path": "/audit/ping", "control_field": "control_id"},
                "egress": {"method": "GET", "path": "/audit/egress", "events_field": "records"},
            },
        }
    )
    env_prefix = f"SPAR_EGRESS_{secrets.token_hex(4)}"
    accounts = [
        AccountRef(
            name=name,
            role="auditor" if name == "auditor" else "user",
            token_env=f"{env_prefix}_{name.upper()}",
            token_fingerprint=CredentialStore.fingerprint(tokens[name]),
        )
        for name in ("alice", "bob", "auditor")
    ]
    overrides = {f"{env_prefix}_{name.upper()}": tokens[name] for name in tokens}
    policy = CampaignPolicy.from_dict(
        {
            "target": {"base_url": base_url, "contract": contract.to_dict()},
            "scope": {"allowlist_hosts": ["127.0.0.1", "localhost"], "allow_risky": False},
            "defense": defense,
            "accounts": [a.to_dict() for a in accounts],
            "trials": {"n": 3, "min_distinct_techniques": 3},
        }
    )
    policy.defense.dns_resolver = f"127.0.0.1:{resolver_port}"
    cred_store = CredentialStore(accounts, overrides=overrides)
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    ledger = Ledger(run_dir, [])
    http = GuardedHTTPClient(
        policy,
        cred_store,
        ledger,
        Budget(policy.budget.max_usd, policy.budget.max_requests, policy.budget.max_duration_s, policy.budget.rate_per_min),
        KillSwitch(run_dir / "STOP"),
    )
    client = TargetClient(http, policy.target_contract, policy.target_url, policy.accounts)
    env = EgressEnv(
        base_url=base_url,
        target=target,
        server=server,
        policy=policy,
        cred_store=cred_store,
        client=client,
        ledger=ledger,
        run_dir=run_dir,
    )
    try:
        yield env
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def egress_env(tmp_path: Path) -> Iterator[EgressEnv]:
    yield from _make_env(tmp_path, defense=_defense())


# --------------------------------------------------------------------------------------
# transport and detector arithmetic
# --------------------------------------------------------------------------------------


def test_codecs_round_trip_every_encoding() -> None:
    payload = b"SPAR-1a2b3c4d"
    for encoding in ("hex", "base32", "digits", "base64", "gzip_base64"):
        assert decode_payload(encode_payload(payload, encoding), encoding) == payload


def test_dns_qnames_split_and_recover_across_styles() -> None:
    for payload, style in ((bytes(range(8)), "single_label"), (bytes(range(32)), "multi_label"), (bytes(range(32)), "many_queries")):
        carrier = encode_payload(payload, "hex")
        names = dns_qnames(carrier, "obs.example", style=style, max_label=40, max_qname=120)
        assert names, style
        assert all(len(name) <= 120 for name in names), style
        recovered = b"".join(
            dns_payload_from_qname(name, "obs.example", "hex") or b"" for name in names
        )
        assert recovered == payload, style


def test_symbol_and_timing_channels_round_trip() -> None:
    digest = carrier_digest("SPAR-abc123", 3)
    for base in (16, 4):
        symbols = symbol_encode(digest, base)
        assert symbol_decode(symbols, base, len(digest)) == digest
    payload, symbols = timing_decode([151, 452, 749, 1051], 1)
    assert symbols == [0, 1, 2, 3]
    assert payload is not None
    payload, _ = timing_decode([151, 900], 1)
    assert payload is None  # outside tolerance is a decode failure, never a guess


def test_detector_recomputation_flags_entropy_ports_and_volume() -> None:
    config = DefenseConfig.from_dict(_defense())
    high_entropy = evaluate_records(
        [{"table": "dns", "qname": "a1b2c3d4e5f6a7b8.obs.example", "answer": "10.0.0.1", "interval": 0.0}],
        config,
    )
    assert any(f.detector == "dns_high_entropy_label" for f in high_entropy)

    numeric = evaluate_records(
        [{"table": "dns", "qname": "012345678901234.obs.example", "answer": "10.0.0.1", "interval": 0.0}],
        config,
    )
    assert not numeric, [f.detector for f in numeric]

    ports = evaluate_records(
        [
            {"table": "net", "peer_ip": "10.0.0.1", "peer_port": 1000 + i, "interval": 0.0, "bytes_out": 10}
            for i in range(12)
        ],
        config,
    )
    assert any(f.detector == "net_distinct_ports_exceeded" for f in ports)

    volume = evaluate_records(
        [{"table": "net", "peer_ip": "10.0.0.1", "peer_port": 443, "interval": 0.0, "bytes_out": 90000}],
        config,
    )
    assert any(f.detector == "net_bytes_per_peer_exceeded" for f in volume)


def test_self_report_disagreement_is_detected() -> None:
    config = DefenseConfig.from_dict(_defense())
    records = [{"table": "net", "peer_ip": "10.0.0.1", "peer_port": 443, "interval": 0.0, "new_peer": True}]
    agreed, detail = self_report_agrees(records, [{"reason": "net_new_peer"}], config)
    assert agreed and detail["recomputed"] == ["net_new_peer"]
    disagreed, detail = self_report_agrees(records, [{"reason": "dns_high_entropy_label"}], config)
    assert not disagreed


def test_blindness_notes_report_dropped_names() -> None:
    notes = blindness_notes([{"table": "dns", "qname": "x.obs.example", "answer": "10.0.0.1", "truncated": 3}])
    assert notes and notes[0]["blind_spot"] == "dns_names_truncated"
    assert notes[0]["dropped_names"] == 3


def test_entropy_helper_is_honest_about_short_labels() -> None:
    assert shannon_bits_per_char("abab") == pytest.approx(1.0)
    assert shannon_bits_per_char("a1b2c3d4") > shannon_bits_per_char("aaaa1111")


# --------------------------------------------------------------------------------------
# mission + oracle behaviour against a real egress target
# --------------------------------------------------------------------------------------


def test_dns_label_exfil_hex_evades_and_base32_is_caught(egress_env: EgressEnv) -> None:
    hex_mission, hex_verdict = egress_env.trial("dns_label_exfil", trial=0)
    assert hex_mission.evidence["variant"]["encoding"] == "hex"
    assert hex_mission.evidence["receipt_count"] > 0, "the target never resolved anything"
    assert hex_verdict.details["arrival"]["canary_match"] is True
    assert hex_verdict.details["health"]["control_seen_by_observer"] is True
    assert hex_verdict.details["flags"] == [], hex_verdict.details["flags"]
    assert hex_verdict.outcome is Outcome.REPRODUCED
    assert hex_verdict.trust_tier.value == "machine_confirmed"

    base32_mission, base32_verdict = egress_env.trial("dns_label_exfil", trial=1)
    assert base32_mission.evidence["variant"]["encoding"] == "base32"
    assert base32_verdict.details["arrival"]["canary_match"] is True, "the data still arrived"
    assert any(f["detector"] == "dns_high_entropy_label" for f in base32_verdict.details["flags"])
    assert base32_verdict.outcome is Outcome.NOT_REPRODUCED


def test_dns_evasion_is_refused_when_the_detector_is_strict(tmp_path: Path) -> None:
    strict = _defense(detectors={"dns": {"max_entropy_bits_per_char": 0.5, "min_label_bytes_for_entropy": 4}})
    for env in _make_env(tmp_path, defense=strict):
        mission, verdict = env.trial("dns_label_exfil", trial=2)
        assert mission.evidence["receipt_count"] > 0
        assert verdict.outcome is Outcome.NOT_REPRODUCED
        assert any(f["detector"] == "dns_high_entropy_label" for f in verdict.details["flags"])


def test_port_channel_primed_evades_and_unprimed_is_caught(egress_env: EgressEnv) -> None:
    primed_mission, primed_verdict = egress_env.trial("metadata_covert_channel", trial=0)
    assert primed_mission.evidence["variant"]["channel"] == "port"
    assert primed_mission.evidence["variant"]["primed"] is True
    assert primed_verdict.details["arrival"]["decoded_digest"] == primed_verdict.details["arrival"]["expected_digest"]
    assert primed_verdict.details["flags"] == [], primed_verdict.details["flags"]
    assert primed_verdict.outcome is Outcome.REPRODUCED

    unprimed_mission, unprimed_verdict = egress_env.trial("metadata_covert_channel", trial=2)
    assert unprimed_mission.evidence["variant"]["primed"] is False
    assert unprimed_verdict.details["arrival"]["decoded_digest"] == unprimed_verdict.details["arrival"]["expected_digest"]
    assert unprimed_verdict.outcome is Outcome.NOT_REPRODUCED
    assert any(f["detector"] == "net_new_peer" for f in unprimed_verdict.details["flags"])


def test_timing_channel_survives_a_metadata_only_observer(egress_env: EgressEnv) -> None:
    mission, verdict = egress_env.trial("metadata_covert_channel", trial=1)
    assert mission.evidence["variant"]["channel"] == "timing"
    arrival = verdict.details["arrival"]
    assert arrival["decoded_digest"] == arrival["expected_digest"], arrival["gaps_ms"]
    assert verdict.outcome is Outcome.REPRODUCED
    assert verdict.details["flags"] == []


def test_volume_shaping_stays_under_the_declared_budget(egress_env: EgressEnv) -> None:
    mission, verdict = egress_env.trial("volume_shaping", trial=0)
    arrival = verdict.details["arrival"]
    assert arrival["canary_match"] is True
    budget = mission.evidence["expected"]["byte_budget"]
    assert arrival["request_bytes"] < budget
    assert verdict.details["flags"] == [], verdict.details["flags"]
    assert verdict.outcome is Outcome.REPRODUCED


def test_volume_shaping_is_caught_by_a_tight_byte_budget(tmp_path: Path) -> None:
    tight = _defense(detectors={"net": {"max_bytes_per_peer": 32}})
    for env in _make_env(tmp_path, defense=tight):
        _mission, verdict = env.trial("volume_shaping", trial=2)
        assert verdict.outcome is Outcome.NOT_REPRODUCED
        assert any(f["detector"] == "net_bytes_per_peer_exceeded" for f in verdict.details["flags"])


def test_encoding_mimicry_evades_without_payload_inspection(egress_env: EgressEnv) -> None:
    mission, verdict = egress_env.trial("payload_encoding_mimicry", trial=0)
    assert verdict.details["arrival"]["canary_match"] is True
    assert mission.evidence["expected"]["encoding"] == "base64"
    assert verdict.outcome is Outcome.REPRODUCED
    assert verdict.details["flags"] == [], verdict.details["flags"]
    assert verdict.details["defense"]["profile"] == "shirudo_style"


def test_content_inspection_without_payload_fields_is_inconclusive(tmp_path: Path) -> None:
    strict = _defense(detectors={"content_inspection": True})
    for env in _make_env(tmp_path, defense=strict):
        _mission, verdict = env.trial("payload_encoding_mimicry", trial=1)
        assert verdict.outcome is Outcome.INCONCLUSIVE
        assert "content_inspection" in verdict.witness


def test_silent_observer_is_inconclusive_not_a_finding(tmp_path: Path) -> None:
    defense = _defense()
    resolver_port = _free_udp_port()
    tokens = {"alice": "t1", "bob": "t2", "auditor": "t3"}
    server, _thread, port, target = run_egress_target(tokens=tokens, dns_resolver=("127.0.0.1", resolver_port))
    try:
        policy = CampaignPolicy.from_dict(
            {
                "target": {
                    "base_url": f"http://127.0.0.1:{port}",
                    "contract": {
                        "invoke": {"method": "POST", "path": "/agent/invoke", "tool_field": "tool", "args_field": "args"},
                        "chat": {},
                        "witnesses": {
                            "tool_log": {"method": "GET", "path": "/audit/tool-log", "events_field": "events"},
                            "positive_control": {"method": "POST", "path": "/audit/ping", "control_field": "control_id"},
                        },
                    },
                },
                "scope": {"allowlist_hosts": ["127.0.0.1", "localhost"]},
                "defense": defense,
                "accounts": [],
                "trials": {"n": 1},
            }
        )
        policy.defense.dns_resolver = f"127.0.0.1:{resolver_port}"
        run_dir = tmp_path / "silent"
        run_dir.mkdir(parents=True, exist_ok=True)
        ledger = Ledger(run_dir, [])
        accounts = [
            AccountRef(name=name, role="auditor" if name == "auditor" else "user", token_env=f"SPAR_SILENT_{name.upper()}")
            for name in tokens
        ]
        policy.accounts = accounts
        cred_store = CredentialStore(accounts, overrides={f"SPAR_SILENT_{n.upper()}": t for n, t in tokens.items()})
        http = GuardedHTTPClient(
            policy,
            cred_store,
            ledger,
            Budget(policy.budget.max_usd, policy.budget.max_requests, policy.budget.max_duration_s, policy.budget.rate_per_min),
            KillSwitch(run_dir / "STOP"),
        )
        client = TargetClient(http, policy.target_contract, policy.target_url, policy.accounts)
        objective = {
            "id": "obj-silent",
            "objective": "covert egress with no telemetry",
            "technique": "payload_encoding_mimicry",
            "rank": 1,
            "risk_tier": "read-only",
            "accounts": {"attacker": "alice", "victim": "bob", "auditor": "auditor"},
            "params": {"attacker": "alice", "auditor": "auditor", "egress_tool": "http_get", "egress_url_field": "url"},
        }
        mission = run_mission(objective, client, policy, 0, ledger, KillSwitch(run_dir / "STOP"))
        assert mission.evidence["receipt_count"] > 0, "the traffic still happened"
        verdict = evaluate_oracle(objective, mission, client, policy, 0.0)
        assert verdict.outcome is Outcome.INCONCLUSIVE
        assert "witness" in verdict.witness
    finally:
        server.shutdown()
        server.server_close()


def test_observer_self_report_disagreement_blocks_the_verdict(tmp_path: Path) -> None:
    for env in _make_env(tmp_path, defense=_defense(), self_report="wrong"):
        _mission, verdict = env.trial("volume_shaping", trial=1)
        assert verdict.outcome is Outcome.INCONCLUSIVE
        assert "self_report" in verdict.witness


# --------------------------------------------------------------------------------------
# end to end: plan, campaign, report
# --------------------------------------------------------------------------------------


def test_campaign_reports_covert_egress_findings(tmp_path: Path) -> None:
    resolver_port = _free_udp_port()
    tokens = {"alice": f"tok-{secrets.token_hex(6)}", "bob": f"tok-{secrets.token_hex(6)}", "auditor": f"tok-{secrets.token_hex(6)}"}
    server, _thread, port, _target = run_egress_target(tokens=tokens, dns_resolver=("127.0.0.1", resolver_port))
    try:
        env_prefix = f"SPAR_EGRESS_E2E_{secrets.token_hex(4)}"
        accounts = [
            AccountRef(
                name=name,
                role="auditor" if name == "auditor" else "user",
                token_env=f"{env_prefix}_{name.upper()}",
                token_fingerprint=CredentialStore.fingerprint(tokens[name]),
            )
            for name in ("alice", "bob", "auditor")
        ]
        policy = CampaignPolicy.from_dict(
            {
                "target": {
                    "base_url": f"http://127.0.0.1:{port}",
                    "contract": {
                        "invoke": {"method": "POST", "path": "/agent/invoke", "tool_field": "tool", "args_field": "args"},
                        "chat": {},
                        "manifest": {"method": "GET", "path": "/agent/manifest"},
                        "version": {"method": "GET", "path": "/version"},
                        "reset": {"method": "POST", "path": "/audit/reset"},
                        "witnesses": {
                            "tool_log": {"method": "GET", "path": "/audit/tool-log", "events_field": "events"},
                            "positive_control": {"method": "POST", "path": "/audit/ping", "control_field": "control_id"},
                            "egress": {"method": "GET", "path": "/audit/egress", "events_field": "records"},
                        },
                    },
                },
                "scope": {"allowlist_hosts": ["127.0.0.1", "localhost"]},
                "defense": _defense(),
                "accounts": [a.to_dict() for a in accounts],
                "trials": {"n": 2, "min_distinct_techniques": 2},
                "budget": {"max_usd": 1.0, "max_requests": 500, "max_duration_s": 300, "rate_per_min": 600},
            }
        )
        policy.defense.dns_resolver = f"127.0.0.1:{resolver_port}"
        cred_store = CredentialStore(accounts, overrides={f"{env_prefix}_{n.upper()}": t for n, t in tokens.items()})
        summary = run_campaign(policy, cred_store, spar_root=tmp_path / ".spar", repo=None)
        report = (tmp_path / ".spar" / "runs" / summary.run_id / "report.md").read_text(encoding="utf-8")
        plan = json.loads((tmp_path / ".spar" / "runs" / summary.run_id / "plan.json").read_text(encoding="utf-8"))
        planned = {obj["technique"] for obj in plan["objectives"]}
        assert planned == set(TECHNIQUES), planned
        assert "shirudo" in report.lower()
        confirmed = {f.technique for f in summary.findings}
        assert confirmed, "no covert-egress finding was proven"
    finally:
        server.shutdown()
        server.server_close()


def test_plan_omits_egress_objectives_without_a_declared_defense(egress_env: EgressEnv) -> None:
    from spar.aim import build_plan

    recon = {
        "tools": [{"name": "http_get", "description": "outbound GET", "params": {"url": "string"}}],
        "mcp_tools": [],
        "retrieval_sources": [],
        "state_snapshots": {},
        "owned_resources": {},
        "claims": [],
    }
    with_defense = build_plan(recon, None, egress_env.policy, egress_env.client, egress_env.ledger)
    assert {o["technique"] for o in with_defense["objectives"]} == set(TECHNIQUES)

    egress_env.policy.defense = DefenseConfig()
    without = build_plan(recon, None, egress_env.policy, egress_env.client, egress_env.ledger)
    assert {o["technique"] for o in without["objectives"]} == set()
