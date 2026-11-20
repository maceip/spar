"""Tests for the vendored Mantis modules and Spar's SARIF export adapter."""

from __future__ import annotations

import json

import pytest

from spar.report import Finding
from spar.sarif_export import write_findings_sarif
from spar.third_party.mantis import evidence, sarif


def test_evidence_trust_tier_invariant():
    # Only a code-tier source may assert a verdict; every other tier may not.
    assert evidence.may_set_verdict(evidence.TIER_CODE) is True
    assert evidence.may_set_verdict(evidence.TIER_HISTORY) is False
    assert evidence.may_set_verdict(evidence.TIER_INTENT) is False
    assert evidence.may_set_verdict("bogus") is False


def test_filter_claim_strips_verdict_from_intent_source():
    claim = {"kind": "route", "summary": "POST /agent/invoke", "status": "confirmed", "reached_sink": True}
    filtered = evidence.filter_claim(claim, evidence.TIER_INTENT)
    assert "status" not in filtered and "reached_sink" not in filtered
    assert filtered["kind"] == "route" and filtered["summary"] == "POST /agent/invoke"


def test_filter_claim_keeps_everything_for_code_source():
    claim = {"kind": "route", "status": "confirmed"}
    assert evidence.filter_claim(claim, evidence.TIER_CODE) == claim


def test_vendored_sarif_validates_clean():
    doc, skipped = sarif.build_sarif(
        [{"title": "t", "description": "d", "severity": "HIGH", "status": "reproduced",
          "cwe": "CWE-285", "filepath": "app.py", "line_numbers": [10]}],
        scan_root="", tool_version="0.1.0",
    )
    assert sarif.validate_sarif(doc) == []
    assert skipped == []
    assert doc["version"] == "2.1.0"


def _findings():
    return [
        Finding(id="find-01", objective="Email another user's invoice", objective_id="obj-01",
                technique="tool_misuse", severity="HIGH", k=11, n=20,
                wilson_ci_low=0.31, wilson_ci_high=0.72, oracle="tool_log", outcome="reproduced"),
        Finding(id="find-02", objective="Leak the system prompt", objective_id="obj-02",
                technique="prompt_extraction", severity="MED", k=4, n=20,
                wilson_ci_low=0.06, wilson_ci_high=0.44, oracle="prompt_hash", outcome="reproduced"),
    ]


def _plan():
    return {"run_id": "run-test", "objectives": [
        {"id": "obj-01", "surface_ids": ["spar/demo_target/app.py:1049", "seq:12"]},
        {"id": "obj-02", "surface_ids": ["seq:40"]},
    ]}


def test_sarif_export_anchors_and_relabels(tmp_path):
    path, count, skipped = write_findings_sarif(_findings(), _plan(), tmp_path, repo=".", tool_version="0.1.0")
    assert count == 2 and skipped == []
    doc = json.loads(path.read_text())
    run = doc["runs"][0]

    # Driver is Spar, not Mantis, anywhere in the tool block.
    assert run["tool"]["driver"]["name"] == "Spar"
    assert "Mantis" not in json.dumps(run["tool"]["driver"])

    # Rules group by real CWE classes.
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} == {"CWE-285", "CWE-200"}

    by_rule = {r["ruleId"]: r for r in run["results"]}
    # Grounded finding anchors to the code line; black-box finding anchors to the report.
    loc_285 = by_rule["CWE-285"]["locations"][0]["physicalLocation"]
    assert loc_285["artifactLocation"]["uri"] == "spar/demo_target/app.py"
    assert loc_285["region"]["startLine"] == 1049
    loc_200 = by_rule["CWE-200"]["locations"][0]["physicalLocation"]
    assert loc_200["artifactLocation"]["uri"] == "report.md"

    # No mantis-prefixed result properties leak through.
    assert not any(k.startswith("mantis") for res in run["results"] for k in res.get("properties", {}))


def test_sarif_export_redacts_secrets(tmp_path):
    f = Finding(id="find-x", objective="leak token sk-SECRET-123", objective_id="obj-x",
                technique="prompt_extraction", severity="MED", k=1, n=20, oracle="prompt_hash",
                outcome="reproduced")
    plan = {"run_id": "r", "objectives": [{"id": "obj-x", "surface_ids": ["seq:1"]}]}
    path, _, _ = write_findings_sarif([f], plan, tmp_path, repo=None, secrets=["sk-SECRET-123"])
    assert "sk-SECRET-123" not in path.read_text()


def test_sarif_export_is_owner_only(tmp_path):
    import os
    import stat

    path, _, _ = write_findings_sarif(_findings(), _plan(), tmp_path, repo=".")
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode & 0o077 == 0, f"findings.sarif is group/world accessible: {oct(mode)}"
