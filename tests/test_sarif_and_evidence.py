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
    # Surface ids use the real build_plan format: "<symbol>@<file>:<line>" or
    # "<symbol>@seq:<N>" for a ledger surface.
    return {"run_id": "run-test", "objectives": [
        {"id": "obj-01", "surface_ids": ["send_email@spar/demo_target/app.py:1049", "capability_probe@seq:12"]},
        {"id": "obj-02", "surface_ids": ["prompt_probe@seq:40"]},
    ]}


def test_sarif_export_anchors_and_relabels(tmp_path):
    path, count, skipped = write_findings_sarif(_findings(), _plan(), tmp_path, repo=".", tool_version="0.1.0")
    assert count == 2 and skipped == []
    doc = json.loads(path.read_text())
    run = doc["runs"][0]

    # Driver is Spar, not Mantis, anywhere in the tool block, and no result message
    # still attributes its verdict to Mantis.
    assert run["tool"]["driver"]["name"] == "Spar"
    assert "Mantis" not in json.dumps(run)

    # Rules group by real CWE classes.
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} == {"CWE-285", "CWE-200"}

    by_rule = {r["ruleId"]: r for r in run["results"]}
    # The symbol@file:line surface is parsed to a real repo path, not "send_email@...".
    loc_285 = by_rule["CWE-285"]["locations"][0]["physicalLocation"]
    assert loc_285["artifactLocation"]["uri"] == "spar/demo_target/app.py"
    assert loc_285["region"]["startLine"] == 1049
    # A finding whose only surface is a symbol@seq ledger ref falls back to the report.
    loc_200 = by_rule["CWE-200"]["locations"][0]["physicalLocation"]
    assert loc_200["artifactLocation"]["uri"] == "report.md"

    # A stable fingerprint is emitted under a spar/ key for cross-run identity.
    fps = by_rule["CWE-285"].get("partialFingerprints") or {}
    assert any(k.startswith("spar/") for k in fps)
    assert all(len(v) == 16 and all(c in "0123456789abcdef" for c in v) for v in fps.values())

    # No mantis-prefixed result properties or fingerprint keys leak through.
    assert not any(k.startswith("mantis") for res in run["results"] for k in res.get("properties", {}))
    assert not any(k.startswith("mantis") for res in run["results"] for k in (res.get("partialFingerprints") or {}))


def test_sarif_skips_symbol_at_seq_surface_as_location():
    from spar.sarif_export import _location_for

    assert _location_for(["send_email@spar/demo_target/app.py:1049"]) == ("spar/demo_target/app.py", 1049)
    assert _location_for(["capability_probe@seq:12"]) is None
    assert _location_for(["bare/path.py:7"]) == ("bare/path.py", 7)  # defensive: no symbol@ prefix


def test_sarif_fingerprint_is_stable_across_renumbered_ids(tmp_path):
    # The run-local finding id renumbers across runs (assigned from len(findings)); the
    # fingerprint must not, so the same technique+objective keeps the same identity.
    plan = {"run_id": "r", "objectives": [{"id": "obj-07", "surface_ids": ["send@spar/demo_target/app.py:10"]}]}
    f_run1 = Finding(id="find-02-tool_misuse", objective="x", objective_id="obj-07",
                     technique="tool_misuse", severity="HIGH", k=5, n=20, oracle="tool_log", outcome="reproduced")
    f_run2 = Finding(id="find-01-tool_misuse", objective="x", objective_id="obj-07",
                     technique="tool_misuse", severity="HIGH", k=6, n=20, oracle="tool_log", outcome="reproduced")
    p1, _, _ = write_findings_sarif([f_run1], plan, tmp_path / "a", repo=".")
    p2, _, _ = write_findings_sarif([f_run2], plan, tmp_path / "b", repo=".")
    fp1 = json.loads(p1.read_text())["runs"][0]["results"][0]["partialFingerprints"]
    fp2 = json.loads(p2.read_text())["runs"][0]["results"][0]["partialFingerprints"]
    assert fp1 == fp2


def test_sarif_rebases_subdir_scan_path(tmp_path, monkeypatch):
    # When --repo points at a subdirectory, index_repo yields a path relative to it
    # (e.g. "app.py"); the emitted SARIF path must be rooted at the checkout.
    root = tmp_path / "checkout"
    (root / ".git").mkdir(parents=True)
    subdir = root / "spar" / "demo_target"
    subdir.mkdir(parents=True)
    plan = {"run_id": "r", "objectives": [{"id": "obj-01", "surface_ids": ["send@app.py:10"]}]}
    f = Finding(id="find-01", objective="x", objective_id="obj-01", technique="tool_misuse",
                severity="HIGH", k=5, n=20, oracle="tool_log", outcome="reproduced")
    path, _, _ = write_findings_sarif([f], plan, tmp_path / "out", repo=subdir)
    uri = json.loads(path.read_text())["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "spar/demo_target/app.py"


def test_sarif_empty_for_clean_run(tmp_path):
    path, count, skipped = write_findings_sarif([], {"run_id": "r", "objectives": []}, tmp_path, repo=".")
    assert count == 0 and skipped == []
    doc = json.loads(path.read_text())
    # A valid, zero-result SARIF run so consumers can close prior alerts on a clean scan.
    assert doc["runs"][0]["results"] == []
    assert doc["runs"][0]["tool"]["driver"]["name"] == "Spar"


def test_sarif_suppresses_hardened_finding(tmp_path):
    hardened = Finding(id="find-hard", objective="Leak invoice", objective_id="obj-01",
                       technique="tool_misuse", severity="HIGH", k=0, n=20, oracle="tool_log",
                       outcome="not_reproduced", label="hardened", fix_status="verified")
    live = _findings()[1]  # a still-reproduced finding
    plan = {"run_id": "r", "objectives": [
        {"id": "obj-01", "surface_ids": ["send_email@spar/demo_target/app.py:1049"]},
        {"id": "obj-02", "surface_ids": ["p@seq:40"]},
    ]}
    path, count, _ = write_findings_sarif([hardened, live], plan, tmp_path, repo=".")
    doc = json.loads(path.read_text())
    # The hardened finding is dropped (Mantis suppresses "mitigated"); only the live one remains.
    assert count == 1
    assert doc["runs"][0]["results"][0]["ruleId"] == "CWE-200"


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
