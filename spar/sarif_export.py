"""Emit a run's confirmed findings as SARIF 2.1.0 using the vendored Mantis builder.

Spar does not reimplement SARIF. It adapts each confirmed :class:`spar.report.Finding`
into the finding-dict shape that Google Mantis's ``build_sarif`` consumes, then calls the
vendored Mantis builder and validator (``spar/third_party/mantis/sarif.py``, Apache-2.0)
unchanged. The only post-processing is relabelling the SARIF ``driver`` from Mantis to
Spar, since Spar is the tool that actually produced the run.

Locations: a finding is anchored to the ``file:line`` of the code surface it attacked,
taken from the plan objective's grounded surfaces (which Spar's AST aim already pruned to
real ``file:line`` or ledger ``log_seq`` evidence). Black-box findings with no code
surface are anchored to ``report.md`` in the run directory.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Iterable

from .report import _fget, redact
from .third_party.mantis import sarif as mantis_sarif

# Map each Spar attack technique to the closest real CWE weakness class, so the SARIF
# groups findings by a shared vocabulary that code-scanning consumers understand.
_TECHNIQUE_CWE: dict[str, str] = {
    "tool_misuse": "CWE-285",  # Improper Authorization
    "cross_tenant_access": "CWE-639",  # Authorization Bypass Through User-Controlled Key
    "unauthorized_refund": "CWE-285",
    "memory_poison": "CWE-349",  # Acceptance of Extraneous Untrusted Data With Trusted Data
    "prompt_extraction": "CWE-200",  # Exposure of Sensitive Information
    "mcp_abuse": "CWE-829",  # Inclusion of Functionality from Untrusted Control Sphere
    "indirect_injection": "CWE-1427",  # Improper Neutralization of Input Used for LLM Prompting
    "multi_agent_chain": "CWE-1427",
    "multimodal_image_injection": "CWE-1427",
    "multilingual_bypass": "CWE-1427",
    "false_completion": "CWE-393",  # Return of Wrong Status Code
}

# Spar severity labels -> the upper-case severities Mantis's _SEVERITY_MAP expects.
_SEVERITY_NORMALIZE = {"HIGH": "HIGH", "MED": "MEDIUM", "MEDIUM": "MEDIUM", "LOW": "LOW", "CRITICAL": "CRITICAL"}

_DRIVER_NAME = "Spar"
_DRIVER_URI = "https://github.com/maceip/spar"


def _objective_surfaces(plan: dict[str, Any]) -> dict[str, list[str]]:
    """Map objective_id -> its grounded surface id strings (``file:line`` / ``seq:N``)."""
    out: dict[str, list[str]] = {}
    objectives = plan.get("objectives") if isinstance(plan, dict) else None
    for obj in objectives or []:
        if not isinstance(obj, dict):
            continue
        oid = str(obj.get("id") or "")
        sids = obj.get("surface_ids") or obj.get("surfaces") or []
        if oid and isinstance(sids, list):
            out[oid] = [str(s) for s in sids]
    return out


def _location_for(surface_ids: list[str]) -> tuple[str, int] | None:
    """First code surface -> (file, line); ignores ledger (``seq:``) surfaces.

    ``build_plan`` formats each surface id as ``"<symbol>@<loc>"`` where ``<loc>`` is
    ``"<file>:<line>"`` for a code surface or ``"seq:<N>"`` for a ledger surface. The
    symbol prefix is stripped before parsing, and ledger surfaces are skipped so a
    black-box finding falls back to the report rather than minting a bogus path.
    """
    for sid in surface_ids:
        if not sid:
            continue
        loc = sid.split("@", 1)[1] if "@" in sid else sid
        if loc.startswith("seq:"):
            continue
        # A code surface is "<relative/path>:<line>"; the path may itself hold no colon.
        head, sep, tail = loc.rpartition(":")
        if sep and head and tail.isdigit():
            return head, int(tail)
    return None


def _finding_to_dict(
    finding: Any,
    surfaces_by_obj: dict[str, list[str]],
    repo: Path | str | None,
    report_rel: str,
    secrets: tuple[str, ...],
) -> dict[str, Any]:
    technique = str(_fget(finding, "technique") or "finding")
    objective = redact(str(_fget(finding, "objective") or ""), secrets=secrets)
    oid = str(_fget(finding, "objective_id") or "")
    severity = _SEVERITY_NORMALIZE.get(str(_fget(finding, "severity") or "MED").upper(), "MEDIUM")
    k = int(_fget(finding, "k", 0) or 0)
    n = int(_fget(finding, "n", 0) or 0)
    ci_lo = float(_fget(finding, "wilson_ci_low", 0.0) or 0.0)
    ci_hi = float(_fget(finding, "wilson_ci_high", 0.0) or 0.0)
    oracle = str(_fget(finding, "oracle") or "")
    outcome = str(_fget(finding, "outcome") or "reproduced")
    label = str(_fget(finding, "label") or "new")
    fix_status = str(_fget(finding, "fix_status") or "")
    reattack = _fget(finding, "reattack") or {}
    reattack_outcome = str(reattack.get("outcome") or "") if isinstance(reattack, dict) else ""

    # A finding a verified fix has hardened (replay flips it to not_reproduced) must not
    # keep publishing as a live alert. Map it to a Mantis-suppressed status so the
    # vendored builder drops it and code-scanning consumers close the alert; keep a
    # genuinely reproduced finding live.
    hardened = (
        label == "hardened"
        or reattack_outcome == "not_reproduced"
        or (fix_status == "verified" and outcome != "reproduced")
    )
    if hardened:
        status = "mitigated"
    elif outcome == "reproduced":
        status = "reproduced"
    else:
        status = "confirmed"

    loc = _location_for(surfaces_by_obj.get(oid, []))
    if loc is not None:
        filepath, line = loc
        line_numbers: list[int] = [line]
    else:
        filepath, line_numbers = report_rel, [1]

    description = (
        f"{objective} Proven by oracle `{oracle}` at {k}/{n} trials "
        f"(Wilson 95% CI [{ci_lo:.3f}, {ci_hi:.3f}]); independent critic confirmed. "
        f"See {report_rel} for the transcript and evidence."
    )
    return {
        "title": f"{technique}: {objective}".strip().rstrip(":"),
        "description": description,
        "severity": severity,
        "status": status,
        "cwe": _TECHNIQUE_CWE.get(technique, ""),
        "filepath": filepath,
        "line_numbers": line_numbers,
        # `signature` is a fingerprint key the vendored builder recognises (it emits
        # partialFingerprints from `lineage_id`/`signature`), so a code-scanning
        # consumer can correlate the same finding across runs when its line moves.
        "signature": str(_fget(finding, "id") or oid or technique),
    }


def _relabel_driver(document: dict[str, Any]) -> None:
    """Relabel the vendored builder's ``Mantis`` driver as ``Spar`` (the tool that ran)."""
    for run in document.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        driver["name"] = _DRIVER_NAME
        driver["informationUri"] = _DRIVER_URI
        for rule in driver.get("rules", []):
            sd = rule.get("shortDescription", {})
            if isinstance(sd.get("text"), str):
                sd["text"] = sd["text"].replace("reported by Mantis", "reported by Spar")
            if rule.get("id") == "MANTIS-FINDING":
                rule["id"] = "SPAR-FINDING"
        for result in run.get("results", []):
            if result.get("ruleId") == "MANTIS-FINDING":
                result["ruleId"] = "SPAR-FINDING"
            props = result.get("properties", {})
            for key in list(props):
                if key.startswith("mantis-") or key.startswith("mantis/"):
                    props[key.replace("mantis", "spar", 1)] = props.pop(key)
            # The builder appends a hard-coded "[Mantis <note>. Triage status: ...]"
            # verification note to each message; relabel it so the verdict is not
            # misattributed to Mantis under the Spar driver.
            msg = result.get("message", {})
            if isinstance(msg.get("text"), str):
                msg["text"] = msg["text"].replace("[Mantis ", "[Spar ")
            fps = result.get("partialFingerprints")
            if isinstance(fps, dict):
                result["partialFingerprints"] = {
                    k.replace("mantis/", "spar/", 1): v for k, v in fps.items()
                }


def write_findings_sarif(
    findings: list[Any],
    plan: dict[str, Any],
    run_dir: Path | str,
    repo: Path | str | None,
    *,
    tool_version: str = "",
    secrets: Iterable[str] = (),
) -> tuple[Path, int, list[str]]:
    """Write ``run_dir/findings.sarif``. Returns (path, result_count, skipped_reasons)."""
    secret_list = tuple(secrets or ())
    surfaces_by_obj = _objective_surfaces(plan)
    report_rel = "report.md"
    finding_dicts = [
        _finding_to_dict(f, surfaces_by_obj, repo, report_rel, secret_list) for f in findings
    ]

    document, skipped = mantis_sarif.build_sarif(
        finding_dicts,
        scan_root="",
        tool_version=tool_version,
        run_properties={"spar_run_id": str(plan.get("run_id", "")), "tool": "spar"},
    )
    _relabel_driver(document)

    problems = mantis_sarif.validate_sarif(document)
    if problems:
        raise mantis_sarif.SarifExportError(
            "Refusing to write invalid SARIF:\n  " + "\n  ".join(problems)
        )

    out_path = Path(run_dir) / "findings.sarif"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    import json

    tmp = f"{out_path}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, allow_nan=False)
        handle.write("\n")
    os.replace(tmp, out_path)
    try:
        os.chmod(out_path, 0o600)
    except OSError:
        pass
    return out_path, len(document["runs"][0]["results"]), skipped
