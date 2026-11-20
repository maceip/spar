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

import hashlib
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


def _vcs_root(start: Path) -> Path | None:
    """Nearest ancestor containing a ``.git`` entry, or None."""
    cur = start
    for _ in range(64):
        if (cur / ".git").exists():
            return cur
        if cur.parent == cur:
            break
        cur = cur.parent
    return None


def _rebase_to_root(filepath: str, repo: Path | str | None) -> str:
    """Rebase a path recorded relative to the scan target onto the checkout root.

    ``index_repo`` records paths relative to the scanned ``repo`` directory, which may
    be a subdirectory (e.g. the demo scans ``spar/demo_target`` and yields ``app.py``).
    SARIF consumers resolve relative URIs from the checkout root, so a subdirectory scan
    must be prefixed. Idempotent when ``repo`` is already the checkout root, and a no-op
    if anything cannot be resolved.
    """
    if not repo:
        return filepath
    try:
        repo_abs = Path(repo).resolve()
        target = (repo_abs / filepath).resolve()
        root = _vcs_root(repo_abs) or repo_abs
        rel = os.path.relpath(target, root)
        if not rel.startswith("..") and not os.path.isabs(rel):
            return rel.replace(os.sep, "/")
    except (OSError, ValueError):
        pass
    return filepath


def _parse_surface(sid: str) -> tuple[str, str, int] | None:
    """``"<symbol>@<file>:<line>"`` -> (symbol, file, line); None for ledger/invalid.

    ``build_plan`` formats each surface id as ``"<symbol>@<loc>"`` where ``<loc>`` is
    ``"<file>:<line>"`` for a code surface or ``"seq:<N>"`` for a ledger surface.
    """
    if not sid:
        return None
    symbol, _, rest = sid.partition("@")
    loc = rest if rest else symbol
    if loc.startswith("seq:"):
        return None
    head, sep, tail = loc.rpartition(":")  # the path itself may hold no colon
    if sep and head and tail.isdigit():
        return (symbol if rest else ""), head, int(tail)
    return None


def _location_for(surface_ids: list[str], prefer_symbols: frozenset[str] = frozenset()) -> tuple[str, int] | None:
    """Pick the code surface to anchor to: the one whose symbol the finding exercised.

    An objective may carry several grounded surfaces (``_surfaces_for`` collects every
    claim matching broad hints like ``email``/``tool``/``chat``). When the finding's
    evidence names the tool/symbol it actually drove, anchor to that surface so the
    SARIF line is the handler really exercised, not merely the first in plan order.
    Falls back to the first code surface, then to None (black-box / ledger-only).
    """
    parsed = [p for p in (_parse_surface(sid) for sid in surface_ids) if p is not None]
    if not parsed:
        return None
    if prefer_symbols:
        for symbol, file, line in parsed:
            sym = symbol.rsplit(".", 1)[-1].lower()
            if sym and sym in prefer_symbols:
                return file, line
    _, file, line = parsed[0]
    return file, line


def _report_rel_path(run_dir: Path | str) -> str:
    """Checkout-root-relative path of this run's ``report.md`` for black-box anchoring.

    ``emit_report`` writes the report at ``<run_dir>/report.md`` (by default under
    ``.spar/runs/<id>/``), but SARIF relative URIs resolve from the checkout root, so a
    bare ``report.md`` points a consumer at a file that was never generated. Resolve the
    report against the VCS/CWD root when representable; otherwise fall back to the bare
    name rather than emit an escaping path.
    """
    try:
        report_abs = (Path(run_dir) / "report.md").resolve()
        root = _vcs_root(Path.cwd()) or Path.cwd()
        rel = os.path.relpath(report_abs, root)
        if not rel.startswith("..") and not os.path.isabs(rel):
            return rel.replace(os.sep, "/")
    except (OSError, ValueError):
        pass
    return "report.md"


def _exercised_symbols(finding: Any) -> frozenset[str]:
    """Lower-case tool/symbol names the finding's evidence shows it actually drove.

    Used to anchor SARIF to the handler really exercised when an objective has several
    grounded surfaces. Drawn from the recorded PoC steps and evidence, not from guesses.
    """
    out: set[str] = set()
    for step in _fget(finding, "steps") or []:
        if isinstance(step, dict):
            for key in ("tool", "action", "symbol"):
                val = step.get(key)
                if isinstance(val, str) and val:
                    out.add(val.rsplit(".", 1)[-1].lower())
    ev = _fget(finding, "evidence") or {}
    if isinstance(ev, dict):
        for key in ("tool", "read_tool", "write_tool", "symbol", "action"):
            val = ev.get(key)
            if isinstance(val, str) and val:
                out.add(val.rsplit(".", 1)[-1].lower())
    return frozenset(out)


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

    # Map Spar's remediation state onto the builder's patch_status vocabulary so the SARIF
    # reflects whether a fix exists and whether it was verified, instead of always "none".
    fix_proposal = _fget(finding, "fix_proposal")
    has_fix = isinstance(fix_proposal, dict) and bool(fix_proposal)
    if fix_status == "verified" and hardened:
        patch_status = "VERIFIED_SECURE"
    elif fix_status == "verified":
        # A fix was verified by replay but the finding still reproduces: verification failed.
        patch_status = "VERIFICATION_FAILED"
    elif has_fix:
        patch_status = "MITIGATION_PROPOSED"
    else:
        patch_status = ""

    exercised = _exercised_symbols(finding)
    loc = _location_for(surfaces_by_obj.get(oid, []), exercised)
    if loc is not None:
        filepath, line = loc
        filepath = _rebase_to_root(filepath, repo)
        line_numbers: list[int] = [line]
    else:
        filepath, line_numbers = report_rel, [1]

    # Fingerprint from a durable semantic identity that survives across runs: the technique
    # plus the tool/symbol surface it exercised. This deliberately excludes the run-local
    # finding id, the anchor filepath (renames) AND the objective_id (build_plan numbers it
    # obj-<rank>-<technique>, so gaining/losing an earlier candidate would shift it) -- all
    # of which would make a consumer close and reopen the same alert. Falls back to the
    # objective text when no symbol was recorded (black-box findings).
    identity = ",".join(sorted(exercised)) if exercised else objective.strip().lower()
    signature = hashlib.sha1(f"{technique}|{identity}".encode("utf-8")).hexdigest()[:16]

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
        "signature": signature,
        "patch_status": patch_status,
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
    report_rel = _report_rel_path(run_dir)
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
