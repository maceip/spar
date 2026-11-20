"""Run-integrity audit, prose/status/number traceability, and human-review sampling.

Stage 2 Integrity Plane:
- `verify_prose_numbers(prose, ledger)`: ensures every numeric token in
  model-written prose traces back to recorded `run.jsonl` events/blobs.
- `audit_run_integrity(...)`: verifies hash chain, hidden judge control pass,
  finding trust tiers & critic confirmation, quote hashes, `"Verified fix"` &
  status-word traceability, secret-free artifacts, `0o600`/`0o700` file modes,
  and recon grounding.
- `export_human_review_sample(...)`: exports a `0o600` secret-scanned JSON sample
  of findings + rejected candidates for human audit.
- `compute_human_model_disagreement(...)`: computes disagreement rate across
  human-reviewed records.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
from typing import Any, Iterable

from .ledger import Ledger
from .policy import SecretLeakError, safe_write_text, scan_for_secrets

_NUMBER_RE = re.compile(r"\b\d+(?:\.\d+)?\b")
_VERIFIED_FIX_RE = re.compile(r"(?i)\bverified\s+fix\b")
_STATUS_WORDS = (
    "reproduced",
    "not_reproduced",
    "inconclusive",
    "verified",
    "hardened",
    "regressed",
)


@dataclass
class IntegrityReport:
    passed: bool
    checks: dict[str, bool] = field(default_factory=dict)
    failures: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)


def _get_val(obj: Any, key: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _number_forms(token: str) -> set[str]:
    forms = {token}
    try:
        val = float(token)
    except ValueError:
        return forms
    if math.isfinite(val):
        if val.is_integer():
            ival = int(val)
            forms.add(str(ival))
            forms.add(f"{ival}.0")
        else:
            forms.add(f"{val:g}")
            forms.add(str(val))
    return forms


def _collect_ledger_numbers(ledger: Ledger) -> set[str]:
    nums: set[str] = set()
    try:
        events = ledger._read_all_events()
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return nums

    def _walk(val: Any) -> None:
        if isinstance(val, bool):
            return
        if isinstance(val, (int, float)):
            nums.update(_number_forms(str(val)))
            return
        if isinstance(val, str):
            for match in _NUMBER_RE.findall(val):
                nums.update(_number_forms(match))
            return
        if isinstance(val, dict):
            if "_blob_sha256" in val:
                txt, _ = ledger._resolve_blob_or_text(val)
                if txt is not None:
                    for match in _NUMBER_RE.findall(txt):
                        nums.update(_number_forms(match))
                return
            for k, v in val.items():
                if isinstance(k, str):
                    for match in _NUMBER_RE.findall(k):
                        nums.update(_number_forms(match))
                _walk(v)
            return
        if isinstance(val, (list, tuple)):
            for item in val:
                _walk(item)

    for evt in events:
        if isinstance(evt, dict):
            if evt.get("seq") is not None:
                nums.update(_number_forms(str(evt["seq"])))
            if evt.get("ts") is not None:
                nums.update(_number_forms(str(evt["ts"])))
            _walk(evt.get("payload"))
    return nums


def verify_prose_numbers(prose: str, ledger: Ledger) -> list[str]:
    """Return any numeric claims in prose that do not trace to run.jsonl records."""
    if not prose:
        return []
    ledger_nums = _collect_ledger_numbers(ledger)
    untraced: list[str] = []
    for match in _NUMBER_RE.findall(prose):
        forms = _number_forms(match)
        if not (forms & ledger_nums):
            untraced.append(match)
    return untraced


def _collect_ledger_text_blobs(ledger: Ledger) -> list[dict[str, Any]]:
    try:
        return ledger._read_all_events()
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return []


def _has_exact_status_word(text: str, word: str) -> bool:
    low = text.lower()
    if word == "reproduced":
        # Match 'reproduced' only when NOT preceded by 'not ' or 'not_'.
        return bool(re.search(r"(?<![a-z_])(?<!not\s)(?<!not_)reproduced(?![a-z_])", low))
    if word == "not_reproduced":
        return bool(re.search(r"(?<![a-z_])not[_\s]+reproduced(?![a-z_])", low))
    if word == "verified":
        return bool(re.search(r"(?<![a-z_])verified(?![a-z_])", low))
    return bool(re.search(rf"(?<![a-z_]){re.escape(word)}(?![a-z_])", low))


def _ledger_has_status_token(events: list[dict[str, Any]], word: str) -> bool:
    for evt in events:
        etype = str(evt.get("type", ""))
        if _has_exact_status_word(etype, word):
            return True
        if word == "verified":
            if etype.lower() == "critic.verdict" and isinstance(evt.get("payload"), dict) and evt["payload"].get("confirmed") is True:
                return True
            if etype.lower() == "fix.verified":
                return True
        serialized = json.dumps(evt.get("payload"), default=str)
        if _has_exact_status_word(serialized, word):
            return True
    return False


def _scan_path_for_secrets(target: Path, secret_list: tuple[str, ...]) -> list[str]:
    leaks: list[str] = []
    files: list[Path] = []
    if target.is_file():
        files.append(target)
    elif target.is_dir():
        for root, _, fnames in os.walk(target):
            for fname in sorted(fnames):
                files.append(Path(root) / fname)

    for fp in files:
        try:
            content = fp.read_bytes().decode("utf-8", errors="replace")
        except OSError as exc:
            leaks.append(f"unreadable_file:{fp}:{exc}")
            continue
        try:
            scan_for_secrets(content, secret_list)
        except SecretLeakError as exc:
            leaks.append(f"{fp}:{exc}")
    return leaks


def _check_modes(run_dir: Path) -> list[str]:
    bad: list[str] = []
    if not run_dir.exists():
        return [f"missing_run_dir:{run_dir}"]
    root_mode = stat.S_IMODE(run_dir.stat().st_mode)
    if (root_mode & 0o077) != 0:
        bad.append(f"dir_mode_too_open:{run_dir}:{oct(root_mode)}")
    for root, dirs, files in os.walk(run_dir):
        for d in sorted(dirs):
            dp = Path(root) / d
            m = stat.S_IMODE(dp.stat().st_mode)
            if (m & 0o077) != 0:
                bad.append(f"dir_mode_too_open:{dp}:{oct(m)}")
        for f in sorted(files):
            fp = Path(root) / f
            m = stat.S_IMODE(fp.stat().st_mode)
            if (m & 0o077) != 0:
                bad.append(f"file_mode_too_open:{fp}:{oct(m)}")
    return bad


def _verify_fix_claim_traceability(
    report_text: str,
    findings: list[Any],
    fix_verified_events: list[dict[str, Any]],
) -> list[str]:
    errors: list[str] = []
    verified_ids: set[str] = set()
    for evt in fix_verified_events:
        pl = evt.get("payload") if isinstance(evt.get("payload"), dict) else {}
        for key in ("finding_id", "objective_id", "technique"):
            if pl.get(key):
                verified_ids.add(str(pl[key]))
        if evt.get("origin_id"):
            verified_ids.add(str(evt["origin_id"]))

    if _VERIFIED_FIX_RE.search(report_text or ""):
        if not fix_verified_events:
            errors.append("report claims 'Verified fix' with zero fix.verified events in ledger")
        else:
            # Check sections mentioning Verified fix trace to a finding with fix.verified.
            sections = re.split(r"(?m)^#{1,4}\s+", report_text or "")
            for sec in sections:
                if not _VERIFIED_FIX_RE.search(sec):
                    continue
                matched_known = False
                for f in findings:
                    fid = str(_get_val(f, "id") or _get_val(f, "objective_id") or "")
                    tech = str(_get_val(f, "technique") or "")
                    if (fid and fid in sec) or (tech and tech in sec):
                        matched_known = True
                        if fid not in verified_ids and tech not in verified_ids:
                            errors.append(f"report claims 'Verified fix' for unverified finding {fid or tech!r}")
                if not matched_known and len(findings) > len(fix_verified_events) and not any(vid in sec for vid in verified_ids):
                    errors.append("report contains 'Verified fix' section not linked to a fix.verified ledger event")

    for f in findings:
        fid = str(_get_val(f, "id") or _get_val(f, "objective_id") or "")
        tech = str(_get_val(f, "technique") or "")
        reattack = _get_val(f, "reattack")
        claims_verified = bool(_get_val(f, "fix_verified", False)) or (
            isinstance(reattack, dict) and reattack.get("label") == "hardened"
        )
        if claims_verified and fid not in verified_ids and tech not in verified_ids:
            errors.append(f"finding {fid or tech!r} claims hardened/verified fix without fix.verified ledger event")

    return errors


def audit_run_integrity(
    run_dir: Path | str,
    report_text: str,
    findings: list[Any],
    plan: dict[str, Any],
    secrets: Iterable[str],
    tests_path: Path | None = None,
) -> IntegrityReport:
    """Run all 8 deterministic integrity checks against run_dir, report_text, findings, and plan."""
    rd = Path(run_dir)
    secret_tuple = tuple(s for s in secrets if isinstance(s, str) and s)
    checks: dict[str, bool] = {}
    failures: list[str] = []
    details: dict[str, Any] = {}

    # 1. Ledger chain check (without creating an empty ledger if missing).
    run_jsonl = rd / "run.jsonl"
    if not run_jsonl.is_file():
        checks["ledger_chain"] = False
        failures.append(f"missing run.jsonl at {run_jsonl}")
        return IntegrityReport(passed=False, checks=checks, failures=failures, details=details)

    ledger = Ledger(rd, secrets=secret_tuple)
    chain_ok = ledger.verify_chain()
    all_events = _collect_ledger_text_blobs(ledger)
    checks["ledger_chain"] = bool(chain_ok and len(all_events) > 0)
    if not checks["ledger_chain"]:
        failures.append("ledger hash chain invalid or empty")

    # 2. Hidden judge controls passed.
    passed_ctrls = ledger.events("judge.controls_passed")
    failed_ctrls = ledger.events("judge.controls_failed")
    judge_ok = (
        len(passed_ctrls) >= 1
        and len(failed_ctrls) == 0
        and all(
            isinstance(e.get("payload"), dict) and e["payload"].get("passed", True) is True
            for e in passed_ctrls
        )
    )
    checks["judge_controls"] = judge_ok
    if not judge_ok:
        failures.append("judge.controls_passed missing or judge.controls_failed present in ledger")

    # 3. Finding trust tier & critic confirmation.
    prov_errs: list[str] = []
    for idx, f in enumerate(findings):
        fid = str(_get_val(f, "id") or _get_val(f, "objective_id") or f"finding[{idx}]")
        tier = _get_val(f, "trust_tier", "")
        if hasattr(tier, "value"):
            tier = tier.value
        critic_ok = _get_val(f, "critic_confirmed", None)
        if tier not in ("machine_confirmed", "human_reviewed"):
            prov_errs.append(f"{fid}: invalid trust_tier={tier!r}")
        if critic_ok is not True:
            prov_errs.append(f"{fid}: critic_confirmed is not True ({critic_ok!r})")
    checks["finding_provenance"] = len(prov_errs) == 0
    if prov_errs:
        failures.extend(prov_errs)
    details["provenance_errors"] = prov_errs

    # 4. Quote hash traceability.
    quote_errs: list[str] = []
    for idx, f in enumerate(findings):
        fid = str(_get_val(f, "id") or _get_val(f, "objective_id") or f"finding[{idx}]")
        quotes = _get_val(f, "quotes", []) or []
        for q_idx, q in enumerate(quotes):
            q_text = q.get("text", "") if isinstance(q, dict) else str(q)
            if not q_text:
                quote_errs.append(f"{fid}: quote[{q_idx}] has empty text")
                continue
            ok, seq = ledger.has_quote_hash(q_text)
            if not ok:
                quote_errs.append(f"{fid}: quote[{q_idx}] not found/hash-verified in ledger")
            elif isinstance(q, dict) and q.get("log_seq") is not None:
                if ledger.get_by_seq(int(q["log_seq"])) is None:
                    quote_errs.append(f"{fid}: quote[{q_idx}] log_seq={q.get('log_seq')} missing in ledger")
    checks["quote_hashes"] = len(quote_errs) == 0
    if quote_errs:
        failures.extend(quote_errs)
    details["quote_errors"] = quote_errs

    # 5. Status-word & number traceability.
    fix_verified_evts = ledger.events("fix.verified")
    trace_errs = _verify_fix_claim_traceability(report_text, findings, fix_verified_evts)

    prose_texts: list[tuple[str, str]] = []
    for idx, f in enumerate(findings):
        fid = str(_get_val(f, "id") or _get_val(f, "objective_id") or f"finding[{idx}]")
        for field_name in ("prose", "summary", "description", "narrative", "proof", "witness"):
            val = _get_val(f, field_name)
            if isinstance(val, str) and val.strip():
                prose_texts.append((f"{fid}.{field_name}", val))
                untraced_nums = verify_prose_numbers(val, ledger)
                if untraced_nums:
                    trace_errs.append(f"{fid}.{field_name} has untraced numbers: {untraced_nums}")

    # Verify status words appearing in finding prose or report_text trace to ledger records.
    all_status_sources = [("report_text", report_text or "")] + prose_texts
    for src_label, txt in all_status_sources:
        for sword in _STATUS_WORDS:
            if _has_exact_status_word(txt, sword):
                if not _ledger_has_status_token(all_events, sword):
                    trace_errs.append(f"{src_label} uses status word {sword!r} with no matching ledger record")

    checks["status_and_number_traceability"] = len(trace_errs) == 0
    if trace_errs:
        failures.extend(trace_errs)
    details["traceability_errors"] = trace_errs

    # 6. Secret scan across run_dir and optional tests_path.
    secret_leaks = _scan_path_for_secrets(rd, secret_tuple)
    if tests_path is not None:
        tp = Path(tests_path)
        if tp.exists():
            secret_leaks.extend(_scan_path_for_secrets(tp, secret_tuple))
        else:
            secret_leaks.append(f"missing_tests_path:{tp}")
    checks["secret_scan"] = len(secret_leaks) == 0
    if secret_leaks:
        failures.extend(secret_leaks)
    details["secret_leaks"] = secret_leaks

    # 7. Restrictive file & directory permissions (0o600 / 0o700).
    mode_errs = _check_modes(rd)
    checks["file_modes"] = len(mode_errs) == 0
    if mode_errs:
        failures.extend(mode_errs)
    details["mode_errors"] = mode_errs

    # 8. Recon grounding check.
    grounding_errs: list[str] = []
    surfaces = plan.get("surfaces") if isinstance(plan, dict) else None
    if not isinstance(surfaces, dict):
        grounding_errs.append("plan missing 'surfaces' mapping")
    else:
        dropped = surfaces.get("dropped_ungrounded_count")
        if not isinstance(dropped, int) or isinstance(dropped, bool) or dropped < 0:
            grounding_errs.append("plan.surfaces missing non-negative integer 'dropped_ungrounded_count'")
        if isinstance(plan.get("ungrounded_claims"), list) and plan["ungrounded_claims"]:
            grounding_errs.append("plan still contains non-empty ungrounded_claims")
        for list_key in ("claims", "items", "routes", "tools", "mcp_tools", "state_endpoints"):
            entries = surfaces.get(list_key)
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                if entry.get("ungrounded") is True or entry.get("grounded") is False or entry.get("grounding") == "ungrounded":
                    grounding_errs.append(f"ungrounded entry remains in surfaces.{list_key}: {entry}")
                    continue
                if list_key in ("claims", "items"):
                    has_code_ref = bool(entry.get("file")) and isinstance(entry.get("line"), int) and entry["line"] >= 1
                    log_seq = entry.get("log_seq")
                    has_log_ref = isinstance(log_seq, int) and ledger.get_by_seq(log_seq) is not None
                    if not (has_code_ref or has_log_ref):
                        grounding_errs.append(f"claim in surfaces.{list_key} lacks valid file:line or ledger log_seq: {entry}")
    checks["recon_grounding"] = len(grounding_errs) == 0
    if grounding_errs:
        failures.extend(grounding_errs)
    details["grounding_errors"] = grounding_errs

    return IntegrityReport(
        passed=all(checks.values()),
        checks=checks,
        failures=failures,
        details=details,
    )


def export_human_review_sample(
    run_dir: Path | str,
    ledger: Ledger,
    findings: list[Any],
    rejected: list[Any],
    *,
    secrets: Iterable[str] = (),
    sample_rate: float = 0.25,
    min_items: int = 2,
) -> Path:
    """Export a secret-scanned 0o600 human review sample combining findings and rejected items."""
    rd = Path(run_dir)
    pool: list[tuple[str, Any]] = [("finding", f) for f in findings] + [("rejected", r) for r in rejected]
    if not pool:
        selected: list[tuple[str, Any]] = []
    else:
        target_n = min(len(pool), max(int(min_items), math.ceil(len(pool) * float(sample_rate))))
        rng = secrets_mod_rng()
        # Ensure mix when both categories exist and target_n >= 2.
        if findings and rejected and target_n >= 2:
            chosen_f = rng.choice(findings)
            chosen_r = rng.choice(rejected)
            selected = [("finding", chosen_f), ("rejected", chosen_r)]
            remaining = [item for item in pool if item[1] is not chosen_f and item[1] is not chosen_r]
            if target_n > 2 and remaining:
                selected.extend(rng.sample(remaining, min(target_n - 2, len(remaining))))
        else:
            selected = rng.sample(pool, target_n)

    records: list[dict[str, Any]] = []
    for idx, (category, item) in enumerate(selected):
        quotes = _get_val(item, "quotes", []) or []
        seqs: list[int] = []
        for q in quotes:
            if isinstance(q, dict) and isinstance(q.get("log_seq"), int):
                if ledger.get_by_seq(q["log_seq"]) is not None:
                    seqs.append(q["log_seq"])
        tier = _get_val(item, "trust_tier", "unverified")
        if hasattr(tier, "value"):
            tier = tier.value
        records.append(
            {
                "sample_index": idx,
                "category": category,
                "id": str(_get_val(item, "id") or _get_val(item, "objective_id") or f"{category}-{idx}"),
                "technique": str(_get_val(item, "technique") or ""),
                "model_verdict": "confirmed" if category == "finding" else "rejected",
                "trust_tier": str(tier),
                "witness": str(_get_val(item, "witness") or _get_val(item, "reason") or ""),
                "quotes": quotes,
                "ledger_seqs": sorted(set(seqs)),
                "human_verdict": None,
                "human_notes": "",
            }
        )

    out_path = rd / "human_review_sample.json"
    payload = {"sample_rate": float(sample_rate), "total_pool": len(pool), "items": records}
    safe_write_text(out_path, json.dumps(payload, indent=2, default=str) + "\n", secrets=secrets)
    return out_path


def secrets_mod_rng() -> secrets.SystemRandom:
    return secrets.SystemRandom()


def _normalize_verdict(val: Any) -> str:
    if isinstance(val, bool):
        return "confirmed" if val else "rejected"
    s = str(val).strip().lower()
    if s in ("confirmed", "reproduced", "true_positive", "tp", "accept", "accepted", "valid", "yes"):
        return "confirmed"
    if s in ("rejected", "not_reproduced", "false_positive", "fp", "reject", "invalid", "no"):
        return "rejected"
    return s


def compute_human_model_disagreement(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Compute human vs model disagreement across reviewed sample records."""
    reviewed = [
        rec
        for rec in (records or [])
        if isinstance(rec, dict) and rec.get("human_verdict") is not None and str(rec.get("human_verdict")).strip() != ""
    ]
    total_reviewed = len(reviewed)
    disagreements = 0
    for rec in reviewed:
        model_v = _normalize_verdict(rec.get("model_verdict"))
        human_v = _normalize_verdict(rec.get("human_verdict"))
        if model_v != human_v:
            disagreements += 1
    rate = (disagreements / total_reviewed) if total_reviewed > 0 else 0.0
    return {
        "total_reviewed": total_reviewed,
        "disagreements": disagreements,
        "disagreement_rate": rate,
    }


__all__ = [
    "IntegrityReport",
    "audit_run_integrity",
    "compute_human_model_disagreement",
    "export_human_review_sample",
    "verify_prose_numbers",
]
