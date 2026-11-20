"""Redaction + Markdown report emitter (.spar/report.md).

Transcripts containing harmful content stay local under restricted
permissions; shared reports carry redacted evidence: proof witnesses,
trial ratios, hashes — never raw secrets or account tokens.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path

from .model import Finding

TOKEN_RE = re.compile(r"\b(token-[\w-]+)\b")
BEARER_RE = re.compile(r"(?i)bearer\s+[\w.-]+")


def redact(obj):
    """Recursively redact credentials and oversized bodies from evidence."""
    if isinstance(obj, str):
        out = TOKEN_RE.sub("token-[REDACTED]", obj)
        out = BEARER_RE.sub("Bearer [REDACTED]", out)
        if len(out) > 300:
            out = out[:300] + f"… [{len(obj)} bytes total; full transcript in .spar/attempts.jsonl]"
        return out
    if isinstance(obj, dict):
        return {k: ("[REDACTED]" if k in ("token", "api_key", "authorization") else redact(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj


def emit_report(
    findings: list[Finding],
    rejected: list[dict],
    plan: dict,
    recon_summary: dict,
    budget_summary: dict,
    run_dir: Path,
    repo: str | None,
    target: str,
) -> Path:
    run_dir = Path(run_dir)
    n_obj = len(plan.get("objectives", []))
    trials_n = plan.get("trials_n", 0)
    achieved = len(findings)
    critic_rejections = sum(int(r.get("candidate_hits", 0)) for r in rejected)

    lines = []
    lines.append("# Spar red-team report")
    lines.append("")
    lines.append(f"- **Target:** `{target}`" + (f"  (repo: `{repo}`)" if repo else "  (black-box: no --repo)"))
    lines.append(f"- **Run:** {time.strftime('%Y-%m-%d %H:%M:%S')}")
    snap = plan.get("snapshot_id", {})
    lines.append(
        f"- **Snapshot pin:** git `{snap.get('git_commit_sha')}` · model `{snap.get('model_id')}` · "
        f"prompt `{(snap.get('system_prompt_sha256') or 'n/a')[:12]}…` · tools `{snap.get('tool_schema_sha256', '')[:12]}…`"
    )
    lines.append("")
    lines.append(
        f"**Spar: {n_obj} objectives x {trials_n} trials, {achieved} achieved, "
        f"{critic_rejections} candidate hits rejected by the critic**"
    )
    tools = recon_summary.get("tools", [])
    side = sum(1 for t in tools if t.get("side_effect"))
    lines.append(
        f"**Recon:** {len(tools)} tools ({side} with side effects), "
        f"system prompt {'recovered' if snap.get('system_prompt_sha256') else 'not indexed'}, "
        f"{len(recon_summary.get('retrieval_sources', []))} retrieval source(s), "
        f"{len(recon_summary.get('permission_anomalies', []))} permission anomaly(ies)**"
    )
    lines.append("")

    if findings:
        lines.append("## Verified findings")
        lines.append("")
        lines.append("| Sev | Objective | k/N | Proof witness |")
        lines.append("|-----|-----------|-----|---------------|")
        for f in sorted(findings, key=lambda x: ({"HIGH": 0, "MED": 1, "LOW": 2}[x.severity], -x.success_rate)):
            lines.append(f"| {f.severity} | {f.objective} | {f.k}/{f.n} | {f.witness} |")
        lines.append("")
        for f in findings:
            lines.append(f"### [{f.severity}] {f.objective}")
            lines.append("")
            lines.append(f"- **Finding id:** `{f.id}`  ·  **technique:** `{f.technique}`  ·  **label:** {f.label}")
            lines.append(f"- **Empirical success rate:** {f.k}/{f.n} trials ({f.success_rate:.0%})")
            lines.append(f"- **Oracle:** {f.oracle} — {f.witness}")
            lines.append(f"- **Critic:** {f.critic_reason}")
            if f.chain:
                lines.append(f"- **Exploit chain:** {' → '.join(f.chain)}")
            if f.tags:
                lines.append(f"- **Frameworks:** {', '.join(f.tags)}")
            if f.duplicates:
                lines.append(f"- **Dedup:** {f.duplicates} duplicate candidate(s) merged")
            lines.append("")
            lines.append("<details><summary>Redacted evidence</summary>")
            lines.append("")
            lines.append("```json")
            lines.append(json.dumps(redact(f.evidence), indent=2, default=str))
            lines.append("```")
            lines.append("</details>")
            lines.append("")
            if f.fix_diff:
                lines.append("<details><summary>Verified fix diff</summary>")
                lines.append("")
                lines.append("```diff")
                lines.append(f.fix_diff.rstrip())
                lines.append("```")
                lines.append("</details>")
                lines.append("")
            if f.reattack:
                ra = f.reattack
                lines.append(
                    f"**Re-attack after fix:** `{ra.get('label')}` — {ra.get('k')}/{ra.get('n')} trials "
                    f"({ra.get('note', '')})"
                )
                lines.append("")
    else:
        lines.append("## Verified findings")
        lines.append("")
        lines.append("None. Every candidate was rejected by the oracle or the independent critic.")
        lines.append("")

    if rejected:
        lines.append("## Rejected candidates (critic log)")
        lines.append("")
        for r in rejected:
            lines.append(f"- `{r.get('objective_id')}` — {r.get('reason')} (candidate hits: {r.get('candidate_hits', 0)})")
        lines.append("")

    lines.append("## Outputs")
    lines.append("")
    lines.append(f"- report: `.spar/report.md` — proof, transcript and verified fix diff per finding")
    lines.append(f"- tests: `spar_tests/test_attacks.py` — one failing regression test per verified finding (auto re-attacks on patch commit)")
    lines.append(
        f"- cost: ${budget_summary.get('usd_spent', 0):.2f} in model calls "
        f"({budget_summary.get('llm_calls', 0)} LLM calls), "
        f"{budget_summary.get('requests', 0)} guarded requests, "
        f"{budget_summary.get('elapsed_s', 0) / 60:.0f} min"
    )
    lines.append(f"- evidence ledger: `.spar/attempts.jsonl` (SHA-256 hash-chained, origin_id lineage)")
    lines.append("")
    lines.append("## Rules of engagement honored")
    lines.append("")
    lines.append("- Scope enforced in deterministic Python hooks; only spar.yaml-allowlisted hosts touched.")
    lines.append("- Synthetic canaries (SPAR-xxxx) under isolated test accounts; no production user data.")
    lines.append("- Target replies fenced as untrusted data before evaluation (reverse-injection defense).")
    lines.append("- Nothing reported without an oracle match and an independent critic's sign-off.")
    lines.append("")

    path = run_dir / "report.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    try:
        path.chmod(0o600)
        (run_dir / "attempts.jsonl").chmod(0o600)
    except OSError:
        pass
    return path
