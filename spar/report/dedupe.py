"""3-tier deduplication (mantis-dedupe pattern).

Tier 1: exact identity — same technique + oracle + witness resource ids.
Tier 2: evidence hash — same compromised content (body hashes) even if the
        path differed.
Tier 3: chain composition (mantis-chain) — a finding whose exploit chain
        embeds another finding's primitive is linked, not duplicated; the
        chain is reported on the end-to-end finding.
"""

from __future__ import annotations

import hashlib
import json

from .model import Finding


def _t1_key(f: Finding) -> str:
    ids = sorted(f.evidence.get("victim_resource_ids") or f.evidence.get("victim_doc_ids") or [])
    return json.dumps([f.technique, f.oracle, ids, f.evidence.get("attacker_inbox", ""), f.evidence.get("invoice_id", "")], sort_keys=True)


def _t2_key(f: Finding) -> str:
    bodies = []
    for v in (f.evidence.get("stolen") or {}).values():
        if isinstance(v, dict) and v.get("body_sha256"):
            bodies.append(v["body_sha256"])
    for e in f.evidence.get("exfiltrated_emails", []):
        bodies.append(hashlib.sha256(json.dumps(e, sort_keys=True, default=str).encode()).hexdigest())
    return hashlib.sha256(json.dumps(sorted(bodies)).encode()).hexdigest() if bodies else ""


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    uniq: list[Finding] = []
    by_t1: dict[str, Finding] = {}
    by_t2: dict[str, Finding] = {}
    for f in findings:
        k1 = _t1_key(f)
        if k1 in by_t1:
            by_t1[k1].duplicates += 1
            by_t1[k1].k = max(by_t1[k1].k, f.k)
            continue
        k2 = _t2_key(f)
        if k2 and k2 in by_t2:
            by_t2[k2].duplicates += 1
            continue
        by_t1[k1] = f
        if k2:
            by_t2[k2] = f
        uniq.append(f)

    # Tier 3: chain linking. If finding A's chain references finding B's
    # primitive, mark B as a link of A (B stays listed only if it also
    # stands alone as its own objective — then we annotate, never drop
    # verified standalone findings).
    for f in uniq:
        links = []
        for step in f.chain:
            # chain entries look like "idor-read:<doc>" or "refund:<inv>"
            if step.startswith("idor-read:") and any(o.technique == "cross_tenant_access" for o in uniq):
                links.append("cross_tenant_access")
        if links:
            f.chain_links = sorted(set(links))  # type: ignore[attr-defined]
    return uniq
