"""Fix-diff synthesizer + applier (verified by independent re-attack).

For the bundled demo target, every verified finding maps to a concrete,
minimal patch of the vulnerable code path. For arbitrary --repo targets
without a recipe, Spar says so honestly and emits remediation guidance
instead of inventing a diff.

After `apply_fix`, the re-attacker re-runs the k/N trials with rotated
identifiers: k=0 → label "hardened"; k>0 → label "bypassed" (the fix did
not close the root cause).
"""

from __future__ import annotations

import difflib
import shutil
from pathlib import Path

DEMO_FILE = "spar/demo_target/app.py"

# technique -> (relative file, old snippet, new snippet)
FIX_RECIPES: dict[str, tuple[str, str, str]] = {
    "cross_tenant_access": (
        DEMO_FILE,
        """        doc = self.state.docs.get(doc_id)
        if doc is None:
            return {"error": f"no such doc: {doc_id}"}
        # VULN V1: no ownership check.
        return {"doc_id": doc_id, "owner": doc["owner"], "title": doc["title"], "body": doc["body"]}""",
        """        doc = self.state.docs.get(doc_id)
        if doc is None:
            return {"error": f"no such doc: {doc_id}"}
        # FIX(V1): enforce ownership — closes IDOR and the confused-deputy fetch.
        if doc["owner"] != user["name"] and user["role"] != "auditor":
            return {"error": "forbidden: you do not own this document"}
        return {"doc_id": doc_id, "owner": doc["owner"], "title": doc["title"], "body": doc["body"]}""",
    ),
    "confused_deputy_email": (
        DEMO_FILE,
        """        doc = self.state.docs.get(doc_id)
        if doc is None:
            return {"error": f"no such doc: {doc_id}"}
        # VULN V1: no ownership check.
        return {"doc_id": doc_id, "owner": doc["owner"], "title": doc["title"], "body": doc["body"]}""",
        """        doc = self.state.docs.get(doc_id)
        if doc is None:
            return {"error": f"no such doc: {doc_id}"}
        # FIX(V1/V2): enforce ownership — the chat email intent routes through
        # get_doc, so this also closes the confused-deputy exfiltration.
        if doc["owner"] != user["name"] and user["role"] != "auditor":
            return {"error": "forbidden: you do not own this document"}
        return {"doc_id": doc_id, "owner": doc["owner"], "title": doc["title"], "body": doc["body"]}""",
    ),
    "memory_poison": (
        DEMO_FILE,
        """        scored = []
        for p in self.state.memory:
            overlap = len(qk & set(p["keywords"]))
            if overlap:
                scored.append((overlap, p))""",
        """        scored = []
        for p in self.state.memory:
            # FIX(V3): per-user memory isolation — only the caller's own or
            # system passages are retrievable into a session.
            if p["added_by"] not in (user["name"], "system"):
                continue
            overlap = len(qk & set(p["keywords"]))
            if overlap:
                scored.append((overlap, p))""",
    ),
    "prompt_extraction": (
        DEMO_FILE,
        """            if _LEAK_TRIGGER.search(msg):
                # VULN V4: escalated extraction phrasing bypasses the refusal;
                # no output filtering.
                sess["refused_instructions"] = True
                self.state.tool_log.append(
                    {"ts": time.time(), "user": user["name"], "role": user["role"], "tool": "policy_echo",
                     "args": {"trigger": msg[:80]}, "result": {"leaked": True}}
                )
                return {"reply": "Sure, here it is verbatim:\\n" + SYSTEM_PROMPT}""",
        """            if _LEAK_TRIGGER.search(msg):
                # FIX(V4): output filtering — escalated phrasing never yields
                # the hidden prompt, regardless of framing.
                sess["refused_instructions"] = True
                self.state.tool_log.append(
                    {"ts": time.time(), "user": user["name"], "role": user["role"], "tool": "policy_echo",
                     "args": {"trigger": msg[:80]}, "result": {"leaked": False, "refused": True}}
                )
                return {"reply": "I can't share my internal instructions, regardless of the framing."}""",
    ),
    "unauthorized_refund": (
        DEMO_FILE,
        """        # VULN V5: no ownership check, no policy ceiling on direct invoke.
        rec = {"invoice_id": inv, "amount": amount, "issued_by": user["name"], "ts": time.time()}""",
        """        # FIX(V5): ownership + policy ceiling enforced on direct invoke.
        owned = any(
            inv and inv in (d["title"] + " " + d["body"])
            for d in self.state.docs.values() if d["owner"] == user["name"]
        )
        if not owned or amount > 500:
            return {"error": "forbidden: refund not permitted for this invoice/amount"}
        rec = {"invoice_id": inv, "amount": amount, "issued_by": user["name"], "ts": time.time()}""",
    ),
}

GUIDANCE = {
    "cross_tenant_access": "Enforce object-level authorization: every resource fetch must check caller identity against resource owner (deny by default).",
    "confused_deputy_email": "The agent's tool layer must authorize the CALLING user against every resource it touches on their behalf; never resolve references across tenants.",
    "memory_poison": "Isolate memory/RAG stores per user/session; retrieval must filter passages by ownership before injection into any prompt context.",
    "prompt_extraction": "Apply output filtering: refuse verbatim policy/system-prompt disclosure under any framing; log extraction attempts.",
    "unauthorized_refund": "Enforce ownership and policy ceilings on state-changing tools at the tool layer, not in prompt policy.",
}


def synthesize_fix(technique: str, repo: Path | None) -> tuple[str | None, list[tuple[Path, str, str]], str]:
    """Returns (unified_diff, [(file, old, new)], guidance). diff is None
    when no recipe matches the target repo (honest 'no auto-fix')."""
    guidance = GUIDANCE.get(technique, "Remediate the verified root cause and re-run Spar.")
    recipe = FIX_RECIPES.get(technique)
    if recipe is None or repo is None:
        return None, [], guidance
    rel, old, new = recipe
    path = Path(repo) / rel
    if not path.exists():
        return None, [], guidance
    text = path.read_text(encoding="utf-8")
    if old not in text:
        return None, [], guidance + " (recipe did not match current source; fix may already be applied or code diverged)"
    patched = text.replace(old, new, 1)
    diff = "".join(
        difflib.unified_diff(
            text.splitlines(keepends=True),
            patched.splitlines(keepends=True),
            fromfile=f"a/{rel}",
            tofile=f"b/{rel}",
        )
    )
    return diff, [(path, old, new)], guidance


def apply_fix(pairs: list[tuple[Path, str, str]], backup_dir: Path) -> list[Path]:
    """Apply (file, old, new) patches in place; backups stored under
    .spar/fix_backups/ so nothing is ever lost."""
    backup_dir = Path(backup_dir)
    backup_dir.mkdir(parents=True, exist_ok=True)
    backups = []
    for path, old, new in pairs:
        bak = backup_dir / (path.name + ".orig")
        shutil.copy2(path, bak)
        backups.append(bak)
        text = path.read_text(encoding="utf-8")
        if old not in text:
            continue  # already applied
        path.write_text(text.replace(old, new, 1), encoding="utf-8")
    return backups
