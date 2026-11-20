"""spar/report/: fewer, proven findings.

3-tier deduplication, exploit-chain composition, severity calibration,
redacted Markdown report, failing pytest regression suite, and fix diffs
verified by independent re-attack.
"""

from .model import Finding, SEVERITY_BASE
from .dedupe import dedupe_findings
from .report import emit_report, redact
from .pytest_gen import emit_pytest_suite
from .fixdiff import synthesize_fix, apply_fix, FIX_RECIPES

__all__ = [
    "Finding", "SEVERITY_BASE", "dedupe_findings", "emit_report", "redact",
    "emit_pytest_suite", "synthesize_fix", "apply_fix", "FIX_RECIPES",
]
