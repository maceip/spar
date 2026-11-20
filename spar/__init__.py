"""Spar: autonomous AI red-team & verification system.

One program, one job: break the target system, prove the compromise
empirically, and verify the fix.
"""

__version__ = "0.1.0"

from .cli import main
from .loop import ReplaySummary, RunSummary, run_campaign, run_replay
from .oracles import Outcome, TrustTier
from .policy import CampaignPolicy, ConfigError, CredentialStore, GuardViolation
from .report import Finding, calibrate_severity, dedupe_findings, emit_pytest_suite, emit_report, redact, wilson_interval

__all__ = [
    "CampaignPolicy",
    "ConfigError",
    "CredentialStore",
    "Finding",
    "GuardViolation",
    "Outcome",
    "ReplaySummary",
    "RunSummary",
    "TrustTier",
    "__version__",
    "calibrate_severity",
    "dedupe_findings",
    "emit_pytest_suite",
    "emit_report",
    "main",
    "redact",
    "run_campaign",
    "run_replay",
    "wilson_interval",
]
