"""Spar Stage 2 attack suite: PyRIT adapter, dynamic recipes, held-out & benign suites."""

from __future__ import annotations

from .benign import BenignReport, run_benign_suite
from .fixtures import REGRESSION_FIXTURE, REGRESSION_FIXTURES
from .held_out import HELD_OUT_VARIANTS, run_held_out
from .pyrit_adapter import (
    Base64Converter,
    BitmapImagePromptConverter,
    CrescendoAttackLoop,
    CrescendoResult,
    LeetspeakConverter,
    MultilingualConverter,
    ROT13Converter,
    SparPyRITTarget,
    UnicodeConfusableConverter,
    apply_converter_chain,
    apply_converter_chain_async,
    distinct_technique_count,
    ensure_pyrit_initialized,
    ensure_pyrit_initialized_async,
    extract_prompt_candidate,
    ngram_jaccard,
)
from .recipes import MISSIONS, MissionContext, MissionResult, make_quote, run_mission

__all__ = [
    "Base64Converter",
    "BenignReport",
    "BitmapImagePromptConverter",
    "CrescendoAttackLoop",
    "CrescendoResult",
    "HELD_OUT_VARIANTS",
    "LeetspeakConverter",
    "MISSIONS",
    "MissionContext",
    "MissionResult",
    "MultilingualConverter",
    "REGRESSION_FIXTURE",
    "REGRESSION_FIXTURES",
    "ROT13Converter",
    "SparPyRITTarget",
    "UnicodeConfusableConverter",
    "apply_converter_chain",
    "apply_converter_chain_async",
    "distinct_technique_count",
    "ensure_pyrit_initialized",
    "ensure_pyrit_initialized_async",
    "extract_prompt_candidate",
    "make_quote",
    "ngram_jaccard",
    "run_benign_suite",
    "run_held_out",
    "run_mission",
]
