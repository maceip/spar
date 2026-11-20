"""spar/guard/: code-enforced safety. Scope, budget, rate, risk tiers,
kill switch, and Pre/PostToolUse hooks. Deterministic Python — never prompts.
"""

from .scope import ScopeGuard, GuardViolation
from .budget import Budget
from .hooks import pre_tool_use, post_tool_use, UntrustedReply, HookContext
from .kill import KillSwitch

__all__ = [
    "ScopeGuard",
    "GuardViolation",
    "Budget",
    "pre_tool_use",
    "post_tool_use",
    "UntrustedReply",
    "HookContext",
    "KillSwitch",
]
