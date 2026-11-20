"""Bundled demo target: a deliberately vulnerable multi-user agent + API.

TRAINING TARGET ONLY. Every vulnerability (V1-V11) here is intentional,
documented, and safe: the app binds strictly to localhost, all users are
synthetic test accounts (alice, bob, auditor), all data is fabricated, and
all side effects are recorded in memory only.
"""

from .app import (
    BITMAP_FONT_5X7,
    DemoAgent,
    DemoState,
    DemoTarget,
    SYSTEM_PROMPT,
    SYSTEM_PROMPT_SHA256,
    TOOLS,
    VULNS,
    decode_bitmap_png,
    generate_ephemeral_tokens,
    render_bitmap_png,
    run_server,
)

__all__ = [
    "BITMAP_FONT_5X7",
    "DemoAgent",
    "DemoState",
    "DemoTarget",
    "SYSTEM_PROMPT",
    "SYSTEM_PROMPT_SHA256",
    "TOOLS",
    "VULNS",
    "decode_bitmap_png",
    "generate_ephemeral_tokens",
    "render_bitmap_png",
    "run_server",
]
