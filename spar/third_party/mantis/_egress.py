# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Terminal-control egress sanitizer used by the vendored Mantis ``sarif`` module.

``_ANSI_ESCAPE_RE``, ``_CONTROL_CHAR_RE`` and ``strip_terminal_control`` are copied
verbatim from Google Mantis ``reference/core/llm_gateway.py`` (Apache-2.0). Upstream,
``sanitize_egress_text`` also runs a ``SecretScrubber`` pass; Spar performs its own
secret redaction (``spar.report.redact`` / ``spar.guard.scan_for_secrets``) before any
text reaches SARIF emission, so the vendored sanitizer here keeps only the
control-sequence stripping. See ``spar/third_party/mantis/__init__.py`` for provenance.
"""

from __future__ import annotations

import re

# Strip every escape that could relocate a terminal, not just CSI colour codes:
#   OSC (7-bit and 8-bit)      window title / hyperlink injection
#   CSI (7-bit and 8-bit)      cursor movement, colours, erasure
_ANSI_ESCAPE_RE = re.compile(
    "|".join(
        (
            r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?",  # OSC (7-bit)
            r"\x9d[^\x07\x9c]*(?:\x07|\x9c)?",  # OSC (8-bit C1)
            r"\x1b\[[0-?]*[ -/]*[@-~]",  # CSI (7-bit)
            r"\x9b[0-?]*[ -/]*[@-~]",  # CSI (8-bit C1)
        )
    )
)

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def strip_terminal_control(text: str) -> str:
    """Removes all terminal escape sequences and control characters except tab/newline."""
    if not text:
        return ""
    return _CONTROL_CHAR_RE.sub("", _ANSI_ESCAPE_RE.sub("", str(text)))


def sanitize_egress_text(text: str) -> str:
    """Strip terminal control sequences from human-readable SARIF text.

    Upstream Mantis also scrubs credentials here; in Spar that scrubbing is performed
    by ``spar.report.redact`` before findings reach this module, so this retains only
    the control-sequence stripping. Idempotent and safe on trusted text.
    """
    if not text:
        return ""
    return strip_terminal_control(str(text))
