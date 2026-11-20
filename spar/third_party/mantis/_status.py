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

"""Finding-status predicates used by the vendored Mantis ``sarif`` module.

The status tuples and the ``is_untriaged`` / ``is_suppressed`` predicates below are
copied verbatim from Google Mantis ``reference/core/database.py`` (Apache-2.0). Only
the surrounding SQLite machinery was left behind; the classification logic is
unchanged so the vendored ``sarif.build_sarif`` filters findings exactly as upstream
does. See ``spar/third_party/mantis/__init__.py`` for provenance.
"""

from __future__ import annotations

from typing import Any

FALSE_POSITIVE_STATUSES = (
    "false_positive",
    "non_viable",
    "sample_or_test",
)
UNTRIAGED_STATUSES = ("reported",)
CLOSED_STATUSES = FALSE_POSITIVE_STATUSES + ("duplicate_merged", "mitigated", "accepted_risk", "archived")
CONFIRMED_LIVE_STATUSES = (
    "confirmed",
    "viable",
    "static_confirmed",
    "reproduced",
    "dynamic_confirmed",
    "patch_verified",
)
OPEN_CONFIRMED_STATUSES = (
    "confirmed",
    "viable",
    "static_confirmed",
    "reproduced",
    "dynamic_confirmed",
)
OPEN_FINDING_STATUSES = UNTRIAGED_STATUSES + OPEN_CONFIRMED_STATUSES
ACTIVE_STATUSES = UNTRIAGED_STATUSES + CONFIRMED_LIVE_STATUSES
ALL_STATUSES = ACTIVE_STATUSES + FALSE_POSITIVE_STATUSES

# Statuses meaning "looked at and set aside" (closed verdicts, merges, mitigations,
# archived code shifts) plus untriaged defaults that must never ship as confirmed alerts.
SUPPRESSED_STATUSES = CLOSED_STATUSES + UNTRIAGED_STATUSES


def is_untriaged(status: Any) -> bool:
    """True when a status represents an unreviewed initial candidate claim."""
    return str(status or "").strip().lower() in UNTRIAGED_STATUSES


def is_suppressed(status: Any) -> bool:
    """True when a status means the finding should not be presented as live.

    Case-insensitive on purpose, matching upstream Mantis: the LLM-facing vocabulary
    is declared in upper case while the filters compare in lower case.
    """
    return str(status or "").strip().lower() in SUPPRESSED_STATUSES
