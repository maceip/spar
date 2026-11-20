"""Vendored Google Mantis modules (Apache-2.0).

Source: https://github.com/google/mantis

Spar reuses Mantis's own modules rather than reimplementing them:

- ``sarif.py``   -- Mantis ``reference/core/sarif.py``, verbatim except that its three
  deferred ``from core.database`` / ``from core.llm_gateway`` imports are repointed to
  the sibling shims ``_status`` and ``_egress`` below. The SARIF build and validation
  logic is unmodified.
- ``evidence.py`` -- Mantis ``reference/core/evidence.py``, verbatim. Provides the
  trust-tier model (``TIER_CODE``/``TIER_HISTORY``/``TIER_INTENT``) and the invariant
  ``may_set_verdict`` / ``filter_claim``: only a code-tier (oracle-backed) source may
  assert a verdict field. Spar routes finding verdicts through this.
- ``_status.py``  -- the finding-status tuples and ``is_untriaged`` / ``is_suppressed``
  predicates copied verbatim from Mantis ``reference/core/database.py``; the SQLite
  machinery around them is not vendored.
- ``_egress.py``  -- the terminal-control regexes and ``strip_terminal_control`` copied
  verbatim from Mantis ``reference/core/llm_gateway.py``. Secret scrubbing is done by
  Spar upstream, so only control-sequence stripping is retained here.

The full Apache-2.0 license text is in ``LICENSE`` in this directory, and the vendoring
is recorded in the repository-root ``NOTICE``.
"""

from . import evidence, sarif

__all__ = ["evidence", "sarif"]
