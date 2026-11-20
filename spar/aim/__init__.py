"""spar/aim/: compile code and recon surfaces into executable missions.

- index.py: Python AST indexer for --repo (white-box aiming)
- recon.py: black-box live probes (automatic when --repo is omitted)
- plan.py: ranked, budgeted plan.json
"""

from .recon import run_recon
from .index import index_repo
from .plan import build_plan

__all__ = ["run_recon", "index_repo", "build_plan"]
