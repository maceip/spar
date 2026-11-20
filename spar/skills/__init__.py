"""spar/skills/: webhook listener (wake re-attack on git push / PR),
portable agent skills, and the spar_check MCP entrypoint."""

from .webhook import serve_webhook

__all__ = ["serve_webhook"]
