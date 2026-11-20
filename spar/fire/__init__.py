"""spar/fire/: short-lived mission workers.

Each worker is spawned with fresh context, receives ONE specific objective
and the core tool set, executes its mission, writes structured evidence,
and terminates immediately — failed paths never pollute subsequent trials.
"""

from .tools import ToolKit, ToolUnavailable
from .worker import MissionContext, MissionResult, MISSIONS, run_mission

__all__ = ["ToolKit", "ToolUnavailable", "MissionContext", "MissionResult", "MISSIONS", "run_mission"]
