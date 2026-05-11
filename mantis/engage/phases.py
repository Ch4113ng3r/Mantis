"""
Base Phase class that all engagement phases inherit from.

Each phase implements execute(context) -> dict, which receives
the shared EngagementContext and returns a dict of results to
merge back into the context.
"""

from abc import ABC, abstractmethod
from typing import Any


class Phase(ABC):
    """
    Abstract base class for engagement phases.

    Every phase (port_scan, crawl, triage, exploit, etc.) inherits
    from this and implements execute(). The EngagementRunner calls
    phases in sequence based on the selected mode.
    """

    def __init__(self, config):
        """
        Args:
            config: EngagementConfig with target, scope, options.
        """
        self.config = config

    @property
    def name(self) -> str:
        """Phase name used in checkpointing and logging."""
        return self.__class__.__name__

    @abstractmethod
    async def execute(self, context) -> dict:
        """
        Execute this phase.

        Args:
            context: EngagementContext with accumulated state.

        Returns:
            Dict of results to merge into context. Keys should match
            EngagementContext field names (findings, endpoints, etc.)
        """
        ...
