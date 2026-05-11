"""
Simple pub/sub event bus for inter-module communication.

Modules can emit events (finding_discovered, guardrail_blocked,
phase_complete, etc.) and other modules can subscribe to them
for logging, metrics, or reactive behavior.
"""

from dataclasses import dataclass, field
from typing import Callable, Any
from datetime import datetime


@dataclass
class Event:
    """A single event on the bus."""
    name: str
    data: dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class EventBus:
    """
    Simple synchronous event bus.

    Usage:
        bus = EventBus()
        bus.subscribe("finding_discovered", lambda e: print(e.data))
        bus.emit(Event("finding_discovered", {"id": "F-001", "title": "SQLi"}))
    """

    def __init__(self):
        self._handlers: dict[str, list[Callable]] = {}

    def subscribe(self, event_name: str, handler: Callable[[Event], None]):
        """Subscribe a handler to an event type."""
        if event_name not in self._handlers:
            self._handlers[event_name] = []
        self._handlers[event_name].append(handler)

    def emit(self, event: Event):
        """Emit an event to all subscribers."""
        for handler in self._handlers.get(event.name, []):
            try:
                handler(event)
            except Exception:
                pass  # Don't let handler errors break the pipeline

    def emit_simple(self, name: str, **data):
        """Convenience: emit an event with keyword arguments."""
        self.emit(Event(name, data))
