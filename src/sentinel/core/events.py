"""A small thread-safe publish/subscribe bus.

The scan engine runs on a worker pool while the CLI progress bar and the Qt
GUI both need live updates. Rather than couple the engine to either front
end, it emits events here and the front ends subscribe.

Contract for subscribers:

* Handlers are called on the *emitting* thread — usually a scan worker.
  Do the minimum amount of work and never block. The Qt front end forwards
  straight to a signal; the CLI increments a counter.
* An exception in a handler is logged and swallowed. A broken progress bar
  must never abort a scan.
"""

from __future__ import annotations

import contextlib
import threading
import time
from collections import defaultdict
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from sentinel.core.logger import get_logger

log = get_logger(__name__)


class EventType(str, Enum):
    """Every event the engine can publish."""

    SCAN_STARTED = "scan.started"
    SCAN_PROGRESS = "scan.progress"
    SCAN_FINISHED = "scan.finished"
    SCAN_CANCELLED = "scan.cancelled"

    FILE_STARTED = "file.started"
    FILE_SCANNED = "file.scanned"
    FILE_SKIPPED = "file.skipped"
    FILE_ERROR = "file.error"

    THREAT_FOUND = "threat.found"
    SUSPICIOUS_FOUND = "threat.suspicious"

    QUARANTINE_ADDED = "quarantine.added"
    QUARANTINE_RESTORED = "quarantine.restored"
    QUARANTINE_DELETED = "quarantine.deleted"

    SIGNATURES_UPDATED = "signatures.updated"
    SIGNATURES_UPDATE_FAILED = "signatures.update_failed"

    ERROR = "error"


@dataclass(frozen=True, slots=True)
class Event:
    """An immutable notification.

    Attributes:
        type: What happened.
        payload: Event-specific data. Keys are documented per event type in
            docs/architecture.md.
        timestamp: Unix time the event was created.
    """

    type: EventType
    payload: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def get(self, key: str, default: Any = None) -> Any:
        return self.payload.get(key, default)

    def __str__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Event {self.type.value} {self.payload!r}>"


Handler = Callable[[Event], None]

#: Sentinel key used to subscribe to every event type.
ALL = "*"


class EventBus:
    """Thread-safe fan-out of :class:`Event` objects to handlers."""

    def __init__(self) -> None:
        self._handlers: dict[str, list[Handler]] = defaultdict(list)
        self._lock = threading.RLock()
        self._muted = False

    # -- subscription --------------------------------------------------

    def subscribe(self, event_type: EventType | str, handler: Handler) -> Callable[[], None]:
        """Register *handler*; returns a callable that unsubscribes it.

        Pass :data:`ALL` as *event_type* to receive everything.
        """
        key = event_type.value if isinstance(event_type, EventType) else event_type
        with self._lock:
            self._handlers[key].append(handler)

        def unsubscribe() -> None:
            self.unsubscribe(key, handler)

        return unsubscribe

    def subscribe_all(self, handler: Handler) -> Callable[[], None]:
        """Shorthand for ``subscribe(ALL, handler)``."""
        return self.subscribe(ALL, handler)

    def unsubscribe(self, event_type: EventType | str, handler: Handler) -> None:
        """Remove a handler. Silently ignores handlers that are not attached."""
        key = event_type.value if isinstance(event_type, EventType) else event_type
        with self._lock, contextlib.suppress(ValueError):
            self._handlers[key].remove(handler)

    def clear(self) -> None:
        """Drop every subscription."""
        with self._lock:
            self._handlers.clear()

    # -- publishing ----------------------------------------------------

    def emit(self, event_type: EventType, /, **payload: Any) -> Event:
        """Build and publish an event. Returns the event for convenience."""
        event = Event(type=event_type, payload=payload)
        self.publish(event)
        return event

    def publish(self, event: Event) -> None:
        """Deliver *event* to matching handlers.

        Handlers are copied under the lock and invoked outside it, so a
        handler may subscribe or unsubscribe without deadlocking.
        """
        if self._muted:
            return
        with self._lock:
            targets = list(self._handlers.get(event.type.value, ()))
            targets += list(self._handlers.get(ALL, ()))

        for handler in targets:
            try:
                handler(event)
            except Exception:
                # Never let a listener break the scan.
                log.exception("event handler failed for %s", event.type.value)

    # -- utilities -----------------------------------------------------

    def mute(self) -> None:
        """Stop delivering events (used while tearing down the GUI)."""
        self._muted = True

    def unmute(self) -> None:
        self._muted = False

    def handler_count(self, event_type: EventType | str | None = None) -> int:
        """Number of registered handlers, total or for one event type."""
        with self._lock:
            if event_type is None:
                return sum(len(v) for v in self._handlers.values())
            key = event_type.value if isinstance(event_type, EventType) else event_type
            return len(self._handlers.get(key, ()))


class EventRecorder:
    """Collects events for assertions in tests and for the GUI's log pane.

    Bounded so a multi-million-file scan cannot exhaust memory.
    """

    def __init__(self, bus: EventBus, max_events: int = 10_000) -> None:
        self.events: list[Event] = []
        self.max_events = max_events
        self._lock = threading.Lock()
        self._unsubscribe = bus.subscribe_all(self._record)

    def _record(self, event: Event) -> None:
        with self._lock:
            self.events.append(event)
            if len(self.events) > self.max_events:
                # Drop the oldest half at once rather than popping every time.
                del self.events[: self.max_events // 2]

    def of_type(self, event_type: EventType) -> list[Event]:
        with self._lock:
            return [e for e in self.events if e.type is event_type]

    def count(self, event_type: EventType) -> int:
        return len(self.of_type(event_type))

    def __iter__(self) -> Iterator[Event]:
        with self._lock:
            return iter(list(self.events))

    def __len__(self) -> int:
        with self._lock:
            return len(self.events)

    def close(self) -> None:
        self._unsubscribe()


#: Process-wide default bus. Front ends that embed the engine should create
#: their own :class:`EventBus` instead of using this one.
default_bus = EventBus()
