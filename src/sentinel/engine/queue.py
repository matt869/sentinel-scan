"""Bounded producer/consumer pool used to parallelise file scanning.

Why not :class:`concurrent.futures.ThreadPoolExecutor`? Because ``map`` over
a generator eagerly drains it. Pointing that at a full-disk walk buffers
millions of ``Future`` objects before the first file is scanned, and the
process runs out of memory long before it runs out of files.

This pool keeps a fixed-size queue between the walker and the workers, so
traversal proceeds only as fast as scanning consumes it, and memory stays
flat regardless of how large the tree is.

Results are yielded as they complete, in no particular order.
"""

from __future__ import annotations

import queue
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from typing import Generic, TypeVar

from sentinel.core.logger import get_logger

log = get_logger(__name__)

T = TypeVar("T")
R = TypeVar("R")

#: Queue depth per worker. Deep enough that workers never starve on a slow
#: disk, shallow enough that cancellation drains quickly.
QUEUE_DEPTH_PER_WORKER = 4

#: Poll interval when waiting on a queue, so cancellation is responsive
#: without spinning.
_POLL = 0.1


@dataclass(slots=True)
class PoolStats:
    """Counters describing a completed run."""

    submitted: int = 0
    completed: int = 0
    failed: int = 0
    duration: float = 0.0

    @property
    def throughput(self) -> float:
        return self.completed / self.duration if self.duration > 0 else 0.0


class _Sentinel:
    """Marks the end of the input stream for one worker."""


_STOP = _Sentinel()


class WorkerPool(Generic[T, R]):
    """Runs ``task`` over an iterable on a fixed pool of threads."""

    def __init__(
        self,
        task: Callable[[T], R],
        workers: int = 4,
        cancel_event: threading.Event | None = None,
        on_error: Callable[[T, Exception], None] | None = None,
    ) -> None:
        """
        Args:
            task: Called on each item, on a worker thread.
            workers: Thread count. Clamped to at least 1.
            cancel_event: Set to stop the pool early.
            on_error: Called as ``(item, exception)`` when *task* raises. The
                item is then dropped; the pool keeps going.
        """
        self.task = task
        self.workers = max(1, workers)
        self.cancel_event = cancel_event or threading.Event()
        self.on_error = on_error
        self.stats = PoolStats()

        self._input: queue.Queue = queue.Queue(
            maxsize=self.workers * QUEUE_DEPTH_PER_WORKER
        )
        self._output: queue.Queue = queue.Queue()
        self._threads: list[threading.Thread] = []
        self._producer: threading.Thread | None = None
        self._live_workers = 0
        self._lock = threading.Lock()

    # -- public API ----------------------------------------------------

    def process(self, items: Iterable[T]) -> Iterator[R]:
        """Yield a result for each item, as they complete.

        The iterator must be fully consumed (or closed) for the worker
        threads to be joined. Use it in a ``for`` loop or wrap in
        ``contextlib.closing``.
        """
        started = time.monotonic()
        self._start(items)

        finished_workers = 0
        try:
            while finished_workers < self.workers:
                try:
                    item = self._output.get(timeout=_POLL)
                except queue.Empty:
                    if self.cancel_event.is_set() and self._all_dead():
                        break
                    continue

                if isinstance(item, _Sentinel):
                    finished_workers += 1
                    continue

                self.stats.completed += 1
                yield item
        finally:
            if finished_workers < self.workers:
                # The consumer abandoned the iterator (a `break`, or an
                # exception upstream). Tell the threads to wind down rather
                # than leaving them blocked on a queue nobody will drain.
                self.cancel_event.set()
            self._join()
            self.stats.duration = time.monotonic() - started

    def cancel(self) -> None:
        """Ask the pool to stop. In-flight tasks finish; queued ones do not."""
        self.cancel_event.set()

    @property
    def cancelled(self) -> bool:
        return self.cancel_event.is_set()

    # -- internals -----------------------------------------------------

    def _start(self, items: Iterable[T]) -> None:
        self._producer = threading.Thread(
            target=self._produce, args=(items,), name="sentinel-walk", daemon=True
        )
        self._producer.start()

        for index in range(self.workers):
            thread = threading.Thread(
                target=self._consume, name=f"sentinel-scan-{index}", daemon=True
            )
            thread.start()
            self._threads.append(thread)

        with self._lock:
            self._live_workers = self.workers

    def _produce(self, items: Iterable[T]) -> None:
        """Feed the input queue, blocking when the workers fall behind."""
        try:
            for item in items:
                if self.cancel_event.is_set():
                    break
                # put() with a timeout rather than blocking forever, so a
                # cancellation while the queue is full is still honoured.
                while True:
                    try:
                        self._input.put(item, timeout=_POLL)
                        break
                    except queue.Full:
                        if self.cancel_event.is_set():
                            return
                self.stats.submitted += 1
        except Exception:
            # A traversal error must not hang the consumers waiting for a
            # stop sentinel that never arrives.
            log.exception("producer failed")
        finally:
            for _ in range(self.workers):
                # The queue is bounded, so this can block; it will drain as
                # workers exit.
                while True:
                    try:
                        self._input.put(_STOP, timeout=_POLL)
                        break
                    except queue.Full:
                        if self.cancel_event.is_set() and self._all_dead():
                            return

    def _consume(self) -> None:
        """Pull items, run the task, push results."""
        try:
            while True:
                try:
                    item = self._input.get(timeout=_POLL)
                except queue.Empty:
                    if self.cancel_event.is_set():
                        return
                    continue

                if isinstance(item, _Sentinel):
                    return
                if self.cancel_event.is_set():
                    continue  # drain quickly rather than scanning

                try:
                    self._output.put(self.task(item))
                except Exception as exc:
                    self.stats.failed += 1
                    if self.on_error is not None:
                        try:
                            self.on_error(item, exc)
                        except Exception:  # pragma: no cover - listener bug
                            log.exception("on_error callback failed")
                    else:
                        log.debug("task failed for %r: %s", item, exc)
        finally:
            with self._lock:
                self._live_workers -= 1
            self._output.put(_STOP)

    def _join(self, timeout: float = 5.0) -> None:
        for thread in self._threads:
            thread.join(timeout=timeout)
        if self._producer is not None:
            self._producer.join(timeout=timeout)
        self._threads.clear()
        self._producer = None

    def _all_dead(self) -> bool:
        with self._lock:
            return self._live_workers <= 0


def map_parallel(
    task: Callable[[T], R],
    items: Iterable[T],
    workers: int = 4,
    cancel_event: threading.Event | None = None,
) -> Iterator[R]:
    """Convenience wrapper around :class:`WorkerPool` for one-off use."""
    pool: WorkerPool[T, R] = WorkerPool(task, workers, cancel_event)
    yield from pool.process(items)
