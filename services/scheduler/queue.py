"""Queue abstraction (port) + in-process adapter.

M2 uses `InMemoryQueue` so the system runs with zero infrastructure. M3 adds `RedisStreamQueue`
implementing the same Protocol (XADD / XREADGROUP / XACK give at-least-once delivery with consumer
groups, which is the semantics we want: a redelivered task is harmless because nonces make
duplicate *results* detectable).
"""

from __future__ import annotations

import queue
import threading
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class QueueMessage:
    message_id: str
    payload: dict[str, Any]
    attempts: int = 0


class TaskQueue(Protocol):
    def publish(self, payload: dict[str, Any]) -> str: ...
    def consume(self, timeout: float | None = None) -> QueueMessage | None: ...
    def ack(self, message_id: str) -> None: ...
    def nack(self, message_id: str) -> None: ...
    def depth(self) -> int: ...
    def reset(self) -> None: ...


@dataclass
class InMemoryQueue:
    """Thread-safe FIFO with explicit ack/nack and redelivery, mirroring Redis Streams semantics."""

    max_deliveries: int = 3
    _q: queue.Queue[QueueMessage] = field(default_factory=queue.Queue, repr=False)
    _pending: dict[str, QueueMessage] = field(default_factory=dict, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _counter: int = 0
    dead_letter: list[QueueMessage] = field(default_factory=list)

    def publish(self, payload: dict[str, Any]) -> str:
        with self._lock:
            self._counter += 1
            mid = f"m-{self._counter:08d}"
        self._q.put(QueueMessage(mid, payload))
        return mid

    def consume(self, timeout: float | None = 0.1) -> QueueMessage | None:
        try:
            msg = self._q.get(timeout=timeout) if timeout else self._q.get_nowait()
        except queue.Empty:
            return None
        msg.attempts += 1
        with self._lock:
            self._pending[msg.message_id] = msg
        return msg

    def ack(self, message_id: str) -> None:
        with self._lock:
            self._pending.pop(message_id, None)

    def nack(self, message_id: str) -> None:
        """Redeliver, or dead-letter once the delivery budget is exhausted."""
        with self._lock:
            msg = self._pending.pop(message_id, None)
        if msg is None:
            return
        if msg.attempts >= self.max_deliveries:
            self.dead_letter.append(msg)
        else:
            self._q.put(msg)

    def depth(self) -> int:
        return self._q.qsize()

    def in_flight(self) -> int:
        with self._lock:
            return len(self._pending)

    def reset(self) -> None:
        with self._lock:
            self._pending.clear()
            self.dead_letter.clear()
        while not self._q.empty():
            try:
                self._q.get_nowait()
            except queue.Empty:
                break
