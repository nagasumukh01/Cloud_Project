"""Worker registry: registration, discovery, health, and eligibility.

Keeps the *public* view (id, public key, capabilities, status) separate from the worker object
itself. Private keys never enter the registry. In M3 this becomes a service with heartbeat TTLs;
the interface is already shaped for that (`heartbeat`, `prune_unreachable`).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from services.common.models import WorkerStatus
from services.workers.worker import ExecutesTasks


@dataclass
class WorkerRecord:
    worker_id: str
    public_key: str
    capabilities: tuple[str, ...]
    handle: ExecutesTasks
    status: WorkerStatus = WorkerStatus.ACTIVE
    registered_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = field(default_factory=lambda: datetime.now(UTC))
    consecutive_failures: int = 0
    circuit_open_until: datetime | None = None

    @property
    def fingerprint(self) -> str:
        return self.public_key[:16]

    def is_available(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(UTC)
        if self.status in (WorkerStatus.QUARANTINED, WorkerStatus.UNREACHABLE):
            return False
        if self.circuit_open_until and now < self.circuit_open_until:
            return False
        return True


class WorkerRegistry:
    """In-memory registry with a circuit breaker per worker.

    Circuit breaker: after `failure_threshold` consecutive failures a worker's circuit opens for
    `open_seconds`, during which it receives no tasks; the next task after expiry is a HALF_OPEN
    probe — success closes the circuit, failure re-opens it. This is the standard pattern and it is
    what keeps a crashed/stalled worker from absorbing the whole retry budget.
    """

    def __init__(self, failure_threshold: int = 3, open_seconds: float = 5.0, heartbeat_ttl_s: float = 30.0):
        self._workers: dict[str, WorkerRecord] = {}
        self.failure_threshold = failure_threshold
        self.open_seconds = open_seconds
        self.heartbeat_ttl_s = heartbeat_ttl_s

    # -- registration ------------------------------------------------------
    def register(self, handle: ExecutesTasks, capabilities: Iterable[str] = ()) -> WorkerRecord:
        wid = handle.worker_id
        if wid in self._workers:
            existing = self._workers[wid]
            if existing.public_key != handle.public_key_hex:
                # Key change must be explicit (rotation flow, M5), never silent: a silent swap
                # would let an attacker re-bind an existing identity to their own key.
                raise ValueError(f"worker {wid!r} already registered with a different public key")
            existing.last_seen = datetime.now(UTC)
            return existing
        caps = tuple(capabilities) or tuple(getattr(handle, "capabilities", ()))
        rec = WorkerRecord(
            worker_id=wid, public_key=handle.public_key_hex, capabilities=caps, handle=handle
        )
        self._workers[wid] = rec
        return rec

    def deregister(self, worker_id: str) -> None:
        self._workers.pop(worker_id, None)

    def get(self, worker_id: str) -> WorkerRecord | None:
        return self._workers.get(worker_id)

    def public_key_of(self, worker_id: str) -> str | None:
        rec = self._workers.get(worker_id)
        return rec.public_key if rec else None

    def all(self) -> list[WorkerRecord]:
        return list(self._workers.values())

    def available(self, capability: str | None = None, exclude: Iterable[str] = ()) -> list[WorkerRecord]:
        ex = set(exclude)
        now = datetime.now(UTC)
        return [
            r
            for r in self._workers.values()
            if r.worker_id not in ex
            and r.is_available(now)
            and (capability is None or capability in r.capabilities)
        ]

    # -- health / circuit breaker -----------------------------------------
    def heartbeat(self, worker_id: str) -> None:
        rec = self._workers.get(worker_id)
        if rec:
            rec.last_seen = datetime.now(UTC)
            if rec.status == WorkerStatus.UNREACHABLE:
                rec.status = WorkerStatus.ACTIVE

    def record_success(self, worker_id: str) -> None:
        rec = self._workers.get(worker_id)
        if not rec:
            return
        rec.consecutive_failures = 0
        rec.circuit_open_until = None
        rec.last_seen = datetime.now(UTC)
        if rec.status == WorkerStatus.DEGRADED:
            rec.status = WorkerStatus.ACTIVE

    def record_failure(self, worker_id: str) -> None:
        rec = self._workers.get(worker_id)
        if not rec:
            return
        rec.consecutive_failures += 1
        rec.last_seen = datetime.now(UTC)
        if rec.consecutive_failures >= self.failure_threshold:
            rec.status = WorkerStatus.DEGRADED
            rec.circuit_open_until = datetime.now(UTC) + timedelta(seconds=self.open_seconds)

    def quarantine(self, worker_id: str, reason: str = "") -> None:
        """Reversible eligibility downgrade. Not an accusation of malice (THREAT_MODEL §8)."""
        rec = self._workers.get(worker_id)
        if rec:
            rec.status = WorkerStatus.QUARANTINED

    def release(self, worker_id: str) -> None:
        rec = self._workers.get(worker_id)
        if rec:
            rec.status = WorkerStatus.ACTIVE
            rec.consecutive_failures = 0
            rec.circuit_open_until = None

    def prune_unreachable(self, now: datetime | None = None) -> list[str]:
        now = now or datetime.now(UTC)
        stale = []
        for rec in self._workers.values():
            if (now - rec.last_seen).total_seconds() > self.heartbeat_ttl_s:
                rec.status = WorkerStatus.UNREACHABLE
                stale.append(rec.worker_id)
        return stale

    def reset(self) -> None:
        self._workers.clear()

    def __len__(self) -> int:
        return len(self._workers)
