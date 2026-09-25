"""Replay protection: nonce exactly-once cache + timestamp freshness window.

Two independent mechanisms, because each alone is insufficient:

  * A **timestamp window** alone allows replay *within* the window.
  * A **nonce cache** alone would have to be unbounded to be complete.

Combining them bounds memory: a nonce only needs to be remembered for as long as an envelope
bearing it could still pass the freshness check, i.e. `max_age + skew`. We keep the TTL
deliberately larger than that bound (default 2x) as a safety margin, and document in
THREAT_MODEL.md (T3) that pruning re-opens a replay window only for envelopes that would already
have failed the freshness check.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

__all__ = ["ReplayGuard", "ReplayDecision"]


@dataclass(frozen=True)
class ReplayDecision:
    accepted: bool
    reason: str  # "ok" | "replayed_nonce" | "stale_timestamp" | "future_timestamp"


@dataclass
class ReplayGuard:
    """Thread-safe, in-memory nonce cache with TTL pruning.

    M3 replaces the backing store with Redis `SET key NX EX ttl`, which gives the same
    exactly-once semantics across processes. The interface stays identical.
    """

    max_age_seconds: float = 300.0
    skew_tolerance_seconds: float = 30.0
    ttl_multiplier: float = 2.0
    _seen: dict[tuple[str, str], datetime] = field(default_factory=dict, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @property
    def ttl(self) -> timedelta:
        return timedelta(
            seconds=(self.max_age_seconds + self.skew_tolerance_seconds) * self.ttl_multiplier
        )

    def check_and_register(
        self, worker_id: str, nonce: str, timestamp: datetime, now: datetime | None = None
    ) -> ReplayDecision:
        """Atomically validate freshness and claim the nonce. Registers only on acceptance."""
        current = now or datetime.now(UTC)
        if timestamp.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware")
        age = (current - timestamp).total_seconds()
        if age > self.max_age_seconds:
            return ReplayDecision(False, "stale_timestamp")
        if age < -self.skew_tolerance_seconds:
            return ReplayDecision(False, "future_timestamp")

        key = (worker_id, nonce)
        with self._lock:
            self._prune(current)
            if key in self._seen:
                return ReplayDecision(False, "replayed_nonce")
            self._seen[key] = current
        return ReplayDecision(True, "ok")

    def has_seen(self, worker_id: str, nonce: str) -> bool:
        with self._lock:
            return (worker_id, nonce) in self._seen

    def _prune(self, now: datetime) -> int:
        cutoff = now - self.ttl
        stale = [k for k, t in self._seen.items() if t < cutoff]
        for k in stale:
            del self._seen[k]
        return len(stale)

    def prune(self, now: datetime | None = None) -> int:
        with self._lock:
            return self._prune(now or datetime.now(UTC))

    def reset(self) -> None:
        """Used by the experiment harness between runs (required reset function, brief §9)."""
        with self._lock:
            self._seen.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._seen)
