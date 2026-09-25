"""Worker trust estimation — deliberately transparent, not a black box.

Design decision (brief §5C): trust must be *explainable*, so we use an exponentially weighted
moving average over labelled outcome events with published weights, plus a latency-stability term.
An operator can always answer "why is this worker at 0.41?" by reading its trust_events rows.

    trust_{t+1} = (1 - alpha) * trust_t + alpha * outcome_value

`alpha` (default 0.15) sets the memory horizon: the influence of an event decays to <5 % after
~ln(0.05)/ln(1-alpha) ≈ 18 events. Chosen so a worker can recover from a bad patch within a few
dozen tasks while a persistent defector is pushed below the quarantine floor quickly; the value is
an ablation parameter in the experiments, not a magic constant.

NOTE: a trust score is a behavioural statistic under a synthetic fault model. It is NOT evidence
of malicious intent (THREAT_MODEL.md §8).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

# Outcome value in [0,1] contributed by each event type, with the reasoning for each weight.
EVENT_VALUES: dict[str, float] = {
    "success": 1.0,            # completed and accepted
    "verified_agreement": 1.0, # independently corroborated by a replica -> strongest positive
    "slow": 0.5,               # completed but late: unreliable, not dishonest
    "timeout": 0.2,            # availability failure
    "crash": 0.1,              # availability failure, harder
    "disagreement": 0.0,       # replica disagreement: possible incorrect computation
    "integrity_failure": 0.0,  # bad signature / hash / replay: strongest negative
}

POSITIVE_EVENTS = {"success", "verified_agreement"}
INTEGRITY_EVENTS = {"integrity_failure"}


@dataclass
class TrustState:
    worker_id: str
    score: float
    n_events: int = 0
    successes: int = 0
    failures: int = 0
    integrity_failures: int = 0
    disagreements: int = 0
    latency_ewma_ms: float = 0.0
    latency_var_ewma: float = 0.0

    @property
    def reliability(self) -> float:
        """Fraction of events that were clean completions. Complements the EWMA score."""
        return self.successes / self.n_events if self.n_events else 0.0


@dataclass
class TrustEngine:
    """In-memory trust state; mirrored to `trust_events` for the audit trail."""

    alpha: float = 0.15
    prior: float = 0.70
    quarantine_floor: float = 0.25
    integrity_penalty: float = 0.35  # extra multiplicative hit for cryptographic failures
    _state: dict[str, TrustState] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        if not 0.0 < self.alpha <= 1.0:
            raise ValueError("alpha must be in (0,1]")
        if not 0.0 <= self.prior <= 1.0:
            raise ValueError("prior must be in [0,1]")

    def register(self, worker_id: str, initial: float | None = None) -> TrustState:
        """New workers start at `prior`, not 1.0: unknown is not the same as trusted."""
        st = TrustState(worker_id=worker_id, score=self.prior if initial is None else initial)
        self._state[worker_id] = st
        return st

    def get(self, worker_id: str) -> TrustState:
        return self._state.get(worker_id) or self.register(worker_id)

    def score(self, worker_id: str) -> float:
        return self.get(worker_id).score

    def record(self, worker_id: str, event_type: str, latency_ms: float | None = None) -> TrustState:
        if event_type not in EVENT_VALUES:
            raise ValueError(f"unknown trust event {event_type!r}")
        st = self.get(worker_id)
        value = EVENT_VALUES[event_type]

        st.score = (1.0 - self.alpha) * st.score + self.alpha * value
        if event_type in INTEGRITY_EVENTS:
            # A cryptographic failure is categorical evidence of a broken/hostile path, so it gets
            # a multiplicative penalty on top of the EWMA update rather than just one bad sample.
            st.score *= 1.0 - self.integrity_penalty
            st.integrity_failures += 1
        st.score = min(1.0, max(0.0, st.score))

        st.n_events += 1
        if event_type in POSITIVE_EVENTS:
            st.successes += 1
        else:
            st.failures += 1
        if event_type == "disagreement":
            st.disagreements += 1

        if latency_ms is not None:
            if st.latency_ewma_ms == 0.0:
                st.latency_ewma_ms = latency_ms
            else:
                prev = st.latency_ewma_ms
                st.latency_ewma_ms = (1 - self.alpha) * prev + self.alpha * latency_ms
                st.latency_var_ewma = (1 - self.alpha) * st.latency_var_ewma + self.alpha * (
                    latency_ms - prev
                ) ** 2
        return st

    def should_quarantine(self, worker_id: str, min_events: int = 5) -> bool:
        """Quarantine is *simulated and reversible* eligibility downgrade, never an accusation."""
        st = self.get(worker_id)
        return st.n_events >= min_events and st.score < self.quarantine_floor

    def explain(self, worker_id: str) -> dict[str, float | int | str]:
        st = self.get(worker_id)
        return {
            "worker_id": st.worker_id,
            "trust_score": round(st.score, 4),
            "events": st.n_events,
            "successes": st.successes,
            "failures": st.failures,
            "integrity_failures": st.integrity_failures,
            "disagreements": st.disagreements,
            "reliability": round(st.reliability, 4),
            "latency_ewma_ms": round(st.latency_ewma_ms, 2),
            "alpha": self.alpha,
            "note": "behavioural statistic under a synthetic fault model; not proof of intent",
        }

    def snapshot(self) -> list[dict]:
        return [self.explain(w) for w in sorted(self._state)]

    def reset(self, worker_ids: Iterable[str] | None = None) -> None:
        if worker_ids is None:
            self._state.clear()
        else:
            for w in worker_ids:
                self._state.pop(w, None)
