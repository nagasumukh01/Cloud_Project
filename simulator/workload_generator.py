"""Workload generation for experiments.

Three arrival/sensitivity regimes, because evaluating on a single uniform stream is the classic way
to accidentally overfit a scheduling policy to one shape of demand:

  * uniform  - steady arrivals, sensitivity drawn uniformly. The control condition.
  * bursty   - Poisson-ish bursts separated by idle gaps. Stresses queueing and the cost of
               verification when capacity is scarce.
  * skewed   - most tasks low-sensitivity, a small tail of high-sensitivity ones. The regime where
               a risk-adaptive policy should shine, and therefore the one where we must be most
               careful not to over-claim.

Everything is seeded and deterministic.
"""

from __future__ import annotations

import random
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Literal

from ml.inference_model import sample_inputs

Regime = Literal["uniform", "bursty", "skewed"]

SENSITIVITY_MIX: dict[Regime, dict[str, float]] = {
    "uniform": {"low": 1 / 3, "medium": 1 / 3, "high": 1 / 3},
    "bursty": {"low": 0.4, "medium": 0.4, "high": 0.2},
    "skewed": {"low": 0.75, "medium": 0.20, "high": 0.05},
}


@dataclass(frozen=True)
class GeneratedTask:
    index: int
    features: list[float]
    sensitivity: str
    inter_arrival_ms: float
    regime: str


@dataclass
class WorkloadGenerator:
    """Deterministic task-stream generator."""

    n_tasks: int
    regime: Regime = "uniform"
    seed: int = 42
    mean_inter_arrival_ms: float = 10.0
    burst_size: int = 20
    burst_gap_ms: float = 200.0

    def __post_init__(self) -> None:
        if self.n_tasks <= 0:
            raise ValueError("n_tasks must be positive")
        if self.regime not in SENSITIVITY_MIX:
            raise ValueError(f"unknown regime {self.regime!r}; use one of {sorted(SENSITIVITY_MIX)}")
        if self.mean_inter_arrival_ms < 0:
            raise ValueError("mean_inter_arrival_ms must be >= 0")

    def _sensitivity(self, rng: random.Random) -> str:
        mix = SENSITIVITY_MIX[self.regime]
        return rng.choices(list(mix), weights=list(mix.values()), k=1)[0]

    def _inter_arrival(self, rng: random.Random, i: int) -> float:
        if self.regime == "bursty":
            # Tight arrivals inside a burst, a long gap between bursts.
            if i > 0 and i % self.burst_size == 0:
                return self.burst_gap_ms
            return rng.expovariate(1.0 / max(self.mean_inter_arrival_ms * 0.2, 1e-6))
        return rng.expovariate(1.0 / max(self.mean_inter_arrival_ms, 1e-6))

    def generate(self) -> list[GeneratedTask]:
        rng = random.Random(self.seed)
        # Inputs are drawn from the real dataset so the classifier does something meaningful.
        inputs = sample_inputs(self.n_tasks, seed=self.seed + 1000)
        return [
            GeneratedTask(
                index=i,
                features=inputs[i % len(inputs)],
                sensitivity=self._sensitivity(rng),
                inter_arrival_ms=round(self._inter_arrival(rng, i), 3),
                regime=self.regime,
            )
            for i in range(self.n_tasks)
        ]

    def __iter__(self) -> Iterator[GeneratedTask]:
        return iter(self.generate())

    def summary(self) -> dict:
        tasks = self.generate()
        counts: dict[str, int] = {}
        for t in tasks:
            counts[t.sensitivity] = counts.get(t.sensitivity, 0) + 1
        total_ms = sum(t.inter_arrival_ms for t in tasks)
        return {
            "regime": self.regime,
            "n_tasks": self.n_tasks,
            "seed": self.seed,
            "sensitivity_counts": counts,
            "total_arrival_span_ms": round(total_ms, 2),
            "mean_inter_arrival_ms": round(total_ms / self.n_tasks, 3),
        }
