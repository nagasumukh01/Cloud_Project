"""Fault injection harness.

Turns a declarative `Scenario` into a configured, isolated system, runs a workload against it, and
collects ground-truth labels for evaluation. Provides the reset function the brief requires (§9)
so no state leaks between experiments.

ISOLATION GUARANTEE: this module only ever constructs in-process `FaultyWorker` objects from
`services.workers.worker`. It performs no network I/O, spawns no processes, and touches no file
outside the configured data directory. Faults cannot escape the simulation.

GROUND TRUTH: labels are read from the injector-controlled worker objects, never from scheduler or
verifier state. `tests/test_research_integrity.py` enforces that decision code cannot see them.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from services.common.bootstrap import System, build_system
from services.common.models import TaskStatus, Verdict
from services.workers.worker import FaultyWorker
from simulator.attack_scenarios import Scenario, get_scenario
from simulator.workload_generator import GeneratedTask, WorkloadGenerator


@dataclass
class AttemptLabel:
    """Ground truth for one task, derived from what the injector actually did."""

    task_index: int
    task_id: str
    corrupted: bool
    behaviours: tuple[str, ...]
    crashed: bool


@dataclass
class InjectionRun:
    scenario_id: str
    policy: str
    seed: int
    outcomes: list = field(default_factory=list)
    labels: list[AttemptLabel] = field(default_factory=list)
    reference_results: dict[int, dict] = field(default_factory=dict)

    # -- derived evaluation metrics -----------------------------------------
    @property
    def n_tasks(self) -> int:
        return len(self.outcomes)

    @property
    def corrupt_tasks(self) -> int:
        return sum(1 for label in self.labels if label.corrupted)

    @property
    def clean_tasks(self) -> int:
        return self.n_tasks - self.corrupt_tasks

    def detected(self, i: int) -> bool:
        o = self.outcomes[i]
        return bool(
            o.integrity_failure
            or "disagreement" in o.detail
            or o.verdict in (Verdict.REJECTED_DISAGREEMENT, Verdict.REJECTED_INTEGRITY)
        )

    def wrong_result_served(self, i: int) -> bool:
        o = self.outcomes[i]
        return o.result is not None and o.result != self.reference_results[i]

    def confusion(self) -> dict[str, int]:
        tp = fp = tn = fn = 0
        for i, label in enumerate(self.labels):
            det = self.detected(i)
            if label.corrupted and det:
                tp += 1
            elif label.corrupted and not det:
                fn += 1
            elif not label.corrupted and det:
                fp += 1
            else:
                tn += 1
        return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}

    def metrics(self) -> dict[str, float]:
        c = self.confusion()
        tp, fp, fn = c["tp"], c["fp"], c["fn"]
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        fpr = fp / (c["fp"] + c["tn"]) if (c["fp"] + c["tn"]) else 0.0
        completed = sum(1 for o in self.outcomes if o.status == TaskStatus.COMPLETED)
        return {
            **{k: float(v) for k, v in c.items()},
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "false_positive_rate": round(fpr, 4),
            "completion_rate": round(completed / self.n_tasks, 4) if self.n_tasks else 0.0,
            "wrong_results_served": float(
                sum(1 for i in range(self.n_tasks) if self.wrong_result_served(i))
            ),
            "mean_cost_units": round(
                sum(o.cost_units for o in self.outcomes) / self.n_tasks, 4
            ) if self.n_tasks else 0.0,
            "mean_latency_ms": round(
                sum(o.latency_ms for o in self.outcomes) / self.n_tasks, 3
            ) if self.n_tasks else 0.0,
        }

    def failure_reasons(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for o in self.outcomes:
            for r in o.integrity_failure_reasons:
                counts[r] = counts.get(r, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: -kv[1]))


class FaultInjector:
    """Builds an isolated system for a scenario and runs a labelled workload against it."""

    def __init__(
        self,
        scenario: str | Scenario,
        *,
        n_workers: int = 8,
        n_faulty: int = 2,
        policy: str = "risk_adaptive",
        selection: str = "trust_weighted",
        fault_rate: float | None = None,
        seed: int = 42,
    ):
        self.scenario = get_scenario(scenario) if isinstance(scenario, str) else scenario
        if not self.scenario.implemented:
            raise NotImplementedError(
                f"scenario {self.scenario.id!r} is declared but not implemented: "
                f"{self.scenario.notes}"
            )
        if n_faulty > n_workers:
            raise ValueError("n_faulty cannot exceed n_workers")
        self.n_workers = n_workers
        self.n_faulty = n_faulty
        self.policy = policy
        self.selection = selection
        self.fault_rate = self.scenario.default_fault_rate if fault_rate is None else fault_rate
        self.seed = seed
        self.system: System | None = None

    def build(self) -> System:
        self.system = build_system(
            n_workers=self.n_workers,
            n_faulty=self.n_faulty,
            fault_rate=self.fault_rate,
            behaviours=self.scenario.behaviours or ("tamper_payload",),
            policy=self.policy,
            selection=self.selection,
            persist=False,
            record_ground_truth=True,
            seed=self.seed,
        )
        return self.system

    @property
    def faulty_worker_ids(self) -> set[str]:
        if self.system is None or self.n_faulty == 0:
            return set()
        return {w.worker_id for w in self.system.workers[self.n_workers - self.n_faulty:]}

    def run(self, tasks: list[GeneratedTask] | int = 100) -> InjectionRun:
        """Execute a labelled workload. Returns ground truth alongside observed outcomes."""
        if self.system is None:
            self.build()
        assert self.system is not None

        if isinstance(tasks, int):
            tasks = WorkloadGenerator(n_tasks=tasks, seed=self.seed).generate()

        run = InjectionRun(scenario_id=self.scenario.id, policy=self.policy, seed=self.seed)
        faulty = self.faulty_worker_ids

        for t in tasks:
            # Reference prediction computed outside the worker pool: the source of truth for
            # "was the served answer actually right?".
            run.reference_results[t.index] = self.system.model.predict_with_uncertainty(
                t.features
            ).as_payload()

            before = {w.worker_id: getattr(w, "executions", 0) for w in self.system.workers}
            for w in self.system.workers:
                if isinstance(w, FaultyWorker):
                    w.last_behaviour = "honest"

            outcome = self.system.scheduler.submit(
                t.features,
                sensitivity=t.sensitivity,
                timeout_ms=self.system.settings.task_timeout_ms,
            )

            behaviours: list[str] = []
            crashed = False
            for w in self.system.workers:
                if w.worker_id not in faulty or not isinstance(w, FaultyWorker):
                    continue
                b = getattr(w, "last_behaviour", "honest")
                ran = getattr(w, "executions", 0) > before[w.worker_id]
                if b == "crash":
                    crashed = True
                    behaviours.append(b)
                elif ran and b != "honest":
                    behaviours.append(b)

            run.outcomes.append(outcome)
            run.labels.append(
                AttemptLabel(
                    task_index=t.index,
                    task_id=outcome.task_id,
                    corrupted=any(b not in ("honest", "slow", "crash") for b in behaviours),
                    behaviours=tuple(behaviours),
                    crashed=crashed,
                )
            )
        return run

    def reset(self) -> None:
        """Required reset hook (brief §9): clears trust, replay cache, queue, stats and
        quarantine state so the next scenario starts from a clean slate."""
        if self.system is not None:
            self.system.reset()

    def teardown(self) -> None:
        self.reset()
        self.system = None
